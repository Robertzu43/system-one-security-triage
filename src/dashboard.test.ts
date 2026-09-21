import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildPublishedDemoData } from "./dashboard.js";
import { parseRecordedDemoRun, type RecordedDemoRun } from "./demo-record.js";
import { loadDemoCases, type DemoCase, type DemoChoiceLabel } from "./demo.js";

async function loadFixtureRuns(cases: readonly DemoCase[]): Promise<RecordedDemoRun[]> {
  return Promise.all((["jev", "terra", "opus"] as const).map(async (evaluator) =>
    parseRecordedDemoRun(JSON.parse(await readFile(`test/fixtures/dashboard-runs/${evaluator}.json`, "utf8")), cases)));
}

test("builder requires one Jev, Terra, and Opus run over one corpus", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns(cases);
  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");
  assert.deepEqual(Object.keys(data.summary), ["jev", "terra", "opus"]);
  assert.equal(data.cases.length, 100);
  assert.equal(data.models.length, 3);
  assert.equal(data.provenance.kind, "fixture");
  assert.throws(() => buildPublishedDemoData(cases, runs.slice(0, 2), data.generatedAt), /requires jev, terra, and opus/);
  assert.throws(() => buildPublishedDemoData(cases, [...runs, runs[0]!], data.generatedAt), /duplicate evaluator/);
  assert.throws(() => buildPublishedDemoData(cases, [runs[0]!, { ...runs[1]!, corpusHash: "0".repeat(64) }, runs[2]!], data.generatedAt), /corpus hash mismatch/);
});

test("builder derives metrics from case results including failures", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns(cases);
  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");
  assert.equal(data.summary.jev.accuracy, runs[0]!.results.filter((row) => row.correct).length / 100);
  assert.equal(data.summary.jev.errors, runs[0]!.results.filter((row) => row.status === "error").length);
  assert.equal(typeof data.summary.terra.balancedAccuracy, "number");
  assert.equal(typeof data.summary.terra.falsePositiveRate, "number");
  assert.equal(data.warnings.some((warning) => /opus recorded 1 explicit error/.test(warning)), true);
});

test("builder preserves Jev Choice probabilities in published case data", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns(cases);
  const choice = {
    selected: "vulnerable_injection" as const,
    confidence: 0.82,
    probabilities: { vulnerable_injection: 0.86, vulnerable_broken_access_control: 0.02, vulnerable_ssrf: 0.01, safe: 0.06, insufficient_context: 0.05 }
  };
  const results = runs[0]!.results.map((result, index) => {
    if (index === 0) return { ...result, decision: { ...result.decision!, choice } };
    const selected: DemoChoiceLabel = result.decision!.disposition !== "vulnerable" ? result.decision!.disposition
      : result.decision!.family === "injection" ? "vulnerable_injection"
      : result.decision!.family === "broken_access_control" ? "vulnerable_broken_access_control"
      : "vulnerable_ssrf";
    return { ...result, decision: { ...result.decision!, choice: {
      selected,
      confidence: 1,
      probabilities: {
        vulnerable_injection: selected === "vulnerable_injection" ? 1 : 0,
        vulnerable_broken_access_control: selected === "vulnerable_broken_access_control" ? 1 : 0,
        vulnerable_ssrf: selected === "vulnerable_ssrf" ? 1 : 0,
        safe: selected === "safe" ? 1 : 0,
        insufficient_context: selected === "insufficient_context" ? 1 : 0
      }
    } } };
  });
  runs[0] = { ...runs[0]!, runId: "2026-09-19-public-v3", results };

  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");

  assert.deepEqual(data.cases[0]!.results.jev.passes[0]!.decision?.choice, choice);
  // Every pass reaches the UI: keeping only the first would discard the variance the repeats exist to show.
  assert.equal(data.cases[0]!.results.jev.passes.length, data.repetitions);
  assert.equal(data.cases[0]!.results.jev.stable, true);
  assert.equal(data.provenance.kind, "direct-choice-mixed");
  assert.match(data.provenance.description, /Jev was rerun.*direct five-way Choice.*Terra and Opus.*retained/);
  assert.equal(typeof data.summary.jev.brierScore, "number");

  const sameRun = runs.map((run) => ({ ...run, runId: "2026-09-20-public-v4" }));
  const single = buildPublishedDemoData(cases, sameRun, "2026-09-18T13:00:00.000Z");
  assert.equal(single.provenance.kind, "direct-choice");
  assert.match(single.provenance.description, /All three evaluators were recorded in one run/);
});

test("builder refuses a degenerate single-outcome run unless explicitly allowed, and publishes warnings", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns(cases);
  const allAbstain: RecordedDemoRun = {
    ...runs[0]!,
    results: runs[0]!.results.map((row) => ({ ...row, status: "valid", decision: { disposition: "insufficient_context", family: null }, correct: cases.find((item) => item.caseId === row.caseId)!.expected.disposition === "insufficient_context", error: null }))
  };
  assert.throws(() => buildPublishedDemoData(cases, [allAbstain, runs[1]!, runs[2]!], "2026-09-18T13:00:00.000Z"), /degenerate run: jev returned a single outcome/);
  const data = buildPublishedDemoData(cases, [allAbstain, runs[1]!, runs[2]!], "2026-09-18T13:00:00.000Z", { allowDegenerate: true });
  assert.equal(data.summary.jev.degenerate, true);
  assert.match(data.warnings.join("\n"), /jev returned a single outcome/);
  assert.match(data.warnings.join("\n"), /terra did not report token usage/);
});

test("builder labels archived threshold-routed Jev data", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  // The fixture Jev run carries Choice data; strip it to simulate a threshold-routed artifact.
  const runs = (await loadFixtureRuns(cases)).map((run) => ({
    ...run,
    runId: "2026-09-19-public-v2",
    results: run.evaluator === "jev" ? run.results.map((row) => row.decision === null ? row : { ...row, decision: (({ choice: _choice, ...rest }) => rest)(row.decision) }) : run.results
  }));

  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");

  assert.equal(data.provenance.kind, "archived-threshold-router");
  assert.match(data.provenance.description, /Jev \+ threshold router/);
  assert.match(data.provenance.description, /needs_deep_review.*insufficient_context/);
});
