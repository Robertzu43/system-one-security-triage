import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildPublishedDemoData } from "./dashboard.js";
import { parseRecordedDemoRun, type RecordedDemoRun } from "./demo-record.js";
import { loadDemoCases, type DemoCase } from "./demo.js";

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
});

test("builder preserves Jev Choice probabilities in published case data", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns(cases);
  const choice = {
    selected: "vulnerable_injection" as const,
    confidence: 0.82,
    probabilities: { vulnerable_injection: 0.86, vulnerable_broken_access_control: 0.02, vulnerable_ssrf: 0.01, safe: 0.06, insufficient_context: 0.05 }
  };
  const first = runs[0]!.results[0]!;
  runs[0] = { ...runs[0]!, results: [{ ...first, decision: { ...first.decision!, choice } }, ...runs[0]!.results.slice(1)] };

  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");

  assert.deepEqual(data.cases[0]!.results.jev.decision?.choice, choice);
});
