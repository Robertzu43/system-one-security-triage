import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { loadDemoCases, runDemo, type DemoAdapter } from "./demo.js";
import { createJevDemoAdapter, createReasoningDemoAdapter } from "./demo-live.js";
import { stableHash } from "./jsonl.js";

test("100-case fixture has the frozen family and disposition matrix", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(cases.length, 100);
  const expected = {
    injection: { vulnerable: 12, safe: 11, insufficient_context: 11 },
    broken_access_control: { vulnerable: 11, safe: 11, insufficient_context: 11 },
    ssrf: { vulnerable: 11, safe: 11, insufficient_context: 11 }
  } as const;
  for (const [family, dispositions] of Object.entries(expected)) {
    for (const [disposition, count] of Object.entries(dispositions)) {
      assert.equal(cases.filter((item) => item.family === family && item.expected.disposition === disposition).length, count, `${family}/${disposition}`);
    }
  }
});

test("100-case fixture uses unique IDs and distinct canonical evidence", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(new Set(cases.map((item) => item.caseId)).size, 100);
  assert.equal(new Set(cases.map((item) => stableHash(item.state))).size, 100);
});

test("all evaluators receive identical canonical evidence and failures stay visible", async () => {
  const cases = (await loadDemoCases("test/fixtures/demo-cases.json")).slice(0, 2);
  const seen = new Map<string, string[]>();
  const adapter = (name: "jev" | "terra" | "opus", fail = false): DemoAdapter => ({
    name,
    metadata: { provider: "Fixture", modelId: name, runner: "fixture", runnerVersion: "1" },
    evaluate: async (stateJson, item) => {
      seen.set(item.caseId, [...(seen.get(item.caseId) ?? []), stateJson]);
      if (fail && item.caseId === cases[1]?.caseId) throw new Error("fixture failure");
      return { ...item.expected };
    }
  });

  const report = await runDemo(cases, [adapter("jev"), adapter("terra", true), adapter("opus")], "fixture");
  for (const payloads of seen.values()) assert.equal(new Set(payloads).size, 1);
  assert.equal(report.results.length, 6);
  assert.equal(report.results.filter((row) => row.status === "error").length, 1);
  assert.equal(report.summary.terra!.errors, 1);
  assert.equal(report.summary.terra!.accuracy, 0.5);
  assert.equal(report.summary.jev!.accuracy, 1);
  assert.equal(report.mode, "fixture");
});

test("triage accuracy scores disposition and vulnerable family", async () => {
  const item = (await loadDemoCases("test/fixtures/demo-cases.json"))[0]!;
  const adapter: DemoAdapter = { name: "jev", metadata: { provider: "Fixture", modelId: "jev", runner: "fixture", runnerVersion: "1" }, evaluate: async () => ({ disposition: "vulnerable", family: "injection" }) };
  const report = await runDemo([item], [adapter], "fixture");
  assert.equal(report.results[0]?.correct, true);
  assert.equal(report.summary.jev!.vulnerabilityRecall, 1);
  assert.deepEqual(Object.keys(report.summary), ["jev"]);
});

test("fixture CLI prints an explicitly simulated three-model report", async () => {
  const result = await new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
    execFile(process.execPath, ["dist/src/cli.js", "demo", "--fixture", "test/fixtures/demo-cases.json"], { cwd: process.cwd() }, (error, stdout, stderr) => {
      const code = (error as (NodeJS.ErrnoException & { code?: number }) | null)?.code;
      done({ code: typeof code === "number" ? code : error === null ? 0 : 1, stdout, stderr });
    });
  });
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.mode, "fixture");
  assert.equal(report.disclaimer, "SIMULATED ADAPTERS — not model benchmark results");
  assert.equal(report.caseCount, 100);
  assert.equal("results" in report, false);
  assert.deepEqual(Object.keys(report.summary).sort(), ["jev", "opus", "terra"]);
  assert.equal((await readFile("test/fixtures/demo-cases.json", "utf8")).includes("expected"), true);
});

test("live CLI fails before calls when the selected Jev credential is absent", async () => {
  const result = await new Promise<{ code: number; stderr: string }>((done) => {
    const env = { ...process.env };
    delete env.TYPESAFE_API_KEY;
    execFile(process.execPath, ["dist/src/cli.js", "demo", "--live", "--models", "jev", "--fixture", "test/fixtures/demo-cases.json"], { cwd: process.cwd(), env }, (error, _stdout, stderr) => {
      const code = (error as (NodeJS.ErrnoException & { code?: number }) | null)?.code;
      done({ code: typeof code === "number" ? code : error === null ? 0 : 1, stderr });
    });
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /TYPESAFE_API_KEY is required/);
});

test("live adapters normalize native decisions while preserving the exact evidence string", async () => {
  const item = (await loadDemoCases("test/fixtures/demo-cases.json"))[0]!;
  const stateJson = JSON.stringify(item.state);
  let jevState = "";
  const jev = createJevDemoAdapter(async (state) => {
    jevState = state;
    return {
      kind: "judgment", model: "jev-1.13.0", usage: { input_tokens: 7, output_tokens: 3 },
      answers: {
        untrusted_influence: { type: "noul", noul: 0.99 }, reaches_sensitive_operation: { type: "noul", noul: 0.99 }, validation_blocks_attack: { type: "noul", noul: 0.01 },
        crosses_authorization_boundary: { type: "noul", noul: 0.01 }, authorization_enforced: { type: "noul", noul: 0.01 }, security_impact: { type: "noul", noul: 0.99 },
        is_injection: { type: "noul", noul: 0.99 }, is_broken_access_control: { type: "noul", noul: 0.01 }, is_ssrf: { type: "noul", noul: 0.01 }, enough_context: { type: "noul", noul: 0.99 },
        exploitability: { type: "score", score: 3, confidence: 1, legend: { 0: "", 1: "", 2: "", 3: "" }, probabilities: { 0: 0, 1: 0, 2: 0, 3: 1 } }
      }
    };
  });
  const terra = createReasoningDemoAdapter("terra", "/empty", async (request) => {
    assert.equal(request.mode, "demo");
    assert.equal(request.schemaPath, "config/demo-output.schema.json");
    assert.match(request.prompt, /not evidence that a control is absent or that code is safe/);
    assert.equal(request.prompt.endsWith(stateJson), true);
    assert.equal(request.prompt.split(stateJson).length, 2);
    return { finalOutcome: "no_alert", output: { decision: "safe", family: "injection", evidence_span_ids: [] }, usage: null, usageStatus: "inconclusive", chargeUsd: null, costStatus: "inconclusive", attempts: 1, stdout: "", stderr: "", error: null };
  });
  assert.deepEqual(await jev.evaluate(stateJson, item), { disposition: "vulnerable", family: "injection", inputTokens: 7, outputTokens: 3 });
  assert.equal(jevState, stateJson);
  assert.deepEqual(await terra.evaluate(stateJson, item), { disposition: "safe", family: null });
});
