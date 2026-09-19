import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadDemoCases, runDemo, type DemoCase, type DemoResult } from "./demo.js";
import { corpusHash, parseRecordedDemoRun, writeRecordedDemoRuns, type RecordedDemoRun } from "./demo-record.js";
import { stableHash } from "./jsonl.js";

const metadata = {
  jev: { provider: "TypeSafe", modelId: "jev-1.13.0", runner: "@typesafe-ai/sdk", runnerVersion: "0.6.0" },
  terra: { provider: "OpenAI", modelId: "gpt-5.6-terra", runner: "codex-cli", runnerVersion: "0.147.0" },
  opus: { provider: "Anthropic", modelId: "claude-opus-4-6", runner: "claude-code", runnerVersion: "2.1.277" }
} as const;

function validRecordedRunFixture(cases: readonly DemoCase[]): RecordedDemoRun {
  const results: DemoResult[] = cases.map((item) => ({
    caseId: item.caseId,
    evaluator: "jev",
    status: "valid",
    decision: item.expected,
    correct: true,
    latencyMs: 1,
    error: null
  }));
  const body = {
    schemaVersion: 1 as const,
    runId: "2026-09-18-demo",
    recordedAt: "2026-09-18T12:00:00.000Z",
    mode: "live-recorded" as const,
    evaluator: "jev" as const,
    ...metadata.jev,
    corpusHash: corpusHash(cases),
    caseCount: cases.length,
    results
  };
  return { ...body, artifactSha256: stableHash(body) };
}

test("recorded runs are complete, hashed, parseable, and immutable", async () => {
  const root = await mkdtemp(join(tmpdir(), "demo-record-test-"));
  try {
    const cases = await loadDemoCases("test/fixtures/demo-cases.json");
    const adapters = (["jev", "terra", "opus"] as const).map((name) => ({
      name,
      metadata: metadata[name],
      evaluate: async (_state: string, item: typeof cases[number]) => item.expected
    }));
    const report = await runDemo(cases, adapters, "live");
    const runs = await writeRecordedDemoRuns({ cases, report, metadata, runId: "2026-09-18-demo", recordedAt: "2026-09-18T12:00:00.000Z", outputRoot: root });
    assert.equal(runs.length, 3);
    assert.equal(runs[0]?.corpusHash, corpusHash(cases));
    assert.equal(runs[0]?.caseCount, 100);
    assert.equal(parseRecordedDemoRun(JSON.parse(await readFile(join(root, "2026-09-18-demo", "jev.json"), "utf8")), cases).evaluator, "jev");
    await assert.rejects(() => writeRecordedDemoRuns({ cases, report, metadata, runId: "2026-09-18-demo", recordedAt: "2026-09-18T12:00:00.000Z", outputRoot: root }), /already exists/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("recorded run parser rejects incomplete, duplicate, unknown, and path-bearing results", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const base = validRecordedRunFixture(cases);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: base.results.slice(1) }, cases), /complete case coverage/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [...base.results, base.results[0]] }, cases), /duplicate case/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0]!, caseId: "unknown" }, ...base.results.slice(1)] }, cases), /unknown case/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0]!, error: "/Users/alice/.claude.json" }, ...base.results.slice(1)] }, cases), /local path/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0]!, error: "runner wrote /tmp/session/output.json" }, ...base.results.slice(1)] }, cases), /local path/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0]!, error: "C:\\Users\\alice\\secret" }, ...base.results.slice(1)] }, cases), /local path/);
  assert.throws(() => parseRecordedDemoRun({ ...base, runnerVersion: "OPENAI_API_KEY=secret" }, cases), /secret text/);
});
