import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { canonicalJson } from "./jsonl.js";
import { buildEvidencePacket } from "./packets.js";

async function pipeline(): Promise<any> {
  return import(new URL("./pipeline.js", import.meta.url).href);
}

const routerConfig = { contextMin: 0.70, safeRiskMax: 0.20, highRiskMin: 0.80, pathMin: 0.70, controlEffectiveMin: 0.80, controlAbsentMax: 0.20, impactMin: 0.70, directExploitabilityMin: 2.50 };
const candidate = {
  candidateId: "candidate-1", repositoryId: "example/repository", sources: ["ast"] as ("ast" | "semgrep")[], familyHint: "injection" as const, rootOperation: "query",
  primarySpan: { path: "src/route.ts", startLine: 4, endLine: 4, text: "db.query(req.query.name)" }, relatedSpans: [],
  contextResolution: { middleware: "resolved" as const, upstreamDataFlow: "resolved" as const, sanitizers: "resolved" as const, authorization: "resolved" as const, callPath: "resolved" as const }
};

const review = async (request: unknown) => ({
  finalOutcome: "alert" as const,
  output: { decision: "vulnerable" as const, family: "injection" as const, evidence_span_ids: ["s1"] },
  usage: { inputTokens: 5, outputTokens: 3 }, chargeUsd: null, costStatus: "inconclusive" as const,
  attempts: 1, stdout: "", stderr: "", error: null
});

test("Terra-all and Jev-to-Terra issue byte-identical review requests and publish an immutable bundle", async () => {
  const root = await mkdtemp(join(tmpdir(), "pipeline-test-"));
  try {
    const calls: unknown[] = [];
    const runReasoning = async (request: unknown) => { calls.push(request); return review(request); };
    const { runArm } = await pipeline();
    const common = {
      candidates: [candidate], snapshot: root, sourceCommit: "0123456789abcdef", prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 200, toolBudget: 3, runReasoning
    };
    const all = await runArm({ ...common, runId: "terra-all", arm: "terra_all", artifactPath: join(root, "terra-all.jsonl") });
    const cascade = await runArm({ ...common, runId: "cascade", arm: "jev_to_terra", artifactPath: join(root, "cascade.jsonl"), jevJudge: async () => ({ kind: "abstain", error: { name: "Error", message: "fixture" } }) });

    assert.equal(all.records[0]?.finalOutcome, "alert");
    assert.equal(cascade.records[0]?.finalOutcome, "alert");
    assert.deepEqual(calls[0], calls[1]);
    const first = await readFile(join(root, "terra-all.jsonl"), "utf8");
    await assert.rejects(runArm({ ...common, runId: "terra-all", arm: "terra_all", artifactPath: join(root, "terra-all.jsonl") }), /already exists/);
    assert.equal(await readFile(join(root, "terra-all.jsonl"), "utf8"), first);
    assert.equal(all.cost.status, "inconclusive");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("controlled evaluation uses one packet-only prompt and maps Jev routes without confidence comparisons", async () => {
  const packet = buildEvidencePacket({
    repositoryId: "example/repository", commit: "0123456789abcdef", sources: ["ast"], entryKind: "call",
    primarySpan: candidate.primarySpan, relatedSpans: [], contextResolution: candidate.contextResolution
  }, 0);
  const calls: Array<{ evaluator: string; mode: string; prompt: string; snapshot: string }> = [];
  const { mapJevRouteToDecision, runControlledComparison } = await pipeline();
  const result = await runControlledComparison({
    packet, emptySnapshot: "/empty", schemaPath: "/schema", timeoutMs: 10, tokenBudget: 1, toolBudget: 1,
    judgeJev: async (packetJson: string) => { assert.equal(packetJson, resultPacketJson(packet)); return "needs_deep_review"; },
    runReasoning: async (request: { evaluator: string; mode: string; prompt: string; snapshot: string }) => {
      calls.push(request);
      return { ...await review(request), output: { decision: request.evaluator === "terra" ? "safe" as const : "abstain" as const, family: "injection" as const, evidence_span_ids: ["s1"] }, finalOutcome: request.evaluator === "terra" ? "no_alert" as const : "manual_review" as const };
    },
    opusModel: "claude-opus-4-6"
  });

  assert.equal(result.packetJson, resultPacketJson(packet));
  assert.deepEqual(calls.map(({ evaluator, mode, prompt, snapshot }) => ({ evaluator, mode, prompt, snapshot })), [
    { evaluator: "terra", mode: "controlled", prompt: resultPacketJson(packet), snapshot: "/empty" },
    { evaluator: "opus", mode: "controlled", prompt: resultPacketJson(packet), snapshot: "/empty" }
  ]);
  assert.equal(result.jev.decision, "abstain");
  assert.equal(result.terra.decision, "safe");
  assert.equal(result.opus?.decision, "abstain");
  assert.equal(mapJevRouteToDecision("likely_vulnerability"), "vulnerable");
  assert.equal(mapJevRouteToDecision("likely_safe"), "safe");
  assert.equal(mapJevRouteToDecision("needs_deep_review"), "abstain");
  assert.equal(mapJevRouteToDecision("insufficient_context"), "abstain");
});

test("Semgrep Claim 2 arms exclude AST-only candidates and retain unresolved routes", async () => {
  const root = await mkdtemp(join(tmpdir(), "pipeline-semgrep-test-"));
  try {
    const { runArm } = await pipeline();
    const astOnlyCandidate = { ...candidate, candidateId: "candidate-ast-only", primarySpan: { ...candidate.primarySpan, startLine: 5, endLine: 5, text: "db.query(req.query.other)" } };
    const semgrepCandidate = { ...candidate, candidateId: "candidate-semgrep", sources: ["semgrep"] as ("ast" | "semgrep")[] };
    const common = {
      candidates: [astOnlyCandidate, semgrepCandidate], snapshot: root, sourceCommit: "0123456789abcdef", prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 1, toolBudget: 1, jevJudge: async () => ({ kind: "abstain" as const, error: { name: "Error", message: "fixture" } })
    };
    const raw = await runArm({ ...common, runId: "raw", arm: "semgrep_raw", artifactPath: join(root, "raw.jsonl") });
    const filtered = await runArm({ ...common, runId: "filtered", arm: "semgrep_to_jev", artifactPath: join(root, "filtered.jsonl") });
    assert.equal(raw.records.length, 1);
    assert.deepEqual(filtered.records.map((record: { candidateId: string; finalOutcome: string; retainedAlert: boolean }) => [record.candidateId, record.finalOutcome, record.retainedAlert]), [[raw.records[0]?.candidateId, "alert", true]]);
    assert.equal(raw.backoffMs, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("fixture CLI completes the unpaid pipeline and verifies immutable publication", async () => {
  const result = await new Promise<{ code: number; stdout: string; stderr: string }>((done, fail) => {
    const child = execFile(process.execPath, ["dist/src/cli.js", "run", "--fixture", "test/fixtures/repository/candidates", "--evaluator", "fixture"], { cwd: process.cwd() }, (error, stdout, stderr) => {
      if (error !== null && "code" in error && typeof error.code === "number") done({ code: error.code, stdout, stderr });
      else if (error !== null) fail(error);
      else done({ code: 0, stdout, stderr });
    });
    child.unref();
  });
  assert.equal(result.code, 0, result.stderr);
  const bundle = JSON.parse(result.stdout) as { immutableSecondWriteRejected: boolean; records: unknown[]; fixtureScore: { claim1: unknown; }; };
  assert.equal(bundle.immutableSecondWriteRejected, true);
  assert(bundle.records.length > 0);
  assert(bundle.fixtureScore.claim1);
});

function resultPacketJson(packet: unknown): string {
  return canonicalJson(packet);
}
