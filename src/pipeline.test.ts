import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
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
  usageStatus: "available" as const,
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
      timeoutMs: 1_000, tokenBudget: 200, toolBudget: 3, runReasoning, verifyColdCache: async () => ({ verifier: "fixture", cleared: ["tool", "result"] })
    };
    const all = await runArm({ ...common, runId: "terra-all", arm: "terra_all", artifactPath: join(root, "terra-all.jsonl") });
    const cascade = await runArm({ ...common, runId: "cascade", arm: "jev_to_terra", artifactPath: join(root, "cascade.jsonl"), jevJudge: async () => ({ kind: "abstain", error: { name: "Error", message: "fixture" } }) });

    assert.equal(all.records[0]?.finalOutcome, "alert");
    assert.equal(cascade.records[0]?.finalOutcome, "alert");
    assert.deepEqual(calls[0], calls[1]);
    const first = await readFile(join(root, "terra-all.jsonl"), "utf8");
    const receipt = JSON.parse(await readFile(join(root, "terra-all.jsonl.receipt.jsonl"), "utf8"));
    assert.deepEqual(receipt, all.publication);
    assert.equal(receipt.artifactSha256, createHash("sha256").update(first).digest("hex"));
    assert(receipt.durationMs >= all.computeDurationMs);
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
    packet, family: "injection", emptySnapshot: "/empty", schemaPath: "/schema", timeoutMs: 10, tokenBudget: 1, toolBudget: 1,
    judgeJev: async (packetJson: string) => { assert.equal(packetJson, resultPacketJson(packet)); return { route: "needs_deep_review", family: "injection", evidence_span_ids: ["s1"] }; },
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
  assert.deepEqual(result.jev, { decision: "abstain", family: "injection", evidence_span_ids: ["s1"] });
  assert.deepEqual(result.terra, { decision: "safe", family: "injection", evidence_span_ids: ["s1"] });
  assert.deepEqual(result.opus, { decision: "abstain", family: "injection", evidence_span_ids: ["s1"] });
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
  const bundle = JSON.parse(result.stdout) as { runId: string; immutableSecondWriteRejected: boolean; records: unknown[]; fixtureScore: { claim1: { terraAllRecall: number; cascadeRecall: number } }; scoreSourceRunId: string; scoreSourceRecordCount: number; };
  assert.equal(bundle.immutableSecondWriteRejected, true);
  assert(bundle.records.length > 0);
  assert.deepEqual(bundle.fixtureScore.claim1, { terraAllRecall: 1, cascadeRecall: 1, recallDifference: 0 });
  assert.equal(bundle.scoreSourceRunId, bundle.runId);
  assert.equal(bundle.scoreSourceRecordCount, bundle.records.length);
});

test("primary eligibility requires verified cold-cache evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "pipeline-cache-test-"));
  try {
    const { runArm } = await pipeline();
    const common = {
      candidates: [candidate], snapshot: root, sourceCommit: "0123456789abcdef", prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 200, toolBudget: 3, runReasoning: review, runId: "cache", arm: "terra_all" as const
    };
    const unverified = await runArm({ ...common, artifactPath: join(root, "unverified.jsonl") });
    const verified = await runArm({ ...common, runId: "cache-verified", artifactPath: join(root, "verified.jsonl"), verifyColdCache: async () => ({ verifier: "fixture", cleared: ["tool", "result"] }) });
    const invalidReview = async () => ({ ...await review({}), finalOutcome: "manual_review" as const, usage: null, usageStatus: "inconclusive" as const, error: { kind: "budget_unverifiable" as any, message: "fixture" } });
    const invalid = await runArm({ ...common, runId: "cache-invalid", artifactPath: join(root, "invalid.jsonl"), runReasoning: invalidReview, verifyColdCache: async () => ({ verifier: "fixture", cleared: ["tool", "result"] }) });
    assert.equal(unverified.primaryEligible, false);
    assert(unverified.ineligibilityReasons.includes("cold_cache_unverified"));
    assert.equal(verified.ineligibilityReasons.includes("cold_cache_unverified"), false);
    assert.deepEqual(verified.coldCacheEvidence, { verifier: "fixture", cleared: ["tool", "result"] });
    assert.equal(invalid.primaryEligible, false);
    assert(invalid.ineligibilityReasons.includes("reasoning_budget_unverifiable"));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("missing reasoning usage stays inconclusive instead of becoming zero tokens", async () => {
  const root = await mkdtemp(join(tmpdir(), "pipeline-usage-test-"));
  try {
    const { runArm } = await pipeline();
    const runReasoning = async () => ({ ...await review({}), usage: null, usageStatus: "inconclusive" as const });
    const result = await runArm({
      candidates: [candidate], snapshot: root, sourceCommit: "0123456789abcdef", prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 200, toolBudget: 3, runReasoning, runId: "usage", arm: "terra_all", artifactPath: join(root, "usage.jsonl"), verifyColdCache: async () => ({ verifier: "fixture", cleared: ["tool", "result"] })
    });
    assert.deepEqual(result.usage, { status: "inconclusive", inputTokens: null, outputTokens: null });
  } finally { await rm(root, { recursive: true, force: true }); }
});

function resultPacketJson(packet: unknown): string {
  return canonicalJson(packet);
}
