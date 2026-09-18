import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { bootstrapPrimary, parseScoreInput, scoreClaims } from "./scorer.js";

function primaryFixture(cascadeHits: number, actualCostAvailable = true) {
  const repositories = ["repo-a", "repo-b"];
  const targets = repositories.map((repositoryId, index) => ({ targetId: `target-${index}`, repositoryId, family: "injection", cwe: "CWE-89", severity: "high", vulnerable: true, rawSemgrepMatched: true }));
  const predictions = [...targets.flatMap((target) => ["terra_all", "jev_to_terra"].flatMap((arm) => [1, 2, 3, 4, 5].filter((repetition) => arm === "terra_all" || repetition <= cascadeHits).map((repetition) => ({ predictionId: `${arm}-${target.targetId}-${repetition}`, deduplicationId: `${arm}-${target.targetId}-${repetition}`, targetId: target.targetId, repositoryId: target.repositoryId, arm, repetition, finalOutcome: "alert", retainedAlert: true, adjudication: "confirmed" })))), { predictionId: "semgrep-alert", deduplicationId: "semgrep-alert", targetId: "target-0", repositoryId: "repo-a", arm: "semgrep_to_jev", repetition: 1, finalOutcome: "alert", retainedAlert: true, adjudication: "confirmed" }];
  const efficiency = repositories.flatMap((repositoryId) => ["terra_all", "jev_to_terra"].flatMap((arm) => [1, 2, 3, 4, 5].map((repetition) => ({ repositoryId, arm, repetition, costUsd: arm === "terra_all" ? 2 : 1, coldLatencyMs: arm === "terra_all" ? 2 : 1 }))));
  const controlled = ["jev", "terra", "opus"].map((evaluator) => ({ packetId: evaluator, evaluator, repetition: 1, decision: "vulnerable", family: "injection", evidenceSpanIds: ["span"], matchedTargetId: "target-0" }));
  return parseScoreInput({ targets, predictions, efficiency, discoveryMatches: [], controlled, validGroundTruth: true, actualCostAvailable });
}

test("uses target-nested recall and ratio-of-mean repository efficiency", async () => {
  const raw = JSON.parse(await readFile("test/fixtures/scoring.json", "utf8"));
  const report = scoreClaims(parseScoreInput(raw));
  assert.equal(report.claim1.terraAllRecall, 1);
  assert.equal(report.claim1.cascadeRecall, 0.55);
  assert.equal(report.claim1.recallDifference, -0.45);
  assert.equal(report.efficiency.costRatio, 2 / 3);
  assert.equal(report.efficiency.latencyRatio, 5 / 7);
  assert.equal(report.claim3.additionalValidatedYield, 1);
});

test("classifies decision boundaries", async () => {
  const { classifyDifference, classifyRatio } = await import("./scorer.js");
  assert.equal(classifyDifference([-0.01, 0]), "supported");
  assert.equal(classifyDifference([-0.03, -0.02]), "contradicted");
  assert.equal(classifyDifference([-0.03, -0.01]), "inconclusive");
  assert.equal(classifyRatio([0.5, 0.9]), "supported");
  assert.equal(classifyRatio([1, 1.2]), "contradicted");
  assert.equal(classifyRatio([0.9, 1]), "inconclusive");
});

test("keeps repository clusters intact in a degenerate bootstrap", () => {
  const inference = bootstrapPrimary(primaryFixture(5), 100, 7);
  assert.deepEqual(inference.recall.interval, [0, 0]);
  assert.deepEqual(inference.cost.interval, [0.5, 0.5]);
  assert.deepEqual(inference.latency.interval, [0.5, 0.5]);
  assert.equal(inference.primaryDecision, "supported");
});

test("combines primary decisions conservatively", () => {
  assert.equal(bootstrapPrimary(primaryFixture(0), 100, 7).primaryDecision, "contradicted");
  assert.equal(bootstrapPrimary(primaryFixture(5, false), 100, 7).primaryDecision, "inconclusive");
});

test("rejects duplicate, mismatched, and invalid measurement records", () => {
  const input = primaryFixture(5);
  const prediction = input.predictions[0]!;
  const measurement = input.efficiency[0]!;
  assert.throws(() => parseScoreInput({ ...input, predictions: [...input.predictions, { ...prediction }] }), /duplicate/);
  assert.throws(() => parseScoreInput({ ...input, predictions: [{ ...prediction, repositoryId: "repo-b" }] }), /mismatch/);
  assert.throws(() => parseScoreInput({ ...input, efficiency: [{ ...measurement, costUsd: -1 }] }), /non-negative/);
  assert.throws(() => parseScoreInput({ ...input, efficiency: [{ ...measurement, repetition: 6 }] }), /1\.\.5/);
});

test("rejects a zero denominator for filtered precision", () => {
  const input = primaryFixture(5);
  assert.throws(() => scoreClaims({ ...input, predictions: input.predictions.filter((prediction) => prediction.arm !== "semgrep_to_jev") }), /zero denominator/);
});

test("rejects an empty controlled evaluator", () => {
  const input = primaryFixture(5);
  assert.throws(() => scoreClaims({ ...input, controlled: [] }), /zero denominator/);
});

test("rejects unmatched predictions from unknown repositories", () => {
  const input = primaryFixture(5);
  const alert = input.predictions[0]!;
  assert.throws(() => parseScoreInput({ ...input, predictions: [...input.predictions, { ...alert, predictionId: "unknown-repository", deduplicationId: "unknown-repository", targetId: null, repositoryId: "unknown-repository" }] }), /unknown repository/);
});
