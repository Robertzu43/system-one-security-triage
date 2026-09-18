export type Family = "injection" | "broken_access_control" | "ssrf";
export type SystemArm = "terra_all" | "jev_to_terra" | "opus_all" | "jev_to_opus";
export type Arm = SystemArm | "semgrep_raw" | "semgrep_to_jev";
export type ControlledEvaluator = "jev" | "terra" | "opus";
export type FinalOutcome = "alert" | "no_alert" | "manual_review";
export type Decision = "supported" | "contradicted" | "inconclusive";
export type Repetition = 1 | 2 | 3 | 4 | 5;
export type Interval = readonly [lower: number, upper: number];
export type ContextResolution = Record<"middleware" | "upstreamDataFlow" | "sanitizers" | "authorization" | "callPath", "resolved" | "unresolved">;

export interface Candidate {
  candidateId: string;
  repositoryId: string;
  sources: Array<"semgrep" | "ast">;
  familyHint: Family;
  rootOperation: string;
  primarySpan: { path: string; startLine: number; endLine: number; text: string };
  relatedSpans: Array<{ path: string; startLine: number; endLine: number; text: string; relationship: "calls" | "flows_to" | "guards" }>;
  contextResolution: ContextResolution;
}

export interface TargetInstance { targetId: string; repositoryId: string; family: Family; cwe: string; severity: "low" | "medium" | "high" | "critical"; vulnerable: boolean; rawSemgrepMatched: boolean; }
export interface ControlledPrediction { packetId: string; evaluator: ControlledEvaluator; repetition: Repetition; decision: "vulnerable" | "safe" | "abstain"; family: Family; evidenceSpanIds: string[]; matchedTargetId: string | null; }
export interface PredictionOutcome { predictionId: string; deduplicationId: string; targetId: string | null; repositoryId: string; arm: Arm; repetition: Repetition; finalOutcome: FinalOutcome; retainedAlert: boolean; adjudication: "confirmed" | "not_vulnerable" | "insufficient_evidence"; }
export interface EfficiencyRecord { repositoryId: string; arm: SystemArm; repetition: Repetition; costUsd: number; coldLatencyMs: number; }
export interface DiscoveryMatch { findingId: string; source: "semgrep" | "ast"; targetId: string; adjudication: "confirmed" | "not_vulnerable" | "insufficient_evidence"; }
export interface ScoreInput { targets: TargetInstance[]; predictions: PredictionOutcome[]; efficiency: EfficiencyRecord[]; discoveryMatches: DiscoveryMatch[]; controlled: ControlledPrediction[]; validGroundTruth: boolean; actualCostAvailable: boolean; }
export interface ScoreReport { claim1: { terraAllRecall: number; cascadeRecall: number; recallDifference: number }; claim2: { rawRecall: number; filteredRecall: number; filteredPrecision: number; unresolvedWorkload: number }; claim3: { additionalValidatedYield: number }; controlled: Record<ControlledEvaluator, { recall: number; precision: number; abstentionRate: number }>; efficiency: { costRatio: number | null; latencyRatio: number }; }
export interface PrimaryInference { recall: { estimate: number; interval: Interval; decision: Decision }; cost: { estimate: number | null; interval: Interval | null; decision: Decision }; latency: { estimate: number; interval: Interval; decision: Decision }; primaryDecision: Decision; }

const families = ["injection", "broken_access_control", "ssrf"] as const;
const arms = ["terra_all", "jev_to_terra", "opus_all", "jev_to_opus", "semgrep_raw", "semgrep_to_jev"] as const;
const systemArms = arms.slice(0, 4) as readonly SystemArm[];
const evaluators = ["jev", "terra", "opus"] as const;
const outcomes = ["alert", "no_alert", "manual_review"] as const;
const adjudications = ["confirmed", "not_vulnerable", "insufficient_evidence"] as const;
const severities = ["low", "medium", "high", "critical"] as const;

function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function string(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`); return value; }
function boolean(value: unknown, label: string): boolean { if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`); return value; }
function number(value: unknown, label: string): number { if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${label} must be a finite number`); return value; }
function oneOf<T extends string>(value: unknown, values: readonly T[], label: string): T { if (typeof value !== "string" || !values.includes(value as T)) throw new Error(`${label} is invalid`); return value as T; }
function repetition(value: unknown, label: string): Repetition { if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 5) throw new Error(`${label} must be 1..5`); return value as Repetition; }
function array(value: unknown, label: string): unknown[] { if (!Array.isArray(value)) throw new Error(`${label} must be an array`); return value; }

export function parseScoreInput(value: unknown): ScoreInput {
  const root = object(value, "score input");
  const targets = array(root.targets, "targets").map((value, index) => {
    const row = object(value, `targets[${index}]`);
    return { targetId: string(row.targetId, "targetId"), repositoryId: string(row.repositoryId, "repositoryId"), family: oneOf(row.family, families, "family"), cwe: string(row.cwe, "cwe"), severity: oneOf(row.severity, severities, "severity"), vulnerable: boolean(row.vulnerable, "vulnerable"), rawSemgrepMatched: boolean(row.rawSemgrepMatched, "rawSemgrepMatched") };
  });
  const targetById = new Map(targets.map((target) => [target.targetId, target]));
  if (targetById.size !== targets.length) throw new Error("targetId must be unique");
  const repositoryIds = new Set(targets.map((target) => target.repositoryId));
  const predictions = array(root.predictions, "predictions").map((value, index) => {
    const row = object(value, `predictions[${index}]`);
    const targetId = row.targetId === null ? null : string(row.targetId, "targetId");
    const prediction = { predictionId: string(row.predictionId, "predictionId"), deduplicationId: string(row.deduplicationId, "deduplicationId"), targetId, repositoryId: string(row.repositoryId, "repositoryId"), arm: oneOf(row.arm, arms, "arm"), repetition: repetition(row.repetition, "repetition"), finalOutcome: oneOf(row.finalOutcome, outcomes, "finalOutcome"), retainedAlert: boolean(row.retainedAlert, "retainedAlert"), adjudication: oneOf(row.adjudication, adjudications, "adjudication") };
    if (!repositoryIds.has(prediction.repositoryId)) throw new Error("prediction has unknown repository");
    if (targetId !== null && targetById.get(targetId)?.repositoryId !== prediction.repositoryId) throw new Error("prediction target/repository mismatch");
    return prediction;
  });
  const predictionKeys = new Set(predictions.map((row) => `${row.deduplicationId}\u0000${row.arm}\u0000${row.repetition}`));
  if (predictionKeys.size !== predictions.length) throw new Error("duplicate deduplicationId/arm/repetition");
  const efficiency = array(root.efficiency, "efficiency").map((value, index) => {
    const row = object(value, `efficiency[${index}]`);
    const costUsd = number(row.costUsd, "costUsd"); const coldLatencyMs = number(row.coldLatencyMs, "coldLatencyMs");
    if (costUsd < 0 || coldLatencyMs < 0) throw new Error("cost and latency must be non-negative");
    const repositoryId = string(row.repositoryId, "repositoryId");
    if (!repositoryIds.has(repositoryId)) throw new Error("efficiency record has unknown repository");
    return { repositoryId, arm: oneOf(row.arm, systemArms, "arm"), repetition: repetition(row.repetition, "repetition"), costUsd, coldLatencyMs };
  });
  const efficiencyKeys = new Set(efficiency.map((row) => `${row.repositoryId}\u0000${row.arm}\u0000${row.repetition}`));
  if (efficiencyKeys.size !== efficiency.length) throw new Error("duplicate efficiency repository/arm/repetition");
  const discoveryMatches = array(root.discoveryMatches, "discoveryMatches").map((value, index) => {
    const row = object(value, `discoveryMatches[${index}]`); const targetId = string(row.targetId, "targetId");
    if (!targetById.has(targetId)) throw new Error("discovery match has unknown target");
    return { findingId: string(row.findingId, "findingId"), source: oneOf(row.source, ["semgrep", "ast"] as const, "source"), targetId, adjudication: oneOf(row.adjudication, adjudications, "adjudication") };
  });
  const controlled = array(root.controlled, "controlled").map((value, index) => {
    const row = object(value, `controlled[${index}]`); const matchedTargetId = row.matchedTargetId === null ? null : string(row.matchedTargetId, "matchedTargetId");
    if (matchedTargetId !== null && !targetById.has(matchedTargetId)) throw new Error("controlled prediction has unknown target");
    const family = oneOf(row.family, families, "family");
    if (matchedTargetId !== null && targetById.get(matchedTargetId)?.family !== family) throw new Error("controlled prediction family mismatch");
    return { packetId: string(row.packetId, "packetId"), evaluator: oneOf(row.evaluator, evaluators, "evaluator"), repetition: repetition(row.repetition, "repetition"), decision: oneOf(row.decision, ["vulnerable", "safe", "abstain"] as const, "decision"), family, evidenceSpanIds: array(row.evidenceSpanIds, "evidenceSpanIds").map((span) => string(span, "evidenceSpanId")), matchedTargetId };
  });
  return { targets, predictions, efficiency, discoveryMatches, controlled, validGroundTruth: boolean(root.validGroundTruth, "validGroundTruth"), actualCostAvailable: boolean(root.actualCostAvailable, "actualCostAvailable") };
}
