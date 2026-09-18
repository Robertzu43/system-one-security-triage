import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { basename } from "node:path";
import type { TypeSafeClient } from "@typesafe-ai/sdk";
import { deduplicateCandidates } from "./discover.js";
import type { Candidate, Family, JevJudgment, RouteOutcome, RouterConfig, SystemArm } from "./contracts.js";
import { judgeWithJev } from "./jev.js";
import { canonicalJson, writeJsonlExclusive } from "./jsonl.js";
import { buildEvidencePacket, type EvidencePacket } from "./packets.js";
import { type ReasoningConfig, type ReasoningRequest, type ReasoningResult, runReasoningReview } from "./reasoning.js";
import { parseRouterConfig, route } from "./router.js";

export type BenchmarkArm = SystemArm | "semgrep_raw" | "semgrep_to_jev";
export type CacheSeries = "cold" | "warm";
export interface ColdCacheEvidence { readonly verifier: string; readonly cleared: readonly string[]; }
export interface RunRecord {
  readonly candidateId: string;
  readonly packetId: string;
  readonly finalOutcome: "alert" | "no_alert" | "manual_review";
  readonly retainedAlert: boolean;
  readonly route: RouteOutcome | null;
  readonly reasoning: ReasoningResult | null;
}
export interface RunBundle {
  readonly runId: string;
  readonly arm: BenchmarkArm;
  readonly cacheSeries: CacheSeries;
  readonly primaryEligible: boolean;
  readonly ineligibilityReasons: string[];
  readonly coldCacheEvidence: ColdCacheEvidence | null;
  readonly discoveryMs: number;
  readonly packetMs: number;
  readonly backoffMs: number;
  readonly computeDurationMs: number;
  readonly modelAttempts: number;
  readonly escalations: number;
  readonly usage: { status: "available"; inputTokens: number; outputTokens: number } | { status: "inconclusive"; inputTokens: null; outputTokens: null };
  readonly cost: { status: "available" | "inconclusive"; providerChargeUsd: number | null };
  readonly errors: Array<{ candidateId: string; kind: string; message: string }>;
  readonly records: RunRecord[];
}
export interface PublicationReceipt {
  readonly artifact: string;
  readonly artifactSha256: string;
  readonly durationMs: number;
  readonly p95LatencyMs: number;
}
export type PublishedRun = RunBundle & { readonly publication: PublicationReceipt };
export interface RunArmInput {
  readonly runId: string;
  readonly arm: BenchmarkArm;
  readonly artifactPath: string;
  readonly snapshot: string;
  readonly sourceCommit: string;
  readonly candidates?: readonly Candidate[];
  readonly discover?: () => Promise<readonly Candidate[]>;
  readonly prompt: string;
  readonly schemaPath: string;
  readonly routerConfig: RouterConfig;
  readonly timeoutMs: number;
  readonly tokenBudget: number;
  readonly toolBudget: number;
  readonly cacheSeries?: CacheSeries;
  readonly verifyColdCache?: () => Promise<ColdCacheEvidence | null>;
  readonly providerChargeUsd?: number;
  readonly opusModel?: string;
  readonly reasoningConfig?: ReasoningConfig;
  readonly jevClient?: Pick<TypeSafeClient, "systemOne">;
  readonly jevJudge?: (packet: EvidencePacket) => Promise<JevJudgment>;
  readonly runReasoning?: (request: ReasoningRequest, config: ReasoningConfig) => Promise<ReasoningResult>;
}
export interface ControlledComparisonInput {
  readonly packet: EvidencePacket;
  readonly family: Family;
  readonly emptySnapshot: string;
  readonly schemaPath: string;
  readonly timeoutMs: number;
  readonly tokenBudget: number;
  readonly toolBudget: number;
  readonly opusModel?: string;
  readonly providerChargeUsd?: number;
  readonly judgeJev?: (packetJson: string) => Promise<{ readonly route: RouteOutcome; readonly family: Family; readonly evidence_span_ids: string[] }>;
  readonly jevJudge?: (packet: EvidencePacket) => Promise<JevJudgment>;
  readonly jevClient?: Pick<TypeSafeClient, "systemOne">;
  readonly routerConfig?: RouterConfig;
  readonly reasoningConfig?: ReasoningConfig;
  readonly runReasoning?: (request: ReasoningRequest, config: ReasoningConfig) => Promise<ReasoningResult>;
}
type StructuredDecision = { readonly decision: "vulnerable" | "safe" | "abstain"; readonly family: Family; readonly evidence_span_ids: string[] };
export interface ControlledComparison {
  readonly packetJson: string;
  readonly jev: StructuredDecision;
  readonly terra: StructuredDecision;
  readonly opus: StructuredDecision | null;
}

function elapsed(start: number): number { return Math.round((performance.now() - start) * 1000) / 1000; }
function candidatePacket(candidate: Candidate, commit: string): EvidencePacket {
  return buildEvidencePacket({ repositoryId: candidate.repositoryId, commit, sources: candidate.sources, entryKind: candidate.rootOperation === "route" ? "route" : "call", primarySpan: candidate.primarySpan, relatedSpans: candidate.relatedSpans, contextResolution: candidate.contextResolution }, 0);
}
function evaluator(arm: BenchmarkArm): "terra" | "opus" | null {
  if (arm === "terra_all" || arm === "jev_to_terra") return "terra";
  if (arm === "opus_all" || arm === "jev_to_opus") return "opus";
  return null;
}
function cascade(arm: BenchmarkArm): boolean { return arm === "jev_to_terra" || arm === "jev_to_opus"; }
function isSemgrepFilter(arm: BenchmarkArm): boolean { return arm === "semgrep_to_jev"; }
function isSemgrepRaw(arm: BenchmarkArm): boolean { return arm === "semgrep_raw"; }
function reviewRequest(input: Pick<RunArmInput, "snapshot" | "schemaPath" | "timeoutMs" | "tokenBudget" | "toolBudget" | "prompt" | "providerChargeUsd" | "opusModel">, model: "terra" | "opus", packet: EvidencePacket, mode: "agentic" | "controlled" = "agentic"): ReasoningRequest {
  const packetJson = canonicalJson(packet);
  return {
    evaluator: model, mode, prompt: mode === "controlled" ? packetJson : input.prompt === "" ? packetJson : `${input.prompt}\n${packetJson}`,
    snapshot: input.snapshot, schemaPath: input.schemaPath, timeoutMs: input.timeoutMs, tokenBudget: input.tokenBudget, toolBudget: input.toolBudget,
    ...(model === "opus" ? { model: input.opusModel } : {}),
    ...(input.providerChargeUsd === undefined ? {} : { providerChargeUsd: input.providerChargeUsd })
  };
}
async function jev(packet: EvidencePacket, input: Pick<RunArmInput, "jevJudge" | "jevClient">): Promise<JevJudgment> {
  if (input.jevJudge !== undefined) return input.jevJudge(packet);
  if (input.jevClient !== undefined) return judgeWithJev(packet, input.jevClient);
  return { kind: "abstain", error: { name: "Error", message: "Jev client not configured" } };
}
function controlledDecision(result: ReasoningResult, family: Family): StructuredDecision {
  return result.output ?? { decision: "abstain", family, evidence_span_ids: [] };
}
function familyFromJev(judgment: JevJudgment, fallback: Family): Family {
  if (judgment.kind === "abstain") return fallback;
  const values = [["injection", judgment.answers.is_injection.noul], ["broken_access_control", judgment.answers.is_broken_access_control.noul], ["ssrf", judgment.answers.is_ssrf.noul]] as const;
  return values.reduce((best, value) => value[1] > best[1] ? value : best)[0];
}

export function mapJevRouteToDecision(outcome: RouteOutcome): "vulnerable" | "safe" | "abstain" {
  return outcome === "likely_vulnerability" ? "vulnerable" : outcome === "likely_safe" ? "safe" : "abstain";
}
export function p95Latency(values: readonly number[]): number {
  if (values.length === 0 || values.some((value) => !Number.isFinite(value) || value < 0)) throw new Error("latencies must be non-empty non-negative finite numbers");
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor((ordered.length - 1) * 0.95)]!;
}

export async function runArm(input: RunArmInput): Promise<PublishedRun> {
  const cacheSeries = input.cacheSeries ?? "cold";
  const verifiedCache = cacheSeries === "cold" && input.verifyColdCache !== undefined ? await input.verifyColdCache() : null;
  const coldCacheEvidence = verifiedCache === null ? null : { verifier: verifiedCache.verifier, cleared: [...verifiedCache.cleared] };
  const coldCacheVerified = coldCacheEvidence !== null && coldCacheEvidence.verifier.length > 0 && coldCacheEvidence.cleared.length > 0 && coldCacheEvidence.cleared.every((value) => value.length > 0);
  const started = performance.now();
  const discovered = input.discover === undefined ? input.candidates ?? [] : await input.discover();
  const discoveryMs = elapsed(started);
  const packetStarted = performance.now();
  const candidates = deduplicateCandidates([...discovered]).filter((candidate) => !isSemgrepRaw(input.arm) && !isSemgrepFilter(input.arm) || candidate.sources.includes("semgrep"));
  const packets = candidates.map((candidate) => ({ candidate, packet: candidatePacket(candidate, input.sourceCommit) }));
  const packetMs = elapsed(packetStarted);
  const config = parseRouterConfig(input.routerConfig);
  const model = evaluator(input.arm);
  if (model === "opus" && input.opusModel === undefined) throw new Error("Opus arm requires a frozen full model ID");
  const runner = input.runReasoning ?? runReasoningReview;
  const reasoningConfig = input.reasoningConfig ?? {};
  const records: RunRecord[] = [];
  let modelAttempts = 0;
  let escalations = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let usageAvailable = true;
  let costAvailable = true;
  let providerChargeUsd = 0;
  const harnessFailures = new Set(["budget_unverifiable", "version_mismatch", "unsupported_platform"]);
  const harnessIneligibility = new Set<string>();
  const errors: Array<{ candidateId: string; kind: string; message: string }> = [];

  for (const { candidate, packet } of packets) {
    if (isSemgrepRaw(input.arm)) {
      records.push({ candidateId: candidate.candidateId, packetId: packet.packetId, finalOutcome: "alert", retainedAlert: true, route: null, reasoning: null });
      continue;
    }
    let routed: RouteOutcome | null = null;
    let needsReasoning = model !== null && !cascade(input.arm);
    if (cascade(input.arm) || isSemgrepFilter(input.arm)) {
      routed = route(packet, await jev(packet, input), config);
      if (routed === "likely_vulnerability") {
        records.push({ candidateId: candidate.candidateId, packetId: packet.packetId, finalOutcome: "alert", retainedAlert: true, route: routed, reasoning: null });
        continue;
      }
      if (routed === "likely_safe") {
        records.push({ candidateId: candidate.candidateId, packetId: packet.packetId, finalOutcome: "no_alert", retainedAlert: false, route: routed, reasoning: null });
        continue;
      }
      if (isSemgrepFilter(input.arm)) {
        records.push({ candidateId: candidate.candidateId, packetId: packet.packetId, finalOutcome: "alert", retainedAlert: true, route: routed, reasoning: null });
        continue;
      }
      needsReasoning = true;
      escalations += 1;
    }
    if (!needsReasoning || model === null) throw new Error(`arm ${input.arm} cannot review candidate`);
    const result = await runner(reviewRequest(input, model, packet), reasoningConfig);
    modelAttempts += result.attempts;
    if (result.usageStatus === "inconclusive" || result.usage === null) usageAvailable = false;
    else { inputTokens += result.usage.inputTokens; outputTokens += result.usage.outputTokens; }
    if (result.costStatus === "inconclusive" || result.chargeUsd === null) costAvailable = false;
    else providerChargeUsd += result.chargeUsd;
    if (result.error !== null) {
      errors.push({ candidateId: candidate.candidateId, kind: result.error.kind, message: result.error.message });
      if (harnessFailures.has(result.error.kind)) harnessIneligibility.add(`reasoning_${result.error.kind}`);
    }
    records.push({ candidateId: candidate.candidateId, packetId: packet.packetId, finalOutcome: result.finalOutcome, retainedAlert: result.finalOutcome !== "no_alert", route: routed, reasoning: result });
  }

  const computeDurationMs = elapsed(started);
  const ineligibilityReasons = [...(cacheSeries === "cold" ? coldCacheVerified ? [] : ["cold_cache_unverified"] : ["warm_cache_series"]), ...harnessIneligibility];
  const bundle = {
    runId: input.runId, arm: input.arm, cacheSeries, primaryEligible: ineligibilityReasons.length === 0, ineligibilityReasons, coldCacheEvidence,
    discoveryMs, packetMs, backoffMs: 0, computeDurationMs,
    modelAttempts, escalations, usage: usageAvailable ? { status: "available" as const, inputTokens, outputTokens } : { status: "inconclusive" as const, inputTokens: null, outputTokens: null }, cost: costAvailable && modelAttempts > 0 ? { status: "available" as const, providerChargeUsd } : { status: "inconclusive" as const, providerChargeUsd: null }, errors, records
  } satisfies RunBundle;
  await writeJsonlExclusive(input.artifactPath, [bundle]);
  const durationMs = elapsed(started);
  const artifactContents = `${canonicalJson(bundle)}\n`;
  const publication = { artifact: basename(input.artifactPath), artifactSha256: createHash("sha256").update(artifactContents).digest("hex"), durationMs, p95LatencyMs: p95Latency([durationMs]) } satisfies PublicationReceipt;
  await writeJsonlExclusive(`${input.artifactPath}.receipt.jsonl`, [publication]);
  return { ...bundle, publication };
}

export async function runControlledComparison(input: ControlledComparisonInput): Promise<ControlledComparison> {
  const packetJson = canonicalJson(input.packet);
  const config = input.reasoningConfig ?? {};
  const runner = input.runReasoning ?? runReasoningReview;
  const routeConfig = input.routerConfig === undefined ? undefined : parseRouterConfig(input.routerConfig);
  let jevResult: StructuredDecision;
  if (input.judgeJev !== undefined) {
    const judged = await input.judgeJev(packetJson);
    jevResult = { decision: mapJevRouteToDecision(judged.route), family: judged.family, evidence_span_ids: [...judged.evidence_span_ids] };
  } else {
    const judgment = await jev(input.packet, input);
    const jevRoute = routeConfig === undefined ? "insufficient_context" : route(input.packet, judgment, routeConfig);
    jevResult = { decision: mapJevRouteToDecision(jevRoute), family: familyFromJev(judgment, input.family), evidence_span_ids: [] };
  }
  const base = { snapshot: input.emptySnapshot, schemaPath: input.schemaPath, timeoutMs: input.timeoutMs, tokenBudget: input.tokenBudget, toolBudget: input.toolBudget, prompt: "", ...(input.providerChargeUsd === undefined ? {} : { providerChargeUsd: input.providerChargeUsd }) };
  const terra = await runner(reviewRequest(base, "terra", input.packet, "controlled"), config);
  const opus = input.opusModel === undefined ? null : await runner(reviewRequest({ ...base, opusModel: input.opusModel }, "opus", input.packet, "controlled"), config);
  return { packetJson, jev: jevResult, terra: controlledDecision(terra, input.family), opus: opus === null ? null : controlledDecision(opus, input.family) };
}
