import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Family } from "./contracts.js";
import { corpusHash, type RecordedDemoRun } from "./demo-record.js";
import { costOf, type PriceTable } from "./pricing.js";
import { summarizeDemoResults, type DemoCase, type DemoDecision, type DemoEvaluator, type DemoResult, type DemoSummary } from "./demo.js";
import { canonicalJson } from "./jsonl.js";

export interface PublishedDemoData {
  schemaVersion: 1;
  generatedAt: string;
  corpusHash: string;
  caseCount: 100;
  /** Passes over the corpus; every case carries one decision per pass. */
  repetitions: number;
  recorded: true;
  synthetic: true;
  /** Human-readable caveats derived from the data itself, shown on the dashboard. */
  warnings: string[];
  provenance: {
    kind: "direct-choice" | "direct-choice-mixed" | "archived-threshold-router" | "fixture";
    description: string;
  };
  sourceArtifacts: Array<{ evaluator: DemoEvaluator; runId: string; artifactSha256: string }>;
  models: Array<{
    evaluator: DemoEvaluator;
    provider: string;
    modelId: string;
    runner: string;
    runnerVersion: string;
    recordedAt: string;
    promptSpecHash: string;
    gitSha: string;
  }>;
  summary: Record<DemoEvaluator, DemoSummary>;
  economics: Economics[];
  stability: Record<DemoEvaluator, { stableCases: number; flippedCases: number; meanAgreement: number }>;
  cases: Array<{
    caseId: string;
    family: Family;
    state: Record<string, unknown>;
    expected: DemoDecision;
    results: Record<DemoEvaluator, CaseOutcome>;
  }>;
}

const evaluators = ["jev", "terra", "opus"] as const;

function provenance(runs: readonly RecordedDemoRun[]): PublishedDemoData["provenance"] {
  if (runs.every((run) => run.runId === "dashboard-runs")) return {
    kind: "fixture",
    description: "Fixture preview using simulated saved outputs. These are not live model benchmark results."
  };
  const jev = runs.find((run) => run.evaluator === "jev");
  const choices = jev?.results.filter((result) => result.status === "valid" && result.decision?.choice !== undefined).length ?? 0;
  const valid = jev?.results.filter((result) => result.status === "valid").length ?? 0;
  if (choices > 0 && choices !== valid) throw new Error("Jev run mixes direct Choice and threshold-routed results");
  const sameRun = new Set(runs.map((run) => run.runId)).size === 1;
  if (choices > 0 && sameRun) return {
    kind: "direct-choice",
    description: "All three evaluators were recorded in one run over the same 100-case corpus. Jev answered one direct five-way Choice; Terra and Opus returned structured final answers."
  };
  return choices > 0 ? {
    kind: "direct-choice-mixed",
    description: "Jev was rerun with one direct five-way Choice. Terra and Opus are retained recorded controls from an earlier run over the same 100-case corpus."
  } : {
    kind: "archived-threshold-router",
    description: "Archived Jev + threshold router run. The router's needs_deep_review outcome was collapsed into insufficient_context in the published comparison."
  };
}

export interface BuildOptions {
  /** Publish even when an evaluator returned one outcome for every case. Off by default. */
  allowDegenerate?: boolean;
  /** Rate cards, applied at build time so re-pricing never requires re-recording. */
  prices?: PriceTable;
}

/** What a run cost, and what each right answer cost. Never a silent zero. */
export interface Economics {
  evaluator: DemoEvaluator;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costUsd: number | null;
  costPerCorrectUsd: number | null;
  /** "provider" when the CLI reported the charge itself, "rate-card" when derived, "unpriced" otherwise. */
  basis: "provider" | "rate-card" | "unpriced";
}

/** One evaluator's answers for one case, across every pass. */
export interface CaseOutcome {
  /** Every pass, in order. Keeping all of them is the point of repeating the corpus. */
  passes: DemoResult[];
  /** The answer given most often; ties resolve to the earliest pass. */
  modal: string;
  /** Share of passes that gave the modal answer: 1 when the model never changed its mind. */
  agreement: number;
  /** True when every pass gave the same answer. */
  stable: boolean;
  /** Passes that matched the expected label. */
  correctPasses: number;
}

function answerOf(result: DemoResult): string {
  if (result.status === "error") return "error";
  return result.decision === null ? "error" : `${result.decision.disposition}${result.decision.family === null ? "" : `:${result.decision.family}`}`;
}

function caseOutcome(passes: readonly DemoResult[]): CaseOutcome {
  const counts = new Map<string, number>();
  for (const pass of passes) counts.set(answerOf(pass), (counts.get(answerOf(pass)) ?? 0) + 1);
  const modal = [...counts].reduce((best, entry) => entry[1] > best[1] ? entry : best)[0];
  const agreement = (counts.get(modal) ?? 0) / passes.length;
  return { passes: [...passes], modal, agreement, stable: counts.size === 1, correctPasses: passes.filter((pass) => pass.correct).length };
}

function economicsFor(run: RecordedDemoRun, prices: PriceTable | undefined): Economics {
  const sum = (key: "inputTokens" | "outputTokens" | "cacheReadTokens" | "cacheWriteTokens"): number =>
    run.results.reduce((total, result) => total + (result.decision?.[key] ?? 0), 0);
  const usage = { inputTokens: sum("inputTokens"), outputTokens: sum("outputTokens"), cacheReadTokens: sum("cacheReadTokens"), cacheWriteTokens: sum("cacheWriteTokens") };
  // A charge the provider stated beats one derived from a rate card: it already accounts for the
  // cache tier actually used, which a rate card can only guess at.
  const reported = run.results.reduce((total, result) => total + (result.decision?.costUsd ?? 0), 0);
  const derived = prices === undefined ? { status: "unpriced" as const } : costOf(prices, run.modelId, usage);
  const costUsd = reported > 0 ? reported : derived.status === "available" ? derived.costUsd : null;
  const basis = reported > 0 ? "provider" as const : costUsd === null ? "unpriced" as const : "rate-card" as const;
  const correct = run.results.filter((result) => result.correct).length;
  return { evaluator: run.evaluator, ...usage, costUsd, costPerCorrectUsd: costUsd === null || correct === 0 ? null : costUsd / correct, basis };
}

export function buildPublishedDemoData(cases: readonly DemoCase[], runs: readonly RecordedDemoRun[], generatedAt: string, options: BuildOptions = {}): PublishedDemoData {
  if (cases.length !== 100) throw new Error("dashboard requires exactly 100 cases");
  if (new Date(generatedAt).toISOString() !== generatedAt) throw new Error("generatedAt must be an exact ISO timestamp");
  const byEvaluator = new Map<DemoEvaluator, RecordedDemoRun>();
  for (const run of runs) {
    if (byEvaluator.has(run.evaluator)) throw new Error(`duplicate evaluator: ${run.evaluator}`);
    byEvaluator.set(run.evaluator, run);
  }
  if (runs.length !== 3 || evaluators.some((evaluator) => !byEvaluator.has(evaluator))) throw new Error("dashboard requires jev, terra, and opus");
  const expectedHash = corpusHash(cases);
  const orderedRuns = evaluators.map((evaluator) => byEvaluator.get(evaluator)!);
  for (const run of orderedRuns) {
    if (run.corpusHash !== expectedHash) throw new Error(`corpus hash mismatch for ${run.evaluator}`);
    // Each case appears once per repetition, so a five-pass run carries 500 results over 100 cases.
    if (run.mode !== "live-recorded" || run.caseCount !== 100 || run.results.length !== 100 * run.repetitions) throw new Error(`incomplete recorded run for ${run.evaluator}`);
  }
  // corpusHash stops runs over different corpora being pooled; this stops runs over different
  // prompts being pooled, which would otherwise read as a model difference rather than an edit.
  const passes = new Set(orderedRuns.map((run) => run.repetitions));
  if (passes.size > 1) throw new Error("evaluators were recorded with different repetition counts; metrics would weight them unequally");
  const reasoningPrompts = new Set(orderedRuns.filter((run) => run.evaluator !== "jev").map((run) => run.promptSpecHash));
  if (reasoningPrompts.size > 1) throw new Error("Terra and Opus were recorded against different prompts; re-record both against one prompt before publishing");
  const summary = Object.fromEntries(orderedRuns.map((run) => [run.evaluator, summarizeDemoResults(cases, run.results, [run.evaluator])[run.evaluator]!])) as Record<DemoEvaluator, DemoSummary>;
  const warnings: string[] = [];
  for (const evaluator of evaluators) {
    const rows = summary[evaluator];
    if (rows.degenerate) {
      const message = `${evaluator} returned a single outcome for all 100 cases; this run measures the harness or policy, not the model.`;
      if (options.allowDegenerate !== true) throw new Error(`degenerate run: ${message} Re-record, or pass --allow-degenerate to publish with a warning.`);
      warnings.push(message);
    }
    if (rows.errors > 0) warnings.push(`${evaluator} recorded ${rows.errors} explicit error${rows.errors === 1 ? "" : "s"}; they count as incorrect in every metric.`);
    if (rows.inputTokens === null) warnings.push(`${evaluator} did not report token usage; cost is unknown, not zero.`);
    if (rows.modelLatencyP50Ms === null) warnings.push(`${evaluator} has no model-only latency; the latency shown is end-to-end including CLI startup.`);
  }
  return {
    schemaVersion: 1,
    generatedAt,
    corpusHash: expectedHash,
    caseCount: 100,
    repetitions: orderedRuns[0]!.repetitions,
    recorded: true,
    synthetic: true,
    warnings,
    provenance: provenance(orderedRuns),
    sourceArtifacts: orderedRuns.map(({ evaluator, runId, artifactSha256 }) => ({ evaluator, runId, artifactSha256 })),
    models: orderedRuns.map(({ evaluator, provider, modelId, runner, runnerVersion, recordedAt, promptSpecHash, gitSha }) => ({ evaluator, provider, modelId, runner, runnerVersion, recordedAt, promptSpecHash, gitSha })),
    summary,
    economics: orderedRuns.map((run) => economicsFor(run, options.prices)),
    stability: Object.fromEntries(orderedRuns.map((run) => {
      // How often the model gave the same answer to the same evidence. A model that flips on
      // identical input is a different risk from one that is simply wrong, and one pass hides it.
      const outcomes = cases.map((item) => caseOutcome(run.results.filter((result) => result.caseId === item.caseId)));
      return [run.evaluator, {
        stableCases: outcomes.filter((outcome) => outcome.stable).length,
        flippedCases: outcomes.filter((outcome) => !outcome.stable).length,
        meanAgreement: outcomes.reduce((total, outcome) => total + outcome.agreement, 0) / outcomes.length
      }];
    })) as Record<DemoEvaluator, { stableCases: number; flippedCases: number; meanAgreement: number }>,
    cases: cases.map(({ caseId, family, state, expected }) => ({
      caseId,
      family,
      state,
      expected,
      results: Object.fromEntries(orderedRuns.map((run) => {
        const passes = run.results.filter((item) => item.caseId === caseId).sort((left, right) => left.repetition - right.repetition);
        if (passes.length === 0) throw new Error(`missing ${run.evaluator} result for ${caseId}`);
        return [run.evaluator, caseOutcome(passes)];
      })) as Record<DemoEvaluator, CaseOutcome>
    }))
  };
}

export async function writePublishedDemoData(path: string, data: PublishedDemoData): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${canonicalJson(data)}\n`, "utf8");
}
