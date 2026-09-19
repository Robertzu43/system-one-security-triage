import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Family } from "./contracts.js";
import { corpusHash, type RecordedDemoRun } from "./demo-record.js";
import { summarizeDemoResults, type DemoCase, type DemoDecision, type DemoEvaluator, type DemoResult, type DemoSummary } from "./demo.js";
import { canonicalJson } from "./jsonl.js";

export interface PublishedDemoData {
  schemaVersion: 1;
  generatedAt: string;
  corpusHash: string;
  caseCount: 100;
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
  }>;
  summary: Record<DemoEvaluator, DemoSummary>;
  cases: Array<{
    caseId: string;
    family: Family;
    state: Record<string, unknown>;
    expected: DemoDecision;
    results: Record<DemoEvaluator, DemoResult>;
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
    if (run.mode !== "live-recorded" || run.caseCount !== 100 || run.results.length !== 100) throw new Error(`incomplete recorded run for ${run.evaluator}`);
  }
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
    recorded: true,
    synthetic: true,
    warnings,
    provenance: provenance(orderedRuns),
    sourceArtifacts: orderedRuns.map(({ evaluator, runId, artifactSha256 }) => ({ evaluator, runId, artifactSha256 })),
    models: orderedRuns.map(({ evaluator, provider, modelId, runner, runnerVersion, recordedAt }) => ({ evaluator, provider, modelId, runner, runnerVersion, recordedAt })),
    summary,
    cases: cases.map(({ caseId, family, state, expected }) => ({
      caseId,
      family,
      state,
      expected,
      results: Object.fromEntries(orderedRuns.map((run) => {
        const result = run.results.find((item) => item.caseId === caseId);
        if (result === undefined) throw new Error(`missing ${run.evaluator} result for ${caseId}`);
        return [run.evaluator, result];
      })) as Record<DemoEvaluator, DemoResult>
    }))
  };
}

export async function writePublishedDemoData(path: string, data: PublishedDemoData): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${canonicalJson(data)}\n`, "utf8");
}
