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

export function buildPublishedDemoData(cases: readonly DemoCase[], runs: readonly RecordedDemoRun[], generatedAt: string): PublishedDemoData {
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
  return {
    schemaVersion: 1,
    generatedAt,
    corpusHash: expectedHash,
    caseCount: 100,
    recorded: true,
    synthetic: true,
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
