import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { TypeSafeClient } from "@typesafe-ai/sdk";
import { inventoryAst } from "./discover.js";
import type { Candidate, ControlledEvaluator, Repetition, ScoreInput } from "./contracts.js";
import { buildPublishedDemoData, writePublishedDemoData } from "./dashboard.js";
import { parseRecordedDemoRun, writeRecordedDemoRuns, type RecordedDemoRun } from "./demo-record.js";
import { loadDemoCases, runDemo, type DemoAdapter, type DemoEvaluator, type EvaluatorMetadata } from "./demo.js";
import { createJevDemoAdapter, createReasoningDemoAdapter } from "./demo-live.js";
import { judgeDemoWithJev } from "./jev.js";
import { canonicalJson } from "./jsonl.js";
import { runArm, type PublishedRun } from "./pipeline.js";
import { type ReasoningResult } from "./reasoning.js";
import { parseRouterConfig } from "./router.js";
import { bootstrapPrimary, parseScoreInput, scoreClaims } from "./scorer.js";
import { createSanitizedSnapshot } from "./sanitize.js";

type Values = Record<string, string | boolean | undefined>;

function required(values: Values, name: string): string {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}
function fixtureReview(): ReasoningResult {
  return {
    finalOutcome: "alert", output: { decision: "vulnerable", family: "injection", evidence_span_ids: ["s1"] }, usage: { inputTokens: 0, outputTokens: 0 },
    usageStatus: "available", chargeUsd: null, costStatus: "inconclusive", attempts: 1, stdout: "", stderr: "", error: null
  };
}

function scoreInputFromFixture(bundle: PublishedRun, candidates: readonly Candidate[]): ScoreInput {
  const rows = bundle.records.map((record) => ({ record, candidate: candidates.find((value) => value.candidateId === record.candidateId) }));
  if (rows.length === 0 || rows.some((row) => row.candidate === undefined)) throw new Error("fixture run produced an unscoreable record");
  const scoreable = rows as Array<{ record: PublishedRun["records"][number]; candidate: Candidate }>;
  const repetitions = [1, 2, 3, 4, 5] as const;
  const evaluators = ["jev", "terra", "opus"] as const satisfies readonly ControlledEvaluator[];
  const targetId = (candidate: Candidate): string => `fixture-target-${candidate.candidateId}`;
  const predictions = repetitions.flatMap((repetition) => scoreable.flatMap(({ record, candidate }) => ["terra_all", "jev_to_terra", "semgrep_to_jev"].map((arm, index) => ({
    predictionId: `${bundle.runId}-${candidate.candidateId}-${arm}-${repetition}`, deduplicationId: `${record.packetId}-${index}`, targetId: targetId(candidate),
    repositoryId: candidate.repositoryId, arm: arm as "terra_all" | "jev_to_terra" | "semgrep_to_jev", repetition, finalOutcome: record.finalOutcome,
    retainedAlert: record.finalOutcome !== "no_alert", adjudication: "confirmed" as const
  }))));
  const repositoryIds = [...new Set(scoreable.map(({ candidate }) => candidate.repositoryId))];
  const efficiency = repositoryIds.flatMap((repositoryId) => repetitions.flatMap((repetition) => [
    { repositoryId, arm: "terra_all" as const, repetition, costUsd: 2, coldLatencyMs: bundle.publication.durationMs },
    { repositoryId, arm: "jev_to_terra" as const, repetition, costUsd: 1, coldLatencyMs: bundle.publication.durationMs }
  ]));
  const controlled = evaluators.flatMap((evaluator) => repetitions.flatMap((repetition: Repetition) => scoreable.map(({ record, candidate }) => ({
    packetId: record.packetId, evaluator, repetition, decision: "vulnerable" as const, family: candidate.familyHint, evidenceSpanIds: ["s1"], matchedTargetId: targetId(candidate)
  }))));
  return {
    targets: scoreable.map(({ candidate }) => ({ targetId: targetId(candidate), repositoryId: candidate.repositoryId, family: candidate.familyHint, cwe: "CWE-fixture", severity: "medium", vulnerable: true, rawSemgrepMatched: true })),
    predictions, efficiency, discoveryMatches: scoreable.map(({ candidate }) => ({ findingId: candidate.candidateId, source: "semgrep", targetId: targetId(candidate), adjudication: "confirmed" })),
    controlled, validGroundTruth: true, actualCostAvailable: true
  };
}

async function sanitize(values: Values): Promise<unknown> {
  return createSanitizedSnapshot(required(values, "source"), required(values, "destination"), { sourceCommit: required(values, "commit") });
}
async function discover(values: Values): Promise<unknown> {
  return inventoryAst(required(values, "snapshot"));
}
async function score(values: Values): Promise<unknown> {
  const input = parseScoreInput(JSON.parse(await readFile(required(values, "input"), "utf8")));
  return { report: scoreClaims(input), inference: bootstrapPrimary(input) };
}
async function runFixture(values: Values): Promise<unknown> {
  if (values.evaluator !== "fixture") throw new Error("run requires --evaluator fixture; live evaluators are not enabled by this CLI");
  const source = resolve(required(values, "fixture"));
  const root = await mkdtemp(join(tmpdir(), "triage-fixture-"));
  const snapshot = join(root, "snapshot");
  const artifactPath = join(root, "run.jsonl");
  try {
    await createSanitizedSnapshot(source, snapshot, { sourceCommit: "fixture" });
    const routerConfig = parseRouterConfig(JSON.parse(await readFile("config/router.dev.json", "utf8")));
    const candidates = await inventoryAst(snapshot);
    const input = {
      runId: typeof values["run-id"] === "string" ? values["run-id"] : "fixture", arm: "jev_to_terra" as const, artifactPath,
      snapshot, sourceCommit: "fixture", candidates, prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 1, toolBudget: 1, cacheSeries: "cold" as const, verifyColdCache: async () => ({ verifier: "fixture", cleared: ["tool", "result"] }),
      jevJudge: async () => ({ kind: "abstain" as const, error: { name: "Fixture", message: "fixture-only Jev evaluator" } }),
      runReasoning: async () => fixtureReview()
    };
    const bundle = await runArm(input);
    const first = await readFile(artifactPath, "utf8");
    let immutableSecondWriteRejected = false;
    try { await runArm(input); } catch (error) {
      immutableSecondWriteRejected = error instanceof Error && /already exists/.test(error.message) && await readFile(artifactPath, "utf8") === first;
    }
    if (!immutableSecondWriteRejected) throw new Error("fixture failed to prove immutable publication");
    const fixtureScore = scoreClaims(parseScoreInput(scoreInputFromFixture(bundle, candidates)));
    return { ...bundle, fixtureScore, scoreSourceRunId: bundle.runId, scoreSourceRecordCount: bundle.records.length, immutableSecondWriteRejected };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function selectedEvaluators(values: Values): DemoEvaluator[] {
  const selected = (typeof values.models === "string" ? values.models : "jev,terra").split(",") as DemoEvaluator[];
  if (selected.length === 0 || selected.some((name) => !["jev", "terra", "opus"].includes(name)) || new Set(selected).size !== selected.length) throw new Error("--models must be a unique comma-separated subset of jev,terra,opus");
  return selected;
}

function requireCredentials(selected: readonly DemoEvaluator[]): void {
  if (selected.includes("jev") && !(process.env.TYPESAFE_API_KEY?.trim())) throw new Error("TYPESAFE_API_KEY is required for live Jev evaluation");
}

async function liveAdapters(selected: readonly DemoEvaluator[], emptySnapshot: string, outputDirectory: string): Promise<DemoAdapter[]> {
  const adapters: DemoAdapter[] = [];
  if (selected.includes("jev")) {
    const client = new TypeSafeClient({ timeout: 30_000, retry: { maxRetries: 0 }, logLevel: "off" });
    adapters.push(createJevDemoAdapter((stateJson) => judgeDemoWithJev(stateJson, client)));
  }
  if (selected.includes("terra")) adapters.push(createReasoningDemoAdapter("terra", emptySnapshot, undefined, { outputDirectory }));
  if (selected.includes("opus")) adapters.push(createReasoningDemoAdapter("opus", emptySnapshot, undefined, { outputDirectory }));
  return adapters;
}

async function demo(values: Values): Promise<unknown> {
  const output = (report: Awaited<ReturnType<typeof runDemo>>): unknown => values.details === true ? report : ({ mode: report.mode, disclaimer: report.disclaimer, caseCount: report.caseCount, summary: report.summary });
  const cases = await loadDemoCases(required(values, "fixture"));
  if (values.live === true) {
    const selected = selectedEvaluators(values);
    requireCredentials(selected);
    const root = await mkdtemp(join(tmpdir(), "triage-demo-"));
    const emptySnapshot = join(root, "empty");
    await mkdir(emptySnapshot);
    try {
      const adapters = await liveAdapters(selected, emptySnapshot, root);
      return output(await runDemo(cases, adapters, "live"));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
  const adapters = (["jev", "terra", "opus"] as const).map((name): DemoAdapter => ({
    name,
    metadata: { provider: "Fixture", modelId: name, runner: "fixture", runnerVersion: "1" },
    evaluate: async (_stateJson, item) => ({ ...item.expected, inputTokens: 0, outputTokens: 0, costUsd: 0 })
  }));
  return output(await runDemo(cases, adapters, "fixture"));
}

async function demoRecord(values: Values): Promise<unknown> {
  const fixture = required(values, "fixture");
  const selected = selectedEvaluators(values);
  const runId = required(values, "run-id");
  const outputRoot = required(values, "output");
  requireCredentials(selected);
  const cases = await loadDemoCases(fixture);
  const root = await mkdtemp(join(tmpdir(), "triage-demo-record-"));
  const emptySnapshot = join(root, "empty");
  await mkdir(emptySnapshot);
  try {
    const adapters = await liveAdapters(selected, emptySnapshot, root);
    const report = await runDemo(cases, adapters, "live", 3);
    return writeRecordedDemoRuns({
      cases,
      report,
      metadata: Object.fromEntries(adapters.map((adapter) => [adapter.name, adapter.metadata])) as Partial<Record<DemoEvaluator, EvaluatorMetadata>>,
      runId,
      recordedAt: new Date().toISOString(),
      outputRoot
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function dashboardBuild(values: Values): Promise<unknown> {
  const cases = await loadDemoCases(required(values, "fixture"));
  const runDirectory = required(values, "run-dir");
  const output = required(values, "output");
  const runs: RecordedDemoRun[] = [];
  for (const evaluator of ["jev", "terra", "opus"] as const) {
    try {
      runs.push(parseRecordedDemoRun(JSON.parse(await readFile(join(runDirectory, `${evaluator}.json`), "utf8")), cases));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  const generatedAt = runs.map((run) => run.recordedAt).sort().at(-1) ?? "1970-01-01T00:00:00.000Z";
  const data = buildPublishedDemoData(cases, runs, generatedAt);
  await writePublishedDemoData(output, data);
  return { output: basename(output), corpusHash: data.corpusHash, sourceHashes: Object.fromEntries(data.sourceArtifacts.map(({ evaluator, artifactSha256 }) => [evaluator, artifactSha256])) };
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ args: process.argv.slice(2), allowPositionals: true, strict: true, options: {
    source: { type: "string" }, destination: { type: "string" }, commit: { type: "string" }, snapshot: { type: "string" }, input: { type: "string" }, output: { type: "string" }, fixture: { type: "string" }, evaluator: { type: "string" }, "run-id": { type: "string" }, "run-dir": { type: "string" }, live: { type: "boolean" }, models: { type: "string" }, details: { type: "boolean" }
  } });
  const command = positionals[0];
  const result = command === "sanitize" ? await sanitize(values) : command === "discover" ? await discover(values) : command === "score" ? await score(values) : command === "run" ? await runFixture(values) : command === "demo" ? await demo(values) : command === "demo-record" ? await demoRecord(values) : command === "dashboard-build" ? await dashboardBuild(values) : (() => { throw new Error("expected sanitize, discover, run, score, demo, demo-record, or dashboard-build"); })();
  process.stdout.write(`${canonicalJson(result)}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
