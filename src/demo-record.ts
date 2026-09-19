import { lstat, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { isCorrectDecision, parseDemoDecision, type DemoCase, type DemoEvaluator, type DemoReport, type DemoResult, type EvaluatorMetadata } from "./demo.js";
import { stableHash, writeJsonlExclusive } from "./jsonl.js";

export interface RecordedDemoRun {
  schemaVersion: 1;
  runId: string;
  recordedAt: string;
  mode: "live-recorded";
  evaluator: DemoEvaluator;
  provider: EvaluatorMetadata["provider"];
  modelId: string;
  runner: string;
  runnerVersion: string;
  /** Hash of the prompt text this evaluator received; runs may only be pooled when it matches. */
  promptSpecHash: string;
  /** Commit that produced the run, so a result can be traced to the code that generated it. */
  gitSha: string;
  corpusHash: string;
  caseCount: number;
  results: DemoResult[];
  artifactSha256: string;
}

export interface RecordDemoInput {
  cases: readonly DemoCase[];
  report: DemoReport;
  runId: string;
  recordedAt: string;
  outputRoot: string;
  gitSha: string;
  metadata: Readonly<Partial<Record<DemoEvaluator, EvaluatorMetadata>>>;
}

const evaluators = new Set<DemoEvaluator>(["jev", "terra", "opus"]);
const providers = new Set<EvaluatorMetadata["provider"]>(["TypeSafe", "OpenAI", "Anthropic", "Fixture"]);
const localPath = /(?:^|[\s("'=])(?:\/(?!\/|\s)|[A-Za-z]:\\|\\\\)/;
const secretText = /(?:TYPESAFE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|authorization:\s*bearer)/i;

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function publicStrings(value: unknown): void {
  if (typeof value === "string") {
    if (localPath.test(value)) throw new Error("recorded run contains a local path");
    if (secretText.test(value)) throw new Error("recorded run contains secret text");
  } else if (Array.isArray(value)) {
    value.forEach(publicStrings);
  } else if (value !== null && typeof value === "object") {
    Object.values(value).forEach(publicStrings);
  }
}

function isoTimestamp(value: unknown): string {
  const timestamp = text(value, "recordedAt");
  try {
    if (new Date(timestamp).toISOString() !== timestamp) throw new Error();
  } catch {
    throw new Error("recordedAt must be an exact ISO timestamp");
  }
  return timestamp;
}

function latency(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error(`${label} is invalid`);
  return value;
}

function parseResult(value: unknown, index: number, evaluator: DemoEvaluator, item: DemoCase): DemoResult {
  const label = `results[${index}]`;
  const row = record(value, label);
  const resultEvaluator = text(row.evaluator, `${label}.evaluator`) as DemoEvaluator;
  if (!evaluators.has(resultEvaluator) || resultEvaluator !== evaluator) throw new Error(`${label} evaluator mismatch`);
  const status = row.status;
  if (status !== "valid" && status !== "error") throw new Error(`${label}.status is invalid`);
  if (typeof row.correct !== "boolean") throw new Error(`${label}.correct must be boolean`);
  const latencyMs = latency(row.latencyMs, `${label}.latencyMs`);
  // Older artifacts predate model-call timing; they parse with null rather than a fabricated zero.
  const modelLatencyMs = row.modelLatencyMs === undefined || row.modelLatencyMs === null ? null : latency(row.modelLatencyMs, `${label}.modelLatencyMs`);
  if (status === "error") {
    if (row.decision !== null || row.correct || typeof row.error !== "string" || row.error.length === 0) throw new Error(`${label} has an invalid error outcome`);
    return { caseId: item.caseId, evaluator, status, decision: null, correct: false, latencyMs, modelLatencyMs, error: row.error };
  }
  if (row.error !== null) throw new Error(`${label} has an error for a valid outcome`);
  const decision = parseDemoDecision(row.decision, `${label}.decision`);
  const correct = isCorrectDecision(decision, item.expected);
  if (row.correct !== correct) throw new Error(`${label}.correct is inconsistent`);
  return { caseId: item.caseId, evaluator, status, decision, correct, latencyMs, modelLatencyMs, error: null };
}

/** Hash over the model-visible corpus and its labels; private ledger metadata is excluded. */
export function corpusHash(cases: readonly DemoCase[]): string {
  return stableHash(cases.map(({ caseId, family, state, expected }) => ({ caseId, family, state, expected })));
}

export function parseRecordedDemoRun(value: unknown, cases: readonly DemoCase[]): RecordedDemoRun {
  publicStrings(value);
  const row = record(value, "recorded run");
  if (row.schemaVersion !== 1 || row.mode !== "live-recorded") throw new Error("recorded run schema or mode is invalid");
  const runId = text(row.runId, "runId");
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(runId)) throw new Error("runId is invalid");
  const evaluator = text(row.evaluator, "evaluator") as DemoEvaluator;
  if (!evaluators.has(evaluator)) throw new Error("evaluator is invalid");
  const provider = text(row.provider, "provider") as EvaluatorMetadata["provider"];
  if (!providers.has(provider)) throw new Error("provider is invalid");
  const hash = text(row.corpusHash, "corpusHash");
  if (hash !== corpusHash(cases)) throw new Error("corpus hash mismatch");
  if (row.caseCount !== cases.length) throw new Error("recorded run must have complete case coverage");
  if (!Array.isArray(row.results)) throw new Error("results must be an array");
  const byId = new Map(cases.map((item) => [item.caseId, item]));
  const seen = new Set<string>();
  for (const [index, result] of row.results.entries()) {
    const caseId = text(record(result, `results[${index}]`).caseId, `results[${index}].caseId`);
    if (seen.has(caseId)) throw new Error(`duplicate case: ${caseId}`);
    if (!byId.has(caseId)) throw new Error(`unknown case: ${caseId}`);
    seen.add(caseId);
  }
  if (seen.size !== cases.length) throw new Error("recorded run must have complete case coverage");
  const results = row.results.map((result, index) => {
    const caseId = (result as Record<string, unknown>).caseId as string;
    return parseResult(result, index, evaluator, byId.get(caseId)!);
  });
  const artifactSha256 = text(row.artifactSha256, "artifactSha256");
  const { artifactSha256: _artifactSha256, ...body } = row;
  if (!/^[0-9a-f]{64}$/.test(artifactSha256) || stableHash(body) !== artifactSha256) throw new Error("artifact hash mismatch");
  return {
    schemaVersion: 1,
    runId,
    recordedAt: isoTimestamp(row.recordedAt),
    mode: "live-recorded",
    evaluator,
    provider,
    modelId: text(row.modelId, "modelId"),
    runner: text(row.runner, "runner"),
    runnerVersion: text(row.runnerVersion, "runnerVersion"),
    promptSpecHash: text(row.promptSpecHash, "promptSpecHash"),
    gitSha: text(row.gitSha, "gitSha"),
    corpusHash: hash,
    caseCount: cases.length,
    results,
    artifactSha256
  };
}

async function assertMissing(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error(`artifact already exists: ${path}`);
}

export async function writeRecordedDemoRuns(input: RecordDemoInput): Promise<RecordedDemoRun[]> {
  if (input.report.mode !== "live" || input.report.caseCount !== input.cases.length) throw new Error("recording requires a complete live demo report");
  const selected = (["jev", "terra", "opus"] as const).filter((evaluator) => input.report.results.some((result) => result.evaluator === evaluator));
  const directory = join(input.outputRoot, input.runId);
  await mkdir(directory, { recursive: true });
  const paths = selected.map((evaluator) => join(directory, `${evaluator}.json`));
  await Promise.all(paths.map(assertMissing));
  const runs = selected.map((evaluator) => {
    const details = input.metadata[evaluator];
    if (details === undefined) throw new Error(`metadata is required for ${evaluator}`);
    const body = {
      schemaVersion: 1 as const,
      runId: input.runId,
      recordedAt: input.recordedAt,
      mode: "live-recorded" as const,
      evaluator,
      ...details,
      gitSha: input.gitSha,
      corpusHash: corpusHash(input.cases),
      caseCount: input.cases.length,
      results: input.report.results.filter((result) => result.evaluator === evaluator)
    };
    return parseRecordedDemoRun({ ...body, artifactSha256: stableHash(body) }, input.cases);
  });
  await Promise.all(runs.map((run, index) => writeJsonlExclusive(paths[index]!, [run])));
  return runs;
}
