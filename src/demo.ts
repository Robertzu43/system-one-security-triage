import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import type { Family } from "./contracts.js";
import { canonicalJson } from "./jsonl.js";

export type DemoDisposition = "vulnerable" | "safe" | "insufficient_context";
export type DemoEvaluator = "jev" | "terra" | "opus";
export type DemoChoiceLabel = "vulnerable_injection" | "vulnerable_broken_access_control" | "vulnerable_ssrf" | "safe" | "insufficient_context";

export interface DemoChoice {
  selected: DemoChoiceLabel;
  confidence: number;
  probabilities: Readonly<Record<DemoChoiceLabel, number>>;
}

export interface DemoDecision {
  disposition: DemoDisposition;
  family: Family | null;
  choice?: DemoChoice;
  inputTokens?: number;
  outputTokens?: number;
  costUsd?: number;
}

export interface DemoCase {
  caseId: string;
  family: Family;
  state: Record<string, unknown>;
  expected: DemoDecision;
  /** Private ground-truth metadata (for example which context dimensions were withheld). Never model-visible. */
  ledger: Record<string, unknown> | null;
}

export interface EvaluatorMetadata {
  provider: "TypeSafe" | "OpenAI" | "Anthropic" | "Fixture";
  modelId: string;
  runner: string;
  runnerVersion: string;
  /**
   * Hash of the exact prompt text this evaluator was given.
   *
   * corpusHash already stops two runs over different corpora being pooled, but says nothing about
   * the prompt. Without this, editing a criterion between recordings produces two runs that look
   * comparable and are not — an "accuracy improved" story that is really "the wording changed".
   */
  promptSpecHash: string;
}

/** An adapter's decision plus, when it can measure it, the time spent in the model request alone. */
export type AdapterDecision = DemoDecision & { modelLatencyMs?: number | null };

export interface DemoAdapter {
  name: DemoEvaluator;
  metadata: EvaluatorMetadata;
  evaluate(stateJson: string, item: DemoCase): Promise<AdapterDecision>;
}

export interface DemoResult {
  caseId: string;
  evaluator: DemoEvaluator;
  status: "valid" | "error";
  decision: DemoDecision | null;
  correct: boolean;
  /** End-to-end time around the adapter call, including any CLI or process overhead. */
  latencyMs: number;
  /** Time around the model request only; null when the adapter cannot separate it. */
  modelLatencyMs: number | null;
  error: string | null;
}

export interface DemoSummary {
  /** Correct disposition (and family for vulnerable) over all cases; errors count as incorrect. */
  accuracy: number;
  /** Unweighted mean of per-class recall over vulnerable, safe, and insufficient_context. */
  balancedAccuracy: number;
  classRecall: Record<DemoDisposition, number>;
  /** Vulnerable cases labeled vulnerable with any family. */
  vulnerabilityRecall: number;
  /** Vulnerable cases labeled vulnerable with the correct family. */
  vulnerabilityRecallWithFamily: number;
  /** Among vulnerable cases labeled vulnerable, the share with the correct family. */
  familyAccuracy: number | null;
  /** Among vulnerable predictions, the share whose case is vulnerable. */
  vulnerablePrecision: number | null;
  /** Vulnerable cases labeled safe. */
  falseSafeRate: number;
  /** Safe cases labeled vulnerable. */
  falsePositiveRate: number;
  errors: number;
  meanLatencyMs: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  modelLatencyP50Ms: number | null;
  modelLatencyP95Ms: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
  /** Multiclass Brier score of the five-way Choice distribution against the expected label; null unless every valid result carries a Choice. */
  brierScore: number | null;
  /** True when every result shares one status and disposition. Such a run measures the harness, not the model. */
  degenerate: boolean;
}

export interface DemoReport {
  mode: "fixture" | "live";
  disclaimer: string;
  caseCount: number;
  results: DemoResult[];
  summary: Record<string, DemoSummary>;
}

const families = new Set<Family>(["injection", "broken_access_control", "ssrf"]);
const dispositions = new Set<DemoDisposition>(["vulnerable", "safe", "insufficient_context"]);
const choiceLabels = ["vulnerable_injection", "vulnerable_broken_access_control", "vulnerable_ssrf", "safe", "insufficient_context"] as const;
const choiceLabelSet = new Set<DemoChoiceLabel>(choiceLabels);

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function probability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

export function decisionForChoice(selected: DemoChoiceLabel): Pick<DemoDecision, "disposition" | "family"> {
  switch (selected) {
    case "vulnerable_injection": return { disposition: "vulnerable", family: "injection" };
    case "vulnerable_broken_access_control": return { disposition: "vulnerable", family: "broken_access_control" };
    case "vulnerable_ssrf": return { disposition: "vulnerable", family: "ssrf" };
    case "safe": return { disposition: "safe", family: null };
    case "insufficient_context": return { disposition: "insufficient_context", family: null };
  }
}

export function parseDemoChoice(value: unknown, label: string): DemoChoice {
  const row = record(value, label);
  const selected = text(row.selected, `${label}.selected`) as DemoChoiceLabel;
  if (!choiceLabelSet.has(selected)) throw new Error(`${label}.selected is invalid`);
  if (!probability(row.confidence)) throw new Error(`${label}.confidence is invalid`);
  const values = record(row.probabilities, `${label}.probabilities`);
  if (Object.keys(values).length !== choiceLabels.length || choiceLabels.some((key) => !probability(values[key]))) throw new Error(`${label}.probabilities are invalid`);
  const probabilities = Object.fromEntries(choiceLabels.map((key) => [key, values[key] as number])) as Record<DemoChoiceLabel, number>;
  const sum = choiceLabels.reduce((total, key) => total + probabilities[key], 0);
  if (Math.abs(sum - 1) > 0.02 + Number.EPSILON * choiceLabels.length) throw new Error(`${label}.probabilities sum to ${sum}`);
  if (probabilities[selected] < Math.max(...choiceLabels.map((key) => probabilities[key]))) throw new Error(`${label}.selected option is not maximal`);
  return { selected, confidence: row.confidence, probabilities };
}

export function parseDemoDecision(value: unknown, label: string): DemoDecision {
  const row = record(value, label);
  const disposition = text(row.disposition, `${label}.disposition`) as DemoDisposition;
  if (!dispositions.has(disposition)) throw new Error(`${label}.disposition is invalid`);
  const family = row.family === null ? null : text(row.family, `${label}.family`) as Family;
  if (family !== null && !families.has(family)) throw new Error(`${label}.family is invalid`);
  if (disposition === "vulnerable" && family === null) throw new Error(`${label}.family is required for vulnerable`);
  if (disposition !== "vulnerable" && family !== null) throw new Error(`${label}.family must be null unless vulnerable`);
  const optionalNumber = (key: "inputTokens" | "outputTokens" | "costUsd"): number | undefined => {
    const number = row[key];
    if (number === undefined) return undefined;
    if (typeof number !== "number" || !Number.isFinite(number) || number < 0 || (key !== "costUsd" && !Number.isInteger(number))) throw new Error(`${label}.${key} is invalid`);
    return number;
  };
  const inputTokens = optionalNumber("inputTokens");
  const outputTokens = optionalNumber("outputTokens");
  const costUsd = optionalNumber("costUsd");
  const choice = row.choice === undefined ? undefined : parseDemoChoice(row.choice, `${label}.choice`);
  if (choice !== undefined) {
    const mapped = decisionForChoice(choice.selected);
    if (mapped.disposition !== disposition || mapped.family !== family) throw new Error(`${label}.choice is inconsistent with disposition and family`);
  }
  return {
    disposition,
    family,
    ...(choice === undefined ? {} : { choice }),
    ...(inputTokens === undefined ? {} : { inputTokens }),
    ...(outputTokens === undefined ? {} : { outputTokens }),
    ...(costUsd === undefined ? {} : { costUsd })
  };
}

/** Words that would hand a model the expected label. Applied to model-visible paths. */
export const labelLeakPattern = /(vulnerab|unsafe|insecure|insufficient|hidden|patched|fixed|cve-|exploit|\bsafe\b|[-_]safe[-_.])/i;
/** Model-visible state keys that encode the answer rather than evidence. */
export const forbiddenStateKeys = new Set(["contextResolution", "expected", "disposition", "label", "groundTruth", "ledger"]);

/** Throws when the model-visible state of a case would reveal its label. */
export function assertNoFixtureLeakage(item: Pick<DemoCase, "caseId" | "state">): void {
  const visit = (value: unknown, path: string): void => {
    if (typeof value === "string") {
      if (value.includes(item.caseId)) throw new Error(`${path} contains the case ID`);
      return;
    }
    if (Array.isArray(value)) { value.forEach((entry, index) => visit(entry, `${path}[${index}]`)); return; }
    if (value !== null && typeof value === "object") {
      for (const [key, entry] of Object.entries(value)) {
        if (forbiddenStateKeys.has(key)) throw new Error(`${path}.${key} is label-bearing metadata and must not be model-visible`);
        visit(entry, `${path}.${key}`);
      }
    }
  };
  visit(item.state, `${item.caseId}.state`);
  const spans = Array.isArray(item.state.spans) ? item.state.spans : [];
  for (const [index, span] of spans.entries()) {
    const row = record(span, `${item.caseId}.state.spans[${index}]`);
    if (typeof row.path === "string" && labelLeakPattern.test(row.path)) throw new Error(`${item.caseId}.state.spans[${index}].path leaks the label: ${row.path}`);
    if (typeof row.text === "string" && /(vulnerab|insufficient|cve-\d)/i.test(row.text)) throw new Error(`${item.caseId}.state.spans[${index}].text leaks the label`);
  }
}

export interface PathTokenSignal { token: string; count: number; label: string; share: number; }

/**
 * Model-visible path tokens that concentrate in one label.
 *
 * A word blocklist only catches words someone thought of, and a token-frequency classifier
 * cannot catch this either — filenames barely repeat across cases, so it scores at chance on a
 * corpus that a reader with world knowledge solves easily. What is measurable is concentration:
 * the real leak here was `allowlist` appearing only on safe cases and `policy` only on
 * insufficient-context ones. Any repeated token that is near-pure in one label is a shortcut
 * available to a model that reads the word, whatever a classifier scores.
 */
export function pathTokenSignals(cases: readonly DemoCase[], minimumCount = 3, maximumShare = 0.9): PathTokenSignal[] {
  const counts = new Map<string, Map<string, number>>();
  for (const item of cases) {
    const tokens = new Set((item.state.spans as Array<{ path?: unknown }>)
      .map((span) => typeof span.path === "string" ? span.path : "")
      .join(" ").toLowerCase().split(/[^a-z]+/).filter((token) => token.length > 2));
    for (const token of tokens) {
      const byLabel = counts.get(token) ?? new Map<string, number>();
      byLabel.set(item.expected.disposition, (byLabel.get(item.expected.disposition) ?? 0) + 1);
      counts.set(token, byLabel);
    }
  }
  const signals: PathTokenSignal[] = [];
  for (const [token, byLabel] of counts) {
    const count = [...byLabel.values()].reduce((sum, value) => sum + value, 0);
    if (count < minimumCount) continue;
    const [label, best] = [...byLabel].reduce((top, entry) => entry[1] > top[1] ? entry : top);
    if (best / count >= maximumShare) signals.push({ token, count, label, share: best / count });
  }
  return signals.sort((left, right) => right.count - left.count);
}

/** Throws when a repeated model-visible path token concentrates in one label. */
export function assertNoPathLabelSignal(cases: readonly DemoCase[]): void {
  const signals = pathTokenSignals(cases);
  if (signals.length > 0) throw new Error(`span path tokens predict the label: ${signals.map((signal) => `${signal.token} (${signal.count}x, ${(signal.share * 100).toFixed(0)}% ${signal.label})`).join(", ")}; rename them to carry no label signal`);
}

export async function loadDemoCases(path: string): Promise<DemoCase[]> {
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!Array.isArray(value) || value.length === 0) throw new Error("demo cases must be a non-empty array");
  const cases = value.map((item, index) => {
    const row = record(item, `cases[${index}]`);
    const family = text(row.family, `cases[${index}].family`) as Family;
    if (!families.has(family)) throw new Error(`cases[${index}].family is invalid`);
    const parsed: DemoCase = {
      caseId: text(row.caseId, `cases[${index}].caseId`),
      family,
      state: record(row.state, `cases[${index}].state`),
      expected: parseDemoDecision(row.expected, `cases[${index}].expected`),
      ledger: row.ledger === undefined || row.ledger === null ? null : record(row.ledger, `cases[${index}].ledger`)
    };
    assertNoFixtureLeakage(parsed);
    return parsed;
  });
  if (new Set(cases.map((item) => item.caseId)).size !== cases.length) throw new Error("caseId must be unique");
  assertNoPathLabelSignal(cases);
  return cases;
}

export function isCorrectDecision(actual: DemoDecision | null, expected: DemoDecision): boolean {
  if (actual === null || actual.disposition !== expected.disposition) return false;
  return expected.disposition !== "vulnerable" || actual.family === expected.family;
}

export function choiceLabelFor(decision: Pick<DemoDecision, "disposition" | "family">): DemoChoiceLabel {
  if (decision.disposition !== "vulnerable") return decision.disposition;
  return decision.family === "injection" ? "vulnerable_injection" : decision.family === "broken_access_control" ? "vulnerable_broken_access_control" : "vulnerable_ssrf";
}

function mean(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

/** Nearest-rank percentile. */
function percentile(values: number[], fraction: number): number {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.min(ordered.length - 1, Math.floor((ordered.length - 1) * fraction + 0.5))]!;
}

function share(rows: readonly DemoResult[], predicate: (row: DemoResult) => boolean): number {
  return rows.length === 0 ? 0 : rows.filter(predicate).length / rows.length;
}

function optionalSum(rows: readonly DemoResult[], key: "inputTokens" | "outputTokens" | "costUsd"): number | null {
  const values = rows.map((row) => row.decision?.[key]);
  return rows.length === 0 || values.some((value) => value === undefined) ? null : (values as number[]).reduce((sum, value) => sum + value, 0);
}

function brier(rows: readonly DemoResult[], expectedById: Map<string, DemoDecision>): number | null {
  const valid = rows.filter((row) => row.status === "valid");
  if (valid.length === 0 || valid.some((row) => row.decision?.choice === undefined)) return null;
  return mean(valid.map((row) => {
    const target = choiceLabelFor(expectedById.get(row.caseId)!);
    return choiceLabels.reduce((total, key) => total + (row.decision!.choice!.probabilities[key] - (key === target ? 1 : 0)) ** 2, 0);
  }));
}

const dispositionList: readonly DemoDisposition[] = ["vulnerable", "safe", "insufficient_context"];

export function summarizeDemoResults(cases: readonly DemoCase[], results: readonly DemoResult[], evaluators: readonly DemoEvaluator[]): Record<string, DemoSummary> {
  const expectedById = new Map(cases.map((item) => [item.caseId, item.expected]));
  return Object.fromEntries(evaluators.map((evaluator) => {
    const rows = results.filter((row) => row.evaluator === evaluator);
    const expected = (row: DemoResult): DemoDisposition | undefined => expectedById.get(row.caseId)?.disposition;
    const byClass = Object.fromEntries(dispositionList.map((disposition) => [disposition, rows.filter((row) => expected(row) === disposition)])) as Record<DemoDisposition, DemoResult[]>;
    const classRecall = Object.fromEntries(dispositionList.map((disposition) => [disposition, share(byClass[disposition], (row) => row.decision?.disposition === disposition)])) as Record<DemoDisposition, number>;
    const vulnerableHits = byClass.vulnerable.filter((row) => row.decision?.disposition === "vulnerable");
    const vulnerablePredictions = rows.filter((row) => row.decision?.disposition === "vulnerable");
    const valid = rows.filter((row) => row.status === "valid");
    const latencies = rows.map((row) => row.latencyMs);
    const modelLatencies = rows.map((row) => row.modelLatencyMs).filter((value): value is number => value !== null);
    const outcomes = new Set(rows.map((row) => `${row.status}:${row.decision?.disposition ?? ""}`));
    return [evaluator, {
      accuracy: share(rows, (row) => row.correct),
      balancedAccuracy: mean(dispositionList.map((disposition) => classRecall[disposition])),
      classRecall,
      vulnerabilityRecall: classRecall.vulnerable,
      vulnerabilityRecallWithFamily: share(byClass.vulnerable, (row) => row.correct),
      familyAccuracy: vulnerableHits.length === 0 ? null : share(vulnerableHits, (row) => row.correct),
      vulnerablePrecision: vulnerablePredictions.length === 0 ? null : share(vulnerablePredictions, (row) => expected(row) === "vulnerable"),
      falseSafeRate: share(byClass.vulnerable, (row) => row.decision?.disposition === "safe"),
      falsePositiveRate: share(byClass.safe, (row) => row.decision?.disposition === "vulnerable"),
      errors: rows.filter((row) => row.status === "error").length,
      meanLatencyMs: mean(latencies),
      latencyP50Ms: percentile(latencies, 0.5),
      latencyP95Ms: percentile(latencies, 0.95),
      modelLatencyP50Ms: modelLatencies.length === 0 ? null : percentile(modelLatencies, 0.5),
      modelLatencyP95Ms: modelLatencies.length === 0 ? null : percentile(modelLatencies, 0.95),
      inputTokens: optionalSum(valid, "inputTokens"),
      outputTokens: optionalSum(valid, "outputTokens"),
      costUsd: optionalSum(valid, "costUsd"),
      brierScore: brier(rows, expectedById),
      degenerate: rows.length > 1 && outcomes.size === 1
    } satisfies DemoSummary];
  }));
}

function modelLatency(value: number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  if (!Number.isFinite(value) || value < 0) throw new Error("modelLatencyMs must be a non-negative finite number");
  return value;
}

export async function runDemo(cases: readonly DemoCase[], adapters: readonly DemoAdapter[], mode: DemoReport["mode"], maxConsecutiveErrors = Number.POSITIVE_INFINITY): Promise<DemoReport> {
  if (cases.length === 0 || adapters.length === 0) throw new Error("demo needs cases and adapters");
  if (new Set(adapters.map((adapter) => adapter.name)).size !== adapters.length) throw new Error("demo evaluator names must be unique");
  const results: DemoResult[] = [];
  const consecutiveErrors = new Map<DemoEvaluator, number>();
  for (const item of cases) {
    const stateJson = canonicalJson(item.state);
    for (const adapter of adapters) {
      const started = performance.now();
      try {
        const { modelLatencyMs, ...returned } = await adapter.evaluate(stateJson, item);
        const latencyMs = performance.now() - started;
        const decision = parseDemoDecision(returned, `${adapter.name} decision`);
        consecutiveErrors.set(adapter.name, 0);
        results.push({ caseId: item.caseId, evaluator: adapter.name, status: "valid", decision, correct: isCorrectDecision(decision, item.expected), latencyMs, modelLatencyMs: modelLatency(modelLatencyMs), error: null });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const failures = (consecutiveErrors.get(adapter.name) ?? 0) + 1;
        consecutiveErrors.set(adapter.name, failures);
        if (failures >= maxConsecutiveErrors) throw new Error(`${adapter.name} aborted after ${failures} consecutive errors: ${message}`);
        results.push({ caseId: item.caseId, evaluator: adapter.name, status: "error", decision: null, correct: false, latencyMs: performance.now() - started, modelLatencyMs: null, error: message });
      }
    }
  }
  const summary = summarizeDemoResults(cases, results, adapters.map(({ name }) => name));
  return {
    mode,
    disclaimer: mode === "fixture" ? "SIMULATED ADAPTERS — not model benchmark results" : "SMALL DEMO — descriptive results, not a statistical benchmark",
    caseCount: cases.length,
    results,
    summary
  };
}
