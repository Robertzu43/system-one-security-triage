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
}

export interface EvaluatorMetadata {
  provider: "TypeSafe" | "OpenAI" | "Anthropic" | "Fixture";
  modelId: string;
  runner: string;
  runnerVersion: string;
}

export interface DemoAdapter {
  name: DemoEvaluator;
  metadata: EvaluatorMetadata;
  evaluate(stateJson: string, item: DemoCase): Promise<DemoDecision>;
}

export interface DemoResult {
  caseId: string;
  evaluator: DemoEvaluator;
  status: "valid" | "error";
  decision: DemoDecision | null;
  correct: boolean;
  latencyMs: number;
  error: string | null;
}

export interface DemoSummary {
  accuracy: number;
  vulnerabilityRecall: number;
  errors: number;
  meanLatencyMs: number;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
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
  if (Math.abs(sum - 1) > 0.02) throw new Error(`${label}.probabilities sum to ${sum}`);
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

export async function loadDemoCases(path: string): Promise<DemoCase[]> {
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!Array.isArray(value) || value.length === 0) throw new Error("demo cases must be a non-empty array");
  const cases = value.map((item, index) => {
    const row = record(item, `cases[${index}]`);
    const family = text(row.family, `cases[${index}].family`) as Family;
    if (!families.has(family)) throw new Error(`cases[${index}].family is invalid`);
    return { caseId: text(row.caseId, `cases[${index}].caseId`), family, state: record(row.state, `cases[${index}].state`), expected: parseDemoDecision(row.expected, `cases[${index}].expected`) };
  });
  if (new Set(cases.map((item) => item.caseId)).size !== cases.length) throw new Error("caseId must be unique");
  return cases;
}

function isCorrect(actual: DemoDecision, expected: DemoDecision): boolean {
  if (actual.disposition !== expected.disposition) return false;
  return expected.disposition !== "vulnerable" || actual.family === expected.family;
}

function mean(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function optionalSum(rows: DemoResult[], key: "inputTokens" | "outputTokens" | "costUsd"): number | null {
  const values = rows.map((row) => row.decision?.[key]);
  return values.some((value) => value === undefined) ? null : (values as number[]).reduce((sum, value) => sum + value, 0);
}

export function summarizeDemoResults(cases: readonly DemoCase[], results: readonly DemoResult[], evaluators: readonly DemoEvaluator[]): Record<string, DemoSummary> {
  return Object.fromEntries(evaluators.map((evaluator) => {
    const rows = results.filter((row) => row.evaluator === evaluator);
    const vulnerable = rows.filter((row) => cases.find((item) => item.caseId === row.caseId)?.expected.disposition === "vulnerable");
    return [evaluator, {
      accuracy: rows.length === 0 ? 0 : rows.filter((row) => row.correct).length / rows.length,
      vulnerabilityRecall: vulnerable.length === 0 ? 0 : vulnerable.filter((row) => row.correct).length / vulnerable.length,
      errors: rows.filter((row) => row.status === "error").length,
      meanLatencyMs: mean(rows.map((row) => row.latencyMs)),
      inputTokens: optionalSum(rows, "inputTokens"),
      outputTokens: optionalSum(rows, "outputTokens"),
      costUsd: optionalSum(rows, "costUsd")
    }];
  }));
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
        const decision = parseDemoDecision(await adapter.evaluate(stateJson, item), `${adapter.name} decision`);
        consecutiveErrors.set(adapter.name, 0);
        results.push({ caseId: item.caseId, evaluator: adapter.name, status: "valid", decision, correct: isCorrect(decision, item.expected), latencyMs: performance.now() - started, error: null });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const failures = (consecutiveErrors.get(adapter.name) ?? 0) + 1;
        consecutiveErrors.set(adapter.name, failures);
        if (failures >= maxConsecutiveErrors) throw new Error(`${adapter.name} aborted after ${failures} consecutive errors: ${message}`);
        results.push({ caseId: item.caseId, evaluator: adapter.name, status: "error", decision: null, correct: false, latencyMs: performance.now() - started, error: message });
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
