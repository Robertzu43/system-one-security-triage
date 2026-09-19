import { readFile } from "node:fs/promises";

export interface ModelRate {
  /** USD per million input tokens; null when no rate is published for this model. */
  readonly inputPerMillionUsd: number | null;
  readonly outputPerMillionUsd: number | null;
  /** Where the rate came from, so a published cost can be traced to a rate card. */
  readonly source: string;
}

export type PriceTable = Readonly<Record<string, ModelRate>>;

export interface TokenUsage { readonly inputTokens: number; readonly outputTokens: number; }

/** A priced total, or the reason it cannot be priced. Never a silent zero. */
export type Cost =
  | { readonly status: "available"; readonly costUsd: number }
  | { readonly status: "unpriced"; readonly reason: "no_rate" | "no_usage" };

function rate(value: unknown, label: string): ModelRate {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const row = value as Record<string, unknown>;
  const money = (key: "inputPerMillionUsd" | "outputPerMillionUsd"): number | null => {
    const entry = row[key];
    if (entry === null) return null;
    if (typeof entry !== "number" || !Number.isFinite(entry) || entry < 0) throw new Error(`${label}.${key} must be a non-negative number or null`);
    return entry;
  };
  if (typeof row.source !== "string" || row.source.length === 0) throw new Error(`${label}.source must be a non-empty string`);
  return { inputPerMillionUsd: money("inputPerMillionUsd"), outputPerMillionUsd: money("outputPerMillionUsd"), source: row.source };
}

export function parsePriceTable(value: unknown): PriceTable {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("price table must be an object");
  return Object.freeze(Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([model, entry]) => [model, rate(entry, model)])));
}

export async function loadPriceTable(path: string): Promise<PriceTable> {
  return parsePriceTable(JSON.parse(await readFile(path, "utf8")) as unknown);
}

/**
 * Cost of one model call.
 *
 * A model with no published rate returns "unpriced" rather than a number. Estimating it from
 * another model's rate, or defaulting an absent rate to zero, would put a fabricated figure on a
 * dashboard that reads as measured — the one failure this table exists to prevent.
 */
export function costOf(table: PriceTable, modelId: string, usage: TokenUsage | null): Cost {
  if (usage === null) return { status: "unpriced", reason: "no_usage" };
  const entry = table[modelId];
  if (entry === undefined || entry.inputPerMillionUsd === null || entry.outputPerMillionUsd === null) return { status: "unpriced", reason: "no_rate" };
  return { status: "available", costUsd: (usage.inputTokens * entry.inputPerMillionUsd + usage.outputTokens * entry.outputPerMillionUsd) / 1_000_000 };
}

/**
 * Cost per correct decision: every call's cost over the calls that were right.
 *
 * Errors and abstentions cost money and produce no correct decision, so they belong in the
 * numerator and not the denominator. One unpriced call makes the whole figure unpriced — a
 * partial sum over the priced subset would understate the true cost while looking exact.
 */
export function costPerCorrect(costs: readonly Cost[], correct: number): Cost | { status: "undefined"; reason: "no_correct_decisions" } {
  if (costs.some((cost) => cost.status === "unpriced")) return { status: "unpriced", reason: "no_rate" };
  const total = costs.reduce((sum, cost) => sum + (cost.status === "available" ? cost.costUsd : 0), 0);
  if (correct === 0) return { status: "undefined", reason: "no_correct_decisions" };
  return { status: "available", costUsd: total / correct };
}
