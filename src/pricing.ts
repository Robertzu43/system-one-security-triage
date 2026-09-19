import { readFile } from "node:fs/promises";

export interface ModelRate {
  /** USD per million uncached input tokens; null when no rate is published for this model. */
  readonly inputPerMillionUsd: number | null;
  readonly outputPerMillionUsd: number | null;
  /** Cache hits bill at a fraction of the input rate (0.1x for both frontier models here). */
  readonly cacheReadPerMillionUsd: number | null;
  /** Writing a cache entry bills at a premium (1.25x input for a five-minute entry). */
  readonly cacheWritePerMillionUsd: number | null;
  /** Where the rate came from, so a published cost can be traced to a rate card. */
  readonly source: string;
}

export type PriceTable = Readonly<Record<string, ModelRate>>;

/**
 * Token counts split by how they bill.
 *
 * Cached tokens must stay separate from fresh ones: a cache read costs a tenth of the input rate
 * and a cache write a quarter more, so folding all three into one number overstates a cached call
 * roughly tenfold. Both frontier CLIs report the buckets separately, so nothing is lost by keeping
 * them apart.
 */
export interface TokenUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens?: number;
  readonly cacheWriteTokens?: number;
}

/** A priced total, or the reason it cannot be priced. Never a silent zero. */
export type Cost =
  | { readonly status: "available"; readonly costUsd: number }
  | { readonly status: "unpriced"; readonly reason: "no_rate" | "no_usage" };

function rate(value: unknown, label: string): ModelRate {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const row = value as Record<string, unknown>;
  const money = (key: "inputPerMillionUsd" | "outputPerMillionUsd" | "cacheReadPerMillionUsd" | "cacheWritePerMillionUsd"): number | null => {
    const entry = row[key];
    if (entry === null || entry === undefined) return null;
    if (typeof entry !== "number" || !Number.isFinite(entry) || entry < 0) throw new Error(`${label}.${key} must be a non-negative number or null`);
    return entry;
  };
  if (typeof row.source !== "string" || row.source.length === 0) throw new Error(`${label}.source must be a non-empty string`);
  return {
    inputPerMillionUsd: money("inputPerMillionUsd"),
    outputPerMillionUsd: money("outputPerMillionUsd"),
    cacheReadPerMillionUsd: money("cacheReadPerMillionUsd"),
    cacheWritePerMillionUsd: money("cacheWritePerMillionUsd"),
    source: row.source
  };
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
  const cacheRead = usage.cacheReadTokens ?? 0;
  const cacheWrite = usage.cacheWriteTokens ?? 0;
  // Cached tokens were billed at their own rate. Falling back to the input rate would overstate a
  // cache hit tenfold, so a model that reports cache usage without a published cache rate is unpriced.
  if (cacheRead > 0 && entry.cacheReadPerMillionUsd === null) return { status: "unpriced", reason: "no_rate" };
  if (cacheWrite > 0 && entry.cacheWritePerMillionUsd === null) return { status: "unpriced", reason: "no_rate" };
  const total = usage.inputTokens * entry.inputPerMillionUsd
    + usage.outputTokens * entry.outputPerMillionUsd
    + cacheRead * (entry.cacheReadPerMillionUsd ?? 0)
    + cacheWrite * (entry.cacheWritePerMillionUsd ?? 0);
  return { status: "available", costUsd: total / 1_000_000 };
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
