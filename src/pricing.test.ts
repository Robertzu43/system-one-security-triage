import assert from "node:assert/strict";
import test from "node:test";
import { costOf, costPerCorrect, loadPriceTable, parsePriceTable, type PriceTable } from "./pricing.js";

const table: PriceTable = parsePriceTable({
  priced: { inputPerMillionUsd: 0.042, outputPerMillionUsd: 0, cacheReadPerMillionUsd: null, cacheWritePerMillionUsd: null, source: "rate card" },
  cached: { inputPerMillionUsd: 5, outputPerMillionUsd: 25, cacheReadPerMillionUsd: 0.5, cacheWritePerMillionUsd: 6.25, source: "rate card" },
  unpriced: { inputPerMillionUsd: null, outputPerMillionUsd: null, cacheReadPerMillionUsd: null, cacheWritePerMillionUsd: null, source: "unset" }
});

test("cached tokens bill at their own rate, not the input rate", () => {
  // 1M fresh input at $5, 1M cache reads at $0.50, 1M cache writes at $6.25, no output.
  const usage = { inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 1_000_000, cacheWriteTokens: 1_000_000 };
  assert.deepEqual(costOf(table, "cached", usage), { status: "available", costUsd: 11.75 });
  // The runner used to sum all three into inputTokens. Priced that way the same call reads $15.00,
  // so the separation is worth $3.25 of accuracy on this example rather than being cosmetic.
  const summed = { inputTokens: usage.inputTokens + usage.cacheReadTokens + usage.cacheWriteTokens, outputTokens: 0 };
  assert.deepEqual(costOf(table, "cached", summed), { status: "available", costUsd: 15 });
});

test("reported cache usage with no published cache rate is unpriced, never charged at the input rate", () => {
  assert.deepEqual(costOf(table, "priced", { inputTokens: 100, outputTokens: 10, cacheReadTokens: 50, cacheWriteTokens: 0 }), { status: "unpriced", reason: "no_rate" });
  assert.deepEqual(costOf(table, "priced", { inputTokens: 100, outputTokens: 10, cacheReadTokens: 0, cacheWriteTokens: 0 }).status, "available");
});

test("a published rate prices input and output tokens", () => {
  assert.deepEqual(costOf(table, "priced", { inputTokens: 1_000_000, outputTokens: 500 }), { status: "available", costUsd: 0.042 });
  assert.deepEqual(costOf(table, "priced", { inputTokens: 69_730, outputTokens: 7_791 }), { status: "available", costUsd: 69_730 * 0.042 / 1_000_000 });
});

test("a missing rate, an unknown model, or missing usage is unpriced and never zero", () => {
  assert.deepEqual(costOf(table, "unpriced", { inputTokens: 1000, outputTokens: 10 }), { status: "unpriced", reason: "no_rate" });
  assert.deepEqual(costOf(table, "never-seen", { inputTokens: 1000, outputTokens: 10 }), { status: "unpriced", reason: "no_rate" });
  assert.deepEqual(costOf(table, "priced", null), { status: "unpriced", reason: "no_usage" });
});

test("cost per correct keeps errors in the numerator and out of the denominator", () => {
  const spent = [costOf(table, "priced", { inputTokens: 1_000_000, outputTokens: 0 }), costOf(table, "priced", { inputTokens: 1_000_000, outputTokens: 0 })];
  // Two calls at $0.042, one of them wrong: the wasted call still counts against the one correct answer.
  assert.deepEqual(costPerCorrect(spent, 1), { status: "available", costUsd: 0.084 });
  assert.deepEqual(costPerCorrect(spent, 2), { status: "available", costUsd: 0.042 });
  assert.deepEqual(costPerCorrect(spent, 0), { status: "undefined", reason: "no_correct_decisions" });
});

test("one unpriced call makes the aggregate unpriced rather than a partial sum", () => {
  const mixed = [costOf(table, "priced", { inputTokens: 1_000_000, outputTokens: 0 }), costOf(table, "unpriced", { inputTokens: 1_000_000, outputTokens: 0 })];
  assert.deepEqual(costPerCorrect(mixed, 2), { status: "unpriced", reason: "no_rate" });
});

test("the shipped table carries every rate card and every source", async () => {
  const shipped = await loadPriceTable("config/pricing.json");
  assert.deepEqual([shipped["jev-1.13.0"]?.inputPerMillionUsd, shipped["jev-1.13.0"]?.outputPerMillionUsd], [0.042, 0]);
  assert.deepEqual([shipped["gpt-5.6-terra"]?.inputPerMillionUsd, shipped["gpt-5.6-terra"]?.outputPerMillionUsd], [2, 12]);
  assert.deepEqual([shipped["gpt-5.6-terra"]?.cacheReadPerMillionUsd, shipped["gpt-5.6-terra"]?.cacheWritePerMillionUsd], [0.2, 2.5]);
  assert.deepEqual([shipped["claude-opus-4-6"]?.inputPerMillionUsd, shipped["claude-opus-4-6"]?.outputPerMillionUsd], [5, 25]);
  assert.deepEqual([shipped["claude-opus-4-6"]?.cacheReadPerMillionUsd, shipped["claude-opus-4-6"]?.cacheWritePerMillionUsd], [0.5, 10]);
  // Every rate must name where it came from, so a published cost can be traced back to a rate card.
  for (const model of Object.keys(shipped)) assert.match(shipped[model]!.source, /https?:\/\/|unmetered/);
});

test("a malformed rate is rejected rather than silently dropped", () => {
  assert.throws(() => parsePriceTable({ bad: { inputPerMillionUsd: -1, outputPerMillionUsd: 0, source: "x" } }), /non-negative/);
  assert.throws(() => parsePriceTable({ bad: { inputPerMillionUsd: 1, outputPerMillionUsd: 0, cacheReadPerMillionUsd: "free", source: "x" } }), /non-negative/);
  assert.throws(() => parsePriceTable({ bad: { inputPerMillionUsd: 1, outputPerMillionUsd: 0 } }), /source/);
});
