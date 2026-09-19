import assert from "node:assert/strict";
import test from "node:test";
import { costOf, costPerCorrect, loadPriceTable, parsePriceTable, type PriceTable } from "./pricing.js";

const table: PriceTable = parsePriceTable({
  priced: { inputPerMillionUsd: 0.042, outputPerMillionUsd: 0, source: "rate card" },
  unpriced: { inputPerMillionUsd: null, outputPerMillionUsd: null, source: "unset" }
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

test("the shipped table prices Jev and leaves the unpublished rates explicitly unset", async () => {
  const shipped = await loadPriceTable("config/pricing.json");
  assert.equal(shipped["jev-1.13.0"]?.inputPerMillionUsd, 0.042);
  assert.equal(shipped["jev-1.13.0"]?.outputPerMillionUsd, 0);
  for (const model of ["gpt-5.6-terra", "claude-opus-4-6"]) assert.equal(shipped[model]?.inputPerMillionUsd, null, `${model} must stay unpriced until a rate card is recorded`);
});

test("a malformed rate is rejected rather than silently dropped", () => {
  assert.throws(() => parsePriceTable({ bad: { inputPerMillionUsd: -1, outputPerMillionUsd: 0, source: "x" } }), /non-negative/);
  assert.throws(() => parsePriceTable({ bad: { inputPerMillionUsd: 1, outputPerMillionUsd: 0 } }), /source/);
});
