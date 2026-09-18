import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { inventoryAst } from "./discover.js";
import { canonicalJson } from "./jsonl.js";
import { runArm } from "./pipeline.js";
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
    chargeUsd: null, costStatus: "inconclusive", attempts: 1, stdout: "", stderr: "", error: null
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
    const input = {
      runId: typeof values["run-id"] === "string" ? values["run-id"] : "fixture", arm: "jev_to_terra" as const, artifactPath,
      snapshot, sourceCommit: "fixture", discover: () => inventoryAst(snapshot), prompt: "", schemaPath: resolve("config/reasoning-output.schema.json"), routerConfig,
      timeoutMs: 1_000, tokenBudget: 1, toolBudget: 1, cacheSeries: "cold" as const,
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
    const fixtureScore = scoreClaims(parseScoreInput(JSON.parse(await readFile("test/fixtures/scoring.json", "utf8"))));
    return { ...bundle, fixtureScore, immutableSecondWriteRejected };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ args: process.argv.slice(2), allowPositionals: true, strict: true, options: {
    source: { type: "string" }, destination: { type: "string" }, commit: { type: "string" }, snapshot: { type: "string" }, input: { type: "string" }, fixture: { type: "string" }, evaluator: { type: "string" }, "run-id": { type: "string" }
  } });
  const command = positionals[0];
  const result = command === "sanitize" ? await sanitize(values) : command === "discover" ? await discover(values) : command === "score" ? await score(values) : command === "run" ? await runFixture(values) : (() => { throw new Error("expected sanitize, discover, run, or score"); })();
  process.stdout.write(`${canonicalJson(result)}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
