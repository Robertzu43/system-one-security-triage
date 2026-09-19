import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

async function reasoning(): Promise<any> {
  return import(new URL("./reasoning.js", import.meta.url).href);
}

async function fixture(root: string, source: string, version = "codex-cli 0.147.0"): Promise<string> {
  const path = join(root, "fixture-runner");
  await writeFile(path, `#!/usr/bin/env node
if (process.argv[2] === "--version") { process.stdout.write(${JSON.stringify(version)}); process.exit(0); }
${source}`, "utf8");
  await chmod(path, 0o755);
  return path;
}

test("reasoning runner uses the fixed Terra command in a sanitized cwd with a minimal environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-test-"));
  try {
    const snapshot = join(root, "snapshot");
    const home = join(root, "home");
    const schemaPath = resolve("config/reasoning-output.schema.json");
    const outside = join(root, "answer-bearing-advisory.txt");
    await (await import("node:fs/promises")).mkdir(snapshot);
    await (await import("node:fs/promises")).mkdir(join(home, ".codex"), { recursive: true });
    await writeFile(join(home, ".codex", "auth.json"), "fixture-auth", "utf8");
    await writeFile(outside, "CVE answer must remain private", "utf8");
    const executable = await fixture(root, `
const { readFile, writeFile } = await import("node:fs/promises");
const args = process.argv.slice(2);
const output = args[args.indexOf("--output-last-message") + 1];
await writeFile(output, JSON.stringify({ decision: "vulnerable", family: "injection", evidence_span_ids: ["s1"] }));
let outsideReadable = true;
try { await readFile(process.env.OUTSIDE_SECRET, "utf8"); } catch { outsideReadable = false; }
const isolatedAuth = await readFile(process.env.CODEX_HOME + "/auth.json", "utf8");
process.stdout.write(JSON.stringify({ usage: { input_tokens: 7, output_tokens: 3 }, tool_calls: 1 }));
process.stderr.write(JSON.stringify({ args, cwd: process.cwd(), env: Object.keys(process.env).sort(), outsideReadable, isolatedAuth }));
`);

    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({
      evaluator: "terra", mode: "agentic", prompt: '{"packet":"same"}', snapshot, schemaPath, timeoutMs: 5_000,
      tokenBudget: 200, toolBudget: 3
    }, { executable, outputDirectory: root, environment: { PATH: process.env.PATH, HOME: home, HTTP_PROXY: "http://must-not-pass", OUTSIDE_SECRET: outside }, environmentKeys: ["OUTSIDE_SECRET"] });

    const observed = JSON.parse(result.stderr);
    assert.deepEqual(observed.args.slice(0, 12), ["exec", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--model", "gpt-5.6-terra", "--dangerously-bypass-approvals-and-sandbox", "--cd", snapshot, "--output-schema", schemaPath]);
    assert.equal(observed.args[12], "--output-last-message");
    assert.match(observed.args[13], new RegExp(`^${root.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}/reasoning-`));
    assert.equal(observed.args[14], "-");
    assert.equal(observed.cwd, await realpath(snapshot));
    assert(observed.env.includes("CODEX_HOME") && observed.env.includes("OUTSIDE_SECRET") && observed.env.includes("HOME") && observed.env.includes("PATH"));
    assert(!observed.env.some((key: string) => /proxy|network/i.test(key)));
    assert.equal(observed.outsideReadable, false);
    assert.equal(observed.isolatedAuth, "fixture-auth");
    assert.deepEqual(result, {
      finalOutcome: "alert",
      output: { decision: "vulnerable", family: "injection", evidence_span_ids: ["s1"] },
      usage: { inputTokens: 7, outputTokens: 3 },
      usageStatus: "available",
      chargeUsd: null,
      costStatus: "inconclusive",
      attempts: 1,
      stdout: '{"usage":{"input_tokens":7,"output_tokens":3},"tool_calls":1}',
      stderr: result.stderr,
      error: null
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("reasoning runner retains malformed, failed, and timed-out reviews as manual review", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-failure-test-"));
  try {
    const snapshot = join(root, "snapshot");
    const schemaPath = resolve("config/reasoning-output.schema.json");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const malformed = await fixture(root, `
const { writeFile } = await import("node:fs/promises");
const args = process.argv.slice(2);
await writeFile(args[args.indexOf("--output-last-message") + 1], JSON.stringify({ decision: "maybe", family: "injection", evidence_span_ids: [] }));
`);
    const delayed = await fixture(root, "setTimeout(() => process.exit(0), 500);");
    const { runReasoningReview } = await reasoning();
    const base = { evaluator: "terra", mode: "agentic", prompt: "{}", snapshot, schemaPath, timeoutMs: 30, tokenBudget: 1, toolBudget: 1 };

    const malformedResult = await runReasoningReview({ ...base, timeoutMs: 5_000 }, { executable: malformed, outputDirectory: root });
    assert.equal(malformedResult.finalOutcome, "manual_review");
    assert.equal(malformedResult.error?.kind, "malformed_output");

    const timeoutResult = await runReasoningReview(base, { executable: delayed, outputDirectory: root });
    assert.equal(timeoutResult.finalOutcome, "manual_review");
    assert.equal(timeoutResult.error?.kind, "timeout");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("controlled Opus uses the frozen full model and an empty allowed-tool list", async () => {
  const root = await mkdtemp(join(tmpdir(), "opus-command-test-"));
  try {
    const snapshot = join(root, "empty");
    const schemaPath = resolve("config/reasoning-output.schema.json");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const executable = await fixture(root, `
process.stderr.write(JSON.stringify({ args: process.argv.slice(2), cwd: process.cwd() }));
process.stdout.write(JSON.stringify({ structured_output: { decision: "safe", family: "ssrf", evidence_span_ids: ["s2"] }, usage: { input_tokens: 11, output_tokens: 13 } }));
`, "2.1.278 (Claude Code)");
    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({
      evaluator: "opus", mode: "controlled", prompt: "{\"packet\":true}", snapshot, schemaPath, timeoutMs: 5_000,
      tokenBudget: 200, toolBudget: 3, model: "claude-opus-4-6"
    }, { executable, outputDirectory: root, environment: { PATH: process.env.PATH, HOME: process.env.HOME } });

    const observed = JSON.parse(result.stderr);
    assert.deepEqual(observed.args, ["--print", "--bare", "--no-session-persistence", "--restricted", "--strict-mcp-config", "--permission-mode", "dontAsk", "--permission-prompts", "none", "--tools", "", "--model", "claude-opus-4-6", "--json-schema", JSON.stringify(JSON.parse(await readFile(schemaPath, "utf8"))), "--output-format", "json"]);
    assert.equal(observed.cwd, await realpath(snapshot));
    assert.equal(result.finalOutcome, "no_alert");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Claude structured_output envelopes preserve output and usage while unsupported Codex usage fails closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-envelope-test-"));
  try {
    const snapshot = join(root, "snapshot");
    const schemaPath = resolve("config/reasoning-output.schema.json");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const opusExecutable = await fixture(root, 'process.stdout.write(JSON.stringify({ structured_output: { decision: "safe", family: "ssrf", evidence_span_ids: ["s2"] }, usage: { input_tokens: 11, output_tokens: 13 } }));', "2.1.278 (Claude Code)");
    const terraRoot = join(root, "terra");
    await (await import("node:fs/promises")).mkdir(terraRoot);
    const terraExecutable = await fixture(terraRoot, `
const { writeFile } = await import("node:fs/promises");
const args = process.argv.slice(2);
await writeFile(args[args.indexOf("--output-last-message") + 1], JSON.stringify({ decision: "safe", family: "ssrf", evidence_span_ids: ["s2"] }));
`);
    const { runReasoningReview } = await reasoning();
    const opus = await runReasoningReview({ evaluator: "opus", mode: "controlled", prompt: "{}", snapshot, schemaPath, timeoutMs: 5_000, tokenBudget: 100, toolBudget: 1, model: "claude-opus-4-6" }, { executable: opusExecutable, outputDirectory: root });
    const terra = await runReasoningReview({ evaluator: "terra", mode: "agentic", prompt: "{}", snapshot, schemaPath, timeoutMs: 5_000, tokenBudget: 100, toolBudget: 1 }, { executable: terraExecutable, outputDirectory: root });
    assert.deepEqual(opus.output, { decision: "safe", family: "ssrf", evidence_span_ids: ["s2"] });
    assert.deepEqual(opus.usage, { inputTokens: 11, outputTokens: 13 });
    assert.equal(opus.usageStatus, "available");
    assert.equal(terra.usage, null);
    assert.equal(terra.usageStatus, "inconclusive");
    assert.equal(terra.finalOutcome, "manual_review");
    assert.equal(terra.error?.kind, "budget_unverifiable");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("demo mode keeps a valid Terra decision when CLI usage metadata is unavailable", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-demo-test-"));
  try {
    const snapshot = join(root, "empty");
    const home = join(root, "home");
    await (await import("node:fs/promises")).mkdir(snapshot);
    await (await import("node:fs/promises")).mkdir(home);
    const executable = await fixture(root, `
const { writeFile } = await import("node:fs/promises");
const args = process.argv.slice(2);
await writeFile(args[args.indexOf("--output-last-message") + 1], JSON.stringify({ decision: "safe", family: null }));
`);
    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({ evaluator: "terra", mode: "demo", prompt: "{}", snapshot, schemaPath: resolve("config/demo-output.schema.json"), timeoutMs: 5_000, tokenBudget: 100, toolBudget: 1 }, { executable, outputDirectory: root, environment: { PATH: process.env.PATH, HOME: home } });
    assert.equal(result.error, null);
    assert.equal(result.output?.decision, "safe");
    assert.equal(result.usageStatus, "inconclusive");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("reasoning runner rejects version drift before a model attempt", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-version-test-"));
  try {
    const snapshot = join(root, "snapshot");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const marker = join(root, "model-called");
    const executable = await fixture(root, `await (await import("node:fs/promises")).writeFile(${JSON.stringify(marker)}, "called");`, "2.1.279 (Claude Code)");
    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({ evaluator: "opus", mode: "controlled", prompt: "{}", snapshot, schemaPath: resolve("config/reasoning-output.schema.json"), timeoutMs: 5_000, tokenBudget: 100, toolBudget: 1, model: "claude-opus-4-6" }, { executable, outputDirectory: root });
    assert.equal(result.error?.kind, "version_mismatch");
    assert.equal(result.attempts, 0);
    await assert.rejects(() => stat(marker), /ENOENT/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("reasoning runner fails closed when filesystem isolation is unsupported", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-platform-test-"));
  try {
    const snapshot = join(root, "snapshot");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const executable = await fixture(root, "throw new Error('must not execute');");
    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({ evaluator: "terra", mode: "agentic", prompt: "{}", snapshot, schemaPath: resolve("config/reasoning-output.schema.json"), timeoutMs: 5_000, tokenBudget: 100, toolBudget: 1 }, { executable, outputDirectory: root, platform: "linux" });
    assert.equal(result.error?.kind, "unsupported_platform");
    assert.equal(result.attempts, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});
