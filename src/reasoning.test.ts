import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

async function reasoning(): Promise<any> {
  return import(new URL("./reasoning.js", import.meta.url).href);
}

async function fixture(root: string, source: string): Promise<string> {
  const path = join(root, "fixture-runner");
  await writeFile(path, `#!/usr/bin/env node\n${source}`, "utf8");
  await chmod(path, 0o755);
  return path;
}

test("reasoning runner uses the fixed Terra command in a sanitized cwd with a minimal environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "reasoning-test-"));
  try {
    const snapshot = join(root, "snapshot");
    const schemaPath = resolve("config/reasoning-output.schema.json");
    const capture = join(root, "capture.json");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const executable = await fixture(root, `
const { writeFile } = await import("node:fs/promises");
const args = process.argv.slice(2);
const output = args[args.indexOf("--output-last-message") + 1];
await writeFile(output, JSON.stringify({ decision: "vulnerable", family: "injection", evidence_span_ids: ["s1"] }));
await writeFile(process.env.FIXTURE_CAPTURE, JSON.stringify({ args, cwd: process.cwd(), env: Object.keys(process.env).sort() }));
process.stdout.write(JSON.stringify({ usage: { input_tokens: 7, output_tokens: 3 } }));
process.stderr.write("fixture stderr");
`);

    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({
      evaluator: "terra", mode: "agentic", prompt: '{"packet":"same"}', snapshot, schemaPath, timeoutMs: 1_000,
      tokenBudget: 200, toolBudget: 3
    }, { executable, outputDirectory: root, environment: { PATH: process.env.PATH, HOME: process.env.HOME, HTTP_PROXY: "http://must-not-pass", FIXTURE_CAPTURE: capture }, environmentKeys: ["FIXTURE_CAPTURE"] });

    const observed = JSON.parse(await readFile(capture, "utf8"));
    assert.deepEqual(observed.args.slice(0, 11), ["exec", "--ephemeral", "--ignore-user-config", "--model", "gpt-5.6-terra", "--sandbox", "read-only", "--cd", snapshot, "--output-schema", schemaPath]);
    assert.equal(observed.args[11], "--output-last-message");
    assert.match(observed.args[12], new RegExp(`^${root.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}/reasoning-`));
    assert.equal(observed.args[13], "-");
    assert.equal(observed.cwd, await realpath(snapshot));
    assert(observed.env.includes("FIXTURE_CAPTURE") && observed.env.includes("HOME") && observed.env.includes("PATH"));
    assert(!observed.env.some((key: string) => /proxy|network/i.test(key)));
    assert.deepEqual(result, {
      finalOutcome: "alert",
      output: { decision: "vulnerable", family: "injection", evidence_span_ids: ["s1"] },
      usage: { inputTokens: 7, outputTokens: 3 },
      chargeUsd: null,
      costStatus: "inconclusive",
      attempts: 1,
      stdout: '{"usage":{"input_tokens":7,"output_tokens":3}}',
      stderr: "fixture stderr",
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

    const malformedResult = await runReasoningReview({ ...base, timeoutMs: 1_000 }, { executable: malformed, outputDirectory: root });
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
    const capture = join(root, "capture.json");
    await (await import("node:fs/promises")).mkdir(snapshot);
    const executable = await fixture(root, `
const { writeFile } = await import("node:fs/promises");
await writeFile(process.env.FIXTURE_CAPTURE, JSON.stringify({ args: process.argv.slice(2), cwd: process.cwd() }));
process.stdout.write(JSON.stringify({ decision: "safe", family: "ssrf", evidence_span_ids: ["s2"] }));
`);
    const { runReasoningReview } = await reasoning();
    const result = await runReasoningReview({
      evaluator: "opus", mode: "controlled", prompt: "{\"packet\":true}", snapshot, schemaPath, timeoutMs: 1_000,
      tokenBudget: 200, toolBudget: 3, model: "claude-opus-4-6"
    }, { executable, outputDirectory: root, environment: { PATH: process.env.PATH, HOME: process.env.HOME, FIXTURE_CAPTURE: capture }, environmentKeys: ["FIXTURE_CAPTURE"] });

    const observed = JSON.parse(await readFile(capture, "utf8"));
    assert.deepEqual(observed.args, ["--print", "--safe-mode", "--no-session-persistence", "--restricted", "--permission-mode", "dontAsk", "--allowedTools", "", "--model", "claude-opus-4-6", "--json-schema", JSON.stringify(JSON.parse(await readFile(schemaPath, "utf8"))), "--output-format", "json"]);
    assert.equal(observed.cwd, await realpath(snapshot));
    assert.equal(result.finalOutcome, "no_alert");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
