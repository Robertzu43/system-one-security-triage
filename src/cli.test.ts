import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function cli(args: readonly string[], environment: NodeJS.ProcessEnv = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, ["dist/src/cli.js", ...args], { cwd: process.cwd(), env: { ...process.env, ...environment }, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    child.once("close", (code) => done({ code: code ?? -1, stdout, stderr }));
  });
}

test("demo-record rejects missing credentials before creating output", async () => {
  const root = await mkdtemp(join(tmpdir(), "demo-record-cli-"));
  try {
    const result = await cli(["demo-record", "--fixture", "test/fixtures/demo-cases.json", "--models", "jev", "--run-id", "test", "--output", root], { TYPESAFE_API_KEY: "" });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /TYPESAFE_API_KEY is required/);
    assert.deepEqual(await readdir(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("demo-record validates model selection and run ID without leaking environment values", async () => {
  const invalid = await cli(["demo-record", "--fixture", "test/fixtures/demo-cases.json", "--models", "terra,bogus", "--run-id", "test", "--output", "unused"], { PRIVATE_TEST_VALUE: "must-not-leak" });
  assert.notEqual(invalid.code, 0);
  assert.match(invalid.stderr, /unique comma-separated subset/);
  assert.doesNotMatch(`${invalid.stdout}${invalid.stderr}`, /must-not-leak/);
  const missing = await cli(["demo-record", "--fixture", "test/fixtures/demo-cases.json", "--models", "terra", "--output", "unused"]);
  assert.notEqual(missing.code, 0);
  assert.match(missing.stderr, /--run-id is required/);
});

test("dashboard-build rejects two-model and mixed-corpus inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "dashboard-build-cli-"));
  try {
    const runDir = join(root, "runs");
    await mkdir(runDir);
    await copyFile("test/fixtures/dashboard-runs/jev.json", join(runDir, "jev.json"));
    await copyFile("test/fixtures/dashboard-runs/terra.json", join(runDir, "terra.json"));
    const missing = await cli(["dashboard-build", "--fixture", "test/fixtures/demo-cases.json", "--run-dir", runDir, "--output", join(root, "missing.json")]);
    assert.notEqual(missing.code, 0);
    assert.match(missing.stderr, /requires jev, terra, and opus/);
    await copyFile("test/fixtures/dashboard-runs/opus.json", join(runDir, "opus.json"));
    const terra = JSON.parse(await readFile(join(runDir, "terra.json"), "utf8"));
    terra.corpusHash = "0".repeat(64);
    await writeFile(join(runDir, "terra.json"), `${JSON.stringify(terra)}\n`, "utf8");
    const mixed = await cli(["dashboard-build", "--fixture", "test/fixtures/demo-cases.json", "--run-dir", runDir, "--output", join(root, "mixed.json")]);
    assert.notEqual(mixed.code, 0);
    assert.match(mixed.stderr, /corpus hash mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dashboard-build reproducibly replaces generated output from complete offline fixtures", async () => {
  const root = await mkdtemp(join(tmpdir(), "dashboard-fixture-cli-"));
  const output = join(root, "nested", "latest.json");
  try {
    await mkdir(join(root, "nested"));
    await writeFile(output, "stale", "utf8");
    const args = ["dashboard-build", "--fixture", "test/fixtures/demo-cases.json", "--run-dir", "test/fixtures/dashboard-runs", "--output", output];
    const first = await cli(args);
    assert.equal(first.code, 0, first.stderr);
    const contents = await readFile(output, "utf8");
    const data = JSON.parse(contents);
    assert.equal(data.caseCount, 100);
    assert.deepEqual(Object.keys(data.summary).sort(), ["jev", "opus", "terra"]);
    assert.equal(JSON.parse(first.stdout).output, "latest.json");
    const second = await cli(args);
    assert.equal(second.code, 0, second.stderr);
    assert.equal(await readFile(output, "utf8"), contents);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
