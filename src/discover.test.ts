import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import { buildEvidencePacket } from "./packets.js";
import { deduplicateCandidates, inventoryAst, runSemgrep, type ProcessRunner } from "./discover.js";

const snapshot = resolve("test/fixtures/repository/candidates");
const rules = resolve("rules/semgrep.yml");

async function execFinding(): Promise<{ line: number; text: string }> {
  const lines = (await readFile(resolve(snapshot, "src/app.ts"), "utf8")).split("\n");
  const index = lines.findIndex((line) => line.includes("child_process.exec(req.body.command)"));
  return { line: index + 1, text: lines[index]! };
}

test("discovery inventories request-controlled and safe controls with one-hop context", async () => {
  const first = await inventoryAst(snapshot);
  const second = await inventoryAst(snapshot);
  assert.deepEqual(first.map((candidate) => candidate.candidateId), second.map((candidate) => candidate.candidateId));
  assert(first.every((candidate) => candidate.sources.length === 1 && candidate.sources[0] === "ast"));

  const wrapped = first.find((candidate) => candidate.primarySpan.text.includes("child_process.exec(command)"));
  assert(wrapped);
  assert(wrapped.relatedSpans.some((span) => span.text.includes("function executeCommand")));

  const unsafeRoute = first.find((candidate) => candidate.primarySpan.text.includes('router.get("/users/:id",'));
  assert(unsafeRoute);
  assert.equal(unsafeRoute.contextResolution.authorization, "unresolved");

  const guardedRoute = first.find((candidate) => candidate.primarySpan.text.includes('router.get("/users/:id/settings"'));
  assert(guardedRoute);
  assert.equal(guardedRoute.contextResolution.authorization, "resolved");
  assert(guardedRoute.relatedSpans.some((span) => span.relationship === "guards" && span.text.includes("requireOwner")));

  const parameterized = first.find((candidate) => candidate.primarySpan.text.includes('db.query("SELECT * FROM users WHERE name = $1"'));
  assert(parameterized);
  assert(parameterized.relatedSpans.some((span) => span.relationship === "flows_to" && span.text.includes("req.query.name")));
});

test("discovery runs frozen Semgrep with a networkless argument array", async () => {
  const finding = await execFinding();
  let command = "";
  let args: readonly string[] = [];
  const runner: ProcessRunner = async (actualCommand, actualArgs) => {
    command = actualCommand;
    args = actualArgs;
    return { code: 0, stderr: "", stdout: JSON.stringify({ results: [{ check_id: "inventory.process-request-input", path: "/src/src/app.ts", start: { line: finding.line }, end: { line: finding.line }, extra: { metavars: {} } }] }) };
  };

  const candidates = await runSemgrep(snapshot, rules, runner);
  assert.equal(command, "docker");
  assert.deepEqual(args, [
    "run", "--rm", "--network", "none",
    "--mount", `type=bind,src=${snapshot},dst=/src,readonly`,
    "--mount", `type=bind,src=${resolve("rules")},dst=/rules,readonly`,
    "semgrep/semgrep:1.177.0",
    "semgrep", "scan", "--config", "/rules/semgrep.yml", "--json", "--metrics", "off", "--disable-version-check", "/src"
  ]);
  assert.deepEqual(candidates[0]?.sources, ["semgrep"]);
  assert.equal(candidates[0]?.primarySpan.text, finding.text);
});

test("discovery rejects failed, malformed, and out-of-snapshot Semgrep output", async () => {
  const failed: ProcessRunner = async () => ({ code: 1, stderr: "failed", stdout: "" });
  const malformed: ProcessRunner = async () => ({ code: 0, stderr: "", stdout: "not json" });
  const outside: ProcessRunner = async () => ({ code: 0, stderr: "", stdout: JSON.stringify({ results: [{ check_id: "inventory.process-request-input", path: "/etc/passwd", start: { line: 1 }, end: { line: 1 }, extra: { metavars: {} } }] }) });
  await assert.rejects(() => runSemgrep(snapshot, rules, failed), /Semgrep failed/);
  await assert.rejects(() => runSemgrep(snapshot, rules, malformed), /JSON/);
  await assert.rejects(() => runSemgrep(snapshot, rules, outside), /outside \/src/);
});

test("overlap keeps both sources in one packet-ready candidate", async () => {
  const ast = await inventoryAst(snapshot);
  const finding = await execFinding();
  const runner: ProcessRunner = async () => ({ code: 0, stderr: "", stdout: JSON.stringify({ results: [{ check_id: "inventory.process-request-input", path: "/src/src/app.ts", start: { line: finding.line }, end: { line: finding.line }, extra: { metavars: {} } }] }) });
  const semgrep = await runSemgrep(snapshot, rules, runner);
  const merged = deduplicateCandidates([...ast, ...semgrep]);
  const overlap = merged.find((candidate) => candidate.primarySpan.text.includes("child_process.exec(req.body.command)"));
  assert(overlap);
  assert.deepEqual(overlap.sources, ["ast", "semgrep"]);
  assert.equal(merged.filter((candidate) => candidate.candidateId === overlap.candidateId).length, 1);
  const packet = buildEvidencePacket({ ...overlap, commit: "0123456789abcdef", entryKind: "call" }, 0);
  assert.deepEqual(packet.candidateSources, ["ast", "semgrep"]);
});
