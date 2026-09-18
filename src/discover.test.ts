import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { buildEvidencePacket } from "./packets.js";
import { deduplicateCandidates, inventoryAst, runSemgrep, type ProcessRunner } from "./discover.js";

const snapshot = resolve("test/fixtures/repository/candidates");
const rules = resolve("rules/semgrep.yml");

async function execFinding(): Promise<{ line: number; text: string }> {
  return finding("child_process.exec(req.body.command)");
}

async function finding(needle: string, occurrence = 0): Promise<{ line: number; text: string }> {
  const lines = (await readFile(resolve(snapshot, "src/app.ts"), "utf8")).split("\n");
  const index = lines.map((line, lineIndex) => ({ line, lineIndex })).filter((entry) => entry.line.includes(needle))[occurrence]?.lineIndex;
  if (index === undefined) throw new Error(`fixture line not found: ${needle}`);
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

  const parameterizedLine = await finding('db.query("SELECT * FROM users WHERE name = $1"');
  const parameterized = first.find((candidate) => candidate.rootOperation === "query" && candidate.primarySpan.startLine === parameterizedLine.line);
  assert(parameterized);
  assert.equal(parameterized.contextResolution.sanitizers, "resolved");
  assert(parameterized.relatedSpans.some((span) => span.relationship === "flows_to" && span.text.includes("req.query.name")));

  const constantProcessLine = await finding('child_process.exec("echo status")');
  const constantProcess = first.find((candidate) => candidate.rootOperation === "exec" && candidate.primarySpan.startLine === constantProcessLine.line);
  assert(constantProcess);
  assert.equal(constantProcess.contextResolution.callPath, "unresolved");

  const constantNetworkLine = await finding('fetch("https://allowed.example.test")');
  const constantNetwork = first.find((candidate) => candidate.rootOperation === "fetch" && candidate.primarySpan.startLine === constantNetworkLine.line);
  assert(constantNetwork);
  assert.equal(constantNetwork.contextResolution.callPath, "unresolved");

  const allowlistedLine = await finding("fetch(requireAllowedHost(req.query.url))");
  const allowlisted = first.find((candidate) => candidate.rootOperation === "fetch" && candidate.primarySpan.startLine === allowlistedLine.line);
  assert(allowlisted);
  assert.equal(allowlisted.contextResolution.sanitizers, "resolved");
  assert(allowlisted.relatedSpans.some((span) => span.relationship === "guards" && span.text.includes("requireAllowedHost")));
});

test("discovery keeps candidate IDs stable across copied snapshot roots", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "discovery-"));
  const first = join(temporary, "first");
  const second = join(temporary, "second");
  try {
    await cp(snapshot, first, { recursive: true });
    await cp(snapshot, second, { recursive: true });
    const [firstAst, secondAst] = await Promise.all([inventoryAst(first), inventoryAst(second)]);
    assert.deepEqual(firstAst.map((candidate) => candidate.candidateId), secondAst.map((candidate) => candidate.candidateId));
    assert.equal(firstAst[0]?.repositoryId, secondAst[0]?.repositoryId);

    const match = await execFinding();
    const runner: ProcessRunner = async () => ({ code: 0, stderr: "", stdout: JSON.stringify({ results: [{ check_id: "inventory.process-request-input", path: "/src/src/app.ts", start: { line: match.line }, end: { line: match.line }, extra: { metavars: {} } }] }) });
    const [firstSemgrep, secondSemgrep] = await Promise.all([runSemgrep(first, rules, runner), runSemgrep(second, rules, runner)]);
    assert.deepEqual(firstSemgrep.map((candidate) => candidate.candidateId), secondSemgrep.map((candidate) => candidate.candidateId));
    assert.equal(firstSemgrep[0]?.repositoryId, secondSemgrep[0]?.repositoryId);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("discovery links inline and named routes to contained sinks", async () => {
  const candidates = await inventoryAst(snapshot);
  const inlineLine = await finding("return fetch(req.query.url)");
  const inline = candidates.find((candidate) => candidate.primarySpan.startLine === inlineLine.line);
  assert(inline);
  assert.equal(inline.contextResolution.callPath, "resolved");
  assert(inline.relatedSpans.some((span) => span.relationship === "calls" && span.text.includes('router.get("/lookup"')));

  const namedLine = await finding("return fetch(req.query.url)", 1);
  const named = candidates.find((candidate) => candidate.primarySpan.startLine === namedLine.line);
  assert(named);
  assert.equal(named.contextResolution.callPath, "resolved");
  assert(named.relatedSpans.some((span) => span.relationship === "calls" && span.text.includes('router.get("/named-lookup"')));
  assert(named.relatedSpans.some((span) => span.relationship === "guards" && span.text.includes("requireOwner")));
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
  const overlap = merged.find((candidate) => candidate.rootOperation === "exec" && candidate.primarySpan.startLine === finding.line);
  assert(overlap);
  assert.deepEqual(overlap.sources, ["ast", "semgrep"]);
  assert.equal(merged.filter((candidate) => candidate.candidateId === overlap.candidateId).length, 1);
  const packet = buildEvidencePacket({ ...overlap, commit: "0123456789abcdef", entryKind: "call" }, 0);
  assert.deepEqual(packet.candidateSources, ["ast", "semgrep"]);
});

test("overlap preserves resolved AST context without mutating inputs", async () => {
  const ast = await inventoryAst(snapshot);
  const match = await finding("return fetch(req.query.url)");
  const runner: ProcessRunner = async () => ({ code: 0, stderr: "", stdout: JSON.stringify({ results: [{ check_id: "inventory.network-request-input", path: "/src/src/app.ts", start: { line: match.line }, end: { line: match.line }, extra: { metavars: {} } }] }) });
  const semgrep = await runSemgrep(snapshot, rules, runner);
  const astCandidate = ast.find((candidate) => candidate.primarySpan.startLine === match.line);
  assert(astCandidate);
  const original = structuredClone(astCandidate);
  const merged = deduplicateCandidates([astCandidate, ...semgrep]);
  const overlap = merged.find((candidate) => candidate.primarySpan.startLine === match.line);
  assert(overlap);
  assert.equal(overlap.contextResolution.callPath, "resolved");
  assert.deepEqual(astCandidate, original);
});
