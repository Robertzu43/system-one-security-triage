import { spawn } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import { basename, dirname, extname, posix, resolve, sep } from "node:path";
import * as ts from "typescript";
import type { Candidate, ContextResolution, Family } from "./contracts.js";
import { stableHash } from "./jsonl.js";

const extensions = new Set([".js", ".jsx", ".ts", ".tsx"]);
const skipped = new Set([".git", "node_modules", "vendor", "generated", "dist", "build", "coverage"]);
const contextKeys = ["middleware", "upstreamDataFlow", "sanitizers", "authorization", "callPath"] as const;
const rules: Record<string, { familyHint: Family; rootOperation: string }> = {
  "inventory.sql-string-query": { familyHint: "injection", rootOperation: "query" },
  "inventory.eval": { familyHint: "injection", rootOperation: "eval" },
  "inventory.process-request-input": { familyHint: "injection", rootOperation: "exec" },
  "inventory.network-request-input": { familyHint: "ssrf", rootOperation: "fetch" },
  "inventory.identifier-route": { familyHint: "broken_access_control", rootOperation: "route" }
};

type Span = Candidate["primarySpan"];
type Related = Candidate["relatedSpans"][number];
type ProcessResult = { code: number; stdout: string; stderr: string };
export type ProcessRunner = (command: string, args: readonly string[]) => Promise<ProcessResult>;
interface Unit { path: string; text: string; source: ts.SourceFile; }

function compare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function cleanSpan(span: Span): Span { return { ...span, text: span.text.replace(/\s+/g, " ").trim() }; }
function id(repositoryId: string, familyHint: Family, rootOperation: string, primarySpan: Span): string { return stableHash({ repositoryId, familyHint, rootOperation, primarySpan: cleanSpan(primarySpan) }); }
function emptyContext(): ContextResolution { return { middleware: "unresolved", upstreamDataFlow: "unresolved", sanitizers: "unresolved", authorization: "unresolved", callPath: "unresolved" }; }
function candidate(repositoryId: string, source: Candidate["sources"][number], familyHint: Family, rootOperation: string, primarySpan: Span, relatedSpans: Related[] = [], contextResolution = emptyContext()): Candidate {
  return { candidateId: id(repositoryId, familyHint, rootOperation, primarySpan), repositoryId, sources: [source], familyHint, rootOperation, primarySpan, relatedSpans, contextResolution };
}
function relatedKey(span: Related): string { return JSON.stringify([span.path, span.startLine, span.endLine, cleanSpan(span).text, span.relationship]); }

export function deduplicateCandidates(candidates: Candidate[]): Candidate[] {
  const result = new Map<string, Candidate>();
  for (const row of candidates) {
    const key = id(row.repositoryId, row.familyHint, row.rootOperation, row.primarySpan);
    const current = result.get(key);
    if (current === undefined) {
      result.set(key, { ...row, candidateId: key, sources: [...new Set(row.sources)].sort(compare) as Candidate["sources"], relatedSpans: [...row.relatedSpans] });
      continue;
    }
    current.sources = [...new Set([...current.sources, ...row.sources])].sort(compare) as Candidate["sources"];
    const related = new Map(current.relatedSpans.map((span) => [relatedKey(span), span]));
    for (const span of row.relatedSpans) related.set(relatedKey(span), span);
    current.relatedSpans = [...related.values()].sort((left, right) => compare(relatedKey(left), relatedKey(right)));
    for (const name of contextKeys) if (row.contextResolution[name] === "unresolved") current.contextResolution[name] = "unresolved";
  }
  return [...result.values()].sort((left, right) => compare(left.candidateId, right.candidateId));
}

async function directory(path: string): Promise<string> {
  const fullPath = resolve(path);
  const entry = await lstat(fullPath);
  if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error(`snapshot must be a directory: ${path}`);
  return fullPath;
}
async function ruleFile(path: string): Promise<string> {
  const fullPath = resolve(path);
  const entry = await lstat(fullPath);
  if (basename(fullPath) !== "semgrep.yml" || entry.isSymbolicLink() || !entry.isFile()) throw new Error("rules must be the local semgrep.yml file");
  return fullPath;
}
async function runProcess(command: string, args: readonly string[]): Promise<ProcessResult> {
  return new Promise((done, fail) => {
    const child = spawn(command, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr?.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", fail);
    child.once("close", (code) => done({ code: code ?? -1, stdout, stderr }));
  });
}

export function semgrepDockerArgs(snapshot: string, rulePath: string): string[] {
  return [
    "run", "--rm", "--network", "none",
    "--mount", `type=bind,src=${resolve(snapshot)},dst=/src,readonly`,
    "--mount", `type=bind,src=${dirname(resolve(rulePath))},dst=/rules,readonly`,
    "semgrep/semgrep:1.177.0",
    "semgrep", "scan", "--config", "/rules/semgrep.yml", "--json", "--metrics", "off", "--disable-version-check", "/src"
  ];
}

function record(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function line(value: unknown, label: string): number { if (typeof value !== "number" || !Number.isInteger(value) || value < 1) throw new Error(`${label} must be a positive line`); return value; }
function scannerPath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/src/") || value.includes("\\") || posix.normalize(value) !== value) throw new Error("Semgrep reported a path outside /src");
  const relative = value.slice(5);
  if (relative === "" || relative === "." || relative === ".." || relative.startsWith("../")) throw new Error("Semgrep reported a path outside /src");
  return relative;
}
async function fileSpan(snapshot: string, path: string, startLine: number, endLine: number): Promise<Span> {
  const fullPath = resolve(snapshot, ...path.split("/"));
  if (fullPath !== snapshot && !fullPath.startsWith(`${snapshot}${sep}`)) throw new Error("Semgrep reported a path outside /src");
  const lines = (await readFile(fullPath, "utf8")).split(/\r?\n/);
  if (endLine < startLine || endLine > lines.length) throw new Error("Semgrep reported an invalid span");
  const text = lines.slice(startLine - 1, endLine).join("\n");
  if (text.trim() === "") throw new Error("Semgrep reported an empty span");
  return { path, startLine, endLine, text };
}

export async function parseSemgrepResults(output: string, snapshot: string): Promise<Candidate[]> {
  let parsed: unknown;
  try { parsed = JSON.parse(output); } catch { throw new Error("Semgrep output must be valid JSON"); }
  const root = record(parsed, "Semgrep output");
  if (!Array.isArray(root.results)) throw new Error("Semgrep results must be an array");
  const repositoryId = stableHash({ snapshot: resolve(snapshot) });
  const candidates: Candidate[] = [];
  for (const [index, value] of root.results.entries()) {
    const result = record(value, `Semgrep result ${index}`);
    if (typeof result.check_id !== "string" || rules[result.check_id] === undefined) throw new Error("Semgrep reported an unknown rule");
    const start = record(result.start, "Semgrep start");
    const end = record(result.end, "Semgrep end");
    const extra = record(result.extra, "Semgrep extra");
    record(extra.metavars, "Semgrep metavariables");
    const rule = rules[result.check_id]!;
    candidates.push(candidate(repositoryId, "semgrep", rule.familyHint, rule.rootOperation, await fileSpan(resolve(snapshot), scannerPath(result.path), line(start.line, "Semgrep start"), line(end.line, "Semgrep end"))));
  }
  return deduplicateCandidates(candidates);
}

export async function runSemgrep(snapshot: string, rulePath: string, runner: ProcessRunner = runProcess): Promise<Candidate[]> {
  const source = await directory(snapshot);
  const localRules = await ruleFile(rulePath);
  const result = await runner("docker", semgrepDockerArgs(source, localRules));
  if (result.code !== 0) throw new Error(`Semgrep failed with exit ${result.code}: ${result.stderr}`);
  return parseSemgrepResults(result.stdout, source);
}

async function units(snapshot: string): Promise<Unit[]> {
  const result: Unit[] = [];
  async function walk(current = ""): Promise<void> {
    const entries = await readdir(resolve(snapshot, current), { withFileTypes: true });
    for (const entry of entries.sort((left, right) => compare(left.name, right.name))) {
      const path = current === "" ? entry.name : `${current}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
      if (entry.isDirectory()) { if (!skipped.has(entry.name.toLowerCase())) await walk(path); }
      else if (entry.isFile() && extensions.has(extname(entry.name).toLowerCase())) {
        const text = await readFile(resolve(snapshot, ...path.split("/")), "utf8");
        const extension = extname(path).toLowerCase();
        const kind = extension === ".tsx" ? ts.ScriptKind.TSX : extension === ".jsx" ? ts.ScriptKind.JSX : extension === ".js" ? ts.ScriptKind.JS : ts.ScriptKind.TS;
        result.push({ path, text, source: ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind) });
      }
    }
  }
  await walk();
  return result;
}
function isFunction(node: ts.Node): node is ts.FunctionLikeDeclaration { return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node); }
function functionName(node: ts.FunctionLikeDeclaration): string | undefined {
  if (node.name !== undefined && ts.isIdentifier(node.name)) return node.name.text;
  return ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name) ? node.parent.name.text : undefined;
}
function callee(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (!ts.isPropertyAccessExpression(expression)) return undefined;
  const base = callee(expression.expression);
  return base === undefined ? undefined : `${base}.${expression.name.text}`;
}
function span(unit: Unit, node: ts.Node): Span {
  const startLine = unit.source.getLineAndCharacterOfPosition(node.getStart(unit.source)).line + 1;
  const endLine = unit.source.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
  return { path: unit.path, startLine, endLine, text: unit.text.split(/\r?\n/).slice(startLine - 1, endLine).join("\n") };
}
function requestProperty(node: ts.PropertyAccessExpression): boolean {
  const names: string[] = [];
  let current: ts.Expression = node;
  while (ts.isPropertyAccessExpression(current)) { names.unshift(current.name.text); current = current.expression; }
  if (ts.isIdentifier(current)) names.unshift(current.text);
  return (names[0] === "req" || names[0] === "request") && ["query", "body", "params"].includes(names[1] ?? "") && names.length >= 3;
}
function contains(parent: ts.Node, child: ts.Node): boolean { return parent.pos <= child.pos && child.end <= parent.end; }
function owner(node: ts.Node): ts.FunctionLikeDeclaration | undefined { for (let current: ts.Node | undefined = node; current !== undefined; current = current.parent) if (isFunction(current)) return current; return undefined; }
function pathArgument(call: ts.CallExpression): string | undefined { const argument = call.arguments[0]; return argument !== undefined && (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) ? argument.text : undefined; }
function route(call: ts.CallExpression): boolean { return /\.(get|post|put|patch|delete|all|use)$/i.test(callee(call.expression) ?? "") && (pathArgument(call)?.includes(":") ?? false); }
function guard(node: ts.Expression): boolean { return /(?:owner|auth|permission|access)/i.test(node.getText()); }
function parameterized(call: ts.CallExpression): boolean { return call.arguments.length > 1 && /\.(query|execute|run)$/i.test(callee(call.expression) ?? ""); }
function sink(call: ts.CallExpression): { familyHint: Family; rootOperation: string } | undefined {
  const name = callee(call.expression) ?? "";
  const leaf = name.split(".").at(-1) ?? "";
  if (name === "eval" || leaf === "eval") return { familyHint: "injection", rootOperation: "eval" };
  if (["query", "execute", "run", "raw"].includes(leaf)) return { familyHint: "injection", rootOperation: leaf === "query" ? "query" : leaf };
  if (["exec", "execSync", "spawn", "spawnSync", "fork", "readFile", "readFileSync", "writeFile", "writeFileSync", "render", "compile"].includes(leaf)) return { familyHint: "injection", rootOperation: leaf === "exec" ? "exec" : leaf };
  if (["fetch", "request", "get", "post"].includes(leaf) && (name === "fetch" || /(?:axios|http|https|got|undici)/i.test(name))) return { familyHint: "ssrf", rootOperation: leaf === "fetch" ? "fetch" : leaf };
  return undefined;
}

export async function inventoryAst(snapshot: string): Promise<Candidate[]> {
  const source = await directory(snapshot);
  const repositoryId = stableHash({ snapshot: source });
  const files = await units(source);
  const functions = new Map<string, { unit: Unit; node: ts.FunctionLikeDeclaration }>();
  const calls: Array<{ unit: Unit; node: ts.CallExpression }> = [];
  const reads: Array<{ unit: Unit; node: ts.PropertyAccessExpression }> = [];
  for (const unit of files) {
    const visit = (node: ts.Node): void => {
      if (isFunction(node)) { const name = functionName(node); if (name !== undefined && !functions.has(name)) functions.set(name, { unit, node }); }
      if (ts.isCallExpression(node)) calls.push({ unit, node });
      if (ts.isPropertyAccessExpression(node) && requestProperty(node)) reads.push({ unit, node });
      ts.forEachChild(node, visit);
    };
    visit(unit.source);
  }
  const candidates: Candidate[] = [];
  for (const call of calls) {
    const details = sink(call.node);
    if (details === undefined) continue;
    const enclosing = owner(call.node);
    const related: Related[] = [];
    const requestReads = enclosing === undefined ? [] : reads.filter((read) => read.unit === call.unit && contains(enclosing, read.node));
    for (const read of requestReads) related.push({ ...span(call.unit, read.node), relationship: "flows_to" });
    const name = enclosing === undefined ? undefined : functionName(enclosing);
    if (enclosing !== undefined && name !== undefined) {
      related.push({ ...span(call.unit, enclosing), relationship: "calls" });
      const caller = calls.find((other) => other.unit === call.unit && other.node !== call.node && callee(other.node.expression) === name && !contains(enclosing, other.node));
      if (caller !== undefined) related.push({ ...span(call.unit, caller.node), relationship: "calls" });
    }
    const context = emptyContext();
    context.upstreamDataFlow = requestReads.length > 0 ? "resolved" : "unresolved";
    context.sanitizers = parameterized(call.node) ? "resolved" : "unresolved";
    context.callPath = enclosing === undefined || name === undefined || related.some((item) => item.relationship === "calls") ? "resolved" : "unresolved";
    candidates.push(candidate(repositoryId, "ast", details.familyHint, details.rootOperation, span(call.unit, call.node), related, context));
  }
  for (const call of calls.filter((item) => route(item.node))) {
    const handler = call.node.arguments.slice(1).find((argument) => isFunction(argument) || (ts.isIdentifier(argument) && !guard(argument)));
    const handlerNode = handler !== undefined && isFunction(handler) ? handler : handler !== undefined && ts.isIdentifier(handler) ? functions.get(handler.text)?.node : undefined;
    const related: Related[] = call.node.arguments.slice(1).filter(guard).map((item) => ({ ...span(call.unit, item), relationship: "guards" }));
    const requestReads = handlerNode === undefined ? [] : reads.filter((read) => read.unit === call.unit && contains(handlerNode, read.node));
    for (const read of requestReads) related.push({ ...span(call.unit, read.node), relationship: "flows_to" });
    const context = emptyContext();
    context.middleware = related.some((item) => item.relationship === "guards") ? "resolved" : "unresolved";
    context.authorization = context.middleware;
    context.upstreamDataFlow = requestReads.length > 0 ? "resolved" : "unresolved";
    context.callPath = handlerNode === undefined ? "unresolved" : "resolved";
    candidates.push(candidate(repositoryId, "ast", "broken_access_control", "route", span(call.unit, call.node), related, context));
  }
  return deduplicateCandidates(candidates);
}
