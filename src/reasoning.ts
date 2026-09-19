import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, resolve, sep } from "node:path";

export type ReasoningEvaluator = "terra" | "opus";
export type ReasoningMode = "agentic" | "controlled" | "demo";
export type StructuredReview = { decision: "vulnerable" | "safe" | "abstain"; family: "injection" | "broken_access_control" | "ssrf"; evidence_span_ids: string[]; };
export type ReasoningFailureKind = "timeout" | "malformed_output" | "tool_denied" | "budget_exhausted" | "budget_unverifiable" | "version_mismatch" | "unsupported_platform" | "nonzero_exit" | "spawn_error";
export interface ReasoningRequest {
  readonly evaluator: ReasoningEvaluator;
  readonly mode: ReasoningMode;
  readonly prompt: string;
  readonly snapshot: string;
  readonly schemaPath: string;
  readonly timeoutMs: number;
  readonly tokenBudget: number;
  readonly toolBudget: number;
  readonly model?: string;
  readonly providerChargeUsd?: number;
}
export interface ReasoningConfig {
  readonly executable?: string;
  readonly outputDirectory?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly environmentKeys?: readonly string[];
  readonly platform?: NodeJS.Platform;
}
export interface ReasoningResult {
  readonly finalOutcome: "alert" | "no_alert" | "manual_review";
  readonly output: StructuredReview | null;
  readonly usage: { inputTokens: number; outputTokens: number } | null;
  readonly usageStatus: "available" | "inconclusive";
  readonly chargeUsd: number | null;
  readonly costStatus: "available" | "inconclusive";
  readonly attempts: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly error: { kind: ReasoningFailureKind; message: string } | null;
}

interface Command { command: string; args: string[]; cwd: string; }
interface ProcessResult { code: number; stdout: string; stderr: string; timedOut: boolean; spawnError: Error | null; }

const decisions = new Set<StructuredReview["decision"]>(["vulnerable", "safe", "abstain"]);
const families = new Set<StructuredReview["family"]>(["injection", "broken_access_control", "ssrf"]);
export const reasoningRunnerVersions: Readonly<Record<ReasoningEvaluator, string>> = { terra: "codex-cli 0.147.0", opus: "2.1.277 (Claude Code)" };

function record(value: unknown): Record<string, unknown> | null { return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null; }
function usage(value: unknown): ReasoningResult["usage"] {
  const root = record(value); const parsed = record(root?.usage);
  const input = parsed?.input_tokens ?? parsed?.inputTokens;
  const output = parsed?.output_tokens ?? parsed?.outputTokens;
  return typeof input === "number" && Number.isInteger(input) && input >= 0 && typeof output === "number" && Number.isInteger(output) && output >= 0 ? { inputTokens: input, outputTokens: output } : null;
}
function parseStructured(value: unknown): StructuredReview {
  const root = record(value);
  if (root === null || Object.keys(root).length !== 3 || !("decision" in root) || !("family" in root) || !("evidence_span_ids" in root) || !decisions.has(root.decision as StructuredReview["decision"]) || !families.has(root.family as StructuredReview["family"]) || !Array.isArray(root.evidence_span_ids) || !root.evidence_span_ids.every((id) => typeof id === "string" && /^s[1-9][0-9]*$/.test(id)) || new Set(root.evidence_span_ids).size !== root.evidence_span_ids.length) throw new Error("malformed structured output");
  return { decision: root.decision as StructuredReview["decision"], family: root.family as StructuredReview["family"], evidence_span_ids: [...root.evidence_span_ids] as string[] };
}
function parseDemoStructured(value: unknown): StructuredReview {
  const root = record(value);
  if (root === null || Object.keys(root).length !== 2 || !("decision" in root) || !("family" in root)) throw new Error("malformed demo output");
  const decision = root.decision;
  if (decision !== "vulnerable" && decision !== "safe" && decision !== "insufficient_context") throw new Error("malformed demo output");
  if (decision === "vulnerable") {
    if (!families.has(root.family as StructuredReview["family"])) throw new Error("malformed demo output");
    return { decision, family: root.family as StructuredReview["family"], evidence_span_ids: [] };
  }
  if (root.family !== null) throw new Error("malformed demo output");
  return { decision: decision === "safe" ? "safe" : "abstain", family: "injection", evidence_span_ids: [] };
}
function finalOutput(text: string, mode: ReasoningMode): StructuredReview {
  const parsed = JSON.parse(text) as unknown;
  const outer = record(parsed);
  const value = outer !== null && outer.structured_output !== undefined ? outer.structured_output : outer !== null && typeof outer.result === "string" ? JSON.parse(outer.result) : parsed;
  return mode === "demo" ? parseDemoStructured(value) : parseStructured(value);
}
function failure(kind: ReasoningFailureKind, message: string, result: Omit<ReasoningResult, "finalOutcome" | "output" | "error">): ReasoningResult {
  return { ...result, finalOutcome: "manual_review", output: null, error: { kind, message } };
}
function minimalEnvironment(config: ReasoningConfig): NodeJS.ProcessEnv {
  const source = config.environment ?? process.env;
  const selected: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", ...(config.environmentKeys ?? [])]) if (!/^(?:all_|http_|https_|no_)?proxy$/i.test(key) && typeof source[key] === "string") selected[key] = source[key];
  return selected;
}
function reasonForFailure(stderr: string, code: number): ReasoningFailureKind {
  if (/(?:denied|required tool|permission)/i.test(stderr)) return "tool_denied";
  if (/(?:budget|token limit|tool limit|exhausted)/i.test(stderr)) return "budget_exhausted";
  return code === -1 ? "spawn_error" : "nonzero_exit";
}
function command(request: ReasoningRequest, executable: string, outputPath: string, compactSchema: string): Command {
  if (request.evaluator === "terra") return {
    command: executable,
    args: ["exec", "--ephemeral", "--ignore-user-config", "--model", "gpt-5.6-terra", "--sandbox", "read-only", "--cd", request.snapshot, "--output-schema", resolve(request.schemaPath), "--output-last-message", outputPath, "-"],
    cwd: request.snapshot
  };
  if (request.model === undefined || request.model.length === 0) throw new Error("Opus requires a frozen full model ID");
  const tools = request.mode === "agentic" ? "Read,Grep,Glob" : "";
  return {
    command: executable,
    args: ["--print", "--bare", "--no-session-persistence", "--restricted", "--strict-mcp-config", "--permission-mode", "dontAsk", "--permission-prompts", "none", "--tools", tools, "--model", request.model, "--json-schema", compactSchema, "--output-format", "json"],
    cwd: request.snapshot
  };
}

async function execute(command: Command, prompt: string, timeoutMs: number, environment: NodeJS.ProcessEnv): Promise<ProcessResult> {
  return new Promise((done) => {
    let stdout = "";
    let stderr = "";
    let spawnError: Error | null = null;
    let timedOut = false;
    const child = spawn(command.command, command.args, { cwd: command.cwd, env: environment, shell: false, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      timedOut = true;
      if (child.pid !== undefined && process.platform !== "win32") {
        try { process.kill(-child.pid, "SIGKILL"); return; } catch { /* child may already have exited */ }
      }
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", (error) => { spawnError = error; });
    child.once("close", (code) => { clearTimeout(timer); done({ code: code ?? -1, stdout, stderr, timedOut, spawnError }); });
    child.stdin.end(prompt);
  });
}

async function executablePath(executable: string, environment: NodeJS.ProcessEnv): Promise<string> {
  if (isAbsolute(executable) || executable.includes(sep)) return realpath(resolve(executable));
  for (const directory of (environment.PATH ?? "").split(delimiter)) {
    if (directory.length === 0) continue;
    const candidate = join(directory, executable);
    try { await access(candidate); return realpath(candidate); } catch { /* keep searching PATH */ }
  }
  throw new Error(`executable not found on PATH: ${executable}`);
}

function sandboxProfile(snapshot: string, schemaPath: string, outputDirectory: string, executable: string, environment: NodeJS.ProcessEnv): string {
  const home = environment.HOME;
  const authFiles = home === undefined ? [] : [join(home, ".codex/auth.json"), join(home, ".claude.json"), join(home, ".claude/.credentials.json")];
  const subpaths = [snapshot].map((path) => `(subpath ${JSON.stringify(resolve(path))})`).join(" ");
  const literals = [schemaPath, executable, ...authFiles].map((path) => `(literal ${JSON.stringify(resolve(path))})`).join(" ");
  return `(version 1)\n(allow default)\n(deny file-read-data (subpath \"/Users\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\") (subpath \"/Volumes\"))\n(allow file-read-data ${subpaths} ${literals})\n(deny file-write*)\n(allow file-write* (subpath ${JSON.stringify(outputDirectory)}) (literal \"/dev/null\"))\n`;
}

function toolCallsFrom(stdout: string): number | null {
  try {
    const parsed = record(JSON.parse(stdout));
    const count = parsed?.tool_calls ?? parsed?.toolCalls;
    return typeof count === "number" && Number.isInteger(count) && count >= 0 ? count : null;
  } catch { return null; }
}

export async function runReasoningReview(request: ReasoningRequest, config: ReasoningConfig): Promise<ReasoningResult> {
  if (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 1 || !Number.isInteger(request.tokenBudget) || request.tokenBudget < 1 || !Number.isInteger(request.toolBudget) || request.toolBudget < 1) throw new Error("reasoning limits must be positive integers");
  if (request.providerChargeUsd !== undefined && (!Number.isFinite(request.providerChargeUsd) || request.providerChargeUsd < 0)) throw new Error("providerChargeUsd must be non-negative and finite");
  const outputRoot = config.outputDirectory ?? tmpdir();
  const outputDirectory = await mkdtemp(join(outputRoot, "reasoning-"));
  const outputPath = join(outputDirectory, "last-message.json");
  const chargeUsd = request.providerChargeUsd ?? null;
  const emptyBase = { usage: null, usageStatus: "inconclusive" as const, chargeUsd, costStatus: chargeUsd === null ? "inconclusive" as const : "available" as const, attempts: 0, stdout: "", stderr: "" };
  try {
    if ((config.platform ?? process.platform) !== "darwin") return failure("unsupported_platform", "snapshot-only filesystem isolation is unavailable on this platform", emptyBase);
    if (request.evaluator === "terra" && request.mode === "controlled") return failure("budget_unverifiable", "controlled Terra cannot disable all repository tools with the frozen CLI", emptyBase);
    const environment = minimalEnvironment(config);
    const executable = config.executable ?? (request.evaluator === "terra" ? "codex" : "claude");
    const version = await execute({ command: executable, args: ["--version"], cwd: request.snapshot }, "", request.timeoutMs, environment);
    if (version.timedOut) return failure("timeout", "CLI version check timed out", { ...emptyBase, stderr: version.stderr });
    if (version.spawnError !== null) return failure("spawn_error", version.spawnError.message, { ...emptyBase, stderr: version.stderr });
    if (version.code !== 0) return failure("nonzero_exit", `CLI version check exited ${version.code}`, { ...emptyBase, stdout: version.stdout, stderr: version.stderr });
    if (version.stdout.trim() !== reasoningRunnerVersions[request.evaluator]) return failure("version_mismatch", `expected ${reasoningRunnerVersions[request.evaluator]}, received ${version.stdout.trim() || "empty version"}`, { ...emptyBase, stdout: version.stdout, stderr: version.stderr });
    const compactSchema = JSON.stringify(JSON.parse(await readFile(resolve(request.schemaPath), "utf8")));
    const inner = command(request, await executablePath(executable, environment), outputPath, compactSchema);
    const profilePath = join(outputDirectory, "filesystem.sb");
    await writeFile(profilePath, sandboxProfile(await realpath(request.snapshot), await realpath(resolve(request.schemaPath)), await realpath(outputDirectory), inner.command, environment), { encoding: "utf8", mode: 0o600 });
    const processResult = await execute({ command: "/usr/bin/sandbox-exec", args: ["-f", profilePath, inner.command, ...inner.args], cwd: inner.cwd }, request.prompt, request.timeoutMs, environment);
    const observedUsage = usageFrom(processResult.stdout);
    const resultBase = { ...emptyBase, usage: observedUsage, usageStatus: observedUsage === null ? "inconclusive" as const : "available" as const, attempts: 1, stdout: processResult.stdout, stderr: processResult.stderr };
    if (processResult.timedOut) return failure("timeout", `review exceeded ${request.timeoutMs}ms`, resultBase);
    if (processResult.spawnError !== null) return failure("spawn_error", processResult.spawnError.message, resultBase);
    if (processResult.code !== 0) return failure(reasonForFailure(processResult.stderr, processResult.code), `review exited ${processResult.code}`, resultBase);
    let text = processResult.stdout;
    try { text = await readFile(outputPath, "utf8"); } catch { /* Opus returns final output on stdout. */ }
    try {
      const output = finalOutput(text, request.mode);
      if (observedUsage === null && request.mode !== "demo") return failure("budget_unverifiable", "token usage is unavailable from the frozen CLI output", resultBase);
      if (observedUsage !== null && observedUsage.inputTokens + observedUsage.outputTokens > request.tokenBudget) return failure("budget_exhausted", `review used more than ${request.tokenBudget} tokens`, resultBase);
      const toolCalls = request.mode === "controlled" ? 0 : toolCallsFrom(processResult.stdout);
      if (toolCalls === null && request.mode !== "demo") return failure("budget_unverifiable", "tool-call usage is unavailable from the frozen CLI output", resultBase);
      if (toolCalls !== null && toolCalls > request.toolBudget) return failure("budget_exhausted", `review used more than ${request.toolBudget} tool calls`, resultBase);
      return { ...resultBase, finalOutcome: output.decision === "vulnerable" ? "alert" : output.decision === "safe" ? "no_alert" : "manual_review", output, error: null };
    } catch (error) {
      return failure("malformed_output", error instanceof Error ? error.message : "malformed structured output", resultBase);
    }
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
}

function usageFrom(stdout: string): ReasoningResult["usage"] {
  try { return usage(JSON.parse(stdout)); } catch { return null; }
}
