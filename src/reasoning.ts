import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export type ReasoningEvaluator = "terra" | "opus";
export type ReasoningMode = "agentic" | "controlled";
export type StructuredReview = { decision: "vulnerable" | "safe" | "abstain"; family: "injection" | "broken_access_control" | "ssrf"; evidence_span_ids: string[]; };
export type ReasoningFailureKind = "timeout" | "malformed_output" | "tool_denied" | "budget_exhausted" | "nonzero_exit" | "spawn_error";
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
}
export interface ReasoningResult {
  readonly finalOutcome: "alert" | "no_alert" | "manual_review";
  readonly output: StructuredReview | null;
  readonly usage: { inputTokens: number; outputTokens: number } | null;
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
function finalOutput(text: string): StructuredReview {
  const parsed = JSON.parse(text) as unknown;
  const outer = record(parsed);
  if (outer !== null && typeof outer.result === "string") return parseStructured(JSON.parse(outer.result));
  return parseStructured(parsed);
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
  const tools = request.mode === "controlled" ? "" : "Read,Grep,Glob";
  return {
    command: executable,
    args: ["--print", "--safe-mode", "--no-session-persistence", "--restricted", "--permission-mode", "dontAsk", "--allowedTools", tools, "--model", request.model, "--json-schema", compactSchema, "--output-format", "json"],
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

export async function runReasoningReview(request: ReasoningRequest, config: ReasoningConfig): Promise<ReasoningResult> {
  if (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 1 || !Number.isInteger(request.tokenBudget) || request.tokenBudget < 1 || !Number.isInteger(request.toolBudget) || request.toolBudget < 1) throw new Error("reasoning limits must be positive integers");
  if (request.providerChargeUsd !== undefined && (!Number.isFinite(request.providerChargeUsd) || request.providerChargeUsd < 0)) throw new Error("providerChargeUsd must be non-negative and finite");
  const outputRoot = config.outputDirectory ?? tmpdir();
  const outputDirectory = await mkdtemp(join(outputRoot, "reasoning-"));
  const outputPath = join(outputDirectory, "last-message.json");
  const chargeUsd = request.providerChargeUsd ?? null;
  const base = { usage: null, chargeUsd, costStatus: chargeUsd === null ? "inconclusive" as const : "available" as const, attempts: 1, stdout: "", stderr: "" };
  try {
    const compactSchema = JSON.stringify(JSON.parse(await readFile(resolve(request.schemaPath), "utf8")));
    const processResult = await execute(command(request, config.executable ?? (request.evaluator === "terra" ? "codex" : "claude"), outputPath, compactSchema), request.prompt, request.timeoutMs, minimalEnvironment(config));
    const resultBase = { ...base, usage: usageFrom(processResult.stdout), stdout: processResult.stdout, stderr: processResult.stderr };
    if (processResult.timedOut) return failure("timeout", `review exceeded ${request.timeoutMs}ms`, resultBase);
    if (processResult.spawnError !== null) return failure("spawn_error", processResult.spawnError.message, resultBase);
    if (processResult.code !== 0) return failure(reasonForFailure(processResult.stderr, processResult.code), `review exited ${processResult.code}`, resultBase);
    let text = processResult.stdout;
    try { text = await readFile(outputPath, "utf8"); } catch { /* Opus returns final output on stdout. */ }
    try {
      const output = finalOutput(text);
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
