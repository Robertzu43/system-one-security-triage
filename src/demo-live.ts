import { performance } from "node:perf_hooks";
import { decisionForChoice, type DemoAdapter, type DemoEvaluator } from "./demo.js";
import { demoCriteria, jevChoiceSpec, jevModel, type JevDemoJudgment } from "./jev.js";
import { stableHash } from "./jsonl.js";
import { reasoningRunnerVersions, type ReasoningConfig, type ReasoningRequest, type ReasoningResult, runReasoningReview } from "./reasoning.js";

/** Jev receives the canonical evidence as a JSON object, the form TypeSafe documents for structured state. */
type JudgeJev = (state: Record<string, unknown>) => Promise<JevDemoJudgment>;
type RunReasoning = (request: ReasoningRequest, config: ReasoningConfig) => Promise<ReasoningResult>;

/**
 * Built from the same `demoCriteria` Jev receives, so all three evaluators are held to one
 * definition of each outcome. Jev takes the criteria as a typed Choice; the reasoning models take
 * the identical text with the output contract their schema needs.
 */
export const reasoningInstructions = [
  "Classify the supplied code evidence into exactly one outcome, using only facts present in the evidence.",
  "",
  "Outcomes:",
  ...Object.entries(demoCriteria).map(([outcome, definition]) => `- ${outcome}: ${definition}`),
  "",
  "A vulnerability requires shown untrusted influence, a path to security-sensitive behavior, no effective shown control for that path, and plausible security impact.",
  "Do not infer that omitted code is safe or unsafe; select insufficient_context when required evidence is not shown.",
  "",
  "Return decision \"vulnerable\" with exactly one family (injection, broken_access_control, or ssrf), or decision \"safe\" or \"insufficient_context\" with family null."
].join("\n");

/** Identifies the exact prompt each evaluator received, so runs are only pooled when it matches. */
export const jevPromptSpecHash = stableHash({ choice: jevChoiceSpec, criteria: demoCriteria });
export const reasoningPromptSpecHash = stableHash(reasoningInstructions);

function diagnostic(text: string): string {
  return text
    .replace(/(?:apikey_|sk-)[A-Za-z0-9_-]+/gi, "[redacted]")
    .replace(/\/(?:Users|private|Volumes)\/[^\s;,"'`]+/g, "[local-path]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 500);
}

export function createJevDemoAdapter(judge: JudgeJev): DemoAdapter {
  return {
    name: "jev",
    metadata: { provider: "TypeSafe", modelId: jevModel, runner: "@typesafe-ai/sdk", runnerVersion: "0.6.0", promptSpecHash: jevPromptSpecHash },
    evaluate: async (stateJson) => {
      const state = JSON.parse(stateJson) as Record<string, unknown>;
      const started = performance.now();
      const judgment = await judge(state);
      const modelLatencyMs = performance.now() - started;
      if (judgment.kind === "abstain") throw new Error(`${judgment.error.name}: ${judgment.error.message}`);
      return {
        ...decisionForChoice(judgment.choice.selected),
        choice: judgment.choice,
        inputTokens: judgment.usage.input_tokens,
        outputTokens: judgment.usage.output_tokens,
        modelLatencyMs
      };
    }
  };
}

export function createReasoningDemoAdapter(evaluator: Exclude<DemoEvaluator, "jev">, emptySnapshot: string, runner: RunReasoning = runReasoningReview, config: ReasoningConfig = {}): DemoAdapter {
  return {
    name: evaluator,
    metadata: evaluator === "terra"
      ? { provider: "OpenAI", modelId: "gpt-5.6-terra", runner: "codex-cli", runnerVersion: reasoningRunnerVersions.terra.replace("codex-cli ", ""), promptSpecHash: reasoningPromptSpecHash }
      : { provider: "Anthropic", modelId: "claude-opus-4-6", runner: "claude-code", runnerVersion: reasoningRunnerVersions.opus.replace(" (Claude Code)", ""), promptSpecHash: reasoningPromptSpecHash },
    evaluate: async (stateJson) => {
      const result = await runner({
        evaluator,
        mode: "demo",
        prompt: `${reasoningInstructions}\n\nEvidence JSON:\n${stateJson}`,
        snapshot: emptySnapshot,
        schemaPath: "config/demo-output.schema.json",
        timeoutMs: 120_000,
        tokenBudget: 8_000,
        toolBudget: 1,
        ...(evaluator === "opus" ? { model: "claude-opus-4-6" } : {})
      }, config);
      if (result.error !== null || result.output === null) {
        const detail = diagnostic(result.stderr || result.stdout);
        throw new Error(`${result.error?.kind ?? "no_output"}: ${result.error?.message ?? "model returned no decision"}${detail ? `; stderr: ${detail}` : ""}`);
      }
      const output = result.output;
      const disposition = output.decision === "abstain" ? "insufficient_context" : output.decision;
      return {
        disposition,
        family: disposition === "vulnerable" ? output.family : null,
        ...(result.usage === null ? {} : { inputTokens: result.usage.inputTokens, outputTokens: result.usage.outputTokens }),
        ...(result.chargeUsd === null ? {} : { costUsd: result.chargeUsd }),
        modelLatencyMs: result.modelLatencyMs
      };
    }
  };
}
