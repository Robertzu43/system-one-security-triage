import type { JevJudgment, RouterConfig } from "./contracts.js";
import type { DemoAdapter, DemoDecision, DemoEvaluator } from "./demo.js";
import { jevModel } from "./jev.js";
import type { EvidencePacket } from "./packets.js";
import { reasoningRunnerVersions, type ReasoningConfig, type ReasoningRequest, type ReasoningResult, runReasoningReview } from "./reasoning.js";
import { parseRouterConfig, route } from "./router.js";

type JudgeJev = (stateJson: string) => Promise<JevJudgment>;
type RunReasoning = (request: ReasoningRequest, config: ReasoningConfig) => Promise<ReasoningResult>;

const routerConfig: RouterConfig = parseRouterConfig({
  contextMin: 0.70,
  safeRiskMax: 0.20,
  highRiskMin: 0.80,
  pathMin: 0.70,
  controlEffectiveMin: 0.80,
  controlAbsentMax: 0.20,
  impactMin: 0.70,
  directExploitabilityMin: 2.50
});

const reasoningInstructions = "Classify the supplied code evidence as vulnerable, safe, or insufficient_context. For vulnerable, return exactly one family: injection, broken_access_control, or ssrf. For safe and insufficient_context, return family null. Missing code is not evidence that a control is absent or that code is safe; use insufficient_context whenever a required authorization, sanitization, middleware, upstream-flow, or call-path fact is not shown.";

function diagnostic(text: string): string {
  return text
    .replace(/(?:apikey_|sk-)[A-Za-z0-9_-]+/gi, "[redacted]")
    .replace(/\/(?:Users|private|Volumes)\/[^\s;,"'`]+/g, "[local-path]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 500);
}

function jevFamily(judgment: Exclude<JevJudgment, { kind: "abstain" }>): DemoDecision["family"] {
  const values = [
    ["injection", judgment.answers.is_injection.noul],
    ["broken_access_control", judgment.answers.is_broken_access_control.noul],
    ["ssrf", judgment.answers.is_ssrf.noul]
  ] as const;
  return values.reduce((best, value) => value[1] > best[1] ? value : best)[0];
}

export function createJevDemoAdapter(judge: JudgeJev): DemoAdapter {
  return {
    name: "jev",
    metadata: { provider: "TypeSafe", modelId: jevModel, runner: "@typesafe-ai/sdk", runnerVersion: "0.6.0" },
    evaluate: async (stateJson, item) => {
      const judgment = await judge(stateJson);
      if (judgment.kind === "abstain") throw new Error(`${judgment.error.name}: ${judgment.error.message}`);
      const outcome = route({ contextResolution: item.state.contextResolution } as EvidencePacket, judgment, routerConfig);
      const base = { inputTokens: judgment.usage.input_tokens, outputTokens: judgment.usage.output_tokens };
      if (outcome === "likely_vulnerability") return { disposition: "vulnerable", family: jevFamily(judgment), ...base };
      if (outcome === "likely_safe") return { disposition: "safe", family: null, ...base };
      return { disposition: "insufficient_context", family: null, ...base };
    }
  };
}

export function createReasoningDemoAdapter(evaluator: Exclude<DemoEvaluator, "jev">, emptySnapshot: string, runner: RunReasoning = runReasoningReview, config: ReasoningConfig = {}): DemoAdapter {
  return {
    name: evaluator,
    metadata: evaluator === "terra"
      ? { provider: "OpenAI", modelId: "gpt-5.6-terra", runner: "codex-cli", runnerVersion: reasoningRunnerVersions.terra.replace("codex-cli ", "") }
      : { provider: "Anthropic", modelId: "claude-opus-4-6", runner: "claude-code", runnerVersion: reasoningRunnerVersions.opus.replace(" (Claude Code)", "") },
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
        ...(result.chargeUsd === null ? {} : { costUsd: result.chargeUsd })
      };
    }
  };
}
