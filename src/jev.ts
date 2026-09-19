import { choice, noul, score, type EntryType, type TypeSafeClient } from "@typesafe-ai/sdk";
import type { JevAbstention, JevAnswers, JevJudgment, NoulAnswer, ScoreAnswer } from "./contracts.js";
import { parseDemoChoice, type DemoChoice } from "./demo.js";
import type { EvidencePacket } from "./packets.js";

export const questionIds = ["untrusted_influence", "reaches_sensitive_operation", "validation_blocks_attack", "crosses_authorization_boundary", "authorization_enforced", "security_impact", "is_injection", "is_broken_access_control", "is_ssrf", "enough_context", "exploitability"] as const;
export const jevModel = "jev-1.13.0";

const questions = {
  untrusted_influence: noul("Can an untrusted actor influence data used by the shown operation?"),
  reaches_sensitive_operation: noul("Can the influenced data reach the shown sensitive operation?"),
  validation_blocks_attack: noul("Does shown validation or sanitization block the relevant injection or SSRF attack?"),
  crosses_authorization_boundary: noul("Can an actor cross the shown authorization boundary?"),
  authorization_enforced: noul("Is authorization effectively enforced for the shown sensitive operation?"),
  security_impact: noul("Would successful exploitation of the shown behavior have a security impact?"),
  is_injection: noul("Does the shown evidence support an injection vulnerability?"),
  is_broken_access_control: noul("Does the shown evidence support a broken access control vulnerability?"),
  is_ssrf: noul("Does the shown evidence support a server-side request forgery vulnerability?"),
  enough_context: noul("Is there enough shown evidence to make a reliable security judgment?"),
  exploitability: score("How exploitable is the shown behavior?", [
    "Unreachable: the shown data or actor cannot reach the operation",
    "Theoretical: a path is imaginable but required evidence or preconditions are absent",
    "Constrained: the path exists but a meaningful restriction or uncommon precondition limits exploitation",
    "Direct: an untrusted actor can reach the sensitive behavior with no effective shown control"
  ])
} as const;

const demoCriteria = {
  vulnerable_injection: "Shown evidence establishes untrusted influence over executable command, query, expression, template, interpreter, or equivalent syntax; the path reaches the sensitive operation; no effective shown control blocks it; and security impact is plausible.",
  vulnerable_broken_access_control: "Shown evidence establishes that an actor can perform an operation or access a resource without the authorization required for that actor, operation, or resource.",
  vulnerable_ssrf: "Shown evidence establishes that an actor can influence a server-side request to reach an unintended destination or network resource without an effective shown destination restriction.",
  safe: "The relevant tested path is shown and an effective shown control prevents the tested vulnerability. Missing code or an unshown helper is not evidence of safety.",
  insufficient_context: "Evidence required to establish vulnerability or safety is not shown, including a hidden helper, middleware, sanitizer, authorization check, upstream data flow, destination policy, or call path."
} as const;

const demoQuestions = {
  classification: choice({
    task: "Classify the shown security evidence into exactly one outcome using only facts present in the state.",
    vulnerable: "A vulnerability requires shown untrusted influence, a path to security-sensitive behavior, no effective shown control for that path, and plausible security impact.",
    missing_evidence: "Do not infer that omitted code is safe or unsafe; select insufficient_context when required evidence is not shown."
  }, demoCriteria)
} as const;

export type JevDemoJudgment = {
  readonly kind: "judgment";
  readonly model: string;
  readonly usage: { readonly input_tokens: number; readonly output_tokens: number };
  readonly choice: DemoChoice;
} | JevAbstention;

function record(value: unknown): Record<string, unknown> | undefined { return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function probability(value: unknown): value is number { return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1; }
function noulAnswer(value: unknown): value is NoulAnswer { const answer = record(value); return answer?.type === "noul" && probability(answer.noul); }
function scoreAnswerError(value: unknown): string | null {
  const answer = record(value); const probabilities = record(answer?.probabilities); const legend = record(answer?.legend);
  const levels = ["0", "1", "2", "3"] as const;
  const probabilityTolerance = 0.02;
  const scoreTolerance = 0.05;
  if (answer?.type !== "score") return "exploitability type is invalid";
  if (typeof answer.score !== "number" || !Number.isFinite(answer.score) || answer.score < 0 || answer.score > 3) return "exploitability score is invalid";
  if (!probability(answer.confidence)) return "exploitability confidence is invalid";
  if (probabilities === undefined || !levels.every((key) => probability(probabilities[key])) || Object.keys(probabilities).length !== 4) return "exploitability probabilities are invalid";
  if (legend === undefined || !levels.every((key) => key in legend)) return "exploitability legend is invalid";
  const sum = levels.reduce((total, key) => total + (probabilities[key] as number), 0);
  if (Math.abs(sum - 1) > probabilityTolerance) return `exploitability probabilities sum to ${sum}`;
  const weightedMean = levels.reduce((total, key) => total + Number(key) * (probabilities[key] as number), 0);
  return Math.abs(answer.score - weightedMean) <= scoreTolerance ? null : `exploitability score ${answer.score} differs from weighted mean ${weightedMean}`;
}
function answersError(value: unknown): string | null {
  const result = record(value);
  if (result === undefined) return "answers must be an object";
  for (const id of questionIds.slice(0, -1)) if (!noulAnswer(result[id])) return `invalid ${id}`;
  return scoreAnswerError(result.exploitability);
}
function abstain(error: unknown): JevAbstention {
  const value = error instanceof Error ? error : new Error(String(error));
  return { kind: "abstain", error: { name: value.name, message: value.message } };
}

export async function judgeDemoWithJev(state: string, client: Pick<TypeSafeClient, "systemOne">): Promise<JevDemoJudgment> {
  try {
    const response: unknown = await client.systemOne({ state, model: jevModel, questions: demoQuestions });
    const result = record(response); const usage = record(result?.usage); const answers = record(result?.answers); const answer = record(answers?.classification);
    if (typeof result?.model !== "string" || result.model.length === 0 || usage === undefined || !Number.isInteger(usage.input_tokens) || (usage.input_tokens as number) < 0 || !Number.isInteger(usage.output_tokens) || (usage.output_tokens as number) < 0) throw new Error("malformed Jev response: invalid envelope");
    if (answer?.type !== "choice") throw new Error("malformed Jev response: classification type is invalid");
    const parsed = parseDemoChoice({ selected: answer.choice, confidence: answer.confidence, probabilities: answer.probabilities }, "classification");
    return { kind: "judgment", model: result.model, usage: { input_tokens: usage.input_tokens as number, output_tokens: usage.output_tokens as number }, choice: parsed };
  } catch (error) {
    return abstain(error);
  }
}

export async function judgeWithJev(packet: EvidencePacket | string, client: Pick<TypeSafeClient, "systemOne">): Promise<JevJudgment> {
  try {
    const response: unknown = await client.systemOne({ state: packet as unknown as EntryType, model: jevModel, questions });
    const result = record(response); const usage = record(result?.usage);
    if (typeof result?.model !== "string" || result.model.length === 0 || usage === undefined || !Number.isInteger(usage.input_tokens) || (usage.input_tokens as number) < 0 || !Number.isInteger(usage.output_tokens) || (usage.output_tokens as number) < 0) throw new Error("malformed Jev response: invalid envelope");
    const answerProblem = answersError(result.answers);
    if (answerProblem !== null) throw new Error(`malformed Jev response: ${answerProblem}`);
    return { kind: "judgment", model: result.model, usage: { input_tokens: usage.input_tokens as number, output_tokens: usage.output_tokens as number }, answers: result.answers as JevAnswers };
  } catch (error) {
    return abstain(error);
  }
}
