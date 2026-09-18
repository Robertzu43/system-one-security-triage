import { noul, score, type EntryType, type TypeSafeClient } from "@typesafe-ai/sdk";
import type { JevAnswers, JevJudgment, NoulAnswer, ScoreAnswer } from "./contracts.js";
import type { EvidencePacket } from "./packets.js";

export const questionIds = ["untrusted_influence", "reaches_sensitive_operation", "validation_blocks_attack", "crosses_authorization_boundary", "authorization_enforced", "security_impact", "is_injection", "is_broken_access_control", "is_ssrf", "enough_context", "exploitability"] as const;

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

function record(value: unknown): Record<string, unknown> | undefined { return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function probability(value: unknown): value is number { return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1; }
function noulAnswer(value: unknown): value is NoulAnswer { const answer = record(value); return answer?.type === "noul" && probability(answer.noul); }
function scoreAnswer(value: unknown): value is ScoreAnswer {
  const answer = record(value); const probabilities = record(answer?.probabilities); const legend = record(answer?.legend);
  const levels = ["0", "1", "2", "3"] as const;
  if (answer?.type !== "score" || typeof answer.score !== "number" || !Number.isFinite(answer.score) || answer.score < 0 || answer.score > 3 || !probability(answer.confidence) || probabilities === undefined || legend === undefined || !levels.every((key) => probability(probabilities[key])) || Object.keys(probabilities).length !== 4 || !levels.every((key) => key in legend) || Math.abs(levels.reduce((sum, key) => sum + (probabilities[key] as number), 0) - 1) >= 1e-9) return false;
  return Math.abs(answer.score - levels.reduce((sum, key) => sum + Number(key) * (probabilities[key] as number), 0)) < 1e-9;
}
function answers(value: unknown): value is JevAnswers {
  const result = record(value);
  return result !== undefined && noulAnswer(result.untrusted_influence) && noulAnswer(result.reaches_sensitive_operation) && noulAnswer(result.validation_blocks_attack) && noulAnswer(result.crosses_authorization_boundary) && noulAnswer(result.authorization_enforced) && noulAnswer(result.security_impact) && noulAnswer(result.is_injection) && noulAnswer(result.is_broken_access_control) && noulAnswer(result.is_ssrf) && noulAnswer(result.enough_context) && scoreAnswer(result.exploitability);
}
function abstain(error: unknown): JevJudgment {
  const value = error instanceof Error ? error : new Error(String(error));
  return { kind: "abstain", error: { name: value.name, message: value.message } };
}

export async function judgeWithJev(packet: EvidencePacket, client: Pick<TypeSafeClient, "systemOne">): Promise<JevJudgment> {
  try {
    const response: unknown = await client.systemOne({ state: packet as unknown as EntryType, model: "jev-1.13.0", questions });
    const result = record(response); const usage = record(result?.usage);
    if (typeof result?.model !== "string" || result.model.length === 0 || usage === undefined || !Number.isInteger(usage.input_tokens) || (usage.input_tokens as number) < 0 || !Number.isInteger(usage.output_tokens) || (usage.output_tokens as number) < 0 || !answers(result.answers)) throw new Error("malformed Jev response");
    return { kind: "judgment", model: result.model, usage: { input_tokens: usage.input_tokens as number, output_tokens: usage.output_tokens as number }, answers: result.answers };
  } catch (error) {
    return abstain(error);
  }
}
