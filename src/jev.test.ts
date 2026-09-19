import assert from "node:assert/strict";
import test from "node:test";
import type { TypeSafeClient } from "@typesafe-ai/sdk";
import { judgeWithJev, questionIds } from "./jev.js";
import { buildEvidencePacket } from "./packets.js";

const packet = buildEvidencePacket({
  repositoryId: "example/repository",
  commit: "0123456789abcdef",
  sources: ["ast"],
  entryKind: "route",
  primarySpan: { path: "src/route.ts", startLine: 4, endLine: 4, text: "db.query(req.query.name)" },
  relatedSpans: [],
  contextResolution: { middleware: "resolved", upstreamDataFlow: "resolved", sanitizers: "resolved", authorization: "resolved", callPath: "resolved" }
}, 0);

function response() {
  const noul = { type: "noul" as const, noul: 0.5 };
  return { model: "jev-1.13.0", usage: { input_tokens: 10, output_tokens: 11 }, answers: {
    untrusted_influence: noul, reaches_sensitive_operation: noul, validation_blocks_attack: noul,
    crosses_authorization_boundary: noul, authorization_enforced: noul, security_impact: noul,
    is_injection: noul, is_broken_access_control: noul, is_ssrf: noul, enough_context: noul,
    exploitability: { type: "score" as const, score: 1.5, confidence: 0.6, legend: { 0: "a", 1: "b", 2: "c", 3: "d" }, probabilities: { 0: 0, 1: 0.5, 2: 0.5, 3: 0 } }
  } };
}

test("Jev sends every independent judgment in one pinned request", async () => {
  let request: unknown;
  const client = { systemOne: async (value: unknown) => { request = value; return response(); } } as unknown as TypeSafeClient;

  const result = await judgeWithJev(packet, client);

  assert.equal(result.kind, "judgment");
  const sent = request as { state: unknown; model: unknown; questions: Record<string, { type: string; criteria?: unknown }> };
  assert.equal(sent.state, packet);
  assert.equal(sent.model, "jev-1.13.0");
  assert.deepEqual(Object.keys(sent.questions), questionIds);
  assert(questionIds.slice(0, -1).every((id) => sent.questions[id]?.type === "noul"));
  assert.deepEqual(sent.questions.exploitability, {
    type: "score",
    instructions: "How exploitable is the shown behavior?",
    criteria: [
      "Unreachable: the shown data or actor cannot reach the operation",
      "Theoretical: a path is imaginable but required evidence or preconditions are absent",
      "Constrained: the path exists but a meaningful restriction or uncommon precondition limits exploitation",
      "Direct: an untrusted actor can reach the sensitive behavior with no effective shown control"
    ]
  });
  assert.deepEqual(questionIds, ["untrusted_influence", "reaches_sensitive_operation", "validation_blocks_attack", "crosses_authorization_boundary", "authorization_enforced", "security_impact", "is_injection", "is_broken_access_control", "is_ssrf", "enough_context", "exploitability"]);
  assert.deepEqual(result, { kind: "judgment", ...response() });
});

test("Jev turns malformed model output into an abstention without inventing scores", async () => {
  const client = { systemOne: async () => ({ ...response(), answers: {} }) } as unknown as TypeSafeClient;
  const result = await judgeWithJev(packet, client);
  assert.deepEqual(result, { kind: "abstain", error: { name: "Error", message: "malformed Jev response: invalid untrusted_influence" } });
});

test("Jev abstains on invalid distributions and exhausted SDK failures", async () => {
  const invalid = response();
  invalid.answers.exploitability.probabilities = { 0: 0, 1: 0.8, 2: 0.8, 3: 0 };
  const malformedClient = { systemOne: async () => invalid } as unknown as TypeSafeClient;
  assert.deepEqual(await judgeWithJev(packet, malformedClient), { kind: "abstain", error: { name: "Error", message: "malformed Jev response: invalid exploitability" } });

  const failedClient = { systemOne: async () => { throw new Error("service unavailable"); } } as unknown as TypeSafeClient;
  assert.deepEqual(await judgeWithJev(packet, failedClient), { kind: "abstain", error: { name: "Error", message: "service unavailable" } });
});

test("Jev abstains when a Score does not equal its probability-weighted mean", async () => {
  const invalid = response();
  invalid.answers.exploitability.score = 3;
  invalid.answers.exploitability.probabilities = { 0: 1, 1: 0, 2: 0, 3: 0 };
  const client = { systemOne: async () => invalid } as unknown as TypeSafeClient;
  assert.deepEqual(await judgeWithJev(packet, client), { kind: "abstain", error: { name: "Error", message: "malformed Jev response: invalid exploitability" } });
});

test("Jev accepts harmless rounding in Score probabilities", async () => {
  const rounded = response();
  rounded.answers.exploitability.score = 2;
  rounded.answers.exploitability.probabilities = { 0: 0.1, 1: 0.2, 2: 0.3, 3: 0.399999 };
  const client = { systemOne: async () => rounded } as unknown as TypeSafeClient;
  assert.equal((await judgeWithJev(packet, client)).kind, "judgment");
});
