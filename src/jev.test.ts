import assert from "node:assert/strict";
import test from "node:test";
import type { TypeSafeClient } from "@typesafe-ai/sdk";
import { judgeDemoWithJev, judgeWithJev, questionIds } from "./jev.js";
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

function demoResponse() {
  return {
    model: "jev-1.13.0",
    usage: { input_tokens: 10, output_tokens: 2 },
    answers: {
      classification: {
        type: "choice" as const,
        choice: "vulnerable_injection",
        confidence: 0.82,
        probabilities: {
          vulnerable_injection: 0.86,
          vulnerable_broken_access_control: 0.02,
          vulnerable_ssrf: 0.01,
          safe: 0.06,
          insufficient_context: 0.05
        }
      }
    }
  };
}

test("demo Jev sends one direct five-outcome Choice over unchanged evidence", async () => {
  let request: unknown;
  const client = { systemOne: async (value: unknown) => { request = value; return demoResponse(); } } as unknown as TypeSafeClient;

  const result = await judgeDemoWithJev(JSON.stringify(packet), client);

  const sent = request as { state: unknown; model: unknown; questions: Record<string, { type: string; instructions: unknown; criteria: Record<string, string> }> };
  assert.equal(sent.state, JSON.stringify(packet));
  assert.equal(sent.model, "jev-1.13.0");
  assert.deepEqual(Object.keys(sent.questions), ["classification"]);
  assert.equal(sent.questions.classification?.type, "choice");
  assert.deepEqual(Object.keys(sent.questions.classification!.criteria), ["vulnerable_injection", "vulnerable_broken_access_control", "vulnerable_ssrf", "safe", "insufficient_context"]);
  assert.match(JSON.stringify(sent.questions.classification), /untrusted influence/i);
  assert.match(JSON.stringify(sent.questions.classification), /broken access control|authorization required/i);
  assert.match(JSON.stringify(sent.questions.classification), /server-side request/i);
  assert.match(JSON.stringify(sent.questions.classification), /effective shown control/i);
  assert.match(JSON.stringify(sent.questions.classification), /not shown/i);
  assert.deepEqual(result, {
    kind: "judgment",
    model: "jev-1.13.0",
    usage: { input_tokens: 10, output_tokens: 2 },
    choice: { selected: "vulnerable_injection", confidence: 0.82, probabilities: demoResponse().answers.classification.probabilities }
  });
});

test("demo Jev rejects malformed Choice distributions", async () => {
  for (const mutate of [
    (answer: ReturnType<typeof demoResponse>["answers"]["classification"]) => { (answer.probabilities as Record<string, number>).other = 0; },
    (answer: ReturnType<typeof demoResponse>["answers"]["classification"]) => { answer.probabilities.vulnerable_injection = 0.5; answer.probabilities.safe = 0.5; },
    (answer: ReturnType<typeof demoResponse>["answers"]["classification"]) => { answer.probabilities.vulnerable_injection = 0.1; answer.probabilities.safe = 0.82; }
  ]) {
    const invalid = demoResponse();
    mutate(invalid.answers.classification);
    const client = { systemOne: async () => invalid } as unknown as TypeSafeClient;
    assert.equal((await judgeDemoWithJev(JSON.stringify(packet), client)).kind, "abstain");
  }
});

test("demo Jev accepts tied maxima and preserves low confidence", async () => {
  const tied = demoResponse();
  tied.answers.classification.confidence = 0.1;
  tied.answers.classification.probabilities = { vulnerable_injection: 0.43, vulnerable_broken_access_control: 0.01, vulnerable_ssrf: 0.02, safe: 0.43, insufficient_context: 0.11 };
  const client = { systemOne: async () => tied } as unknown as TypeSafeClient;

  const result = await judgeDemoWithJev(JSON.stringify(packet), client);

  assert.equal(result.kind, "judgment");
  if (result.kind === "judgment") assert.equal(result.choice.confidence, 0.1);
});

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
  assert.deepEqual(await judgeWithJev(packet, malformedClient), { kind: "abstain", error: { name: "Error", message: "malformed Jev response: exploitability probabilities sum to 1.6" } });

  const failedClient = { systemOne: async () => { throw new Error("service unavailable"); } } as unknown as TypeSafeClient;
  assert.deepEqual(await judgeWithJev(packet, failedClient), { kind: "abstain", error: { name: "Error", message: "service unavailable" } });
});

test("Jev abstains when a Score does not equal its probability-weighted mean", async () => {
  const invalid = response();
  invalid.answers.exploitability.score = 3;
  invalid.answers.exploitability.probabilities = { 0: 1, 1: 0, 2: 0, 3: 0 };
  const client = { systemOne: async () => invalid } as unknown as TypeSafeClient;
  assert.deepEqual(await judgeWithJev(packet, client), { kind: "abstain", error: { name: "Error", message: "malformed Jev response: exploitability score 3 differs from weighted mean 0" } });
});

test("Jev accepts harmless rounding in Score probabilities", async () => {
  const rounded = response();
  rounded.answers.exploitability.score = 2;
  rounded.answers.exploitability.probabilities = { 0: 0.1, 1: 0.2, 2: 0.3, 3: 0.399999 };
  const client = { systemOne: async () => rounded } as unknown as TypeSafeClient;
  assert.equal((await judgeWithJev(packet, client)).kind, "judgment");
});

test("Jev accepts independently rounded Score and weighted mean", async () => {
  const rounded = response();
  rounded.answers.exploitability.score = 2.29;
  rounded.answers.exploitability.probabilities = { 0: 0, 1: 0, 2: 0.72, 3: 0.28 };
  const client = { systemOne: async () => rounded } as unknown as TypeSafeClient;
  assert.equal((await judgeWithJev(packet, client)).kind, "judgment");
});
