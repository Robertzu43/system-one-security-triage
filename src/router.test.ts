import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { JevJudgment, RouterConfig } from "./contracts.js";
import { parseRouterConfig, route } from "./router.js";
import { buildEvidencePacket } from "./packets.js";

const config: RouterConfig = Object.freeze({ contextMin: 0.70, safeRiskMax: 0.20, highRiskMin: 0.80, pathMin: 0.70, controlEffectiveMin: 0.80, controlAbsentMax: 0.20, impactMin: 0.70, directExploitabilityMin: 2.50 });
const packet = buildEvidencePacket({ repositoryId: "example/repository", commit: "0123456789abcdef", sources: ["ast"], entryKind: "route", primarySpan: { path: "src/route.ts", startLine: 4, endLine: 4, text: "db.query(req.query.name)" }, relatedSpans: [], contextResolution: { middleware: "resolved", upstreamDataFlow: "resolved", sanitizers: "resolved", authorization: "resolved", callPath: "resolved" } }, 0);

function judgment(values: Partial<Record<"untrusted_influence" | "reaches_sensitive_operation" | "validation_blocks_attack" | "crosses_authorization_boundary" | "authorization_enforced" | "security_impact" | "is_injection" | "is_broken_access_control" | "is_ssrf" | "enough_context", number>> = {}, exploitability = 1): JevJudgment {
  const noul = (key: keyof typeof values) => ({ type: "noul" as const, noul: values[key] ?? 0.5 });
  return { kind: "judgment", model: "jev-1.13.0", usage: { input_tokens: 1, output_tokens: 1 }, answers: {
    untrusted_influence: noul("untrusted_influence"), reaches_sensitive_operation: noul("reaches_sensitive_operation"), validation_blocks_attack: noul("validation_blocks_attack"), crosses_authorization_boundary: noul("crosses_authorization_boundary"), authorization_enforced: noul("authorization_enforced"), security_impact: noul("security_impact"), is_injection: noul("is_injection"), is_broken_access_control: noul("is_broken_access_control"), is_ssrf: noul("is_ssrf"), enough_context: noul("enough_context"),
    exploitability: { type: "score", score: exploitability, confidence: 1, legend: { 0: "a", 1: "b", 2: "c", 3: "d" }, probabilities: { 0: 0, 1: 0, 2: 0, 3: 1 } }
  } };
}

test("router validates and freezes the JSON boundary config", async () => {
  const parsed = parseRouterConfig(JSON.parse(await readFile("config/router.dev.json", "utf8")));
  assert(Object.isFrozen(parsed));
  assert.deepEqual(parsed, config);
  assert.throws(() => parseRouterConfig({ ...config, contextMin: "0.7" }), /finite number/);
  assert.throws(() => parseRouterConfig({ ...config, extra: 1 }), /keys/);
});

test("router sends unresolved packet context to insufficient_context before risk", () => {
  const unresolved = { ...packet, contextResolution: { ...packet.contextResolution, middleware: "unresolved" as const } };
  assert.equal(route(unresolved, judgment({ enough_context: 1, is_injection: 1, untrusted_influence: 1, reaches_sensitive_operation: 1, validation_blocks_attack: 0, security_impact: 1 }, 3), config), "insufficient_context");
});

test("router sends evidence below the context threshold to insufficient_context", () => {
  assert.equal(route(packet, judgment({ enough_context: 0.699999, is_injection: 1, untrusted_influence: 1, reaches_sensitive_operation: 1, validation_blocks_attack: 0, security_impact: 1 }, 3), config), "insufficient_context");
  assert.equal(route(packet, judgment({ enough_context: 0.70, is_injection: 1, untrusted_influence: 1, reaches_sensitive_operation: 1, validation_blocks_attack: 0, security_impact: 1 }, 3), config), "likely_vulnerability");
});

test("router recognizes exact high-risk vulnerability thresholds and their lower sides", () => {
  const base = { enough_context: 0.70, is_injection: 0.80, is_broken_access_control: 0.1, is_ssrf: 0.1, untrusted_influence: 0.70, reaches_sensitive_operation: 0.70, validation_blocks_attack: 0.20, security_impact: 0.70 };
  assert.equal(route(packet, judgment(base, 2.50), config), "likely_vulnerability");
  assert.equal(route(packet, judgment({ ...base, is_injection: 0.799999 }, 2.50), config), "needs_deep_review");
  assert.equal(route(packet, judgment({ ...base, untrusted_influence: 0.699999 }, 2.50), config), "needs_deep_review");
  assert.equal(route(packet, judgment({ ...base, security_impact: 0.699999 }, 2.50), config), "needs_deep_review");
  assert.equal(route(packet, judgment({ ...base, validation_blocks_attack: 0.200001 }, 2.50), config), "needs_deep_review");
  assert.equal(route(packet, judgment(base, 2.499999), config), "needs_deep_review");
});

test("router recognizes exact safe thresholds for blocked paths and effective controls", () => {
  const base = { enough_context: 0.70, is_injection: 0.20, is_broken_access_control: 0.1, is_ssrf: 0.1, untrusted_influence: 0.20, reaches_sensitive_operation: 0.8, validation_blocks_attack: 0.1, security_impact: 1 };
  assert.equal(route(packet, judgment(base, 2.499999), config), "likely_safe");
  assert.equal(route(packet, judgment({ ...base, is_injection: 0.200001 }, 2.499999), config), "needs_deep_review");
  assert.equal(route(packet, judgment({ ...base, untrusted_influence: 0.200001, validation_blocks_attack: 0.80 }, 2.499999), config), "likely_safe");
  assert.equal(route(packet, judgment({ ...base, untrusted_influence: 0.200001, validation_blocks_attack: 0.799999 }, 2.499999), config), "needs_deep_review");
});

test("router uses authorization evidence for broken access control", () => {
  const vulnerable = { enough_context: 0.70, is_injection: 0.1, is_broken_access_control: 0.80, is_ssrf: 0.1, crosses_authorization_boundary: 0.70, authorization_enforced: 0.20, security_impact: 0.70 };
  assert.equal(route(packet, judgment(vulnerable, 2.50), config), "likely_vulnerability");
  assert.equal(route(packet, judgment({ ...vulnerable, authorization_enforced: 0.200001 }, 2.50), config), "needs_deep_review");
  assert.equal(route(packet, judgment({ ...vulnerable, is_broken_access_control: 0.20, crosses_authorization_boundary: 0.200001, authorization_enforced: 0.80 }, 2.499999), config), "likely_safe");
});

test("router escalates family ties, abstentions, and not-shown evidence", () => {
  assert.equal(route(packet, judgment({ enough_context: 1, is_injection: 0.9, is_ssrf: 0.9 }, 3), config), "needs_deep_review");
  assert.equal(route(packet, { kind: "abstain", error: { name: "Error", message: "service failed" } }, config), "needs_deep_review");
  assert.notEqual(route(packet, judgment({ enough_context: 1, is_injection: 0.1, untrusted_influence: 0.1, reaches_sensitive_operation: 0.1 }, 2.5), config), "likely_safe");
});
