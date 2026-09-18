import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson } from "./jsonl.js";
import { buildEvidencePacket, type PacketCandidate } from "./packets.js";

function candidate(text = "db.query(name)"): PacketCandidate {
  return {
    repositoryId: "example/repository",
    commit: "0123456789abcdef",
    sources: ["ast", "semgrep"],
    entryKind: "route",
    primarySpan: { path: "src/route.ts", startLine: 4, endLine: 4, text },
    relatedSpans: [{ path: "src/db.ts", startLine: 2, endLine: 2, text: "export const db = createDb();", relationship: "calls" }],
    contextResolution: { middleware: "unresolved", upstreamDataFlow: "resolved", sanitizers: "unresolved", authorization: "unresolved", callPath: "resolved" }
  };
}

test("packet IDs ignore object key insertion order", () => {
  const first = candidate();
  const second: PacketCandidate = {
    entryKind: "route",
    repositoryId: "example/repository",
    contextResolution: { callPath: "resolved", authorization: "unresolved", sanitizers: "unresolved", upstreamDataFlow: "resolved", middleware: "unresolved" },
    relatedSpans: [{ relationship: "calls", text: "export const db = createDb();", endLine: 2, path: "src/db.ts", startLine: 2 }],
    commit: "0123456789abcdef",
    primarySpan: { text: "db.query(name)", endLine: 4, startLine: 4, path: "src/route.ts" },
    sources: ["semgrep", "ast"]
  };
  assert.equal(buildEvidencePacket(first, 0).packetId, buildEvidencePacket(second, 0).packetId);
});

test("packet ID changes when a code span changes", () => {
  assert.notEqual(buildEvidencePacket(candidate("db.query(name)"), 0).packetId, buildEvidencePacket(candidate("db.query(email)"), 0).packetId);
});

test("packet ceiling includes its visible packet ID at the exact boundary", () => {
  const baselineBytes = Buffer.byteLength(canonicalJson(buildEvidencePacket(candidate("x"), 0)), "utf8");
  const text = "x".repeat(32_000 - baselineBytes + 1);
  const atLimit = buildEvidencePacket(candidate(text), 0);
  assert.equal(Buffer.byteLength(canonicalJson(atLimit), "utf8"), 32_000);
  assert.throws(() => buildEvidencePacket(candidate(`${text}x`), 0), /32,000/);
});

test("packet construction rejects unsafe evidence", () => {
  assert.throws(() => buildEvidencePacket({ ...candidate(), repositoryId: "/private/repository" }, 0), /absolute/);
  assert.throws(() => buildEvidencePacket({ ...candidate(), primarySpan: { ...candidate().primarySpan, path: "/private/route.ts" } }, 0), /relative/);
  assert.throws(() => buildEvidencePacket({ ...candidate(), primarySpan: { ...candidate().primarySpan, text: "" } }, 0), /non-empty/);
  assert.throws(() => buildEvidencePacket({ ...candidate(), primarySpan: { ...candidate().primarySpan, startLine: 0 } }, 0), /positive/);
  assert.throws(() => buildEvidencePacket({ ...candidate(), contextResolution: { ...candidate().contextResolution, extra: "resolved" } as PacketCandidate["contextResolution"] }, 0), /context/);
  assert.throws(() => buildEvidencePacket(candidate("// known vulnerable"), 0), /label/);
  assert.throws(() => buildEvidencePacket(candidate("x".repeat(32_001)), 0), /32,000/);
});
