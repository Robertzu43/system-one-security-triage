import { posix } from "node:path";
import { canonicalJson, stableHash } from "./jsonl.js";

const sources = ["semgrep", "ast"] as const;
const entryKinds = ["route", "handler", "call"] as const;
const relationshipKinds = ["calls", "flows_to", "guards"] as const;
const contextKeys = ["middleware", "upstreamDataFlow", "sanitizers", "authorization", "callPath"] as const;
const statuses = ["resolved", "unresolved"] as const;
const forbiddenText = [/\bCVE-\d{4}-\d+\b/i, /vuln-code-snippet/i, /\bchallenge\b/i, /known vulnerable/i, /patched version/i];
const maxPacketStateBytes = 32_000;

type CandidateSource = (typeof sources)[number];
type EntryKind = (typeof entryKinds)[number];
type RelationshipKind = (typeof relationshipKinds)[number];
type ContextKey = (typeof contextKeys)[number];
type ContextStatus = (typeof statuses)[number];
export type ContextResolution = Record<ContextKey, ContextStatus>;
export interface SpanInput { path: string; startLine: number; endLine: number; text: string; }
export interface RelatedSpan extends SpanInput { relationship: RelationshipKind; }
export interface PacketCandidate {
  repositoryId: string;
  commit: string;
  sources: CandidateSource[];
  entryKind: EntryKind;
  primarySpan: SpanInput;
  relatedSpans: RelatedSpan[];
  contextResolution: ContextResolution;
}
export interface EvidencePacket {
  schemaVersion: 1;
  packetId: string;
  repositoryId: string;
  commit: string;
  candidateSources: CandidateSource[];
  entryKind: EntryKind;
  spans: Array<{ id: string; path: string; startLine: number; endLine: number; text: string }>;
  relationships: Array<{ from: string; to: string; kind: RelationshipKind }>;
  contextResolution: ContextResolution;
}

function record(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function string(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be non-empty`); if (forbiddenText.some((pattern) => pattern.test(value))) throw new Error(`label leakage in ${label}`); return value; }
function metadata(value: unknown, label: string): string { const result = string(value, label); if (posix.isAbsolute(result) || /^(?:[A-Za-z]:[\\/]|\\\\)/.test(result)) throw new Error(`${label} must not be absolute`); return result; }
function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T { const result = string(value, label); if (!allowed.includes(result as T)) throw new Error(`${label} is invalid`); return result as T; }
function path(value: unknown, label: string): string {
  const result = string(value, label);
  if (posix.isAbsolute(result) || /^(?:[A-Za-z]:[\\/]|\\\\)/.test(result) || result === "." || result === ".." || result.startsWith("../") || result !== posix.normalize(result) || result.includes("\\")) throw new Error(`${label} must be a normalized relative path`);
  return result;
}
function positiveLine(value: unknown, label: string): number { if (typeof value !== "number" || !Number.isInteger(value) || value < 1) throw new Error(`${label} must be positive`); return value; }
function span(value: unknown, label: string): SpanInput {
  const input = record(value, label); const startLine = positiveLine(input.startLine, `${label}.startLine`); const endLine = positiveLine(input.endLine, `${label}.endLine`);
  if (endLine < startLine) throw new Error(`${label}.endLine must not precede startLine`);
  return { path: path(input.path, `${label}.path`), startLine, endLine, text: string(input.text, `${label}.text`) };
}
function context(value: unknown): ContextResolution {
  const input = record(value, "contextResolution");
  if (Object.keys(input).length !== contextKeys.length || contextKeys.some((key) => !(key in input))) throw new Error("contextResolution keys are invalid");
  return Object.fromEntries(contextKeys.map((key) => [key, oneOf(input[key], statuses, `contextResolution.${key}`)])) as ContextResolution;
}

export function buildEvidencePacket(candidate: PacketCandidate, _index: number): EvidencePacket {
  const input = record(candidate, "candidate");
  const candidateSources = (() => {
    if (!Array.isArray(input.sources) || input.sources.length === 0) throw new Error("sources must be non-empty");
    return [...new Set(input.sources.map((source) => oneOf(source, sources, "source")))].sort() as CandidateSource[];
  })();
  if (!Array.isArray(input.relatedSpans)) throw new Error("relatedSpans must be an array");
  const primary = span(input.primarySpan, "primarySpan");
  const related = input.relatedSpans.map((value, index) => {
    const relation = record(value, `relatedSpans[${index}]`);
    return { ...span(relation, `relatedSpans[${index}]`), relationship: oneOf(relation.relationship, relationshipKinds, `relatedSpans[${index}].relationship`) };
  });
  const spans = [primary, ...related].map((value, index) => ({ id: `s${index + 1}`, ...value }));
  const state = {
    schemaVersion: 1 as const,
    repositoryId: metadata(input.repositoryId, "repositoryId"),
    commit: metadata(input.commit, "commit"),
    candidateSources,
    entryKind: oneOf(input.entryKind, entryKinds, "entryKind"),
    spans,
    relationships: related.map((value, index) => ({ from: "s1", to: `s${index + 2}`, kind: value.relationship })),
    contextResolution: context(input.contextResolution)
  };
  const packet = { ...state, packetId: stableHash(state) };
  if (Buffer.byteLength(canonicalJson(packet), "utf8") > maxPacketStateBytes) throw new Error("packet state exceeds 32,000 bytes");
  return packet;
}
