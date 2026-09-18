# System One Security Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible TypeScript benchmark that measures Jev-routed security triage against Terra-all, preserves the distinct Claim 1/2/3 scoring rules, and renders the frozen results in a static dashboard.

**Architecture:** One dependency-light Node CLI writes immutable JSONL artifacts through five stages: sanitize, discover, judge, route, and score. Pure TypeScript owns matching, routing, aggregation, bootstrap intervals, and decision labels; Jev supplies typed atomic judgments, while Terra and Opus run behind the same bounded command runner on the same sanitized snapshot. The report and static dashboard read the scorer's JSON output and never recalculate metrics.

**Tech Stack:** Node.js 24+, TypeScript, Node's built-in test runner, `@typesafe-ai/sdk@0.6.0`, Jev `jev-1.13.0`, Semgrep `1.177.0`, Codex CLI `0.147.0`, Claude Code `2.1.276`, plain HTML/CSS/JavaScript

**Spec:** `docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md`

## Global Constraints

- Limit the first release to injection, broken access control, and SSRF.
- Use Juice Shop only for development and examples; use repository-disjoint OpenSSF repositories for calibration and holdout.
- Keep vulnerable/patched pairs and shared root causes in the same split.
- Treat one deduplicated target instance as the recall unit; a patched target is negative only for that target instance.
- Keep Claim 1 automated-detection recall separate from Claim 2 retained-alert recall.
- Keep the packet-only Jev/Terra/Opus comparison separate from the agentic cascade system comparison.
- Count no-candidate, abstained, failed, and final `manual_review` vulnerable instances as undetected for Claim 1.
- Retain unresolved Semgrep findings as alerts for Claim 2 and include them in review workload.
- Count Claim 3 yield only when no Semgrep finding matches the same deduplicated target instance anywhere in the repository.
- Give Terra-all and Jev-to-Terra identical sanitized snapshots, permissions, budgets, prompts, and command versions.
- Exclude `.git`, answer-bearing tests, advisories, challenge metadata, solution material, patches, and labels from model-visible snapshots.
- Force `insufficient_context` escalation whenever middleware, sanitizer, authorization, or call-path evidence is unresolved.
- Pin Jev to `jev-1.13.0`; never use `jev-latest` in benchmark artifacts.
- Run five randomized, interleaved repetitions per arm and repository at fixed concurrency.
- Use 10,000 paired repository bootstrap draws with seed `20260918`, keeping both arms, every target, and all five repetitions together.
- Compute recall by averaging five binary outcomes within each target, then averaging across unique targets.
- Compute efficiency as the ratio of arithmetic mean repository costs and the ratio of arithmetic mean repository-median latencies, never the mean of repository ratios.
- Classify every primary component and the combined claim as `supported`, `contradicted`, or `inconclusive` under the frozen bounds.
- Keep credentials in environment variables, preserve raw usage/timing without secrets, and never commit `private/` or `artifacts/`.
- Use network-restricted containers for vulnerable code and non-destructive proofs only.
- Use no database, frontend framework, workflow framework, or runtime validation dependency.

## File Structure

```text
package.json                              scripts and exact dependency pins
package-lock.json                         reproducible npm dependency graph
tsconfig.json                             strict Node ESM compilation
.gitignore                                excludes artifacts, private labels, and secrets
src/contracts.ts                          artifact types and trust-boundary validators
src/jsonl.ts                              canonical JSON, JSONL I/O, atomic writes, hashes
src/scorer.ts                             matching, all three claims, aggregation, bootstrap
src/sanitize.ts                           snapshot copying, exclusions, leakage scan
src/discover.ts                           Semgrep runner and TypeScript AST inventory
src/packets.ts                            evidence slicing and one-hop context resolution
src/router.ts                             frozen deterministic Jev routing policy
src/jev.ts                                one-request Jev judgment construction and parsing
src/reasoning.ts                          bounded Codex/Claude command execution
src/pipeline.ts                           arm orchestration and immutable run records
src/calibrate.ts                          split creation, threshold search, freeze manifest
src/report.ts                             Markdown and dashboard-data generation
src/cli.ts                                subcommands and argument validation
src/*.test.ts                             colocated Node tests for each module
config/reasoning-output.schema.json       shared structured response schema
config/router.dev.json                    development-only router thresholds
rules/semgrep.yml                         frozen local Semgrep rules
test/fixtures/scoring.json                hand-calculated scoring fixture
test/fixtures/repository/                 safe, vulnerable, leaky, and overlap code fixtures
benchmark/dev.json                        pinned Juice Shop development revision
benchmark/splits.json                     frozen public repository split metadata
benchmark/freeze.json                     public versions, hashes, policy, and run settings
dashboard/index.html                      accessible static result explorer
dashboard/app.js                          renders frozen scorer output
README.md                                 reproducibility, claims, and limitations
```

The private target ledger and reproduction evidence live under ignored `private/`. Generated run bundles and dashboard data live under ignored `artifacts/`.

---

### Task 1: Scorer and hand-calculated fixtures

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.gitignore`
- Create: `src/contracts.ts`
- Create: `src/scorer.ts`
- Create: `src/scorer.test.ts`
- Create: `test/fixtures/scoring.json`

**Interfaces:**
- Consumes: a private `TargetInstance[]`, immutable `PredictionOutcome[]`, `ControlledPrediction[]`, and `EfficiencyRecord[]`.
- Produces: `parseScoreInput(value: unknown): ScoreInput`, `scoreClaims(input: ScoreInput): ScoreReport`, `bootstrapPrimary(input: ScoreInput, draws?: number, seed?: number): PrimaryInference`, `classifyDifference(interval: Interval, margin: number): Decision`, and `classifyRatio(interval: Interval): Decision`.

- [ ] **Step 1: Add the minimal TypeScript project and failing scorer test**

Create `package.json` with Node's test runner and only the dependencies the benchmark uses:

```json
{
  "name": "system-one-security-triage",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "engines": { "node": ">=24" },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "npm run build && node --test dist/src/*.test.js",
    "check": "npm test && git diff --check"
  },
  "dependencies": {
    "@typesafe-ai/sdk": "0.6.0"
  },
  "devDependencies": {
    "@types/node": "24.5.2",
    "typescript": "5.9.2"
  }
}
```

Create `tsconfig.json` with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `module: NodeNext`, `moduleResolution: NodeNext`, `resolveJsonModule`, `rootDir: .`, and `outDir: dist`. Add `artifacts/`, `private/`, `.env`, and `dist/` to `.gitignore`.

Create a test that imports the scorer and asserts the hand calculations:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseScoreInput, scoreClaims } from "./scorer.js";

test("uses target-nested recall and ratio-of-mean repository efficiency", async () => {
  const raw = JSON.parse(await readFile("test/fixtures/scoring.json", "utf8"));
  const report = scoreClaims(parseScoreInput(raw));
  assert.equal(report.claim1.terraAllRecall, 1);
  assert.equal(report.claim1.cascadeRecall, 0.55);
  assert.equal(report.claim1.recallDifference, -0.45);
  assert.equal(report.efficiency.costRatio, 2 / 3);
  assert.equal(report.efficiency.latencyRatio, 5 / 7);
  assert.equal(report.claim3.additionalValidatedYield, 1);
});
```

The fixture contains four unique vulnerable targets over two repositories. Terra detects all four in all five runs. Cascade run hits are `5/5`, `4/5`, `2/5`, and `0/5`, so its recall is `(1 + 0.8 + 0.4 + 0) / 4 = 0.55`. Repository mean costs are cascade `[2, 6]` and Terra `[4, 8]`, yielding `mean([2,6]) / mean([4,8]) = 2/3`; repository median latencies are cascade `[10, 40]` and Terra `[20, 50]`, yielding `mean([10,40]) / mean([20,50]) = 5/7`. Include two validated AST findings: one overlaps a target matched by Semgrep and one has no Semgrep match, so Claim 3 yield is one.

- [ ] **Step 2: Run the test to verify the scorer is missing**

Run: `npm install && npm test`

Expected: TypeScript fails because `src/scorer.ts` does not exist.

- [ ] **Step 3: Implement strict contracts and point estimates**

Define these discriminated records in `src/contracts.ts` and validate unknown JSON with explicit property/type checks:

```ts
export type Family = "injection" | "broken_access_control" | "ssrf";
export type SystemArm = "terra_all" | "jev_to_terra" | "opus_all" | "jev_to_opus";
export type Arm = SystemArm | "semgrep_raw" | "semgrep_to_jev";
export type ControlledEvaluator = "jev" | "terra" | "opus";
export type FinalOutcome = "alert" | "no_alert" | "manual_review";
export type Decision = "supported" | "contradicted" | "inconclusive";
export type Repetition = 1 | 2 | 3 | 4 | 5;
export type Interval = readonly [lower: number, upper: number];

export interface TargetInstance {
  targetId: string;
  repositoryId: string;
  family: Family;
  cwe: string;
  severity: "low" | "medium" | "high" | "critical";
  vulnerable: boolean;
  rawSemgrepMatched: boolean;
}

export interface ControlledPrediction {
  packetId: string;
  evaluator: ControlledEvaluator;
  repetition: Repetition;
  decision: "vulnerable" | "safe" | "abstain";
  family: Family;
  evidenceSpanIds: string[];
  matchedTargetId: string | null;
}

export interface PredictionOutcome {
  predictionId: string;
  deduplicationId: string;
  targetId: string | null;
  repositoryId: string;
  arm: Arm;
  repetition: Repetition;
  finalOutcome: FinalOutcome;
  retainedAlert: boolean;
  adjudication: "confirmed" | "not_vulnerable" | "insufficient_evidence";
}

export interface EfficiencyRecord {
  repositoryId: string;
  arm: SystemArm;
  repetition: Repetition;
  costUsd: number;
  coldLatencyMs: number;
}

export interface DiscoveryMatch {
  findingId: string;
  source: "semgrep" | "ast";
  targetId: string;
  adjudication: "confirmed" | "not_vulnerable" | "insufficient_evidence";
}

export interface ScoreInput {
  targets: TargetInstance[];
  predictions: PredictionOutcome[];
  efficiency: EfficiencyRecord[];
  discoveryMatches: DiscoveryMatch[];
  controlled: ControlledPrediction[];
  validGroundTruth: boolean;
  actualCostAvailable: boolean;
}

export interface ScoreReport {
  claim1: { terraAllRecall: number; cascadeRecall: number; recallDifference: number };
  claim2: { rawRecall: number; filteredRecall: number; filteredPrecision: number; unresolvedWorkload: number };
  claim3: { additionalValidatedYield: number };
  controlled: Record<ControlledEvaluator, { recall: number; precision: number; abstentionRate: number }>;
  efficiency: { costRatio: number | null; latencyRatio: number };
}

export interface PrimaryInference {
  recall: { estimate: number; interval: Interval; decision: Decision };
  cost: { estimate: number | null; interval: Interval | null; decision: Decision };
  latency: { estimate: number; interval: Interval; decision: Decision };
  primaryDecision: Decision;
}
```

Implement point estimates with these exact rules:

```text
targetDetectionRate = sum(over five runs, any deduplicated matching final alert ? 1 : 0) / 5;
claim1Recall = mean(targetDetectionRate for every vulnerable target);
targetRetainedRate = sum(over five runs, any deduplicated matching retained alert ? 1 : 0) / 5;
claim2Recall = mean(targetRetainedRate for vulnerable targets with rawSemgrepMatched);
controlledRecall = mean(over vulnerable targets, five-run matched vulnerable decisions);
controlledPrecision = confirmed matched vulnerable decisions / adjudicated vulnerable decisions;
controlledAbstentionRate = abstain decisions / all controlled decisions;
repositoryCost = mean(five repetition costs);
repositoryLatency = median(five repetition latencies);
costRatio = mean(cascade repository costs) / mean(Terra repository costs);
latencyRatio = mean(cascade repository latencies) / mean(Terra repository latencies);
```

For each target/run, detection is one when any deduplicated matching prediction is a final alert; otherwise it is zero. Missing target outcomes therefore contribute zero. Reject duplicate `(deduplicationId, arm, repetition)` records, target/repository mismatches, repetitions outside `1..5`, negative cost/latency, and zero denominators. A final `manual_review` is zero for automated recall. For Claim 2, `retainedAlert: true` counts even when unresolved. Precision uses adjudicated, deduplicated alert records; `insufficient_evidence` stays outside confirmed/false counts and is reported separately. Deduplicate Claim 3 by `targetId` and require zero matching Semgrep findings across the repository.

- [ ] **Step 4: Add the paired repository bootstrap and three-way decisions**

Use a small seeded Mulberry32 generator in `src/scorer.ts`. For each of 10,000 draws, sample repository IDs with replacement and carry the repository's targets, both arms, and all five repetitions as one cluster. Recompute every nested statistic on the resample. After sorting 10,000 finite estimates ascending, use indexes `floor((n - 1) * 0.05)` and `floor((n - 1) * 0.95)` for the two-sided 90% interval.

```ts
export function classifyDifference([lower, upper]: Interval, margin = -0.02): Decision {
  if (lower > margin) return "supported";
  if (upper <= margin) return "contradicted";
  return "inconclusive";
}

export function classifyRatio([lower, upper]: Interval): Decision {
  if (upper < 1) return "supported";
  if (lower >= 1) return "contradicted";
  return "inconclusive";
}
```

Add degenerate bootstrap tests where every repository has the same difference/ratio, plus direct boundary tests for all three labels. Assert that the combined claim is supported only when recall, cost, and latency are supported; contradicted when any component is contradicted; and inconclusive otherwise.

- [ ] **Step 5: Run scorer verification**

Run: `npm test`

Expected: all scorer tests pass, including the `0.55`, `2/3`, `5/7`, overlap, cluster-bootstrap, and decision-boundary assertions.

- [ ] **Step 6: Commit the scoring foundation**

```bash
git add package.json package-lock.json tsconfig.json .gitignore src/contracts.ts src/scorer.ts src/scorer.test.ts test/fixtures/scoring.json
git commit -m "feat: add benchmark scorer"
```

---

### Task 2: Sanitized snapshots and stable evidence packets

**Files:**
- Create: `src/jsonl.ts`
- Create: `src/sanitize.ts`
- Create: `src/packets.ts`
- Create: `src/sanitize.test.ts`
- Create: `src/packets.test.ts`
- Create: `test/fixtures/repository/leaky/src/route.ts`
- Create: `test/fixtures/repository/leaky/tests/CVE-2025-0001.test.ts`
- Create: `test/fixtures/repository/leaky/advisories/security.md`
- Create: `test/fixtures/repository/leaky/solutions/challenge.md`

**Interfaces:**
- Consumes: an immutable source checkout, a `SanitizationPolicy`, and normalized `Candidate` records.
- Produces: `createSanitizedSnapshot(source, destination, policy): Promise<SnapshotManifest>`, `assertNoLabelLeakage(snapshot): Promise<void>`, `buildEvidencePacket(candidate, index): EvidencePacket`, `stableHash(value): string`, and atomic JSONL readers/writers.

- [ ] **Step 1: Write failing sanitization and packet tests**

Assert that snapshot creation:

- copies `src/route.ts` byte-for-byte;
- excludes `.git`, `tests`, `advisories`, `solutions`, `*.patch`, and `*.diff`;
- rejects symlinks instead of following them;
- records every included file's SHA-256 and one aggregate snapshot SHA-256;
- fails if included text contains `CVE-`, `vuln-code-snippet`, `challenge`, `known vulnerable`, or `patched version`;
- never includes an absolute source path in the manifest.

Assert that two logically identical evidence packets with different object key insertion order receive the same packet ID, while a code-span change changes the ID.

- [ ] **Step 2: Run the focused tests to verify missing modules**

Run: `npm test -- --test-name-pattern="snapshot|packet"`

Expected: TypeScript fails on missing `sanitize.js` and `packets.js` imports.

- [ ] **Step 3: Implement canonical artifacts and atomic writes**

In `src/jsonl.ts`, recursively sort object keys, preserve array order, serialize one compact JSON value per line, and hash UTF-8 canonical JSON with `node:crypto`. Write artifacts to a sibling `.tmp` path opened with exclusive creation, `fsync`, close, and rename. Reject an existing final path instead of overwriting it.

```ts
export function canonicalJson(value: unknown): string;
export function stableHash(value: unknown): string;
export async function readJsonl<T>(path: string, parse: (value: unknown) => T): Promise<T[]>;
export async function writeJsonlExclusive(path: string, values: readonly unknown[]): Promise<void>;
```

- [ ] **Step 4: Implement sanitized copying and leakage scanning**

Walk the checkout with `fs.readdir({ withFileTypes: true })`; do not shell out. Match normalized repository-relative POSIX paths against this frozen development policy:

```ts
const excludedSegments = new Set([
  ".git", "test", "tests", "__tests__", "advisories", "solutions",
  "challenges", "writeups", "patches"
]);
const excludedSuffixes = [".patch", ".diff"];
const forbiddenText = [
  /\bCVE-\d{4}-\d+\b/i,
  /vuln-code-snippet/i,
  /\bchallenge\b/i,
  /known vulnerable/i,
  /patched version/i
];
```

Copy only regular files and directories. Throw on any symbolic link or unsupported file type. Emit `SnapshotManifest { sourceCommit, policyHash, files, contentHash }`; expose no original absolute paths.

- [ ] **Step 5: Implement evidence packets with explicit context status**

Define packet spans with neutral IDs (`s1`, `s2`) and no scanner verdict. Include `contextResolution` fields for `middleware`, `upstreamDataFlow`, `sanitizers`, `authorization`, and `callPath`, each exactly `resolved` or `unresolved`.

```ts
export interface EvidencePacket {
  schemaVersion: 1;
  packetId: string;
  repositoryId: string;
  commit: string;
  candidateSources: Array<"semgrep" | "ast">;
  entryKind: "route" | "handler" | "call";
  spans: Array<{ id: string; path: string; startLine: number; endLine: number; text: string }>;
  relationships: Array<{ from: string; to: string; kind: "calls" | "flows_to" | "guards" }>;
  contextResolution: Record<"middleware" | "upstreamDataFlow" | "sanitizers" | "authorization" | "callPath", "resolved" | "unresolved">;
}
```

Calculate `packetId` from all fields except `packetId` itself. Reject absolute paths, empty spans, non-positive lines, unknown context keys, forbidden labels, and packets above the frozen 32k-state limit before any model call.

- [ ] **Step 6: Run tests and commit**

Run: `npm test`

Expected: sanitization, leakage, symlink, hash, packet validation, and all Task 1 tests pass.

```bash
git add src/jsonl.ts src/sanitize.ts src/packets.ts src/sanitize.test.ts src/packets.test.ts test/fixtures/repository
git commit -m "feat: sanitize evidence packets"
```

---

### Task 3: Frozen candidate discovery and overlap matching

**Files:**
- Create: `rules/semgrep.yml`
- Create: `src/discover.ts`
- Create: `src/discover.test.ts`
- Create: `test/fixtures/repository/candidates/src/app.ts`
- Modify: `src/packets.ts`
- Modify: `src/contracts.ts`

**Interfaces:**
- Consumes: a sanitized snapshot and the local Semgrep rules file.
- Produces: `runSemgrep(snapshot, rules): Promise<Candidate[]>`, `inventoryAst(snapshot): Promise<Candidate[]>`, `deduplicateCandidates(candidates): Candidate[]`, and packet-ready one-hop evidence.

Define the shared candidate contract before writing either discovery path:

```ts
export interface Candidate {
  candidateId: string;
  repositoryId: string;
  sources: Array<"semgrep" | "ast">;
  familyHint: Family;
  rootOperation: string;
  primarySpan: { path: string; startLine: number; endLine: number; text: string };
  relatedSpans: Array<{ path: string; startLine: number; endLine: number; text: string; relationship: "calls" | "flows_to" | "guards" }>;
  contextResolution: EvidencePacket["contextResolution"];
}
```

- [ ] **Step 1: Add one compact vulnerable/safe fixture and failing discovery tests**

The fixture must contain:

- SQL built from `req.query.name` and a parameterized SQL control;
- `child_process.exec(req.body.command)` and a constant-command control;
- `fetch(req.query.url)` and a host-allowlisted control;
- `GET /users/:id` without an ownership check and a neighboring route guarded by `requireOwner`;
- a wrapper function one hop away from one sink;
- one location matched by both AST and Semgrep.

Assert that discovery emits stable candidate IDs, records the source separately, captures the one-hop wrapper, marks omitted authorization context unresolved, and deduplicates exact duplicate source/span/family candidates without treating AST/Semgrep overlap as Claim 3 yield.

- [ ] **Step 2: Run focused tests to verify discovery is missing**

Run: `npm test -- --test-name-pattern="discovery|overlap"`

Expected: TypeScript fails on the missing `discover.js` import.

- [ ] **Step 3: Add the frozen local Semgrep rules**

Add explicit JavaScript/TypeScript rules for SQL/string query construction, `eval`, child-process calls, server-side network calls with request-controlled arguments, and unguarded identifier-based route access. Each rule emits only a neutral rule ID, metavariables, path, and span; the packet builder must not copy rule messages or severity.

Run Semgrep in the pinned image with no network and no registry rules:

```text
docker run --rm --network none
  --mount type=bind,src=<snapshot>,dst=/src,readonly
  --mount type=bind,src=<rules-dir>,dst=/rules,readonly
  semgrep/semgrep:1.177.0
  semgrep scan --config /rules/semgrep.yml --json --metrics off --disable-version-check /src
```

Construct the argument array directly with `spawn`; never invoke a shell. Reject a non-zero exit, malformed JSON, or a reported path outside `/src`.

- [ ] **Step 4: Implement the TypeScript AST inventory**

Use the installed TypeScript compiler API. Parse `.js`, `.jsx`, `.ts`, and `.tsx`; skip generated/vendor directories. Walk route registrations, request-property reads, calls to database/interpreter/process/filesystem/template/network sinks, middleware arrays, and local calls. Build a symbol table for top-level/local functions and include at most one caller and one callee hop.

The inventory is intentionally broad: it emits candidates rather than vulnerability verdicts. Mark a context dimension `unresolved` whenever symbol resolution leaves the snapshot, a dynamic call cannot be resolved, or the one-hop budget ends before the relevant control.

- [ ] **Step 5: Merge candidates and prove overlap behavior**

Deduplicate only identical `(repositoryId, familyHint, normalizedSpan, rootOperation)` candidates. Preserve `sources: ["semgrep", "ast"]` when both discover the same candidate. The private matching ledger, not span equality, decides whether an AST candidate and a Semgrep finding map to the same target instance elsewhere in the repository.

Run: `npm test`

Expected: all candidate, one-hop, safe-control, and overlap assertions pass.

- [ ] **Step 6: Commit discovery**

```bash
git add rules/semgrep.yml src/contracts.ts src/discover.ts src/discover.test.ts src/packets.ts test/fixtures/repository/candidates
git commit -m "feat: discover security candidates"
```

---

### Task 4: Jev judgments and deterministic routing

**Files:**
- Create: `config/router.dev.json`
- Create: `src/jev.ts`
- Create: `src/router.ts`
- Create: `src/jev.test.ts`
- Create: `src/router.test.ts`
- Modify: `src/contracts.ts`

**Interfaces:**
- Consumes: one validated `EvidencePacket`, Jev `jev-1.13.0`, and a frozen `RouterConfig`.
- Produces: `judgeWithJev(packet, client): Promise<JevJudgment>` and `route(packet, judgment, config): RouteOutcome` where `RouteOutcome` is `likely_safe | likely_vulnerability | needs_deep_review | insufficient_context`.

- [ ] **Step 1: Write failing question-shape and router-boundary tests**

Assert that one Jev request contains all independent questions, the state equals the packet object, and the model is `jev-1.13.0`. Use Noul questions for influence, reachability, controls, impact, three independent family judgments, and evidence sufficiency; use one four-level Score for exploitability. Test exact threshold equality on both sides of every router branch.

Required routing tests:

- any unresolved packet context forces `insufficient_context` even with high vulnerability probabilities;
- low Jev evidence-sufficiency forces `insufficient_context`;
- strong path, weak control, high family risk, and direct exploitability yields `likely_vulnerability`;
- low family risk plus a blocked path or effective control yields `likely_safe`;
- all remaining combinations yield `needs_deep_review`;
- “not shown” never yields `likely_safe`.

- [ ] **Step 2: Run focused tests to verify modules are missing**

Run: `npm test -- --test-name-pattern="Jev|router"`

Expected: TypeScript fails on missing `jev.js` and `router.js` imports.

- [ ] **Step 3: Implement one typed Jev request per packet**

Use `TypeSafeClient.systemOne` with the pinned model and question IDs below:

```ts
const questionIds = [
  "untrusted_influence",
  "reaches_sensitive_operation",
  "validation_blocks_attack",
  "crosses_authorization_boundary",
  "authorization_enforced",
  "security_impact",
  "is_injection",
  "is_broken_access_control",
  "is_ssrf",
  "enough_context",
  "exploitability"
] as const;
```

The exploitability criteria are exactly:

```ts
[
  "Unreachable: the shown data or actor cannot reach the operation",
  "Theoretical: a path is imaginable but required evidence or preconditions are absent",
  "Constrained: the path exists but a meaningful restriction or uncommon precondition limits exploitation",
  "Direct: an untrusted actor can reach the sensitive behavior with no effective shown control"
]
```

Persist the full answers, distributions, confidence values, returned model ID, and token usage. On exhausted SDK retries or malformed output, return an explicit abstention record; never fabricate probabilities.

- [ ] **Step 4: Implement the pure router**

Use one JSON config with these numeric keys: `contextMin`, `safeRiskMax`, `highRiskMin`, `pathMin`, `controlEffectiveMin`, `controlAbsentMax`, `impactMin`, and `directExploitabilityMin`. Freeze development values at `0.70`, `0.20`, `0.80`, `0.70`, `0.80`, `0.20`, `0.70`, and `2.50`; calibration replaces the entire config atomically.

Choose a family only when exactly one family Noul is the maximum; a tie routes to `needs_deep_review`. Let `risk` be that maximum. For injection/SSRF, let `pathSupport = min(untrusted_influence, reaches_sensitive_operation)` and use `validation_blocks_attack` as the relevant control. For broken access control, let `pathSupport = crosses_authorization_boundary` and use `authorization_enforced` as the relevant control. Apply branches in this order:

1. unresolved packet context or `enough_context < contextMin` → `insufficient_context`;
2. `risk >= highRiskMin`, `pathSupport >= pathMin`, impact at least `impactMin`, relevant control at most `controlAbsentMax`, and exploitability at least `directExploitabilityMin` → `likely_vulnerability`;
3. `risk <= safeRiskMax`, exploitability below `directExploitabilityMin`, and either `pathSupport <= safeRiskMax` or relevant control at least `controlEffectiveMin` → `likely_safe`;
4. otherwise → `needs_deep_review`.

- [ ] **Step 5: Run tests and commit**

Run: `npm test`

Expected: all Jev request, raw probability, context escalation, and router boundary tests pass without a live API call.

```bash
git add config/router.dev.json src/contracts.ts src/jev.ts src/router.ts src/jev.test.ts src/router.test.ts
git commit -m "feat: route Jev security judgments"
```

---

### Task 5: Identical reasoning-model arms and immutable orchestration

**Files:**
- Create: `config/reasoning-output.schema.json`
- Create: `src/reasoning.ts`
- Create: `src/pipeline.ts`
- Create: `src/reasoning.test.ts`
- Create: `src/pipeline.test.ts`
- Create: `src/cli.ts`
- Modify: `package.json`

**Interfaces:**
- Consumes: the same candidate pool, snapshot, prompt, schema, command version, permissions, token/tool budget, and timeout for both Terra arms.
- Produces: `runReasoningReview(request, config): Promise<ReasoningResult>`, `runArm(input): Promise<RunBundle>`, and CLI subcommands `sanitize`, `discover`, `run`, and `score`.

- [ ] **Step 1: Write failing command and end-to-end fixture tests**

Use a tiny Node fixture process that reads a prompt from stdin and prints schema-valid JSON. Assert exact executable/argument arrays, sanitized `cwd`, cleared proxy/network environment, wall timeout, stdout/stderr capture, structured parsing, usage capture, and failure classification. Assert that Terra-all and Jev-to-Terra build byte-identical review requests for any candidate that reaches Terra.

Also assert a controlled mode where Jev, Terra, and Opus receive byte-identical packet JSON with no repository snapshot or tools. Map Jev `likely_vulnerability` to `vulnerable`, `likely_safe` to `safe`, and both escalation outcomes to `abstain`; do not compare prose or self-reported LLM confidence.

- [ ] **Step 2: Add the shared structured response schema**

`config/reasoning-output.schema.json` permits exactly:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["decision", "family", "evidence_span_ids"],
  "properties": {
    "decision": { "enum": ["vulnerable", "safe", "abstain"] },
    "family": { "enum": ["injection", "broken_access_control", "ssrf"] },
    "evidence_span_ids": {
      "type": "array",
      "items": { "type": "string", "pattern": "^s[1-9][0-9]*$" },
      "uniqueItems": true
    }
  }
}
```

- [ ] **Step 3: Implement bounded command execution without a shell**

For Terra, spawn this exact shape, substituting only paths:

```text
codex exec --ephemeral --ignore-user-config --model gpt-5.6-terra
  --sandbox read-only --cd <snapshot>
  --output-schema <absolute-schema-path>
  --output-last-message <exclusive-output-path> -
```

For the controlled Terra comparison, use the same executable, version, model, schema, and limits, but set `--cd` to an empty temporary directory and provide only the packet JSON in the prompt. The directory is read-only and contains no repository files.

For authenticated Opus runs, spawn this exact shape with the full non-alias model ID from the frozen manifest:

```text
claude --print --safe-mode --no-session-persistence --restricted
  --permission-mode dontAsk --allowedTools Read,Grep,Glob
  --model <frozen-full-opus-model-id>
  --json-schema <compact-schema-json> --output-format json
```

For the controlled Opus comparison, use an empty temporary working directory and an empty allowed-tool list. The agentic Opus comparison uses only `Read`, `Grep`, and `Glob` against the sanitized snapshot.

Spawn with `cwd` set to the snapshot, stdin set to the shared prompt, no shell, a frozen timeout, and only the credential variables required by that CLI. Kill the process group on timeout. Parse only schema-valid final output; timeout, malformed output, denied required tool, exhausted budget, or non-zero exit becomes `manual_review` and remains in the run.

- [ ] **Step 4: Implement arm orchestration and durable timing**

Start the monotonic timer immediately before discovery and stop only after the exclusive JSONL artifact has been renamed into place. Terra-all reviews every combined candidate. Jev-to-Terra calls Jev once per packet, directly emits `alert` for `likely_vulnerability`, suppresses `likely_safe`, and sends both escalation outcomes to the same Terra runner.

When the frozen Opus model ID and authenticated CLI are present, run `opus_all` and `jev_to_opus` through the same orchestration with identical Opus permissions and budgets in both arms. Keep Opus metrics secondary to the preregistered Terra primary hypothesis.

Claim 2 runs only raw Semgrep candidates: `likely_safe` suppresses, `likely_vulnerability` alerts, and both escalation outcomes stay retained unresolved alerts. Every run records discovery time, packet time, model attempts, backoff, escalations, token usage, model/provider charge when available, compute duration, final outcome, and errors.

Run cold repetitions with local tool/result caches cleared. Record warm-cache runs in a distinct diagnostic series that is excluded from primary estimates. Derive p95 with the same frozen sorted-index rule as the bootstrap percentiles and report it only as a secondary latency diagnostic.

Reject any primary cost decision when a model charge is unavailable or subscription cost cannot be allocated; label the cost component `inconclusive` instead of treating the call as free. Development/calibration may still measure recall and latency through subscription CLIs.

- [ ] **Step 5: Add the CLI and run the unpaid end-to-end fixture**

Use `node:util.parseArgs`; do not add a CLI package. Add scripts:

```json
{
  "triage": "npm run build --silent && node dist/src/cli.js",
  "test:e2e": "npm run build --silent && node dist/src/cli.js run --fixture test/fixtures/repository/candidates --evaluator fixture"
}
```

Run: `npm test && npm run test:e2e`

Expected: the complete sanitize → discover → packet → fake judgment → route → score flow passes without a network call or paid model call, and a second write to the same run ID fails without changing the first bundle.

- [ ] **Step 6: Commit orchestration**

```bash
git add config/reasoning-output.schema.json package.json src/reasoning.ts src/pipeline.ts src/reasoning.test.ts src/pipeline.test.ts src/cli.ts
git commit -m "feat: orchestrate benchmark arms"
```

---

### Task 6: Live development and calibration freeze

**Files:**
- Create: `benchmark/dev.json`
- Create: `src/calibrate.ts`
- Create: `src/calibrate.test.ts`
- Create: `benchmark/splits.json`
- Create: `benchmark/freeze.json`
- Modify: `src/cli.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: frozen Juice Shop/OpenSSF inputs, live Jev/Terra outputs, and the threshold grid.
- Produces: repository-disjoint splits, one selected router config, power diagnostics, and a content-hashed freeze manifest.

- [ ] **Step 1: Write failing deterministic split, power, and threshold-selection tests**

Build a synthetic corpus containing repeated repositories, vulnerable/patched pairs, and root causes shared across repositories. Assert that grouping occurs before hashing, no repository/root cause crosses a split, Juice Shop is development only, and repeated executions produce byte-identical manifests.

For threshold selection, assert that the algorithm rejects any config whose calibration recall lower bound is at or below `-0.02`, then chooses the surviving config with the lowest mean escalation rate. Break ties by lower `safeRiskMax`, higher `highRiskMin`, higher `contextMin`, then canonical JSON order. If no config clears the margin, calibration fails and no freeze file is written.

For power, use seed `20260919`. In each of 1,000 outer simulations, resample the planned number of repository clusters from calibration with replacement, then independently swap the two arm labels with probability `0.5` for every paired target/repetition outcome to impose a true recall difference of zero while preserving observed paired outcomes. Build a 2,000-draw repository bootstrap interval for that simulated dataset. Estimated power is the fraction whose lower bound is above `-0.02`; require at least `0.80`. Keep all five repetitions inside their repository cluster throughout both sampling levels.

- [ ] **Step 2: Implement deterministic corpus grouping and split creation**

Filter OpenSSF cases to JavaScript/TypeScript with verified vulnerable and fixed commits, localized target evidence, runnable non-destructive validation, and audited upstream license. Build connected components where cases are linked by either repository ID or underlying root-cause ID; vulnerable/patched pairs are linked explicitly. Hash each component's sorted IDs with SHA-256, sort by hash, and add whole components to calibration until the repository count is as close as possible to 30% without exceeding it; assign the remaining components to holdout. Abort if either split lacks every in-scope family or if the preregistered power simulation cannot detect a two-point margin at 80% power.

Write only public repository IDs, commits, language, family counts, licenses, and group hashes to `benchmark/splits.json`. Write target mappings, reproductions, advisories, and patches only under ignored `private/`.

- [ ] **Step 3: Implement the finite router search**

Evaluate the Cartesian product below only on calibration runs:

```ts
const grid = {
  contextMin: [0.6, 0.7, 0.8],
  safeRiskMax: [0.1, 0.2, 0.3],
  highRiskMin: [0.7, 0.8, 0.9],
  pathMin: [0.6, 0.7, 0.8],
  controlEffectiveMin: [0.7, 0.8, 0.9],
  controlAbsentMax: [0.1, 0.2, 0.3],
  impactMin: [0.6, 0.7, 0.8],
  directExploitabilityMin: [2.0, 2.5]
};
```

Cache raw Jev judgments by packet hash so the grid never repeats model calls. Select exactly by the tested rule above; thresholds never look at holdout labels.

- [ ] **Step 4: Run live development, then calibration**

First rotate the TypeSafe key previously pasted into chat and export the replacement only in the shell as `TYPESAFE_API_KEY`. Do not write it to `.env`, shell history, manifests, or artifacts.

Run Juice Shop development until packet construction, questions, and prompts are frozen. Then run calibration once with randomized/interleaved arm order and five repetitions:

```bash
npm run triage -- calibrate \
  --splits benchmark/splits.json \
  --partition calibration \
  --repetitions 5 \
  --concurrency 1 \
  --seed 20260918 \
  --output artifacts/calibration-2026-09-18
```

Expected: the command verifies `jev-1.13.0`, Semgrep `1.177.0`, Codex CLI `0.147.0`, sanitized snapshot hashes, split isolation, and every run count before selecting thresholds.

- [ ] **Step 5: Freeze the benchmark manifest**

`benchmark/freeze.json` records model IDs, CLI/SDK/scanner versions, local rule hash, prompts, question hash, packet schema hash, sanitizer policy hash, selected router config, five repetitions, concurrency one, seed `20260918`, retry policy, timeouts, runner hourly price, cost provenance rules, split hash, and calibration artifact hash. Refuse `run --partition holdout` when any observed value differs.

Run: `npm test && npm run triage -- verify-freeze --manifest benchmark/freeze.json`

Expected: tests pass and the manifest verifies without reading holdout labels.

- [ ] **Step 6: Commit the public freeze**

```bash
git add benchmark/dev.json benchmark/splits.json benchmark/freeze.json src/calibrate.ts src/calibrate.test.ts src/cli.ts README.md
git commit -m "feat: freeze benchmark calibration"
```

---

### Task 7: Frozen holdout, scoring report, and claim decisions

**Files:**
- Create: `src/report.ts`
- Create: `src/report.test.ts`
- Modify: `src/cli.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: the verified freeze manifest, hidden holdout ledger, five run bundles per arm/repository, and blinded adjudications.
- Produces: immutable `score.json`, `cases.jsonl`, `report.md`, and a three-outcome result for every component and the primary hypothesis.

- [ ] **Step 1: Write failing report consistency tests**

Feed the hand-calculated fixture through `scoreClaims` and `renderReport`. Assert exact metric values, denominators, interval endpoints, component labels, primary label, unresolved-review count, no-candidate count, AST/Semgrep overlap exclusion, cost provenance, and contamination limitation. Assert that report values come from `ScoreReport` and are not recomputed.

- [ ] **Step 2: Implement holdout preflight and execution**

Before the first holdout model call, verify:

- freeze manifest and split hashes;
- zero calibration/holdout repository or root-cause overlap;
- exact model/scanner/CLI versions;
- sanitized snapshot and rule hashes;
- complete hidden ledger and blinded reviewer assignments;
- two independent blinded security-review decisions per real finding, with a third blinded adjudication for disagreements and `insufficient_evidence` preserved when consensus is not reached;
- adequate power for the fixed two-point margin;
- writable empty output directory;
- five planned paired repetitions in seeded randomized/interleaved order.

Abort before any model call on failure. During execution, never retry only an unfavorable semantic result; only the frozen transport retry policy applies. Preserve failed/abstained runs in scoring.

- [ ] **Step 3: Generate immutable score and Markdown report artifacts**

The report must show Claim 1, Claim 2, and Claim 3 separately; the packet-only Jev/Terra/Opus comparison separately from agentic systems; target and repository counts; all denominators; repetition-nested recall; cost/latency ratio-of-means; bootstrap method/seed; supported/contradicted/inconclusive rules; family/severity slices; router-gate misses; review workload; model failure rates; cold p50/p95 latency; separately labeled warm-cache diagnostics; reviewer agreement; unresolved adjudications; and public-corpus contamination limits.

Run the holdout only after the freeze commit exists:

```bash
npm run triage -- run \
  --manifest benchmark/freeze.json \
  --partition holdout \
  --output artifacts/holdout-2026-09-18

npm run triage -- score \
  --run artifacts/holdout-2026-09-18 \
  --ledger private/holdout-ledger.jsonl \
  --output artifacts/holdout-2026-09-18/scored
```

Expected: exactly one immutable scored bundle, with `inconclusive` for any component lacking valid ground truth or actual cost provenance, `contradicted` for any valid interval entirely on the failing side, and no hidden case removed from a denominator.

- [ ] **Step 4: Verify and commit reporting code**

Run: `npm test && npm run check`

Expected: all unit and unpaid end-to-end checks pass; generated artifacts remain ignored.

```bash
git add src/report.ts src/report.test.ts src/cli.ts README.md
git commit -m "feat: report frozen holdout results"
```

---

### Task 8: Static benchmark dashboard

**Files:**
- Create: `dashboard/index.html`
- Create: `dashboard/app.js`
- Create: `src/dashboard.test.ts`
- Modify: `src/report.ts`
- Modify: `package.json`
- Modify: `README.md`

**Interfaces:**
- Consumes: the exact `score.json` and redacted `cases.jsonl` written by Task 7.
- Produces: a static, accessible dashboard bundle with no backend and no arbitrary scan input.

- [ ] **Step 1: Write a failing dashboard artifact test**

Generate dashboard data from the hand-calculated fixture and assert that the HTML contains a title, primary three-state verdict, metric table, pipeline waterfall, family filter, corpus filter, case explorer, limitations, and contamination disclosure. Assert no API key, absolute local path, private target note, reproduction secret, or hidden ledger field appears.

- [ ] **Step 2: Build the dashboard with platform-native HTML**

Use semantic HTML, CSS custom properties, inline SVG bars, and plain JavaScript. Render:

- Jev-to-Terra versus Terra-all recall, cost, and latency with interval bounds;
- raw Semgrep versus Semgrep-to-Jev retained-alert metrics;
- candidate → routed → escalated → alert/manual-review waterfall;
- redacted case evidence and decision provenance;
- family/corpus filters;
- visible method, limitations, and public-corpus contamination text.

Use a text label and shape in addition to color for `supported`, `contradicted`, and `inconclusive`. Ensure keyboard-operable filters, visible focus, table captions, and reduced-motion support. Do not add a charting library or web framework.

- [ ] **Step 3: Generate and inspect the static bundle**

Add:

```json
{
  "dashboard": "npm run build --silent && node dist/src/cli.js dashboard --score artifacts/holdout-2026-09-18/scored/score.json --cases artifacts/holdout-2026-09-18/scored/cases.jsonl --output artifacts/dashboard"
}
```

Run: `npm test && npm run dashboard`

Expected: `artifacts/dashboard/index.html`, `app.js`, and redacted `data.json` are generated; opening `index.html` from a static server makes no network requests except local asset reads.

- [ ] **Step 4: Final repository verification and commit**

Run:

```bash
npm run check
npm run test:e2e
git status --short
```

Expected: all checks pass; status lists only the intended dashboard and documentation changes before commit.

```bash
git add dashboard/index.html dashboard/app.js src/dashboard.test.ts src/report.ts package.json README.md
git commit -m "feat: add static benchmark dashboard"
```

## Acceptance Matrix

| Spec requirement | Implemented by |
| --- | --- |
| Target-instance matching, no-candidate recall, Claim 1/2 separation | Task 1 |
| Packet-only Jev/Terra/Opus comparison without tool access | Tasks 1 and 5 |
| Five-run nesting, paired repository bootstrap, ratio-of-means, three outcomes | Task 1 |
| Sanitized identical snapshots, leakage prevention, stable packets | Task 2 |
| Semgrep plus AST inventory, one-hop context, overlap fixture | Task 3 |
| Typed Jev questions, raw probabilities, forced context escalation | Task 4 |
| Identical Terra permissions and candidate pools, failure preservation | Task 5 |
| Repository-disjoint split, live calibration, threshold and version freeze | Task 6 |
| Frozen holdout, blinded ground truth, immutable scored report | Task 7 |
| Shared-data static dashboard, accessibility, disclosures | Task 8 |
