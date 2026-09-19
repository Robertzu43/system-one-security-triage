# Controlled Model Comparison Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the old cascade-first primary analysis with a reproducible, failure-preserving Jev-versus-Terra-versus-Opus controlled comparison over identical canonical evidence, while keeping the existing cascade code available only as a secondary experiment.

**Architecture:** Frozen evidence packets are projected to one canonical model-visible JSON string and scheduled for five seeded, interleaved repetitions across three evaluator adapters. Each adapter maps its native response to one shared primary result union, immutable attempt artifacts feed a pure controlled scorer, and the report/dashboard render scorer output without recalculating metrics. The current Codex CLI cannot disable shell and retrieval tools strongly enough for the primary experiment, so its Terra adapter is explicitly ineligible and every live command preflights all adapters before making any provider call.

**Tech Stack:** Node.js 24+, TypeScript 5.9.2, Node's built-in test runner, `@typesafe-ai/sdk@0.6.0`, Jev `jev-1.13.0`, Codex CLI `0.147.0` (secondary only; controlled Terra ineligible), Claude Code `2.1.276`, Opus `claude-opus-4-6`, plain HTML/CSS/JavaScript

**Spec:** `docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md`

## Global Constraints

- Treat `docs/superpowers/plans/2026-09-18-system-one-security-triage.md` as a historical record of the old cascade-first design. Do not execute its Tasks 6–8 and do not rewrite it.
- Complete and merge the code-only tasks from `docs/superpowers/plans/2026-09-18-controlled-corpus-preparation.md` before starting this plan. Preserve its `corpus` scripts and README sections; do not run vulnerable applications, Docker, or any real corpus command as part of this prerequisite.
- Start implementation in `/private/tmp/system-one-security-triage-impl` on `feature/system-one-security-triage`; merge `main` before changing code so the approved revised spec, both plans, and the corpus-preparation interfaces are present.
- Limit the first release to injection, broken access control, and SSRF.
- The primary dispositions are exactly `vulnerable`, `safe`, and `insufficient_context`.
- The primary statuses are exactly `valid`, `timeout`, `malformed_output`, `policy_failure`, and `service_failure`.
- A failed attempt has no disposition, family, or evidence spans; never encode a provider or harness failure as `insufficient_context`.
- `family` is non-null only for a valid `vulnerable` result. Valid `safe` and `insufficient_context` results use `family: null` and `evidenceSpanIds: []`.
- Jev, Terra, and Opus must receive the same `canonicalEvidenceState(packet)` bytes. Model-native instructions and output mechanisms may differ, but their semantic meaning and hashes are frozen before calibration.
- Primary evaluators receive no repository, web, shell, retrieval, scanner, Git-history, or private-ledger access.
- The model-visible evidence state excludes repository ID, commit, candidate source, private target ID, expected disposition, acceptable spans, reproductions, patches, and reviewer notes.
- Pin Jev to `jev-1.13.0`, the SDK to `0.6.0`, Claude Code to `2.1.276`, Opus to `claude-opus-4-6`, and all future eligible Terra adapters to a full immutable model ID and versioned transport.
- The installed Codex CLI `0.147.0` is not an eligible controlled Terra adapter because it cannot prove that shell and retrieval tools are absent. It must fail closed before model invocation.
- Use five randomized, interleaved repetitions per packet and evaluator at frozen concurrency `1`, with schedule seed `20260918`.
- Within a repetition, execute exactly one attempt per evaluator/packet. Set the benchmark-owned transport retry count to `0` for every adapter; provider-internal behavior is pinned by transport version and must be disclosed. Never retry based on the semantic answer.
- Average the five outcomes within each packet first. Repetitions never become independent examples.
- Use 10,000 paired, repository-clustered percentile-bootstrap draws with seed `20260918`; a sampled repository carries all targets, packets, evaluators, and repetitions.
- Apply the frozen `-0.02` non-inferiority margin separately to balanced triage accuracy and vulnerability recall for Jev–Terra and Jev–Opus.
- The primary claim is supported only when all four comparisons are supported, contradicted when any is contradicted, and inconclusive otherwise.
- Cost is fully loaded USD per 1,000 controlled packet decisions. Missing defensible provider cost makes only the cost result inconclusive; it does not rewrite a valid semantic result.
- Cold latency starts before serializing the frozen request and ends after the parsed attempt result is durably written. Report per-evaluator p50 and p95 at fixed concurrency.
- Do not use provider batch APIs or prompt caching for primary measurements. A runner that cannot verify these policies is ineligible.
- Use no database, workflow framework, runtime validation package, CLI package, charting library, or frontend framework.
- Tasks 1–8 use only fake clients, fixture executables, and checked-in fixtures. They must not read provider credentials or make network/model calls.
- Task 9 is the only live-model smoke task in this plan. It requires an explicit `--live` flag, user approval, development-only packets, and an all-adapter eligibility preflight before the first paid request.
- Keep API credentials in environment variables, redact them from artifacts, and never commit `private/`, `artifacts/`, `.env`, or generated `dist/` output.
- Every production behavior change follows RED → verify the expected failure → minimal GREEN → full regression checks.

## Current Baseline and Scope Boundary

The feature branch already contains the old plan's scorer, evidence sanitization, discovery, Jev routing, agentic reasoning runner, cascade orchestration, and unpaid fixture. Reuse their tested low-level behavior where it matches the revised design. The primary experiment must not call discovery, `runArm`, or `route`.

Keep these files unchanged during the primary implementation unless a task below names them:

- `src/jsonl.ts` and `src/jsonl.test.ts`
- `src/sanitize.ts` and `src/sanitize.test.ts`
- `src/discover.ts` and `src/discover.test.ts`
- `rules/semgrep.yml`
- all existing repository fixtures
- `config/router.dev.json`

Park these interfaces as secondary-only:

- `runArm`, `BenchmarkArm`, and cascade run records in `src/pipeline.ts`
- `route` and `RouteOutcome` in `src/router.ts`
- `config/reasoning-output.schema.json`
- the old `test/fixtures/scoring.json`
- Semgrep false-alert and AST-yield scoring

Delete these obsolete primary shortcuts when Task 4 reaches GREEN:

- `mapJevRouteToDecision`
- `runControlledComparison`
- the test named `controlled evaluation uses one packet-only prompt and maps Jev routes without confidence comparisons`

## File Structure

```text
src/contracts.ts                         shared primary and secondary artifact types plus trust-boundary parsers
src/contracts.test.ts                    primary union, ledger, and artifact validation
src/packets.ts                           existing packets plus canonical model-visible evidence projection
src/packets.test.ts                      projection byte stability and provenance-exclusion tests
src/jev.ts                               Jev atomic questions, supplied-span Choice, parsing, and primary mapping
src/jev.test.ts                          one-request shape, raw distributions, status, and mapping boundaries
src/reasoning.ts                         existing secondary runner plus shared bounded-process helpers for Opus
src/reasoning.test.ts                    existing agentic checks plus controlled Opus isolation/failure tests
src/controlled-adapters.ts               primary adapter contract, Jev/Opus adapters, ineligible Terra adapter
src/controlled-adapters.test.ts          fake-client adapter and all-adapter eligibility tests
src/controlled.ts                        seeded schedule, attempt execution, immutable artifacts, receipts
src/controlled.test.ts                   schedule, failure retention, timing, hash, and no-live tests
src/scorer.ts                             secondary scorer plus controlled metrics and paired bootstrap
src/scorer.test.ts                        controlled hand calculations, nesting, failures, and boundaries
src/cli.ts                                offline controlled fixture, primary scoring, report, dashboard, gated smoke
src/cli.test.ts                           subprocess tests proving live calls cannot occur accidentally
src/report.ts                             Markdown report and redacted dashboard-data generation
src/report.test.ts                        scorer/report agreement and disclosure checks
src/calibrate.ts                          calibration-only mapping selection, power-artifact gate, and freeze manifest
src/calibrate.test.ts                     selector, outcome export, imported power gate, and hash tests
config/controlled-output.schema.json      frontier-model primary output schema
config/controlled-instructions.json       frozen bounded decision meaning for Terra and Opus
config/primary-mapping.dev.json           development-only Jev disposition thresholds
test/fixtures/controlled-scoring.json     hand-calculated three-disposition primary fixture
test/fixtures/controlled-packets.jsonl    safe, vulnerable, and incomplete packets for all three families
dashboard/index.html                      accessible static controlled-comparison dashboard
dashboard/app.js                          plain-JS rendering from scorer-produced data
README.md                                 reproducibility, gating, limitations, and run boundaries
```

Generated calibration, holdout, smoke, reports, and dashboard data remain under ignored `artifacts/`. Private target mappings and adjudication labels remain under ignored `private/`.

## Dependency and Ownership Order

```text
Task 1 contracts/state
   └── Task 2 Jev adapter
         └── Task 3 frontier adapters
               └── Task 4 controlled runner
                     └── Task 5 controlled scorer
                           └── Task 6 offline CLI
                                 └── Task 7 report/dashboard
Task 4 + Task 5 + Task 7 + corpus-preparation plan ──> Task 8 calibration/freeze tooling
Tasks 1–8 ──────────────────────────────────────────> Task 9 explicitly gated live smoke
```

Implement Tasks 1–9 sequentially. Task 1 owns the shared primary contracts; Task 2 adds only Jev-native observation/mapping types, and Task 5 only renames the legacy cascade inference type. No later task may redefine the primary unions. `src/cli.ts` is first modified in Task 6 and then extended sequentially by Tasks 7–9. The corpus-preparation plan exclusively owns corpus intake, adjudication, split allocation, power simulation, `src/split.ts`, and `src/power.ts`; this plan reads their frozen outputs in Task 8.

---

### Task 1: Adopt the Revised Spec, Primary Contracts, and Canonical Evidence State

**Files:**
- Modify: `src/contracts.ts`
- Create: `src/contracts.test.ts`
- Modify: `src/packets.ts`
- Modify: `src/packets.test.ts`
- Create: `config/controlled-output.schema.json`
- Create: `config/controlled-instructions.json`

**Interfaces:**
- Consumes: existing `EvidencePacket`, `Family`, `Repetition`, `canonicalJson`, and the approved revised spec.
- Produces: `PrimaryDisposition`, `PrimaryStatus`, `PrimaryEvaluator`, `PrimaryResult`, `PrimaryAttempt`, `PrimaryLedgerRow`, `CanonicalEvidenceState`, `parsePrimaryAttempt(value)`, `parsePrimaryLedger(value)`, `parseCanonicalEvidenceState(value)`, and `canonicalEvidenceState(packet): string`.

- [ ] **Step 1: Merge the revised specification and verify the historical boundary**

```bash
git merge --no-edit main
git status --short
sed -n '1,24p' docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md
```

Expected: the spec says `Status: approved revised design`, this plan exists, and the old plan remains unchanged.

- [ ] **Step 2: Write failing canonical-state and primary-contract tests**

Add tests with these assertions:

```ts
test("canonical evidence excludes provenance and labels", () => {
  const packet = buildEvidencePacket(candidate(), 0);
  const state = canonicalEvidenceState(packet);
  assert.deepEqual(JSON.parse(state), {
    schemaVersion: 1,
    packetId: packet.packetId,
    entryKind: packet.entryKind,
    spans: packet.spans,
    relationships: packet.relationships,
    contextResolution: packet.contextResolution
  });
  assert.equal(state.includes(packet.repositoryId), false);
  assert.equal(state.includes(packet.commit), false);
  assert.equal(state.includes("candidateSources"), false);
  assert.deepEqual(parseCanonicalEvidenceState(JSON.parse(state)), JSON.parse(state));
});

test("primary result union keeps failures distinct from insufficient context", () => {
  assert.deepEqual(parsePrimaryAttempt(validSafeAttempt), validSafeAttempt);
  assert.throws(() => parsePrimaryAttempt({ ...validSafeAttempt, family: "ssrf" }), /family must be null/);
  assert.throws(() => parsePrimaryAttempt({ ...failureAttempt, disposition: "insufficient_context" }), /failure disposition must be null/);
});
```

Use `validSafeAttempt` with `status: "valid"`, `disposition: "safe"`, `family: null`, and `evidenceSpanIds: []`. Use `failureAttempt` with `status: "timeout"`, null decision fields, and `{ kind: "request_timeout", message: "fixture" }`.

- [ ] **Step 3: Run the focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='canonical evidence|primary result union' dist/src/packets.test.js dist/src/contracts.test.js
```

Expected: TypeScript fails because `canonicalEvidenceState`, `parseCanonicalEvidenceState`, `parsePrimaryAttempt`, and `parsePrimaryLedger` do not exist.

- [ ] **Step 4: Add the exact primary contract**

Add these types to `src/contracts.ts`:

```ts
export type PrimaryDisposition = "vulnerable" | "safe" | "insufficient_context";
export type PrimaryStatus = "valid" | "timeout" | "malformed_output" | "policy_failure" | "service_failure";
export type PrimaryEvaluator = "jev" | "terra" | "opus";
export type JevBinaryQuestionId = Exclude<keyof JevAnswers, "exploitability">;

export interface JevAttemptObservation {
  nouls: Record<JevBinaryQuestionId, number>;
  exploitability: Pick<ScoreAnswer, "score" | "confidence" | "probabilities">;
  evidenceSpan: { choice: string; confidence: number; probabilities: Readonly<Record<string, number>> };
}

export type PrimaryResult =
  | { status: "valid"; disposition: "vulnerable"; family: Family; evidenceSpanIds: string[]; error: null }
  | { status: "valid"; disposition: "safe" | "insufficient_context"; family: null; evidenceSpanIds: []; error: null }
  | { status: Exclude<PrimaryStatus, "valid">; disposition: null; family: null; evidenceSpanIds: []; error: { kind: string; message: string } };

export interface PrimaryAttempt {
  attemptId: string;
  packetId: string;
  evaluator: PrimaryEvaluator;
  repetition: Repetition;
  evidenceStateSha256: string;
  result: PrimaryResult;
  modelId: string | null;
  usage: { inputTokens: number; outputTokens: number; cachedInputTokens: number } | null;
  jevObservation: JevAttemptObservation | null;
  providerCost: { status: "available"; usd: number; provenance: string } | { status: "inconclusive"; usd: null; provenance: string };
  requestArtifact: string;
  responseArtifact: string;
}

export interface PrimaryLedgerRow {
  packetId: string;
  targetId: string;
  rootCauseId: string;
  repositoryId: string;
  corpus: "development" | "calibration" | "holdout";
  applicableFamily: Family;
  expectedDisposition: PrimaryDisposition;
  expectedFamily: Family | null;
  acceptableEvidenceSpanIds: string[];
  severity: "low" | "medium" | "high" | "critical";
  jevExpected: Partial<Record<JevBinaryQuestionId, boolean>>;
}
```

Implement explicit object, string, number, array, enum, probability, and cross-field checks in `parsePrimaryAttempt` and `parsePrimaryLedger`. Require unique packet IDs in the ledger. A valid Jev result requires a complete `jevObservation`; a failed Jev result may use null, and Terra/Opus must use null. Require expected family and non-empty acceptable spans only for expected `vulnerable`; require null family and empty acceptable spans for the other two dispositions. For vulnerable rows, require `expectedFamily === applicableFamily`. Task 5's score-input parser owns cross-attempt uniqueness.

- [ ] **Step 5: Implement canonical evidence projection**

Add to `src/packets.ts`:

```ts
export type CanonicalEvidenceState = Pick<EvidencePacket,
  "schemaVersion" | "packetId" | "entryKind" | "spans" | "relationships" | "contextResolution"
>;

export const canonicalEvidenceSchemaDescriptor = {
  version: 1,
  exactKeys: ["schemaVersion", "packetId", "entryKind", "spans", "relationships", "contextResolution"],
  entryKinds: ["route", "handler", "call"],
  spanExactKeys: ["id", "path", "startLine", "endLine", "text"],
  relationshipExactKeys: ["from", "to", "kind"],
  relationshipKinds: ["calls", "flows_to", "guards"],
  contextKeys: ["middleware", "upstreamDataFlow", "sanitizers", "authorization", "callPath"],
  contextValues: ["resolved", "unresolved"],
  maximumUtf8Bytes: 32000
} as const;

export const canonicalEvidenceProjectionDescriptor = {
  version: 1,
  includedFields: ["schemaVersion", "packetId", "entryKind", "spans", "relationships", "contextResolution"],
  excludedFields: ["repositoryId", "commit", "candidateSources"]
} as const;

export function canonicalEvidenceState(packet: EvidencePacket): string {
  const state: CanonicalEvidenceState = {
    schemaVersion: packet.schemaVersion,
    packetId: packet.packetId,
    entryKind: packet.entryKind,
    spans: packet.spans,
    relationships: packet.relationships,
    contextResolution: packet.contextResolution
  };
  return canonicalJson(state);
}
```

Implement `parseCanonicalEvidenceState` from `canonicalEvidenceSchemaDescriptor`, with the same existing span, relationship, context, path, line, leakage, exact-key, referential-integrity, and 32,000-byte checks, but without accepting repository, commit, or candidate-source fields. Build the projection from `canonicalEvidenceProjectionDescriptor.includedFields`; do not duplicate either field list elsewhere. Keep packet construction, packet IDs, provenance, and the existing full-packet validation unchanged. The model-visible projection is the new equality boundary.

- [ ] **Step 6: Add the controlled schema and frozen instruction**

Create `config/controlled-output.schema.json`:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["disposition", "family", "evidence_span_ids"],
  "properties": {
    "disposition": { "enum": ["vulnerable", "safe", "insufficient_context"] },
    "family": { "enum": ["injection", "broken_access_control", "ssrf", null] },
    "evidence_span_ids": {
      "type": "array",
      "items": { "type": "string", "pattern": "^s[1-9][0-9]*$" },
      "uniqueItems": true
    }
  },
  "allOf": [
    {
      "if": { "properties": { "disposition": { "const": "vulnerable" } } },
      "then": { "properties": { "family": { "enum": ["injection", "broken_access_control", "ssrf"] } } },
      "else": { "properties": { "family": { "const": null }, "evidence_span_ids": { "maxItems": 0 } } }
    }
  ]
}
```

Create `config/controlled-instructions.json` with exactly one property:

```json
{
  "decision": "Evaluate only the supplied frozen evidence. Return vulnerable only when it establishes one of the three allowed vulnerability families. Return safe only when the supplied evidence establishes that the target path is blocked or protected. Return insufficient_context when evidence required for the decision is absent. Never infer that an omitted control is absent or present. For vulnerable, choose exactly one family and cite only supplied evidence span IDs. For safe or insufficient_context, return family null and an empty evidence_span_ids array. Return only the requested structured object and do not use tools."
}
```

- [ ] **Step 7: Run all tests and commit the contract boundary**

```bash
npm test
git diff --check
git add src/contracts.ts src/contracts.test.ts src/packets.ts src/packets.test.ts config/controlled-output.schema.json config/controlled-instructions.json
git commit -m "feat: define controlled comparison contracts"
```

Expected: every existing test plus the new contract and projection tests passes without a network call.

---

### Task 2: Jev Primary Adapter and Frozen Disposition Mapping

**Files:**
- Modify: `src/jev.ts`
- Modify: `src/jev.test.ts`
- Modify: `src/contracts.ts`
- Create: `config/primary-mapping.dev.json`

**Interfaces:**
- Consumes: `canonicalEvidenceState(packet)`, `PrimaryResult`, `EvidencePacket`, `TypeSafeClient.systemOne`, and `PrimaryMappingConfig`.
- Produces: `parsePrimaryMappingConfig(value): PrimaryMappingConfig`, `judgePrimaryWithJev(packet, client, options): Promise<JevPrimaryObservation>`, and `mapJevPrimary(state, observation, config): PrimaryResult`, where `state` is `CanonicalEvidenceState`.

- [ ] **Step 1: Write failing tests for exact state bytes, span Choice, and failure classes**

```ts
test("Jev receives the canonical state once with a supplied-span choice", async () => {
  let request: unknown;
  const client = { systemOne: async (value: unknown) => { request = value; return response(); } } as Pick<TypeSafeClient, "systemOne">;
  const observation = await judgePrimaryWithJev(packet, client, { timeoutMs: 1_000, maxRetries: 0 });
  const sent = request as { state: string; model: string; questions: Record<string, unknown> };
  assert.equal(sent.state, canonicalEvidenceState(packet));
  assert.equal(sent.model, "jev-1.13.0");
  assert.deepEqual(Object.keys((sent.questions.evidence_span as { criteria: object }).criteria), ["none", "s1"]);
  assert.equal(observation.kind, "judgment");
});

test("Jev distinguishes incomplete evidence from service failure", async () => {
  assert.deepEqual(mapJevPrimary(unresolvedPacket, completeObservation(), config), {
    status: "valid", disposition: "insufficient_context", family: null, evidenceSpanIds: [], error: null
  });
  assert.equal((await judgePrimaryWithJev(packet, timeoutClient, limits)).kind, "timeout");
});
```

Also assert that an unresolved authorization field does not force `insufficient_context` for a unique injection family, while unresolved sanitizer or call-path evidence does.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='canonical state|supplied-span|incomplete evidence|service failure' dist/src/jev.test.js
```

Expected: TypeScript fails because the primary Jev functions and evidence-span answer do not exist.

- [ ] **Step 3: Add Jev observation and mapping types**

Add to `src/contracts.ts`:

```ts
export interface ChoiceAnswer {
  readonly type: "choice";
  readonly choice: string;
  readonly confidence: number;
  readonly probabilities: Readonly<Record<string, number>>;
}

export interface JevPrimaryAnswers extends JevAnswers {
  readonly evidence_span: ChoiceAnswer;
}

export type JevPrimaryObservation =
  | { kind: "judgment"; model: "jev-1.13.0"; usage: { input_tokens: number; output_tokens: number }; answers: JevPrimaryAnswers }
  | { kind: "timeout" | "malformed_output" | "policy_failure" | "service_failure"; error: { name: string; message: string } };

export interface JevPrimaryOptions {
  timeoutMs: number;
  maxRetries: 0;
}

export interface PrimaryMappingConfig {
  contextMin: number;
  safeRiskMax: number;
  vulnerableRiskMin: number;
  pathMin: number;
  controlEffectiveMin: number;
  controlAbsentMax: number;
  impactMin: number;
  directExploitabilityMin: number;
}
```

Implement `parsePrimaryMappingConfig` with exactly those eight keys. Require every value to be finite, the first seven to be in `[0, 1]`, `directExploitabilityMin` to be in `[0, 3]`, `safeRiskMax <= vulnerableRiskMin`, and `controlAbsentMax <= controlEffectiveMin`. Add boundary tests beside the adapter tests; neither the development file nor a calibration result may bypass this parser.

- [ ] **Step 4: Send one typed Jev request with explicit transport limits**

Import `choice`, `APITimeoutError`, `APIConnectionError`, `APIError`, and `TypeSafeError` from the installed SDK. Retain the existing ten Noul instructions and four-level exploitability Score verbatim, export them through this frozen descriptor, and build the runtime question object from it:

```ts
export const primaryQuestionDescriptor = {
  version: 1,
  atomicQuestions,
  evidenceSpanChoice: {
    instructions: "Which supplied span most directly supports a vulnerable conclusion?",
    noneDescription: "No supplied span directly supports a vulnerable conclusion",
    suppliedSpanDescriptionFields: ["path", "text"]
  }
} as const;
```

Build the dynamic supplied-span question beside the existing Nouls and Score:

```ts
const evidenceCriteria = Object.fromEntries([
  ["none", primaryQuestionDescriptor.evidenceSpanChoice.noneDescription],
  ...packet.spans.map((span) => [span.id, { path: span.path, text: span.text }])
]);
const questions = {
  ...primaryQuestionDescriptor.atomicQuestions,
  evidence_span: choice(primaryQuestionDescriptor.evidenceSpanChoice.instructions, evidenceCriteria)
};
const response = await client.systemOne(
  { state: canonicalEvidenceState(packet), model: "jev-1.13.0", questions },
  { timeout: options.timeoutMs, retry: { maxRetries: options.maxRetries } }
);
```

Reject a returned model other than `jev-1.13.0`, invalid Noul probabilities, invalid Score distributions, invalid Choice distributions, or Choice keys not equal to the supplied criteria. Map `APITimeoutError` to `timeout`, malformed response data to `malformed_output`, local `TypeSafeError` configuration failures to `policy_failure`, and `APIConnectionError`/`APIError`/unknown transport failures to `service_failure`.

- [ ] **Step 5: Implement the pure primary mapping**

Create `config/primary-mapping.dev.json`:

```json
{
  "contextMin": 0.70,
  "safeRiskMax": 0.20,
  "vulnerableRiskMin": 0.80,
  "pathMin": 0.70,
  "controlEffectiveMin": 0.80,
  "controlAbsentMax": 0.20,
  "impactMin": 0.70,
  "directExploitabilityMin": 2.50
}
```

Implement mapping in this exact order:

```ts
const requiredContext: Record<Family, readonly (keyof ContextResolution)[]> = {
  injection: ["upstreamDataFlow", "sanitizers", "callPath"],
  broken_access_control: ["middleware", "authorization", "callPath"],
  ssrf: ["upstreamDataFlow", "sanitizers", "callPath"]
};

// 1. Propagate non-judgment observation kind to the same PrimaryStatus with null decision fields.
const rankedFamilies = [
  ["injection", answers.is_injection.noul],
  ["broken_access_control", answers.is_broken_access_control.noul],
  ["ssrf", answers.is_ssrf.noul]
] as const;
// 2. Require one unique maximum family score; a tie is valid insufficient_context.
const [family, risk] = uniqueMaximum(rankedFamilies);
// 3. Any requiredContext[family] field unresolved, or enough_context < contextMin, is valid insufficient_context.
const pathSupport = family === "broken_access_control"
  ? answers.crosses_authorization_boundary.noul
  : Math.min(answers.untrusted_influence.noul, answers.reaches_sensitive_operation.noul);
const controlEffective = family === "broken_access_control"
  ? answers.authorization_enforced.noul
  : answers.validation_blocks_attack.noul;
// 4. vulnerable iff risk >= vulnerableRiskMin, pathSupport >= pathMin,
//    controlEffective <= controlAbsentMax, security_impact >= impactMin,
//    and exploitability.score >= directExploitabilityMin.
// 5. safe iff risk <= safeRiskMax, exploitability.score < directExploitabilityMin,
//    and (pathSupport <= safeRiskMax or controlEffective >= controlEffectiveMin).
// 6. Every remaining valid judgment is insufficient_context.
```

For vulnerable output, emit the selected span unless Choice returned `none`; `none` produces an empty array and therefore an evidence-localization miss rather than a malformed response.

- [ ] **Step 6: Verify mapping boundaries and full regression**

```bash
npm run build && node --test --test-name-pattern='Jev|primary mapping|supplied-span' dist/src/jev.test.js
npm test
git diff --check
```

Expected: all tests pass with fake clients and no API key.

- [ ] **Step 7: Commit the Jev adapter**

```bash
git add src/contracts.ts src/jev.ts src/jev.test.ts config/primary-mapping.dev.json
git commit -m "feat: map Jev controlled decisions"
```

---

### Task 3: Controlled Adapter Contract, Opus Isolation, and Fail-Closed Terra

**Files:**
- Create: `src/controlled-adapters.ts`
- Create: `src/controlled-adapters.test.ts`
- Modify: `src/reasoning.ts`
- Modify: `src/reasoning.test.ts`

**Interfaces:**
- Consumes: `EvidencePacket`, `PrimaryResult`, `judgePrimaryWithJev`, `mapJevPrimary`, existing bounded-process helpers, controlled schema, and frozen instruction.
- Produces: `ControlledAdapter`, `ControlledEvaluationRequest`, `AdapterEligibility`, `createJevControlledAdapter`, `createOpusControlledAdapter`, `createTerraControlledAdapter`, and `assertAllAdaptersEligible(adapters)`.

- [ ] **Step 1: Write failing adapter eligibility and no-invocation tests**

```ts
test("current Codex CLI Terra adapter is ineligible and never invokes a process", async () => {
  let invoked = false;
  const adapter = createTerraControlledAdapter({ invoke: async () => { invoked = true; throw new Error("must not run"); } });
  assert.deepEqual(adapter.capability(), {
    eligible: false,
    reason: "codex-cli-0.147.0-cannot-disable-shell-and-retrieval-tools"
  });
  await assert.rejects(adapter.evaluate(request), /ineligible controlled Terra adapter/);
  assert.equal(invoked, false);
});

test("all-adapter preflight fails before checking credentials or invoking models", async () => {
  await assert.rejects(assertAllAdaptersEligible([eligibleJev, ineligibleTerra, eligibleOpus]), /terra.*ineligible/);
  assert.equal(modelCalls, 0);
  assert.equal(runtimePreflightCalls, 0);
});
```

Add Opus fixture tests asserting an empty working directory, `--allowedTools ""`, exact full model ID, compact controlled schema, no proxy variables, and a parsed valid safe result. A second fixture response with nonzero `cache_read_input_tokens` or `cache_creation_input_tokens` must become `policy_failure`.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='ineligible|all-adapter preflight|controlled Opus' dist/src/controlled-adapters.test.js dist/src/reasoning.test.js
```

Expected: TypeScript fails because the adapter module and controlled Opus entry point do not exist.

- [ ] **Step 3: Define the adapter boundary**

Create `src/controlled-adapters.ts` with:

```ts
export interface AdapterEligibility {
  eligible: boolean;
  reason: string;
}

export interface ControlledEvaluationRequest {
  packet: EvidencePacket;
  repetition: Repetition;
  timeoutMs: number;
  maxRetries: 0;
  schemaPath: string;
  instruction: string;
}

export interface ControlledAdapter {
  readonly evaluator: PrimaryEvaluator;
  capability(): AdapterEligibility;
  preflight(): Promise<AdapterEligibility>;
  evaluate(request: ControlledEvaluationRequest): Promise<{
    result: PrimaryResult;
    modelId: string | null;
    usage: PrimaryAttempt["usage"];
    jevObservation: PrimaryAttempt["jevObservation"];
    providerCost: PrimaryAttempt["providerCost"];
    rawRequest: unknown;
    rawResponse: unknown;
  }>;
}
```

`assertAllAdaptersEligible` checks the set is exactly `jev`, `terra`, and `opus` and rejects duplicates. It first evaluates all synchronous `capability()` descriptors and throws with all static reasons when any is false. Only when all three static descriptors are eligible does it await every `preflight()`, which may resolve pinned executables or versions but must not construct provider clients, read credentials, or invoke a model. It collects and throws all runtime reasons before returning adapters.

All three constructors accept lazy client/process factories. Construction, `capability()`, and `preflight()` must not read API-key environment variables; only `evaluate()` may resolve the factory after the all-adapter preflight succeeds.

- [ ] **Step 4: Implement Jev and Terra adapters**

`createJevControlledAdapter` delegates to Task 2 and returns statically eligible only when the SDK version, frozen model, explicit timeout, explicit retry count, and canonical-state hash are configured; its runtime preflight verifies the imported SDK `VERSION` equals `0.6.0` without constructing a client. It copies every Noul probability plus the exploitability Score and supplied-span Choice distributions into `jevObservation`. When usage is available, set provider cost to `inputTokens * 0.042 / 1_000_000` with provenance `TypeSafe Jev 1.13.0 input price frozen at USD 0.042/M`; if the frozen price cannot be verified, use inconclusive provider cost. Opus and Terra return `jevObservation: null`.

`createTerraControlledAdapter.capability()` returns this constant result, `preflight()` returns the same result, and neither method calls its injected process function:

```ts
const TERRA_INELIGIBLE = {
  eligible: false,
  reason: "codex-cli-0.147.0-cannot-disable-shell-and-retrieval-tools"
} as const;
```

Its `evaluate` method throws `Error("ineligible controlled Terra adapter: codex-cli-0.147.0-cannot-disable-shell-and-retrieval-tools")`. Do not add prompt-only, empty-directory-only, event-audit-only, or sandbox-only bypasses.

- [ ] **Step 5: Extract the minimum reusable process result from the existing runner**

In `src/reasoning.ts`, retain the agentic public API and add one exported helper for the eligible Opus adapter:

```ts
export interface BoundedProcessRequest {
  command: string;
  args: string[];
  cwd: string;
  prompt: string;
  timeoutMs: number;
  environmentKeys: readonly string[];
  readablePaths: readonly string[];
  outputDirectory: string;
}

export async function runBoundedProcess(request: BoundedProcessRequest, config: ReasoningConfig): Promise<{
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnError: { name: string; message: string } | null;
}>;
```

Move only the existing spawn, timeout/process-group kill, minimal-environment, executable-resolution, and macOS sandbox-profile behavior behind this helper. Keep `runReasoningReview` behavior and its existing tests unchanged.

- [ ] **Step 6: Implement the controlled Opus adapter**

Its static capability requires Darwin sandbox isolation, exact configured Claude Code version `2.1.276`, full model ID `claude-opus-4-6`, empty allowed-tools configuration, no prompt caching, and no batch mode. Its runtime preflight invokes only `claude --version` through the bounded helper with no credential environment keys and requires exact stdout `2.1.276 (Claude Code)`; timeout, mismatch, or spawn failure makes the adapter ineligible before any model call.

Create a new empty temporary directory per attempt and execute this exact shape through `runBoundedProcess`:

```ts
const args = [
  "--print",
  "--safe-mode",
  "--no-session-persistence",
  "--restricted",
  "--permission-mode", "dontAsk",
  "--allowedTools", "",
  "--model", "claude-opus-4-6",
  "--json-schema", canonicalJson(JSON.parse(await readFile("config/controlled-output.schema.json", "utf8"))),
  "--output-format", "json"
];
```

The prompt is `${instruction}\n\nEVIDENCE_STATE_JSON:\n${canonicalEvidenceState(packet)}`. Read only the typed `structured_output` and usage envelope. Map input/output token fields to `usage`; map both cache-read and cache-creation input tokens into `cachedInputTokens`. Any nonzero cached-input count, tool event, or denied-tool event is `policy_failure`. Validate every evidence span against `packet.spans`. Map timeout to `timeout`, invalid/extra output to `malformed_output`, typed policy refusal to `policy_failure`, and spawn/nonzero service failure to `service_failure`. A valid output with absent charge remains semantically valid with `providerCost.status: "inconclusive"`. When the CLI exposes a defensible per-call charge, retain the exact charge and its provider-field provenance; never derive a charge from a subscription price.

- [ ] **Step 7: Run full offline verification and commit**

```bash
npm test
npm run test:e2e
git diff --check
git add src/controlled-adapters.ts src/controlled-adapters.test.ts src/reasoning.ts src/reasoning.test.ts
git commit -m "feat: add controlled evaluator adapters"
```

Expected: all tests pass, Terra is proven non-invoking, and no provider credential is read.

---

### Task 4: Seeded Controlled Schedule and Immutable Attempt Artifacts

**Files:**
- Create: `src/controlled.ts`
- Create: `src/controlled.test.ts`
- Modify: `src/pipeline.ts`
- Modify: `src/pipeline.test.ts`

**Interfaces:**
- Consumes: validated `EvidencePacket[]`, exactly three eligible `ControlledAdapter` objects, `writeJsonlExclusive`, `canonicalEvidenceState`, seed `20260918`, five repetitions, and concurrency `1`.
- Produces: `buildControlledSchedule(packets, seed): ScheduledAttempt[]`, `runControlledBenchmark(input): Promise<ControlledRunManifest>`, one immutable attempt JSONL plus one receipt JSONL per scheduled attempt, and one immutable run manifest.

- [ ] **Step 1: Write failing schedule and artifact tests**

```ts
test("schedule contains five interleaved attempts per packet and evaluator", () => {
  const schedule = buildControlledSchedule([packetA, packetB], 20260918);
  assert.equal(schedule.length, 2 * 3 * 5);
  for (const packet of [packetA, packetB]) for (const evaluator of ["jev", "terra", "opus"]) {
    assert.deepEqual(
      schedule.filter((row) => row.packetId === packet.packetId && row.evaluator === evaluator).map((row) => row.repetition).sort(),
      [1, 2, 3, 4, 5]
    );
  }
  assert.deepEqual(schedule, buildControlledSchedule([packetA, packetB], 20260918));
  assert.notDeepEqual(schedule, buildControlledSchedule([packetA, packetB], 20260919));
});

test("runner persists failures and hashes identical evidence bytes", async () => {
  const manifest = await runControlledBenchmark(fixtureInput);
  assert.equal(manifest.attempts.length, 15);
  assert.equal(new Set(manifest.attempts.map((row) => row.evidenceStateSha256)).size, 1);
  assert(manifest.attempts.some((row) => row.result.status === "service_failure"));
  await assert.rejects(runControlledBenchmark(fixtureInput), /already exists|not empty/);
});
```

Inject three eligible fixture adapters. Make one fixture attempt return `service_failure`; do not make the fixture adapter throw for that expected failure.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='schedule contains|persists failures|identical evidence' dist/src/controlled.test.js
```

Expected: TypeScript fails because `src/controlled.ts` does not exist.

- [ ] **Step 3: Implement deterministic block shuffling**

Define:

```ts
export interface ScheduledAttempt {
  attemptId: string;
  packetId: string;
  evaluator: PrimaryEvaluator;
  repetition: Repetition;
  ordinal: number;
}
```

Use the existing Mulberry32 algorithm with a local Fisher–Yates shuffle. For each repetition `1..5`, create every packet/evaluator pair, sort first by packet ID and evaluator, shuffle that repetition's block, then append it. Set `attemptId` to `stableHash({ packetId, evaluator, repetition })` and `ordinal` to its final zero-based index. Reject duplicate packet IDs and an empty packet list.

- [ ] **Step 4: Define the run input, receipt, and manifest**

```ts
export interface ControlledRunInput {
  runId: string;
  packets: readonly EvidencePacket[];
  adapters: readonly ControlledAdapter[];
  outputDirectory: string;
  schemaPath: string;
  instruction: string;
  timeoutMs: number;
  maxRetries: 0;
  runnerUsdPerHour: number;
  now?: () => Date;
  seed: 20260918;
  repetitions: 5;
  concurrency: 1;
}

export interface AttemptReceipt {
  attemptId: string;
  artifactSha256: string;
  requestSha256: string;
  responseSha256: string;
  coldLatencyMs: number;
}

export interface ControlledRunManifest {
  runId: string;
  startedAt: string;
  completedAt: string;
  seed: 20260918;
  repetitions: 5;
  concurrency: 1;
  timeoutMs: number;
  maxRetries: 0;
  runnerUsdPerHour: number;
  instructionSha256: string;
  schemaSha256: string;
  scheduleSha256: string;
  attempts: PrimaryAttempt[];
  receipts: AttemptReceipt[];
  primaryEligible: boolean;
  ineligibilityReasons: string[];
}
```

Require a previously nonexistent output directory, exact fixed settings, a finite non-negative `runnerUsdPerHour`, and exactly one adapter for each evaluator. Set `instructionSha256` to SHA-256 of the UTF-8 instruction string and `schemaSha256` to `stableHash` of the parsed schema object. Call `assertAllAdaptersEligible` before creating the output directory or reading provider credentials. After preflight succeeds, record `startedAt` from `(input.now ?? (() => new Date()))().toISOString()` immediately before creating output; record `completedAt` from the same clock after all artifact hashes verify and before the manifest write. Tests inject a monotonic fixed clock.

- [ ] **Step 5: Execute attempts serially and durably**

After eligibility passes, create the output directory and its `requests`, `responses`, `attempts`, and `receipts` subdirectories. For each scheduled row, use these exact relative artifact names and run the attempt serially:

```ts
const requestArtifact = `requests/${attemptId}.jsonl`;
const responseArtifact = `responses/${attemptId}.jsonl`;
const attemptArtifact = `attempts/${attemptId}.jsonl`;
const receiptArtifact = `receipts/${attemptId}.jsonl`;
const requestPath = join(outputDirectory, requestArtifact);
const responsePath = join(outputDirectory, responseArtifact);
const attemptPath = join(outputDirectory, attemptArtifact);
const receiptPath = join(outputDirectory, receiptArtifact);
const started = performance.now();
const evidenceState = canonicalEvidenceState(packet);
const evidenceStateSha256 = createHash("sha256").update(evidenceState).digest("hex");
const evaluated = await adapter.evaluate({ packet, repetition, timeoutMs, maxRetries, schemaPath, instruction });
await writeJsonlExclusive(requestPath, [evaluated.rawRequest]);
await writeJsonlExclusive(responsePath, [evaluated.rawResponse]);
await writeJsonlExclusive(attemptPath, [attempt]);
const coldLatencyMs = Math.round((performance.now() - started) * 1000) / 1000;
const requestSha256 = sha256(await readFile(requestPath));
const responseSha256 = sha256(await readFile(responsePath));
const artifactSha256 = sha256(await readFile(attemptPath));
await writeJsonlExclusive(receiptPath, [{ attemptId, artifactSha256, requestSha256, responseSha256, coldLatencyMs }]);
```

Set the attempt's `requestArtifact` and `responseArtifact` to the relative names above. Compute `requestSha256`, `responseSha256`, and `artifactSha256` by rereading the three files before writing the receipt. Wrap an unexpected adapter throw as `service_failure` with null decision fields and persist a sanitized synthetic raw request plus `{ error: { name, message } }` raw response. Do not retry in the scheduler; the adapter owns the frozen transport retry count. Write exactly one row to `run-manifest.jsonl` only after all attempt and receipt hashes have been reread and verified.

- [ ] **Step 6: Remove the obsolete controlled shortcut without touching secondary orchestration**

Delete only `mapJevRouteToDecision`, `runControlledComparison`, `ControlledComparisonInput`, `ControlledComparison`, and their obsolete pipeline test. Keep `runArm`, Semgrep arms, agentic review requests, and every existing secondary test.

Add this negative assertion to `src/pipeline.test.ts`:

```ts
test("secondary pipeline exports no primary controlled shortcut", async () => {
  const module = await pipeline();
  assert.equal("runControlledComparison" in module, false);
  assert.equal("mapJevRouteToDecision" in module, false);
});
```

- [ ] **Step 7: Run regression checks and commit**

```bash
npm test
npm run test:e2e
git diff --check
git add src/controlled.ts src/controlled.test.ts src/pipeline.ts src/pipeline.test.ts
git commit -m "feat: orchestrate controlled attempts"
```

Expected: the offline run produces exactly fifteen immutable attempt/receipt pairs per packet, and all parked secondary tests remain green.

---

### Task 5: Controlled Metrics, Paired Bootstrap, and Primary Decision

**Files:**
- Modify: `src/scorer.ts`
- Modify: `src/scorer.test.ts`
- Modify: `src/contracts.ts`
- Create: `test/fixtures/controlled-scoring.json`

**Interfaces:**
- Consumes: `PrimaryAttempt[]`, `AttemptReceipt[]`, `PrimaryLedgerRow[]`, `validGroundTruth`, and the frozen bootstrap settings.
- Produces: `parsePrimaryScoreInput(value): PrimaryScoreInput`, `scoreControlled(input): ControlledScoreReport`, `bootstrapControlled(input, draws?, seed?): ControlledInference`, `scoreSecondary(input)` for the parked old analysis, and `bootstrapCascade(input)` for the parked old cascade inference.

- [ ] **Step 1: Add the exact hand-calculated controlled fixture**

Create six packets over two repositories:

```text
repo-a: vulnerable injection, safe injection, insufficient_context injection
repo-b: vulnerable broken_access_control, safe ssrf, insufficient_context ssrf
```

Include five attempts per packet/evaluator. Terra is fully correct. Jev has four fully correct vulnerable outcomes plus one valid safe outcome on the repo-a vulnerable packet and is otherwise fully correct. Opus has four correct outcomes plus one valid safe outcome on the repo-a context-incomplete packet and is otherwise fully correct. Every correct vulnerable attempt uses the expected family and an acceptable span. Set every ledger row's corpus to `development`, every provider cost to an available synthetic USD value with provenance `fixture`, `runnerUsdPerHour` to `0.25`, and every receipt to a finite non-negative latency.

- [ ] **Step 2: Write failing point-metric and failure-accounting tests**

```ts
test("controlled scorer nests repetitions within packets", async () => {
  const input = parsePrimaryScoreInput(JSON.parse(await readFile("test/fixtures/controlled-scoring.json", "utf8")));
  const report = scoreControlled(input);
  assert.equal(report.evaluators.terra.balancedAccuracy, 1);
  assert.equal(report.evaluators.terra.vulnerabilityRecall, 1);
  assert.equal(report.evaluators.jev.vulnerabilityRecall, 0.9);
  assert.equal(report.evaluators.jev.balancedAccuracy, (0.9 + 1 + 1) / 3);
  assert.equal(report.evaluators.opus.vulnerabilityRecall, 1);
  assert.equal(report.evaluators.opus.balancedAccuracy, (1 + 1 + 0.9) / 3);
});

test("wrong family, wrong span, and failures are never vulnerable true positives", () => {
  const report = scoreControlled(parsePrimaryScoreInput(failureFixture));
  assert.equal(report.evaluators.jev.vulnerabilityRecall, 0);
  assert.deepEqual(report.evaluators.jev.statusRates, {
    valid: 0.4, timeout: 0.2, malformed_output: 0.2, policy_failure: 0.2, service_failure: 0
  });
});
```

- [ ] **Step 3: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='controlled scorer|wrong family|status rates' dist/src/scorer.test.js
```

Expected: TypeScript fails because the controlled scorer APIs do not exist.

- [ ] **Step 4: Implement strict primary score-input validation**

Define in `src/scorer.ts`:

```ts
export interface PrimaryScoreInput {
  attempts: PrimaryAttempt[];
  receipts: AttemptReceipt[];
  ledger: PrimaryLedgerRow[];
  validGroundTruth: boolean;
  runnerUsdPerHour: number;
}

export interface ControlledEvaluatorMetrics {
  balancedAccuracy: number;
  vulnerabilityRecall: number;
  vulnerablePrecision: number | null;
  falseSafeRate: number;
  safeSpecificity: number;
  insufficientContextRecall: number;
  familyAccuracy: number | null;
  evidenceSpanHitRate: number | null;
  selective: { coverage: number; accuracy: number | null };
  statusRates: Record<PrimaryStatus, number>;
  brier: Partial<Record<JevBinaryQuestionId, number>>;
  calibration: Partial<Record<JevBinaryQuestionId, Array<{
    lowerInclusive: number;
    upperInclusive: number;
    meanProbability: number | null;
    observedRate: number | null;
    packetCount: number;
  }>>>;
  tokenUsage: { inputTokens: number; outputTokens: number; cachedInputTokens: number; attemptsWithUsage: number; attemptsWithoutUsage: number };
  latency: { p50Ms: number; p95Ms: number };
  costPer1000:
    | { status: "available"; usd: number; providerProvenance: string[]; runnerUsdPerHour: number }
    | { status: "inconclusive"; usd: null; providerProvenance: string[]; runnerUsdPerHour: number };
}

export interface ControlledSliceMetrics {
  packetCount: number;
  correctDispositionRate: number;
  vulnerabilityRecall: number | null;
}

export interface ControlledScoreReport {
  evaluators: Record<PrimaryEvaluator, ControlledEvaluatorMetrics>;
  failures: Record<PrimaryEvaluator, Record<PrimaryStatus, number>>;
  counts: { repositories: number; targets: number; packets: number; attempts: number };
  slices: {
    byCorpus: Record<PrimaryLedgerRow["corpus"], Record<PrimaryEvaluator, ControlledSliceMetrics>>;
    byRepository: Record<string, Record<PrimaryEvaluator, ControlledSliceMetrics>>;
    byTarget: Record<string, Record<PrimaryEvaluator, ControlledSliceMetrics>>;
    byFamily: Record<Family, Record<PrimaryEvaluator, ControlledSliceMetrics>>;
    bySeverity: Record<PrimaryLedgerRow["severity"], Record<PrimaryEvaluator, ControlledSliceMetrics>>;
    byDisposition: Record<PrimaryDisposition, Record<PrimaryEvaluator, ControlledSliceMetrics>>;
  };
  terraOpusDescriptive: { balancedAccuracyDifference: number; vulnerabilityRecallDifference: number };
}
```

Validate exactly five repetitions for every ledger packet/evaluator, exactly one matching receipt per attempt, identical evidence-state hashes across evaluators for a packet, no extra packet IDs, finite non-negative latency and runner rate, and unique attempt/receipt IDs.

- [ ] **Step 5: Implement packet-nested metrics**

For each packet/evaluator, average five binary indicators first:

```text
primaryCorrect = for expected vulnerable: status valid, disposition vulnerable, correct family,
                 and evidence spans intersect acceptable spans;
                 for expected safe or insufficient_context: status valid and disposition equals expectedDisposition
vulnerableTruePositive = expected vulnerable, status valid, disposition vulnerable,
                         family equals expectedFamily, and evidence spans intersect acceptable spans
predictedVulnerable = status valid and disposition vulnerable
falseSafe = expected vulnerable, status valid, disposition safe
familyHit = expected vulnerable, predicted vulnerable, family equals expectedFamily
spanHit = expected vulnerable, predicted vulnerable, evidence intersects acceptable spans
```

Balanced accuracy is the unweighted mean of the three expected-disposition `primaryCorrect` recalls, so the vulnerable class is correct only with the expected family and an acceptable evidence span. Vulnerability recall is the mean packet true-positive rate over vulnerable packets. Vulnerable precision is the sum of packet true-positive rates divided by the sum of packet predicted-vulnerable rates. Family and span accuracy use the same ratio form over expected-vulnerable predicted-vulnerable rates. Safe specificity is the mean `primaryCorrect` rate over expected-safe packets; insufficient-context recall is the corresponding mean over expected-insufficient-context packets. Return `null` when one of the precision-style denominators is zero; do not invent zero.

For the cross-model selective operating point, `covered` means a valid `vulnerable` or `safe` result; valid `insufficient_context` and every failure are uncovered. Average covered and covered-correct indicators within packet first. `selective.coverage` is the mean packet covered rate, and `selective.accuracy` is the sum of packet covered-correct rates divided by the sum of packet covered rates, or null when coverage is zero. Do not compare frontier verbal confidence with Jev probabilities.

For each Jev atomic Noul, first average available `jevObservation.nouls` probabilities across repetitions within packet, then use only packets whose ledger has an explicit boolean label. Brier score is `mean((packetMeanProbability - Number(label)) ** 2)`. Build ten fixed bins `[0.0,0.1)` through `[0.9,1.0]`; every bin is emitted, with null mean/observed rate and count zero when empty. Frontier `brier` and `calibration` objects remain empty because no equivalent provider probability exists.

Sum every observed usage envelope into `tokenUsage` and report how many attempts have missing usage; never impute missing tokens. Sort receipt latencies and select p50/p95 at indexes `floor((n - 1) * 0.50)` and `floor((n - 1) * 0.95)`. Fully loaded cost per attempt is `providerCost.usd + coldLatencyMs / 3_600_000 * runnerUsdPerHour`; cost per 1,000 is its mean times 1,000. Return inconclusive if any attempt lacks defensible provider cost. Preserve the sorted unique provider provenance strings and the frozen runner rate in either result.

Populate `byCorpus`, `byRepository`, `byTarget`, `byFamily`, `bySeverity`, and `byDisposition` by filtering ledger packet IDs and recomputing only the three fields in `ControlledSliceMetrics`. Family slices use `applicableFamily`, including safe and context-incomplete variants whose output family is correctly null.

- [ ] **Step 6: Implement paired repository bootstrap and four claim decisions**

Define:

```ts
export interface ControlledComparisonInference {
  metric: "balancedAccuracy" | "vulnerabilityRecall";
  frontier: "terra" | "opus";
  estimate: number;
  interval: Interval;
  decision: Decision;
}

export interface ControlledInference {
  comparisons: ControlledComparisonInference[];
  efficiencyComparisons: Array<{
    metric: "cost" | "latency";
    frontier: "terra" | "opus";
    ratio: number | null;
    interval: Interval | null;
    decision: Decision;
  }>;
  primaryDecision: Decision;
}
```

For each of 10,000 draws, sample repository IDs with replacement, concatenate every selected repository's ledger rows and all matching attempts/receipts while preserving multiplicity, recompute metrics, and record Jev minus frontier. Use the existing 5th/95th percentile indexes and `classifyDifference(interval, -0.02)`. Emit comparisons in this order:

```ts
[
  ["balancedAccuracy", "terra"],
  ["vulnerabilityRecall", "terra"],
  ["balancedAccuracy", "opus"],
  ["vulnerabilityRecall", "opus"]
]
```

Return `inconclusive` when ground truth is invalid; otherwise combine only the four quality decisions using the frozen all-supported/any-contradicted rule.

For secondary efficiency comparisons, first average cost across five repetitions within each packet and take median latency across five repetitions within each packet. Average packet values within repository, then compute `mean(Jev repository values) / mean(frontier repository values)`. Bootstrap paired repositories with the same draws. Use `classifyRatio`; return a null ratio/interval and `inconclusive` cost decision when any required charge is unavailable. Efficiency decisions never change `primaryDecision`.

- [ ] **Step 7: Preserve secondary scoring under unambiguous names**

Rename the old entry points and their callers:

```ts
scoreClaims       -> scoreSecondary
bootstrapPrimary -> bootstrapCascade
PrimaryInference -> CascadeInference
```

Keep their calculations and old fixture unchanged. Update existing test names to call the renamed functions.

- [ ] **Step 8: Run all scorer checks and commit**

```bash
npm test
git diff --check
git add src/contracts.ts src/scorer.ts src/scorer.test.ts test/fixtures/controlled-scoring.json
git commit -m "feat: score controlled comparison"
```

Expected: the exact `0.9`, `0.966666…`, and `1.0` fixture values pass; all four non-inferiority boundaries and repository-cluster tests pass.

---

### Task 6: Offline Controlled CLI and End-to-End Fixture

**Files:**
- Modify: `src/cli.ts`
- Create: `src/cli.test.ts`
- Modify: `package.json`
- Create: `test/fixtures/controlled-packets.jsonl`

**Interfaces:**
- Consumes: `runControlledBenchmark`, `scoreControlled`, `bootstrapControlled`, checked-in packets/ledger, and three injected fixture adapters.
- Produces: CLI subcommands `run-controlled-fixture`, `score-controlled`, and `score-secondary`; scripts `test:e2e` and `test:e2e:secondary`.

- [ ] **Step 1: Create the complete offline packet fixture**

Write eighteen packet rows: vulnerable, safe, and context-incomplete evidence for injection, broken access control, and SSRF, with two variants per family/disposition. Every row must pass `buildEvidencePacket`, contain only neutral `sN` spans, and stay below 32,000 canonical evidence bytes. The paired private-style fixture ledger lives inside `src/cli.test.ts`; do not commit expected labels beside the model-visible packet fixture.

- [ ] **Step 2: Write failing subprocess tests proving live calls are unreachable**

```ts
test("controlled fixture completes without reading provider credentials", async () => {
  const ledger = join(root, "ledger.jsonl");
  await writeJsonlExclusive(ledger, fixtureLedger);
  const result = await execCli(["run-controlled-fixture", "--packets", fixture, "--output", output], {
    TYPESAFE_API_KEY: "must-not-be-read",
    ANTHROPIC_API_KEY: "must-not-be-read",
    OPENAI_API_KEY: "must-not-be-read"
  });
  assert.equal(result.code, 0, result.stderr);
  const manifest = JSON.parse(result.stdout);
  assert.equal(manifest.attempts.length, 18 * 3 * 5);
  const scored = await execCli(["score-controlled", "--run", join(output, "run-manifest.jsonl"), "--ledger", ledger, "--output", join(root, "score")], providerEnv);
  assert.equal(scored.code, 0, scored.stderr);
  await stat(join(root, "score", "score.jsonl"));
  await stat(join(root, "score", "inference.jsonl"));
});

test("offline CLI rejects every live evaluator spelling", async () => {
  for (const command of ["run-controlled", "calibrate", "holdout", "smoke"]) {
    const result = await execCli([command, "--live"], providerEnv);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /live model execution is not enabled/);
  }
  assert.equal(await providerCallMarkerExists(), false);
});
```

- [ ] **Step 3: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='controlled fixture|rejects every live' dist/src/cli.test.js
```

Expected: the new subcommands are rejected as unknown and the first test fails.

- [ ] **Step 4: Add only offline subcommands**

Use `node:util.parseArgs`. `run-controlled-fixture` reads packet JSONL, creates three deterministic in-process fixture adapters, executes the frozen schedule with synthetic `runnerUsdPerHour: 0.25`, and prints the manifest. `score-controlled` accepts `--run`, `--ledger`, and `--output`, validates both inputs, rereads and verifies every attempt/receipt hash named by the run manifest, copies `runnerUsdPerHour` into `PrimaryScoreInput`, writes immutable `score.jsonl` and `inference.jsonl`, and prints their hashes. `score-secondary` preserves the old JSON input behavior.

The default branch for `run-controlled`, `calibrate`, `holdout`, and `smoke` must throw before constructing a TypeSafe client or resolving a provider executable:

```ts
throw new Error("live model execution is not enabled; complete the explicit smoke task");
```

- [ ] **Step 5: Replace the primary e2e script and retain the old one explicitly**

Set scripts to:

```json
{
  "test:e2e": "npm run build --silent && node --test --test-name-pattern='controlled fixture completes' dist/src/cli.test.js",
  "test:e2e:secondary": "npm run build --silent && node dist/src/cli.js run --fixture test/fixtures/repository/candidates --evaluator fixture"
}
```

Keep `build`, `test`, `triage`, `check`, `corpus`, and `corpus:test` unchanged.

- [ ] **Step 6: Run offline end-to-end verification and commit**

```bash
npm test
npm run test:e2e
npm run test:e2e:secondary
npm run check
git diff --check
git add src/cli.ts src/cli.test.ts package.json test/fixtures/controlled-packets.jsonl
git commit -m "feat: add unpaid controlled benchmark CLI"
```

Expected: both pipelines pass; no network request, external model process, or provider credential access occurs.

---

### Task 7: Controlled Report and Static Dashboard

**Files:**
- Create: `src/report.ts`
- Create: `src/report.test.ts`
- Create: `dashboard/index.html`
- Create: `dashboard/app.js`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: only validated `ControlledScoreReport`, `ControlledInference`, redacted case records, and frozen run metadata.
- Produces: `renderControlledReport(input): string`, `buildControlledDashboardData(input): ControlledDashboardData`, CLI subcommand `report-controlled`, and a static dashboard that never recalculates metrics.

- [ ] **Step 1: Write failing report-consistency and redaction tests**

```ts
test("report and dashboard use scorer values without recomputation", async () => {
  const score = scoreControlled(fixtureInput);
  const inference = bootstrapControlled(fixtureInput, 100, 7);
  const markdown = renderControlledReport({ score, inference, run: fixtureRun, cases: redactedCases });
  const dashboard = buildControlledDashboardData({ score, inference, run: fixtureRun, cases: redactedCases });
  assert.match(markdown, /Jev vs Terra vs Opus: security-triage decision quality/);
  assert.match(markdown, new RegExp(String(score.evaluators.jev.balancedAccuracy)));
  assert.deepEqual(dashboard.metrics, score.evaluators);
  assert.deepEqual(dashboard.slices, score.slices);
  assert.deepEqual(dashboard.comparisons, inference.comparisons);
  assert.deepEqual(dashboard.terraOpusDescriptive, score.terraOpusDescriptive);
});

test("published artifacts contain no private or credential material", () => {
  const text = JSON.stringify(buildControlledDashboardData(publishableFixture));
  for (const forbidden of ["TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "/Users/", "private/", "reproductionCommand", "reviewerNotes"]) {
    assert.equal(text.includes(forbidden), false);
  }
});
```

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='report and dashboard|private or credential' dist/src/report.test.js
```

Expected: TypeScript fails because `src/report.ts` does not exist.

- [ ] **Step 3: Define one report input and one dashboard-data contract**

```ts
export interface ControlledReportInput {
  score: ControlledScoreReport;
  inference: ControlledInference;
  run: Pick<ControlledRunManifest, "runId" | "startedAt" | "completedAt" | "seed" | "repetitions" | "concurrency" | "timeoutMs" | "maxRetries" | "runnerUsdPerHour" | "instructionSha256" | "schemaSha256" | "scheduleSha256" | "primaryEligible" | "ineligibilityReasons">;
  cases: Array<{
    packetId: string;
    repositoryLabel: string;
    corpus: PrimaryLedgerRow["corpus"];
    applicableFamily: Family;
    expectedDisposition: PrimaryDisposition;
    spans: Array<{ id: string; path: string; startLine: number; endLine: number; text: string }>;
    patchedSpans: Array<{ path: string; startLine: number; endLine: number; text: string }>;
    decisions: Record<PrimaryEvaluator, PrimaryResult[]>;
  }>;
}

export interface ControlledDashboardData {
  title: "Jev vs Terra vs Opus: security-triage decision quality";
  primaryDecision: Decision;
  metrics: ControlledScoreReport["evaluators"];
  slices: ControlledScoreReport["slices"];
  comparisons: ControlledComparisonInference[];
  terraOpusDescriptive: ControlledScoreReport["terraOpusDescriptive"];
  efficiencyComparisons: ControlledInference["efficiencyComparisons"];
  failures: ControlledScoreReport["failures"];
  cases: ControlledReportInput["cases"];
  method: { repetitions: 5; bootstrapDraws: 10000; seed: 20260918; margin: -0.02; concurrency: 1; timeoutMs: number; maxRetries: 0 };
  limitations: string[];
}
```

The limitations array contains these exact statements:

```ts
[
  "The public corpora may have appeared in model training data; the holdout is experiment-untouched, not contamination-free.",
  "Candidate-generation coverage is not part of the primary fixed-packet comparison.",
  "Jev probabilities are not compared with language-model self-reported confidence.",
  "A missing defensible provider charge makes cost inconclusive rather than free.",
  "The controlled Terra arm is ineligible while the available runner cannot prove that shell and retrieval tools are absent."
]
```

- [ ] **Step 4: Render the Markdown report entirely from scorer output**

`renderControlledReport` must include, in order:

1. primary decision, all four non-inferiority comparisons, and descriptive Terra-versus-Opus point differences clearly excluded from the primary decision;
2. evaluator table for balanced accuracy, vulnerability recall/precision, false-safe rate, safe specificity, context recall, family accuracy, span hit rate, and selective coverage/accuracy;
3. valid/timeout/malformed/policy/service rates;
4. observed token totals/missing-usage counts, cost provenance, p50/p95 latency, and paired Jev/frontier cost and latency ratio intervals;
5. corpus, target, family, severity, repository, and disposition slices already present in `ControlledScoreReport`;
6. Jev Brier values and packet-nested calibration bins, plus a statement that frontier confidence is unavailable unless equivalent provider probabilities exist;
7. packet/repository/target counts, five-run nesting, bootstrap method, seed, margin, concurrency, timeout, and zero benchmark-owned retries;
8. limitations and contamination disclosure;
9. a separately titled secondary cascade section that says no secondary result changes the primary claim.

Do not calculate a ratio, mean, interval, decision, or denominator in `report.ts`; format existing fields only.

- [ ] **Step 5: Build the accessible static dashboard without dependencies**

`dashboard/index.html` contains semantic `header`, `main`, `section`, `table`, `caption`, `label`, `select`, and `button` elements; visible focus styles; and reduced-motion CSS. `dashboard/app.js` reads `data.json`, selects the matching precomputed corpus/repository/family/disposition slice, filters case rows only for the explorer, and renders text plus inline SVG bars and a Jev calibration plot directly from scorer-produced bins. It never derives metrics from case rows. Every supported/contradicted/inconclusive mark uses a word and a shape in addition to color.

The page includes:

```html
<h1>Jev vs Terra vs Opus: security-triage decision quality</h1>
<section id="primary-comparisons" aria-labelledby="primary-heading"></section>
<section id="quality-metrics" aria-labelledby="quality-heading"></section>
<section id="jev-calibration" aria-labelledby="calibration-heading"></section>
<section id="failures" aria-labelledby="failure-heading"></section>
<section id="cases" aria-labelledby="cases-heading"></section>
<section id="secondary-cascade" aria-labelledby="secondary-heading"></section>
<section id="method" aria-labelledby="method-heading"></section>
<section id="limitations" aria-labelledby="limitations-heading"></section>
```

Until a separately frozen secondary run exists, the secondary section renders exactly `Secondary cascade not run; no secondary result changes the primary claim.` It must not synthesize a waterfall from primary attempts.

- [ ] **Step 6: Add the offline report command**

`report-controlled` accepts `--score`, `--inference`, `--run`, `--cases`, and `--output`. It validates all inputs, then exclusively writes `report.md`, `data.json`, `index.html`, and `app.js`.

```bash
npm run triage -- report-controlled \
  --score artifacts/controlled-fixture/score.jsonl \
  --inference artifacts/controlled-fixture/inference.jsonl \
  --run artifacts/controlled-fixture/run-manifest.jsonl \
  --cases artifacts/controlled-fixture/cases.jsonl \
  --output artifacts/controlled-dashboard
```

Running it without all five explicit paths exits nonzero and prints the required flags.

Extend the `controlled fixture completes without reading provider credentials` subprocess test from Task 6: write the redacted `fixtureCases` array to a test-owned JSONL file, invoke `report-controlled` on the score/run artifacts created earlier in that test, and assert all four output files exist. `npm run test:e2e` therefore covers scheduling, attempts, receipts, scoring, bootstrap inference, report, and dashboard without a model call.

- [ ] **Step 7: Document the primary/secondary and live-run boundaries**

Extend `README.md` without removing its corpus-preparation commands or limitations. Add exact commands for `npm install`, `npm test`, `npm run test:e2e`, `npm run test:e2e:secondary`, `run-controlled-fixture`, `score-controlled`, and `report-controlled`. State that the old plan is historical, the controlled comparison is primary, cascade/Semgrep/AST analyses are secondary or exploratory, and no live calibration or holdout is permitted while Terra is ineligible.

- [ ] **Step 8: Run report/dashboard verification and commit**

```bash
npm test
npm run test:e2e
npm run check
git diff --check
git add src/report.ts src/report.test.ts dashboard/index.html dashboard/app.js src/cli.ts src/cli.test.ts README.md
git commit -m "feat: report controlled comparison"
```

Expected: all numeric values match scorer output byte-for-byte and no prohibited field reaches published artifacts.

---

### Task 8: Calibration Mapping and Protocol Freeze from Prepared Corpus Artifacts

**Files:**
- Create: `src/calibrate.ts`
- Create: `src/calibrate.test.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: `PublicCalibrationManifest` from `src/split.ts`, `PowerReport` from `src/power.ts`, a completed calibration-only controlled run, its private calibration ledger, the frozen finite threshold grid, and exact public version metadata.
- Produces: `rankPrimaryMappings(rows)`, `selectPrimaryMapping(calibrationInput)`, `buildCalibrationOutcomes(input)`, `createFreezeManifest(input)`, `verifyFreezeManifest(manifest, observed)`, and offline CLI subcommands `select-primary-mapping` and `freeze-primary`.

`src/split.ts`, `src/power.ts`, their tests, `config/corpus-power.json`, and all corpus manifests are owned by `docs/superpowers/plans/2026-09-18-controlled-corpus-preparation.md`. Do not duplicate or modify their algorithms here. Task 8 may start only after that plan's preparation CLI, `PrimaryLedgerRow`-compatible resolved calibration ledger (including severity and independently adjudicated partial `jevExpected` labels), public calibration manifest, sealed-holdout repository counts by family, and power report are implemented and merged.

Implement and test this task only with synthetic calibration fixtures. The documented real commands remain unauthorized while Terra is ineligible; they cannot produce a real selection, power report, or freeze in this plan.

- [ ] **Step 1: Write failing mapping, outcome-export, and freeze-gate tests**

For `rankPrimaryMappings`, give four rows whose `(balancedAccuracy, vulnerabilityRecall, falseSafeRate)` are `(0.90,0.90,0.02)`, `(0.92,0.89,0.01)`, `(0.90,0.90,0.01)`, and `(0.90,0.90,0.01)` with different canonical mapping JSON. Assert ranking maximizes minimum accuracy/recall, then recall, then balanced accuracy, then lower false-safe rate, then lexicographically smaller canonical JSON.

Build one synthetic `PublicCalibrationManifest` whose calibration packet IDs exactly match a fixture controlled run and ledger. Assert `buildCalibrationOutcomes` emits exactly one row per packet/evaluator/repetition, sets failures to both binary outcomes `false`, and defines vulnerable `correctDisposition` and `vulnerableDetected` only when disposition, family, and acceptable span are all correct.

Add freeze tests for these exact rejection cases:

```ts
await assert.rejects(() => createFreezeManifest({ ...input, powerReport: insufficientPower }), /power report is insufficient/);
await assert.rejects(() => createFreezeManifest({ ...input, metadata: codexCliTerra }), /codex-cli-0\.147\.0.*ineligible/);
await assert.rejects(() => createFreezeManifest({ ...input, publicManifest: undersizedHoldout }), /sealed holdout.*power requirement/);
await assert.rejects(() => createFreezeManifest({ ...input, calibrationLedger: ledgerWithHoldoutPacket }), /packet is not in calibration manifest/);
```

- [ ] **Step 2: Run focused tests and verify RED**

```bash
npm run build && node --test --test-name-pattern='mapping selection|calibration outcomes|freeze manifest' dist/src/calibrate.test.js
```

Expected: TypeScript fails because `src/calibrate.ts` does not exist.

- [ ] **Step 3: Validate the corpus-owned calibration boundary**

Parse the imported `PublicCalibrationManifest` and `PowerReport` with their owning modules. Require manifest seed `20260918`, all three calibration families, exactly three calibration packet IDs per target, and no duplicate packet, target, repository, or root-cause ID. Require the controlled run and private calibration ledger to contain exactly the manifest's calibration packet IDs; reject extras and omissions before reading raw responses. Never accept a private holdout manifest or path in either command.

Require `powerReport.split === "calibration"`, margin `-0.02`, seed `20260918`, five repetitions, repository resampling, status `sufficient`, a non-null `requiredRepositoriesPerFamily`, and both true-difference scenarios `0` and `-0.01` with Wilson lower 95% bounds at least `0.8`. For each family, require `publicManifest.sealedHoldout.repositoryCountsByFamily[family] >= powerReport.requiredRepositoriesPerFamily`. This is a read-only gate over artifacts owned by the corpus plan; no split or power calculation belongs in `src/calibrate.ts`.

- [ ] **Step 4: Implement the finite Jev mapping search**

Enumerate exactly:

```ts
const grid = {
  contextMin: [0.6, 0.7, 0.8],
  safeRiskMax: [0.1, 0.2, 0.3],
  vulnerableRiskMin: [0.7, 0.8, 0.9],
  pathMin: [0.6, 0.7, 0.8],
  controlEffectiveMin: [0.7, 0.8, 0.9],
  controlAbsentMax: [0.1, 0.2, 0.3],
  impactMin: [0.6, 0.7, 0.8],
  directExploitabilityMin: [2.0, 2.5]
};
```

Apply every config only to cached raw Jev calibration attempts. For each Jev attempt, parse the canonical state string from its verified raw request artifact with `parseCanonicalEvidenceState`, rebuild the mapping input from `attempt.jevObservation`, and join only to the calibration ledger. Reject any packet ID not listed in `publicManifest.calibration.packetIds`; never open a holdout ledger or holdout request artifact. For each grid point, replace only the Jev `PrimaryResult`, then call `scoreControlled` so selection uses the production full-vulnerable correctness rule.

Rank by descending `min(balancedAccuracy, vulnerabilityRecall)`, descending vulnerability recall, descending balanced accuracy, ascending false-safe rate, then ascending `canonicalJson(config)`. Return the first row and the complete ranking in this artifact:

```ts
export interface PrimaryMappingSelection {
  schemaVersion: 1;
  split: "calibration";
  publicManifestSha256: string;
  controlledRunSha256: string;
  gridSha256: string;
  selected: PrimaryMappingConfig;
  ranking: Array<{ config: PrimaryMappingConfig; balancedAccuracy: number; vulnerabilityRecall: number; falseSafeRate: number }>;
  selectionSha256: string;
}
```

`selectionSha256` hashes canonical JSON without the hash field. Never read, rank, or report a holdout answer.

- [ ] **Step 5: Export corpus-power outcomes from the selected mapping**

Remap Jev attempts with `selection.selected`, leave Terra and Opus unchanged, and emit the corpus-owned `CalibrationOutcome` fields. `correctDisposition` is the same `primaryCorrect` indicator used by Task 5: vulnerable packets require valid vulnerable disposition, correct family, and an acceptable span; safe and insufficient-context packets require their exact valid disposition. `vulnerableDetected` uses that same full-vulnerable condition and is false for all non-vulnerable packets. Preserve all five repetitions and every failure row. Sort by repository group, packet ID, evaluator, and repetition before writing immutable JSONL.

This step exports inputs for `npm run corpus -- power`; it does not implement or call a second bootstrap.

- [ ] **Step 6: Define and hash the freeze manifest**

```ts
export interface PrimaryFreezeMetadata {
  schemaVersion: 1;
  models: { jev: "jev-1.13.0"; terra: string; opus: "claude-opus-4-6" };
  versions: { typesafeSdk: "0.6.0"; terraTransport: string; claudeCode: "2.1.276"; node: string };
  execution: { timeoutMs: number; maxRetries: 0; runnerUsdPerHour: number };
}

export interface PrimaryFreezeManifest {
  schemaVersion: 1;
  models: PrimaryFreezeMetadata["models"];
  versions: PrimaryFreezeMetadata["versions"];
  hashes: {
    packetSchema: string;
    evidenceProjection: string;
    questions: string;
    instruction: string;
    outputSchema: string;
    publicCalibrationManifest: string;
    controlledCalibrationRun: string;
    mappingSelection: string;
    powerReport: string;
    calibrationArtifacts: string;
  };
  mapping: PrimaryMappingConfig;
  execution: { repetitions: 5; concurrency: 1; scheduleSeed: 20260918; bootstrapDraws: 10000; bootstrapSeed: 20260918; margin: -0.02; timeoutMs: number; maxRetries: 0; calibrationStartedAt: string; calibrationCompletedAt: string };
  cost: {
    jevInputUsdPerMillion: 0.042;
    terra: "provider_reported_per_call_charge_required";
    opus: "provider_reported_per_call_charge_required";
    runnerUsdPerHour: number;
  };
  power: {
    status: "sufficient";
    requiredRepositoriesPerFamily: number;
    scenarios: Array<{ trueDifference: 0 | -0.01; estimatedJointPower: number; wilsonLower95: number }>;
  };
  manifestSha256: string;
}
```

Copy `timeoutMs` from metadata only when it equals the controlled calibration run value; copy `runnerUsdPerHour` only when it equals the run value. `manifestSha256` hashes canonical JSON without the hash field. Require a nonempty immutable Terra model ID with no `latest`, `preview`, or unversioned alias token and an eligible controlled Terra transport identifier; reject `codex-cli-0.147.0` explicitly. `verifyFreezeManifest` recomputes every observed version/hash/config value and returns all mismatches in deterministic key order.

Compute each hash from exactly one source:

```ts
packetSchema        = stableHash(canonicalEvidenceSchemaDescriptor);
evidenceProjection = stableHash(canonicalEvidenceProjectionDescriptor);
questions           = stableHash(primaryQuestionDescriptor);
instruction         = sha256(JSON.parse(await readFile("config/controlled-instructions.json", "utf8")).decision);
outputSchema        = stableHash(JSON.parse(await readFile("config/controlled-output.schema.json", "utf8")));
publicCalibrationManifest = stableHash(publicManifest);
controlledCalibrationRun = sha256(await readFile(controlledRunPath));
mappingSelection    = selection.selectionSha256;
powerReport         = stableHash(powerReport);
calibrationArtifacts = stableHash(sortedVerifiedArtifactPathAndSha256Pairs);
```

`sortedVerifiedArtifactPathAndSha256Pairs` contains paths relative to the run directory for every calibration request, response, attempt, and receipt named by the run manifest after their receipt hashes pass. Task 4 computes `instructionSha256` and `schemaSha256` with the same expressions above. `verifyFreezeManifest` recomputes descriptor hashes from imports and content hashes from parsed files; metadata-supplied hashes are comparison values, never trusted replacements.

- [ ] **Step 7: Add offline mapping-selection and freeze CLI commands**

Add these exact offline command shapes to `README.md` and cover them with subprocess tests that create equivalent valid and invalid inputs inside a test-owned temporary directory:

```bash
npm run triage -- select-primary-mapping --manifest artifacts/corpus/calibration-manifest.json --run artifacts/controlled-calibration/run-manifest.jsonl --ledger private/corpus/controlled-calibration-ledger.jsonl --selection artifacts/controlled-calibration/mapping-selection.jsonl --outcomes artifacts/controlled-calibration/power-outcomes.jsonl
npm run corpus -- power --split calibration --manifest artifacts/corpus/calibration-manifest.json --outcomes artifacts/controlled-calibration/power-outcomes.jsonl --config config/corpus-power.json --output artifacts/corpus/power-report.json
npm run triage -- freeze-primary --manifest artifacts/corpus/calibration-manifest.json --run artifacts/controlled-calibration/run-manifest.jsonl --ledger private/corpus/controlled-calibration-ledger.jsonl --selection artifacts/controlled-calibration/mapping-selection.jsonl --power-report artifacts/corpus/power-report.json --metadata private/controlled-versions.json --output private/primary-freeze.json
```

`select-primary-mapping` requires exactly the five option paths shown and verifies all run-artifact hashes before calculating any candidate score. `freeze-primary` requires exactly the seven option paths shown and repeats artifact, manifest, power, mapping, version, and holdout-size verification before its exclusive write. The middle command belongs to the corpus-preparation plan. All three are local calculations; they never construct model clients or invoke executables.

Add subprocess tests proving an insufficient corpus power report, a calibration packet-set mismatch, and `codex-cli-0.147.0` each fail with no selection/freeze output file.

- [ ] **Step 8: Run offline freeze verification and commit**

```bash
npm test
npm run test:e2e
npm run check
git diff --check
git add src/calibrate.ts src/calibrate.test.ts src/cli.ts src/cli.test.ts README.md
git commit -m "feat: freeze controlled benchmark protocol"
```

Expected: synthetic selection, outcome export, imported power gates, and freeze tests pass; no real selection or freeze file is fabricated from incomplete evidence.

---

### Task 9: Explicitly Gated Live Smoke Preflight

**Files:**
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: the production adapter registry, one development-only packet, explicit `--live`, explicit `--output`, and user approval.
- Produces: CLI subcommand `smoke`; with the current runner inventory it exits before all provider calls and writes no partial artifact because Terra is ineligible.

- [ ] **Step 1: Write the failing all-or-nothing smoke test**

```ts
test("live smoke preflight aborts all evaluators when Terra is ineligible", async () => {
  const marker = join(root, "provider-called");
  const result = await execCli([
    "smoke", "--live", "--packets", "test/fixtures/controlled-packets.jsonl", "--packet-index", "0", "--output", join(root, "smoke")
  ], {
    TYPESAFE_API_KEY: "fixture",
    ANTHROPIC_API_KEY: "fixture",
    PROVIDER_CALL_MARKER: marker
  });
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /terra.*codex-cli-0\.147\.0.*ineligible/i);
  await assert.rejects(() => stat(marker), /ENOENT/);
  await assert.rejects(() => stat(join(root, "smoke")), /ENOENT/);
});
```

The injected Jev and Opus adapters create the marker in `evaluate`; the test proves neither is called when Terra fails eligibility.

- [ ] **Step 2: Run the focused test and verify RED**

```bash
npm run build && node --test --test-name-pattern='live smoke preflight aborts' dist/src/cli.test.js
```

Expected: the current CLI says live execution is not enabled, so the test fails to receive the specific all-adapter eligibility error.

- [ ] **Step 3: Add the gated smoke command without weakening eligibility**

Parse these exact required options:

```text
smoke --live --packets test/fixtures/controlled-packets.jsonl --packet-index 0 --output artifacts/smoke-2026-09-18
```

Reject absent `--live`, any `--packets` path whose real path is not the checked-in `test/fixtures/controlled-packets.jsonl`, a packet index other than `0`, or a preexisting output path. Construct adapter capability descriptors without reading credentials, then call `assertAllAdaptersEligible` before creating clients, resolving executables, creating the output directory, or evaluating any packet.

Update Task 6's generic live-command rejection test so its loop remains exactly `run-controlled`, `calibrate`, and `holdout`; `smoke` is now covered by the stricter all-or-nothing test above.

With the installed production adapters, the command must throw:

```text
controlled smoke blocked: terra adapter codex-cli-0.147.0-cannot-disable-shell-and-retrieval-tools is ineligible
```

- [ ] **Step 4: Verify the final gate offline**

```bash
npm test
npm run test:e2e
npm run check
git diff --check
```

Expected: every check passes, and the smoke subprocess proves zero provider invocations and zero partial artifacts.

- [ ] **Step 5: Commit the smoke gate**

```bash
git add src/cli.ts src/cli.test.ts README.md
git commit -m "feat: gate controlled live smoke"
```

- [ ] **Step 6: Run the explicit development smoke preflight only after user approval**

```bash
npm run triage -- smoke \
  --live \
  --packets test/fixtures/controlled-packets.jsonl \
  --packet-index 0 \
  --output artifacts/smoke-2026-09-18
```

Expected with Codex CLI `0.147.0`: exit nonzero with the exact Terra ineligibility message before any paid request; `artifacts/smoke-2026-09-18` does not exist.

This is the terminal state for this plan. Do not run calibration or holdout, and do not call Jev or Opus independently, because doing so would break the paired all-evaluator preflight. A future eligible Terra transport requires a separately reviewed adapter change, its own offline contract tests, and a repeat of this complete smoke task before any calibration call.

---

## Acceptance Matrix

| Revised design requirement | Implemented or enforced by |
| --- | --- |
| Shared three-disposition/five-status record | Task 1 |
| Family nullable outside vulnerable and failures distinct from context abstention | Task 1 |
| Identical canonical model-visible evidence bytes with provenance excluded | Tasks 1, 2, 3, and 4 |
| Jev atomic questions, raw probabilities, supplied-span Choice, pinned model | Task 2 |
| Family-relevant context policy and separate primary mapping | Task 2 |
| No repository, web, shell, or retrieval tools in the primary experiment | Task 3 eligibility plus Task 9 all-adapter gate |
| Current Codex CLI Terra runner fails closed | Tasks 3 and 9 |
| Five seeded interleaved repetitions and one attempt per evaluator/packet | Task 4 |
| Immutable raw requests, responses, attempts, hashes, and durable latency receipts | Task 4 |
| Failures remain in denominators | Tasks 4 and 5 |
| Balanced accuracy, full vulnerable recall/precision, false-safe, context, family, and span metrics | Task 5 |
| Jev Brier scores without LLM confidence comparison | Task 5 |
| Paired repository bootstrap, four non-inferiority comparisons, frozen decision rule | Task 5 |
| Unpaid complete three-family/three-disposition fixture | Task 6 |
| Report/dashboard read scorer results without recalculation | Task 7 |
| Static accessible dashboard and contamination/cost limitations | Task 7 |
| Repository/root-cause split isolation and holdout protection | Corpus-preparation plan, consumed and revalidated in Task 8 |
| Calibration-only deterministic Jev mapping selection | Task 8 |
| Joint power check against actual sealed-holdout size and exact freeze hashes | Corpus-preparation plan plus Task 8 gate |
| No live paid calls before an explicit final smoke | Tasks 1–8 and Task 9 preflight |
| Secondary cascade, Semgrep filtering, and AST yield cannot replace the headline | Global constraints, parked interfaces, Task 7 |

## Explicitly Deferred Secondary Work

The existing agentic cascade, Semgrep false-alert analysis, and validated AST-yield analysis remain compiled and tested but are not modified by this plan. After a valid controlled calibration freeze exists, a separate secondary plan may update `src/router.ts` so only family-relevant unresolved context forces escalation and may execute agentic Terra/Opus arms with identical sanitized snapshots and permissions.

No live calibration, holdout execution, public freeze artifact, or benchmark result is produced while Terra is ineligible. That is an enforced safety outcome, not a missing implementation step.
