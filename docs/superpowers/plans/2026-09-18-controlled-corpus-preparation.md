# Controlled Corpus Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fail-closed, auditable corpus-preparation pipeline that promotes repository-disjoint JavaScript/TypeScript targets into calibration eligibility only after exact metadata, network-disabled reproduction, three blinded packet variants, independent adjudication, deterministic grouping, and prespecified power checks succeed.

**Architecture:** A versioned intake registry records candidates but confers no eligibility. Pure TypeScript validators and small command adapters produce immutable metadata, reproduction, packet, adjudication, split, and power artifacts; private answer-bearing material never enters model-visible packets. The preparation CLI may inspect development and calibration artifacts, but a central run-policy guard rejects every holdout execution request before repository checkout, container startup, or model invocation.

**Tech Stack:** Node.js 24+, TypeScript 5.9.2, Node's built-in test runner, built-in `child_process`, `crypto`, `fs`, and `path` modules, Git, Docker or another OCI-compatible runtime for later validator-controlled reproduction, immutable JSONL artifacts, no new npm dependencies

**Spec:** `docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md`

## Global Constraints

- Implement this plan only after the async preparation branch containing `benchmark/corpus-candidates.json`, `docs/corpus-preparation.md`, and the existing `src/packets.ts` and `src/jsonl.ts` tests is merged into the execution branch.
- Development is exactly the frozen, redacted `owasp/juice-shop` revision. Juice Shop may shape packet construction and dashboard examples, but it may not calibrate mappings, thresholds, abstention policies, routing budgets, or power assumptions.
- Calibration and holdout must be repository-disjoint from Juice Shop and from each other, and root-cause-disjoint from each other.
- The only vulnerability families are `injection`, `broken_access_control`, and `ssrf`.
- Every eligible target has exactly three packet variants: `vulnerable`, `safe`, and `insufficient_context`; all three stay in the same repository/root-cause group and split.
- A patched revision is safe only for the labeled target path. It is not evidence that the whole route, file, or repository is safe.
- Metadata verification and reproduction verification are separate states. Metadata evidence alone never makes a candidate split-eligible.
- Reproduction is non-destructive, credential-free, network-disabled, resource-limited, and run only inside a digest-pinned container. This implementation plan itself must not execute any vulnerable application.
- Model-visible packets exclude repository names, commits, CVE/GHSA IDs, advisories, patches, tests, challenge or solution text, reviewer notes, expected labels, reproduction evidence, and Git history.
- “Not shown” never means “not enforced,” “unsanitized,” or “safe.” Omitting any family-required evidence dimension makes the packet's expected disposition `insufficient_context`.
- Two distinct security reviewers independently adjudicate each packet while blinded to model output. Disagreements require a third review; unresolved packets remain ineligible.
- Repository groups, root-cause groups, and explicit relationship groups are indivisible. The three Rendertron records in the current intake remain one connected group.
- Split construction is deterministic with seed `20260918`. Before allocation, validators may prepare and adjudicate private packets for still-unassigned candidates. After allocation, preparation commands may export calibration packets but must never open sealed holdout packet bodies or invoke holdout evaluators.
- Use five repetitions only in calibration power inputs. Average repetitions within packet before repository aggregation; repeated observations are never independent vulnerabilities.
- Use 10,000 paired repository-clustered percentile-bootstrap draws with seed `20260918` and the frozen non-inferiority margin `-0.02`.
- Power must be adequate before any holdout run. If it is inadequate, recruit more untouched repositories; never widen the margin or move viewed calibration repositories into holdout.
- Keep `private/`, `artifacts/`, `validation/private/`, checkouts, reproduction output, and sealed holdout packet bodies out of Git.
- Use `writeJsonlExclusive` for generated JSONL so reruns cannot overwrite evidence silently.
- All production changes follow RED → verify the expected failure → minimal GREEN → full checks → commit.
- Tasks 1–7 use fixtures, fake process runners, and static files only. Their test commands must not access the network, start Docker, run vulnerable code, or call a model.

## Current Evidence and Recruitment Priorities

The current registry has nine metadata-audited records across seven repository groups: six injection labels and three SSRF labels, with the Rendertron trio sharing one repository and commit pair. It has no broken-access-control target and no reproduction-verified target, so it is neither split-ready nor power-ready.

Recruit and verify in this order:

1. Broken access control: Keystone `CVE-2022-39322` / `GHSA-6mhr-52mv-6v6f`, vulnerable parent `03061416c36e0d97cc5fefc08a29e5e2294af58b`, fixed commit `65c6ee3deef23605fc72b80230908696a7a65e7c`. Confirm the exact target path, exact-revision license, and a credential-free local regression before adding it to the registry.
2. Broken access control: Payload `CVE-2023-30843` / `GHSA-35jj-vqcf-f2jf`. Release commit `a4fd0df69c944a13eec6221f0779ee40bf47cf61` and MIT manifest are leads, not an eligible pair; isolate exact vulnerable and fixed commits first.
3. Broken access control: Clerk `CVE-2024-22206` / `GHSA-q6w5-jg5q-47vg`. Release commit `18aba588b53bf08a339ca890933c1e0b6a88c870` is a lead; exact vulnerable/fixed pairing and a credential-free proof remain blockers.
4. SSRF: Next.js `CVE-2024-34351` / `GHSA-fr5h-rqp8-mj6g`, fixed commit `8f7a6ca7d21a97bc9f7a1bbe10427b5ad74b9085`. Use two loopback services inside the same network-disabled container; no host or Internet connection is allowed.
5. SSRF: Axios `CVE-2024-39338` / `GHSA-8hc4-vh64-cxmj`, upstream fix prefix `6b6b605`. Resolve the full SHA and admit it only if upstream code establishes attacker-controlled input; a synthetic wrapper is not sufficient ground truth.
6. Injection expansion from the pinned OpenSSF snapshot: FlintCMS `CVE-2018-3783`, limdu `CVE-2020-4066`, node-connect-pg-simple `CVE-2019-15658`, and Strapi `CVE-2019-18818`. Each remains an intake lead until exact full commits, target location, license at both revisions, and isolated reproduction are verified.

Do not infer family membership from a broad CWE match. Prototype pollution, path traversal, and XSS records enter this benchmark only when the target behavior satisfies the approved injection definition and reviewers document the source-to-sensitive-operation path.

The pinned OpenSSF snapshot is the primary corpus source, not merely a discovery hint. Before promoting any recruitment lead, verify that its source case exists in the pinned snapshot and that the snapshot's repository and revisions agree with upstream. If a lead is absent or disagrees, leave it `blocked` in `benchmark/corpus-intake.json`; admitting a supplementary source would require an approved spec amendment and a newly pinned source snapshot before split construction.

## File Structure

```text
benchmark/corpus-candidates.json         versioned intake registry; no verification claims
benchmark/corpus-intake.json             blocked recruitment leads and exact blockers
config/corpus-power.json                 frozen power design and simulation grid
src/corpus.ts                            registry contracts, parsing, and eligibility invariants
src/corpus.test.ts                       registry and current-gap tests
src/corpus-metadata.ts                   injected Git runner and metadata evidence generation
src/corpus-metadata.test.ts              fake-Git tests; never accesses a remote
src/reproduction.ts                      hardened OCI command builder and result parser
src/reproduction.test.ts                 fake-runtime safety and promotion tests
src/corpus-packets.ts                    triplet construction and private provenance mapping
src/corpus-packets.test.ts               vulnerable/safe/incomplete and leakage tests
src/packets.ts                           opaque public packet identity
src/packets.test.ts                      canonical identity and provenance-exclusion tests
src/adjudication.ts                      independent-review merge and eligibility resolution
src/adjudication.test.ts                 agreement, third-review, and unresolved tests
src/split.ts                             connected grouping, deterministic allocation, run guard
src/split.test.ts                        disjointness, coverage, determinism, and holdout-denial tests
src/power.ts                             nested aggregation, paired bootstrap, and simulation
src/power.test.ts                        hand-calculated aggregation and power-decision tests
src/corpus-cli.ts                        preparation-only command dispatcher
src/corpus-cli.test.ts                   subprocess tests proving holdout is unreachable
test/fixtures/corpus/registry.json        six-repository, three-family fixture registry
test/fixtures/corpus/git/                static fake Git responses
test/fixtures/corpus/reproduction/       safe fake verdicts and receipts
test/fixtures/corpus/adjudication/        blinded review fixtures
test/fixtures/corpus/calibration.jsonl    five-run calibration fixture
docs/corpus-preparation.md               operator procedure, evidence states, and blockers
.gitignore                               private ledgers, sealed packets, checkouts, receipts
package.json                             preparation scripts only
```

Generated files live below ignored paths:

```text
artifacts/corpus/metadata.jsonl
artifacts/corpus/reproduction.jsonl
artifacts/corpus/calibration-packets.jsonl
artifacts/corpus/calibration-manifest.json
artifacts/corpus/power-report.json
artifacts/corpus/freeze-eligibility.json
private/corpus/provenance.jsonl
private/corpus/preallocation-packets.jsonl
private/corpus/adjudication-draft.jsonl
private/corpus/adjudication-final.jsonl
private/corpus/calibration-ground-truth.jsonl
private/corpus/holdout-manifest.json
private/corpus/holdout-packets.jsonl
private/corpus/holdout-ground-truth.jsonl
validation/private/recipes.jsonl
validation/private/proofs/
```

## Dependency Order

```text
Task 1 registry
  └── Task 2 metadata evidence
        └── Task 3 reproduction evidence
Task 1 ───────────────┐
Task 3 ───────────────┼── Task 4 packet triplets
                      └── Task 5 adjudication
Tasks 1–5 ─────────────── Task 6 grouping and split guard
Tasks 5–6 ─────────────── Task 7 power simulation
Tasks 1–7 ─────────────── Task 8 preparation CLI and operator docs
```

Tasks are sequential because later artifact schemas consume earlier exact names. No task may open or evaluate holdout packet bodies.

---

### Task 1: Version the Intake Registry and Encode Eligibility Invariants

**Files:**
- Modify: `benchmark/corpus-candidates.json`
- Create: `benchmark/corpus-intake.json`
- Create: `src/corpus.ts`
- Create: `src/corpus.test.ts`
- Modify: `docs/corpus-preparation.md`

**Interfaces:**
- Consumes: `Family` from `src/contracts.ts`, the current nine candidates, and OpenSSF snapshot commit `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4`.
- Produces: `CorpusRegistry`, `CorpusCandidate`, `parseCorpusRegistry(value): CorpusRegistry`, `repositorySlug(url): string`, and `assertCorpusShape(registry): void`.

- [ ] **Step 1: Write registry tests that expose the present gaps**

Create `src/corpus.test.ts` with these core cases:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertCorpusShape, parseCorpusRegistry } from "./corpus.js";

test("current intake is versioned, exact, and honestly not split ready", async () => {
  const registry = parseCorpusRegistry(JSON.parse(await readFile("benchmark/corpus-candidates.json", "utf8")));
  assert.equal(registry.schemaVersion, 1);
  assert.equal(registry.developmentRepository, "owasp/juice-shop");
  assert.equal(registry.sourceSnapshots[0]?.commit, "91c59fd54b2b768c0f310bb0027d2ac59cdf74d4");
  assert.equal(registry.candidates.length, 9);
  assert.equal(registry.candidates.some((row) => row.family === "broken_access_control"), false);
  assert.throws(() => assertCorpusShape(registry), /broken_access_control/);
});

test("Rendertron records remain one repository and relationship group", async () => {
  const registry = parseCorpusRegistry(JSON.parse(await readFile("benchmark/corpus-candidates.json", "utf8")));
  const rows = registry.candidates.filter((row) => row.repositoryGroup === "github.com/GoogleChrome/rendertron");
  assert.equal(rows.length, 3);
  assert.deepEqual(new Set(rows.flatMap((row) => row.relationshipGroups)), new Set(["rendertron-16ade320-to-324ac997"]));
});

test("candidate parser rejects abbreviated commits and verification claims", async () => {
  const valid = JSON.parse(await readFile("benchmark/corpus-candidates.json", "utf8"));
  const abbreviated = structuredClone(valid);
  abbreviated.candidates[0].vulnerableCommit = "6b6b605";
  assert.throws(() => parseCorpusRegistry(abbreviated), /40 lowercase hexadecimal/);
  const claimed = structuredClone(valid);
  claimed.candidates[0].verificationStatus = "reproduction_verified";
  assert.throws(() => parseCorpusRegistry(claimed), /unknown field/);
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/corpus.test.js`

Expected: FAIL because `src/corpus.ts` and the versioned registry shape do not exist.

- [ ] **Step 3: Implement the exact registry contract and strict parser**

Create `src/corpus.ts` with these exported shapes and validations:

```ts
import type { Family } from "./contracts.js";

export type CorpusLanguage = "JavaScript" | "TypeScript";
export type IntakeStatus = "queued" | "excluded";

export interface CorpusCandidate {
  candidateId: string;
  sourceCaseId: string;
  repositoryUrl: string;
  repositoryGroup: string;
  rootCauseGroup: string;
  vulnerableCommit: string;
  fixedCommit: string;
  languages: CorpusLanguage[];
  family: Family;
  cwes: string[];
  location: { path: string; startLine: number; endLine: number };
  license: { spdx: string; path: string; evidenceUrl: string };
  sourceUrls: string[];
  relationshipGroups: string[];
  intakeStatus: IntakeStatus;
  exclusionReason: string | null;
}

export interface CorpusRegistry {
  schemaVersion: 1;
  developmentRepository: "owasp/juice-shop";
  sourceSnapshots: Array<{ name: "OpenSSF CVE Benchmark"; commit: string; url: string }>;
  candidates: CorpusCandidate[];
}

export function repositorySlug(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.hostname !== "github.com") throw new Error("repositoryUrl must be HTTPS GitHub");
  return `${parsed.hostname}${parsed.pathname.replace(/\.git$/, "").replace(/\/$/, "")}`;
}

export function assertCorpusShape(registry: CorpusRegistry): void {
  const families = new Set(registry.candidates.filter((row) => row.intakeStatus === "queued").map((row) => row.family));
  for (const family of ["injection", "broken_access_control", "ssrf"] as const) {
    if (!families.has(family)) throw new Error(`missing queued family: ${family}`);
  }
}
```

`parseCorpusRegistry` must reject unknown keys; duplicate `candidateId`; duplicate `(repositoryUrl, sourceCaseId, rootCauseGroup)` tuples; non-HTTPS source URLs; commits that do not match `/^[0-9a-f]{40}$/`; non-normalized relative paths; invalid line ranges; empty CWE, language, source, or relationship arrays; a `repositoryGroup` unequal to `repositorySlug(repositoryUrl)`; and `excluded` rows without a non-empty `exclusionReason`. It must not accept `verificationStatus`, `reproductionCommand`, or `blocker`; verification belongs to generated evidence.

- [ ] **Step 4: Migrate the nine current rows and record blocked leads**

Wrap `benchmark/corpus-candidates.json` in the `CorpusRegistry` object, retain the exact nine full commit pairs and cited URLs, set `intakeStatus: "queued"`, and use stable IDs of the form `ossf-CVE-2020-15152`. Add exact target locations from the pinned OpenSSF record rather than guessing paths or line numbers; if any current row lacks an exact location, set `intakeStatus: "excluded"` with `exclusionReason: "exact target location unresolved at OpenSSF snapshot 91c59fd54b2b768c0f310bb0027d2ac59cdf74d4"`.

Create `benchmark/corpus-intake.json` as a versioned array of the six recruitment leads listed above. Each row must have `leadId`, `family`, `sourceUrls`, `knownCommits`, `requiredChecks`, and `status: "blocked"`. Do not invent a missing full SHA, path, license, or reproducer merely to satisfy the candidate schema.

- [ ] **Step 5: Document the evidence-state boundary**

Update `docs/corpus-preparation.md` to define these exact states:

```text
intake lead -> queued candidate -> metadata_verified -> reproduction_verified
            -> packet_triplet_ready -> adjudication_resolved -> split_eligible
```

State that each arrow requires a new immutable artifact, promotion is monotonic, and a blocked or excluded candidate cannot be silently dropped from the audit log.

- [ ] **Step 6: Run tests and commit**

```bash
npm run check
git diff --check
git add benchmark/corpus-candidates.json benchmark/corpus-intake.json src/corpus.ts src/corpus.test.ts docs/corpus-preparation.md
git commit -m "feat: version corpus intake registry"
```

Expected: all tests pass; the only intentional readiness failure is asserted inside the test because the present registry has no broken-access-control case.

---

### Task 2: Verify Exact Revisions, Target Files, and Licenses Without Running Code

**Files:**
- Create: `src/corpus-metadata.ts`
- Create: `src/corpus-metadata.test.ts`
- Create: `test/fixtures/corpus/git/metadata.json`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `CorpusCandidate`, `canonicalJson`, `stableHash`, and `writeJsonlExclusive`.
- Produces: `CommandRunner`, `MetadataEvidence`, `verifyCandidateMetadata(candidate, checkoutRoot, runner, runDate): Promise<MetadataEvidence>`, and `verifyRegistryMetadata(registry, checkoutRoot, runner, runDate): Promise<MetadataEvidence[]>`.

- [ ] **Step 1: Write fake-runner tests for successful and blocked metadata verification**

Define the fixture and runner at the top of `src/corpus-metadata.test.ts`:

```ts
const checkoutRoot = "/private/tmp/system-one-security-corpus/checkouts";
const candidate: CorpusCandidate = {
  candidateId: "fixture-CVE-2026-0001",
  sourceCaseId: "CVE-2026-0001",
  repositoryUrl: "https://github.com/example/security-fixture.git",
  repositoryGroup: "github.com/example/security-fixture",
  rootCauseGroup: "fixture-authz-root",
  vulnerableCommit: "1111111111111111111111111111111111111111",
  fixedCommit: "2222222222222222222222222222222222222222",
  languages: ["TypeScript"],
  family: "broken_access_control",
  cwes: ["CWE-862"],
  location: { path: "src/route.ts", startLine: 10, endLine: 14 },
  license: { spdx: "MIT", path: "LICENSE", evidenceUrl: "https://github.com/example/security-fixture/blob/2222222222222222222222222222222222222222/LICENSE" },
  sourceUrls: ["https://github.com/example/security-fixture/commit/2222222222222222222222222222222222222222"],
  relationshipGroups: ["fixture-authz-root"],
  intakeStatus: "queued",
  exclusionReason: null
};
const checkout = `${checkoutRoot}/${stableHash(candidate.repositoryGroup)}`;

function scriptedRunner(steps: Array<[string, string[], string?, number?]>): CommandRunner {
  let index = 0;
  return async (file, args) => {
    const [expectedFile, expectedArgs, stdout = "", code = 0] = steps[index++]!;
    assert.equal(file, expectedFile);
    assert.deepEqual(args, expectedArgs);
    return { code, stdout, stderr: code === 0 ? "" : "fixture failure" };
  };
}
```

Define `runnerThatFailsFixedLicense` with the same successful prefix as the first test and a nonzero result for `git show 2222...:LICENSE`; assert that no later command is accepted.

```ts
test("metadata verification proves both commits, both licenses, and a target-changing diff", async () => {
  const runner = scriptedRunner([
    ["git", ["clone", "--filter=blob:none", "--no-checkout", candidate.repositoryUrl, checkout]],
    ["git", ["-C", checkout, "fetch", "--no-tags", "origin", candidate.vulnerableCommit, candidate.fixedCommit]],
    ["git", ["-C", checkout, "cat-file", "-e", `${candidate.vulnerableCommit}^{commit}`]],
    ["git", ["-C", checkout, "cat-file", "-e", `${candidate.fixedCommit}^{commit}`]],
    ["git", ["-C", checkout, "show", `${candidate.vulnerableCommit}:${candidate.location.path}`], "vulnerable source"],
    ["git", ["-C", checkout, "show", `${candidate.fixedCommit}:${candidate.location.path}`], "fixed source"],
    ["git", ["-C", checkout, "show", `${candidate.vulnerableCommit}:${candidate.license.path}`], "MIT license"],
    ["git", ["-C", checkout, "show", `${candidate.fixedCommit}:${candidate.license.path}`], "MIT license"],
    ["git", ["-C", checkout, "diff", "--name-only", candidate.vulnerableCommit, candidate.fixedCommit, "--", candidate.location.path], `${candidate.location.path}\n`]
  ]);
  const evidence = await verifyCandidateMetadata(candidate, "/private/tmp/system-one-security-corpus/checkouts", runner, "2026-09-18");
  assert.equal(evidence.status, "metadata_verified");
  assert.equal(evidence.diffTouchesTarget, true);
  assert.equal(evidence.blockers.length, 0);
});

test("missing fixed-revision license blocks promotion without executing code", async () => {
  const evidence = await verifyCandidateMetadata(candidate, checkoutRoot, runnerThatFailsFixedLicense, "2026-09-18");
  assert.equal(evidence.status, "blocked");
  assert.deepEqual(evidence.blockers, ["license missing at fixed revision"]);
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/corpus-metadata.test.js`

Expected: FAIL because `verifyCandidateMetadata` does not exist.

- [ ] **Step 3: Implement an injected, argv-only Git verifier**

Use these exact interfaces:

```ts
export interface CommandResult { code: number; stdout: string; stderr: string }
export type CommandRunner = (file: string, args: readonly string[], options: { cwd?: string; timeoutMs: number }) => Promise<CommandResult>;

export interface MetadataEvidence {
  schemaVersion: 1;
  candidateId: string;
  runDate: string;
  repositoryGroup: string;
  vulnerableCommit: string;
  fixedCommit: string;
  vulnerableFileSha256: string | null;
  fixedFileSha256: string | null;
  vulnerableLicenseSha256: string | null;
  fixedLicenseSha256: string | null;
  diffTouchesTarget: boolean;
  commandReceiptSha256: string;
  status: "metadata_verified" | "blocked";
  blockers: string[];
}
```

Call only `runner("git", argv, { timeoutMs: 120_000 })`; never use a shell string. Create one checkout directory per `stableHash(repositoryGroup)`. Clone with `git clone --filter=blob:none --no-checkout`, fetch the two exact SHAs, prove each object with `git cat-file -e SHA^{commit}`, read source and license with `git show SHA:path`, and limit the diff to `git diff --name-only vulnerable fixed -- targetPath`. Hash command names, argv, exit codes, and stdout/stderr hashes in the receipt; do not store full source or license contents in the public evidence row.

- [ ] **Step 4: Ignore generated and private material**

Add these exact entries to `.gitignore`:

```gitignore
artifacts/corpus/
private/corpus/
validation/private/
```

The checkout root remains `/private/tmp/system-one-security-corpus/checkouts`, outside the repository.

- [ ] **Step 5: Run tests and commit**

```bash
npm run check
git diff --check
git add .gitignore src/corpus-metadata.ts src/corpus-metadata.test.ts test/fixtures/corpus/git/metadata.json
git commit -m "feat: verify corpus metadata without execution"
```

Expected: fake-runner tests pass, no network call occurs, and failed evidence is returned as `blocked` rather than thrown away.

---

### Task 3: Add Network-Disabled, Digest-Pinned Reproduction Receipts

**Files:**
- Create: `src/reproduction.ts`
- Create: `src/reproduction.test.ts`
- Create: `test/fixtures/corpus/reproduction/vulnerable.json`
- Create: `test/fixtures/corpus/reproduction/fixed.json`
- Create: `validation/README.md`

**Interfaces:**
- Consumes: `MetadataEvidence` with status `metadata_verified` and injected `CommandRunner`.
- Produces: `ReproductionRecipe`, `ReproductionEvidence`, `buildContainerArgs(recipe, revision, paths): string[]`, `parseReproductionVerdict(value, revision)`, and `verifyReproduction(recipe, metadata, paths, runner): Promise<ReproductionEvidence>`.

- [ ] **Step 1: Write safety-boundary and two-revision tests**

Define these fixtures in `src/reproduction.test.ts`:

```ts
const recipe: ReproductionRecipe = {
  schemaVersion: 1,
  candidateId: "fixture-CVE-2026-0001",
  image: `node@sha256:${"a".repeat(64)}`,
  proofPath: "proofs/authz-regression.mjs",
  command: ["node", "/proof/authz-regression.mjs"],
  timeoutMs: 30_000,
  expected: { vulnerable: "vulnerable", fixed: "fixed" }
};
const paths = {
  vulnerableRevision: "/private/tmp/system-one-security-corpus/revisions/vulnerable",
  fixedRevision: "/private/tmp/system-one-security-corpus/revisions/fixed",
  proof: "/private/tmp/system-one-security-corpus/proofs/authz-regression.mjs",
  output: "/private/tmp/system-one-security-corpus/output"
};
const metadata: MetadataEvidence = {
  schemaVersion: 1,
  candidateId: recipe.candidateId,
  runDate: "2026-09-18",
  repositoryGroup: "github.com/example/security-fixture",
  vulnerableCommit: "1111111111111111111111111111111111111111",
  fixedCommit: "2222222222222222222222222222222222222222",
  vulnerableFileSha256: "b".repeat(64),
  fixedFileSha256: "c".repeat(64),
  vulnerableLicenseSha256: "d".repeat(64),
  fixedLicenseSha256: "d".repeat(64),
  diffTouchesTarget: true,
  commandReceiptSha256: "e".repeat(64),
  status: "metadata_verified",
  blockers: []
};
```

`fakeRuntime` must write the supplied canonical verdict to the injected output-file adapter before returning `{ code, stdout: "", stderr: "" }`; `timeoutRunner` throws an error with `code: "ETIMEDOUT"`. Neither helper starts a process.

```ts
test("container args are digest-pinned and deny network, mutation, privilege, and host credentials", () => {
  const args = buildContainerArgs(recipe, "vulnerable", paths);
  assert.deepEqual(args.slice(0, 16), [
    "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g", "--cpus", "1"
  ]);
  assert.equal(args.includes("--user"), true);
  assert.equal(args.includes("65532:65532"), true);
  assert.equal(args.some((arg) => arg.includes("docker.sock") || arg.includes(".env") || arg.includes(".ssh")), false);
  assert.match(args.at(-2)!, /@sha256:[0-9a-f]{64}$/);
});

test("promotion requires vulnerable observed before the fix and fixed observed after it", async () => {
  const evidence = await verifyReproduction(recipe, metadata, paths, fakeRuntime([
    { code: 0, verdict: { observed: "vulnerable" } },
    { code: 0, verdict: { observed: "fixed" } }
  ]));
  assert.equal(evidence.status, "reproduction_verified");
  assert.equal(evidence.vulnerableObserved, true);
  assert.equal(evidence.fixedObserved, true);
});

test("timeouts, outbound-network flags, and ambiguous verdicts block promotion", async () => {
  assert.throws(() => buildContainerArgs({ ...recipe, command: ["curl", "https://example.com"] }, "vulnerable", paths), /network-capable command/);
  const evidence = await verifyReproduction(recipe, metadata, paths, timeoutRunner);
  assert.equal(evidence.status, "blocked");
  assert.deepEqual(evidence.blockers, ["vulnerable revision timed out"]);
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/reproduction.test.js`

Expected: FAIL because the reproduction module does not exist.

- [ ] **Step 3: Implement the exact recipe and evidence contracts**

```ts
export interface ReproductionRecipe {
  schemaVersion: 1;
  candidateId: string;
  image: `${string}@sha256:${string}`;
  proofPath: string;
  command: string[];
  timeoutMs: number;
  expected: { vulnerable: "vulnerable"; fixed: "fixed" };
}

export interface ReproductionEvidence {
  schemaVersion: 1;
  candidateId: string;
  image: string;
  vulnerableCommit: string;
  fixedCommit: string;
  vulnerableObserved: boolean;
  fixedObserved: boolean;
  vulnerableReceiptSha256: string | null;
  fixedReceiptSha256: string | null;
  durationMs: number;
  status: "reproduction_verified" | "blocked";
  blockers: string[];
}
```

Require `timeoutMs` from 1 through 300,000, a normalized relative `proofPath`, a non-empty argv array, and an image matching `/^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/`. Reject command elements containing `curl`, `wget`, `nc`, `ssh`, `/var/run/docker.sock`, `--network`, `host.docker.internal`, absolute host paths, shell operators, or environment expansion. Invoke `docker` through the injected runner with argv; never invoke `/bin/sh`, `bash`, `zsh`, `cmd`, or PowerShell.

Build these exact runtime controls after `run --rm`:

```ts
const revisionPath = revision === "vulnerable" ? paths.vulnerableRevision : paths.fixedRevision;
const mounts = [
  `type=bind,src=${revisionPath},dst=/workspace,readonly`,
  `type=bind,src=${paths.proof},dst=/proof,readonly`,
  `type=bind,src=${paths.output},dst=/output`
];
const controls = [
  "--network", "none", "--read-only", "--cap-drop", "ALL",
  "--security-opt", "no-new-privileges", "--pids-limit", "128",
  "--memory", "1g", "--cpus", "1", "--user", "65532:65532",
  "--mount", mounts[0], "--mount", mounts[1], "--mount", mounts[2],
  "--workdir", "/workspace"
];
```

The private proof writes only `/output/verdict.json` containing exactly `{"observed":"vulnerable"}` or `{"observed":"fixed"}` and exits zero. Hash stdout, stderr, verdict bytes, image digest, argv, commit, exit status, and duration into each receipt. A nonzero exit, timeout, missing verdict, extra verdict key, mismatched observation, or incomplete metadata returns `blocked`.

- [ ] **Step 4: Document safe validator operation without running it**

In `validation/README.md`, state that only a designated validator may create recipes in ignored `validation/private/recipes.jsonl`; recipes must be reviewed before execution; secrets and credentials are forbidden; no vulnerable service may bind to the host; internal loopback services for SSRF must run within the same `--network none` container; outputs are hashes and booleans, not payloads or exploit logs.

- [ ] **Step 5: Run fixture tests and commit**

```bash
npm run check
git diff --check
git add src/reproduction.ts src/reproduction.test.ts test/fixtures/corpus/reproduction/vulnerable.json test/fixtures/corpus/reproduction/fixed.json validation/README.md
git commit -m "feat: gate corpus on isolated reproduction"
```

Expected: all tests pass using the fake runner; neither Docker nor vulnerable code starts.

---

### Task 4: Build Redacted Vulnerable, Safe, and Insufficient-Context Packet Triplets

**Files:**
- Modify: `src/packets.ts`
- Modify: `src/packets.test.ts`
- Create: `src/corpus-packets.ts`
- Create: `src/corpus-packets.test.ts`
- Modify: `src/jev.test.ts`
- Modify: `src/router.test.ts`
- Modify: `src/discover.test.ts`

**Interfaces:**
- Consumes: `CorpusCandidate`, `MetadataEvidence`, `ReproductionEvidence`, `PacketCandidate`, `EvidencePacket`, and `writeJsonlExclusive`.
- Produces: opaque `EvidencePacket.sourceRef`, `PacketRecipe`, `PrivatePacketLedgerRow`, `requiredContextForFamily(family)`, and `buildPacketTriplet(recipe): { packets: EvidencePacket[]; ledger: PrivatePacketLedgerRow[] }`.

- [ ] **Step 1: Write failing packet-privacy and triplet tests**

Use these local factories so every assertion has a concrete packet:

```ts
const resolvedContext: ContextResolution = {
  middleware: "resolved",
  upstreamDataFlow: "resolved",
  sanitizers: "resolved",
  authorization: "resolved",
  callPath: "resolved"
};

function packetCandidate(sourceRef: string, commit: string, text: string, contextResolution = resolvedContext): PacketCandidate {
  return {
    sourceRef,
    repositoryId: "example/repository",
    commit,
    sources: ["ast"],
    entryKind: "route",
    primarySpan: { path: "src/route.ts", startLine: 10, endLine: 10, text },
    relatedSpans: [{ path: "src/policy.ts", startLine: 2, endLine: 4, text: "export const canRead = actor.id === ownerId;", relationship: "guards" }],
    contextResolution
  };
}

function packetRecipe(): PacketRecipe {
  return {
    targetId: "target-authz-1",
    candidateId: "fixture-CVE-2026-0001",
    repositoryGroup: "github.com/example/security-fixture",
    rootCauseGroup: "fixture-authz-root",
    family: "broken_access_control",
    vulnerableCandidate: packetCandidate("src_111111111111111111111111", "1".repeat(40), "return db.read(req.params.id);"),
    safeCandidate: packetCandidate("src_222222222222222222222222", "2".repeat(40), "if (!canRead) throw forbidden(); return db.read(req.params.id);"),
    incompleteCandidate: packetCandidate("src_333333333333333333333333", "1".repeat(40), "return db.read(req.params.id);", { ...resolvedContext, authorization: "unresolved" }),
    omittedContext: ["authorization"],
    acceptableEvidenceByDisposition: {
      vulnerable: ["s1"],
      safe: ["s1", "s2"],
      insufficient_context: []
    }
  };
}
```

```ts
test("public packets carry opaque source references and no repository provenance", () => {
  const packet = buildEvidencePacket(packetCandidate("src_111111111111111111111111", "1".repeat(40), "return db.read(req.params.id);"), 0);
  assert.match(packet.sourceRef, /^src_[0-9a-f]{24}$/);
  const bytes = canonicalJson(packet);
  assert.equal(bytes.includes("example/repository"), false);
  assert.equal(bytes.includes("0123456789abcdef"), false);
  assert.equal("repositoryId" in packet, false);
  assert.equal("commit" in packet, false);
});

test("one verified target creates exactly one packet per disposition", () => {
  const result = buildPacketTriplet(packetRecipe());
  assert.deepEqual(result.ledger.map((row) => row.expectedDisposition).sort(), ["insufficient_context", "safe", "vulnerable"]);
  assert.equal(new Set(result.ledger.map((row) => row.repositoryGroup)).size, 1);
  assert.equal(new Set(result.ledger.map((row) => row.rootCauseGroup)).size, 1);
});

test("incomplete packet omits a required dimension instead of asserting a negative", () => {
  const result = buildPacketTriplet(packetRecipe());
  const row = result.ledger.find((item) => item.expectedDisposition === "insufficient_context")!;
  const packet = result.packets.find((item) => item.packetId === row.packetId)!;
  assert.equal(row.omittedContext.length > 0, true);
  for (const key of row.omittedContext) assert.equal(packet.contextResolution[key], "unresolved");
});
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm run build && node --test dist/src/packets.test.js dist/src/corpus-packets.test.js`

Expected: FAIL because packets still expose repository and commit and triplet construction is absent.

- [ ] **Step 3: Replace public provenance with an opaque source reference**

Change `PacketCandidate` to keep private construction provenance but change `EvidencePacket` to:

```ts
export interface EvidencePacket {
  schemaVersion: 1;
  packetId: string;
  sourceRef: string;
  candidateSources: CandidateSource[];
  entryKind: EntryKind;
  spans: Array<{ id: string; path: string; startLine: number; endLine: number; text: string }>;
  relationships: Array<{ from: string; to: string; kind: RelationshipKind }>;
  contextResolution: ContextResolution;
}
```

Add a validated `sourceRef` field to private `PacketCandidate`; it must match `/^src_[0-9a-f]{24}$/`. Generate it once with `src_${randomBytes(12).toString("hex")}` when the private recipe is frozen, store it in the private provenance ledger, and reuse it for the packet variant. Do not derive it from repository, commit, CVE, or target identity. Compute `packetId` from the complete public state. Repository ID and commit remain only in the private ledger. Reject CVE/GHSA identifiers and answer-bearing names in packet paths or annotations; retain literal program source needed for evaluation rather than rejecting ordinary source identifiers that happen to contain words such as `fixed`. Update all existing packet fixtures and call sites to use fixed fixture `sourceRef` values; do not weaken existing 32,000-byte, path, line, and canonicalization checks.

- [ ] **Step 4: Implement family-required context and triplet construction**

```ts
export type CorpusDisposition = "vulnerable" | "safe" | "insufficient_context";
export type ContextKey = keyof ContextResolution;

export interface PacketRecipe {
  targetId: string;
  candidateId: string;
  repositoryGroup: string;
  rootCauseGroup: string;
  family: Family;
  vulnerableCandidate: PacketCandidate;
  safeCandidate: PacketCandidate;
  incompleteCandidate: PacketCandidate;
  omittedContext: ContextKey[];
  acceptableEvidenceByDisposition: Record<CorpusDisposition, string[]>;
}

export interface PrivatePacketLedgerRow {
  schemaVersion: 1;
  packetId: string;
  targetId: string;
  candidateId: string;
  repositoryGroup: string;
  rootCauseGroup: string;
  expectedDisposition: CorpusDisposition;
  applicableFamily: Family;
  sourceRevision: "vulnerable" | "fixed";
  omittedContext: ContextKey[];
  acceptableEvidenceSpanIds: string[];
}

export function requiredContextForFamily(family: Family): readonly ContextKey[] {
  return family === "broken_access_control"
    ? ["middleware", "authorization", "callPath"]
    : ["upstreamDataFlow", "sanitizers", "callPath"];
}
```

`buildPacketTriplet` must require metadata and reproduction verification before it is called at the CLI boundary. The vulnerable packet uses vulnerable-revision source; the safe packet uses fixed-revision source and is labeled safe only for this target; the incomplete packet uses the vulnerable revision but physically excludes at least one required evidence span and marks each omitted dimension unresolved. Reject recipes where the incomplete packet resolves every required dimension, where the safe and vulnerable public packet bytes match, where any packet contains expected labels, or where target/group identity differs across variants.

- [ ] **Step 5: Update dependent fixture tests and run the suite**

Update `src/jev.test.ts`, `src/router.test.ts`, and `src/discover.test.ts` only where their fixture constructors still expect public `repositoryId` or `commit`. Then run:

```bash
npm run check
git diff --check
```

Expected: all prior packet, Jev, router, and discovery behavior passes with opaque public identity.

- [ ] **Step 6: Commit**

```bash
git add src/packets.ts src/packets.test.ts src/corpus-packets.ts src/corpus-packets.test.ts src/jev.test.ts src/router.test.ts src/discover.test.ts
git commit -m "feat: build redacted corpus packet triplets"
```

---

### Task 5: Freeze Blinded Independent Adjudication and Private Ground Truth

**Files:**
- Create: `src/adjudication.ts`
- Create: `src/adjudication.test.ts`
- Create: `test/fixtures/corpus/adjudication/reviews.jsonl`

**Interfaces:**
- Consumes: `PrivatePacketLedgerRow` and the three exact dispositions.
- Produces: `AdjudicationReview`, `ResolvedGroundTruth`, `repositoryIdFromGroup(repositoryGroup)`, `rootCauseIdFromGroup(rootCauseGroup)`, `mergeAdjudications(draft, reviews)`, `toPrimaryLedgerRow(resolved, corpus)`, and `assertReviewBlinding(review)`.

- [ ] **Step 1: Write agreement, third-review, and unresolved tests**

Use this exact private draft and helper:

```ts
const draft: PrivatePacketLedgerRow = {
  schemaVersion: 1,
  packetId: "a".repeat(64),
  targetId: "target-authz-1",
  candidateId: "fixture-CVE-2026-0001",
  repositoryGroup: "github.com/example/security-fixture",
  rootCauseGroup: "fixture-authz-root",
  expectedDisposition: "vulnerable",
  applicableFamily: "broken_access_control",
  sourceRevision: "vulnerable",
  omittedContext: [],
  acceptableEvidenceSpanIds: ["s1"]
};

function review(reviewerId: string, disposition: CorpusDisposition): AdjudicationReview {
  return {
    schemaVersion: 1,
    packetId: draft.packetId,
    reviewerId,
    disposition,
    applicableFamily: "broken_access_control",
    acceptableEvidenceSpanIds: disposition === "vulnerable" ? ["s1"] : [],
    severity: "high",
    jevExpected: {
      untrusted_influence: true,
      crosses_authorization_boundary: true,
      authorization_enforced: false,
      enough_context: true
    },
    verdict: "resolved",
    reviewedPacketSha256: "b".repeat(64)
  };
}
```

```ts
test("two matching independent reviewers resolve one packet", () => {
  const result = mergeAdjudications([draft], [review("reviewer-a", "vulnerable"), review("reviewer-b", "vulnerable")]);
  assert.equal(result.resolved.length, 1);
  assert.equal(result.needsThirdReview.length, 0);
  assert.equal(result.unresolved.length, 0);
});

test("disagreement requires a distinct third reviewer and majority agreement", () => {
  const initial = [review("reviewer-a", "vulnerable"), review("reviewer-b", "insufficient_context")];
  const first = mergeAdjudications([draft], initial);
  assert.deepEqual(first.needsThirdReview, [draft.packetId]);
  const resolved = mergeAdjudications([draft], [...initial, review("reviewer-c", "vulnerable")]);
  assert.equal(resolved.resolved[0]?.expectedDisposition, "vulnerable");
});

test("unresolved packets never become eligible", () => {
  const result = mergeAdjudications([draft], [review("reviewer-a", "vulnerable"), review("reviewer-b", "safe"), review("reviewer-c", "insufficient_context")]);
  assert.deepEqual(result.unresolved, [draft.packetId]);
  assert.equal(result.resolved.length, 0);
});

test("opaque repository and root-cause IDs are deterministic and primary-ledger compatible", () => {
  assert.equal(repositoryIdFromGroup(draft.repositoryGroup), repositoryIdFromGroup(draft.repositoryGroup));
  assert.equal(rootCauseIdFromGroup(draft.rootCauseGroup), rootCauseIdFromGroup(draft.rootCauseGroup));
  assert.match(repositoryIdFromGroup(draft.repositoryGroup), /^repo_[0-9a-f]{24}$/);
  assert.match(rootCauseIdFromGroup(draft.rootCauseGroup), /^root_[0-9a-f]{24}$/);
  const resolved = mergeAdjudications([draft], [review("reviewer-a", "vulnerable"), review("reviewer-b", "vulnerable")]).resolved[0]!;
  const primary = toPrimaryLedgerRow(resolved, "calibration");
  assert.equal(primary.repositoryId, repositoryIdFromGroup(draft.repositoryGroup));
  assert.equal(primary.rootCauseId, rootCauseIdFromGroup(draft.rootCauseGroup));
  assert.equal(primary.expectedFamily, "broken_access_control");
  assert.equal(primary.severity, "high");
  assert.deepEqual(primary.jevExpected, {
    authorization_enforced: false,
    crosses_authorization_boundary: true,
    enough_context: true,
    untrusted_influence: true
  });
});

test("Jev atomic labels require two matching explicit reviewer labels", () => {
  const first = review("reviewer-a", "vulnerable");
  const second = { ...review("reviewer-b", "vulnerable"), jevExpected: { untrusted_influence: true } };
  const resolved = mergeAdjudications([draft], [first, second]).resolved[0]!;
  assert.deepEqual(resolved.jevExpected, { untrusted_influence: true });
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/adjudication.test.js`

Expected: FAIL because adjudication contracts are absent.

- [ ] **Step 3: Implement exact blinded-review contracts**

```ts
export interface AdjudicationReview {
  schemaVersion: 1;
  packetId: string;
  reviewerId: string;
  disposition: CorpusDisposition;
  applicableFamily: Family;
  acceptableEvidenceSpanIds: string[];
  severity: "low" | "medium" | "high" | "critical";
  jevExpected: Partial<Record<JevBinaryQuestionId, boolean>>;
  verdict: "resolved" | "unresolved";
  reviewedPacketSha256: string;
}

export interface ResolvedGroundTruth {
  schemaVersion: 1;
  packetId: string;
  targetId: string;
  repositoryId: string;
  rootCauseId: string;
  repositoryGroup: string;
  rootCauseGroup: string;
  expectedDisposition: CorpusDisposition;
  applicableFamily: Family;
  expectedFamily: Family | null;
  acceptableEvidenceSpanIds: string[];
  severity: "low" | "medium" | "high" | "critical";
  jevExpected: Partial<Record<JevBinaryQuestionId, boolean>>;
  reviewerIds: string[];
  provenanceHash: string;
}

export interface PrimaryLedgerCompatibleRow {
  packetId: string;
  targetId: string;
  rootCauseId: string;
  repositoryId: string;
  corpus: "development" | "calibration" | "holdout";
  applicableFamily: Family;
  expectedDisposition: CorpusDisposition;
  expectedFamily: Family | null;
  acceptableEvidenceSpanIds: string[];
  severity: "low" | "medium" | "high" | "critical";
  jevExpected: Partial<Record<JevBinaryQuestionId, boolean>>;
}
```

Define `JevBinaryQuestionId` as `Exclude<keyof JevAnswers, "exploitability">`, using the existing `JevAnswers` contract. Require exactly two distinct initial reviewers. Core agreement means exact equality of disposition, applicable family, severity, sorted unique acceptable span IDs, `verdict: "resolved"`, and reviewed packet hash. On core disagreement, accept exactly one distinct third reviewer and resolve only when two reviews agree exactly; otherwise mark the packet unresolved. Vulnerable ground truth requires at least one acceptable span; safe and insufficient-context ground truth uses `expectedFamily: null` and may use an empty span list.

Atomic Jev labels are optional and never determine packet eligibility. For each `JevBinaryQuestionId`, include a label in final `jevExpected` only when at least two distinct reviewers explicitly supplied the same boolean. Omit a label when fewer than two reviewers supplied it or when explicit values conflict; never infer it from the packet disposition. Sort the resulting object keys before hashing. Reject review objects containing model name, model output, prediction, confidence, CVE/GHSA ID, pre-filled labels from the private draft, repository, commit, advisory, patch, reproduction, or private-ledger fields. Reviewer-entered `disposition`, `applicableFamily`, `severity`, acceptable spans, and optional `jevExpected` are the only ground-truth labels permitted in the review artifact.

Map private grouping keys deterministically and structurally project the resolved row for the controlled scorer:

```ts
export function repositoryIdFromGroup(repositoryGroup: string): string {
  return `repo_${stableHash({ repositoryGroup }).slice(0, 24)}`;
}

export function rootCauseIdFromGroup(rootCauseGroup: string): string {
  return `root_${stableHash({ rootCauseGroup }).slice(0, 24)}`;
}

export function toPrimaryLedgerRow(row: ResolvedGroundTruth, corpus: PrimaryLedgerCompatibleRow["corpus"]): PrimaryLedgerCompatibleRow {
  return {
    packetId: row.packetId,
    targetId: row.targetId,
    rootCauseId: row.rootCauseId,
    repositoryId: row.repositoryId,
    corpus,
    applicableFamily: row.applicableFamily,
    expectedDisposition: row.expectedDisposition,
    expectedFamily: row.expectedFamily,
    acceptableEvidenceSpanIds: [...row.acceptableEvidenceSpanIds],
    severity: row.severity,
    jevExpected: { ...row.jevExpected }
  };
}
```

`mergeAdjudications` must set `repositoryId = repositoryIdFromGroup(repositoryGroup)` and `rootCauseId = rootCauseIdFromGroup(rootCauseGroup)`. This makes the resolved artifact structurally identical to the controlled plan's `PrimaryLedgerRow` after adding the split's `corpus` field; no relabeling or model-dependent transformation is allowed.

- [ ] **Step 4: Preserve blinding and randomized order**

Add `orderPacketsForReview(packetIds, reviewerId, seed = 20260918)` that sorts by `stableHash({ seed, reviewerId, packetId })`. Each reviewer sees only packet ID, canonical packet bytes, the disposition definitions, family definitions, severity rubric, Jev atomic-question definitions, and neutral span IDs. They do not see another review, the private draft label, provenance, split, or evaluator output.

Real review inputs and outputs live only in ignored `validation/private/` and `private/corpus/`. The checked-in `test/fixtures/corpus/adjudication/reviews.jsonl` contains synthetic fixture IDs and source snippets only; never copy a real adjudication record, `jevExpected` label, or reviewer ID into a public artifact.

- [ ] **Step 5: Run tests and commit**

```bash
npm run check
git diff --check
git add src/adjudication.ts src/adjudication.test.ts test/fixtures/corpus/adjudication/reviews.jsonl
git commit -m "feat: resolve blinded corpus adjudication"
```

Expected: all tests pass and unresolved cases remain visible but ineligible.

---

### Task 6: Form Indivisible Groups, Allocate Calibration Deterministically, and Deny Holdout Runs

**Files:**
- Create: `src/split.ts`
- Create: `src/split.test.ts`
- Create: `test/fixtures/corpus/registry.json`

**Interfaces:**
- Consumes: registry, metadata evidence, reproduction evidence, packet ledgers, and resolved ground truth.
- Produces: `EligibleTarget`, `EligibilityAudit`, `PrivateSplitManifest`, `PublicCalibrationManifest`, `collectEligibleTargets(inputs): EligibilityAudit`, `connectedGroups(targets)`, `buildSplit(targets, seed, calibrationShare)`, `redactSplitManifest(manifest): PublicCalibrationManifest`, and `assertPreparationRunAllowed(split)`.

- [ ] **Step 1: Write eligibility, grouping, coverage, and run-policy tests**

```ts
const fixture = JSON.parse(await readFile("test/fixtures/corpus/registry.json", "utf8")) as {
  completeInputs: EligibilityInputs;
  rendertronAndIndependentTargets: EligibleTarget[];
  sixRepositoryTargets: EligibleTarget[];
};

test("eligibility requires every gate and exactly one packet per disposition", () => {
  assert.deepEqual(collectEligibleTargets(fixture.completeInputs).eligible.map((row) => row.targetId), ["target-1"]);
  assert.deepEqual(collectEligibleTargets({ ...fixture.completeInputs, reproduction: [] }).eligible, []);
  assert.deepEqual(collectEligibleTargets({ ...fixture.completeInputs, resolvedGroundTruth: [] }).eligible, []);
});

test("repository, root-cause, and relationship links form indivisible components", () => {
  const groups = connectedGroups(fixture.rendertronAndIndependentTargets);
  assert.deepEqual(groups.find((group) => group.targetIds.includes("rendertron-18352"))?.targetIds.sort(), ["rendertron-18352", "rendertron-18353", "rendertron-18354"]);
});

test("split is deterministic, repository-disjoint, root-cause-disjoint, and covers all families", () => {
  const first = buildSplit(fixture.sixRepositoryTargets, 20260918, 0.4);
  const second = buildSplit([...fixture.sixRepositoryTargets].reverse(), 20260918, 0.4);
  assert.deepEqual(first, second);
  assert.equal(first.calibration.repositoryGroups.some((id) => first.holdout.repositoryGroups.includes(id)), false);
  assert.deepEqual(new Set(first.calibration.families), new Set(["injection", "broken_access_control", "ssrf"]));
  assert.deepEqual(new Set(first.holdout.families), new Set(["injection", "broken_access_control", "ssrf"]));
});

test("public manifest exposes sealed holdout repository capacity by family without identities", () => {
  const privateManifest = buildSplit(fixture.sixRepositoryTargets, 20260918, 0.4);
  const publicManifest = redactSplitManifest(privateManifest);
  assert.deepEqual(publicManifest.sealedHoldout.repositoryCountsByFamily, {
    injection: 1,
    broken_access_control: 1,
    ssrf: 1
  });
  assert.equal(JSON.stringify(publicManifest).includes(privateManifest.holdout.repositoryGroups[0]!), false);
  assert.equal("targetIds" in publicManifest.sealedHoldout, false);
  assert.equal("packetIds" in publicManifest.sealedHoldout, false);
});

test("preparation commands categorically deny holdout execution", () => {
  assert.doesNotThrow(() => assertPreparationRunAllowed("development"));
  assert.doesNotThrow(() => assertPreparationRunAllowed("calibration"));
  assert.throws(() => assertPreparationRunAllowed("holdout"), /holdout execution is prohibited/);
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/split.test.js`

Expected: FAIL because split and run-policy functions do not exist.

- [ ] **Step 3: Implement exact eligibility and manifest types**

```ts
export type CorpusSplit = "development" | "calibration" | "holdout";

export interface EligibilityInputs {
  registry: CorpusRegistry;
  metadata: MetadataEvidence[];
  reproduction: ReproductionEvidence[];
  packetLedger: PrivatePacketLedgerRow[];
  resolvedGroundTruth: ResolvedGroundTruth[];
}

export interface EligibleTarget {
  targetId: string;
  candidateId: string;
  repositoryGroup: string;
  rootCauseGroup: string;
  relationshipGroups: string[];
  family: Family;
  packetIds: { vulnerable: string; safe: string; insufficient_context: string };
}

export interface EligibilityAudit {
  eligible: EligibleTarget[];
  excluded: Array<{ targetId: string; reasons: string[] }>;
}

export interface PrivateSplitManifest {
  schemaVersion: 1;
  seed: 20260918;
  development: { repositoryGroups: ["owasp/juice-shop"] };
  calibration: { repositoryGroups: string[]; rootCauseGroups: string[]; targetIds: string[]; packetIds: string[]; families: Family[] };
  holdout: { repositoryGroups: string[]; rootCauseGroups: string[]; targetIds: string[]; packetIds: string[]; families: Family[] };
  manifestHash: string;
}

export interface PublicCalibrationManifest {
  schemaVersion: 1;
  seed: 20260918;
  development: { repositoryGroups: ["owasp/juice-shop"] };
  calibration: { repositoryIds: string[]; rootCauseIds: string[]; targetIds: string[]; packetIds: string[]; families: Family[] };
  sealedHoldout: {
    manifestHash: string;
    repositoryCount: number;
    targetCount: number;
    packetCount: number;
    targetCountsByFamily: Record<Family, number>;
    repositoryCountsByFamily: Record<Family, number>;
  };
}
```

`collectEligibleTargets` requires: queued candidate; metadata status `metadata_verified`; reproduction status `reproduction_verified`; exactly three packet rows; one resolved adjudication per packet; exact vulnerable/safe/insufficient-context set; matching repository and root-cause identity; and no unresolved review. It returns an audit object with `eligible` and `excluded`, where every exclusion has explicit gate reasons.

Build `test/fixtures/corpus/registry.json` with `completeInputs` containing one fully matched target named `target-1`; removing its `reproduction` or `resolvedGroundTruth` arrays must produce no eligible target. Its `rendertronAndIndependentTargets` array contains the three Rendertron target IDs sharing repository and relationship groups plus one independent target. Its `sixRepositoryTargets` array contains six targets: two repositories per family, each with distinct repository/root-cause/relationship groups and the exact three packet IDs `-vulnerable`, `-safe`, and `-insufficient-context`. Validate this fixture through the same production parsers before using it in assertions.

- [ ] **Step 4: Implement connected components and deterministic allocation**

Build an undirected union-find graph. Union targets sharing `repositoryGroup`, `rootCauseGroup`, or any `relationshipGroup`. Treat each connected component as one allocation unit. Reject the entire registry if fewer than two distinct components contain any required family, because both calibration and holdout must represent all three families.

Allocate components with deterministic dynamic programming over `(index, calibrationFamilyMask, holdoutFamilyMask, calibrationPacketCount)`. Choose only states where both masks equal `0b111`. Minimize absolute distance between the calibration packet fraction and `0.4`; break ties by lexicographically comparing component IDs sorted by `stableHash({ seed, componentId })`. Sort every emitted array before hashing the manifest.

Write `PublicCalibrationManifest` to `artifacts/corpus/calibration-manifest.json` without holdout packet IDs or target IDs. Its calibration arrays use `repositoryIdFromGroup` and `rootCauseIdFromGroup`; raw groups remain only in the private manifest. Copy only the calibration packet bodies from ignored `private/corpus/preallocation-packets.jsonl` to `artifacts/corpus/calibration-packets.jsonl`. Project calibration `ResolvedGroundTruth` rows through `toPrimaryLedgerRow(row, "calibration")` and write them only to ignored `private/corpus/calibration-ground-truth.jsonl`. Write the complete `PrivateSplitManifest`, selected holdout packet bodies, and `toPrimaryLedgerRow(row, "holdout")` rows only to ignored `private/corpus/holdout-manifest.json`, `private/corpus/holdout-packets.jsonl`, and `private/corpus/holdout-ground-truth.jsonl`. The public manifest contains the hash of the private manifest plus total counts, target counts per family, and repository counts per family, never bodies, holdout identities, expected labels, severity, acceptable spans, or `jevExpected`. Count one holdout repository in every family for which it contains at least one eligible target, but count it at most once within that family even when it contains several targets. Once this write succeeds, no corpus-preparation command may read either sealed holdout JSONL file.

- [ ] **Step 5: Centralize the holdout prohibition**

```ts
export function assertPreparationRunAllowed(split: CorpusSplit): void {
  if (split === "holdout") throw new Error("holdout execution is prohibited during corpus preparation");
}
```

Every CLI path that reads packet bodies, starts a container, or invokes an evaluator must call this function before resolving an input path or constructing a process runner. No `--allow-holdout`, environment variable, hidden command, or force option exists.

- [ ] **Step 6: Run tests and commit**

```bash
npm run check
git diff --check
git add src/split.ts src/split.test.ts test/fixtures/corpus/registry.json
git commit -m "feat: freeze grouped corpus allocation"
```

Expected: all tests pass; current real intake remains ineligible, while the synthetic six-repository fixture proves allocation logic.

---

### Task 7: Simulate Joint Non-Inferiority Power With Nested Repetitions

**Files:**
- Create: `config/corpus-power.json`
- Create: `src/power.ts`
- Create: `src/power.test.ts`
- Create: `test/fixtures/corpus/calibration.jsonl`

**Interfaces:**
- Consumes: calibration-only split manifest and five-run Jev/Terra/Opus outcomes.
- Produces: `PowerConfig`, `CalibrationPrediction`, `CalibrationOutcome`, `scoreCalibrationPrediction(prediction)`, `aggregateCalibration(outcomes)`, `pairedRepositoryBootstrap(aggregates, config)`, `simulatePower(aggregates, config)`, `assessFreezeEligibility(manifest, report)`, `FreezeEligibility`, and `PowerReport`.

- [ ] **Step 1: Freeze the power configuration**

Create `config/corpus-power.json` with exactly:

```json
{
  "schemaVersion": 1,
  "margin": -0.02,
  "alpha": 0.05,
  "targetJointPower": 0.8,
  "outerSimulations": 1000,
  "bootstrapDraws": 10000,
  "seed": 20260918,
  "trueDifferenceScenarios": [0, -0.01],
  "candidateRepositoriesPerFamily": [2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 40, 60, 80, 120]
}
```

- [ ] **Step 2: Write hand-calculated nesting and decision tests**

```ts
const powerConfig = JSON.parse(await readFile("config/corpus-power.json", "utf8")) as PowerConfig;

function repositoryOutcomes(repositoryId: string): CalibrationOutcome[] {
  const rows: CalibrationOutcome[] = [];
  for (const expectedDisposition of ["vulnerable", "safe", "insufficient_context"] as const) {
    for (const evaluator of ["jev", "terra", "opus"] as const) {
      for (const repetition of [1, 2, 3, 4, 5] as const) {
        const isTargetPacket = expectedDisposition === "vulnerable" && evaluator === "jev";
        const predictedDisposition: CalibrationPrediction["predictedDisposition"] = isTargetPacket
          ? (repetition <= 3 ? "vulnerable" : "safe")
          : expectedDisposition;
        const scored = scoreCalibrationPrediction({
          expectedDisposition,
          expectedFamily: "injection",
          acceptableEvidenceSpanIds: expectedDisposition === "vulnerable" ? ["s1"] : [],
          status: "valid",
          predictedDisposition,
          predictedFamily: predictedDisposition === "vulnerable"
            ? (isTargetPacket && repetition === 3 ? "ssrf" : "injection")
            : null,
          evidenceSpanIds: predictedDisposition === "vulnerable" ? ["s1"] : []
        });
        rows.push({
          repositoryId,
          packetId: `${repositoryId}-${expectedDisposition}`,
          disposition: expectedDisposition,
          evaluator,
          repetition,
          ...scored
        });
      }
    }
  }
  return rows;
}

test("five repetitions are averaged within packet before class and repository aggregation", () => {
  const aggregate = aggregateCalibration(repositoryOutcomes("repo-a"));
  const packet = aggregate.packets.find((row) => row.packetId === "repo-a-vulnerable" && row.evaluator === "jev")!;
  assert.equal(packet.correctDisposition, 2 / 5);
  assert.equal(packet.vulnerableDetected, 2 / 5);
  assert.equal(aggregate.packets.find((row) => row.packetId === "repo-a-safe" && row.evaluator === "jev")!.correctDisposition, 1);
  assert.equal(aggregate.packets.find((row) => row.packetId === "repo-a-insufficient_context" && row.evaluator === "jev")!.correctDisposition, 1);
  assert.equal(aggregate.independentPacketCount, 3);
  assert.equal(aggregate.observationCount, 45);
});

test("vulnerable correctness requires disposition, family, and an acceptable evidence span", () => {
  const base: CalibrationPrediction = {
    expectedDisposition: "vulnerable",
    expectedFamily: "injection",
    acceptableEvidenceSpanIds: ["s1"],
    status: "valid",
    predictedDisposition: "vulnerable",
    predictedFamily: "injection",
    evidenceSpanIds: ["s1"]
  };
  assert.deepEqual(scoreCalibrationPrediction(base), { correctDisposition: true, vulnerableDetected: true });
  assert.deepEqual(scoreCalibrationPrediction({ ...base, predictedFamily: "ssrf" }), { correctDisposition: false, vulnerableDetected: false });
  assert.deepEqual(scoreCalibrationPrediction({ ...base, evidenceSpanIds: ["unlabeled"] }), { correctDisposition: false, vulnerableDetected: false });
  assert.deepEqual(scoreCalibrationPrediction({ ...base, status: "timeout", predictedDisposition: null, predictedFamily: null, evidenceSpanIds: [] }), { correctDisposition: false, vulnerableDetected: false });
});

test("bootstrap resamples paired repositories with all repetitions and evaluators together", () => {
  const aggregate = aggregateCalibration([...repositoryOutcomes("repo-a"), ...repositoryOutcomes("repo-b")]);
  const report = pairedRepositoryBootstrap(aggregate, powerConfig);
  assert.equal(report.draws, 10000);
  assert.equal(report.seed, 20260918);
  assert.equal(report.resamplingUnit, "repository");
});

test("power is sufficient only when the lower Wilson bound clears 0.8 in both scenarios", () => {
  const report = decidePower([
    { trueDifference: 0, supportedRuns: 870, totalRuns: 1000 },
    { trueDifference: -0.01, supportedRuns: 865, totalRuns: 1000 }
  ], 0.8);
  assert.equal(report.status, "sufficient");
  assert.equal(report.scenarios.every((row) => row.wilsonLower95 >= 0.8), true);
});

test("freeze eligibility also requires sealed holdout repository capacity in every family", () => {
  const report: PowerReport = {
    schemaVersion: 1,
    split: "calibration",
    margin: -0.02,
    seed: 20260918,
    repetitionsPerPacket: 5,
    resamplingUnit: "repository",
    requiredRepositoriesPerFamily: 2,
    scenarios: [
      { trueDifference: 0, estimatedJointPower: 0.87, wilsonLower95: 0.84 },
      { trueDifference: -0.01, estimatedJointPower: 0.86, wilsonLower95: 0.83 }
    ],
    status: "sufficient",
    blockers: []
  };
  const manifest = manifestWithHoldoutRepositoryCounts({ injection: 2, broken_access_control: 1, ssrf: 2 });
  assert.deepEqual(assessFreezeEligibility(manifest, report), {
    status: "blocked",
    blockers: ["sealed holdout has 1 broken_access_control repositories; 2 required"]
  });
  assert.deepEqual(assessFreezeEligibility(manifestWithHoldoutRepositoryCounts({ injection: 2, broken_access_control: 2, ssrf: 2 }), report), {
    status: "eligible",
    blockers: []
  });
});
```

Define the helper exactly as:

```ts
function manifestWithHoldoutRepositoryCounts(repositoryCountsByFamily: Record<Family, number>): PublicCalibrationManifest {
  const repositoryCount = Object.values(repositoryCountsByFamily).reduce((sum, count) => sum + count, 0);
  return {
    schemaVersion: 1,
    seed: 20260918,
    development: { repositoryGroups: ["owasp/juice-shop"] },
    calibration: { repositoryGroups: [], rootCauseGroups: [], targetIds: [], packetIds: [], families: [] },
    sealedHoldout: {
      manifestHash: "a".repeat(64),
      repositoryCount,
      targetCount: repositoryCount,
      packetCount: repositoryCount * 3,
      targetCountsByFamily: { ...repositoryCountsByFamily },
      repositoryCountsByFamily
    }
  };
}
```

The fixture models single-family repositories, so summing family counts is exact. It never contains a holdout repository ID.

- [ ] **Step 3: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/power.test.js`

Expected: FAIL because power aggregation and simulation do not exist.

- [ ] **Step 4: Implement exact outcome and report types**

```ts
export interface CalibrationPrediction {
  expectedDisposition: "vulnerable" | "safe" | "insufficient_context";
  expectedFamily: Family;
  acceptableEvidenceSpanIds: string[];
  status: "valid" | "timeout" | "malformed_output" | "policy_failure" | "service_failure";
  predictedDisposition: "vulnerable" | "safe" | "insufficient_context" | null;
  predictedFamily: Family | null;
  evidenceSpanIds: string[];
}

export interface CalibrationOutcome {
  repositoryId: string;
  packetId: string;
  disposition: "vulnerable" | "safe" | "insufficient_context";
  evaluator: "jev" | "terra" | "opus";
  repetition: 1 | 2 | 3 | 4 | 5;
  correctDisposition: boolean;
  vulnerableDetected: boolean;
}

export interface PowerReport {
  schemaVersion: 1;
  split: "calibration";
  margin: -0.02;
  seed: 20260918;
  repetitionsPerPacket: 5;
  resamplingUnit: "repository";
  requiredRepositoriesPerFamily: number | null;
  scenarios: Array<{ trueDifference: 0 | -0.01; estimatedJointPower: number; wilsonLower95: number }>;
  status: "sufficient" | "insufficient";
  blockers: string[];
}

export interface FreezeEligibility {
  status: "eligible" | "blocked";
  blockers: string[];
}
```

Implement the shared scoring rule exactly:

```ts
export function scoreCalibrationPrediction(prediction: CalibrationPrediction): Pick<CalibrationOutcome, "correctDisposition" | "vulnerableDetected"> {
  if (prediction.status !== "valid" || prediction.predictedDisposition === null) {
    return { correctDisposition: false, vulnerableDetected: false };
  }
  if (prediction.expectedDisposition === "vulnerable") {
    const fullyCorrect = prediction.predictedDisposition === "vulnerable"
      && prediction.predictedFamily === prediction.expectedFamily
      && prediction.evidenceSpanIds.some((spanId) => prediction.acceptableEvidenceSpanIds.includes(spanId));
    return { correctDisposition: fullyCorrect, vulnerableDetected: fullyCorrect };
  }
  return {
    correctDisposition: prediction.predictedDisposition === prediction.expectedDisposition,
    vulnerableDetected: false
  };
}
```

The parser feeding `scoreCalibrationPrediction` must require non-empty acceptable evidence spans for vulnerable ground truth; valid vulnerable predictions require non-null family and at least one evidence span; valid safe and insufficient-context predictions require `predictedFamily: null` and `evidenceSpanIds: []`; failures require all prediction fields null or empty. The controlled calibration exporter must call this corpus-owned helper for every attempt rather than implement a second scoring rule.

The `CalibrationOutcome` parser must require exactly one outcome for every `(repositoryId, packetId, evaluator, repetition)` combination and all repetitions 1–5. Each `repositoryId` must be present in `PublicCalibrationManifest.calibration.repositoryIds`. No row may disappear. First average both derived binary outcomes over five repetitions per packet/evaluator. Balanced triage accuracy is the unweighted mean of per-class `correctDisposition` recall; vulnerable-class correctness therefore includes correct family and acceptable-span localization, while safe and insufficient-context correctness depends only on disposition. Vulnerability recall uses only vulnerable packets and their derived `vulnerableDetected` mean.

- [ ] **Step 5: Implement paired repository bootstrap and simulation**

For each bootstrap draw, sample repository groups with replacement and carry every packet, disposition, evaluator, and repetition belonging to each sampled repository. Compute four differences: Jev–Terra balanced accuracy, Jev–Terra vulnerability recall, Jev–Opus balanced accuracy, and Jev–Opus vulnerability recall. Use the 5th and 95th percentiles of 10,000 draws as the two-sided 90% interval. A comparison is supported only when its lower bound is greater than `-0.02`; one simulated experiment succeeds only when all four comparisons are supported.

Use an empirical paired-cluster simulation rather than treating repetitions or packets as independent. Assign each calibration repository component to one power stratum: the least frequent family represented by that component, breaking equal-frequency ties in the order `broken_access_control`, `ssrf`, `injection`. For candidate grid value `n`, draw `n` component blocks with replacement from each of the three strata; give repeated draws distinct synthetic repository IDs, but keep every target, disposition, evaluator, and all five repetitions inside its block. If any stratum is empty, return `status: "insufficient"` with blocker `"calibration lacks a repository stratum for FAMILY"`.

For each of 1,000 outer simulations, compute all four paired estimates on the sampled blocks. For each estimate, recenter sampling error onto the configured true difference with `scenarioEstimate = trueDifference + (sampleEstimate - calibrationEstimate)`. Run the 10,000-draw paired repository bootstrap on that same sampled block set and recenter each bootstrap endpoint with `scenarioEndpoint = trueDifference + (sampleEndpoint - sampleEstimate)`. This preserves the observed three-evaluator, two-metric, repository, packet, and repetition dependence while testing the prespecified `0` and `-0.01` differences. One outer simulation succeeds only when all four recentered lower bounds are greater than `-0.02`. Report per-disposition rates, paired disagreement rates, and repository intraclass correlations as diagnostics; do not use them as independent sample counts.

For each scenario, divide joint-success count by 1,000 and compute its Wilson 95% lower bound. Select the first grid value whose Wilson lower bound is at least `0.8` in both scenarios. If none passes, report `requiredRepositoriesPerFamily: null`, `status: "insufficient"`, and blocker `"power grid exhausted; recruit additional untouched repositories"`.

After simulation, assess the already sealed allocation without opening its identities or packet bodies:

```ts
export function assessFreezeEligibility(manifest: PublicCalibrationManifest, report: PowerReport): FreezeEligibility {
  const blockers = [...report.blockers];
  if (report.status !== "sufficient" || report.requiredRepositoriesPerFamily === null) {
    blockers.push("calibration power simulation is insufficient");
  } else {
    for (const family of ["injection", "broken_access_control", "ssrf"] as const) {
      const observed = manifest.sealedHoldout.repositoryCountsByFamily[family];
      if (observed < report.requiredRepositoriesPerFamily) {
        blockers.push(`sealed holdout has ${observed} ${family} repositories; ${report.requiredRepositoriesPerFamily} required`);
      }
    }
  }
  return { status: blockers.length === 0 ? "eligible" : "blocked", blockers: [...new Set(blockers)] };
}
```

The confirmatory run remains prohibited unless this result is `eligible`. A statistically sufficient calibration simulation does not compensate for an undersized sealed holdout. If the holdout is short in any family, retain the existing sealed identities, recruit untouched candidates, rerun deterministic grouping/allocation without inspecting holdout bodies, and publish a new manifest hash before any model run.

Add a transparent optimistic lower-bound diagnostic:

```ts
export function optimisticPairedSampleSize(disagreementRate: number, margin = 0.02): number {
  const zOneSided95 = 1.6448536269514722;
  const zPower80 = 0.8416212335729143;
  return Math.ceil(disagreementRate * ((zOneSided95 + zPower80) ** 2) / (margin ** 2));
}
```

Label this diagnostic optimistic because it ignores repository clustering, three-class balance, and the requirement that all four comparisons pass. It may explain why a small corpus is underpowered; it may not override simulation.

- [ ] **Step 6: Refuse holdout input and run tests**

`simulatePower` must require `split: "calibration"` in its input header and reject `holdout` before reading outcome rows. Then run:

```bash
npm run check
git diff --check
```

Expected: hand-calculated aggregation, paired resampling, deterministic seed, and sufficient/insufficient boundary tests pass.

- [ ] **Step 7: Commit**

```bash
git add config/corpus-power.json src/power.ts src/power.test.ts test/fixtures/corpus/calibration.jsonl
git commit -m "feat: gate corpus on joint power simulation"
```

---

### Task 8: Expose a Preparation-Only CLI and Complete the Audit Trail

**Files:**
- Create: `src/corpus-cli.ts`
- Create: `src/corpus-cli.test.ts`
- Modify: `package.json`
- Modify: `docs/corpus-preparation.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all Tasks 1–7 interfaces.
- Produces: `CorpusCommand`, `CorpusCliDependencies`, `CorpusCliResult`, `assertNoHoldoutArg(argv)`, `parseCorpusCommand(argv)`, `assertCorpusCommandPolicy(request)`, `readCorpusInputs(request, readText)`, `executeCorpusCommand(request, inputs, dependencies)`, `writeCorpusOutputs(request, result, writers)`, `runCorpusCli(argv, dependencies): Promise<CorpusCliResult>`, and these commands: `check`, `metadata`, `reproduce`, `packets`, `adjudicate`, `split`, and `power`.

- [ ] **Step 1: Write subprocess tests for offline checks and categorical holdout denial**

```ts
test("corpus check reports current blockers without network or Docker", async () => {
  const result = await runCorpusCli(["check", "--registry", "benchmark/corpus-candidates.json"], fixtureDependencies);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /broken_access_control/);
  assert.match(result.stderr, /reproduction_verified/);
});

test("every execution-shaped command rejects holdout before dependencies run", async () => {
  for (const command of ["check", "metadata", "reproduce", "packets", "adjudicate", "split", "power"] as const) {
    const result = await runCorpusCli([command, "--split", "holdout"], dependenciesThatThrowIfCalled);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /holdout execution is prohibited/);
  }
});

test("fixture pipeline creates calibration artifacts without provider, network, or container calls", async () => {
  const result = await runCorpusCli(["check", "--fixture", "test/fixtures/corpus/registry.json"], fixtureDependencies);
  assert.equal(result.code, 0);
});
```

Define `fixtureDependencies` with in-memory read/write functions and a process runner that throws `new Error("external process forbidden in fixture test")`. Define `dependenciesThatThrowIfCalled` as a `Proxy` whose property access throws `new Error("dependency accessed before holdout denial")`; the holdout test proves argument policy is checked before dependency access.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/corpus-cli.test.js`

Expected: FAIL because the corpus CLI does not exist.

- [ ] **Step 3: Implement the minimal preparation dispatcher**

Use explicit argv parsing without a CLI dependency. Require named input and output paths; reject unknown flags and duplicate flags. Exit codes are `0` for success, `2` for validation or policy blockage, and `1` for an unexpected internal error. All JSON output uses `canonicalJson`; JSONL output uses `writeJsonlExclusive`.

```ts
type PreparationScope = "preparation";
export type CorpusCommand =
  | { command: "check"; registry?: string; fixture?: string; split?: CorpusSplit }
  | { command: "metadata"; scope: PreparationScope; registry: string; output: string; split?: CorpusSplit }
  | { command: "reproduce"; scope: PreparationScope; metadata: string; recipes: string; output: string; runtime: "docker"; split?: CorpusSplit }
  | { command: "packets"; scope: PreparationScope; registry: string; metadata: string; reproduction: string; packetOutput: string; ledgerOutput: string; split?: CorpusSplit }
  | { command: "adjudicate"; scope: PreparationScope; draft: string; reviews: string; output: string; split?: CorpusSplit }
  | { command: "split"; scope: PreparationScope; registry: string; metadata: string; reproduction: string; packets: string; ledger: string; groundTruth: string; calibrationManifest: string; calibrationPackets: string; calibrationGroundTruth: string; holdoutManifest: string; holdoutPackets: string; holdoutGroundTruth: string; split?: CorpusSplit }
  | { command: "power"; split: "calibration" | "holdout"; manifest: string; outcomes: string; config: string; output: string; eligibilityOutput: string };

export interface CorpusCliDependencies {
  readText(path: string): Promise<string>;
  writeJsonExclusive(path: string, value: unknown): Promise<void>;
  writeJsonlExclusive(path: string, values: readonly unknown[]): Promise<void>;
  runCommand: CommandRunner;
}

export interface CorpusCliResult {
  code: 0 | 1 | 2;
  stdout: string;
  stderr: string;
}
```

Dispatch order for every command is:

```ts
assertNoHoldoutArg(argv);
const request = parseCorpusCommand(argv);
assertCorpusCommandPolicy(request);
const inputs = await readCorpusInputs(request, dependencies.readText);
const result = await executeCorpusCommand(request, inputs, dependencies);
await writeCorpusOutputs(request, result, {
  writeJsonExclusive: dependencies.writeJsonExclusive,
  writeJsonlExclusive: dependencies.writeJsonlExclusive
});
return {
  code: result.blockers.length === 0 ? 0 : 2,
  stdout: canonicalJson(result),
  stderr: result.blockers.join("\n")
};
```

Implement the argv preflight exactly as:

```ts
export function assertNoHoldoutArg(argv: readonly string[]): void {
  for (let index = 0; index + 1 < argv.length; index += 1) {
    if (argv[index] === "--split" && argv[index + 1] === "holdout") assertPreparationRunAllowed("holdout");
  }
}
```

This ensures the categorical policy error wins even when other required arguments are absent, and it occurs before any dependency property is read.

Implement the policy check as:

```ts
export function assertCorpusCommandPolicy(request: CorpusCommand): void {
  if (request.split !== undefined) assertPreparationRunAllowed(request.split);
  if (request.scope !== undefined && request.scope !== "preparation") throw new Error("scope must be preparation");
  if (request.command === "power" && request.split !== "calibration") throw new Error("power requires calibration split");
}
```

`metadata`, `reproduce`, `packets`, and `adjudicate` accept only `--scope preparation`, because candidates have not yet been allocated. For `metadata`, default checkout root to `/private/tmp/system-one-security-corpus/checkouts`. For `reproduce`, require `--recipes validation/private/recipes.jsonl` and `--runtime docker`; there is no default recipe path and no automatic execution from `check`. For `packets` and `adjudicate`, require private output paths under `private/corpus/`. `split` accepts only `--scope preparation`, emits only calibration identities and packet bodies publicly, and writes calibration and holdout ground-truth ledgers only beneath ignored `private/corpus/`. `power` requires `--split calibration`, rejects holdout, writes `PowerReport` to `--output`, and writes the result of `assessFreezeEligibility(publicManifest, report)` to `--eligibility-output`. Any command receiving `--split holdout` fails before dependencies are called.

- [ ] **Step 4: Add exact package scripts**

Add:

```json
{
  "corpus": "npm run build --silent && node dist/src/corpus-cli.js",
  "corpus:check": "npm run corpus -- check --registry benchmark/corpus-candidates.json",
  "corpus:test": "npm run build --silent && node --test dist/src/corpus.test.js dist/src/corpus-metadata.test.js dist/src/reproduction.test.js dist/src/corpus-packets.test.js dist/src/adjudication.test.js dist/src/split.test.js dist/src/power.test.js dist/src/corpus-cli.test.js"
}
```

Merge these keys into the existing `scripts` object; do not replace `build`, `test`, or `check`.

- [ ] **Step 5: Write the operator runbook with exact gates**

Document this order in `docs/corpus-preparation.md`:

```bash
npm run corpus:check
npm run corpus -- metadata --scope preparation --registry benchmark/corpus-candidates.json --output artifacts/corpus/metadata.jsonl
npm run corpus -- reproduce --scope preparation --metadata artifacts/corpus/metadata.jsonl --recipes validation/private/recipes.jsonl --output artifacts/corpus/reproduction.jsonl --runtime docker
npm run corpus -- packets --scope preparation --registry benchmark/corpus-candidates.json --metadata artifacts/corpus/metadata.jsonl --reproduction artifacts/corpus/reproduction.jsonl --packet-output private/corpus/preallocation-packets.jsonl --ledger-output private/corpus/provenance.jsonl
npm run corpus -- adjudicate --scope preparation --draft private/corpus/adjudication-draft.jsonl --reviews validation/private/reviews.jsonl --output private/corpus/adjudication-final.jsonl
npm run corpus -- split --scope preparation --registry benchmark/corpus-candidates.json --metadata artifacts/corpus/metadata.jsonl --reproduction artifacts/corpus/reproduction.jsonl --packets private/corpus/preallocation-packets.jsonl --ledger private/corpus/provenance.jsonl --ground-truth private/corpus/adjudication-final.jsonl --calibration-manifest artifacts/corpus/calibration-manifest.json --calibration-packets artifacts/corpus/calibration-packets.jsonl --calibration-ground-truth private/corpus/calibration-ground-truth.jsonl --holdout-manifest private/corpus/holdout-manifest.json --holdout-packets private/corpus/holdout-packets.jsonl --holdout-ground-truth private/corpus/holdout-ground-truth.jsonl
npm run corpus -- power --split calibration --manifest artifacts/corpus/calibration-manifest.json --outcomes artifacts/calibration/controlled-attempts.jsonl --config config/corpus-power.json --output artifacts/corpus/power-report.json --eligibility-output artifacts/corpus/freeze-eligibility.json
```

Immediately after the commands, state: these commands are documentation, not authorization to execute vulnerable applications; `reproduce` requires a designated validator and reviewed private recipes. Also state that `npm run corpus -- power --split holdout` and every other holdout execution command must fail before reading the holdout path.

Update `README.md` with four limitations: public-corpus contamination is possible; metadata verification is not reproduction; patched means target fixed rather than repository safe; an underpowered corpus yields no confirmatory run.

- [ ] **Step 6: Run the full offline verification**

```bash
npm run corpus:test
npm run check
npm run corpus:check
git diff --check
```

Expected: `corpus:test` and `check` pass. `corpus:check` exits `2` and reports the real corpus's missing broken-access-control and reproduction gates; this is the correct fail-closed result until independent preparation completes.

- [ ] **Step 7: Inspect the final diff and commit**

```bash
git status --short
git diff --stat
git diff --check
git add src/corpus-cli.ts src/corpus-cli.test.ts package.json docs/corpus-preparation.md README.md
git commit -m "feat: expose controlled corpus preparation workflow"
```

Expected: only the named files and prior task commits are present; no generated artifact, private ledger, checkout, recipe, reproduction output, or secret is staged.

---

## Completion Gate

The implementation is ready for an independent security-methodology review only when all of these are true:

- The real intake includes at least two indivisible repository components capable of representing each of injection, broken access control, and SSRF across calibration and sealed holdout.
- Every allocated target is metadata-verified and reproduction-verified with immutable receipts.
- Every target has one vulnerable, one target-safe patched, and one deliberately insufficient-context packet.
- Public packet bytes contain no answer-bearing provenance and reproduce the frozen packet hash.
- Two blinded reviewers agree on core labels, or a third resolves the disagreement; unresolved packets are excluded with an audit reason. Resolved private rows include severity plus only independently corroborated optional Jev atomic labels and project directly to `PrimaryLedgerRow`.
- Calibration and sealed holdout are repository-, root-cause-, and relationship-group-disjoint.
- The power report is `sufficient` for both true-difference scenarios using the frozen margin, seed, bootstrap count, and joint four-comparison decision.
- The public sealed-holdout aggregate has at least `PowerReport.requiredRepositoriesPerFamily` distinct repositories in every family and `freeze-eligibility.json` is `eligible`; simulation sufficiency alone cannot authorize a confirmatory run.
- The preparation CLI denies holdout execution before any external dependency is called.
- `npm run check`, `npm run corpus:test`, and `git diff --check` pass offline.

If any item fails, the corpus remains in preparation. The allowed response is to repair evidence or recruit additional untouched repositories; it is not to inspect the holdout, weaken a gate, relabel an ambiguous packet, or widen the non-inferiority margin.
