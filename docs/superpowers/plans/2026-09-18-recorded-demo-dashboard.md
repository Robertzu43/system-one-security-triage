# Recorded 100-Case Demo Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the synthetic security-triage demo to 100 distinct cases, record immutable Jev/Terra/Opus results, and publish a reproducible static comparison dashboard through GitHub Pages.

**Architecture:** Extend the existing canonical demo path instead of creating a second evaluator or scorer. Each model writes one validated immutable JSON artifact keyed to the corpus hash; a pure builder validates three artifacts and generates the only dataset consumed by a dependency-free HTML/CSS/JavaScript dashboard. A manual GitHub Pages workflow publishes only a complete Jev/Terra/Opus recorded run.

**Tech Stack:** Node.js 24+, TypeScript 5.9, Node test runner, `@typesafe-ai/sdk@0.6.0`, plain HTML/CSS/JavaScript/SVG, GitHub Actions, GitHub Pages

**Spec:** `docs/superpowers/specs/2026-09-18-recorded-demo-dashboard-design.md`

## Global Constraints

- The corpus contains exactly 100 distinct synthetic cases in the frozen 34/33/33 family and disposition matrix.
- Every evaluator receives the same canonical evidence bytes for a case.
- Jev is identified as TypeSafe's System One decision model; Terra as an OpenAI model through Codex CLI; Opus as Anthropic Claude Opus through Claude tooling.
- Public results are recorded, never presented as live browser inference.
- Publishing requires exactly one complete Jev, Terra, and Opus artifact with the same corpus hash.
- Case-level failures remain visible and remain in every metric denominator.
- Missing usage or cost is `null`, never zero.
- Recorded result files are immutable and may not contain credentials, absolute local paths, or private CLI output.
- The deployed site contains no API keys, backend, database, provider SDK, or runtime model call.
- Use native HTML, CSS, JavaScript, and SVG; add no frontend or charting dependency.
- Tests and dashboard builds make no paid model calls.
- The UI must be responsive, keyboard accessible, usable with reduced motion, and never communicate correctness by color alone.

## Review Focus

- A run containing 99 results, 101 results, a duplicate case, or an unknown case must fail publication rather than silently skew metrics; Task 2 pins all four shapes.
- A structurally complete run with explicit model errors must publish and count those cases as incorrect; Task 3 pins this denominator behavior.
- Two individually valid runs from different corpus revisions must fail before dashboard data is written; Task 3 pins cross-run corpus agreement.
- Error text containing Unix, macOS, UNC, or Windows absolute paths must fail the public-artifact boundary; Task 2 pins path rejection.
- Replay must not fetch, mutate, or recompute model results and must collapse immediately under reduced motion; Task 4 pins the static network boundary and reduced-motion behavior.

---

## File Structure

```text
src/demo.ts                         existing case/result types plus reusable summary calculation
src/demo.test.ts                    existing demo checks plus 100-case matrix and evidence uniqueness
src/demo-live.ts                    existing live adapters with explicit evaluator metadata
src/demo-record.ts                  recorded-run schema, parser, corpus hash, immutable writer
src/demo-record.test.ts             artifact validation, immutability, completeness, redaction
src/dashboard.ts                    three-run validation and public dataset generation
src/dashboard.test.ts               mixed-run rejection and hand-calculated metric agreement
src/cli.ts                          demo-record and dashboard-build commands
src/cli.test.ts                     subprocess gates for credentials, files, and offline builds
src/jev.ts                          exported pinned Jev model ID
src/reasoning.ts                    exported pinned runner versions
test/fixtures/demo-cases.json       100 distinct synthetic cases
test/fixtures/dashboard-runs/       three small recorded artifacts for offline dashboard tests
dashboard/index.html                semantic static dashboard shell
dashboard/styles.css                responsive scorecard-first visual system
dashboard/app.js                    rendering, filters, SVG charts, and recorded replay
src/dashboard-app.test.ts           static boundary and accessibility contract checks
.github/workflows/pages.yml         manually selected recorded-run deployment
package.json                        record, dashboard build, preview, and verification scripts
README.md                           100-case workflow, Opus handoff, replay, and publication instructions
.gitignore                          local visual-companion and generated dashboard data exclusions
```

Generated `dashboard/data/latest.json` is ignored locally and produced from selected committed run artifacts. Live artifacts are committed under `results/recorded/<run-id>/`; fixture artifacts stay under `test/fixtures/dashboard-runs/`.

---

### Task 1: Freeze the 100-Case Synthetic Corpus

**Files:**
- Modify: `test/fixtures/demo-cases.json`
- Modify: `src/demo.test.ts`

**Interfaces:**
- Consumes: `loadDemoCases(path: string): Promise<DemoCase[]>` from `src/demo.ts`
- Produces: a 100-element fixture with stable unique IDs and distinct canonical evidence; all later tasks consume this exact fixture and its hash

- [ ] **Step 1: Replace the loose nine-case count check with the frozen matrix test**

Add these assertions to `src/demo.test.ts`:

```ts
import { stableHash } from "./jsonl.js";

test("100-case fixture has the frozen family and disposition matrix", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(cases.length, 100);
  const expected = {
    injection: { vulnerable: 12, safe: 11, insufficient_context: 11 },
    broken_access_control: { vulnerable: 11, safe: 11, insufficient_context: 11 },
    ssrf: { vulnerable: 11, safe: 11, insufficient_context: 11 }
  } as const;
  for (const [family, dispositions] of Object.entries(expected)) {
    for (const [disposition, count] of Object.entries(dispositions)) {
      assert.equal(cases.filter((item) => item.family === family && item.expected.disposition === disposition).length, count, `${family}/${disposition}`);
    }
  }
});

test("100-case fixture uses unique IDs and distinct canonical evidence", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(new Set(cases.map((item) => item.caseId)).size, 100);
  assert.equal(new Set(cases.map((item) => stableHash(item.state))).size, 100);
});
```

- [ ] **Step 2: Run the focused tests and verify the old fixture fails**

Run:

```bash
npm run build && node --test dist/src/demo.test.js
```

Expected: FAIL because the fixture has 9 cases rather than 100.

- [ ] **Step 3: Expand the fixture with distinct scenarios**

Keep the existing nine cases and add 91 hand-authored cases. Use these scenario allocations so the evidence is substantively different rather than renamed templates:

| Family | Scenario groups | Total |
| --- | --- | ---: |
| Injection | SQL query construction (8), shell/process execution (7), `eval`/dynamic compilation (6), template/render injection (5), filesystem/path interpretation (4), parser/ORM raw-expression boundaries (4) | 34 |
| Broken access control | object ownership reads (6), object ownership writes (6), tenant isolation (5), role/admin boundaries (5), indirect service authorization (5), mass assignment/field access (3), middleware/call-path incompleteness (3) | 33 |
| SSRF | direct URL fetches (7), host allowlists (6), redirect handling (5), private/metadata address controls (5), webhook callbacks (4), image/document fetchers (3), DNS/proxy context gaps (3) | 33 |

For each family, fill the exact disposition counts from the frozen matrix. Every state must use different paths, operations, control placement, and evidence relationships. Safe cases must show the effective control. Insufficient-context cases must omit the precise fact needed to decide and mark the corresponding `contextResolution` field unresolved. Vulnerable cases must show both attacker influence and the sensitive operation or authorization boundary.

Use stable IDs with this shape:

```text
injection-vulnerable-sql-concatenation
access-safe-tenant-ownership-check
ssrf-insufficient-redirect-policy-hidden
```

Do not add numeric-only duplicates such as `sql-case-01` and `sql-case-02` with the same code shape.

- [ ] **Step 4: Run the corpus and complete regression suite**

Run:

```bash
npm run check
```

Expected: 100-case tests PASS and all existing tests PASS. Existing tests that assert `caseCount === 9` must be updated to `100` in the same file; no production behavior changes in this task.

- [ ] **Step 5: Commit the frozen corpus**

```bash
git add test/fixtures/demo-cases.json src/demo.test.ts
git commit -m "test: expand security triage demo to 100 cases"
```

---

### Task 2: Add Immutable Recorded-Run Artifacts

**Files:**
- Create: `src/demo-record.ts`
- Create: `src/demo-record.test.ts`
- Modify: `src/demo.ts`
- Modify: `src/demo-live.ts`
- Modify: `src/jev.ts`
- Modify: `src/reasoning.ts`

**Interfaces:**
- Consumes: `DemoCase`, `DemoResult`, `DemoEvaluator`, `canonicalJson`, `stableHash`, and `writeJsonlExclusive`
- Produces:
  - `EvaluatorMetadata`
  - `RecordedDemoRun`
  - `corpusHash(cases: readonly DemoCase[]): string`
  - `parseRecordedDemoRun(value: unknown, cases: readonly DemoCase[]): RecordedDemoRun`
  - `writeRecordedDemoRuns(input: RecordDemoInput): Promise<RecordedDemoRun[]>`

- [ ] **Step 1: Write failing artifact contract tests**

Create `src/demo-record.test.ts` with tests covering a valid round trip, exclusive writes, incomplete/duplicate/unknown results, and local path rejection:

```ts
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadDemoCases, runDemo } from "./demo.js";
import { corpusHash, parseRecordedDemoRun, writeRecordedDemoRuns } from "./demo-record.js";

const metadata = {
  jev: { provider: "TypeSafe", modelId: "jev-1.13.0", runner: "@typesafe-ai/sdk", runnerVersion: "0.6.0" },
  terra: { provider: "OpenAI", modelId: "gpt-5.6-terra", runner: "codex-cli", runnerVersion: "0.147.0" },
  opus: { provider: "Anthropic", modelId: "claude-opus-4-6", runner: "claude-code", runnerVersion: "2.1.277" }
} as const;

test("recorded runs are complete, hashed, parseable, and immutable", async () => {
  const root = await mkdtemp(join(tmpdir(), "demo-record-test-"));
  try {
    const cases = await loadDemoCases("test/fixtures/demo-cases.json");
    const adapters = (["jev", "terra", "opus"] as const).map((name) => ({
      name,
      metadata: metadata[name],
      evaluate: async (_state: string, item: typeof cases[number]) => item.expected
    }));
    const report = await runDemo(cases, adapters, "live");
    const runs = await writeRecordedDemoRuns({ cases, report, metadata, runId: "2026-09-18-demo", recordedAt: "2026-09-18T12:00:00.000Z", outputRoot: root });
    assert.equal(runs.length, 3);
    assert.equal(runs[0]?.corpusHash, corpusHash(cases));
    assert.equal(runs[0]?.caseCount, 100);
    assert.equal(parseRecordedDemoRun(JSON.parse(await readFile(join(root, "2026-09-18-demo", "jev.json"), "utf8")), cases).evaluator, "jev");
    await assert.rejects(() => writeRecordedDemoRuns({ cases, report, metadata, runId: "2026-09-18-demo", recordedAt: "2026-09-18T12:00:00.000Z", outputRoot: root }), /already exists/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("recorded run parser rejects incomplete, duplicate, unknown, and path-bearing results", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const base = validRecordedRunFixture(cases);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: base.results.slice(1) }, cases), /complete case coverage/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [...base.results, base.results[0]] }, cases), /duplicate case/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0], caseId: "unknown" }, ...base.results.slice(1)] }, cases), /unknown case/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0], error: "/Users/alice/.claude.json" }, ...base.results.slice(1)] }, cases), /local path/);
  assert.throws(() => parseRecordedDemoRun({ ...base, results: [{ ...base.results[0], error: "C:\\Users\\alice\\secret" }, ...base.results.slice(1)] }, cases), /local path/);
});
```

Define `validRecordedRunFixture` in the test as a local helper that maps every loaded case to a valid terminal `DemoResult`; do not export test construction from production code.

- [ ] **Step 2: Run the new tests and verify the module is missing**

Run:

```bash
npm run build
```

Expected: FAIL because `src/demo-record.ts` does not exist and `DemoAdapter` lacks metadata.

- [ ] **Step 3: Export pinned evaluator metadata sources**

In `src/jev.ts` replace the inline model string with:

```ts
export const jevModel = "jev-1.13.0";
```

and pass `model: jevModel` to `client.systemOne`.

In `src/reasoning.ts`, export the pinned versions without changing validation:

```ts
export const reasoningRunnerVersions: Readonly<Record<ReasoningEvaluator, string>> = {
  terra: "codex-cli 0.147.0",
  opus: "2.1.277 (Claude Code)"
};
```

Use `reasoningRunnerVersions` where `expectedVersions` is currently read.

Extend `DemoAdapter` in `src/demo.ts`:

```ts
export interface EvaluatorMetadata {
  provider: "TypeSafe" | "OpenAI" | "Anthropic" | "Fixture";
  modelId: string;
  runner: string;
  runnerVersion: string;
}

export interface DemoAdapter {
  name: DemoEvaluator;
  metadata: EvaluatorMetadata;
  evaluate(stateJson: string, item: DemoCase): Promise<DemoDecision>;
}
```

Update `createJevDemoAdapter`, `createReasoningDemoAdapter`, and fixture adapters to supply metadata from the exported constants. Do not infer a model version from response prose.

- [ ] **Step 4: Implement the recorded artifact parser and writer**

Create `src/demo-record.ts` with these public types:

```ts
export interface RecordedDemoRun {
  schemaVersion: 1;
  runId: string;
  recordedAt: string;
  mode: "live-recorded";
  evaluator: DemoEvaluator;
  provider: EvaluatorMetadata["provider"];
  modelId: string;
  runner: string;
  runnerVersion: string;
  corpusHash: string;
  caseCount: number;
  results: DemoResult[];
  artifactSha256: string;
}

export interface RecordDemoInput {
  cases: readonly DemoCase[];
  report: DemoReport;
  runId: string;
  recordedAt: string;
  outputRoot: string;
  metadata: Readonly<Partial<Record<DemoEvaluator, EvaluatorMetadata>>>;
}
```

Implement `corpusHash` using only model-visible and label fields:

```ts
export function corpusHash(cases: readonly DemoCase[]): string {
  return stableHash(cases.map(({ caseId, family, state, expected }) => ({ caseId, family, state, expected })));
}
```

Validate `runId` with `/^[a-z0-9][a-z0-9._-]{0,63}$/`, `recordedAt` by round-tripping `new Date(value).toISOString()`, finite non-negative metrics, exact evaluator/result agreement, 100 unique known case IDs, and forbidden public strings. Reject strings matching any of:

```ts
const localPath = /(?:^|\s)(?:\/Users\/|\/home\/|\/private\/|\/var\/folders\/|\/Volumes\/|[A-Za-z]:\\|\\\\)/;
const secretText = /(?:TYPESAFE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|authorization:\s*bearer)/i;
```

Compute `artifactSha256` as `stableHash(bodyWithoutArtifactSha256)`, then validate it by recomputation in `parseRecordedDemoRun`.

Use `mkdir(join(outputRoot, runId), { recursive: true })` and the existing `writeJsonlExclusive` with one value per `<evaluator>.json`. A one-record JSONL document is also valid JSON and preserves the repository's existing atomic, exclusive publication behavior.

- [ ] **Step 5: Run focused and full tests**

Run:

```bash
npm run build && node --test dist/src/demo-record.test.js dist/src/demo.test.js dist/src/jev.test.js dist/src/reasoning.test.js
npm run check
```

Expected: all tests PASS.

- [ ] **Step 6: Commit the recorded-run contract**

```bash
git add src/demo-record.ts src/demo-record.test.ts src/demo.ts src/demo.test.ts src/demo-live.ts src/jev.ts src/jev.test.ts src/reasoning.ts src/reasoning.test.ts
git commit -m "feat: record immutable model demo runs"
```

---

### Task 3: Build and Validate the Public Dashboard Dataset

**Files:**
- Create: `src/dashboard.ts`
- Create: `src/dashboard.test.ts`
- Create: `test/fixtures/dashboard-runs/jev.json`
- Create: `test/fixtures/dashboard-runs/terra.json`
- Create: `test/fixtures/dashboard-runs/opus.json`
- Modify: `src/demo.ts`

**Interfaces:**
- Consumes: `DemoCase[]`, `RecordedDemoRun[]`, `parseRecordedDemoRun`, and the existing correctness semantics
- Produces:
  - `PublishedDemoData`
  - `buildPublishedDemoData(cases: readonly DemoCase[], runs: readonly RecordedDemoRun[], generatedAt: string): PublishedDemoData`
  - `writePublishedDemoData(path: string, data: PublishedDemoData): Promise<void>`

- [ ] **Step 1: Extract one reusable summary function with characterization tests**

Before moving logic, add to `src/demo.test.ts`:

```ts
test("summary keeps explicit errors in both denominators", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const results: DemoResult[] = cases.map((item) => ({
    caseId: item.caseId, evaluator: "jev", status: "valid", decision: item.expected,
    correct: true, latencyMs: 1, error: null
  }));
  results[0] = { ...results[0]!, status: "error", decision: null, correct: false, error: "service unavailable" };
  const summary = summarizeDemoResults(cases, results, ["jev"]);
  assert.equal(summary.jev.accuracy, 0.99);
  assert.equal(summary.jev.errors, 1);
  assert.ok(summary.jev.vulnerabilityRecall < 1);
});
```

Export this signature from `src/demo.ts` and make `runDemo` call it:

```ts
export function summarizeDemoResults(
  cases: readonly DemoCase[],
  results: readonly DemoResult[],
  evaluators: readonly DemoEvaluator[]
): Record<string, DemoSummary>;
```

Move the current `summary` calculation without changing its arithmetic.

- [ ] **Step 2: Write failing publication-gate tests**

Create `src/dashboard.test.ts`:

```ts
test("builder requires one Jev, Terra, and Opus run over one corpus", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns();
  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");
  assert.deepEqual(Object.keys(data.summary), ["jev", "terra", "opus"]);
  assert.equal(data.cases.length, 100);
  assert.equal(data.models.length, 3);
  assert.throws(() => buildPublishedDemoData(cases, runs.slice(0, 2), data.generatedAt), /requires jev, terra, and opus/);
  assert.throws(() => buildPublishedDemoData(cases, [...runs, runs[0]!], data.generatedAt), /duplicate evaluator/);
  assert.throws(() => buildPublishedDemoData(cases, [runs[0]!, { ...runs[1]!, corpusHash: "0".repeat(64) }, runs[2]!], data.generatedAt), /corpus hash mismatch/);
});

test("builder derives metrics from case results including failures", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const runs = await loadFixtureRuns();
  const data = buildPublishedDemoData(cases, runs, "2026-09-18T13:00:00.000Z");
  assert.equal(data.summary.jev.accuracy, runs[0]!.results.filter((row) => row.correct).length / 100);
  assert.equal(data.summary.jev.errors, runs[0]!.results.filter((row) => row.status === "error").length);
});
```

- [ ] **Step 3: Run the focused tests and verify they fail**

Run:

```bash
npm run build
```

Expected: FAIL because `src/dashboard.ts` and `summarizeDemoResults` do not exist.

- [ ] **Step 4: Implement the public dataset builder**

Create these core shapes in `src/dashboard.ts`:

```ts
export interface PublishedDemoData {
  schemaVersion: 1;
  generatedAt: string;
  corpusHash: string;
  caseCount: 100;
  recorded: true;
  synthetic: true;
  sourceArtifacts: Array<{ evaluator: DemoEvaluator; runId: string; artifactSha256: string }>;
  models: Array<{
    evaluator: DemoEvaluator;
    provider: string;
    modelId: string;
    runner: string;
    runnerVersion: string;
    recordedAt: string;
  }>;
  summary: Record<DemoEvaluator, DemoSummary>;
  cases: Array<{
    caseId: string;
    family: Family;
    state: Record<string, unknown>;
    expected: DemoDecision;
    results: Record<DemoEvaluator, DemoResult>;
  }>;
}
```

Validate exact evaluator membership with an ordered `const evaluators = ["jev", "terra", "opus"] as const`. Compare every run's `corpusHash` to `corpusHash(cases)`, require `caseCount === 100`, require `mode === "live-recorded"`, and map each case to exactly one result per evaluator. Call `summarizeDemoResults` independently for each run rather than trusting a stored aggregate.

Implement `writePublishedDemoData` as:

```ts
await mkdir(dirname(path), { recursive: true });
await writeFile(path, `${canonicalJson(data)}\n`, "utf8");
```

This output is a reproducible generated projection and may be rebuilt; only the source model-run artifacts are immutable.

- [ ] **Step 5: Add minimal complete fixture runs**

Create three one-line JSON files under `test/fixtures/dashboard-runs/` by using the production writer from a temporary generation command, then copy the resulting public artifacts into the fixture directory. The fixture runs must:

- cover all 100 current case IDs;
- use the current corpus hash;
- contain at least one correct, one incorrect, one insufficient-context, and one explicit error result across the three models;
- use provider `Fixture` only if `mode` is changed to a separate test-only parser input before publication; otherwise use the real provider/model metadata with clearly synthetic result values; and
- contain valid recomputed artifact hashes.

Never hand-edit the hashes.

- [ ] **Step 6: Run focused and full tests**

Run:

```bash
npm run build && node --test dist/src/dashboard.test.js dist/src/demo.test.js
npm run check
```

Expected: all tests PASS.

- [ ] **Step 7: Commit the public data builder**

```bash
git add src/demo.ts src/demo.test.ts src/dashboard.ts src/dashboard.test.ts test/fixtures/dashboard-runs
git commit -m "feat: build validated dashboard data"
```

---

### Task 4: Add CLI Recording and Build Commands

**Files:**
- Modify: `src/cli.ts`
- Create: `src/cli.test.ts`
- Modify: `package.json`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: live adapter construction, `writeRecordedDemoRuns`, `parseRecordedDemoRun`, `buildPublishedDemoData`, `writePublishedDemoData`
- Produces:
  - `demo-record --fixture <path> --models <list> --run-id <id> --output <dir>`
  - `dashboard-build --fixture <path> --run-dir <dir> --output <file>`
  - npm scripts `demo:record`, `dashboard:build`, and `dashboard:fixture`

- [ ] **Step 1: Write subprocess tests for command boundaries**

Create `src/cli.test.ts` using `spawn` with `shell: false`. Add tests that prove:

```ts
test("demo-record rejects missing credentials before creating output", async () => {
  const root = await mkdtemp(join(tmpdir(), "demo-record-cli-"));
  try {
    const result = await cli(["demo-record", "--fixture", "test/fixtures/demo-cases.json", "--models", "jev", "--run-id", "test", "--output", root], { TYPESAFE_API_KEY: "" });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /TYPESAFE_API_KEY is required/);
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("dashboard-build rejects two-model and mixed-corpus inputs", async () => {
  const result = await cli(["dashboard-build", "--fixture", "test/fixtures/demo-cases.json", "--run-dir", "test/fixtures/dashboard-runs-missing-opus", "--output", temporaryOutput]);
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /requires jev, terra, and opus/);
});
```

Also cover an invalid `--models` list, missing `--run-id`, deterministic replacement of an existing generated dashboard output, a complete offline fixture build, and error output that contains no environment values.

- [ ] **Step 2: Run the CLI tests and verify commands are absent**

Run:

```bash
npm run build && node --test dist/src/cli.test.js
```

Expected: FAIL because both commands are unknown.

- [ ] **Step 3: Refactor live adapter construction once**

Extract the existing live branch from `demo(values)` into:

```ts
async function liveAdapters(selected: readonly DemoEvaluator[], emptySnapshot: string, outputDirectory: string): Promise<DemoAdapter[]>;
```

Both `demo --live` and `demo-record` call this function. Keep credential validation before `mkdtemp` and before adapter creation. Do not create a second Jev or reasoning-adapter configuration.

- [ ] **Step 4: Implement `demo-record`**

Require `--run-id` and `--output`, load the same fixture as `demo`, build only selected adapters, call `runDemo(cases, adapters, "live")`, and write one artifact per selected evaluator:

```ts
const report = await runDemo(cases, adapters, "live");
return writeRecordedDemoRuns({
  cases,
  report,
  metadata: Object.fromEntries(adapters.map((adapter) => [adapter.name, adapter.metadata])) as Record<DemoEvaluator, EvaluatorMetadata>,
  runId: required(values, "run-id"),
  recordedAt: new Date().toISOString(),
  outputRoot: required(values, "output")
});
```

The writer must accept metadata for only the selected evaluators so Jev/Terra and Opus may be recorded in separate invocations under the same run directory.

- [ ] **Step 5: Implement `dashboard-build`**

Read exactly `jev.json`, `terra.json`, and `opus.json` from `--run-dir`, parse each with `parseRecordedDemoRun`, build data from the current fixture, then exclusively write `--output`. Create only the destination's parent directory. Return a compact receipt containing the output basename, corpus hash, and three source hashes.

- [ ] **Step 6: Add npm scripts and generated-file ignores**

Update `package.json`:

```json
"demo:record": "npm run build --silent && node dist/src/cli.js demo-record --fixture test/fixtures/demo-cases.json --output results/recorded",
"dashboard:build": "npm run build --silent && node dist/src/cli.js dashboard-build --fixture test/fixtures/demo-cases.json",
"dashboard:fixture": "npm run dashboard:build -- --run-dir test/fixtures/dashboard-runs --output dashboard/data/latest.json",
"dashboard:preview": "python3 -m http.server 4173 --directory dashboard"
```

Add to `.gitignore`:

```gitignore
.superpowers/
dashboard/data/latest.json
```

Do not ignore `results/recorded/`; selected live artifacts must be committable.

- [ ] **Step 7: Run command and regression checks**

Run:

```bash
npm run build && node --test dist/src/cli.test.js
npm run dashboard:fixture
test -s dashboard/data/latest.json
npm run check
```

Expected: all tests PASS and the fixture dashboard dataset is generated.

- [ ] **Step 8: Commit the CLI workflow**

```bash
git add src/cli.ts src/cli.test.ts package.json package-lock.json .gitignore
git commit -m "feat: add reproducible demo recording commands"
```

---

### Task 5: Build the Static Scoreboard-First Dashboard

**Files:**
- Create: `dashboard/index.html`
- Create: `dashboard/styles.css`
- Create: `dashboard/app.js`
- Create: `src/dashboard-app.test.ts`

**Interfaces:**
- Consumes: `dashboard/data/latest.json` matching `PublishedDemoData`
- Produces: a static responsive page with scorecards, Jev decision map, SVG comparison bars, confusion matrices, recorded replay, and case filters

- [ ] **Step 1: Write static dashboard contract tests**

Create `src/dashboard-app.test.ts`:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("dashboard explains recorded synthetic model comparison accessibly", async () => {
  const html = await readFile("dashboard/index.html", "utf8");
  const js = await readFile("dashboard/app.js", "utf8");
  const css = await readFile("dashboard/styles.css", "utf8");
  assert.match(html, /Jev.*System One/s);
  assert.match(html, /Terra.*OpenAI/s);
  assert.match(html, /Opus.*Anthropic/s);
  assert.match(html, /recorded/i);
  assert.match(html, /synthetic/i);
  assert.match(html, /<button[^>]*id="replay"/);
  assert.match(html, /<main/);
  assert.match(html, /<noscript>/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /:focus-visible/);
  assert.doesNotMatch(js, /fetch\((?!["']\.\/data\/latest\.json["'])/);
  assert.doesNotMatch(js, /TypeSafeClient|TYPESAFE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY/);
});
```

Add a second test asserting that filters are native labeled controls, the decision grid has an `aria-live` status, legends contain text labels, and accessible table containers exist for chart values.

- [ ] **Step 2: Run the dashboard contract test and verify files are absent**

Run:

```bash
npm run build
```

Expected: FAIL because the dashboard files do not exist.

- [ ] **Step 3: Create the semantic HTML shell**

Create `dashboard/index.html` with:

- a skip link and `<main>`;
- an eyebrow reading `100 synthetic cases · recorded model run`;
- clear evaluator definitions in visible copy;
- a recorded-run metadata region;
- one replay button labeled `Replay recorded run`;
- three scorecard containers;
- sections for decision map, comparison bars, confusion matrices, methodology, and case explorer;
- labeled native `<select>` controls for model, family, expected disposition, decision, correctness, and status;
- a case-list region;
- links to `data/latest.json`, the source repository, and `test/fixtures/demo-cases.json`; and
- `<noscript>` copy that still explains the method and links to the data.

Load only `styles.css` and `app.js`; use no CDN assets.

- [ ] **Step 4: Implement the technical scorecard visual system**

In `dashboard/styles.css`, use CSS custom properties for a restrained neutral background, ink, model accents, correct, incorrect, insufficient, and error states. Implement:

```css
.decision-grid { display:grid; grid-template-columns:repeat(10,minmax(1.5rem,1fr)); gap:.35rem; }
.scorecards { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1rem; }
@media (max-width: 760px) {
  .scorecards { grid-template-columns:1fr; }
  .decision-grid { grid-template-columns:repeat(5,minmax(1.5rem,1fr)); }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior:auto !important; animation-duration:.01ms !important; transition-duration:.01ms !important; }
}
:focus-visible { outline:3px solid var(--focus); outline-offset:3px; }
```

Every state style also includes a visible symbol or text abbreviation so color is not the only encoding.

- [ ] **Step 5: Implement rendering and filtering**

In `dashboard/app.js`, fetch only `./data/latest.json`, validate `schemaVersion === 1`, `recorded === true`, `synthetic === true`, and `caseCount === 100`, then render from the supplied case-level data.

Implement these named functions:

```js
function renderMetadata(data) {}
function renderScorecards(data) {}
function renderDecisionGrid(data, visibleCount = 100) {}
function renderComparisonBars(data) {}
function renderConfusionMatrices(data) {}
function renderCases(data, filters) {}
function selectedFilters() {}
function replayRecordedRun(data) {}
```

SVG bars must include `<title>` and textual values. Confusion matrices must be semantic HTML tables. Case evidence must be inserted with `textContent`, never `innerHTML`. Filter changes update the results count and case list without changing the source data.

- [ ] **Step 6: Implement honest recorded replay**

`replayRecordedRun` disables the button, resets the visible Jev cells and scorecards, then progressively reveals saved results with `requestAnimationFrame`. It must not call `fetch`, randomize decisions, or modify `data`.

Use:

```js
if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
  renderDecisionGrid(data, 100);
  renderScorecards(data);
  return;
}
```

Update an `aria-live="polite"` status with `Replaying recorded result N of 100` and finish with `Recorded replay complete`. Restore the button when complete.

- [ ] **Step 7: Run static tests and visually verify fixture data**

Run:

```bash
npm run dashboard:fixture
npm run build && node --test dist/src/dashboard-app.test.js
npm run dashboard:preview
```

Open `http://localhost:4173` and verify at 1440×900, 768×1024, and 390×844:

- all three scorecards appear before secondary charts;
- the 100-cell grid is legible and keyboard focus is visible;
- replay is explicitly recorded and honors reduced motion;
- model definitions and exact IDs are visible;
- filters change the visible case count correctly;
- long code evidence wraps or scrolls without breaking the layout; and
- error and insufficient-context results have text/symbol distinctions.

Stop the preview server after inspection.

- [ ] **Step 8: Run the full suite and commit**

Run:

```bash
npm run check
git diff --check
```

Expected: all tests PASS.

```bash
git add dashboard/index.html dashboard/styles.css dashboard/app.js src/dashboard-app.test.ts
git commit -m "feat: add recorded demo dashboard"
```

---

### Task 6: Add Reproducible GitHub Pages Publication

**Files:**
- Create: `.github/workflows/pages.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: a committed `results/recorded/<run-id>/{jev,terra,opus}.json` directory
- Produces: a manual GitHub Pages deployment of `dashboard/` after validation

- [ ] **Step 1: Add a test that the deployment remains manual and credential-free**

Extend `src/dashboard-app.test.ts`:

```ts
test("Pages deployment validates a selected committed run without provider credentials", async () => {
  const workflow = await readFile(".github/workflows/pages.yml", "utf8");
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /run_id:/);
  assert.match(workflow, /npm ci/);
  assert.match(workflow, /npm run check/);
  assert.match(workflow, /dashboard-build/);
  assert.match(workflow, /actions\/deploy-pages/);
  assert.doesNotMatch(workflow, /TYPESAFE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY/);
  assert.doesNotMatch(workflow, /pull_request:|push:/);
});
```

- [ ] **Step 2: Run the test and verify the workflow is missing**

Run:

```bash
npm run build
```

Expected: FAIL because `.github/workflows/pages.yml` does not exist.

- [ ] **Step 3: Create the manual Pages workflow**

Create `.github/workflows/pages.yml` with `workflow_dispatch.inputs.run_id` required as a string. Give only `contents: read`, `pages: write`, and `id-token: write` permissions. Use one deploy concurrency group.

The job steps are:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 24
    cache: npm
- run: npm ci
- run: npm run check
- run: npm run dashboard:build -- --run-dir "results/recorded/${{ inputs.run_id }}" --output dashboard/data/latest.json
- uses: actions/configure-pages@v5
- uses: actions/upload-pages-artifact@v3
  with:
    path: dashboard
- id: deployment
  uses: actions/deploy-pages@v4
```

Do not add provider secrets or run `demo:record` in Actions.

- [ ] **Step 4: Document the exact local and Claude handoff**

Update `README.md` so the demo-first flow is:

```bash
# Local Jev + Terra recording
export TYPESAFE_API_KEY='...'
npm run demo:record -- --models jev,terra --run-id 2026-09-18-public

# From the same checkout opened in Claude
npm run demo:record -- --models opus --run-id 2026-09-18-public

# Validate and preview all three saved runs
npm run dashboard:build -- --run-dir results/recorded/2026-09-18-public --output dashboard/data/latest.json
npm run dashboard:preview
```

Explain that the second command uses the pinned bounded Claude adapter rather than conversational context, that all three files must be reviewed before commit, and that Pages deployment is manually started with the matching `run_id`.

Add the eventual URL `https://robertzu43.github.io/system-one-security-triage/`, clearly marked unavailable until the first three-model run is deployed.

- [ ] **Step 5: Run verification**

Run:

```bash
npm run dashboard:fixture
npm run check
git diff --check
```

Expected: all tests PASS and fixture dashboard generation succeeds without credentials.

- [ ] **Step 6: Commit publication support**

```bash
git add .github/workflows/pages.yml README.md src/dashboard-app.test.ts
git commit -m "ci: publish validated demo dashboard"
```

---

### Task 7: Complete the Offline Acceptance Run

**Files:**
- Modify only if verification reveals a defect in files owned by Tasks 1–6

**Interfaces:**
- Consumes: the complete implementation
- Produces: evidence that the offline project is ready for separately authorized live recordings

- [ ] **Step 1: Remove generated local dashboard data and rebuild it**

Delete only the ignored generated file `dashboard/data/latest.json`, then run:

```bash
npm run dashboard:fixture
```

Expected: the file is regenerated from three fixture artifacts and contains `caseCount: 100`, `recorded: true`, and all three model entries.

- [ ] **Step 2: Run every offline check from a clean dependency install**

Run:

```bash
npm ci
npm run check
npm run demo
npm run dashboard:fixture
git diff --check
git status --short
```

Expected:

- 100-case fixture demo succeeds and says simulated adapters are not model results;
- all tests pass;
- dashboard fixture build succeeds;
- no tracked generated output changes; and
- only intentionally untracked live artifacts, if any, appear.

- [ ] **Step 3: Verify the publication boundary**

Run the production dashboard build against directories containing zero, two, and three fixture model files. The zero- and two-file commands must fail without creating output; the three-file command must succeed. Then rerun against one artifact whose copied `corpusHash` is changed; it must fail before output.

- [ ] **Step 4: Review the generated page manually**

Serve `dashboard/`, inspect desktop and mobile widths, activate every filter, replay the recorded run, navigate controls by keyboard, enable reduced motion, and open the raw JSON link. Confirm no network request occurs except the static JSON and local files.

- [ ] **Step 5: Commit any acceptance-only correction, otherwise leave the tree unchanged**

If the acceptance run required a correction, rerun Steps 1–4 and commit only that fix with a message naming the corrected behavior. If no correction was required, do not create an empty commit.

---

## Live Recording and First Publication Gate

This gate is intentionally outside automated implementation because it makes paid provider calls and requires the user's authenticated local Claude environment.

1. Choose a permanent run ID and ensure `results/recorded/<run-id>/` does not exist.
2. Run Jev and Terra once with `npm run demo:record -- --models jev,terra --run-id <run-id>`.
3. Open the same commit in Claude and run Opus once with `npm run demo:record -- --models opus --run-id <run-id>`.
4. Inspect all three artifact metadata blocks, case errors, model IDs, runner versions, corpus hashes, and hashes.
5. Run `npm run dashboard:build -- --run-dir results/recorded/<run-id> --output dashboard/data/latest.json`.
6. Preview and inspect the exact generated dashboard.
7. Commit the three immutable artifacts, not the ignored generated `latest.json`.
8. Push the commit and manually dispatch the Pages workflow with the same run ID.
9. Verify the deployed URL and compare its published source hashes with the committed artifacts.

Never rerun only unfavorable cases. A failed complete result remains in the artifact and dashboard. A wholly interrupted run gets a new run ID rather than replacement.
