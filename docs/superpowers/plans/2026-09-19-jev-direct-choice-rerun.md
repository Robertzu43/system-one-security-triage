# Jev Direct-Choice Rerun Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace only the demo's threshold-routed Jev evaluation with one five-option Choice, preserve its probabilities, and record Jev again over the existing 100 cases without rerunning Terra or Opus.

**Architecture:** Keep the larger triage pipeline's existing Noul/Score Jev judgment and router unchanged. Add a demo-only Choice judgment beside it, carry the validated Choice through the existing `DemoDecision` and recorded-artifact path, and render it in the case explorer. Assemble a new publication directory from the new Jev artifact plus byte-identical copies of the existing Terra and Opus artifacts.

**Tech Stack:** TypeScript 5.9, Node.js 24 test runner, `@typesafe-ai/sdk` 0.6.0, static HTML/CSS/JavaScript, immutable JSON artifacts.

**Spec:** `docs/superpowers/specs/2026-09-19-jev-direct-choice-demo-design.md`

## Global Constraints

- The frozen corpus remains exactly `test/fixtures/demo-cases.json` with 100 cases and its existing corpus hash.
- Jev uses exactly one Choice with `vulnerable_injection`, `vulnerable_broken_access_control`, `vulnerable_ssrf`, `safe`, and `insufficient_context`.
- The selected Choice is the final classification; no risk or confidence threshold may change it.
- The Choice must contain exactly five finite probabilities in `[0,1]`, summing within `0.02` of one, and the selected option must be one of the maxima.
- The existing `2026-09-19-public-v2` Terra and Opus artifacts are not modified or regenerated.
- The existing main Jev Noul/Score pipeline and router remain unchanged.
- Browser code reads committed JSON only and never receives provider credentials.

## Review Focus

- A Choice with a missing, extra, negative, or non-finite probability must become an explicit Jev error.
- A selected label below another label's probability must be rejected; tied maxima must be accepted.
- A low-confidence valid Choice must retain its selected outcome rather than becoming `insufficient_context`.
- Old Terra and Opus decisions with no `choice` field must still parse and publish unchanged.
- The new Jev label, disposition, and family must remain mutually consistent through recording and dashboard generation.

---

### Task 1: Add the probability-bearing demo decision contract

**Files:**
- Modify: `src/demo.ts`
- Test: `src/demo.test.ts`
- Test: `src/demo-record.test.ts`
- Test: `src/dashboard.test.ts`

**Interfaces:**
- Produces: `DemoChoiceLabel`, `DemoChoice`, `parseDemoChoice(value, label)`, and `decisionForChoice(selected)`.
- Extends: `DemoDecision` with optional `choice?: DemoChoice` while leaving old decisions valid.

- [ ] **Step 1: Write failing parser and mapping tests**

Add a test using this hand-checked valid Choice:

```ts
const choice = {
  selected: "vulnerable_injection",
  confidence: 0.82,
  probabilities: {
    vulnerable_injection: 0.86,
    vulnerable_broken_access_control: 0.02,
    vulnerable_ssrf: 0.01,
    safe: 0.06,
    insufficient_context: 0.05
  }
};

assert.deepEqual(parseDemoDecision({ disposition: "vulnerable", family: "injection", choice }, "decision"), {
  disposition: "vulnerable",
  family: "injection",
  choice
});
assert.deepEqual(decisionForChoice("safe"), { disposition: "safe", family: null });
assert.deepEqual(decisionForChoice("insufficient_context"), { disposition: "insufficient_context", family: null });
```

Add separate rejection assertions for an extra probability key, a sum of `1.6`, a non-maximal selected option, and a Choice whose selected label maps to a different decision family. Add an acceptance assertion for tied maximal probabilities and for confidence `0.1`, proving low confidence is preserved.

In `src/demo-record.test.ts`, put the same Choice on the first valid Jev decision, write the artifact, parse it again, and assert the parsed decision's `choice` deep-equals the input. In `src/dashboard.test.ts`, add the Choice to a Jev run result before calling `buildPublishedDemoData` and assert `data.cases[0].results.jev.decision?.choice` deep-equals it.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test dist/src/demo.test.js dist/src/demo-record.test.js dist/src/dashboard.test.js`

Expected: TypeScript fails because the Choice types and helpers do not exist.

- [ ] **Step 3: Implement the minimum shared Choice contract**

In `src/demo.ts`, define the five labels once, map them with an exhaustive `switch`, and parse the optional object:

```ts
export type DemoChoiceLabel = "vulnerable_injection" | "vulnerable_broken_access_control" | "vulnerable_ssrf" | "safe" | "insufficient_context";

export interface DemoChoice {
  selected: DemoChoiceLabel;
  confidence: number;
  probabilities: Readonly<Record<DemoChoiceLabel, number>>;
}

export function decisionForChoice(selected: DemoChoiceLabel): Pick<DemoDecision, "disposition" | "family"> {
  switch (selected) {
    case "vulnerable_injection": return { disposition: "vulnerable", family: "injection" };
    case "vulnerable_broken_access_control": return { disposition: "vulnerable", family: "broken_access_control" };
    case "vulnerable_ssrf": return { disposition: "vulnerable", family: "ssrf" };
    case "safe": return { disposition: "safe", family: null };
    case "insufficient_context": return { disposition: "insufficient_context", family: null };
  }
}
```

`parseDemoChoice` must enforce the exact key set, numeric bounds, `0.02` sum tolerance, maximal selection with ties allowed, and confidence bounds. `parseDemoDecision` must preserve `choice` and reject a mismatch between `decisionForChoice(choice.selected)` and the surrounding disposition/family.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm run build && node --test dist/src/demo.test.js dist/src/demo-record.test.js dist/src/dashboard.test.js`

Expected: all three focused test files pass; old decisions without a Choice still round-trip.

- [ ] **Step 5: Commit the contract**

```bash
git add src/demo.ts src/demo.test.ts src/demo-record.test.ts src/dashboard.test.ts
git commit -m "feat: preserve Jev Choice decisions"
```

### Task 2: Replace the demo-only Jev router with one Choice

**Files:**
- Modify: `src/jev.ts`
- Modify: `src/demo-live.ts`
- Modify: `src/cli.ts`
- Test: `src/jev.test.ts`
- Test: `src/demo.test.ts`

**Interfaces:**
- Consumes: `parseDemoChoice(value, label)` and `decisionForChoice(selected)` from Task 1.
- Produces: `judgeDemoWithJev(state, client): Promise<JevDemoJudgment>`.
- Preserves: existing `judgeWithJev`, `JevJudgment`, router configuration, and non-demo pipeline behavior.

- [ ] **Step 1: Write a failing exact-request test for the demo Choice**

Add a client double returning the complete documented Choice response shape:

```ts
{
  model: "jev-1.13.0",
  usage: { input_tokens: 10, output_tokens: 2 },
  answers: {
    classification: {
      type: "choice",
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
}
```

Assert that `judgeDemoWithJev` sends the unchanged canonical state, model `jev-1.13.0`, and exactly one `classification` question of type `choice`. Assert that its five criteria define vulnerability, injection, broken access control, SSRF, safety, and missing evidence, and that the returned judgment preserves model, usage, selected label, confidence, and all probabilities.

Add focused tests proving malformed keys, an invalid sum, and a non-maximal selection become `kind: "abstain"`, while tied maxima and low confidence remain valid judgments.

- [ ] **Step 2: Run the Jev test and verify RED**

Run: `npm run build && node --test dist/src/jev.test.js`

Expected: TypeScript fails because `judgeDemoWithJev` does not exist.

- [ ] **Step 3: Implement the demo-only Choice call**

Import `choice` alongside the existing primitives in `src/jev.ts`. Add one `classification` question whose structured instructions say to classify only from shown evidence and whose criteria use these meanings:

```ts
const demoCriteria = {
  vulnerable_injection: "Shown evidence establishes untrusted influence over executable command, query, expression, template, interpreter, or equivalent syntax; the path reaches the sensitive operation; no effective shown control blocks it; and security impact is plausible.",
  vulnerable_broken_access_control: "Shown evidence establishes that an actor can perform an operation or access a resource without the authorization required for that actor, operation, or resource.",
  vulnerable_ssrf: "Shown evidence establishes that an actor can influence a server-side request to reach an unintended destination or network resource without an effective shown destination restriction.",
  safe: "The relevant tested path is shown and an effective shown control prevents the tested vulnerability. Missing code or an unshown helper is not evidence of safety.",
  insufficient_context: "Evidence required to establish vulnerability or safety is not shown, including a hidden helper, middleware, sanitizer, authorization check, upstream data flow, destination policy, or call path."
} as const;
```

Validate the envelope and pass the answer through `parseDemoChoice`. Return explicit abstentions with sanitized error messages through the existing `abstain` helper. Do not alter the current `questions` object or `judgeWithJev` used by the larger pipeline.

- [ ] **Step 4: Run the Jev test and verify GREEN**

Run: `npm run build && node --test dist/src/jev.test.js`

Expected: all `jev.test.js` tests pass, including the unchanged Noul/Score tests.

- [ ] **Step 5: Write a failing adapter test proving direct mapping**

Replace the demo adapter fixture's eleven Noul/Score answers with one direct Choice judgment. Assert that a low-confidence `vulnerable_ssrf` selection returns:

```ts
{
  disposition: "vulnerable",
  family: "ssrf",
  inputTokens: 7,
  outputTokens: 3,
  choice: {
    selected: "vulnerable_ssrf",
    confidence: 0.1,
    probabilities: {
      vulnerable_injection: 0.1,
      vulnerable_broken_access_control: 0.1,
      vulnerable_ssrf: 0.3,
      safe: 0.25,
      insufficient_context: 0.25
    }
  }
}
```

This test must fail while `createJevDemoAdapter` still invokes the threshold router.

- [ ] **Step 6: Run the adapter test and verify RED**

Run: `npm run build && node --test dist/src/demo.test.js`

Expected: the live-adapter test fails because the old adapter expects `answers` and routes with thresholds.

- [ ] **Step 7: Wire the direct judgment into the demo only**

Change `createJevDemoAdapter` to accept `JevDemoJudgment`, map `choice.selected` with `decisionForChoice`, and attach the Choice and usage fields. Remove the demo-only router configuration and `jevFamily`; do not remove `src/router.ts` or any main-pipeline use.

In `src/cli.ts`, import `judgeDemoWithJev` and use it only inside `liveAdapters` for the Jev demo adapter.

- [ ] **Step 8: Run the focused tests and verify GREEN**

Run: `npm run build && node --test dist/src/jev.test.js dist/src/demo.test.js dist/src/pipeline.test.js dist/src/router.test.js`

Expected: all focused tests pass, including the unchanged pipeline/router coverage.

- [ ] **Step 9: Commit the direct demo path**

```bash
git add src/jev.ts src/jev.test.ts src/demo-live.ts src/demo.test.ts src/cli.ts
git commit -m "feat: classify demo cases with Jev Choice"
```

### Task 3: Preserve and explain Choice data in artifacts and the dashboard

**Files:**
- Modify: `dashboard/app.js`
- Modify: `dashboard/index.html`
- Modify: `src/dashboard-app.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: optional `DemoDecision.choice` from Task 1.
- Produces: recorded and published Jev results retaining the Choice object; visible mixed-run provenance; per-case probability text.

- [ ] **Step 1: Write failing dashboard behavior assertions**

Extend `src/dashboard-app.test.ts` to require a visible statement that Jev alone was rerun and to require the browser script's user-visible label `Choice confidence`. Keep the existing no-provider-credentials and single-fetch assertions.

- [ ] **Step 2: Run the dashboard test and verify RED**

Run: `npm run build && node --test dist/src/dashboard-app.test.js`

Expected: the test fails because neither the mixed-provenance note nor the Choice probability line exists.

- [ ] **Step 3: Add the smallest dashboard rendering and disclosure**

In each valid Jev case row in `dashboard/app.js`, append one text line when `result.decision.choice` exists:

```text
Choice confidence 82% · injection 86% · broken access control 2% · SSRF 1% · safe 6% · insufficient context 5%
```

Use `textContent` through the existing `element` helper. Do not render raw HTML or add provider calls.

In `dashboard/index.html`, replace the simultaneous-run implication with a visible note: Jev was rerun with one direct five-way Choice; Terra and Opus are retained recorded controls from the earlier run over the same corpus.

Update `README.md` with the exact Jev-only command and explain that the publication bundle reuses unchanged Terra and Opus artifacts.

- [ ] **Step 5: Run dashboard checks**

Run: `npm run build && node --test dist/src/demo-record.test.js dist/src/dashboard.test.js dist/src/dashboard-app.test.js`

Expected: all focused dashboard and artifact tests pass.

- [ ] **Step 6: Commit dashboard support**

```bash
git add dashboard/app.js dashboard/index.html src/dashboard-app.test.ts README.md
git commit -m "feat: show Jev Choice probabilities"
```

### Task 4: Record only Jev and assemble the reviewed publication bundle

**Files:**
- Create: `results/recorded/2026-09-19-public-v3/jev.json`
- Copy unchanged: `results/recorded/2026-09-19-public-v3/terra.json`
- Copy unchanged: `results/recorded/2026-09-19-public-v3/opus.json`

**Interfaces:**
- Consumes: the live `TYPESAFE_API_KEY` from the operator's local shell and the committed v2 Terra/Opus artifacts.
- Produces: one complete offline publication directory accepted by the existing dashboard builder.

- [ ] **Step 1: Run the full offline verification before spending a live call**

Run: `npm run check`

Expected: build succeeds, all tests pass, and `git diff --check` reports no errors.

- [ ] **Step 2: Verify the credential is present without printing it**

Run: `test -n "$TYPESAFE_API_KEY" && echo "TypeSafe credential available"`

Expected: `TypeSafe credential available`.

- [ ] **Step 3: Run one paid smoke case through the compiled direct Choice**

Run:

```bash
node --input-type=module -e 'import { TypeSafeClient } from "@typesafe-ai/sdk"; import { loadDemoCases } from "./dist/src/demo.js"; import { judgeDemoWithJev } from "./dist/src/jev.js"; import { canonicalJson } from "./dist/src/jsonl.js"; const [item] = await loadDemoCases("test/fixtures/demo-cases.json"); const result = await judgeDemoWithJev(canonicalJson(item.state), new TypeSafeClient({ timeout: 30000, retry: { maxRetries: 0 }, logLevel: "off" })); console.log(JSON.stringify(result)); if (result.kind !== "judgment") process.exitCode = 1;'
```

Expected: one `kind: "judgment"` result with a five-key Choice distribution and no router output.

- [ ] **Step 4: Record the full Jev run once**

Run:

```bash
npm run demo:record -- --models jev --run-id 2026-09-19-public-v3
node -e 'const x=require("./results/recorded/2026-09-19-public-v3/jev.json"); if (x.caseCount!==100 || x.results.length!==100 || x.results.some(r=>r.status!=="valid" || !r.decision?.choice)) process.exit(1); console.log("100 valid Jev Choice results");'
```

Expected: one immutable `jev.json` and `100 valid Jev Choice results`. If either command fails, inspect the explicit error and do not copy controls or publish an incomplete directory.

- [ ] **Step 5: Reuse the recorded controls byte-for-byte**

Run:

```bash
cp results/recorded/2026-09-19-public-v2/terra.json results/recorded/2026-09-19-public-v3/terra.json
cp results/recorded/2026-09-19-public-v2/opus.json results/recorded/2026-09-19-public-v3/opus.json
cmp results/recorded/2026-09-19-public-v2/terra.json results/recorded/2026-09-19-public-v3/terra.json
cmp results/recorded/2026-09-19-public-v2/opus.json results/recorded/2026-09-19-public-v3/opus.json
```

Expected: both `cmp` commands exit `0` with no output.

- [ ] **Step 6: Build and inspect the offline dashboard dataset**

Run:

```bash
npm run dashboard:build -- --run-dir results/recorded/2026-09-19-public-v3 --output dashboard/data/latest.json
node -e 'const d=require("./dashboard/data/latest.json"); const jev=d.cases.map(x=>x.results.jev); if (jev.length!==100 || jev.some(x=>x.status!=="valid" || !x.decision.choice)) process.exit(1); console.log(JSON.stringify(d.summary));'
```

Expected: the builder succeeds; the validation exits `0`; the printed summary contains Jev, Terra, and Opus.

- [ ] **Step 7: Preview and manually verify one case**

Run: `npm run dashboard:preview`

Open `http://localhost:4173`, expand one case, and confirm that Jev shows the selected outcome, Choice confidence, and all five probabilities while Terra and Opus show their retained decisions. Confirm the mixed-recording note is visible.

- [ ] **Step 8: Run final verification and inspect scope**

Run:

```bash
npm run check
git status --short
git diff --stat HEAD
```

Expected: all checks pass; only the planned code, docs, tests, and `2026-09-19-public-v3` artifacts are present. The untracked failed `results/recorded/2026-09-19-public/` directory remains excluded.

- [ ] **Step 9: Commit and push the reviewed result**

```bash
git add docs/superpowers/specs/2026-09-19-jev-direct-choice-demo-design.md docs/superpowers/plans/2026-09-19-jev-direct-choice-rerun.md results/recorded/2026-09-19-public-v3
git commit -m "data: record direct-choice Jev demo"
git push origin codex/recorded-demo-dashboard
git push https://github.com/Robertzu43/system-one-security-triage.git HEAD:codex/recorded-demo-dashboard
```

Do not trigger GitHub Pages until the recorded Jev results and the generated local dashboard have been reviewed.
