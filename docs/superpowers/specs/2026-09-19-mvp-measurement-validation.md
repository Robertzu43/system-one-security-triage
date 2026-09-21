# MVP measurement validation

Status: harness fixes implemented; re-recorded as `2026-09-19-public-v5` (three evaluators, five passes, 1,500 decisions); real-corpus work outstanding
Date: 2026-09-19

## Why this exists

The recorded 100-case runs (`2026-09-19-public-v2` and `-v3`) did not measure
bounded security-triage skill. A review of the fixture, the adapters, and the
published artifacts found problems that made every headline number
uninterpretable. This document records what was wrong, what changed, and what
still has to happen before a Jev-versus-frontier comparison can be defended in
the security field.

## What was wrong

1. **The label was in the evidence.** 91 of 100 span paths contained the word
   `vulnerable`, `safe`, or `insufficient` (for example
   `src/demo/access-safe-invoice-owner-query.ts`). Opus at 100/100 and Terra at
   92/100 cannot be read as triage performance, and the v3 direct-choice Jev run
   (71/100) saw the same paths.
2. **The insufficient-context class was decided by metadata.** The
   `contextResolution` block was part of the model-visible state and carried an
   `unresolved` value on exactly the 33 insufficient cases. In v2 the Jev router
   returned `insufficient_context` on that flag before reading Jev's answers.
3. **v2 relabeled Jev's uncertainty as abstention.** The v2 adapter mapped the
   policy outcome `needs_deep_review` to `insufficient_context` and stored no
   probabilities. The direct-choice design (see the Jev direct-choice demo design
   spec) fixed this: Jev now selects one of five outcomes and the full
   distribution is recorded. This document keeps that design.
4. **Jev received the evidence as a string.** The adapter passed pre-serialized
   JSON rather than the JSON object form TypeSafe documents for structured state.
5. **Latency was not like for like.** Jev latency was one SDK call. Terra and
   Opus latency included CLI spawn, a separate version-check subprocess, temp
   directory and sandbox setup, shown side by side as "Mean latency".
6. **Token accounting was wrong for Opus and absent for Terra.** Claude Code's
   JSON reports uncached input only; every Opus result recorded exactly 3 input
   tokens. Terra recorded no usage at all.

Smaller issues: vulnerability recall required the family to match, accuracy was
plain rather than balanced, and no test would have caught any of the above.

A diagnostic worth carrying forward from v3: Jev's direct Choice found 0 of 11
broken access control vulnerabilities while finding 12 of 12 injection and 9 of
11 SSRF, and its mean confidence was higher on correct answers than on wrong
ones. Whether that pattern survives on a label-neutral corpus is the first thing
the re-recording will show.

## What the first label-neutral recording showed (v4, Jev and Terra only)

Jev and Terra were recorded on the label-neutral corpus before Opus. The run was
not completed or committed because it exposed a ground-truth defect, but the
numbers are worth keeping:

| Metric | Jev | Terra |
| --- | ---: | ---: |
| Accuracy | 58 / 100 | 74 / 100 |
| Vulnerable recall | 16 / 34 | 24 / 34 |
| Safe recall | 10 / 33 | 25 / 33 |
| Insufficient-context recall | 32 / 33 | 25 / 33 |
| Safe called vulnerable | 3 | 1 |
| Vulnerable called safe | 0 | 0 |
| Broken access control vulnerable found | 1 / 11 | 2 / 11 |

On the leaking corpus the same models scored 71 (v3 Jev) and 92 (v2 Terra).

**Both models called almost every broken access control vulnerability
`insufficient_context`, and by the rubric they were right.** Those cases were a
single line such as `invoices.findById(req.params.invoiceId)`. Nothing in the
span ruled out an authorization middleware upstream, and the instructions say
missing code is not evidence that a control is absent. In v2 and v3 the case was
decidable only because the context flag said middleware was resolved. Once the
flag was removed, 10 of the 11 vulnerable access-control cases were
indistinguishable from the insufficient ones. That is a labeling defect, not a
model failure. Injection and SSRF did not have it because source and sink are
both in the span.

The fix: every broken access control case now shows two spans, the route
registration with its middleware chain and the handler body. A vulnerable case
shows authentication but no authorization on a request-controlled id. A safe case
shows the authorization decision in full, including the body of any middleware
it relies on. An insufficient case delegates authorization to a helper or policy
whose body is not shown. Span counts are uniform within the family so structure
does not leak the label. The corpus hash changed again; v4 is superseded and was
never committed.

## What changed

### Fixture (`test/fixtures/demo-cases.json`)

- Span paths are label-neutral (`src/demo/invoice-owner-query.ts`). Case IDs are
  unchanged and are never model-visible.
- `contextResolution` moved out of `state` into a private top-level `ledger`. It
  is excluded from the corpus hash and never sent to any evaluator.
- `loadDemoCases` runs `assertNoFixtureLeakage` on every case: no label words in
  paths, no `vulnerab|insufficient|cve-` in span text, no label-bearing keys in
  state, no case ID in state. A dedicated test covers the check itself.

The corpus hash changed, so every earlier recorded run is rejected by the
builder. That is the intended outcome; both run directories carry a
`SUPERSEDED.md`.

### Jev adapter (`src/demo-live.ts`, `src/jev.ts`)

- The direct five-way Choice from the direct-choice design is unchanged. No
  threshold, confidence cutoff, or router touches the selected option.
- Jev receives the canonical evidence as a JSON object.
- The adapter times the SDK call alone and reports it as `modelLatencyMs`.

### Metrics (`src/demo.ts`)

The summary now reports: accuracy, balanced accuracy, per-class recall,
vulnerability recall (disposition only) and with family, family accuracy,
vulnerable precision, false-safe rate on vulnerable cases, false-positive rate on
safe cases, error count, p50 and p95 end-to-end latency, p50 and p95 model-call
latency, token and cost sums, a multiclass Brier score for evaluators whose every
valid result carries a Choice distribution, and a `degenerate` flag set when
every result shares one outcome.

### Recording and publication (`src/demo-record.ts`, `src/dashboard.ts`, `src/cli.ts`)

- Results carry `modelLatencyMs`; older artifacts parse with `null`.
- `dashboard-build` refuses a run in which one evaluator returned a single
  outcome for all 100 cases. `--allow-degenerate` publishes it with a visible
  warning instead.
- Published data carries a `warnings` array (degenerate runs, explicit errors,
  missing usage, missing model-only latency) shown on the page.
- Provenance distinguishes a single three-model run (`direct-choice`) from a
  Jev-only refresh beside retained controls (`direct-choice-mixed`).

### Reasoning runner (`src/reasoning.ts`)

- `modelLatencyMs` times only the sandboxed CLI invocation.
- Claude usage sums `input_tokens`, `cache_read_input_tokens`, and
  `cache_creation_input_tokens`.

### Dashboard (`dashboard/`)

Balanced accuracy leads each scorecard; false-positive rate, false-safe rate,
errors, and model-latency p50 follow. The comparison table adds false-positive
and false-safe rates. Warnings render under the run strip. The method copy states
what the models did and did not see. The Choice probability display from the
direct-choice design is retained.

## What still has to happen

These items decide whether the comparison is valid in the field. None can be
done from fixture data.

1. **Re-record all three evaluators on the current corpus** under one run ID. Done: `2026-09-19-public-v5`.
   No earlier artifact can be reused as a control because the corpus hash
   changed twice: once to remove the label leak, once to make access-control
   cases decidable.
2. **Real corpus.** Vulnerable and patched pairs from the OpenSSF CVE Benchmark
   JavaScript and TypeScript cases, Semgrep false positives from the same
   repositories, and deliberate false-positive traps. Repository-disjoint
   splits. Around twenty or more repositories so the repository-clustered
   bootstrap in the design spec produces meaningful intervals. The synthetic 100
   stays as an offline smoke test. See the controlled corpus preparation plan.
3. **Pairwise scoring.** Add pairwise accuracy once vulnerable and patched pairs
   exist: a pair counts only when both halves are right.
4. **Selective-prediction view for Jev.** With the distribution recorded, report
   accuracy among covered against coverage at a confidence gate chosen on a
   calibration split, and a reliability plot. Never let the gate change the
   primary forced-choice result.
5. **Terra tool isolation.** Terra runs with approvals and sandbox bypassed and
   its tool count is not verified in demo mode; Opus runs with tools disabled.
   Either pin a Codex invocation that disables tools or report Terra as an
   agentic arm only.
6. **Second frontier arm with repository access.** That is how these models are
   used in practice and how SastBench and related work evaluate them. Report it
   separately from the bounded arm.
7. **Cost.** Compute cost per thousand decisions from provider usage, with Jev at
   the published input-only price and free output. Terra usage is still null.
8. **Repetitions and intervals.** Five repetitions per case (done in v5), paired
   repository-clustered bootstrap, the preregistered two-point margin, as the
   design spec already requires.

## Re-recording

```bash
export TYPESAFE_API_KEY='...'
./record-v5.sh "$(date -u +%Y-%m-%d)-public-v6"   # or by hand:
export RUN_ID="$(date -u +%Y-%m-%d)-public-v6"
npm run demo:record -- --models jev,terra,opus --repetitions 5 --run-id "$RUN_ID"
npm run dashboard:build -- --run-dir "results/recorded/$RUN_ID" --output dashboard/data/latest.json
```

If an evaluator returns one outcome for every case, the build fails. Inspect the
per-case `choice` distributions in `jev.json` before deciding whether the
criteria, the state, or the model is responsible. Do not publish with
`--allow-degenerate` unless the warning is the point of the publication.
