# System One security triage

The current focus is a reproducible **100-case recorded demo** comparing three models on identical security evidence:

| Evaluator | What it is | Runner |
| --- | --- | --- |
| **Jev** | TypeSafe's System One decision model (`jev-1.13.0`) | `@typesafe-ai/sdk` |
| **Terra** | OpenAI model (`gpt-5.6-terra`) | Codex CLI |
| **Opus** | Anthropic Claude Opus (`claude-opus-4-6`) | Claude tooling |

Jev is the model making the first set of decisions—not the name of the benchmark or dashboard. The browser only renders saved JSON artifacts. It contains no provider credentials, backend, or runtime model calls.

> Dashboard URL: [https://robertzu43.github.io/system-one-security-triage/](https://robertzu43.github.io/system-one-security-triage/)

> **Measurement status (2026-09-19).** Both recorded runs so far (`2026-09-19-public-v2` and `-v3`) were made on a corpus whose model-visible file paths contained the expected label and whose context-resolution flags marked the insufficient-context cases. The corpus is now label-neutral, so all three evaluators must be re-recorded before any number is cited. Read [MVP measurement validation](docs/superpowers/specs/2026-09-19-mvp-measurement-validation.md) first.

## The 100-case demo

The frozen synthetic TypeScript/Node.js corpus covers three vulnerability families and three expected outcomes:

| Family | Vulnerable | Safe | Insufficient context | Total |
| --- | ---: | ---: | ---: | ---: |
| Injection | 12 | 11 | 11 | 34 |
| Broken access control | 11 | 11 | 11 | 33 |
| SSRF | 11 | 11 | 11 | 33 |
| **Total** | **34** | **33** | **33** | **100** |

Model-visible evidence is label-neutral: span paths carry no disposition words, and the private `ledger.contextResolution` metadata is never sent to any evaluator. A loader check enforces this on every case.

Scoring:

- **Accuracy** scores the disposition and, for vulnerable cases, the vulnerability family. **Balanced accuracy** is the unweighted mean of per-class recall and leads the dashboard.
- **Vulnerability recall** counts vulnerable cases labeled vulnerable with any family. Recall with the family required, family accuracy, vulnerable precision, false-safe rate, and false-positive rate on safe cases are reported alongside.
- **Jev** answers one five-way typed Choice; the selected option is scored exactly like Terra's and Opus's structured answers, with no threshold in between. The full probability distribution is recorded and a multiclass Brier score is reported for Jev. It is not compared with any frontier-model confidence.
- Explicit errors remain incorrect and stay in every denominator.
- **Model latency** (p50/p95) times only the model request. End-to-end latency including CLI startup is recorded separately. Claude token counts include cache reads and writes; missing usage stays `null`.
- The builder refuses a run in which one evaluator returned a single outcome for every case; `--allow-degenerate` publishes it with a visible warning.

This is a descriptive, synthetic demo—not a statistically powered benchmark or a claim of general model superiority.

### Preview with saved fixture results

No credentials or paid model calls are needed:

```bash
npm install
npm run dashboard:fixture
npm run dashboard:preview
```

Open [http://localhost:4173](http://localhost:4173). The fixture results exercise the complete dashboard path and are visibly synthetic; they are not model benchmark results.

The older terminal summary remains available with `npm run demo`. It also uses explicitly simulated adapters.

## Record a real three-model run

The corpus hash changed when the fixture was de-leaked, so the committed `2026-09-19-public-v2` and `-v3` artifacts no longer validate and cannot be reused as controls. Record all three evaluators under one run ID (Terra and Opus need macOS, Codex CLI 0.147.0, and Claude Code 2.1.278):

```bash
export TYPESAFE_API_KEY='...'
export RUN_ID="$(date -u +%Y-%m-%d)-public-v4"

npm run demo:record -- --models jev,terra --run-id "$RUN_ID"
npm run demo:record -- --models opus --run-id "$RUN_ID"

npm run dashboard:build -- --run-dir "results/recorded/$RUN_ID" --output dashboard/data/latest.json
npm run dashboard:preview
```

Jev answers one direct five-way TypeSafe Choice and records the selected label, all five probabilities, and confidence. Each evaluator receives the same canonical evidence; Jev receives it as a JSON object, Terra and Opus embedded in their structured-output prompt. Missing usage or cost stays `null`, never zero.

### Refresh Jev only

Once a complete three-model run exists on the current corpus, Jev can be refreshed alone while Terra and Opus are retained as recorded controls. The dashboard discloses the mixed provenance.

```bash
JEV_RUN_ID="jev-choice-$(date -u +%Y%m%d-%H%M%S)"
npm run demo:record -- --models jev --run-id "$JEV_RUN_ID"
cp "results/recorded/$RUN_ID/terra.json" "results/recorded/$JEV_RUN_ID/terra.json"
cp "results/recorded/$RUN_ID/opus.json" "results/recorded/$JEV_RUN_ID/opus.json"
npm run dashboard:build -- --run-dir "results/recorded/$JEV_RUN_ID" --output dashboard/data/latest.json
```

Before committing, review all three files under `results/recorded/<run-id>/`. They must contain the same corpus hash and complete coverage of all 100 cases. Artifacts are exclusive-write and reject credentials, absolute local paths, duplicates, missing cases, unknown cases, and invalid hashes. If the build reports a degenerate run, inspect the per-case `choice` distributions before anything else.

## Publish on GitHub Pages

Commit the reviewed `results/recorded/<run-id>/` directory, push it, then manually run the **Publish recorded demo dashboard** workflow in GitHub Actions with the matching `run_id`.

The workflow runs the full test suite, rebuilds the public dataset from the three committed artifacts, and deploys only the static `dashboard/` directory. It has no provider secrets and cannot record new model results.

## Larger project: in progress

The larger goal is a reproducible security-triage benchmark using sanitized repository snapshots, Semgrep and AST discovery, immutable evidence packets, controlled Jev/Terra/Opus evaluation, cascade experiments, and statistical scoring.

Those foundations are actively being developed, but they are not the current published result. The 100-case recorded demo above is the runnable focus today:

- [MVP measurement validation](docs/superpowers/specs/2026-09-19-mvp-measurement-validation.md) — what the first runs got wrong and what remains
- [Jev direct-choice demo design](docs/superpowers/specs/2026-09-19-jev-direct-choice-demo-design.md)
- [Recorded dashboard design](docs/superpowers/specs/2026-09-18-recorded-demo-dashboard-design.md)
- [Larger benchmark design](docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md)
- [Controlled model comparison plan](docs/superpowers/plans/2026-09-18-controlled-model-comparison.md)
- [Controlled corpus preparation plan](docs/superpowers/plans/2026-09-18-controlled-corpus-preparation.md)

## Verification

```bash
npm run check
```

Tests and dashboard builds never make paid model calls.
