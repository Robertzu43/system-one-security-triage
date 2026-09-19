# System One security triage

The current focus is a reproducible **100-case recorded demo** comparing three models on identical security evidence:

| Evaluator | What it is | Runner |
| --- | --- | --- |
| **Jev** | TypeSafe's System One decision model (`jev-1.13.0`) | `@typesafe-ai/sdk` |
| **Terra** | OpenAI model (`gpt-5.6-terra`) | Codex CLI |
| **Opus** | Anthropic Claude Opus (`claude-opus-4-6`) | Claude tooling |

Jev is the model making the first set of decisions—not the name of the benchmark or dashboard. The browser only renders saved JSON artifacts. It contains no provider credentials, backend, or runtime model calls.

> Dashboard URL: [https://robertzu43.github.io/system-one-security-triage/](https://robertzu43.github.io/system-one-security-triage/)

## The 100-case demo

The frozen synthetic TypeScript/Node.js corpus covers three vulnerability families and three expected outcomes:

| Family | Vulnerable | Safe | Insufficient context | Total |
| --- | ---: | ---: | ---: | ---: |
| Injection | 12 | 11 | 11 | 34 |
| Broken access control | 11 | 11 | 11 | 33 |
| SSRF | 11 | 11 | 11 | 33 |
| **Total** | **34** | **33** | **33** | **100** |

Accuracy scores the disposition and, for vulnerable cases, the vulnerability family. Explicit errors remain incorrect and stay in every denominator. This is a descriptive, synthetic demo—not a statistically powered benchmark or a claim of general model superiority.

### Preview with saved fixture results

No credentials or paid model calls are needed:

```bash
npm install
npm run dashboard:fixture
npm run dashboard:preview
```

Open [http://localhost:4173](http://localhost:4173). The fixture results exercise the complete dashboard path and are visibly synthetic; they are not model benchmark results.

The older terminal summary remains available with `npm run demo`. It also uses explicitly simulated adapters.

## Refresh Jev while retaining the recorded controls

Jev now answers one direct five-way TypeSafe Choice and records the selected label, all five probabilities, and confidence. To refresh only Jev while keeping the existing Terra and Opus results:

```bash
export TYPESAFE_API_KEY='...'
JEV_RUN_ID="jev-choice-$(date -u +%Y%m%d-%H%M%S)"
npm run demo:record -- --models jev --run-id "$JEV_RUN_ID"

cp results/recorded/2026-09-19-public-v2/terra.json "results/recorded/$JEV_RUN_ID/terra.json"
cp results/recorded/2026-09-19-public-v2/opus.json "results/recorded/$JEV_RUN_ID/opus.json"

npm run dashboard:build -- --run-dir "results/recorded/$JEV_RUN_ID" --output dashboard/data/latest.json
npm run dashboard:preview
```

The copied Terra and Opus files remain byte-for-byte identical to their `2026-09-19-public-v2` artifacts. All three evaluated the same canonical evidence corpus, but only Jev was rerun with the new Choice criteria; the dashboard discloses this mixed recording provenance. Missing usage or cost stays `null`, never zero.

Before committing, review all three files:

```text
results/recorded/2026-09-19-public-v3/jev.json
results/recorded/2026-09-19-public-v3/terra.json
results/recorded/2026-09-19-public-v3/opus.json
```

They must contain the same corpus hash and complete coverage of all 100 cases. Artifacts are exclusive-write and reject credentials, absolute local paths, duplicates, missing cases, unknown cases, and invalid hashes.

To preview the already committed public v3 bundle without making model calls:

```bash
npm run dashboard:build -- --run-dir results/recorded/2026-09-19-public-v3 --output dashboard/data/latest.json
npm run dashboard:preview
```

## Publish on GitHub Pages

Commit the reviewed `results/recorded/<run-id>/` directory, push it, then manually run the **Publish recorded demo dashboard** workflow in GitHub Actions with the matching `run_id`.

The workflow runs the full test suite, rebuilds the public dataset from the three committed artifacts, and deploys only the static `dashboard/` directory. It has no provider secrets and cannot record new model results.

## Larger project: in progress

The larger goal is a reproducible security-triage benchmark using sanitized repository snapshots, Semgrep and AST discovery, immutable evidence packets, controlled Jev/Terra/Opus evaluation, cascade experiments, and statistical scoring.

Those foundations are actively being developed, but they are not the current published result. The 100-case recorded demo above is the runnable focus today:

- [Recorded dashboard design](docs/superpowers/specs/2026-09-18-recorded-demo-dashboard-design.md)
- [Larger benchmark design](docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md)
- [Controlled model comparison plan](docs/superpowers/plans/2026-09-18-controlled-model-comparison.md)
- [Controlled corpus preparation plan](docs/superpowers/plans/2026-09-18-controlled-corpus-preparation.md)

## Verification

```bash
npm run check
```

Tests and dashboard builds never make paid model calls.
