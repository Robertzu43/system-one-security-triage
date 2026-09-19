# System One security triage

The current focus is a reproducible **100-case recorded demo** comparing three models on identical security evidence:

| Evaluator | What it is | Runner |
| --- | --- | --- |
| **Jev** | TypeSafe's System One decision model (`jev-1.13.0`) | `@typesafe-ai/sdk` |
| **Terra** | OpenAI model (`gpt-5.6-terra`) | Codex CLI |
| **Opus** | Anthropic Claude Opus (`claude-opus-4-6`) | Claude tooling |

Jev is the model making the first set of decisions—not the name of the benchmark or dashboard. The browser only renders saved JSON artifacts. It contains no provider credentials, backend, or runtime model calls.

> Dashboard URL: [https://robertzu43.github.io/system-one-security-triage/](https://robertzu43.github.io/system-one-security-triage/) — unavailable until the first complete three-model run is deployed.

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

## Record a real three-model run

Use one run ID for all three immutable artifacts:

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

The Opus command uses the repository's pinned, bounded Claude adapter; it does not use conversational context as model input. Each evaluator receives the same canonical evidence bytes. Missing usage or cost stays `null`, never zero.

Before committing, review all three files:

```text
results/recorded/2026-09-18-public/jev.json
results/recorded/2026-09-18-public/terra.json
results/recorded/2026-09-18-public/opus.json
```

They must contain the same corpus hash and complete coverage of all 100 cases. Artifacts are exclusive-write and reject credentials, absolute local paths, duplicates, missing cases, unknown cases, and invalid hashes.

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
