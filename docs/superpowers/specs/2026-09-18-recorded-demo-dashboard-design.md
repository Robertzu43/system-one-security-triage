# Recorded 100-Case Security-Triage Demo Dashboard

Status: approved design
Date: 2026-09-18

## Objective

Turn the current nine-case command-line demonstration into a public, reproducible 100-case demo that clearly compares decisions from Jev, Terra, and Opus.

The public dashboard replays immutable saved results. It never calls a model from the browser and never implies that replaying a run performs fresh inference. Visitors can inspect the exact synthetic evidence, expected label, recorded model decisions, run metadata, and source JSON behind every chart.

This remains a synthetic demonstration. It is not the repository's planned real-world security benchmark and must not be presented as evidence of general model superiority or production vulnerability-detection performance.

## Evaluators

The dashboard identifies each evaluator by provider, role, exact model ID, and runner:

- **Jev** is TypeSafe's System One decision model. It returns typed probabilities for independent security judgments and a scored exploitability rubric. Repository code converts those values into a disposition using a frozen routing policy.
- **Terra** is an OpenAI model executed through the pinned Codex CLI adapter.
- **Opus** is Anthropic's Claude Opus model executed through the pinned Claude tooling adapter.

The UI must not describe Jev as an application, framework, or generic rules engine. It must not treat Terra or Opus self-reported confidence as comparable with Jev probabilities.

## Scope

### Included

- 100 distinct, hand-labeled synthetic TypeScript/Node security-triage cases.
- Injection, broken access control, and SSRF.
- Vulnerable, safe, and insufficient-context dispositions.
- Separate immutable recorded runs for Jev, Terra, and Opus.
- A generated static dashboard with model scorecards, charts, recorded-run replay, and case-level inspection.
- GitHub Pages deployment after validation and tests pass.
- A documented Opus recording command that can be run after opening the repository in Claude.

### Excluded

- Browser-triggered model inference.
- A backend, database, authentication layer, or API-key handling in the deployed site.
- Runtime dependence on a model provider.
- Real repositories, CVEs, vulnerability exploitation, or claims about real-world benchmark performance.
- New UI or charting frameworks when native HTML, CSS, JavaScript, and SVG suffice.
- Automatic publication of partial Jev/Terra-only comparisons.

## Corpus

The committed fixture contains exactly 100 distinct cases:

| Family | Vulnerable | Safe | Insufficient context | Total |
| --- | ---: | ---: | ---: | ---: |
| Injection | 12 | 11 | 11 | 34 |
| Broken access control | 11 | 11 | 11 | 33 |
| SSRF | 11 | 11 | 11 | 33 |
| **Total** | **34** | **33** | **33** | **100** |

Every case has:

- a unique stable case ID;
- one declared vulnerability family;
- neutral, model-visible evidence state;
- one expected disposition;
- an expected family only when the disposition is `vulnerable`; and
- distinct evidence rather than a parameter-only variation of another case.

The fixture remains JSON so it is inspectable and receives the same canonical serialization already used by the demo. A corpus hash is computed over the canonical case collection and stored in every run artifact.

The repository and dashboard prominently label the fixture as a hand-curated synthetic demonstration corpus.

## Architecture

```text
100-case canonical fixture
          |
          +------ Jev recorder  ------ immutable Jev run
          +------ Terra recorder ----- immutable Terra run
          +------ Opus recorder  ------ immutable Opus run
                                                    |
                       artifact validation + corpus-hash agreement
                                                    |
                                      generated public dataset
                                                    |
                             static HTML/CSS/JS/SVG dashboard
                                                    |
                                          GitHub Pages deploy
```

The implementation extends the existing demo flow rather than creating a second scoring system. Case parsing and correctness rules remain shared. Dashboard metrics are calculated from validated case-level results, never copied from manually edited summary numbers.

## Recording workflow

The intended workflow is:

```bash
npm run demo:record -- --models jev,terra
npm run demo:record -- --models opus
npm run dashboard:build
```

The Opus command is designed to be invoked from the checked-out project after the user opens it in Claude. The recorder still uses the repository's pinned bounded adapter so Opus receives the same canonical evidence bytes as the other evaluators; conversational project context is not model evidence.

Each invocation writes one immutable artifact per selected model. Attempting to reuse an artifact path or run ID fails rather than replacing history. Credentials remain environment-only and are never serialized.

## Recorded artifact contract

Each model run records:

- schema version;
- run ID and UTC timestamp;
- evaluator name and provider;
- exact model ID and runner version;
- corpus hash and case count;
- mode `live-recorded`;
- aggregate start/end timing;
- one result per case, including status, normalized decision, correctness, latency, error, token usage, and defensible provider cost when available; and
- a hash covering the public artifact contents.

Raw provider envelopes may be retained only when they contain no credential, local absolute path, private configuration, or unrelated CLI output. The dashboard consumes the normalized public projection. Missing usage or cost stays `null`; it is never converted to zero.

All errors remain visible and remain in metric denominators. A model run is structurally publishable when it contains one terminal result for every case, including explicit error results.

## Publication manifest

The dashboard builder requires exactly one selected Jev artifact, one Terra artifact, and one Opus artifact. It rejects:

- missing evaluators;
- duplicate evaluator artifacts;
- mismatched corpus hashes or case counts;
- unknown cases, missing cases, or duplicate case results;
- unsupported schema versions;
- invalid decisions, families, metrics, or metadata; and
- a destination that would overwrite an immutable recorded run.

After validation, the builder generates one public `latest.json` containing model metadata, case-level normalized results, and recalculated summaries. A manifest identifies the three source artifact hashes. This makes every displayed result traceable to committed input files.

## Dashboard experience

The selected layout is scoreboard-first.

### Header and context

The opening copy answers three questions immediately:

1. What is being compared?
2. What kind of model is each evaluator?
3. Is this live or recorded?

A persistent recorded-run badge shows the run date and corpus hash. The primary action is labeled **Replay recorded run**, never **Run models** or **Run benchmark**.

### Scorecards

Jev, Terra, and Opus receive equal visual weight. Each scorecard shows:

- overall accuracy;
- vulnerability recall;
- errors;
- exact model ID;
- runner version; and
- recorded timestamp.

### Charts

The first chart is a 100-cell Jev decision map. Cells distinguish correct, incorrect, insufficient-context, and failed outcomes, with text/tooltips and a non-color legend.

Additional views include:

- grouped model accuracy and vulnerability-recall bars;
- per-family accuracy bars;
- a decision/confusion matrix for each evaluator; and
- recorded latency and token/cost fields where the artifacts provide comparable values.

Native SVG and accessible HTML tables provide the charts. No charting dependency is added.

### Recorded replay

Replay progressively reveals the already-saved decisions across the 100 cells and updates the scorecards. It is presentation only: replay does not fetch a provider, modify results, or recalculate different answers.

Reduced-motion users receive the completed state immediately. Replay controls support keyboard input and expose their state to assistive technology.

### Case explorer

Visitors can filter by evaluator, family, expected disposition, recorded decision, correctness, and error status. Each case shows:

- canonical evidence;
- expected label;
- each evaluator's recorded decision;
- status and error, if any;
- latency and usage when available; and
- the run and corpus identifiers.

The page links directly to the public generated JSON and the synthetic case fixture.

## Styling and accessibility

The visual direction is a precise technical scorecard rather than a marketing landing page. It uses restrained color, strong typography, visible evidence, and compact charts. Correctness is never communicated by color alone.

The dashboard must support:

- responsive narrow and wide layouts;
- semantic headings, tables, buttons, and status text;
- keyboard-accessible filters and replay controls;
- visible focus states;
- sufficient color contrast;
- reduced-motion preferences; and
- useful content when JavaScript is unavailable, including the methodology and links to artifacts.

## Hosting

The site is deployed as static files through GitHub Pages, targeting:

`https://robertzu43.github.io/system-one-security-triage/`

A GitHub Actions workflow installs locked dependencies, runs the repository checks, builds the dashboard, and deploys only the generated static directory. No provider credential is present in the deployment workflow because all live inference occurs before results are committed.

Publication waits until all three selected artifacts are present and valid. A case-level error inside a complete artifact remains visible but does not prevent publication.

## Failure handling

- Missing credentials fail a recording command before the first paid request.
- Invalid model selections fail before execution.
- A model error produces an explicit case error and stays in the denominator.
- Interrupted partial recordings are not publishable.
- Artifact collisions fail without replacement.
- Mixed corpus versions fail dashboard generation.
- Missing metrics display as unavailable rather than zero.
- Dashboard generation fails on any hand-authored aggregate that disagrees with recalculated case-level results.

## Verification

Automated checks cover:

- exactly 100 unique cases and the frozen family/disposition matrix;
- distinct canonical evidence hashes for all cases;
- artifact boundary parsing and secret/path rejection;
- immutable model-run publication;
- complete per-case result coverage, including errors;
- corpus-hash and model uniqueness gates;
- hand-calculated dashboard metric fixtures;
- agreement between CLI summaries and generated dashboard data;
- deterministic static generation;
- absence of provider calls from dashboard code;
- responsive dashboard rendering at representative viewport sizes;
- keyboard operation, reduced-motion behavior, and basic accessibility semantics; and
- a full offline fixture that builds the dashboard without credentials.

Live Jev, Terra, and Opus recordings are explicit, separately invoked operations. Automated tests and dashboard builds never make paid model calls.

## Acceptance criteria

The work is complete when:

1. The repository contains 100 distinct synthetic cases in the approved matrix.
2. Jev, Terra, and Opus can produce separate immutable artifacts over identical canonical evidence.
3. The dashboard builder refuses missing or mismatched model artifacts.
4. Every public metric is derived from visible case-level data.
5. The static dashboard implements the selected scoreboard-first layout, recorded replay, charts, and case explorer.
6. The UI clearly explains what Jev, Terra, and Opus are and that results are recorded.
7. The full offline verification suite passes without provider credentials.
8. A validated three-model recorded run can be deployed reproducibly to GitHub Pages.
