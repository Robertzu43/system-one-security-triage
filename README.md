# Jev vs Terra vs Opus: nine-case security-triage demo

This repository currently focuses on a small, reproducible demonstration: can Jev make the same bounded security-triage decisions as Terra and Opus when all three receive identical evidence JSON?

The demo contains nine TypeScript/Node cases across three vulnerability families:

| Family | Vulnerable | Safe | Insufficient context |
| --- | --- | --- | --- |
| Injection | 1 | 1 | 1 |
| Broken access control | 1 | 1 | 1 |
| SSRF | 1 | 1 | 1 |

Accuracy scores the disposition and, for vulnerable cases, the vulnerability family. This is a descriptive demo, not a statistically powered benchmark.

## Run the demo without credentials

```bash
npm install
npm run demo
```

This exercises the complete comparison and scoring path with explicitly simulated adapters. It verifies the harness; its output is not a model result.

Add `--details` to include every per-case decision:

```bash
npm run demo -- --details
```

## Run the live comparison

Set a newly rotated TypeSafe key locally; do not reuse a key pasted into chat or commit it:

```bash
export TYPESAFE_API_KEY='...'
npm run demo:live -- --models jev,terra
```

Add Opus after the local Claude subscription is authenticated:

```bash
npm run demo:live -- --models jev,terra,opus
```

Every adapter receives the same canonical JSON string. Errors remain in the denominator. The report includes decision accuracy, vulnerability recall, failures, latency, and token/cost fields when the provider exposes them. Evidence localization is excluded because the current Jev primitive does not return comparable source-span selections.

## Larger project: in progress

The long-term project is a reproducible security-triage benchmark with sanitized repository snapshots, Semgrep and AST candidate discovery, immutable evidence packets, controlled Jev/Terra/Opus evaluation, cascade experiments, statistical scoring, and a static report.

That larger benchmark is actively being developed, but it is not the current runnable result. Its approved design and implementation roadmaps live here:

- [Benchmark design](docs/superpowers/specs/2026-09-18-system-one-security-triage-design.md)
- [Controlled model comparison plan](docs/superpowers/plans/2026-09-18-controlled-model-comparison.md)
- [Controlled corpus preparation plan](docs/superpowers/plans/2026-09-18-controlled-corpus-preparation.md)
- [Original implementation plan](docs/superpowers/plans/2026-09-18-system-one-security-triage.md)

The supporting benchmark modules already in `src/` are foundations for that work. They should not be mistaken for a completed or published benchmark.

## Current claim boundary

The nine cases are intentionally small and hand-curated. They demonstrate a controlled comparison workflow; they do not establish general model superiority, production security coverage, or performance on real-world vulnerability distributions.

Terra runs through Codex CLI in an empty read-only directory, but that CLI does not prove that every agent tool is disabled. Live results should therefore be reported as demo results, not primary benchmark findings.
