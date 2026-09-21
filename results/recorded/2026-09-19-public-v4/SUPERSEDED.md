# Superseded: 2026-09-19-public-v4

This run is retired. Do not publish it or compare it with any later run.

## Why

v4 was recorded against a corpus that has since been corrected in two ways that change what the
numbers mean:

1. **Sixteen cases were undecidable.** Their label was `vulnerable` or `safe`, but the evidence
   shown to the model did not contain the fact that settles it — that fact lived only in the
   private `ledger`. The instructions tell every evaluator to answer `insufficient_context` when a
   required fact is not shown, so models followed the rule and were scored wrong for it. Nine of
   the nine broken-access-control failures in this run come from that defect, and both evaluators
   failed the same cases the same way.

2. **Span paths carried the label.** Six repeated path tokens were fully label-pure — `allowlist`,
   `owner` and `query` appeared only on safe cases, `policy` only on insufficient-context ones,
   `url` and `order` only on vulnerable ones. Paths are now `src/demo/case-NNN.ts`, and
   `assertNoPathLabelSignal` fails the build if any repeated token concentrates in one label again.

The corpus hash changed accordingly, so `dashboard-build` already refuses to mix this run with a
current one. This file records why, for anyone reading the directory directly.

## What was measured here

Jev 58/100, Terra 74/100, no Opus run. Those figures are not a model comparison: they substantially
measure how willing each model was to follow the stated abstention rule against labels that
punished it.

## Replacement

Re-record all three evaluators against the corrected corpus in one run.
