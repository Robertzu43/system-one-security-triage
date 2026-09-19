# System One security triage

A small, reproducible demonstration of one question: can Jev make the same bounded security-triage decisions as Terra and Opus when all three receive the same evidence JSON?

The frozen fixture has nine TypeScript/Node cases: one `vulnerable`, one `safe`, and one `insufficient_context` case for each of injection, broken access control, and SSRF. Accuracy scores the disposition and, for vulnerable cases, the vulnerability family.

## Run without credentials

```bash
npm install
npm run demo
```

This validates the complete comparison and scoring path with explicitly simulated adapters. Its output is not a model result.

## Run Jev versus Terra

Set a newly rotated TypeSafe key locally; do not reuse a key pasted into chat or commit it:

```bash
export TYPESAFE_API_KEY='...'
npm run demo:live -- --models jev,terra
```

Add Opus after the local Claude subscription is authenticated:

```bash
npm run demo:live -- --models jev,terra,opus
```

Every adapter receives the same canonical JSON string. Errors remain in the denominator. The report includes decision accuracy, vulnerability recall, failures, latency, and token/cost fields when the provider exposes them. Evidence localization is deliberately excluded because the current Jev primitive does not return comparable source-span selections.
Add `--details` after `--` to include every per-case decision.

## Claim boundary

This is a nine-case descriptive demonstration, not a statistically powered benchmark. Terra runs through Codex CLI in an empty read-only directory; that CLI does not prove that every agent tool is disabled. The larger OpenSSF/Juice Shop benchmark design remains in `docs/superpowers/`, but it is intentionally outside this MVP.
