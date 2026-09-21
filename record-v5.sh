#!/bin/sh
# Records all three evaluators over the 100-case corpus, five passes each.
#
# Needs TYPESAFE_API_KEY in the environment; Codex and Claude Code auth is taken from their own
# config. Roughly 3.3 hours and about $40: Jev $0.01, Terra $13.81, Opus $25.80, measured per case
# from a two-case smoke run rather than estimated.
#
# All three must be recorded together: dashboard-build refuses a run directory missing any of them,
# so a partial run spends the money without producing anything publishable.
set -eu

cd "$(dirname "$0")"

[ -n "${TYPESAFE_API_KEY:-}" ] || { echo "TYPESAFE_API_KEY is not set" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is dirty; commit first so the run is reproducible" >&2; exit 1; }

RUN_ID="${1:-$(date -u +%Y-%m-%d)-public-v5}"

npm run build --silent
node dist/src/cli.js demo-record \
  --fixture test/fixtures/demo-cases.json \
  --models jev,terra,opus \
  --repetitions 5 \
  --run-id "$RUN_ID" \
  --output results/recorded

echo "recorded to results/recorded/$RUN_ID"
node dist/src/cli.js dashboard-build \
  --fixture test/fixtures/demo-cases.json \
  --run-dir "results/recorded/$RUN_ID" \
  --output dashboard/data/latest.json
