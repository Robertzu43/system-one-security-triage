import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const dashboard = join(process.cwd(), "dashboard");

test("fixture data carries every comparison, waterfall, filter, and redacted decision field", async () => {
  const data = JSON.parse(await readFile(join(dashboard, "fixture-data.json"), "utf8")) as Record<string, unknown>;

  assert.equal(data.mode, "fixture");
  assert.deepEqual(data.filters, {
    families: ["all", "injection", "broken-access-control", "ssrf"],
    corpora: ["all", "public", "private"]
  });

  const strategies = data.strategies as Array<Record<string, Record<string, unknown>>>;
  assert.deepEqual(strategies.map((strategy) => strategy.id), ["jev-terra", "terra-all"]);
  for (const strategy of strategies) {
    for (const metric of ["recall", "cost", "latency"]) {
      assert.ok(strategy[metric]?.estimate, `${strategy.id}.${metric}.estimate`);
      assert.match(String(strategy[metric]?.interval), /–/);
    }
  }

  assert.deepEqual(Object.keys(data.semgrep as object), ["raw", "retained"]);
  assert.deepEqual(Object.keys(data.waterfall as object), ["candidate", "routed", "escalated", "finalAlert", "manualReview"]);

  const cases = data.cases as Array<Record<string, unknown>>;
  assert.deepEqual(cases.map((entry) => entry.decision), ["supported", "contradicted", "inconclusive"]);
  for (const entry of cases) {
    assert.match(String(entry.caseId), /^CASE-[A-Z0-9-]+$/);
    assert.match(String(entry.spanId), /^span_[a-z0-9_]+$/);
    assert.equal("source" in entry, false);
    assert.equal("secret" in entry, false);
  }
});

test("dashboard exposes accessible evidence landmarks and remains offline and redacted", async () => {
  const [html, script, fixture] = await Promise.all([
    readFile(join(dashboard, "index.html"), "utf8"),
    readFile(join(dashboard, "app.js"), "utf8"),
    readFile(join(dashboard, "fixture-data.json"), "utf8")
  ]);
  const bundle = `${html}\n${script}\n${fixture}`;

  for (const landmark of ["<header", "<nav", "<main", "<form", "<section", "<table", "<caption"]) {
    assert.ok(html.includes(landmark), `missing ${landmark}`);
  }
  for (const copy of [
    "NON-LIVE FIXTURE",
    "Jev → Terra",
    "Terra all",
    "Raw Semgrep",
    "Retained after Jev",
    "Public-corpus contamination",
    "Limitations",
    "supported",
    "contradicted",
    "inconclusive"
  ]) assert.ok(html.includes(copy), `missing visible copy: ${copy}`);

  assert.match(html, /<label[^>]+for="family-filter"/);
  assert.match(html, /<label[^>]+for="corpus-filter"/);
  assert.match(html, /:focus-visible/);
  assert.match(html, /prefers-reduced-motion:\s*reduce/);
  assert.match(script, /addEventListener\("change"/);
  assert.match(script, /renderCases/);
  assert.match(script, /renderWaterfall/);

  assert.doesNotMatch(bundle, /https?:\/\//i);
  assert.doesNotMatch(script, /\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/);
  assert.doesNotMatch(bundle, /(?:\/Users\/|\/private\/|[A-Z]:\\Users\\)/);
  assert.doesNotMatch(bundle, /(?:api[_-]?key|sk-ant-|secret|ledger)/i);
  assert.doesNotMatch(html, /<input[^>]+type=["']hidden["']/i);
});
