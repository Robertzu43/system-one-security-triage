import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("dashboard explains recorded synthetic model comparison accessibly", async () => {
  const html = await readFile("dashboard/index.html", "utf8");
  const js = await readFile("dashboard/app.js", "utf8");
  const css = await readFile("dashboard/styles.css", "utf8");
  const readme = await readFile("README.md", "utf8");
  assert.match(html, /Jev.*System One/s);
  assert.match(html, /Terra.*OpenAI/s);
  assert.match(html, /Opus.*Anthropic/s);
  assert.match(html, /recorded/i);
  assert.match(html, /synthetic/i);
  assert.match(html, /id="provenance-note"/);
  assert.match(html, /<main/);
  assert.match(html, /<noscript>/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /--surface:\s*#101210/);
  assert.match(css, /--signal:\s*#caff4a/);
  assert.match(css, /linear-gradient\([^;]*rgba\(202,255,74/);
  assert.match(css, /\.choice-probabilities\s*\{[^}]*grid-column:\s*1\s*\/\s*-1/s);
  assert.doesNotMatch(js, /fetch\((?!["']\.\/data\/latest\.json["'])/);
  assert.doesNotMatch(js, /TypeSafeClient|TYPESAFE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY/);
  assert.match(js, /Choice confidence/);
  assert.doesNotMatch(readme, /demo:record[^\n]*--run-id 2026-09-19-public-v3/);
  assert.match(readme, /JEV_RUN_ID/);
});

test("dashboard controls and chart tables have semantic fallbacks", async () => {
  const html = await readFile("dashboard/index.html", "utf8");
  for (const id of ["model-filter", "family-filter", "expected-filter", "decision-filter", "correct-filter", "status-filter"]) {
    assert.match(html, new RegExp(`<label[^>]*for="${id}"`));
    assert.match(html, new RegExp(`<select[^>]*id="${id}"`));
  }
  assert.match(html, /class="table-scroll"[^>]*tabindex="0"/);
  assert.match(html, /<table/);
});

