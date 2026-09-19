import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertNoFixtureLeakage, decisionForChoice, loadDemoCases, parseDemoDecision, runDemo, summarizeDemoResults, type DemoAdapter, type DemoCase, type DemoDecision, type DemoResult } from "./demo.js";
import { createJevDemoAdapter, createReasoningDemoAdapter } from "./demo-live.js";
import { stableHash } from "./jsonl.js";

const directChoice = {
  selected: "vulnerable_injection",
  confidence: 0.82,
  probabilities: {
    vulnerable_injection: 0.86,
    vulnerable_broken_access_control: 0.02,
    vulnerable_ssrf: 0.01,
    safe: 0.06,
    insufficient_context: 0.05
  }
} as const;

test("demo decisions preserve a valid direct Choice and its mapping", () => {
  assert.deepEqual(parseDemoDecision({ disposition: "vulnerable", family: "injection", choice: directChoice }, "decision"), {
    disposition: "vulnerable",
    family: "injection",
    choice: directChoice
  });
  assert.deepEqual(decisionForChoice("safe"), { disposition: "safe", family: null });
  assert.deepEqual(decisionForChoice("insufficient_context"), { disposition: "insufficient_context", family: null });
});

test("demo decisions reject malformed or inconsistent direct Choices", () => {
  assert.throws(() => parseDemoDecision({ disposition: "vulnerable", family: "injection", choice: {
    ...directChoice,
    probabilities: { ...directChoice.probabilities, other: 0 }
  } }, "decision"), /probabilities are invalid/);
  assert.throws(() => parseDemoDecision({ disposition: "vulnerable", family: "injection", choice: {
    ...directChoice,
    probabilities: { ...directChoice.probabilities, vulnerable_injection: 1.6 }
  } }, "decision"), /probabilities are invalid|sum/);
  assert.throws(() => parseDemoDecision({ disposition: "vulnerable", family: "injection", choice: {
    ...directChoice,
    probabilities: { ...directChoice.probabilities, vulnerable_injection: 0.1, safe: 0.82 }
  } }, "decision"), /selected option is not maximal/);
  assert.throws(() => parseDemoDecision({ disposition: "vulnerable", family: "ssrf", choice: directChoice }, "decision"), /choice is inconsistent/);
});

test("demo decisions accept tied maxima and preserve low confidence", () => {
  const choice = {
    ...directChoice,
    confidence: 0.1,
    probabilities: { ...directChoice.probabilities, vulnerable_injection: 0.43, safe: 0.43, insufficient_context: 0.11 }
  };
  assert.deepEqual(parseDemoDecision({ disposition: "vulnerable", family: "injection", choice }, "decision").choice, choice);
});

test("demo Choice probability tolerance includes both endpoints only", () => {
  for (const value of [0.49, 0.51]) {
    const choice = {
      selected: "safe" as const,
      confidence: 0.1,
      probabilities: { vulnerable_injection: 0, vulnerable_broken_access_control: 0, vulnerable_ssrf: 0, safe: value, insufficient_context: value }
    };
    assert.deepEqual(parseDemoDecision({ disposition: "safe", family: null, choice }, "decision").choice, choice);
  }
  assert.throws(() => parseDemoDecision({ disposition: "safe", family: null, choice: {
    selected: "safe", confidence: 0.1,
    probabilities: { vulnerable_injection: 0, vulnerable_broken_access_control: 0, vulnerable_ssrf: 0, safe: 0.4895, insufficient_context: 0.4895 }
  } }, "decision"), /probabilities sum/);
});

test("100-case fixture has the frozen family and disposition matrix", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(cases.length, 100);
  const expected = {
    injection: { vulnerable: 12, safe: 11, insufficient_context: 11 },
    broken_access_control: { vulnerable: 11, safe: 11, insufficient_context: 11 },
    ssrf: { vulnerable: 11, safe: 11, insufficient_context: 11 }
  } as const;
  for (const [family, dispositions] of Object.entries(expected)) {
    for (const [disposition, count] of Object.entries(dispositions)) {
      assert.equal(cases.filter((item) => item.family === family && item.expected.disposition === disposition).length, count, `${family}/${disposition}`);
    }
  }
});

test("100-case fixture uses unique IDs and distinct canonical evidence", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  assert.equal(new Set(cases.map((item) => item.caseId)).size, 100);
  assert.equal(new Set(cases.map((item) => stableHash(item.state))).size, 100);
});

test("model-visible state carries no label: neutral paths, no context flags, no case IDs", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  for (const item of cases) {
    assert.equal("contextResolution" in item.state, false, item.caseId);
    assert.doesNotMatch(JSON.stringify(item.state), /vulnerable|insufficient|hidden|-safe-|_safe|contextResolution/i, item.caseId);
    assert.equal(JSON.stringify(item.state).includes(item.caseId), false, item.caseId);
  }
  assert.equal(cases.filter((item) => item.ledger !== null).length, 100);
  const withheld = cases.filter((item) => item.expected.disposition === "insufficient_context");
  assert.equal(withheld.every((item) => Object.values((item.ledger as { contextResolution: Record<string, string> }).contextResolution).includes("unresolved")), true);
});

test("fixture leakage check rejects label-bearing paths, text, and metadata keys", () => {
  const clean: Pick<DemoCase, "caseId" | "state"> = { caseId: "case-1", state: { spans: [{ id: "s1", path: "src/orders.ts", text: "db.query(id)" }] } };
  assert.doesNotThrow(() => assertNoFixtureLeakage(clean));
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [{ id: "s1", path: "src/demo/access-vulnerable-invoice.ts", text: "x" }] } }), /leaks the label/);
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [{ id: "s1", path: "src/demo/ssrf-safe-avatar.ts", text: "x" }] } }), /leaks the label/);
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [{ id: "s1", path: "src/demo/helper-hidden.ts", text: "x" }] } }), /leaks the label/);
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [{ id: "s1", path: "src/a.ts", text: "// insufficient context here" }] } }), /leaks the label/);
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [], contextResolution: { middleware: "unresolved" } } }), /label-bearing metadata/);
  assert.throws(() => assertNoFixtureLeakage({ caseId: "case-1", state: { spans: [{ id: "s1", path: "src/case-1.ts", text: "x" }] } }), /contains the case ID/);
});

const validResult = (item: DemoCase, overrides: Partial<DemoResult> = {}): DemoResult => ({
  caseId: item.caseId, evaluator: "jev", status: "valid", decision: item.expected, correct: true, latencyMs: 1, modelLatencyMs: 1, error: null, ...overrides
});

test("recall is reported with and without family; family accuracy and precision are separate", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const vulnerable = cases.filter((item) => item.expected.disposition === "vulnerable");
  const wrongFamily: DemoAdapter = { name: "jev", metadata: { provider: "Fixture", modelId: "jev", runner: "fixture", runnerVersion: "1" }, evaluate: async (_state, item) => ({ disposition: "vulnerable", family: item.family === "ssrf" ? "injection" : "ssrf" }) };
  const report = await runDemo(vulnerable, [wrongFamily], "fixture");
  assert.equal(report.summary.jev!.accuracy, 0);
  assert.equal(report.summary.jev!.vulnerabilityRecall, 1);
  assert.equal(report.summary.jev!.vulnerabilityRecallWithFamily, 0);
  assert.equal(report.summary.jev!.familyAccuracy, 0);
  assert.equal(report.summary.jev!.vulnerablePrecision, 1);
  assert.equal(report.summary.jev!.brierScore, null);
});

test("summary reports balanced accuracy, false-safe and false-positive rates, latency percentiles, and Brier score", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const byDisposition = (disposition: DemoDecision["disposition"]) => cases.filter((item) => item.expected.disposition === disposition);
  const oneHot = (selected: DemoDecision["disposition"] | "vulnerable_injection" | "vulnerable_broken_access_control" | "vulnerable_ssrf", confidence = 1) => ({
    selected: selected === "vulnerable" ? "vulnerable_injection" as const : selected,
    confidence,
    probabilities: {
      vulnerable_injection: selected === "vulnerable_injection" || selected === "vulnerable" ? 1 : 0,
      vulnerable_broken_access_control: selected === "vulnerable_broken_access_control" ? 1 : 0,
      vulnerable_ssrf: selected === "vulnerable_ssrf" ? 1 : 0,
      safe: selected === "safe" ? 1 : 0,
      insufficient_context: selected === "insufficient_context" ? 1 : 0
    }
  });
  const choiceFor = (decision: DemoDecision) => oneHot(decision.disposition === "vulnerable" ? `vulnerable_${decision.family}` as "vulnerable_injection" : decision.disposition);
  const results: DemoResult[] = [
    // vulnerable: 17 right, 17 called safe
    ...byDisposition("vulnerable").map((item, index) => index < 17
      ? validResult(item, { decision: { ...item.expected, choice: choiceFor(item.expected) }, latencyMs: 100 + index, modelLatencyMs: 10 + index })
      : validResult(item, { decision: { disposition: "safe", family: null, choice: oneHot("safe") }, correct: false, latencyMs: 100, modelLatencyMs: 10 })),
    // safe: 22 right, 11 called vulnerable
    ...byDisposition("safe").map((item, index) => index < 22
      ? validResult(item, { decision: { ...item.expected, choice: oneHot("safe") }, latencyMs: 100, modelLatencyMs: 10 })
      : validResult(item, { decision: { disposition: "vulnerable", family: item.family, choice: choiceFor({ disposition: "vulnerable", family: item.family }) }, correct: false, latencyMs: 100, modelLatencyMs: 10 })),
    // insufficient: all right, one error
    ...byDisposition("insufficient_context").map((item, index) => index === 0
      ? validResult(item, { status: "error", decision: null, correct: false, error: "service unavailable", modelLatencyMs: null, latencyMs: 5_000 })
      : validResult(item, { decision: { ...item.expected, choice: oneHot("insufficient_context") }, latencyMs: 100, modelLatencyMs: 10 }))
  ];
  const summary = summarizeDemoResults(cases, results, ["jev"]).jev!;
  assert.equal(summary.accuracy, (17 + 22 + 32) / 100);
  assert.equal(summary.classRecall.vulnerable, 17 / 34);
  assert.equal(summary.classRecall.safe, 22 / 33);
  assert.equal(summary.classRecall.insufficient_context, 32 / 33);
  assert.equal(summary.balancedAccuracy, (17 / 34 + 22 / 33 + 32 / 33) / 3);
  assert.equal(summary.falseSafeRate, 17 / 34);
  assert.equal(summary.falsePositiveRate, 11 / 33);
  assert.equal(summary.vulnerablePrecision, 17 / 28);
  assert.equal(summary.errors, 1);
  // 100 latencies: 83 at 100 ms, 16 spread over 101..116 ms, one 5000 ms outlier. Nearest-rank p95 lands at 112, not on the outlier.
  assert.equal(summary.latencyP50Ms, 100);
  assert.equal(summary.latencyP95Ms, 112);
  assert.ok(summary.meanLatencyMs > 140);
  // 99 model latencies (the error has none): 82 at 10 ms, 17 spread over 10..26 ms. Nearest-rank p95 is 21.
  assert.equal(summary.modelLatencyP50Ms, 10);
  assert.equal(summary.modelLatencyP95Ms, 21);
  // One-hot distributions: each wrong valid answer contributes a Brier term of 2; 28 wrong of 99 valid.
  assert.ok(Math.abs(summary.brierScore! - (28 * 2) / 99) < 1e-12);
  assert.equal(summary.degenerate, false);
});

test("summary flags a run that returns one outcome for every case as degenerate", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const allAbstain: DemoResult[] = cases.map((item) => validResult(item, { decision: { disposition: "insufficient_context", family: null }, correct: item.expected.disposition === "insufficient_context" }));
  assert.equal(summarizeDemoResults(cases, allAbstain, ["jev"]).jev!.degenerate, true);
  assert.equal(summarizeDemoResults(cases, allAbstain, ["jev"]).jev!.accuracy, 0.33);
  const mixed = [...allAbstain];
  mixed[0] = validResult(cases[0]!);
  assert.equal(summarizeDemoResults(cases, mixed, ["jev"]).jev!.degenerate, false);
});

test("all evaluators receive identical canonical evidence and failures stay visible", async () => {
  const cases = (await loadDemoCases("test/fixtures/demo-cases.json")).slice(0, 2);
  const seen = new Map<string, string[]>();
  const adapter = (name: "jev" | "terra" | "opus", fail = false): DemoAdapter => ({
    name,
    metadata: { provider: "Fixture", modelId: name, runner: "fixture", runnerVersion: "1" },
    evaluate: async (stateJson, item) => {
      seen.set(item.caseId, [...(seen.get(item.caseId) ?? []), stateJson]);
      if (fail && item.caseId === cases[1]?.caseId) throw new Error("fixture failure");
      return { ...item.expected };
    }
  });

  const report = await runDemo(cases, [adapter("jev"), adapter("terra", true), adapter("opus")], "fixture");
  for (const payloads of seen.values()) assert.equal(new Set(payloads).size, 1);
  assert.equal(report.results.length, 6);
  assert.equal(report.results.filter((row) => row.status === "error").length, 1);
  assert.equal(report.summary.terra!.errors, 1);
  assert.equal(report.summary.terra!.accuracy, 0.5);
  assert.equal(report.summary.jev!.accuracy, 1);
  assert.equal(report.mode, "fixture");
});

test("triage accuracy scores disposition and vulnerable family", async () => {
  const item = (await loadDemoCases("test/fixtures/demo-cases.json"))[0]!;
  const adapter: DemoAdapter = { name: "jev", metadata: { provider: "Fixture", modelId: "jev", runner: "fixture", runnerVersion: "1" }, evaluate: async () => ({ disposition: "vulnerable", family: "injection" }) };
  const report = await runDemo([item], [adapter], "fixture");
  assert.equal(report.results[0]?.correct, true);
  assert.equal(report.summary.jev!.vulnerabilityRecall, 1);
  assert.deepEqual(Object.keys(report.summary), ["jev"]);
});

test("summary keeps explicit errors in both denominators", async () => {
  const cases = await loadDemoCases("test/fixtures/demo-cases.json");
  const results: DemoResult[] = cases.map((item) => ({
    caseId: item.caseId, evaluator: "jev", status: "valid", decision: item.expected,
    correct: true, latencyMs: 1, modelLatencyMs: 1, error: null
  }));
  results[0] = { ...results[0]!, status: "error", decision: null, correct: false, error: "service unavailable" };
  const summary = summarizeDemoResults(cases, results, ["jev"]);
  assert.equal(summary.jev!.accuracy, 0.99);
  assert.equal(summary.jev!.errors, 1);
  assert.ok(summary.jev!.vulnerabilityRecall < 1);
});

test("live recording aborts an evaluator after three consecutive failures", async () => {
  const cases = (await loadDemoCases("test/fixtures/demo-cases.json")).slice(0, 4);
  let attempts = 0;
  const adapter: DemoAdapter = {
    name: "terra",
    metadata: { provider: "Fixture", modelId: "terra", runner: "fixture", runnerVersion: "1" },
    evaluate: async () => { attempts += 1; throw new Error("nonzero_exit: review exited 1"); }
  };
  await assert.rejects(() => runDemo(cases, [adapter], "live", 3), /terra aborted after 3 consecutive errors: nonzero_exit: review exited 1/);
  assert.equal(attempts, 3);
});

test("fixture CLI prints an explicitly simulated three-model report", async () => {
  const result = await new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
    execFile(process.execPath, ["dist/src/cli.js", "demo", "--fixture", "test/fixtures/demo-cases.json"], { cwd: process.cwd() }, (error, stdout, stderr) => {
      const code = (error as (NodeJS.ErrnoException & { code?: number }) | null)?.code;
      done({ code: typeof code === "number" ? code : error === null ? 0 : 1, stdout, stderr });
    });
  });
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.mode, "fixture");
  assert.equal(report.disclaimer, "SIMULATED ADAPTERS — not model benchmark results");
  assert.equal(report.caseCount, 100);
  assert.equal("results" in report, false);
  assert.deepEqual(Object.keys(report.summary).sort(), ["jev", "opus", "terra"]);
  assert.equal((await readFile("test/fixtures/demo-cases.json", "utf8")).includes("expected"), true);
});

test("live CLI fails before calls when the selected Jev credential is absent", async () => {
  const result = await new Promise<{ code: number; stderr: string }>((done) => {
    const env = { ...process.env };
    delete env.TYPESAFE_API_KEY;
    execFile(process.execPath, ["dist/src/cli.js", "demo", "--live", "--models", "jev", "--fixture", "test/fixtures/demo-cases.json"], { cwd: process.cwd(), env }, (error, _stdout, stderr) => {
      const code = (error as (NodeJS.ErrnoException & { code?: number }) | null)?.code;
      done({ code: typeof code === "number" ? code : error === null ? 0 : 1, stderr });
    });
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /TYPESAFE_API_KEY is required/);
});

test("live adapters normalize native decisions while preserving the exact evidence string", async () => {
  const item = (await loadDemoCases("test/fixtures/demo-cases.json"))[0]!;
  const stateJson = JSON.stringify(item.state);
  let jevState: unknown;
  const jev = createJevDemoAdapter(async (state) => {
    jevState = state;
    return {
      kind: "judgment", model: "jev-1.13.0", usage: { input_tokens: 7, output_tokens: 3 },
      choice: {
        selected: "vulnerable_ssrf", confidence: 0.1,
        probabilities: { vulnerable_injection: 0.1, vulnerable_broken_access_control: 0.1, vulnerable_ssrf: 0.3, safe: 0.25, insufficient_context: 0.25 }
      }
    };
  });
  const terra = createReasoningDemoAdapter("terra", "/empty", async (request) => {
    assert.equal(request.mode, "demo");
    assert.equal(request.schemaPath, "config/demo-output.schema.json");
    assert.match(request.prompt, /not evidence that a control is absent or that code is safe/);
    assert.equal(request.prompt.endsWith(stateJson), true);
    assert.equal(request.prompt.split(stateJson).length, 2);
    return { finalOutcome: "no_alert", output: { decision: "safe", family: "injection", evidence_span_ids: [] }, usage: null, usageStatus: "inconclusive", chargeUsd: null, costStatus: "inconclusive", attempts: 1, modelLatencyMs: 4_200, stdout: "", stderr: "", error: null };
  });
  const { modelLatencyMs, ...jevDecision } = await jev.evaluate(stateJson, item);
  assert.deepEqual(jevDecision, {
    disposition: "vulnerable", family: "ssrf", inputTokens: 7, outputTokens: 3,
    choice: { selected: "vulnerable_ssrf", confidence: 0.1, probabilities: { vulnerable_injection: 0.1, vulnerable_broken_access_control: 0.1, vulnerable_ssrf: 0.3, safe: 0.25, insufficient_context: 0.25 } }
  });
  assert.equal(typeof modelLatencyMs, "number");
  // Jev receives the canonical evidence as a JSON object, not a pre-serialized string.
  assert.deepEqual(jevState, item.state);
  assert.equal(typeof jevState, "object");
  assert.deepEqual(await terra.evaluate(stateJson, item), { disposition: "safe", family: null, modelLatencyMs: 4_200 });
});

test("reasoning adapters retain useful CLI failures without leaking paths or credentials", async () => {
  const item = (await loadDemoCases("test/fixtures/demo-cases.json"))[0]!;
  const terra = createReasoningDemoAdapter("terra", "/empty", async () => ({
    finalOutcome: "manual_review", output: null, usage: null, usageStatus: "inconclusive", chargeUsd: null, costStatus: "inconclusive", attempts: 1, modelLatencyMs: null,
    stdout: "", stderr: "failed reading /Users/roberto/private/config; token apikey_secret123", error: { kind: "nonzero_exit", message: "review exited 1" }
  }));
  await assert.rejects(
    () => terra.evaluate(JSON.stringify(item.state), item),
    /nonzero_exit: review exited 1; stderr: failed reading \[local-path\]; token \[redacted\]/
  );
});
