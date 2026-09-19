const evaluators = ["jev", "terra", "opus"];
const names = { jev: "Jev", terra: "Terra", opus: "Opus" };
const symbols = { vulnerable: "V", safe: "S", insufficient_context: "?", error: "!" };
const choiceNames = { vulnerable_injection: "injection", vulnerable_broken_access_control: "broken access control", vulnerable_ssrf: "SSRF", safe: "safe", insufficient_context: "insufficient context" };
let sourceData;

const byId = (id) => document.getElementById(id);
const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const percent = (value) => `${(value * 100).toFixed(0)}%`;
const decisionName = (value) => value.replaceAll("_", " ");

function renderMetadata(data) {
  byId("corpus-id").textContent = data.corpusHash.slice(0, 12);
  byId("recorded-at").textContent = new Date(data.models[0].recordedAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  byId("case-count").textContent = `${data.caseCount} synthetic`;
  byId("provenance-note").textContent = data.provenance.description;
  const warnings = byId("warnings");
  warnings.replaceChildren(...(data.warnings ?? []).map((text) => element("li", "", text)));
  warnings.parentElement.hidden = (data.warnings ?? []).length === 0;
}
const milliseconds = (value) => value === null || value === undefined ? "unavailable" : `${Math.round(value)} ms`;

function renderScorecards(data) {
  const root = byId("scorecards");
  root.replaceChildren(...data.models.map((model, index) => {
    const summary = data.summary[model.evaluator];
    const card = element("article", "scorecard");
    card.dataset.model = model.evaluator;
    card.dataset.index = String(index + 1).padStart(2, "0");
    card.append(element("p", "model-kicker", model.provider), element("h3", "", names[model.evaluator]), element("p", "model-id", `${model.modelId} · ${model.runner} ${model.runnerVersion}`));
    const hero = element("div", "hero-metric");
    hero.append(element("span", "metric-label", "Balanced accuracy"), element("strong", "metric-value", percent(summary.balancedAccuracy)));
    card.append(hero);
    const metrics = element("div", "metric-grid");
    for (const [label, value] of [
      ["Accuracy", percent(summary.accuracy)],
      ["Vuln. recall", percent(summary.vulnerabilityRecall)],
      ["False positive rate", percent(summary.falsePositiveRate)],
      ["False safe rate", percent(summary.falseSafeRate)],
      ["Errors", String(summary.errors)],
      ["Model latency p50", summary.modelLatencyP50Ms === null ? `${milliseconds(summary.latencyP50Ms)} end-to-end` : milliseconds(summary.modelLatencyP50Ms)],
      // Scores the reported distribution rather than only the argmax. Null for an evaluator that
      // returns a bare verdict, which is a fact about the model, not a gap in the recording.
      ["Brier score", summary.brierScore === null ? "n/a - no distribution reported" : summary.brierScore.toFixed(3)]
    ]) {
      const item = element("div");
      item.append(element("span", "metric-label", label), element("strong", "", value));
      metrics.append(item);
    }
    card.append(metrics);
    return card;
  }));
}

function decisionCell(item) {
  const result = item.results.jev;
  const state = result.status === "error" ? "error" : result.decision.disposition;
  const cell = element("button", `decision-cell ${state}`, symbols[state]);
  cell.type = "button";
  cell.setAttribute("role", "listitem");
  cell.title = `${item.caseId}: ${decisionName(state)}`;
  cell.setAttribute("aria-label", cell.title);
  cell.addEventListener("click", () => {
    byId("model-filter").value = "jev";
    renderCases(sourceData, { ...selectedFilters(), caseId: item.caseId });
    byId("explorer-title").scrollIntoView({ behavior: "smooth" });
  });
  return cell;
}

function renderDecisionGrid(data, visibleCount = 100) {
  byId("decision-grid").replaceChildren(...data.cases.slice(0, visibleCount).map(decisionCell));
}

function renderComparisonBars(data) {
  const width = 520;
  const height = 235;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("role", "img");
  svg.append(document.createElementNS(svg.namespaceURI, "title"));
  svg.firstChild.textContent = "Balanced accuracy and vulnerability recall by model";
  for (let tick = 0; tick <= 4; tick += 1) {
    const x = 120 + tick * 90;
    const line = document.createElementNS(svg.namespaceURI, "line");
    line.setAttribute("x1", x); line.setAttribute("x2", x); line.setAttribute("y1", 10); line.setAttribute("y2", 205); line.setAttribute("class", "gridline");
    svg.append(line);
    const label = document.createElementNS(svg.namespaceURI, "text");
    label.setAttribute("x", x); label.setAttribute("y", 225); label.setAttribute("text-anchor", "middle"); label.textContent = `${tick * 25}%`;
    svg.append(label);
  }
  data.models.forEach((model, index) => {
    const y = 27 + index * 65;
    const summary = data.summary[model.evaluator];
    const label = document.createElementNS(svg.namespaceURI, "text");
    label.setAttribute("x", "0"); label.setAttribute("y", String(y + 18)); label.textContent = names[model.evaluator]; svg.append(label);
    [[summary.balancedAccuracy, "Balanced accuracy", 0], [summary.vulnerabilityRecall, "Recall", 24]].forEach(([value, metric, offset]) => {
      const bar = document.createElementNS(svg.namespaceURI, "rect");
      bar.setAttribute("x", "120"); bar.setAttribute("y", String(y + offset)); bar.setAttribute("width", String(value * 360)); bar.setAttribute("height", "17"); bar.setAttribute("rx", "2"); bar.setAttribute("fill", `var(--${model.evaluator})`);
      const title = document.createElementNS(svg.namespaceURI, "title"); title.textContent = `${names[model.evaluator]} ${metric}: ${percent(value)}`; bar.append(title); svg.append(bar);
    });
  });
  byId("comparison-bars").replaceChildren(svg);
  const tbody = byId("comparison-table").querySelector("tbody");
  tbody.replaceChildren(...data.models.map((model) => {
    const row = element("tr");
    const summary = data.summary[model.evaluator];
    row.append(element("th", "", names[model.evaluator]), element("td", "", percent(summary.balancedAccuracy)), element("td", "", percent(summary.vulnerabilityRecall)), element("td", "", percent(summary.falsePositiveRate)), element("td", "", percent(summary.falseSafeRate)));
    return row;
  }));
}

function renderConfusionMatrices(data) {
  const outcomes = ["vulnerable", "safe", "insufficient_context", "error"];
  byId("confusion-matrices").replaceChildren(...evaluators.map((evaluator) => {
    const wrap = element("div", "matrix-wrap");
    const table = element("table");
    table.append(element("caption", "", `${names[evaluator]} · expected × decision`));
    const head = element("thead");
    const headRow = element("tr");
    headRow.append(element("th", "", "Expected"), ...outcomes.map((value) => element("th", "", value === "insufficient_context" ? "Context" : decisionName(value))));
    head.append(headRow); table.append(head);
    const body = element("tbody");
    for (const expected of outcomes.slice(0, 3)) {
      const row = element("tr");
      row.append(element("th", "", decisionName(expected)));
      for (const actual of outcomes) {
        const count = data.cases.filter((item) => item.expected.disposition === expected && (item.results[evaluator].status === "error" ? "error" : item.results[evaluator].decision.disposition) === actual).length;
        row.append(element("td", "", String(count)));
      }
      body.append(row);
    }
    table.append(body); wrap.append(table); return wrap;
  }));
}

function selectedFilters() {
  return Object.fromEntries(["model", "family", "expected", "decision", "correct", "status"].map((name) => [name, byId(`${name}-filter`).value]));
}

function renderCases(data, filters) {
  const cases = data.cases.filter((item) => {
    if (filters.caseId && item.caseId !== filters.caseId) return false;
    if (filters.family !== "all" && item.family !== filters.family) return false;
    if (filters.expected !== "all" && item.expected.disposition !== filters.expected) return false;
    const results = filters.model === "all" ? evaluators.map((name) => item.results[name]) : [item.results[filters.model]];
    return results.some((result) => (filters.status === "all" || result.status === filters.status)
      && (filters.correct === "all" || String(result.correct) === filters.correct)
      && (filters.decision === "all" || (result.decision?.disposition ?? "error") === filters.decision));
  });
  byId("results-count").textContent = `${cases.length} of ${data.caseCount} cases`;
  const root = byId("case-list");
  if (cases.length === 0) { root.replaceChildren(element("p", "empty", "No cases match these filters.")); return; }
  root.replaceChildren(...cases.map((item) => {
    const details = element("details", "case");
    const summary = element("summary");
    summary.append(element("span", "case-id", item.caseId), element("span", "tag", decisionName(item.family)), element("span", "tag", `Expected: ${decisionName(item.expected.disposition)}`));
    details.append(summary);
    const body = element("div", "case-body");
    const evidence = element("pre");
    evidence.textContent = JSON.stringify(item.state, null, 2);
    const results = element("div", "case-results");
    for (const evaluator of evaluators) {
      const result = item.results[evaluator];
      const row = element("div", "case-result");
      const outcome = result.status === "error" ? `error · ${result.error}` : `${decisionName(result.decision.disposition)}${result.decision.family ? ` · ${decisionName(result.decision.family)}` : ""}`;
      row.append(element("strong", "", names[evaluator]), element("span", "outcome", outcome), element("span", `correctness ${result.correct ? "yes" : "no"}`, result.correct ? "✓ correct" : "× incorrect"));
      if (evaluator === "jev" && result.decision?.choice) {
        const choice = result.decision.choice;
        const probabilities = Object.entries(choiceNames).map(([key, label]) => `${label} ${percent(choice.probabilities[key])}`).join(" · ");
        row.append(element("span", "choice-probabilities", `Choice confidence ${percent(choice.confidence)} · ${probabilities}`));
      } else if (result.status !== "error") {
        // Without this the empty space reads as "withheld" rather than "cannot produce one".
        row.append(element("span", "no-probabilities", "No probability reported - this model returns a final verdict only, not a distribution."));
      }
      results.append(row);
    }
    body.append(evidence, results); details.append(body); return details;
  }));
  if (filters.caseId) root.querySelector("details")?.setAttribute("open", "");
}

function replayRecordedRun(data) {
  const button = byId("replay");
  const status = byId("replay-status");
  button.disabled = true;
  byId("decision-grid").replaceChildren();
  byId("scorecards").replaceChildren();
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    renderDecisionGrid(data, 100);
    renderScorecards(data);
    status.textContent = "Recorded replay complete";
    button.disabled = false;
    return;
  }
  let visible = 0;
  const frame = () => {
    visible += 1;
    // ponytail: fixed 100-case replay; switch to append-only rendering if the corpus grows.
    renderDecisionGrid(data, visible);
    status.textContent = `Replaying recorded result ${visible} of 100`;
    if (visible < 100) requestAnimationFrame(frame);
    else { renderScorecards(data); status.textContent = "Recorded replay complete"; button.disabled = false; }
  };
  requestAnimationFrame(frame);
}

async function start() {
  try {
    const response = await fetch("./data/latest.json");
    if (!response.ok) throw new Error(`data request failed: ${response.status}`);
    const data = await response.json();
    if (data.schemaVersion !== 1 || data.recorded !== true || data.synthetic !== true || data.caseCount !== 100 || typeof data.provenance?.description !== "string" || !Array.isArray(data.warnings)) throw new Error("dashboard data contract is invalid");
    sourceData = data;
    renderMetadata(data); renderScorecards(data); renderDecisionGrid(data); renderComparisonBars(data); renderConfusionMatrices(data); renderCases(data, selectedFilters());
    byId("replay").addEventListener("click", () => replayRecordedRun(data));
    document.querySelectorAll(".filters select").forEach((control) => control.addEventListener("change", () => renderCases(data, selectedFilters())));
  } catch (error) {
    byId("results-count").textContent = `Unable to load recorded data: ${error instanceof Error ? error.message : String(error)}`;
  }
}

start();
