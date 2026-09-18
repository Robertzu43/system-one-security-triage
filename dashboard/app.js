const fixture = JSON.parse(document.querySelector("#fixture-data").textContent);

const labels = {
  all: "All",
  injection: "Injection",
  "broken-access-control": "Broken access control",
  ssrf: "SSRF",
  public: "Public corpus",
  private: "Private corpus",
  candidate: "Candidate",
  routed: "Routed",
  escalated: "Escalated",
  finalAlert: "Final alert",
  manualReview: "Manual review"
};

const marks = { supported: "●", contradicted: "◆", inconclusive: "▲" };

function renderStrategies() {
  const body = document.querySelector("#strategy-rows");
  body.replaceChildren(...fixture.strategies.map((strategy) => {
    const row = document.createElement("tr");
    const values = [strategy.label, strategy.recall, strategy.cost, strategy.latency];
    for (const value of values) {
      const cell = document.createElement("td");
      if (typeof value === "string") cell.textContent = value;
      else {
        const strong = document.createElement("strong");
        strong.textContent = value.estimate;
        const interval = document.createElement("small");
        interval.textContent = value.interval;
        cell.append(strong, interval);
      }
      row.append(cell);
    }
    return row;
  }));
}

function renderSemgrep() {
  const body = document.querySelector("#semgrep-rows");
  body.replaceChildren(...Object.values(fixture.semgrep).map((metric) => {
    const row = document.createElement("tr");
    for (const value of [metric.label, metric.alerts.toLocaleString(), metric.rate]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    return row;
  }));
}

function renderWaterfall() {
  const root = document.querySelector("#waterfall");
  const maximum = fixture.waterfall.candidate;
  root.replaceChildren(...Object.entries(fixture.waterfall).map(([stage, value], index) => {
    const item = document.createElement("li");
    const head = document.createElement("div");
    const name = document.createElement("span");
    const count = document.createElement("strong");
    const track = document.createElement("div");
    const bar = document.createElement("span");
    name.textContent = `${String(index + 1).padStart(2, "0")} / ${labels[stage]}`;
    count.textContent = value.toLocaleString();
    head.append(name, count);
    head.className = "waterfall-head";
    track.className = "waterfall-track";
    bar.style.width = `${Math.max(2, (value / maximum) * 100)}%`;
    track.append(bar);
    item.append(head, track);
    return item;
  }));
}

function fillFilter(id, values) {
  const select = document.querySelector(id);
  select.replaceChildren(...values.map((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = labels[value];
    return option;
  }));
}

function caseCard(entry) {
  const card = document.createElement("article");
  const heading = document.createElement("h3");
  const meta = document.createElement("p");
  const badge = document.createElement("span");
  const finding = document.createElement("p");
  const evidence = document.createElement("p");

  card.className = "case-card";
  card.dataset.family = entry.family;
  card.dataset.corpus = entry.corpus;
  heading.textContent = entry.caseId;
  badge.className = `decision decision--${entry.decision}`;
  badge.textContent = `${marks[entry.decision]} ${entry.decision}`;
  meta.className = "case-meta";
  meta.textContent = `${entry.spanId} · ${labels[entry.family]} · ${labels[entry.corpus]}`;
  finding.textContent = entry.finding;
  evidence.className = "case-evidence";
  evidence.textContent = `Evidence note: ${entry.evidence}`;
  card.append(badge, heading, meta, finding, evidence);
  return card;
}

function renderCases() {
  const family = document.querySelector("#family-filter").value;
  const corpus = document.querySelector("#corpus-filter").value;
  const visible = fixture.cases.filter((entry) =>
    (family === "all" || entry.family === family) &&
    (corpus === "all" || entry.corpus === corpus)
  );
  document.querySelector("#case-grid").replaceChildren(...visible.map(caseCard));
  document.querySelector("#case-count").textContent = `${visible.length} / ${fixture.cases.length} redacted cases shown`;
}

renderStrategies();
renderSemgrep();
renderWaterfall();
fillFilter("#family-filter", fixture.filters.families);
fillFilter("#corpus-filter", fixture.filters.corpora);
renderCases();

for (const select of document.querySelectorAll("#case-filters select")) {
  select.addEventListener("change", renderCases);
}
