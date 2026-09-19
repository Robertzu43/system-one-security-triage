# System One Security Triage

Status: approved revised design
Date: 2026-09-18

## Objective

Build a reproducible TypeScript/Node cybersecurity benchmark and static dashboard
that compares Jev, Terra, and Opus as bounded security-triage decision makers over
the same redacted evidence. Measure decision quality, evidence localization,
abstention behavior, latency, and cost without pretending that System One and
reasoning models use the same internal mechanism.

The repository name is `system-one-security-triage`. The public framing is
**Jev vs Terra vs Opus: security-triage decision quality**. The controlled
comparison below is the preregistered primary experiment. A Jev-routed cascade is
an applied secondary experiment whose design may use only calibration results.
The eventual publication title may emphasize a supported result but must not
replace, broaden, or obscure the frozen primary question after results are known.

## Scope

The first release covers three vulnerability families:

- Injection: attacker-controlled input reaching SQL, shell, `eval`, or another
  dangerous interpreter or operation.
- Broken access control: an actor reading or changing a resource without the
  required authorization.
- SSRF: attacker-controlled input influencing a server-side network request.

This deliberately excludes broad coverage of the full OWASP Top Ten. The three
families exercise data flow, application policy, and network-boundary reasoning
while keeping ground-truth validation tractable.

## Claims under test

1. On identical bounded evidence, Jev can achieve non-inferior balanced triage
   accuracy and vulnerability recall relative to Terra and Opus within the frozen
   two-percentage-point margins.
2. Jev can make those bounded decisions with lower observed latency and, when
   defensible provider charges are available, lower cost than the frontier models.
3. A Jev-routed cascade can reduce frontier-model invocations while satisfying the
   same frozen vulnerability-recall guardrail.

Semgrep false-alert reduction and additional validated AST yield remain exploratory
secondary analyses. They must not replace the controlled model comparison in the
headline result, and AST yield must be stated narrowly rather than generalized to
security scanners as a category.

## Corpus

### OWASP Juice Shop

Use a frozen, redacted Juice Shop revision only for development, question and packet
design, dashboard examples, and qualitative case studies. Do not use Juice Shop to
select decision mappings, thresholds, abstention policies, or escalation budgets.

Juice Shop is not the sole or primary holdout because it is public training
software. Challenge identifiers, solutions, marker comments, tests, and tutorial
material can reveal expected answers and may have appeared in model training data.
Remove those artifacts from model inputs while retaining a private mapping to the
underlying vulnerability root causes.

### Calibration repositories

Reserve separate JavaScript/TypeScript repositories for calibration. They must be
repository-disjoint from Juice Shop and the final holdout. Use them to freeze the
shared output mapping, Jev thresholds, abstention policy, and later cascade routing
after questions, model-native instructions, and packet construction have been
developed on Juice Shop.

### OpenSSF CVE Benchmark

Use pinned, real vulnerable and patched JavaScript/TypeScript revisions from the
OpenSSF CVE Benchmark for calibration and holdout, partitioned by repository before
any calibration run. Verify the language, localization, build requirements,
reproduction, and upstream license of every selected case.

The holdout is untouched by this experiment, not contamination-free. OpenSSF is a
public CVE corpus, so its code, advisories, and patches may have appeared in model
training data. Report that limitation explicitly and do not interpret the split as
proof of model unfamiliarity.

### Safe controls

Include patched counterparts, representative non-vulnerable routes, and deliberately
context-incomplete packets. A patch establishes that its target vulnerability was
removed; it does not establish that the entire route, file, or repository is safe.
Label the patched example as negative only for that target instance. Adjudicate
unrelated findings as separate instances.

An absence of generated candidates is not proof that code is safe;
candidate-generation coverage is measured separately.

Split development, calibration, and holdout data by repository and underlying
vulnerability root cause. Vulnerable, patched, and deliberately context-incomplete
variants of one root cause must remain in the same split. The frozen controlled
holdout must represent all three vulnerability families and all three dispositions:
`vulnerable`, `safe`, and `insufficient_context`.

## Ground truth

The primary measurement unit is one frozen evidence packet linked to a target
instance and context condition, not one alert, line, file, or Juice Shop challenge.
Packets derived from the same vulnerability root cause form one statistical cluster.
The end-to-end secondary analyses continue to use one deduplicated vulnerability
instance as their unit. A ground-truth record contains:

- repository and immutable commit;
- vulnerability family and CWE;
- attacker precondition and entry point;
- affected operation, source/sink path, or authorization boundary;
- expected disposition and required context dimensions;
- vulnerable and patched locations;
- a safe reproduction or regression test;
- provenance and independent reviewer decisions.

Before the holdout run, freeze a private matching ledger that maps every evidence
packet ID to its target-instance ID, expected disposition, applicable family, and
acceptable evidence spans or paths. The expected disposition is exactly one of:

- `vulnerable`: the supplied evidence establishes the labeled target vulnerability;
- `safe`: the supplied evidence establishes that the labeled target path is blocked
  or protected; or
- `insufficient_context`: the packet intentionally omits evidence required to decide
  safely, regardless of the full repository's private target label.

A vulnerable prediction is fully correct only when it selects `vulnerable`, selects
the correct family, and identifies a labeled vulnerable span or labeled path. Safe
and insufficient-context correctness is scored separately from family and vulnerable
span localization. Multiple packets derived from the same root cause remain one
cluster and never become independent vulnerabilities merely because they expose
different context conditions.

For the primary controlled experiment, every evaluator receives every frozen packet.
A missing, malformed, timed-out, or policy-invalid model response is a failed attempt,
not `insufficient_context`, and remains in all denominators under the frozen failure
mapping. A vulnerable packet classified as `safe` or `insufficient_context` is not a
true positive. Failures, insufficient-context decisions, and frontier-model refusals
are reported separately and never disappear from scoring.

The exploratory Semgrep analysis uses a different, explicitly named metric:
retained-alert recall. Its denominator is the set of deduplicated known vulnerable
target instances matched by
at least one raw Semgrep finding. A target instance is retained when at least one of
its matching findings remains an alert after Jev filtering, including an unresolved
finding sent to review. It is a false negative for retained-alert recall only when
Jev suppresses every matching Semgrep finding. Retention does not imply automated
detection; unresolved retained findings contribute to review workload, not automated
detection recall. The scorer implements these as separate metrics with separate
outcome mappings.

Two security reviewers independently label the target disposition, family, and
acceptable evidence spans while blinded to model outputs. A third review or
consensus process adjudicates disagreements. Unresolved ground truth makes the
packet ineligible for the primary holdout; it is retained only as an explicitly
unscored qualitative case.

Every confirmed real vulnerability requires a non-destructive, sandboxed proof or
a source/fix validation showing that the vulnerable behavior disappears after the
patch.

## Architecture

```text
Pinned repository revision + private ground truth
                         |
             frozen redacted evidence packet
                         |
              +----------+----------+
              |          |          |
              v          v          v
             Jev       Terra       Opus
          typed atomic  structured  structured
           judgments     output      output
              |          |          |
              +----------+----------+
                         |
        shared disposition / family / evidence spans
                         |
                  controlled scorer
                         |
        +----------------+----------------+
        v                                 v
 head-to-head report             secondary Jev router
 decision quality, cost,          and cascade analysis
 latency, abstention                       |
        |                                  v
        +----------------------- benchmark dashboard
```

One TypeScript CLI performs packet construction, controlled evaluator invocation,
scoring, and the secondary routing experiment. Inputs and outputs are immutable
JSONL artifacts. Model adapters may use model-native instructions and typed-output
mechanisms, but the canonical evidence-state bytes and shared result schema are
frozen. There is no database or workflow framework.

## Candidate generation

Semgrep and the deterministic AST inventory are complementary ways to propose packet
candidates, but discovery quality is not part of the primary controlled comparison.
Primary holdout packets are selected from the frozen ground-truth ledger before any
model run, and every model receives the same packet IDs. Candidate-generation
coverage is measured only in the exploratory end-to-end analysis.

The inventory should cover, at minimum:

- framework routes and handlers;
- untrusted request inputs;
- database, interpreter, process, filesystem, template, and network sinks relevant
  to the three vulnerability families;
- authentication and authorization middleware or checks;
- local validation and sanitization calls;
- one-hop callers and callees needed to interpret the candidate.

The evidence builder assigns neutral span identifiers and emits the smallest useful
packet. It removes CVE IDs, challenge names, solution comments, commit messages,
scanner verdicts, vulnerable/fixed filenames, and other label-bearing metadata.

The primary evaluators receive no repository, web, shell, or retrieval tools. They
receive only the canonical evidence packet through their model-native input wrapper.
The packet excludes answer-bearing tests, advisories, challenge metadata, solution
material, vulnerable/fixed labels, and Git history. Reproduction inputs, regression
proofs, patches used as labels, and the private matching ledger remain available
only to validators. Record the sanitization manifest and packet hash.

The secondary agentic cascade, if run, uses a sanitized repository snapshot rather
than the original checkout. Terra-all and Jev-to-Terra receive the identical
snapshot and permissions; apply the same rule to both Opus arms.

One-hop context is a starting budget, not evidence that omitted controls do not
exist. The packet records whether route middleware, upstream data flow, sanitizers,
authorization, and call-path evidence relevant to the labeled family were resolved.
Irrelevant unresolved dimensions do not force abstention. If evidence required for
the labeled decision lies outside the packet, the correct primary disposition is
`insufficient_context`. “Not shown” never means “not enforced,” “unsanitized,” or
“safe.”

## Jev judgments

Jev receives one packet once and answers independent questions together:

- Can an untrusted actor influence the value?
- Can the value reach the security-sensitive operation shown?
- Does the shown validation or sanitization block the relevant attack?
- Does the operation cross an authorization boundary?
- Is the required authorization actually enforced?
- Could the behavior violate confidentiality, integrity, or availability?
- Does the packet support injection, broken access control, or SSRF?
- Does the packet contain enough source, middleware, sanitizer, authorization, and
  call-path evidence to make the relevant judgment?
- On a concrete ordered rubric, is exploitation unreachable, theoretical,
  constrained, or direct?

Use Nouls for independent yes/no judgments, a Choice only where answers are
mutually exclusive, and a Score for the ordered exploitability rubric. Raw
probabilities are retained. A frozen mapping converts them to the shared primary
disposition and family output; a separate frozen policy combines them into secondary
routing outcomes. Jev does not own the control flow.

Thresholds and disposition mappings are tuned only on calibration data and frozen
before the holdout. Any evidence dimension required for the candidate family and
marked unresolved forces `insufficient_context`; unresolved dimensions irrelevant
to that family do not. High-impact or uncertain cases escalate only in the secondary
cascade. The implementation must not compare Jev probabilities with an LLM's
self-reported confidence.

Routing outcomes have fixed operational meanings:

- `likely_safe`: suppress the candidate. Any hidden known vulnerability counts as a
  false negative.
- `likely_vulnerability`: emit a final machine alert without reasoning-model review.
- `needs_deep_review`: send the candidate to the configured reasoning model.
- `insufficient_context`: always send the candidate to the configured reasoning
  model with repository access.

The reasoning model returns `alert`, `no_alert`, or `manual_review`. A final
`manual_review` is visible in results and counts as undetected for automated recall;
it is not silently converted to either safe or vulnerable.

## Experiments

### Primary: controlled Jev vs Terra vs Opus comparison

Jev, Terra, and Opus receive the same canonical redacted evidence-state bytes with
no repository, web, shell, or retrieval tools. Model-native instructions and output
mechanisms may differ because the systems have different interfaces, but their
meaning is frozen before calibration and every output maps to this shared record:

```text
disposition: vulnerable | safe | insufficient_context
family: injection | broken_access_control | ssrf | null
evidence_span_ids: [...]
status: valid | timeout | malformed_output | policy_failure | service_failure
```

`family` is required only for `vulnerable`; the other dispositions use `null`.
Failures are represented by `status` and never disguised as
`insufficient_context`. Jev uses typed atomic questions and supplied span choices.
Terra and Opus use their native structured-output mechanisms. Prose quality,
chain-of-thought, and LLM self-reported confidence are not benchmark targets.

The primary confirmatory claim is that Jev's balanced triage accuracy and
vulnerability recall are each non-inferior within two percentage points to both
Terra and Opus. Pairwise Terra-versus-Opus results are reported descriptively and do
not change that claim. Precision, false-safe rate, insufficient-context recognition,
family accuracy, evidence localization, latency, and cost are prespecified secondary
outcomes of the same controlled run.

### Secondary: Jev-routed cascade

Only after freezing the primary calibration results, build a combined
Semgrep-plus-AST candidate pool and run:

- Terra or Opus reviewing every candidate; and
- Jev routing the identical candidate pool, with the configured frontier model
  reviewing only uncertain or context-incomplete outcomes.

The all-model and cascade arms receive identical agentic permissions and
per-candidate budgets: the same sanitized, read-only repository snapshot, network
policy, command allowlist, tool-call limit, token budget, and wall-clock cap. Only
the set of candidates sent to the frontier model differs. This is a system
comparison and must remain separate from the primary bounded decision comparison.

### Exploratory: Semgrep false-alert reduction

Use only frozen raw Semgrep findings and compare raw Semgrep with Semgrep-to-Jev.
Jev suppresses only `likely_safe`, emits `likely_vulnerability`, and retains uncertain
or context-incomplete findings as unresolved alerts. Do not include AST-only
candidates. Score retained-alert recall, retained-alert precision, and unresolved
review workload; do not reuse the primary controlled outcome mapping.

### Exploratory: validated yield beyond Semgrep

Run the frozen AST inventory alongside Semgrep. An AST-only candidate is not itself
Semgrep-missed yield: Semgrep may flag the same deduplicated target instance at a
different location. Count additional validated yield only when the frozen matching
ledger shows that no Semgrep finding matches that target instance anywhere in the
repository and independent adjudication confirms it.

Pin exact model snapshots, SDKs, instructions, schemas, scanner versions, rules,
containers, concurrency, retry policies, and run dates. Do not use moving aliases in
headline results.

## Metrics

The primary controlled report includes:

- balanced triage accuracy: the unweighted mean of per-class recall for
  `vulnerable`, `safe`, and `insufficient_context`;
- vulnerability recall and vulnerable-prediction precision;
- false-safe rate on vulnerable packets;
- safe specificity and insufficient-context recall;
- family accuracy and evidence-span hit rate on vulnerable packets;
- valid-response, timeout, malformed-output, and policy/service-failure rates;
- results by vulnerability family, severity, repository, and disposition;
- actual tokens and defensible provider cost; and
- cold per-packet p50/p95 end-to-end latency at fixed concurrency.

Jev probability calibration is reported with Brier score and calibration plots for
the underlying binary judgments. It is not compared with LLM verbal confidence.
Terra or Opus calibration is included only if the frozen interface exposes a
provider-supported probability with equivalent semantics; otherwise selective
accuracy versus abstention coverage is the cross-model uncertainty comparison.

Use five randomized, interleaved repetitions per packet and evaluator. Within each
repetition, score exactly one attempt per evaluator/packet. A failed attempt receives
zero for correct disposition and vulnerable recall and remains visible by failure
type. For each packet and evaluator, average the five binary outcomes first; then
compute target- and repository-level aggregates. Repetitions estimate one packet's
stability and never become independent examples.

Use 10,000 paired, repository-clustered percentile-bootstrap resamples with seed
`20260918`. A sampled repository carries every related target, vulnerable/patched/
context-incomplete variant, evaluator, and repetition. The two-sided 90% interval
provides the lower and upper one-sided 95% bounds used for decisions.

For each Jev-versus-frontier comparison and for both balanced accuracy and
vulnerability recall, classify the difference with a frozen `-0.02` margin:

- `supported` when the lower bound is above `-0.02`;
- `contradicted` when the upper bound is at or below `-0.02`; and
- `inconclusive` otherwise.

The primary claim is `supported` only when both metrics are supported against both
Terra and Opus. It is `contradicted` when any valid comparison is contradicted and
`inconclusive` otherwise. Insufficient ground truth or an invalid evaluation is also
inconclusive. Assess whether the frozen repository and target counts can detect the
margin with adequate power before the holdout; do not widen the margin after seeing
results.

Efficiency is secondary and frozen before the holdout:

- Cost is fully loaded USD per 1,000 controlled packet decisions at fixed
  concurrency. Include model/API charges, retries, and the preregistered runner
  compute allocation. A subscription-backed call without a defensible per-call
  allocation is not free; its cost result is inconclusive.
- Latency starts immediately before serializing the frozen request and ends after
  the parsed result is durably recorded. The primary latency summary is cold
  per-packet median and p95 at fixed concurrency. Warm behavior is diagnostic.
- Do not use provider batch APIs or prompt caching for primary measurements.
- Report ratio-of-mean cost and latency with paired repository bootstrap intervals;
  do not average repository-level ratios.

The secondary cascade retains the original automated-detection recall, retained-
alert recall, escalation, unresolved workload, end-to-end repository cost, and
repository latency metrics. Candidate-generation misses count only in that
end-to-end analysis, not in the primary fixed-packet comparison.

## Report and dashboard

The CLI writes immutable run artifacts. A generated Markdown report and static
dashboard read the same scored result files.

The dashboard provides:

- a Jev vs Terra vs Opus comparison for balanced accuracy, vulnerability recall,
  precision, false-safe rate, abstention/context handling, evidence localization,
  cost, and latency;
- pairwise uncertainty intervals and `supported`, `contradicted`, or `inconclusive`
  labels attached to the actual preregistered claims;
- a secondary pipeline waterfall from candidates through escalations and
  confirmations;
- a case explorer showing evidence, model decisions, ground truth, and patched code;
- filters for corpus and vulnerability family;
- explicit limitations and contamination disclosures.

The first release explores completed benchmark runs. It does not accept or execute
arbitrary repository scans.

## Safety and failure handling

- Execute vulnerable software and reproductions in network-restricted containers.
- Mount evaluated repositories read-only.
- Keep API credentials in environment variables and redact them from artifacts.
- Use only non-destructive proofs against intentionally vulnerable or locally owned
  targets.
- Record timeouts, malformed outputs, exhausted retries, and tool-budget exhaustion
  as failures or abstentions according to a frozen policy.
- Preserve raw requests, responses, usage, and timing metadata without secrets.
- Never discard failed calls silently or rerun only unfavorable outcomes.

## Verification

Automated checks cover:

- packet schema and stable hashes;
- label-leakage scanning;
- split contamination;
- vulnerable/patched pair grouping;
- target-instance matching and prediction deduplication;
- AST/Semgrep overlap, where an AST-only candidate maps to a target instance already
  matched by a Semgrep finding and therefore adds no exploratory validated yield;
- router thresholds and boundary cases;
- primary insufficient-context classification and secondary forced escalation when
  evidence required for the applicable family is unresolved;
- known vulnerable, safe, and context-incomplete fixtures for all three families;
- recall accounting for no-candidate, abstained, and manual-review positives;
- separate retained-alert and automated-detection outcome mappings;
- sanitized-snapshot exclusion and content-hash checks;
- model-output parsing and failure classification;
- identical packet-ID and canonical evidence-state checks across all three model
  adapters;
- correct-disposition, balanced-accuracy, false-safe, family, and evidence-span
  scoring fixtures;
- repetition nesting that never treats repeated observations as independent packets;
- pairwise Jev/Terra and Jev/Opus non-inferiority boundaries;
- metric calculations and confidence-interval inputs;
- agreement between CLI results, report, and dashboard.

A small end-to-end fixture runs the complete pipeline without paid model calls.
Live-model smoke tests remain explicit and separately reported.

## Explicit exclusions

- Full OWASP Top Ten coverage in the first release.
- Claims of exhaustive vulnerability discovery.
- Comparing Jev probabilities with LLM verbal confidence.
- Treating model-native instruction wrappers as byte-identical prompts; only the
  canonical evidence state and shared decision meaning are identical.
- Using agentic repository navigation in the primary model comparison.
- A backend database or general-purpose scan service.
- Network-enabled exploitation or testing third-party targets.

## Primary references

- [TypeSafe System One](https://docs.typesafe.ai/concepts/system-one.md)
- [TypeSafe confidence](https://docs.typesafe.ai/confidence.md)
- [TypeSafe models and versioning](https://docs.typesafe.ai/models.md)
- [OWASP Juice Shop](https://owasp.org/projects/juice-shop)
- [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)
- [NIST SATE VI](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-341.pdf)
- [NIST SARD design guidance](https://www.nist.gov/itl/ai/ai-standards-and-guidelines-group/sard-design-issues)
- [MITRE CWE vulnerability theory](https://cwe.mitre.org/documents/vulnerability_theory/intro.html)
- [FIRST CVSS v4](https://www.first.org/cvss/v4.0/specification-document)
