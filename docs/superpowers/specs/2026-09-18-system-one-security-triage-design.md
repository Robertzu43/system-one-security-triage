# System One Security Triage

Status: approved design
Date: 2026-09-18

## Objective

Build a reproducible TypeScript/Node cybersecurity benchmark and static dashboard
showing how Jev can triage security candidates before expensive reasoning models
investigate them.

The repository name is `system-one-security-triage`. The public demo may use the
competitive framing **Jev vs Opus vs Terra**. Claim 1 below is the preregistered
primary claim. The eventual publication title may emphasize a supported result but
must not replace, broaden, or obscure that primary claim after results are known.

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

1. A Jev-routed cascade can preserve vulnerability recall while reducing cost and
   latency relative to sending every candidate to a reasoning model.
2. Jev can reduce the false-alert burden of a frozen Semgrep configuration without
   sacrificing the preregistered recall target.
3. A broad deterministic inventory plus Jev can produce independently validated
   findings missed by that exact Semgrep version, ruleset, and configuration.

The third claim must be stated narrowly. It is not evidence that the system finds
everything missed by security scanners generally.

## Corpus

### OWASP Juice Shop

Use a frozen, redacted Juice Shop revision only for development, prompt design,
dashboard examples, and qualitative case studies. Do not use Juice Shop to select
thresholds or escalation budgets.

Juice Shop is not the sole or primary holdout because it is public training
software. Challenge identifiers, solutions, marker comments, tests, and tutorial
material can reveal expected answers and may have appeared in model training data.
Remove those artifacts from model inputs while retaining a private mapping to the
underlying vulnerability root causes.

### Calibration repositories

Reserve separate JavaScript/TypeScript repositories for calibration. They must be
repository-disjoint from Juice Shop and the final holdout. Use them to select
thresholds and escalation budgets after prompts, packet construction, and routing
logic have been developed on Juice Shop.

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

Include patched counterparts and representative non-vulnerable routes, sinks, and
authorization checks. A patch establishes that its target vulnerability was removed;
it does not establish that the entire route, file, or repository is safe. Label the
patched example as negative only for that target instance. Adjudicate unrelated
findings as separate instances.

An absence of generated candidates is not proof that code is safe;
candidate-generation coverage is measured separately.

Split development, calibration, and holdout data by repository and underlying
vulnerability root cause. Vulnerable/patched pairs and related examples must remain
in the same split.

## Ground truth

The unit of measurement is one deduplicated vulnerability instance, not one alert,
line, file, or Juice Shop challenge. A record contains:

- repository and immutable commit;
- vulnerability family and CWE;
- attacker precondition and entry point;
- affected operation, source/sink path, or authorization boundary;
- vulnerable and patched locations;
- a safe reproduction or regression test;
- provenance and independent reviewer decisions.

Before the holdout run, freeze a private matching ledger that maps every known
evidence-packet ID to zero or more target-instance IDs. A prediction matches a known
instance only when it comes from a mapped packet, selects the correct vulnerability
family, and identifies a labeled vulnerable span or the labeled source-to-sink or
authorization path. Multiple alerts matching the same target instance count as one
true positive. One alert cannot satisfy multiple target instances unless the frozen
ledger explicitly records that shared root cause. Unmatched predictions are
adjudicated as possible new instances and then deduplicated by root cause.

Known target instances that produce no candidate remain in the recall denominator
and count as false negatives. A model abstention or final `manual_review` outcome on
a known vulnerable instance also remains in the denominator and counts as a false
negative for automated detection recall. Abstentions and manual-review outcomes are
reported separately and never disappear from scoring.

Claim 2 uses a different, explicitly named metric: retained-alert recall. Its
denominator is the set of deduplicated known vulnerable target instances matched by
at least one raw Semgrep finding. A target instance is retained when at least one of
its matching findings remains an alert after Jev filtering, including an unresolved
finding sent to review. It is a false negative for retained-alert recall only when
Jev suppresses every matching Semgrep finding. Retention does not imply automated
detection; unresolved retained findings contribute to review workload, not automated
detection recall. The scorer implements these as separate metrics with separate
outcome mappings.

Two security reviewers label real findings as `confirmed`, `not_vulnerable`, or
`insufficient_evidence` while blinded to the system that produced them. A third
review or consensus process adjudicates disagreements. Unresolved cases remain
separate and are never silently counted as false positives.

Every confirmed real vulnerability requires a non-destructive, sandboxed proof or
a source/fix validation showing that the vulnerable behavior disappears after the
patch.

## Architecture

```text
Pinned repository revision
        |
        +-- Semgrep -> ordinary security findings
        |
        +-- AST inventory -> routes, input sources, sinks,
                             auth checks, dependency calls
                           |
                           v
                    Evidence packets
            code slice + one-hop context + metadata
                           |
             +-------------+-------------+
             |                           |
             v                           v
   Controlled Jev/Terra/Opus      Jev security judgments
       without tools              batched atomic questions
             |                           |
             |                           v
             |                Deterministic router
             |             +-------------+-------------+
             |             |             |             |
             |             v             v             v
             |        likely_safe      likely_     needs_deep_review or
             |          suppress    vulnerability  insufficient_context
             |             |              |             |
             |             |              |             v
             |             |              |    Agentic Terra/Opus review
             |             |              |             |
             |             |              +------+------+
             |             |                     |
             +-------------+---------------------+
                                   |
                                   v
                     Final no_alert / alert /
                            manual_review
                                   |
                                   v
                        Ground-truth validation
                                   |
                       +-----------+-----------+
                       v                       v
                Benchmark report       Interactive dashboard
```

One TypeScript CLI performs discovery, packet construction, evaluator invocation,
routing, and scoring. Inputs and outputs are immutable JSONL artifacts. Routing
rules and thresholds live in one reviewable module. There is no database or
workflow framework.

## Candidate generation

Semgrep and the deterministic AST inventory are complementary candidate sources.
The inventory must cover, at minimum:

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

Agentic review uses a sanitized repository snapshot, not the original checkout. The
snapshot excludes answer-bearing tests, advisories, challenge metadata, solution
material, vulnerable/fixed labels, and Git history while preserving executable code
needed for analysis. Reproduction inputs, regression proofs, patches used as labels,
and the private matching ledger remain available only to validators. Record the
sanitization manifest and snapshot content hash. Terra-all and Jev-to-Terra receive
the identical snapshot; apply the same rule to both Opus arms.

One-hop context is a starting budget, not evidence that omitted controls do not
exist. The packet records whether route middleware, upstream data flow, sanitizers,
and authorization checks were resolved. If evidence needed for a decision lies
outside the packet or cannot be resolved, the outcome is `insufficient_context` and
must escalate. “Not shown” never means “not enforced,” “unsanitized,” or “safe.”

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
probabilities are retained. Code combines them into routing outcomes; Jev does not
own the control flow.

Thresholds are tuned only on calibration data and frozen before the holdout.
High-impact, uncertain, or context-incomplete cases escalate. Any required evidence
dimension marked unresolved forces `insufficient_context`, regardless of other
probabilities. The implementation must not compare Jev's probabilities directly
with an LLM's self-reported confidence.

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

### Controlled model comparison

Jev, Terra, and later Opus receive byte-identical redacted evidence with no web or
repository tools. Each model uses a preregistered model-native rendering and output
mechanism, then maps to the shared record:

```text
decision: vulnerable | safe | abstain
family: injection | broken_access_control | ssrf
evidence_span_ids: [...]
```

Jev uses typed atomic questions and supplied span choices. Terra and Opus use their
native structured-output mechanism. Only the bounded decision, family, and evidence
localization are compared. Prose quality and LLM self-confidence are not benchmark
targets.

### Claim 1: cascade efficiency at matched recall

Build one combined Semgrep-plus-AST candidate pool, then run these arms:

- Terra reviewing every candidate;
- Jev routing the identical candidate pool, with Terra reviewing only
  `needs_deep_review` and `insufficient_context` outcomes;
- later, the equivalent all-Opus and Jev-to-Opus arms.

Terra receives identical agentic permissions and per-candidate budgets in the
Terra-all and Jev-to-Terra arms: the same sanitized, read-only repository snapshot,
network policy, command allowlist, tool-call limit, token budget, and wall-clock cap.
Only the set of candidates sent to Terra differs. Apply the same rule to Opus. This
is a system comparison, not a claim that Jev and a tool-using LLM perform the same
task.

### Claim 2: Semgrep false-alert reduction

Use only the frozen raw Semgrep findings as the candidate pool and compare:

- raw Semgrep, where every Semgrep finding is an alert;
- Semgrep-to-Jev, where Jev suppresses only `likely_safe`, emits
  `likely_vulnerability`, and retains `needs_deep_review` or
  `insufficient_context` as unresolved alerts requiring review.

Do not include AST-only candidates in this comparison. The combined Semgrep-plus-AST
pipeline is reported separately and cannot isolate filtering of Semgrep false alerts.
Score this claim with retained-alert recall and retained-alert precision. Report the
number and rate of unresolved retained alerts as review workload. Do not reuse the
automated detection recall mapping from Claim 1.

### Claim 3: validated yield beyond Semgrep

Run the frozen AST inventory alongside Semgrep. An AST-only candidate is not itself
Semgrep-missed yield: Semgrep may flag the same deduplicated target instance at a
different location. Report a confirmed instance as additional validated yield only
when the frozen matching ledger shows that no Semgrep finding matches that target
instance anywhere in the repository. Apply the ground-truth and adjudication rules
above before counting it.

Pin exact model snapshots, SDKs, prompts, schemas, scanner versions, rules,
containers, concurrency, retry policies, and run dates. Do not use moving aliases in
headline results.

## Metrics

Report:

- candidate-generation coverage, with known no-candidate instances counted as false
  negatives in end-to-end recall;
- automated detection recall for Claim 1;
- retained-alert recall and retained-alert precision for Claim 2;
- alert precision and verified false alerts per repository and KLOC;
- abstention, manual-review, insufficient-context, escalation, and unresolved-review
  workload rates;
- recall lost at the router gate;
- analyst success conditional on escalation;
- validated yield missed by the frozen Semgrep configuration;
- results by vulnerability family and severity;
- actual tokens and fully loaded cost, including retries and escalations;
- cold and warm end-to-end p50/p95 latency at fixed concurrency.

The preregistered primary hypothesis is that Jev-to-Terra loses no more than two
percentage points of automated detection recall versus Terra-all while reducing
fully loaded cost and end-to-end latency. Fix that two-point margin before assessing
sample size. Then determine whether the available repository count and vulnerable
instance count can detect it with adequate power; do not widen the margin after
seeing the corpus or results.

The primary recall claim passes only when the one-sided 95% confidence bound for
`recall(Jev-to-Terra) - recall(Terra-all)` is above `-0.02`. Cost and latency must
also favor the cascade under their preregistered comparisons. If the corpus is too
small, the confidence bound crosses the margin, or ground truth remains insufficient,
the result is inconclusive—not “recall preserved.” Select thresholds and escalation
budgets only on calibration data. Use paired, repository-clustered confidence
intervals. Keep recall and precision separate rather than presenting F1 as the
headline metric.

Freeze the efficiency measurements before the holdout:

- The cost unit is fully loaded USD per repository. It is the actual model/API spend
  plus discovery and packet-construction compute valued at one preregistered cloud
  runner's hourly price. Include all retries, backoff time, and reasoning-model
  escalations. Exclude one-time corpus download, dependency installation, container
  image construction, private validation, and report rendering from both arms.
- The primary latency statistic is median cold end-to-end wall-clock time per
  repository. Timing starts immediately before Semgrep and AST discovery and ends
  after the final `no_alert`, `alert`, or `manual_review` records are durably written.
  It includes discovery, packet construction, model requests, retries, backoff, and
  escalations.
- Run five timed repetitions of each arm for each repository in randomized,
  interleaved order at the same fixed concurrency. Start each repetition from the
  same preinstalled sanitized snapshot with local result/tool caches cleared. Do not
  use provider batch APIs or prompt caching for the primary measurement. Report p95
  latency and warm-cache behavior only as secondary diagnostics.
- For each repository, average fully loaded cost and take the median latency across
  its five repetitions. The cost criterion passes only when the one-sided 95%
  repository-clustered bootstrap upper bound for
  `cost(Jev-to-Terra) / cost(Terra-all)` is below `1.0`. The latency criterion uses
  the same rule for the ratio of per-repository median latencies. Both criteria and
  the recall criterion must pass; otherwise the primary claim is inconclusive.

## Report and dashboard

The CLI writes immutable run artifacts. A generated Markdown report and static
dashboard read the same scored result files.

The dashboard provides:

- a Jev vs Terra vs Opus comparison for recall, precision, cost, and latency;
- a pipeline waterfall from candidates through escalations and confirmations;
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
  matched by a Semgrep finding and therefore adds no Claim 3 yield;
- router thresholds and boundary cases;
- forced escalation for missing middleware, sanitizer, authorization, or call-path
  context;
- known vulnerable and safe fixtures for all three families;
- recall accounting for no-candidate, abstained, and manual-review positives;
- separate retained-alert and automated-detection outcome mappings;
- sanitized-snapshot exclusion and content-hash checks;
- model-output parsing and failure classification;
- metric calculations and confidence-interval inputs;
- agreement between CLI results, report, and dashboard.

A small end-to-end fixture runs the complete pipeline without paid model calls.
Live-model smoke tests remain explicit and separately reported.

## Explicit exclusions

- Full OWASP Top Ten coverage in the first release.
- Claims of exhaustive vulnerability discovery.
- Comparing Jev probabilities with LLM verbal confidence.
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
