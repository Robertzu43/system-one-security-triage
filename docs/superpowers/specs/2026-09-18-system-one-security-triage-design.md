# System One Security Triage

Status: approved design
Date: 2026-09-18

## Objective

Build a reproducible TypeScript/Node cybersecurity benchmark and static dashboard
showing how Jev can triage security candidates before expensive reasoning models
investigate them.

The repository name is `system-one-security-triage`. The public demo may use the
competitive framing **Jev vs Opus vs Terra**. The eventual publication title will
be chosen after the measurements reveal the strongest defensible result.

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

Use a frozen, redacted Juice Shop revision for development, prompt design,
threshold calibration, dashboard examples, and qualitative case studies.

Juice Shop is not the sole or primary holdout because it is public training
software. Challenge identifiers, solutions, marker comments, tests, and tutorial
material can reveal expected answers and may have appeared in model training data.
Remove those artifacts from model inputs while retaining a private mapping to the
underlying vulnerability root causes.

### OpenSSF CVE Benchmark

Use pinned, real vulnerable and patched JavaScript/TypeScript revisions from the
OpenSSF CVE Benchmark as the untouched public holdout. Verify the language,
localization, build requirements, reproduction, and upstream license of every
selected case.

### Safe controls

Include patched counterparts and representative non-vulnerable routes, sinks, and
authorization checks. An absence of generated candidates is not proof that code is
safe; candidate-generation coverage is measured separately.

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
            +--------------+--------------+
            |                             |
            v                             v
     Controlled evaluators          Jev security judgments
     Terra / Opus later             batched atomic questions
            |                             |
            +--------------+--------------+
                           v
                Deterministic router
          likely_safe / likely_vulnerability /
                    needs_deep_review
                           |
                           v
               Agentic Terra/Opus review
                   for escalations only
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

## Jev judgments

Jev receives one packet once and answers independent questions together:

- Can an untrusted actor influence the value?
- Can the value reach the security-sensitive operation shown?
- Does the shown validation or sanitization block the relevant attack?
- Does the operation cross an authorization boundary?
- Is the required authorization actually enforced?
- Could the behavior violate confidentiality, integrity, or availability?
- Does the packet support injection, broken access control, or SSRF?
- On a concrete ordered rubric, is exploitation unreachable, theoretical,
  constrained, or direct?

Use Nouls for independent yes/no judgments, a Choice only where answers are
mutually exclusive, and a Score for the ordered exploitability rubric. Raw
probabilities are retained. Code combines them into routing outcomes; Jev does not
own the control flow.

Thresholds are tuned only on calibration data and frozen before the holdout.
High-impact or uncertain cases escalate. The implementation must not compare Jev's
probabilities directly with an LLM's self-reported confidence.

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

### End-to-end cascade

Run these arms:

- frozen scanner alone;
- Jev on every generated candidate;
- Terra on every candidate;
- Jev routing to Terra for escalated cases;
- later, Opus on every candidate and Jev routing to Opus.

For agentic review, use the same read-only repository snapshot, network policy,
command allowlist, tool-call limit, token budget, and wall-clock cap. This is a
system comparison, not a claim that Jev and a tool-using LLM perform the same task.

Pin exact model snapshots, SDKs, prompts, schemas, scanner versions, rules,
containers, concurrency, retry policies, and run dates. Do not use moving aliases in
headline results.

## Metrics

Report:

- candidate-generation coverage;
- vulnerability-level recall;
- alert precision and verified false alerts per repository and KLOC;
- abstention and escalation rates;
- recall lost at the router gate;
- analyst success conditional on escalation;
- validated yield missed by the frozen Semgrep configuration;
- results by vulnerability family and severity;
- actual tokens and fully loaded cost, including retries and escalations;
- cold and warm end-to-end p50/p95 latency at fixed concurrency.

Pre-register a recall non-inferiority margin after auditing the available sample
size. Select thresholds and escalation budgets only on calibration data. Use paired,
repository-clustered confidence intervals. Keep recall and precision separate rather
than presenting F1 as the headline metric.

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
- router thresholds and boundary cases;
- known vulnerable and safe fixtures for all three families;
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
