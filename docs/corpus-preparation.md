# Corpus candidate preparation

## Scope and evidence standard

This is a candidate audit, not a frozen calibration/holdout split. It records nine JavaScript or TypeScript vulnerable/fixed pairs for injection or server-side request forgery (SSRF). Broken-access-control cases were not added because the inspected OpenSSF snapshot did not provide a candidate with equally direct metadata in the requested families.

The audit uses the official OpenSSF CVE Benchmark snapshot at commit [`91c59fd54b2b768c0f310bb0027d2ac59cdf74d4`](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark/tree/91c59fd54b2b768c0f310bb0027d2ac59cdf74d4) for repository, commit, weakness, and CWE metadata. License identifiers were checked against upstream license text or, for devcert, the upstream package manifest at the exact fixed revision. Each record links the evidence it relies on.

`metadata_verified` means only that the OpenSSF record, vulnerable/fixed commit identifiers, language-bearing vulnerable file, and upstream license evidence were inspected. It does **not** mean the vulnerability was reproduced. No candidate is `reproduction_verified` in this preparation pass.

## Selection

| Candidate | Family | Language | Readiness | Relationship note |
| --- | --- | --- | --- | --- |
| CVE-2020-15152 | SSRF | JavaScript | Metadata ready | Independent repository |
| CVE-2020-8205 | SSRF | JavaScript | Metadata ready | Independent repository |
| CVE-2017-18352 | Injection (XSS) | JavaScript | Metadata ready; group before split | Rendertron shared commit pair |
| CVE-2017-18353 | Injection (XSS) | JavaScript | Metadata ready; group before split | Rendertron shared commit pair |
| CVE-2017-18354 | SSRF | JavaScript | Metadata ready; group before split | Rendertron shared commit pair |
| CVE-2020-7752 | Injection (command) | JavaScript | Metadata ready | Independent repository |
| CVE-2020-5251 | Injection (SQL) | JavaScript | Metadata ready | Independent repository |
| CVE-2020-15123 | Injection (command) | JavaScript | Metadata ready | Independent repository |
| CVE-2019-10778 | Injection (command) | TypeScript | Metadata ready | Independent repository |

The mix intentionally keeps three SSRF records, multiple injection mechanisms, and one TypeScript source case. It does not claim family balance or representativeness.

## Pairing and contamination controls

Every record keeps its vulnerable and fixed commit together. CVE-2017-18352, CVE-2017-18353, and CVE-2017-18354 share the Rendertron repository and the same vulnerable/fixed commit pair. They must be assigned to the same future split and treated as one root-cause group for independence calculations. Repository-level grouping should also be used if the candidate set expands with additional cases from any listed upstream.

This is a public, longstanding benchmark. Model pretraining, tool tuning, public write-ups, and prior exposure to the vulnerable or fixed source can contaminate results. A later split must therefore:

1. group identical commit pairs and repositories before randomization;
2. measure results as public-corpus performance, not previously unseen-vulnerability performance;
3. avoid putting variants of one root cause across calibration and holdout sets;
4. retain the OpenSSF snapshot identifier and evidence links in the frozen manifest; and
5. record any prompt, rule, or tool tuning performed with these cases.

## Reproduction blockers

The `reproductionCommand` values are command templates for the OpenSSF driver interface. They require a configured local tool ID, tool dependencies, and candidate source checkouts. Those prerequisites were not prepared in this audit. No vulnerable application was executed, no live target was tested, and no network-enabled exploit validation occurred.

Before promoting a record to `reproduction_verified`, run the selected static analysis or regression reproducer against both commits, preserve only non-sensitive summarized evidence, and place any vulnerable application execution in a network-disabled container. Failed setup, missing historical dependencies, or an ambiguous signal must leave the record `blocked` or `metadata_verified`, never silently promoted.

## Split readiness

All nine records are ready for later grouped split construction at the metadata level. None is ready to support a claim of end-to-end vulnerability reproduction. The Rendertron trio contributes three labels but only one independent repository/commit-pair group; the current audit therefore represents seven independent groups.
