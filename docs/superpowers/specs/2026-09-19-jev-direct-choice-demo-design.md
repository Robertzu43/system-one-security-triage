# Jev-Native Direct-Choice Security Demo

Status: approved design
Date: 2026-09-19

## Objective

Replace the published demo's threshold-routed Jev result with a direct, probability-based Jev classification over the same final label space used by Terra and Opus. Keep the existing recorded Terra and Opus results unchanged for this iteration and rerun only Jev over the same frozen 100 cases.

The new run must answer one narrow question: given the frozen security rubric and the shown evidence, which of five mutually exclusive outcomes best describes the case? Jev supplies a typed Choice distribution; repository code maps the selected option to the existing disposition and family fields without applying risk thresholds.

This remains a descriptive experiment over 100 hand-curated synthetic cases. It does not establish general model superiority or production vulnerability-detection performance.

## Why the current run is not sufficient

The current Jev adapter asks ten Noul questions and one Score question, then applies eight hand-selected thresholds. Any router result other than `likely_vulnerability` or `likely_safe`, including `needs_deep_review`, is published as `insufficient_context`.

That design measures Jev plus an uncalibrated routing policy while Terra and Opus directly select the scored outcome. The recorded artifact also retains only the normalized final decision, so the Jev probabilities needed to diagnose the router are unavailable. The published `33%` result is therefore a property of that pipeline, not a defensible direct estimate of Jev's classification quality.

## Evaluation contract

### Jev rubric and comparison boundary

A committed rubric defines the terms supplied to Jev:

- **Vulnerable:** the shown evidence establishes an actor-controlled or otherwise untrusted influence, a path to security-sensitive behavior, no effective shown control for that path, and plausible security impact.
- **Safe:** the relevant path is shown and an effective control prevents the tested vulnerability. Missing code is not evidence of safety.
- **Insufficient context:** evidence required to establish either vulnerability or safety is not shown.
- **Injection:** untrusted data can change the meaning of a command, query, expression, template, interpreter input, or equivalent executable syntax.
- **Broken access control:** an actor can perform an operation or access a resource without the authorization required for that actor, operation, or resource.
- **SSRF:** an actor can influence a server-side request so it can reach an unintended destination or network resource without an effective destination restriction.

The existing Terra and Opus runs used the same evidence corpus and the same three dispositions and vulnerability families, but they did not receive this exact Choice criteria object. Reusing them is an explicit interim scope decision, not a claim that all three provider requests were rerun under a new byte-identical rubric. The dashboard must disclose that only Jev was rerun.

### Final label space

All evaluators select exactly one of these five semantic outcomes:

1. `vulnerable_injection`
2. `vulnerable_broken_access_control`
3. `vulnerable_ssrf`
4. `safe`
5. `insufficient_context`

Repository code maps the first three to disposition `vulnerable` plus their family. `safe` and `insufficient_context` map to their matching disposition and a null family.

### Jev protocol

Jev receives one TypeSafe Choice question with the five outcomes as structured criteria. Each criterion includes what the outcome means, what distinguishes it from neighboring outcomes, and representative examples grounded in the three supported vulnerability families.

The SDK's selected Choice is the final Jev classification. The application validates that the selected option has the highest reported probability; a tie is valid when the selected option is one of the tied maxima. The application must not add risk, confidence, family, or exploitability thresholds and must not convert low confidence into `insufficient_context`.

The normalized result preserves:

- selected option;
- probability for every option;
- Choice confidence;
- model ID and token usage; and
- mapped disposition and family.

Validation requires the exact five probability keys, finite values from zero through one, a sum within `0.02` of one, confidence from zero through one, and a selected option whose probability is maximal. Invalid envelopes remain explicit errors.

### Terra and Opus controls

The committed Terra and Opus artifacts from `2026-09-19-public-v2` remain byte-for-byte unchanged. They continue to provide useful recorded controls over the same corpus, but they are not new observations from the Jev Choice run.

## Recorded artifacts

The revised Jev artifact uses a new immutable run ID. Existing artifacts remain unchanged as historical evidence. The optional Jev `choice` field extends the existing schema without changing how the old Terra and Opus artifacts parse.

Every result retains the existing normalized fields. Jev valid results additionally contain a public `choice` object:

```json
{
  "selected": "vulnerable_injection",
  "confidence": 0.82,
  "probabilities": {
    "vulnerable_injection": 0.86,
    "vulnerable_broken_access_control": 0.02,
    "vulnerable_ssrf": 0.01,
    "safe": 0.06,
    "insufficient_context": 0.05
  }
}
```

Terra and Opus results do not invent comparable probabilities. Their `choice` field is absent. Raw provider envelopes remain excluded from public artifacts.

Dashboard generation rejects corpus mismatches, incomplete coverage, invalid probability distributions, or a Jev selected option inconsistent with its normalized disposition and family. A publication bundle may contain the new Jev artifact beside exact copies of the existing Terra and Opus artifacts; their embedded run IDs and artifact hashes retain the true provenance.

## Scoring

The primary comparison remains identical for all three evaluators:

- overall five-outcome accuracy;
- vulnerability recall, including the correct vulnerability family;
- per-family accuracy;
- confusion matrix;
- error count; and
- recorded mean latency and available usage/cost.

The case explorer reports Jev's probability distribution and Choice confidence. This iteration does not add aggregate probability metrics.

No confidence cutoff changes the primary Jev prediction. The recorded selected option is scored exactly as Terra's and Opus's selected outcome is scored.

## Dashboard

The dashboard describes the result as a direct-classification demonstration, not a universal model benchmark. It explains that Jev is a System One decision model returning a typed Choice distribution, while Terra and Opus are reasoning/generative models returning structured final answers.

The scoreboard gives all three evaluators equal weight for the shared primary metrics. The case explorer shows Jev's five probabilities and confidence beside the three final decisions. A visible note says Jev was rerun with a direct Choice while Terra and Opus are retained from the earlier recording.

The previous threshold-routed run must not remain the default comparison. It remains committed and traceable as an archived run, labeled `Jev + threshold router`, with a note that `needs_deep_review` was collapsed into `insufficient_context`.

## Recording and publication

The recorder writes only a new Jev artifact under a new run ID; it never overwrites `2026-09-19-public-v2`. After successful validation, the publication directory combines that new Jev artifact with byte-for-byte copies of the existing Terra and Opus artifacts. Their artifact hashes must remain identical to `2026-09-19-public-v2`.

The static dashboard continues to replay saved artifacts only. Browser actions never invoke a provider. GitHub Pages publication continues to rebuild the generated dataset from committed artifacts without provider credentials.

## Failure handling

- Missing credentials fail before the first provider request.
- Invalid Choice responses become explicit Jev errors rather than guessed decisions.
- Low confidence remains valid recorded information and does not become an error or abstention.
- Interrupted or incomplete recordings remain unpublishable.
- A corpus mismatch prevents dashboard generation.
- Provider usage and cost remain unavailable when the provider does not supply defensible values; unavailable never means zero.

## Verification

Automated checks cover:

- exact five-option Jev Choice configuration;
- Choice response parsing, probability sums, selected-option consistency, and malformed responses;
- exact mapping from each Choice option to disposition and family;
- absence of threshold routing from the direct Jev demo adapter;
- preservation of low-confidence selected outcomes;
- backward-compatible artifact parsing and corpus mismatch rejection;
- preservation of Jev probabilities in generated dashboard data;
- disclosure that only Jev was rerun;
- archived-run labeling;
- complete offline dashboard generation; and
- full repository checks without paid provider calls.

The dashboard case explorer is manually checked after the generated dataset is built to confirm that all five probabilities and Choice confidence render for a recorded Jev result.

One explicit live smoke case is run before starting the paid 100-case recordings. The immutable public run is recorded only after the smoke result validates.

## Acceptance criteria

1. Jev selects one of the five outcomes through a single typed Choice distribution over the unchanged 100-case corpus.
2. No threshold router modifies Jev's selected direct-classification outcome.
3. Public Jev results preserve the complete validated probability distribution and confidence.
4. Terra and Opus retain their exact `2026-09-19-public-v2` artifact hashes and are not called again.
5. Shared accuracy and recall metrics score the same five-outcome task for all evaluators.
6. Jev probabilities are visible but are not compared with unavailable LLM confidence values.
7. The dashboard discloses the mixed recording provenance and does not describe the result as a simultaneous rerun.
8. The old threshold-routed Jev artifact remains committed and traceable.
