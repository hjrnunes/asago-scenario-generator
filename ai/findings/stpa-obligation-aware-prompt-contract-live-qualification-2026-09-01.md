# STPA obligation-aware prompt-contract live qualification

**Date:** 2026-09-01  
**Status:** The contract is functionally proven and a fresh OpenShift run
publishes 42 scenarios while realizing all five accepted obligation findings.
The withdrawn word-based gate would have reduced an earlier Klarna run to zero;
it is not a publication gate. The current qualification keeps the obligation
effective while preventing its taxonomy mechanism from becoming causal fact
without independent evidence.

## What was qualified

This run tested the corrected synthesis flow in its intended order:

1. retain every taxonomy obligation;
2. give STPA a compact explanation of each applicable obligation;
3. let STPA decide whether the system contains a credible unsafe-control path;
4. carry an accepted path's exact ICA, hazard, constraint, loss, control path,
   and obligation context into ordinary scenario production; and
5. report obligation consideration separately from scenario realization.

The correction does not require STPA to reproduce a taxonomy mechanism and
does not grant Phase 2 correspondence or coverage.

The implementation now includes strict Stage 2 control-action decoding,
stage-specific prompt views, prompt preflight, bounded revision, semantic ICA
compilation, exact scenario context, typed causal evidence, strict Stage 6
output parsing, per-case scenario failure isolation, a separate realization
ledger, and prompt-call evidence in the synthesis manifest.

## Runs

### NHS OcciAI

- Artifacts:
  `output/runs/20260901-synthesis-nhs-prompt-contract-v13`
- SP1 profile: `gemma4-openrouter`
- routing, ICA, and scenario profile: `gemma4-oc`
- temperature: `0.2`
- routing batch size: `2`
- workers: `4`

OpenRouter was used only for the NHS SP1 risk-derivation call. Its audited
input was 28,805 tokens, above the OpenShift profile's 21,299-token safe input
budget. The remaining calls ran on OpenShift.

### Klarna

- Artifacts:
  `output/runs/20260901-synthesis-klarna-prompt-contract-v1`
- all stages: `gemma4-oc`
- temperature: `0.2`
- routing batch size: `2`
- workers: `4`

## Results

### Semantic-quality implementation comparison

The completed semantic-quality implementation was exercised in two fresh runs:

- Klarna: `output/runs/20260901-synthesis-klarna-semantic-quality-v2`
- NHS: `output/runs/20260901-synthesis-nhs-semantic-quality-v1`

SP1 used `gemma4-openrouter`; the baseline STPA, obligation-aware routing, ICA,
and scenario calls used `gemma4-oc`. An initial all-cluster Klarna attempt was
stopped before obligation processing because the baseline Stage 2 response was
truncated and then returned the wrong shape. This was a baseline provider
failure, not a failure of the obligation prompts.

| Terminal result | Klarna | NHS |
|---|---:|---:|
| Obligations retained | 92 | 152 |
| Governance-only | 40 | 100 |
| Scenario realized | 1 | 2 |
| Risk/pattern mismatch | 45 | 38 |
| No structural route | 3 | 10 |
| Inapplicability evidence incomplete | 2 | 2 |
| ICA consideration unresolved | 1 | 0 |
| Applicable-obligation total reconciles | 52/52 | 52/52 |
| Ordinary STPA scenarios published | 35 | 33 |

This is the intended separation. All applicable obligations ran, but only
exactly supported obligation/ICA pairs received obligation credit. The many
ordinary STPA scenarios were not suppressed merely because a taxonomy pair was
weak.

The motivating NHS mass-action/data-acquisition pair now terminates as
`risk_pattern_mismatch`: the route correctly says that legal restrictions on
acquiring data are not realized by an automated mass-action mechanism. It does
not receive obligation credit.

Inspection also found one weaker NHS credit in which authentication rejection
was treated as evidence for poisoned tool output. Stronger routing prose alone
did not reliably correct Gemma: bounded replays replaced the same mechanism
first with external-content ingress and then with generic user-input
sanitization.

The final implementation therefore uses a compact second decision. It removes
capability flags, taxonomy mappings, and the proposed route rationale, then
asks whether the exact selected structural descriptions govern the distinctive
mechanism, an adjacent control, or neither. The integrated live result is:

- artifacts: `output/runs/20260902-nhs-mechanism-verifier-integrated-v2`;
- routing still selected `RESP-2:CA-2-1:NOT_PROVIDED`, preserving the ordinary
  input-sanitization STPA finding;
- the verifier classified that path as `adjacent_control` because input
  sanitization does not govern poisoned source output being interpreted as an
  operational goal;
- the route's mechanism assessment became `insufficient_evidence`; and
- accounting uses `mechanism_path_unsubstantiated`, so the route receives no
  obligation credit while remaining eligible for ordinary scenario work.

This bounded OpenShift run completes the post-guidance live sample. The whole
NHS/Klarna pipelines do not need to be repeated for this correction.

The final verifier input contained only the distinctive attack mechanism and
the exact selected structural path. It contained no reviewed-risk prose,
capability flags, taxonomy mapping strength, applicability facts, or proposed
route rationale. This prevents contextual similarity from being reused as
mechanism evidence in the second decision.

Provider lifecycle evidence is now distinct: response receipt, typed parsing,
semantic validation, compilation, and publication are recorded separately.
The NHS obligation calls completed cleanly. Klarna retained local provider and
contract failures while continuing valid sibling work, so its totals still
reconcile rather than hiding failed calls.

### Current mechanism-boundary Klarna rerun

The current live artifacts are under
`output/runs/20260901-synthesis-klarna-quality-v6`. All stages used
`gemma4-oc`, temperature `0.2`, routing batches of two, and four workers.

| Result | Current Klarna rerun |
|---|---:|
| Obligations retained | 92 |
| Governance-only | 40 |
| Addressed by an STPA finding | 5 |
| Unresolved by STPA | 47 |
| Addressed findings realized by an exact scenario | 5/5 |
| Scenario artifacts published | 42 |
| Validation errors | 0 |
| Scenario cases failed locally | 6 |

The five realization rows map to four scenarios because `SCN-035` carries two
exact obligation/ICA pairs. In every obligation-backed scenario, the Stage 5
cause is now a typed `structural_failure` with no fabricated capability or
access reference. The strongest examples are `SCN-025`, where a missing
threshold block permits a high-value transaction, and `SCN-035`, where stale
validation status causes required external-data sanitization to be omitted.

`SCN-024` still names prompt injection in its hazardous context, but that text
comes from the independently generated STPA hazard `H-3`, not from the
AP-T2-01 obligation. Its causal factor remains the mechanism-neutral failure
to evaluate a transaction against its threshold. This is an important
remaining distinction: exact STPA hazard meaning is preserved, while the
obligation itself is not treated as proof of access.

The same run exposed a separate renderer defect: the attack-tree hard template
contained examples such as “Poison PM” and “Fabricate a tool result,” which the
model copied for structural failures. The template now uses neutral
process-model divergence and feedback-path conditions. A targeted live
OpenShift rerender of the worst saved case (`SCN-030`) produced only stale,
late, inaccurate, and anomalous state leaves; it introduced no poisoning,
replay, injection, or tool-result fabrication.

The scenario count is materially higher than the previous run (42 versus 22).
That reflects model variability in how many ordinary STPA slots it marks
unsafe, not an obligation multiplier. The separate denominators and exact
realization ledger remain the reliable measures; raw scenario count is not a
quality score.

### Strict post-correction Klarna rerun

The final prompt/schema rerun is under
`output/runs/20260901-synthesis-klarna-quality-v4`. All stages used
`gemma4-oc`, temperature `0.2`, routing batches of two, and four workers.

This run proves that the corrected provider boundaries work:

- all selected defender beliefs received a non-empty vulnerability;
- the provider returned only local causal handles and the compiler restored
  valid `PM-*`, `FB-*`, and `CA-*` identities;
- each ICA finding selected exactly one governing constraint; and
- the run contained no empty-vulnerability, causal-namespace, or ambiguous
  constraint failure.

It also exposes a blocking quality result:

| Result | Strict Klarna rerun |
|---|---:|
| Obligations retained | 92 |
| Governance-only | 40 |
| Addressed by an STPA finding | 4 |
| Unresolved by STPA | 48 |
| Addressed findings realized by an exact scenario | 0/4 |
| Scenario artifacts initially published | 10 |
| Missing exact controlled-process targets | 6 |
| Word-based access diagnostics (withdrawn) | 45 false-positive-prone diagnostics |

The initial conclusion that all ten artifacts should be rejected was wrong.
The diagnostic conflated adversarial intent with technical access: for
example, “exploit a timing gap” can mean taking advantage of an existing STPA
failure and does not assert a new tool, channel, or privilege. Making that word
list a publication gate would reduce the same run to zero scenarios.

The corrected admission rule uses the typed causal evidence. Exact capability
or access-path references must resolve to the immutable context, while prose
may describe an adversary taking advantage of the declared structural
condition. Replaying the ten artifacts through all remaining structural
validators accepts 10/10. They still require the qualitative review below;
restoring them does not claim that every narrative or ICA is good.

The surviving structural material also remains uneven. Timing failures such as
late response validation and late output sanitization are clear and useful,
while several `WRONG_DURATION` findings invent persistence for actions that
look one-shot. ICA text remains repetitive (roughly 234–411 characters in the
published sample). These are the next quality issues after provider-boundary
correctness.

The final deterministic gates are green: 147 generated acceptance tests,
39/39 external production-wiring QA checks, 15/15 full-level Gherkin
mutations, and 284 focused prompt/scenario tests. Every function changed for
this correction has CRAP at or below 6. The full unit run passed 10,194 tests
with 16 skips; its only sandbox failure was the known loopback-server
restriction, and that isolated compatibility test passed when rerun with
loopback access. Source mutation was intentionally deferred.

### Earlier functional qualification

| Result | NHS | Klarna |
|---|---:|---:|
| Obligations retained | 152 | 92 |
| Governance-only | 100 | 40 |
| Addressed by an STPA finding | 3 | 9 |
| Unresolved by STPA | 49 | 43 |
| Addressed findings realized by an exact scenario | 3/3 | 4/9 |
| Scenarios generated | 10 | 6 |
| Scenario cases failed closed | 11 | 7 |
| Whole-stage failures | 0 | 0 |

The denominators remain separate. “Addressed” means that STPA found a typed
unsafe-control path for the obligation. “Realized” means that ordinary
scenario production produced a scenario retaining that exact accepted
context. Neither means Phase 2 correspondence or coverage.

## Prompt behaviour

The routing prompt no longer repeats every description in every edge and
slot. It contains one glossary entry per structural identifier and uses IDs in
the relationship tables.

| Prompt group | NHS audited input | Klarna audited input | Safe input budget |
|---|---:|---:|---:|
| Obligation routing | 13,866–14,851 | 10,292–11,568 | 21,299 |
| Obligation-aware ICA | 3,349–6,547 | 3,532–7,592 | profile-dependent, all allowed |
| Stage 5 scenario reasoning | 3,079–5,085 | 3,110–4,650 | 13,107 |
| Stage 6 rendering | 3,147–6,177 | 3,214–5,293 | 13,107 |

No corrected routing, ICA, or scenario call was rejected by prompt preflight.
The NHS SP1 exception is explicit and was routed to a profile whose context
window could accept it.

## Scenario quality

The strongest result is Klarna `SCN-001`. It turns the AP-T2-02 multi-tool
chain obligation into a concrete coordination failure: validation and
redaction are not synchronized across a tool chain, allowing cumulative
context to expose sensitive data. The mechanism, unsafe coordination action,
hazard, constraint, and Gherkin steps remain about the same concern.

Klarna `SCN-013` also retains a coherent configuration-poisoning path, and
Klarna `SCN-010` retains a plausible high-volume/redaction failure. NHS
`SCN-006` gives a coherent poisoned external-content path that redirects the
agent and leads to disclosure. NHS `SCN-019` gives a credible missing
rate-limiting/anomaly-response path to queue flooding.

The output is materially better than the pre-correction runs: accepted
scenarios now carry typed causal factors and exact local loss, hazard,
constraint, ICA, and obligation evidence. Invalid causal source identities are
rejected instead of being silently published, and one bad scenario case no
longer discards valid siblings.

Quality is still uneven:

- ICA prose is often much too long and repetitive. Exact meaning is preserved,
  but the human-facing text needs a tighter semantic writing contract.
- The current model frequently chooses the wrong causal-source namespace in
  Stage 5. Those cases fail closed, but this caused most of the 18 failed
  scenario cases.
- Some taxonomy risk-to-pattern pairings are weak before STPA sees them. For
  example, the NHS mass-action mechanism is plausible, but its reviewed risk
  context is about data-acquisition restrictions. STPA cannot repair an
  upstream semantic mismatch merely by preserving IDs.
- Many applicable obligations remain unresolved. This is visible rather than
  hidden, but it shows that the current model is not yet reliable enough for a
  production completeness claim.

The Klarna live files also exposed model-authored titles such as
`Feature: Feature: ...`. The parser now removes renderer-owned `Feature:` and
`Scenario:` prefixes deterministically. The retained live artifacts show the
pre-fix presentation bug; no new model run is needed to prove the correction.

## Qualification decision

The corrected contract is functionally demonstrated:

- obligations focus STPA without dictating findings;
- prompts fit their selected context budgets;
- opaque IDs are accompanied by local meaning;
- accepted meaning survives into generated scenarios;
- invalid model output fails locally;
- valid sibling cases continue; and
- consideration and realization are accounted for separately.

It should not yet be described as production-ready with `gemma4-oc`. The next
hardening target is provider compliance, not another architectural redesign:
make the ICA text concise, improve causal-source selection in Stage 5, and add
an upstream semantic check for obviously mismatched risk/pattern obligations.
Those improvements must retain the current fail-closed contracts.
