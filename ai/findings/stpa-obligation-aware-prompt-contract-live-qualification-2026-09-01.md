# STPA obligation-aware prompt-contract live qualification

**Date:** 2026-09-01  
**Status:** Functionally proven on Klarna and NHS; not yet production-ready on
the current model profile.

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
