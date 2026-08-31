# STPA–Taxonomy Closed-Loop Domain

This context names the domain concepts used when a taxonomy obligation asks an
STPA analysis to revisit an earlier structural decision. It describes the
meaning of the work, not how the repository implements or stores it.

## Language

**Taxonomy obligation**:
A risk-specific requirement to account for one authoritative attack pattern
for one capability context.
_Avoid_: catalog item, coverage claim

**Phase 2 assessment**:
The reviewed account of structural STPA consideration and exact taxonomy
correspondence, including accepted relations and unresolved findings.
_Avoid_: prompt result, merged coverage score

**Obligation challenge**:
A bounded request for STPA to revisit a named structural decision because an
eligible taxonomy obligation remains to be accounted for.
_Avoid_: taxonomy scenario, automatic match, coverage assignment

**Challenge target**:
One exact taxonomy-obligation and STPA-slot pair selected for a possible
obligation challenge.
_Avoid_: candidate guess, prose match

**Eligibility**:
An explicit, evidence-backed decision that a challenge target may be
considered under an approved challenge policy.
_Avoid_: inferred trigger, implicit priority

**Original STPA decision**:
The immutable STPA disposition and evidence recorded before an obligation
challenge: an ICA, a justified N/A, or unresolved for the named target.
_Avoid_: prior answer, overwritten decision

**Reconsideration**:
The one permitted review of an original STPA decision for an eligible target;
it records a new outcome while retaining the original decision and evidence.
_Avoid_: retry, replacement, regeneration

**Challenge outcome**:
The result of a reconsideration, limited to ICA, justified N/A, or unresolved.
_Avoid_: correspondence result, scenario result

**Challenge analysis controls**:
The explicit named model profile, resolved model, deadline, and temperature
recorded for one opted-in, no-retry reconsideration attempt.
_Avoid_: inherited defaults, hidden provider settings

**Technical challenge failure**:
A provider, protocol, or identity-validation failure before a valid structural
outcome exists. It is separate from ICA, justified N/A, and unresolved.
_Avoid_: unresolved STPA result, implicit N/A

**Bounded once-only behavior**:
The rule that, for one exact Phase 2 assessment and explicit challenge budget,
each eligible target is considered at most once and the selected target count
does not exceed that budget.
_Avoid_: open-ended review, retry loop

**Accepted Phase 2 relation**:
An explicit coverage-bearing relation that passed Phase 2 validation and
adjudication for exact taxonomy and STPA identities.
_Avoid_: shared-resource link, challenge suggestion

**Structural consideration**:
The STPA account of each UCA slot as an ICA, justified N/A, or unresolved,
independent of taxonomy correspondence.
_Avoid_: taxonomy coverage

**Closed-loop STPA analysis**:
An explicitly opted-in STPA analysis that uses a Phase 2 assessment to
consider eligible obligation challenges while preserving the original STPA
analysis as history.
_Avoid_: ordinary stpa-run, hybrid generation

**Closed-loop run record**:
One content-addressed record containing the exact challenge ledger, pending
selected targets, completed or technical reconsideration attempts, and their
separate counts. It has no blended success or coverage status.
_Avoid_: rewritten assessment, combined scenario run, aggregate score

**Hybrid scenario projection**:
One immutable graph that joins an already accepted taxonomy mechanism to its
exact STPA causal path through reviewed, typed bridge evidence.
_Avoid_: generated scenario, blended coverage result, inferred match

**Normative bookkeeping fixture**:
Synthetic evidence used only to prove deterministic identity, validation, and
persistence behavior. It is never semantic evidence that a real system is
covered or ready.
_Avoid_: pilot result, reviewed production evidence

**Target-scoped semantic pilot**:
A future, explicitly bounded qualification run for named
`(relation_id, selected_candidate_id)` targets backed by fresh corrected
taxonomy scenarios and exact Phase 1, Phase 2, STPA, review, and run evidence.
_Avoid_: complete-corpus claim, automatic generation run

**Pilot readiness**:
The offline determination that a target-scoped semantic pilot has all required
exact evidence. A negative result retains typed blockers and exact counts; it
does not repair identities or start the pilot.
_Avoid_: execution readiness, scenario admission, aggregate score

**Pilot provenance bundle**:
The content-addressed record binding one generation run, its inputs, model-call
evidence, scenario artifacts, expected targets, outcomes, and exact join
counts.
_Avoid_: collection of caller assertions, raw prompt log
