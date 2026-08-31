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
The exact STPA structural identity selected for a possible obligation
challenge.
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
