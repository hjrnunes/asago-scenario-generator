# STPA–taxonomy synthesis: Phase 3 closed-loop challenge contract

**Status:** Task 1 approved on 2026-08-31. The provider-capable Task 2 and
end-to-end Task 3 remain draft until their remaining operational decisions are
approved.

**Scope:** The third delivery phase of the STPA-led, taxonomy-audited workflow:
use the exact Phase 2 assessment to make a bounded, opt-in request for STPA to
reconsider explicitly eligible structural decisions. The result remains an
auditable STPA analysis record. It does not generate a hybrid scenario.

The [Phase 1–2 specification](stpa-taxonomy-phases-1-2-spec.md) remains the
authority for obligation identity, resource identity, correspondence, and the
three Phase 2 matrices. The [synthesis](stpa-taxonomy-synthesis.md) supplies
the causal rationale and longer-term direction. GitHub Issues remain the
durable source of approved decisions under the
[SwarmForge work contract](../../docs/development/swarmforge.md#work-contract).

## 1. Outcome and boundary

Phase 1 answers what risk-specific taxonomy obligations must be accounted for.
Phase 2 answers where those obligations do or do not have an exact,
evidence-backed relation to the existing STPA structure. Phase 3 adds one
closed loop around that observation:

```text
exact Phase 2 assessment
          │
          v
explicit eligibility + explicit budget
          │
          v
deterministic target selection
          │
          v
optional STPA analysis-adapter challenge
          │
          v
ICA | justified N/A | unresolved
          │
          v
challenge record retaining the original decision
```

The challenge asks STPA to account for a taxonomy obligation. It does not make
the taxonomy obligation an unsafe control action, and it does not convert a
resource join or a model response into correspondence. STPA remains the
causal authority; the Phase 2 assessment remains the only authority for
whether a taxonomy/STPA relation was accepted.

Phase 3 therefore has two products with different authority:

1. the unchanged `hybrid-coverage-assessment-v1` produced by Phase 2; and
2. a separate challenge record containing selection, original-decision
   snapshots, reconsideration evidence, and one of the three challenge
   outcomes for each completed reconsideration.

For the approved offline ledger slice, the record is the closed
`stpa-obligation-challenge-ledger-v1` artifact published atomically as
`stpa-obligation-challenge-ledger.yaml`. Later adapter evidence may extend the
record only through a separately approved compatible contract.

## 2. Approved invariants

The following are the proposed Phase 3 invariants to carry into an approved
issue. They are deliberately narrower than a complete command or schema
design.

### 2.1 Exact Phase 2 authority

1. A closed-loop analysis MUST consume one successfully validated,
   content-addressed `hybrid-coverage-assessment-v1` and retain its exact
   semantic digest and source pins.
2. The assessment MUST be intact before selection. A substituted, stale,
   malformed, or digest-mismatched assessment fails closed.
3. Eligibility and challenge selection MAY inspect typed Phase 2 rows,
   dispositions, accepted relation IDs, findings, and source pins. They MUST
   not rebuild any of those values from prompts, scenario prose, display
   names, resource overlap, or a second taxonomy traversal.
4. Every selected target MUST resolve through exact assessment identities. An
   unknown slot, ICA, obligation, relation, or source pin is not a challenge
   target.
5. The Phase 2 assessment is historical input. A challenge MUST NOT rewrite,
   re-digest, or silently append to that assessment.

The challenge prompt may carry exact obligation and STPA identities plus typed
evidence needed for analysis. That transport is explanatory input to the
analysis adapter; it is never a new correspondence algorithm.

### 2.2 Explicit opt-in and workflow preservation

1. Closed-loop analysis MUST be explicitly opted into by the caller and a
   selected analysis mode. The presence of a Phase 2 file, an unresolved row,
   or an eligible-target record alone MUST NOT activate it.
2. An ordinary `stpa-run` with no closed-loop opt-in MUST retain its existing
   prompts, call sequence, counts, decisions, artifacts, and exit behavior.
3. Phase 3 MUST not import a Phase 2 artifact as a hidden dependency of the
   ordinary STPA path. The opt-in boundary is the only path that may read the
   assessment for challenge purposes.
4. Phase 3 MUST not replace the original STPA run, even when a challenge
   produces an ICA. The original run remains available as the baseline
   structural analysis.

### 2.3 Decision preservation

1. Before a challenge is attempted, the record MUST capture the original
   decision for the exact target: target identity, slot identity, original ICA
   identities when present, original disposition, original evidence, and the
   applicable assessment/source digests.
2. The original decision MUST be immutable history. A reconsideration result
   is an additional fact and MUST NOT overwrite or relabel the original
   `ica`, `justified_na`, or `unresolved` disposition.
3. Every completed reconsideration MUST have exactly one challenge outcome in
   the closed vocabulary: `ica`, `justified_na`, or `unresolved`. Handling a
   provider or adapter failure before a completed outcome is an explicit
   decision in §8; it MUST NOT be silently presented as one of these outcomes.
4. An `ica` outcome MUST retain the exact new or reaffirmed ICA identity and
   the STPA evidence required by the existing structural contract. The
   details of whether it is an added ICA or a revision of an existing ICA are
   not selected by this document.
5. A `justified_na` outcome MUST retain its explicit structural rationale and
   evidence. It MUST not be inferred only from the absence of a mechanism.
6. An `unresolved` outcome MUST retain a typed reason and the evidence showing
   why the challenge did not resolve the target. It is a valid terminal result,
   not a hidden failure or an implicit N/A.

### 2.4 Bounded, once-only behavior

1. The caller MUST supply an explicit challenge budget. No default or hidden
   budget is part of this contract.
2. For one exact Phase 2 assessment and one explicit budget/policy input, each
   eligible target MUST be selected at most once. The total number of selected
   targets MUST NOT exceed the budget.
3. Selection, duplicate detection, and persistence MUST be deterministic for
   identical assessment content, eligibility input, budget, and approved
   selection-policy version. Reordering source collections MUST not change
   selected identities or serialized content.
4. A once-only challenge is not an unbounded retry loop. Whether a transport
   retry inside one opted-in provider interaction exists, and whether it is
   counted as an adapter attempt, remains an approval decision in §8.
5. A target that is not selected because the budget is exhausted remains a
   traceable non-selected eligibility result; it does not become an
   unresolved STPA decision merely because it was not attempted.

The invariant limits challenge selection. It does not decide which target
granularity, trigger, priority, or cardinality policy is correct; those must be
explicit inputs once approved.

### 2.5 Correspondence and coverage separation

1. Phase 3 MUST consume the exact accepted/rejected/unresolved relation state
   in the Phase 2 assessment. It MUST never re-derive correspondence from an
   obligation prompt, STPA prompt, final scenario prose, resource overlap, or
   keyword match.
2. A challenge outcome is not a Phase 2 relation and MUST NOT create an
   accepted relation, a relation ID, or a coverage-bearing proposal.
3. No coverage credit is allowed without an accepted Phase 2 relation. In
   particular, an ICA challenge outcome alone cannot move a taxonomy row to
   `satisfied`, and a justified N/A outcome cannot close a taxonomy obligation.
4. `related_but_not_coverage`, rejected, unresolved, contradictory, and
   unreviewed Phase 2 evidence remains outside coverage credit after a
   challenge.
5. The Phase 2 scenario-realization matrix remains
   `hybrid_generation_status: not_attempted` and
   `hybrid_admission_status: not_assessed`. Phase 3 produces no hybrid
   scenario, combined projection, admission decision, or scenario receipt.

### 2.6 Determinism, evidence, and provider boundary

1. Assessment validation, eligibility validation, target selection,
   duplicate/once-only enforcement, outcome validation, digest calculation,
   and persistence MUST be deterministic and offline.
2. No Phase 3 planning, selection, reconciliation, assessment, or persistence
   seam may construct a provider client or contact an endpoint.
3. Provider interaction is permitted only inside the explicitly opted-in STPA
   analysis adapter. The adapter receives the exact selected target and
   typed context, and returns a typed challenge result plus its call/evidence
   record; it cannot mutate Phase 2 artifacts or write confirmed relations.
4. The default deterministic tests and acceptance suite MUST use no endpoint.
   A fake analysis adapter MAY supply deterministic ICA, justified-N/A, and
   unresolved responses for contract tests. Live model behavior remains a
   separately gated qualification activity.
5. Any request/response, effective control, validation, and adapter outcome
   evidence required by the existing STPA generation contract MUST remain
   attached to the challenge record when an analysis adapter is used. The
   exact retry/exhaustion policy is not chosen here.

### 2.7 Pin and lineage integrity

1. The challenge record MUST retain the exact Phase 2 assessment digest and
   enough upstream pins to prove which capability snapshot, STPA structural
   artifacts, obligation plan, and correspondence state it observed.
2. Each original decision and challenge outcome MUST retain exact target and
   evidence references. Display names, prompt text, and fuzzy aliases are not
   identities.
3. An assessment/target mismatch MUST stop that challenge before provider
   interaction. The contract does not authorize a best-effort remapping.
4. The challenge record MUST distinguish original, selected, attempted,
   outcome, and non-selected states. Counts must be derived from those records,
   not independently maintained counters.
5. The completed lineage audit in §7 is the authority for fixture identities
   and target eligibility examples. It permits Phase 3 to consume the
   corrected Phase 2 assessment with exact STPA lineage; it does not authorize
   reuse of superseded taxonomy scenario observations.

## 3. Conceptual contract seams

These seams describe responsibilities, not approved Python names or a public
CLI. They keep pure deterministic work separate from the only place where an
LLM/provider may be used.

### 3.1 Exact assessment intake

The intake boundary accepts one closed Phase 2 assessment and verifies:

- `schema_version == hybrid-coverage-assessment-v1`;
- the recorded semantic digest matches its canonical content;
- source pins are complete and internally consistent;
- structural, taxonomy, and realization matrices remain the Phase 2 matrices;
- no challenge data has been smuggled into the historical assessment.

Intake returns an immutable assessment view. It does not load current catalog
data, resolve prose, or invoke either generation workflow.

### 3.2 Eligibility and selection

Eligibility is an explicit input to selection. A target entry identifies the
exact assessment record(s), carries the approved policy/version that makes it
eligible, and carries evidence for that decision. Selection accepts an
explicit budget and a policy input and returns a deterministic ordered set of
selected target identities plus traceable non-selected entries.

This seam must fail closed on unknown or duplicate identities and must enforce
the once-only rule. It does not decide eligibility by scanning obligation
text, hazard prose, resource names, or scenario wording.

The approved target is one exact `(obligation_id, slot_id)` pair. Eligibility
is supplied explicitly, smaller priority values sort first, and exact
obligation/slot identities break ties as recorded in §8.

### 3.3 STPA analysis adapter

The adapter is the sole provider-capable boundary. It receives one selected
obligation/STPA-slot pair at a time, the immutable
original-decision snapshot, exact Phase 2 evidence, and approved STPA context.
It returns one typed challenge outcome and evidence.

The adapter MUST preserve the existing STPA causal requirements. A returned
ICA must remain grounded in the loss/hazard/constraint/control-structure
identities and pass the applicable deterministic structural validation. A
returned justified N/A must carry explicit evidence. A returned unresolved
result must name a typed reason. The adapter cannot assert that a taxonomy
obligation is covered.

### 3.4 Challenge record and persistence

The persistence boundary writes an immutable, canonical record only after
validation. At minimum, the conceptual record contains:

```text
assessment_digest and exact source pins
eligibility/selection-policy identity
explicit challenge budget
target entries
  exact target identity
  eligibility evidence
  original decision snapshot and digest
  selection/attempt state
  challenge outcome: ica | justified_na | unresolved
   outcome evidence and exact STPA identities
  optional analysis-adapter call evidence
derived diagnostics
```

The record is separate from `hybrid-coverage-assessment-v1`. It must be
canonical, digest-verified, and atomically published once a filename/schema
decision is approved. Re-running deterministic selection/persistence with the
same inputs must not create duplicate challenge entries.

## 4. Challenge lifecycle

The lifecycle is intentionally small and preserves two histories:

| State or fact | Meaning | May it change the Phase 2 assessment? |
| --- | --- | --- |
| Original decision | Exact pre-challenge ICA/N/A/unresolved disposition and evidence | No |
| Eligible | Explicit policy/evidence permits consideration | No |
| Selected | Deterministic budgeted selection of an eligible target | No |
| Not selected | Eligible target left outside the budget or selection policy | No |
| Attempted | Opted-in adapter was invoked for the selected target | No |
| Challenge outcome | ICA, justified N/A, or unresolved, with evidence | No |
| Accepted Phase 2 relation | Existing exact, reviewed coverage relation in the assessment | Already authoritative; challenge does not create one |

An implementation may expose more operational states, but it must preserve
these semantic distinctions. In particular, a provider timeout, schema error,
or retry outcome must not be silently represented as a structural N/A or as a
new correspondence claim; the approved failure policy must define its typed
handling.

### 4.1 ICA outcome

An ICA outcome says that reconsideration identified an unsafe control action
for the exact target. It must carry the exact ICA/slot/`EXEC:*` identities that
the existing STPA structural contract accepts, causal evidence, and a trace
back to the original decision. It is an STPA result only. It is not proof that
the taxonomy mechanism and ICA are semantically equivalent.

### 4.2 Justified N/A outcome

A justified-N/A outcome says that reconsideration still found no applicable
unsafe control action for the exact target and records explicit structural
evidence. It must retain the original decision even when the new rationale is
stronger or different. Inventory completeness rules from Phase 2 continue to
apply to any claim of structural absence.

### 4.3 Unresolved outcome

An unresolved outcome says that this bounded reconsideration did not support
either an ICA or a justified N/A. It retains typed missing, contradictory, or
otherwise approved evidence. It does not imply rejection, absence, or
coverage.

## 5. Acceptance contract

The following examples are Gherkin-style contract examples. They use an
explicit eligibility fixture so they do not decide which real Phase 2 status
or target kind should trigger a challenge. The fixture supplies exact IDs and
the approved selection policy; production policy is still open in §8.

```gherkin
Feature: opt-in closed-loop STPA obligation challenge
  The Phase 2 assessment remains historical authority and each challenge is
  bounded, exact, and separately traceable.

  Background:
    Given a valid hybrid-coverage-assessment-v1 with digest "assess-A"
    And the assessment contains structural target "slot-A"
    And target "slot-A" has original disposition "justified_na"
    And target "slot-A" has original evidence "stpa-evidence-A"
    And an approved eligibility record names target "slot-A"
    And the explicit challenge budget is 1

  Scenario: ordinary STPA remains unchanged without opt-in
    When I run ordinary stpa-run without closed-loop opt-in
    Then no obligation challenge is selected or attempted
    And the STPA prompts, calls, counts, decisions, and artifacts are unchanged
    And no Phase 3 challenge record is required

  Scenario: the selector consumes the exact assessment and is offline
    When I select eligible challenge targets from assessment "assess-A"
    Then selection contains exactly target "slot-A"
    And the selection records assessment digest "assess-A"
    And no provider client is constructed
    And no network endpoint is contacted

  Scenario: a stale assessment cannot be remapped
    Given the assessment content is changed without updating its digest
    When I select challenge targets
    Then selection fails closed with a digest or integrity violation
    And no provider interaction occurs

  Scenario: one challenge can produce an ICA without replacing the original
    Given the opted-in STPA analysis adapter returns ICA "ICA-A"
    When target "slot-A" is reconsidered
    Then the challenge outcome is "ica"
    And the record retains original disposition "justified_na"
    And the record retains original evidence "stpa-evidence-A"
    And the record retains exact ICA identity "ICA-A" and challenge evidence
    And the Phase 2 assessment remains byte-equivalent to "assess-A"

  Scenario: one challenge can produce a justified N/A with evidence
    Given the opted-in STPA analysis adapter returns justified N/A evidence
    When target "slot-A" is reconsidered
    Then the challenge outcome is "justified_na"
    And original disposition and evidence remain unchanged
    And the outcome contains explicit structural rationale

  Scenario: one challenge can remain unresolved
    Given the opted-in STPA analysis adapter returns typed unresolved evidence
    When target "slot-A" is reconsidered
    Then the challenge outcome is "unresolved"
    And original disposition and evidence remain unchanged
    And the outcome is not treated as absence or coverage

  Scenario: once-only selection respects the explicit budget
    Given two eligible targets "slot-A" and "slot-B"
    And the explicit challenge budget is 1
    When deterministic selection is repeated with the same inputs
    Then exactly one target is selected in both runs
    And no target is selected more than once
    And the serialized selections are identical
    And the other eligible target is retained as not selected

  Scenario: a challenge outcome cannot create coverage
    Given target "slot-A" has no accepted Phase 2 relation
    And the opted-in STPA analysis adapter returns ICA "ICA-A"
    When target "slot-A" is reconsidered
    Then the challenge outcome is "ica"
    And no accepted Phase 2 relation or coverage-bearing proposal is created
    And the taxonomy correspondence row remains its Phase 2 unresolved state
    And hybrid generation remains "not_attempted"
    And hybrid admission remains "not_assessed"

  Scenario: correspondence is never derived from prose
    Given the exact assessment and typed eligibility records are unchanged
    But the obligation prompt and STPA response prose are changed
    When deterministic selection and persistence are repeated
    Then target identities and selection are unchanged
    And no new correspondence relation is created from the prose

  Scenario: provider interaction is confined to explicit opt-in analysis
    Given deterministic selection has selected target "slot-A"
    When closed-loop analysis is not explicitly opted in
    Then the STPA analysis adapter is not invoked
    When closed-loop analysis is explicitly opted in with a fake adapter
    Then only the STPA analysis adapter may observe a provider call
    And the returned outcome is validated and persisted without changing Phase 2
```

The examples use the approved explicit trigger and exact pair target. Provider
controls, the technical-failure record, live fixtures, and any public command
remain approval items rather than facts implied by the examples.

## 6. Explicit exclusions

Phase 3 does not:

- alter ordinary `stpa-run` behavior, prompts, counts, artifacts, or exit
  semantics;
- infer eligibility from prose, keywords, shared resources, or absence alone;
- re-run Phase 1 or Phase 2 planning, proposal generation, or correspondence
  reconciliation;
- create or promote correspondence proposals or accepted relations;
- grant taxonomy or hybrid coverage credit from an ICA challenge outcome;
- generate, select, finalize, admit, quarantine, or evaluate a hybrid scenario;
- create a combined taxonomy/STPA execution projection or bridge graph;
- replace the original STPA decision or discard its evidence;
- contact a provider from deterministic planning, selection, validation,
  reporting, or persistence;
- decide the public CLI/mode name, artifact filename/schema, target
  granularity, challenge trigger, relation cardinality, or provider failure
  policy.

## 7. Completed lineage audit and handoff

The parallel real-scenario lineage audit is complete. Its exact identity
results now constrain this contract; they are not an invitation to recover the
superseded scenario joins through prose:

- corrected offline Phase 1 retained 92 Klarna obligations and 152 NHS
  obligations, with 38 and 20 ready obligations respectively;
- corrected Phase 2 produced zero coverage-bearing proposals after manual
  calibration for both use cases;
- for Klarna's 94 taxonomy envelopes, 77 candidate IDs recompute exactly and
  join the original plan but zero join the corrected plan. The 77 are
  classified as `inconsistent_planning_input`; the remaining 17 are
  `expected_extra_candidate`; there are zero lineage bugs;
- for NHS's 27 taxonomy envelopes, 13 candidate IDs recompute exactly and join
  the original plan but zero join the corrected plan. The 13 are classified as
  `inconsistent_planning_input`; the remaining 14 are
  `expected_extra_candidate`; there are zero lineage bugs;
- every candidate ID recomputes exactly, so the corrected plan's rejection of
  the old taxonomy candidate identities is intentional rather than an
  identity-resolution failure;
- exact STPA lineage is clean: 16/16 Klarna and 18/18 NHS scenarios resolve to
  exact slot, ICA, and `EXEC:*` identities; and
- synthetic all-confirmed assessments are bookkeeping transition fixtures,
  not semantic coverage evidence.

These findings are recorded in
[phase12-live-run-klarna-nhs-2026-08-29.md](phase12-live-run-klarna-nhs-2026-08-29.md).
They make the following contract updates binding:

1. **Corrected assessment authority:** Phase 3 MAY consume the corrected
   Phase 2 assessment and the exact STPA slot/ICA/`EXEC:*` lineage. It MUST
   reject or omit any old taxonomy scenario observation whose candidate ID is
   not present in the corrected plan.
2. **Taxonomy scenario prohibition:** The 77 Klarna and 13 NHS observations
   that only join the original plan, together with Klarna's 17 and NHS's 14
   `expected_extra_candidate` observations, MUST NOT be adapted into corrected
   Phase 2 assessment rows, challenge eligibility, or corrected
   scenario-realization claims. No prose or display-name repair is permitted.
3. **Phase 3 timing:** A fresh taxonomy generation under the corrected pinned
   inputs is not required before the Phase 3 ledger contract. It is required
   only before a later Phase 4/combined-generation fixture that needs taxonomy
   scenario observations; that fixture must use newly generated envelopes whose
   candidate IDs resolve to the corrected plan.
4. **Exact STPA fixtures:** Challenge examples MAY use the audited 16/16 and
   18/18 STPA joins, but every fixture must retain the exact slot, ICA, and
   `EXEC:*` identities. The illustrative IDs in §5 remain placeholders.
5. **Eligibility evidence:** Which exact Phase 2 rows or findings are
   eligible remains a product decision in §8, but the audit classifications
   are fixed evidence: `inconsistent_planning_input` and
   `expected_extra_candidate`, with zero lineage bugs.
6. **Original evidence quality:** The audit's untraced Klarna hazards/processes
   and the clean NHS structural run remain evidence context. A warning is not
   automatically a trigger or a failure.
7. **Regression examples:** Gherkin fixtures and task handoffs must carry the
   classifications and counts above and must not treat synthetic
   all-confirmed relations as semantic truth.

No Phase 3 implementation may proceed with guessed identity mappings. The
lineage audit is a contract input, and a fresh taxonomy generation is a later
Phase 4 fixture gate rather than a Phase 3 ledger prerequisite.

## 8. Approved Task 1 decisions and remaining decisions

The following decisions were approved for Task 1 on 2026-08-31:

1. **Eligibility is explicit.** A caller supplies typed eligibility records;
   Phase 2 gaps, dispositions, prose, and resource overlap do not create them.
2. **One target is one exact pair.** A target is `(obligation_id, slot_id)`.
   Its original-decision snapshot retains every ICA already attached to that
   slot rather than selecting one ICA by prose.
3. **Selection is deterministic.** Smaller caller-supplied priority values are
   selected first; exact obligation and slot IDs break ties. One record and at
   most one later attempt belong to each exact pair.
4. **The budget is explicit.** It is a strict non-negative integer scoped to
   one ledger. Exhausted eligible pairs remain `not_selected_budget`; they do
   not become unresolved STPA decisions.
5. **Task 1 persistence is separate.** The closed
   `stpa-obligation-challenge-ledger-v1` artifact is written atomically as
   `stpa-obligation-challenge-ledger.yaml`. It pins the assessment and its
   upstream artifacts and snapshots the original decision. Task 1 has no CLI
   or report.
6. **Execution is once-only.** A later adapter gets one analysis attempt for a
   selected pair and performs no automatic retry. A technical failure is a
   separate attempt result, never an ICA, justified N/A, or unresolved STPA
   conclusion.
7. **An ICA result is additive.** It is retained as a proposed ICA in the
   challenge record and never overwrites the original STPA analysis.
8. **Ordinary STPA is unchanged.** The normal `stpa-run` command neither reads
   nor requires the challenge ledger.

Tasks 2 and 3 still require explicit approval for:

1. the model profile, effective controls, deadline, and opt-in surface for the
   provider-capable STPA analysis adapter;
2. the exact typed technical-failure record and evidence required for all
   three completed challenge outcomes;
3. run-directory placement, resume/idempotence behavior, and any public
   orchestration command;
4. whether and where challenge outcomes are presented alongside the unchanged
   Phase 2 matrices;
5. the first audited Klarna/NHS STPA pairs used for live qualification; and
6. whether unresolved or technically failed opt-in runs are reported as
   completed, degraded, or failed.

## 9. Exit criteria for Phase 3

Phase 3 is ready for a later combined-projection phase only when deterministic
tests and review evidence show that:

1. the exact Phase 2 assessment is validated and pinned before any challenge;
2. ordinary `stpa-run` remains behaviorally unchanged when opt-in is absent;
3. explicit eligibility and budget produce deterministic, once-only target
   selection with no hidden trigger or retry policy;
4. every completed reconsideration retains the original ICA/N/A/unresolved
   decision and evidence and receives exactly one typed challenge outcome;
5. ICA, justified N/A, and unresolved outcomes all round-trip with exact STPA
   identities and typed evidence;
6. no challenge path creates correspondence, coverage credit, a hybrid
   projection, or a hybrid scenario;
7. deterministic seams make no provider calls, while provider interaction is
   possible only through the explicitly opted-in STPA analysis adapter;
8. malformed, stale, substituted, unknown, and duplicate identities fail
   closed before provider interaction;
9. the completed lineage-audit classifications are reflected in exact STPA
   fixtures and approved target policy, with old taxonomy scenario observations
   excluded; and
10. the six-pack handoffs in the companion task plan contain independent
    deterministic quality and acceptance evidence.

The phase exits by producing trustworthy, bounded reconsideration evidence. It
does not exit by claiming more taxonomy correspondence or by generating a
combined scenario corpus.
