# SwarmForge task sequence: STPA–taxonomy synthesis, Phase 3

**Status:** Tasks 1–3 approved on 2026-08-31. Task 1 fixes explicit
eligibility, exact obligation/STPA-slot targets, priority ordering, budget, and
separate atomic persistence. Task 2 fixes the internal opt-in seam, explicit
controls, one attempt with no retry, typed outcomes, and separate technical
failure. Task 3 fixes the narrow internal composition seam, exact resume,
single atomic aggregate record, separate diagnostics, and no CLI or report.

**Source specification:**
[stpa-taxonomy-phase3-closed-loop-spec.md](stpa-taxonomy-phase3-closed-loop-spec.md)

**Prerequisites:** Accepted Phase 1 obligation planning and Phase 2 resource
identity/reconciliation contracts, plus the completed lineage-audit findings
in this document. Phase 3 may use the corrected Phase 2 assessment and exact
STPA lineage without a fresh taxonomy generation. The work must preserve the
existing `generate` and `stpa-run` surfaces and must not begin hybrid scenario
generation.

## Delivery shape

Use three dependency-ordered SwarmForge tasks. Each task passes through the
full six-pack independently and leaves a reviewable increment. Submit one task
at a time; do not run the tasks as an equal-priority batch.

| Order | Stable task name | Delivers | Depends on |
| --- | --- | --- | --- |
| 1 | `phase3-challenge-ledger` | Exact Phase 2 intake, eligibility/budget boundary, once-only selection, original-decision preservation, and deterministic challenge-record contract | Accepted Phase 2 assessment contract, corrected-plan lineage findings, and exact STPA lineage |
| 2 | `phase3-stpa-analysis-adapter` | Explicitly opted-in STPA challenge adapter with typed ICA/N/A/unresolved outcomes and isolated provider interaction | Task 1 and approved provider/outcome/failure decisions |
| 3 | `phase3-closed-loop-compatibility` | Opt-in composition, end-to-end persistence/compatibility proof, and lineage-updated deterministic acceptance | Tasks 1–2 and completed lineage-audit decisions |

The dependency direction is:

```text
completed lineage audit + corrected Phase 2 assessment
              │
              v
      challenge ledger/selection
              │
              v
      opted-in STPA adapter
              │
              v
  compatibility and acceptance proof
```

No task may introduce a Phase 2 correspondence recalculation, a hidden
dependency in ordinary `stpa-run`, or a hybrid scenario/projection path.

## Shared gates for every task

The six-pack is a sequence of responsibilities. The task handoff must identify
the evidence for each role, even when one contributor performs several roles.

1. **Specifier:** Convert the approved issue into observable behavior and
   acceptance examples. Retain the approved explicit trigger, exact-pair
   target, selection, Task 1 persistence, and Task 2 adapter/failure choices;
   record remaining orchestration choices rather than silently choosing them.
2. **Coder:** Work test-first against the smallest vertical slice. Keep pure
   selection and validation independent from STPA/provider orchestration.
3. **Cleaner:** Remove duplicate state, ambiguous names, prose joins, and
   imports from either existing generation workflow. Preserve the original
   decision as a first-class history record.
4. **Architect:** Verify exact Phase 2 digest/pin direction, closed identity
   resolution, dependency boundaries, and compatibility with the current
   architecture overview.
5. **Hardener:** Exercise stale/substituted/unknown/duplicate identities,
   budget and once-only boundaries, contradictory evidence, and provider
   failures according to the approved policy. Add mutation/property tests
   where the slice has branching or identity logic.
6. **QA:** Run independent deterministic quality and acceptance gates with no
   endpoint, then verify the issue contract, artifact cleanliness, and
   unchanged ordinary workflows.

Each task is complete only when all six handoffs are present, the focused
acceptance examples pass offline, and the task's explicit exclusions are
demonstrably still true.

---

# Task 1: `phase3-challenge-ledger`

## Objective

Establish a deterministic, exact, and auditable Phase 3 ledger boundary. It
must consume one intact Phase 2 assessment, accept explicit eligibility and an
explicit budget, select eligible targets at most once, and retain the original
STPA decision without contacting a provider.

## Problem statement

Phase 2 already records structural consideration and taxonomy correspondence.
Without a separate challenge ledger, a later closed loop could overwrite an
N/A, reinterpret an unresolved row, or silently turn a shared-resource finding
into a coverage claim. This task makes the historical boundary and selection
budget executable before any provider-capable adapter exists.

## Required behavior

Implement the domain and persistence seam described in the Phase 3 contract:

- validate the exact closed `hybrid-coverage-assessment-v1` schema, semantic
  digest, and source-pin universe before selecting a target;
- accept explicit eligibility records that point to exact Phase 2 structural
  identities and carry policy/evidence; do not infer eligibility from prose or
  absence;
- accept an explicit challenge budget and an explicitly versioned selection
  policy; do not add a hidden default;
- select at most one challenge for each eligible target and no more targets
  than the budget, with deterministic identity ordering for identical inputs;
- retain not-selected eligible targets as traceable selection results without
  relabeling their original STPA disposition;
- snapshot the exact original decision, including target/slot/ICA identities,
  disposition (`ica`, `justified_na`, or `unresolved`), evidence, assessment
  digest, and upstream pins;
- accept corrected Phase 2 assessment identity and exact STPA lineage from the
  completed audit; old taxonomy scenario observations whose candidate IDs are
  absent from the corrected plan are rejected or omitted rather than adapted;
- reserve the closed challenge-outcome vocabulary `ica`, `justified_na`, and
  `unresolved`, with typed evidence and exact STPA references;
- persist the immutable `stpa-obligation-challenge-ledger-v1` record as
  `stpa-obligation-challenge-ledger.yaml` with a canonical, digest-verified,
  atomic round trip;
- derive diagnostics from retained records rather than hand-maintained
  counters; and
- make no provider/model/network calls.

The approved target, trigger, ordering, budget, and persistence decisions are
fixed inputs to this task. Provider controls and the technical-failure record
remain deferred to Task 2 and must not leak into the ledger builder.

## Acceptance criteria

1. A valid Phase 2 assessment is consumed by exact digest and pins; changing
   its content without its digest fails closed before selection.
2. An unknown, duplicate, stale, or mismatched slot/ICA/obligation identity is
   rejected without a best-effort prose or display-name mapping.
3. Explicit eligibility is required for selection; an unresolved assessment
   row alone does not silently create a target.
4. Identical assessment, eligibility, policy, and budget inputs produce the
   same selected IDs and canonical serialized content under reordered source
   collections.
5. The selected set never contains more targets than the explicit budget and
   never selects the same eligible target twice.
6. A budget-exhausted eligible target remains a not-selected record and does
   not become an unresolved STPA decision merely because it was not attempted.
7. Every selected/attempted record retains an immutable original ICA/N/A/
   unresolved decision snapshot and its evidence.
8. The three allowed challenge outcomes round-trip with typed evidence and
   exact STPA identities; no other outcome string is accepted.
9. Challenge records retain the Phase 2 assessment digest and source pins and
   cannot mutate or append to the historical Phase 2 assessment.
10. No challenge result creates a proposal, accepted relation, coverage credit,
    hybrid projection, scenario receipt, or admission decision.
11. Pure intake, eligibility, selection, validation, digest, and persistence
    tests construct no provider client and contact no endpoint.
12. The focused Gherkin examples in the source specification pass in
    deterministic mode, including unchanged ordinary `stpa-run` behavior.
13. Corrected Phase 2 input accepts exact STPA slot/ICA/`EXEC:*` lineage and
    rejects or omits superseded taxonomy scenario candidate identities; a
    fresh taxonomy generation is not required for this ledger slice.

## Explicit exclusions

- No provider-capable STPA adapter.
- No policy-derived trigger unless an approved issue supplies that policy.
- No target granularity beyond the approved exact obligation/STPA-slot pair.
- No provider retry, timeout, malformed-response, or failure classification
  policy.
- No correspondence proposal/reconciliation or Phase 2 assessment rewrite.
- No hybrid scenario generation, combined projection, admission, or report
  coverage credit.
- No adaptation of old taxonomy scenario observations into corrected-plan
  rows or scenario-realization claims.
- No public CLI; Task 1 uses the approved normative artifact filename only.

## Six-pack evidence gates

### Specifier gate

- The issue names the exact assessment schema/digest boundary and the
  completed lineage-audit revision used by fixtures, including the corrected
  plan and exact STPA lineage.
- Eligibility input, budget, and selection policy are explicit.
- The approved explicit trigger, exact pair target, ordering, budget, and
  persistence decisions are asserted directly; deferred provider controls and
  technical-failure shape are not hidden in test helpers.
- Gherkin examples cover stale assessment, explicit eligibility, budget,
  once-only selection, original-decision preservation, and rejection of old
  taxonomy scenario identities.

### Coder gate

- Closed models/validators are implemented test-first behind a narrow seam.
- Canonical selection and persistence are pure/offline and independent of
  STPA/provider modules.
- Original decision snapshots and challenge outcomes are immutable and
  content-pinned.
- Focused tests cover accepted and rejected inputs before any integration.

### Cleaner gate

- No duplicate representation of the Phase 2 assessment is introduced.
- Names distinguish original decision, selection, attempt, and outcome.
- No prose, keyword, shared-resource, or display-name join remains in the
  ledger path.
- Artifact writes and digest computation have one authoritative path.

### Architect gate

- Dependency direction follows Phase 2 models inward; ordinary `stpa-run` has
  no new required Phase 2 input.
- Assessment history is referenced by exact digest/pins rather than copied and
  silently modified.
- The proposed challenge record shape does not leak persistence into the
  eligibility/selection interface.
- Open product decisions are visible in the issue before Task 2 starts.

### Hardener gate

- Property tests prove selection invariance under collection reordering and
  no duplicate target selection.
- Negative fixtures cover digest substitution, unknown identity, duplicate
  target, budget overrun, forged original evidence, and invalid outcome.
- Mutation or equivalent adversarial tests demonstrate that removing the
  once-only and no-coverage guards is detected.
- All negative paths remain provider-free.

### QA gate

- Focused unit/acceptance tests pass without `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.
- The canonical quality sequence is run as appropriate for the changed
  contract, with generated acceptance artifacts untracked.
- An ordinary `stpa-run` compatibility fixture shows no changed prompt,
  count, decision, artifact, or exit behavior when opt-in is absent.
- Handoff includes the exact corrected-assessment digest, selected/not-selected
  records, round-trip artifact, exact STPA lineage, and unresolved decisions.

## Review evidence

The handoff must include one representative challenge record using an exact
corrected Phase 2 fixture, one invalid/substituted fixture, deterministic
selection evidence under reordered inputs, exact STPA slot/ICA/`EXEC:*`
lineage, proof that old taxonomy scenario identities are rejected or omitted,
and proof that no provider was constructed.

---

# Task 2: `phase3-stpa-analysis-adapter`

## Objective

Add the only provider-capable boundary: an explicitly opted-in STPA analysis
adapter that receives a selected target and returns one validated ICA,
justified-N/A, or unresolved outcome while preserving the original decision.

## Problem statement

The closed loop needs STPA reasoning to answer an eligible challenge, but the
existing ordinary `stpa-run` must remain a stable peer product surface. Mixing
provider calls into planning, Phase 2 reconciliation, or default STPA execution
would make deterministic behavior and provenance ambiguous. This task isolates
the provider interaction and keeps all challenge evidence in a separate record.

## Required behavior

- accept only the Task 1 selected target and its exact original-decision
  snapshot;
- carry structured Phase 2 obligation/evidence context into the adapter
  without recomputing correspondence;
- require explicit closed-loop opt-in before any provider interaction;
- keep deterministic preflight, identity resolution, outcome validation, and
  persistence outside the provider boundary;
- return exactly one typed challenge outcome for each completed
  reconsideration: `ica`, `justified_na`, or `unresolved`; handling an
  adapter/provider failure before a completed outcome follows the approved
  issue policy and is not silently mapped to one of those outcomes;
- validate an ICA against the existing STPA causal identities and structural
  requirements, validate justified-N/A with explicit evidence, and retain
  typed unresolved evidence;
- preserve the original decision and evidence on every result;
- retain provider request/response/control/validation evidence according to
  the approved STPA adapter contract; and
- leave Phase 2 relation state, matrices, digests, and artifacts unchanged.

The approved Task 2 seam is internal and one-target-at-a-time. It requires an
explicit boolean opt-in and caller-supplied adapter factory; records the named
profile, resolved model, positive deadline, and explicit temperature; permits
one attempt and zero automatic retries; and records technical failure outside
the ICA/N/A/unresolved vocabulary. The closed failure kinds are
`provider_initialization`, `provider_timeout`, `provider_error`,
`invalid_response`, and `identity_validation_failed`. Task 2 adds no public
command, run-directory placement, report, or live qualification call.

## Acceptance criteria

1. Without explicit opt-in, the adapter is not invoked and no provider client
   is constructed.
2. With explicit opt-in and a deterministic fake adapter, each completed
   reconsideration yields exactly one of the three closed outcomes.
3. ICA results retain exact slot/ICA/`EXEC:*` identities, causal evidence, and
   a reference to the original decision; malformed or dangling identities fail
   closed according to the approved adapter policy.
4. Justified-N/A results retain explicit structural rationale and evidence and
   do not infer absence from an empty response.
5. Unresolved results retain a typed reason/evidence and are not silently
   changed to N/A, rejected, or covered.
6. Original ICA/N/A/unresolved disposition and evidence are byte-equivalent in
   the challenge record before and after adapter execution.
7. A challenge outcome never creates an accepted Phase 2 relation, relation
   proposal, correspondence credit, or hybrid realization row.
8. Provider request/response evidence is retained only for the explicitly
   opted-in adapter interaction; deterministic selection and persistence remain
   offline and provider-free.
9. Existing `stpa-run` calls, prompts, counts, decisions, artifacts, and exit
   behavior are unchanged when the new mode is absent.
10. Default acceptance uses a fake adapter or deterministic fixture and never
    reaches an LLM endpoint; any live test remains separately opt-in.

## Explicit exclusions

- No modification of the default `stpa-run` prompt/call path.
- No Phase 1/Phase 2 rerun, correspondence inference, proposal confirmation,
  or assessment mutation.
- No implicit trigger from an unresolved or N/A row.
- No alternative target/cardinality, provider controls, timeout, or technical
  failure vocabulary; the approved explicit-controls and one-attempt/no-retry
  rules remain binding.
- No hybrid projection, scenario generation, finalization, admission,
  quarantine, evaluation, or coverage report.

## Six-pack evidence gates

### Specifier gate

- The issue records the approved opt-in boundary and exactly which adapter
  outcome/failure semantics are in scope.
- It names the selected target and original-decision inputs without inventing
  a trigger or grouping policy.
- It distinguishes provider evidence from Phase 2 authority and includes the
  ICA/N/A/unresolved Gherkin examples.

### Coder gate

- A fake-provider contract is implemented first for all three outcomes.
- The adapter receives typed IDs/evidence and returns a typed result; no raw
  prose is used as an identity or correspondence key.
- The existing STPA structural validators are reused through a dependency-safe
  seam.
- Provider construction is impossible from the deterministic selector and
  persistence modules.

### Cleaner gate

- The adapter is the sole provider-capable module in the slice.
- Original decision, challenge outcome, provider evidence, and Phase 2
  relation state have distinct names and storage paths.
- No duplicate prompt-to-relation or scenario-to-obligation logic is added.
- Opt-in plumbing does not leak into ordinary STPA defaults.

### Architect gate

- Imports follow the architecture overview; Phase 2 models are consumed as
  typed inputs and no generation workflow implementation is imported into
  Phase 2.
- The adapter's output can be persisted without mutating the Phase 2
  assessment.
- Causal STPA authority remains with loss/hazard/constraint/control-structure
  evidence.
- Provider controls and failure choices are documented as approved issue
  decisions, not inferred from live-run behavior.

### Hardener gate

- Tests cover opt-in bypass, stale assessment, forged target, malformed ICA,
  evidence-free N/A, unresolved evidence, contradictory provider output, and
  provider failure according to the approved policy.
- The once-only guard rejects a second challenge for the same exact target.
- Mutation/adversarial tests show that provider output cannot create coverage
  or overwrite original evidence.
- A no-endpoint run proves deterministic seams remain offline.

### QA gate

- All deterministic unit/acceptance tests pass without a reachable endpoint.
- A compatibility comparison runs ordinary `stpa-run` with and without the
  absent opt-in configuration and shows unchanged artifacts/counts.
- A fake-adapter run proves all three challenge outcomes round-trip and keeps
  Phase 2 byte-equivalent.
- Any live adapter check uses the explicit environment gate and is reported
  separately from deterministic quality evidence.

## Review evidence

The handoff must include the fake-adapter contract, one result for each closed
outcome, provider-boundary evidence, an unchanged Phase 2 assessment digest,
and ordinary `stpa-run` compatibility evidence.

---

# Task 3: `phase3-closed-loop-compatibility`

## Objective

Compose the exact ledger and opt-in STPA adapter into a bounded closed-loop
analysis path, update fixtures from the lineage audit, and prove that Phase 3
remains observational with respect to correspondence, coverage, hybrid
generation, and ordinary workflows.

## Problem statement

The first two tasks establish isolated contracts. The final Phase 3 slice must
prove their composition: exact assessment intake selects only approved
targets, the adapter is called only when explicitly enabled, every result
retains the original decision, and no result changes Phase 2 coverage or starts
hybrid generation. Real-run lineage findings must be reflected in fixtures so
the first pilot cannot hide identity gaps behind prose.

## Required behavior

- compose Task 1 selection and Task 2 adapter calls behind an explicitly
  approved opt-in orchestration surface;
- pass the exact Phase 2 assessment digest/pins and selected target identities
  through the whole path;
- enforce the explicit budget and once-only rule end to end;
- persist deterministic selection and challenge records atomically and
  idempotently according to the approved schema decision;
- retain non-selected, attempted, and outcome records distinctly;
- leave the input Phase 2 assessment byte-equivalent and report no new
  accepted relation or coverage credit;
- leave hybrid generation/admission in its Phase 2 `not_attempted`/
  `not_assessed` state and produce no combined scenario artifacts;
- update real-use-case fixture identities and examples from the completed
  lineage audit: Klarna's 77 original-plan-only IDs are
  `inconsistent_planning_input` and its 17 remaining IDs are
  `expected_extra_candidate`; NHS's corresponding counts are 13 and 14;
  every candidate ID recomputes exactly and there are zero lineage bugs;
- exclude all old taxonomy scenario observations from corrected-plan
  assessment, challenge eligibility, and scenario-realization claims. A fresh
  taxonomy generation under corrected pinned inputs is required only for a
  later Phase 4/combined-generation fixture that needs taxonomy scenarios,
  not for this Phase 3 composition; and
- document unresolved product decisions and any audit-dependent limitation in
  the issue handoff rather than guessing.

The exact CLI, report, resume, and artifact-name surface remains an approval
item. Composition may be exercised through a typed internal seam and fake
adapter until that decision is approved.

## Acceptance criteria

1. An opted-out ordinary `stpa-run` is behaviorally unchanged and never reads
   the Phase 2 assessment for challenge purposes.
2. An opted-in run rejects a stale/substituted Phase 2 assessment before any
   adapter/provider call.
3. Given exact eligibility and budget inputs, composition selects the same
   target IDs and writes the same canonical record on repeated runs.
4. Every completed reconsideration has one original-decision snapshot and one
   typed outcome; no target is challenged twice and the budget is never
   exceeded. Adapter/provider failures follow the approved failure policy.
5. All three outcomes remain distinguishable and traceable to exact STPA
   identities and evidence.
6. The Phase 2 assessment digest, matrices, relation state, correspondence
   dispositions, diagnostics, and hybrid status remain unchanged after a
   challenge.
7. No prompt/prose/resource overlap creates a relation, and no challenge
   outcome contributes coverage without an accepted Phase 2 relation that was
   already present in the input assessment.
8. Klarna's 77 original-plan-only candidate IDs are classified as
   `inconsistent_planning_input`, its 17 remaining IDs as
   `expected_extra_candidate`, and NHS's corresponding counts are 13 and 14;
   all IDs recompute exactly and zero lineage bugs are recorded. No old
   taxonomy scenario identity is adapted into the corrected assessment.
9. Exact STPA lineage remains clean for 16/16 Klarna and 18/18 NHS scenarios,
   each resolving to slot/ICA/`EXEC:*`; Klarna's untraced-hazard/process
   warnings and NHS's clean structural run are retained as evidence context,
   not silently converted into eligibility or failure decisions.
10. Default deterministic composition constructs no provider client and
    contacts no endpoint; only explicit opt-in invokes the Task 2 adapter.
11. No hybrid scenario, combined projection, admission, realization credit, or
    scenario report is produced.
12. The complete focused Gherkin contract and the repository quality sequence
    pass with generated/runtime state absent from the diff.

## Explicit exclusions

- No change to existing Phase 1/Phase 2 schemas or denominators.
- No automatic trigger, target grouping, relation cardinality, or provider
  failure policy beyond approved issue decisions.
- No hybrid scenario generation or combined projection (that is a later phase).
- No model-assisted correspondence, prose matching, or resource-only credit.
- No ordinary `stpa-run` behavior change or hidden required sidecar.
- No claim that the synthetic all-confirmed live-run transition fixture is
  semantic coverage evidence.

## Six-pack evidence gates

### Specifier gate

- The issue approves the orchestration opt-in surface or explicitly keeps it
  internal for this slice.
- The approved explicit trigger, exact pair target, once-only policy, and Task
  1 persistence contract are retained; remaining provider-failure,
  orchestration, and presentation choices stay blocked rather than inferred.
- The completed lineage classifications and exact STPA fixture IDs are
  attached to the issue; old taxonomy scenario IDs are explicitly excluded.
- End-to-end Gherkin examples cover opt-in, stale input, budget, three
  outcomes, preservation, no-coverage, and no-hybrid behavior.

### Coder gate

- Composition delegates to the Task 1 and Task 2 seams rather than reimplementing
  selection, identity, or provider logic.
- Exact assessment digest/pins are checked once at the boundary and retained
  throughout the result.
- Atomic persistence and idempotent deterministic rerun behavior are tested.
- No default STPA path imports or requires Phase 3 artifacts.

### Cleaner gate

- End-to-end state names clearly distinguish assessment history, eligibility,
  selection, attempt, challenge outcome, and existing Phase 2 relation.
- Duplicate orchestration or report coverage calculations are removed.
- Lineage fixture updates use exact candidate/slot/ICA/`EXEC:*` identities and
  do not add fallback text matching.
- No generated live-run outputs or harness state enter the repository diff.

### Architect gate

- The dependency graph remains `Phase 2 assessment → ledger → opt-in adapter`.
- Phase 3 output is an adjacent challenge record, not a rewritten Phase 2
  assessment or hybrid scenario envelope.
- The unchanged ordinary workflow has a compatibility proof at the public
  boundary.
- Later combined-projection work can consume accepted Phase 2 relations
  without treating challenge outcomes as correspondence.

### Hardener gate

- End-to-end adversarial tests cover assessment substitution, eligibility
  spoofing, duplicate targets, reordered inputs, budget exhaustion, adapter
  bypass, outcome spoofing, coverage promotion, and hybrid-generation leakage.
- Property/mutation tests prove deterministic selection/persistence and
  original-evidence preservation.
- The corrected-plan boundary rejects or omits Klarna's 77
  `inconsistent_planning_input` and 17 `expected_extra_candidate` old taxonomy
  scenario identities, and NHS's corresponding 13 and 14 identities,
  according to their audited classifications; all candidate IDs recompute
  exactly and no lineage bug is masked.
- Provider call evidence proves the boundary is opt-in-only.

### QA gate

- `./scripts/quality.sh`, deterministic acceptance, and the unit suite pass in
  the configured repository sequence; generated acceptance artifacts remain
  untracked.
- Ordinary `stpa-run` and existing taxonomy behavior are compared before and
  after with unchanged counts/prompts/artifacts.
- A fake-adapter end-to-end run validates all three outcomes and confirms the
  exact Phase 2 assessment digest is unchanged.
- The handoff reports lineage classifications, unresolved decisions, and
  separately identifies any opt-in live evidence.

## Review evidence

The handoff must include an end-to-end deterministic fixture, the immutable
input Phase 2 assessment and output challenge record, repeated-run byte
comparison, three outcome traces, no-coverage/no-hybrid proof, lineage audit
classification, and ordinary workflow compatibility evidence.

---

## Completed lineage-audit handoff

The parallel audit has updated the task cards and fixtures. The exact evidence
in
[phase12-live-run-klarna-nhs-2026-08-29.md](phase12-live-run-klarna-nhs-2026-08-29.md)
records:

- Klarna has 94 taxonomy envelopes: 77 IDs recompute exactly and join only the
  original plan (`inconsistent_planning_input`), 17 are
  `expected_extra_candidate`, zero join the corrected plan, and zero lineage
  bugs were found;
- NHS has 27 taxonomy envelopes: 13 IDs recompute exactly and join only the
  original plan (`inconsistent_planning_input`), 14 are
  `expected_extra_candidate`, zero join the corrected plan, and zero lineage
  bugs were found;
- every candidate ID recomputes exactly, and the corrected plan intentionally
  invalidates all old taxonomy scenario candidate identities;
- exact STPA joins are clean for all 16 Klarna and 18 NHS scenarios, each with
  exact slot/ICA/`EXEC:*` identity;
- corrected Phase 1 counts are 92 Klarna and 152 NHS obligations, with 38 and
  20 ready obligations;
- zero coverage-bearing proposals remain after reviewed calibration for both
  use cases; and
- synthetic all-confirmed relations remain only a transition/bookkeeping
  fixture, not semantic truth.

Task 1 may begin from the corrected Phase 2 assessment and exact STPA lineage.
A fresh taxonomy generation is not a prerequisite for the Phase 3 ledger,
adapter, or compatibility contract. Before any later Phase 4/combined-
generation fixture that needs taxonomy scenario observations, generate a fresh
taxonomy corpus under the corrected pinned inputs and require every candidate
ID to resolve to that corrected plan. Never adapt the old taxonomy envelopes.

The remaining handoff items are product decisions, not unresolved lineage
findings: exact challenge eligibility/target policy, provider failure policy,
and persistence/orchestration surface. Do not resolve them in a proposer,
prompt, or fixture helper.

## Submission procedure

For each stable task name:

1. create or update the GitHub Issue with the corresponding body and accepted
   Gherkin examples;
2. obtain specifier approval for the task-specific decisions and lineage
   handoff;
3. run the six-pack in order and retain each role's evidence;
4. review implementation, architecture, deterministic gates, and compatibility
   before submitting the dependent task; and
5. amend downstream task bodies if an upstream contract is intentionally
   changed.

The three tasks are intentionally sequential. The lineage audit is complete;
independent investigation of live-run quality may continue in parallel but may
not silently alter the Phase 3 contract.

## Phase 3 exit evidence

The task sequence is complete only when the approved closed-loop contract is
implemented and all of the following are independently evidenced:

- exact Phase 2 assessment intake and digest/pin preservation;
- explicit eligibility and budget with deterministic once-only selection;
- original ICA/N/A/unresolved decision and evidence retained for every attempt;
- typed ICA/justified-N/A/unresolved challenge outcomes;
- provider interaction confined to explicit opt-in STPA analysis;
- zero new correspondence or coverage credit without an accepted Phase 2
  relation;
- zero hybrid scenario/projection generation;
- ordinary `stpa-run` unchanged; and
- lineage-audit classifications and unresolved product decisions documented.
