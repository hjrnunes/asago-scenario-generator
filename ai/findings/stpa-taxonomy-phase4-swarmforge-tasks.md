# SwarmForge task sequence: STPA–taxonomy synthesis, Phase 4

**Status:** Proposed — pending user approval. This plan is not an approved
work item. Do not submit implementation tasks until the Phase 4 contract issue
accepts or changes the companion specification.

**Source contract:**
[`stpa-taxonomy-phase4-combined-projection-spec.md`](stpa-taxonomy-phase4-combined-projection-spec.md)

## Boundary and prerequisites

Phase 4 means **combined projection only**. It composes already accepted Phase 2
relations into an immutable graph that retains a separate canonical taxonomy
mechanism materialization and the STPA causal path. Phase 5 owns scenario
generation and finalization and is explicitly excluded.

Required upstream inputs:

- accepted Phase 1 obligation plan for candidate identity and disposition;
- a separate content-addressed `CandidateMaterializationSet` whose entries
  contain complete canonical mechanism projections and match Phase 1 candidate
  records;
- the exact Phase 2 assessment and reconciliation authority, including the
  proposal-set pin and digest;
- a successful `SystemResourceMapValidation` attestation;
- a `PinnedStpaProjectionAttestation` containing exact loss, control structure,
  ICA, slot, and `EXEC:*` projection authorities;
- exact typed confirmed review/mechanism evidence and the approved closed
  bridge vocabulary/evidence authority; and
- the existing Phase 3 contract, treated as historical diagnostics only.

A fresh taxonomy generation is **not** required to implement the deterministic
contract. It **is** required for a later target-scoped semantic pilot. The pilot
must name an explicit expected `(relation_id, selected_candidate_id)` list; it
must not claim a complete plan or corpus. Current `generate` is live, IBM-only
filtered, has no `--plan`, and sees only 20/49 Klarna risk cards and 38/112 NHS
risk cards. The recorded blockers are old Klarna joins 0/94, old NHS joins
0/27, and zero accepted coverage-bearing relations in both corrected
assessments. Do not adapt old IDs or use synthetic all-confirmed data as
semantic evidence.

## Delivery shape

Use three dependency-ordered, pipeline-sized tasks. Submit one task at a time;
do not run them as an equal-priority batch.

| Order | Stable task name | Delivers | Depends on |
|---|---|---|---|
| 1 | `phase4-projection-authority` | Closed inward models, one `HybridProjectionInputs` envelope, exact authority/materialization resolution, confirmed review evidence, and typed exclusions | Approved Phase 4 contract; accepted Phase 1/2 models; exact STPA authority |
| 2 | `phase4-bridge-composition-persistence` | Closed bridge evidence/endpoints, deterministic DAG composition, canonical digests, and atomic YAML persistence | Task 1 and the fixed bridge endpoint table |
| 3 | `phase4-acceptance-pilot-gate` | Gherkin/runtime, independent QA, compatibility proof, and an offline target-scoped pilot-readiness harness | Tasks 1–2 and later corrected-plan/review evidence for a pilot |

The dependency direction is:

```text
Phase 1/2 exact authority
          │
          v
closed projection identity + typed exclusions
          │
          v
operator/curated bridge validation + DAG composition
          │
          v
atomic projection-set artifact + acceptance/compatibility evidence
```

No task may add scenario generation, finalization, a provider call, a public
CLI/report, Phase 2 recalculation, or a hidden dependency in `generate` or
`stpa-run`.

## Shared quality gates

Every task must identify evidence for the six responsibilities:

1. **Specifier:** approved behavior, constraints, exclusions, fixed endpoint
   table, digest recipe, and examples are written in the Phase 4 issue.
2. **Coder:** red tests precede the smallest typed vertical slice; source
   models, graph logic, and persistence remain separate.
3. **Cleaner:** one identity constructor, one digest path, one bridge vocabulary,
   no prose joins, and no duplicated coverage calculations.
4. **Architect:** dependency direction is inward from typed Phase 1/2/STPA
   artifacts; Phase 3 remains historical; existing workflows remain unaware.
5. **Hardener:** stale, substituted, unknown, duplicate, non-projectable,
   resource-mismatched, unreviewed, cyclical, and reordered inputs fail closed
   or become explicit typed exclusions; malformed/tampered authorities are
   fatal, never exclusions.
6. **QA:** deterministic tests use no endpoint; independent artifact QA,
   Gherkin mutation, source mutation, CRAP, DRY, and compatibility evidence are
   retained.

The repository quality target is CRAP ≤ 6 and source mutation ≥ 80%; changed
covered sites should have no surviving mutants. Generated acceptance artifacts
remain ignored.

---

# Task 1: `phase4-projection-authority`

## Objective

Create the closed inward domain boundary for one exact combined projection and
its typed omissions. Resolve every identity through intact Phase 1/2 and STPA
authorities without composing bridges or writing a file yet.

## Owned paths

Proposed implementation ownership:

```text
src/asago_scenario_generator/models/hybrid_scenario_projection.py
src/asago_scenario_generator/models/hybrid_projection_inputs.py
src/asago_scenario_generator/models/candidate_materialization.py
src/asago_scenario_generator/pipeline/hybrid_scenario_projection.py
src/asago_scenario_generator/models/__init__.py       # exports only
tests/test_hybrid_scenario_projection.py
tests/test_hybrid_scenario_projection_architecture.py
```

The pipeline file may contain explicit outer adapters from current
`ProjectedCandidate`/`CandidateExecutionEnvelope` values into neutral
`MechanismProjection`/`CausalProjection` values. The model files MUST NOT
import pipeline types. The task MUST NOT edit ordinary generation runners,
Phase 1/2/3 models, public CLI modules, or reports.

## Required behavior

- Define closed, immutable `MechanismProjection`, `CausalProjection`,
  `CandidateMaterializationSet`, `PinnedStpaProjectionAttestation`,
  `HybridCorrespondenceAttestation`, `ConfirmedCoverageReview`, `BridgeLink`, and
  `HybridProjectionInputs` models with the exact fields in the companion
  contract.
- Use the exact unit identity
  `(relation_id, obligation_id, selected_candidate_id, ica_id,
  exec_candidate_id)`.
- Enforce at most one output unit for each unique requested relation ID and
  require an explicit `bridge_links` input collection.
- Match each materialization entry to a Phase 1 `CandidateRecord`, plan pin,
  selected candidate, disposition, and the framed
  `asago.phase1-candidate-record.v1` digest over the complete canonical record.
  Do not depend on old live scenario envelopes.
- Resolve the exact accepted Phase 2 relation, obligation, risk, pattern,
  selected candidate, slot, ICA, `EXEC:*`, resource links, hazards, and
  constraints across the supplied artifacts.
- Require exact proposal-set/reconciliation pins and a successful resource-map
  attestation, plus a pinned STPA projection wrapper.
- Construct materialization, correspondence, STPA, and confirmed-review
  attestations only through verified `from_artifacts` adapters over the exact
  typed source artifacts and their recomputed pins; the builder rejects raw
  dictionaries and directly assembled authority lists.
- Retain exact source pins and the required homogeneous evidence class
  (`normative_bookkeeping_fixture` or `reviewed_semantic_evidence`).
- Require typed confirmed review/mechanism evidence with reviewer identity and
  digest, independent of bridge evidence.
- Represent all per-relation omissions with the closed typed exclusion
  vocabulary from the source contract.
- Treat Phase 3 outputs as historical diagnostics only; they cannot promote a
  relation or add coverage.
- Make malformed, substituted, or tampered source/digest/schema/pin defects
  fatal before constructing any partial result; only intact-source
  relation-local ineligibility becomes an exclusion.
- Keep models free of pipeline, filesystem, provider, and generation-runner
  imports.
- Enforce closed typed mechanism predicates and complete local referential
  integrity for mechanism steps/conditions/bindings and causal
  nodes/edges/trace paths; reject arbitrary predicate strings, dangling
  references, wrong-kind edges, duplicate IDs, multiple/nonterminal `EXEC:*`
  nodes, and cycles.

## Red tests and Gherkin obligations

Write failing tests first for:

1. a valid closed envelope and exact unit;
2. extra fields, mutable nested values, unsupported schemas, and mixed evidence
   classes;
3. Phase 1 plan/materialization pin mismatch as fatal;
4. missing materialization, non-projectable candidate, and candidate-binding
   mismatch as relation-local exclusions;
5. proposal-set/reconciliation and STPA-wrapper digest substitution as fatal;
6. relation/obligation/candidate/ICA/`EXEC:*`/hazard/constraint mismatch;
7. related-only, unresolved, contradictory, or Phase 3-only relation;
8. same `EXEC:*` with distinct ICA identities remaining distinct; and
9. reviewer/digest mismatch or bridge evidence reused as mechanism evidence.
10. direct wrapper construction bypass, arbitrary source pins, an incorrect
    Phase 1 candidate-record digest, and a factory/source-artifact mismatch;
11. free-form predicates, dangling mechanism references, wrong-kind causal
    edges, missing loss-to-`EXEC:*` trace members, and nonterminal `EXEC:*`.

The first Gherkin examples may describe in-memory construction, but they must
not imply persistence or scenario generation until Task 2 exists.

## Stop conditions

Stop and return to the specifier if:

- the slice needs a full projection in the Phase 1 plan, a second
  taxonomy/STPA traversal, fuzzy/prose identity repair, or an untyped bridge;
- a Phase 3 result is being used to establish correspondence; or
- a model field would require changing an existing Phase 1–3 schema.
Stop the whole operation, rather than converting the defect to an exclusion,
on any malformed or tampered authority, digest, or pin.

## Task 1 exit evidence

- Focused model/authority tests pass.
- Architecture tests prove no generation/provider/filesystem dependency.
- Negative tests fail closed for every identity and pin substitution path.
- Ruff, formatting, and diff checks pass.
- No persistence, CLI, report, or ordinary-workflow changes are present.

---

# Task 2: `phase4-bridge-composition-persistence`

## Objective

Validate explicit bridges and their fixed typed endpoints, compose the taxonomy
and STPA subgraphs into a deterministic DAG, compute canonical IDs/digests, and
atomically publish the projection set.

## Owned paths

Proposed implementation ownership:

```text
src/asago_scenario_generator/pipeline/hybrid_scenario_projection.py
src/asago_scenario_generator/pipeline/hybrid_scenario_projection_persistence.py
src/asago_scenario_generator/models/hybrid_scenario_projection.py
tests/test_hybrid_scenario_projection.py
tests/test_hybrid_scenario_projection_persistence.py
tests/fixtures/hybrid-scenario-projection-set.yaml
```

If Task 1 places the bridge model in a separate inward model module, retain
that boundary rather than duplicating it. Do not edit `generate`, `stpa-run`,
Phase 2 reconciliation, or the artifact generator.

## Required behavior

- Implement exactly the fixed bridge vocabulary and endpoint table:
  `corrupts_process_model`, `delays_feedback`, `perturbs_control_action`,
  `enables_unsafe_action`, and `realizes_unsafe_outcome`; direction is always
  taxonomy → STPA.
- Require typed `BridgeEvidence` with exact artifact pin/record ID, closed
  evidence kind, provenance, reviewer/curator identity, and explanatory-only
  rationale. Only `operator_declared` or `curated` evidence can authorize.
- Reject model-proposed, unreviewed, keyword-derived, relabelled-prose, and
  resource-only bridges; retain their exact typed exclusions.
- Validate typed taxonomy/STPA endpoint unions against the selected authority;
  no endpoint rule may be guessed or deferred to implementation.
- Preserve taxonomy step order, STPA causal-factor order, and the terminal UCA/
  `EXEC:*` step; accept only bridge edges that keep the combined graph acyclic.
- Reject duplicate/semantic-equivalent edges, cycles, reversed local order,
  dangling nodes, and projections without a causal bridge.
- Produce at most one projection for each accepted requested relation and keep
  excluded relations as typed exclusions in the set.
- Sort all collections canonically and compute deterministic projection/set
  digests using existing version-framed canonical JSON, never YAML bytes.
- Atomically write
  `hybrid-scenario-projection-set.yaml`, reload through the closed model, and
  compare the semantic digest before reporting success.
- Keep the Phase 2 assessment and Phase 3 record byte-equivalent and unchanged.

## Red tests and Gherkin obligations

Write failing tests first for:

1. each of the five bridge kinds with every permitted exact endpoint union;
2. missing, model-proposed, unreviewed, relabelled-prose, and resource-only
   evidence;
3. unknown namespace/kind, dangling endpoint, duplicate edge, reversed edge,
   and cycle;
4. two distinct ICAs sharing one `EXEC:*` identity;
5. reordered taxonomy/STPA inputs yielding byte-identical IDs, digests, and
   output;
6. fatal source-pin and digest substitution before publication;
7. atomic interruption preserving the previous valid artifact;
8. empty projections with explicit exclusions; and
9. normative fixture output retaining its non-semantic evidence class.

The persistence acceptance feature must assert the exact filename,
round-trip bytes, typed exclusions, zero provider/network calls, and no blended
score or readiness verdict.

## Stop conditions

Stop publication if:

- any bridge endpoint, evidence record, or source pin cannot be resolved
  exactly;
- a bridge is authorized only by model output, prose, shared resources, or
  `EXEC:*` coincidence;
- the graph has a cycle or reverses an authoritative subgraph order;
- a projection would create a relation, coverage, scenario, or execution
  result; or
- atomic reload does not reproduce the same canonical digest and bytes.

## Task 2 exit evidence

- Focused bridge/DAG/persistence tests pass.
- A committed normative fixture round-trips with exact canonical content and is
  explicitly marked `normative_bookkeeping_fixture` and non-semantic.
- Source mutation has no surviving covered-site mutants; CRAP is ≤6; Ruff and
  diff checks pass.
- The Phase 2 assessment, reconciliation, and Phase 3 records remain unchanged.
- No provider, network, generation, CLI, or report path was introduced.

---

# Task 3: `phase4-acceptance-pilot-gate`

## Objective

Prove the complete Phase 4 contract independently and provide an offline,
target-scoped gate that distinguishes a deterministic contract fixture from a
real semantic pilot.

This task may create acceptance and QA harnesses. It must not perform live
taxonomy regeneration, call a provider, generate scenarios, or finalize an
artifact.

## Owned paths

Proposed acceptance/QA ownership:

```text
features/hybrid_scenario_projection.feature
acceptance/runtime_features/hybrid_scenario_projection.py
acceptance/runtime_manifest.py
acceptance/qa/taxonomy_risk/hybrid_scenario_projection.py
acceptance/qa/taxonomy_risk/hybrid_scenario_projection.md
tests/test_hybrid_scenario_projection_acceptance.py
tests/fixtures/hybrid-scenario-projection-set.yaml
ai/findings/stpa-taxonomy-phase4-live-pilot-runbook.md  # required future deliverable
README.md
docs/architecture/overview.md
CONTEXT.md
```

The runbook is a required future qualification deliverable; Task 3 may prepare
its checklist, but must not perform the live run. It must document corrected
nested capability-profile and qualification-facts extraction, exact inputs,
run manifest/run ID, model-call evidence, target list, candidate admission,
human review/adjudication, and quarantine handling. The task may update
repository documentation only after the contract issue is approved. It MUST
NOT edit ordinary taxonomy/STPA runtime handlers except to register the
isolated acceptance feature.

## Required acceptance behavior

The feature and external QA must cover:

- exact accepted relation → at most one projection;
- Phase 1 candidate identity matched to a separate complete
  `CandidateMaterializationSet`;
- exact five-part unit identity and distinct same-`EXEC:*` ICAs;
- closed mechanism/causal serialization fields and exact digest recipe;
- every typed exclusion from the contract;
- bridge provenance, typed endpoint unions, and the fixed five-kind table;
- graph order, cycle, duplicate, and digest failures;
- fatal source defects versus intact-source relation-local exclusions;
- canonical reordering and atomic round trip;
- no correspondence/coverage change and no Phase 3 promotion;
- normative fixture labeling and rejection of semantic-pilot claims from it;
- exact pin inheritance from projection to set;
- independent confirmed reviewer/mechanism evidence distinct from bridge
  evidence;
- zero model/provider/network calls; and
- unchanged ordinary `generate` and `stpa-run` compatibility.

The external QA implementation must read the YAML independently, recompute the
version-framed digest, verify all identity/pin/order/exclusion rules, and avoid
importing the application package where practical.

## Pilot-readiness harness

The task should add a deterministic, offline check that a proposed semantic
pilot is eligible only for an explicit expected list of
`(relation_id, selected_candidate_id)` targets and only when:

1. each fresh corrected taxonomy envelope parses as a typed `ScenarioEnvelope`;
2. each envelope's `cand:v2` ID recomputes from its pattern and canonical
   projection and equals the envelope ID;
3. the full projectable candidate/materialization resolves in the corrected
   Phase 1 plan, with exact projection, ingress, and resource-binding equality;
4. duplicate IDs, old/superseded IDs, and extra unrequested entries are
   rejected before `TaxonomyCoverageInput.from_scenario_envelopes` is called;
5. exact STPA scenario/projection identities resolve to slot/ICA/`EXEC:*`;
6. at least one accepted, coverage-bearing Phase 2 relation has exact typed
   confirmed review/adjudication evidence, reviewer identity/digest, and
   independent mechanism evidence distinct from bridge evidence; and
7. map, assessment, reconciliation, candidate-materialization, and STPA pins
   agree.

The harness consumes a typed `PilotProvenanceBundle` with an exact
`generate_run_manifest_pin` and `run_id`, hashes for the use case, risk
extraction, SSSOM, cross-taxonomy mappings, threats, corrected nested
capability profile, qualification facts, catalog/mappings, settings/model
profile, scenario artifacts, and model-call evidence. It records exact
expected/generated/admitted/quarantined/exact-join counts.

The harness may report “not ready” with exact missing evidence. It must not
repair old envelopes, infer a relation, convert a shared-resource association
into coverage, or invoke live generation. Fresh taxonomy regeneration and
human review are later qualification work, not an implementation dependency for
Tasks 1–2.

Current recorded pilot blockers must be surfaced verbatim:

- old Klarna taxonomy envelopes: 0/94 corrected-plan joins;
- old NHS taxonomy envelopes: 0/27 corrected-plan joins; and
- corrected assessments: zero accepted coverage-bearing relations for both.

## Stop conditions

Stop the pilot gate, but do not weaken the contract, if:

- only superseded taxonomy envelopes are available;
- no independently reviewed accepted coverage-bearing relation exists;
- the evidence is synthetic all-confirmed bookkeeping only;
- any identity requires fuzzy/prose repair;
- any default acceptance path contacts a provider or network; or
- ordinary `generate`/`stpa-run` behavior differs.

## Task 3 exit evidence

Run and retain:

```text
Gherkin DRY and generated acceptance tests: pass, zero survivors/errors
focused and full unit suite: pass
source mutation: >=80%, with no surviving covered-site mutants
Gherkin mutation: zero survivors and zero errors
CRAP: every changed function <=6
Ruff check and format: pass
git diff --check: pass
independent external QA: pass, zero provider/network calls
ordinary generate/stpa-run compatibility: unchanged
```

The handoff must include the canonical fixture, exact digest, typed exclusion
inventory, mutation manifests, compatibility comparison, and a separate pilot
readiness result. A normative fixture passing these gates is not a semantic
coverage claim.

## Overall Phase 4 exit criteria

Phase 4 is complete only when:

1. the approved contract and three task handoffs are present;
2. each emitted projection has one exact accepted Phase 2 relation and at least
   one authorized causal bridge;
3. all omitted relations remain explicit typed exclusions;
4. taxonomy and STPA internal ordering is preserved and the combined graph is a
   validated DAG;
5. source pins, candidate bindings, identities, and digests round-trip exactly;
6. the set is atomically persisted as
   `hybrid-scenario-projection-set.yaml`;
7. no Phase 1/2/3 artifact, matrix, relation, or ordinary workflow changes;
8. all deterministic paths make zero provider/network calls; and
9. any semantic pilot is separately marked not-ready until its target-scoped
   fresh-corpus, provenance, and genuinely reviewed-relation gates pass.

Completion does not authorize Phase 5 generation or finalization. A new issue
must approve that later boundary.

## References

- [`stpa-taxonomy-phase4-combined-projection-spec.md`](stpa-taxonomy-phase4-combined-projection-spec.md)
- [`stpa-taxonomy-synthesis.md`](stpa-taxonomy-synthesis.md)
- [`stpa-taxonomy-phases-1-2-spec.md`](stpa-taxonomy-phases-1-2-spec.md)
- [`stpa-taxonomy-phase3-closed-loop-spec.md`](stpa-taxonomy-phase3-closed-loop-spec.md)
- [`stpa-taxonomy-phase3-swarmforge-tasks.md`](stpa-taxonomy-phase3-swarmforge-tasks.md)
- [`phase12-live-run-klarna-nhs-2026-08-29.md`](phase12-live-run-klarna-nhs-2026-08-29.md)
- [`../../docs/development/swarmforge.md`](../../docs/development/swarmforge.md)
