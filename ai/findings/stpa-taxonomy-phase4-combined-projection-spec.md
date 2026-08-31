# STPA–taxonomy synthesis: Phase 4 combined-projection contract

**Status:** Approved on 2026-08-31 for the deterministic Phase 4 Tasks 1–3.
The later semantic pilot and Phase 5 generation remain separately gated.

**Scope:** Phase 4 is the first phase that may compose an accepted taxonomy/STPA
relation into one executable-shaped, but not yet executable, projection. It
produces a standalone `hybrid-scenario-projection-set-v1` artifact. It does not
generate a scenario, call a provider, or change either existing workflow.

This proposal is based on the recommended combined-projection step in
[`stpa-taxonomy-synthesis.md`](stpa-taxonomy-synthesis.md), the approved Phase
1–3 contracts, the corrected Klarna/NHS lineage audit, and the repository
architecture rules. The synthesis document remains an investigation rather
than an approved contract; this narrower Phase 4 document records the user's
approved implementation choices. A durable issue may mirror those choices but
does not reopen them implicitly.

## 1. Purpose and boundary

The lifecycle phases have deliberately different jobs:

1. **Phase 1** records the risk-specific taxonomy obligation, disposition, and
   candidate identity. It does not contain the complete canonical mechanism
   projection needed by Phase 4.
2. **Phase 2** records whether an obligation has an explicit, evidence-backed
   relation to an exact STPA ICA.
3. **Phase 3** optionally asks STPA to reconsider a specifically eligible
   structural decision while preserving the historical record.
4. **Phase 4** composes one already accepted Phase 2 relation into a validated
   graph that contains a separate canonical taxonomy materialization and the
   STPA causal path.

The proposed flow is:

```text
validated Phase 2 assessment and accepted relation
                         │
                         v
exact taxonomy candidate + exact STPA projection
                         │
                         v
operator/curated causal bridge evidence
                         │
                         v
deterministic graph and pin validation
                         │
                         v
hybrid-scenario-projection-set-v1
```

The Phase 4 output says: “this exact taxonomy mechanism is connected to this
exact STPA causal path, for these reasons and through these links.” It does not
say that the scenario has been generated, admitted, executed, or covered.

The first release proposes an internal typed Python seam. It adds no public
CLI, report, provider interaction, or change to `generate` or `stpa-run`.

## 2. Goals

Phase 4 should:

1. Accept one closed `HybridProjectionInputs` envelope, including typed bridge
   links, an explicit evidence class, and an explicit requested relation list.
2. Emit at most one projection for each requested accepted Phase 2 relation. A
   relation with no valid bridge is retained as a typed exclusion and emits no
   projection.
3. Preserve separate identity for the relation, obligation, selected taxonomy
   candidate, STPA ICA, and structural `EXEC:*` candidate.
4. Use a separate, content-addressed `CandidateMaterializationSet` whose
   canonical mechanism projections are checked against Phase 1 candidate
   records.
5. Compose neutral closed mechanism and causal projections without flattening
   either one.
6. Require at least one explicit, operator-declared or curated causal bridge for
   each emitted projection.
7. Preserve the internal order of both projections and reject cycles or
   invalid bridge endpoints deterministically.
8. Retain every omission as a typed exclusion or diagnostic rather than
   silently dropping it.
9. Pin all upstream artifacts and compute a deterministic semantic digest.
10. Publish one canonical adjacent YAML artifact atomically and verify it after
    reload.
11. Keep the Phase 1–3 artifacts and their independent denominators unchanged.
12. Distinguish a deterministic bookkeeping fixture from independently reviewed
    semantic evidence.

## 3. Explicit non-goals

Phase 4 MUST NOT:

- generate, select, finalize, admit, quarantine, execute, or evaluate a
  scenario;
- create a scenario envelope, Gherkin file, execution transcript, oracle, or
  runtime binding;
- create, confirm, or rewrite a Phase 2 correspondence proposal or relation;
- treat a Phase 3 ICA, justified-N/A, unresolved, or technical result as a new
  correspondence relation or coverage claim;
- infer a bridge from prose, keywords, display names, shared resources, or
  matching `EXEC:*` prefixes;
- accept `related_but_not_coverage`, rejected, unresolved, contradictory, or
  unreviewed evidence as a combined projection;
- use a synthetic all-confirmed assessment as semantic coverage evidence;
- run a second taxonomy traversal, rebuild the Phase 2 assessment, or adapt old
  taxonomy scenario envelopes;
- claim that the Phase 1 plan itself contains a complete mechanism projection;
- add a public `hybrid-run` command, a Phase 4 report, or a hidden sidecar
  dependency to either existing command;
- import the `generate` or ordinary `stpa-run` orchestration implementation;
- construct a provider client, contact an endpoint, or require an LLM;
- change the Phase 1, Phase 2, or Phase 3 schemas, matrices, digests, prompts,
  counts, manifests, or exit behavior; or
- integrate directly with `asago-artifact-generator`. Its standalone consumer
  contract remains a separate proposed workstream.

Scenario generation and finalization are explicitly a later Phase 5. A valid
Phase 4 projection is not automatically executable.

## 4. Approved defaults

These are the deliberate choices approved for Tasks 1–3:

1. **Composition surface:** one internal typed seam first; no CLI or report.
2. **Unit of composition:** at most one projection per requested accepted Phase
   2 relation; one is emitted when all authority and bridge checks pass.
   Several obligations may therefore yield several projections, even when they
   share a candidate or ICA.
3. **Exact unit identity:**
   `(relation_id, obligation_id, selected_candidate_id, ica_id,
   exec_candidate_id)`. `relation_kind` remains a required checked field but
   does not replace any member of this identity.
4. **Bridge authority:** only `operator_declared` or `curated` bridge evidence
   can authorize a projection in the first release. Model-proposed and
   deterministically inferred bridges may be retained as diagnostics, but they
   cannot authorize output.
5. **Artifact:** the adjacent closed
   `hybrid-scenario-projection-set-v1` artifact, persisted as
   `hybrid-scenario-projection-set.yaml`.
6. **Evidence class:** a projection records either
   `normative_bookkeeping_fixture` or `reviewed_semantic_evidence`. The input
   envelope is required to declare one class and a set cannot mix them. The
   former is valid for deterministic contract tests only; Phase 5 MUST reject
   it.
7. **Candidate materialization:** complete mechanism projections live in a
   content-addressed `CandidateMaterializationSet`, not in the Phase 1 plan or
   old live scenario envelopes. Each entry is pinned to and checked against one
   Phase 1 `CandidateRecord`.
8. **Correspondence authority:** the exact Phase 2 reconciliation is the sole
   authority for accepted relations. The originating proposal-set pin and
   digest remain required and must match the reconciliation attestation.
9. **STPA authority:** a `PinnedStpaProjectionAttestation` wrapper is required;
   raw execution envelopes are not accepted as an unpinned lookup.
10. **Qualification facts:** the input chain must retain the exact authoritative
   facts and capability snapshot pins already required by Phase 1/2. Omitted
   compatibility is not sufficient for a semantic pilot.
11. **Lifecycle:** if a later generation adapter is approved, it should consume
   the existing taxonomy finalization lifecycle and its target-scoped evidence,
   not replace it with the simplified STPA manifest.

## 5. Closed input contract

The composition seam is proposed as
`build_hybrid_scenario_projection_set(inputs: HybridProjectionInputs)`.
There is one public input shape; separate arguments must not provide a bypass
around validation. `HybridProjectionInputs` is a closed, frozen envelope with
this exact top-level shape:

```text
HybridProjectionInputs {
  schema_version = hybrid-projection-inputs-v1
  obligation_plan: TaxonomyObligationPlan
  capability_facts: CapabilityFactAttestation
  candidate_materializations: CandidateMaterializationSet
  phase2_assessment: HybridCoverageAssessment
  correspondence: HybridCorrespondenceAttestation
  resource_map_validation: SystemResourceMapValidation
  stpa_projection_authority: PinnedStpaProjectionAttestation
  confirmed_reviews: [ConfirmedCoverageReview]
  bridge_links: [BridgeLink]
  requested_relation_ids: [string]
  evidence_class: normative_bookkeeping_fixture | reviewed_semantic_evidence
  closed_loop_run: ClosedLoopStpaRun | null
}
```

Unknown fields, duplicate IDs, unsupported schemas, and mutable nested values
are rejected. The envelope requires exact accepted Phase 2 assessment and
reconciliation, the Phase 1 plan, the resource-map attestation, and the exact
STPA authorities needed to resolve loss/hazard/constraint, slot/ICA, and
`EXEC:*` identities.

### 5.1 Source-pin and capability/fact attestation

Phase 4 does not flatten the existing Phase 1 `TaxonomyPin(release, digest)`
into `ArtifactPin(artifact_id, schema_version, semantic_digest)`. Source pins
use a closed discriminated union:

```text
ArtifactProjectionSourcePin {
  kind = artifact
  role
  pin: ArtifactPin
}

TaxonomyProjectionSourcePin {
  kind = taxonomy
  role: catalog | mapping
  taxonomy_id
  pin: TaxonomyPin
}

ProjectionSourcePin = ArtifactProjectionSourcePin | TaxonomyProjectionSourcePin
```

The adapter retains `TaxonomyPin.release` and `TaxonomyPin.digest` exactly;
neither value is repurposed as an artifact ID or schema version.

The Phase 1 plan contains only `qualification_facts_digest`, so exact facts are
supplied separately through:

```text
CapabilityFactAttestation {
  schema_version = capability-fact-attestation-v1
  capability_snapshot_digest
  qualification_facts_digest
  source_pin: ArtifactPin
  semantic_digest
}
```

`CapabilityFactAttestation.from_snapshot(...)` accepts an exact typed
`CapabilityFactSnapshot`, asserts its integrity, deep-copies and revalidates
its profile/facts immediately, computes the qualification-facts digest from
those facts, and verifies both digests against the Phase 1 plan and successful
resource-map validation. Raw mappings are not accepted.

### 5.2 Phase 1 plan and candidate materialization

The Phase 1 plan is authoritative for obligation and candidate identity,
disposition, qualification facts, and upstream pins. It does **not** contain a
full mechanism projection. Phase 4 requires this separate content-addressed
set:

```text
CandidateMaterializationSet {
  schema_version = taxonomy-candidate-materialization-set-v1
  obligation_plan_pin: ArtifactPin
  entries: [CandidateMaterialization]
  source_pins: [ProjectionSourcePin]
  semantic_digest
}

CandidateMaterialization {
  materialization_id
  obligation_id
  risk_id
  attack_pattern_id
  selected_candidate_id
  phase1_candidate_record_digest
  mechanism_projection: MechanismProjection
  source_pins: [ProjectionSourcePin]
  semantic_digest
}
```

Each entry must resolve to one Phase 1 `CandidateRecord` under the exact plan
pin. Obligation, risk, attack-pattern, selected-candidate ID, disposition, and
candidate-record digest must agree. The complete canonical mechanism
projection, ingress, conditions, and resource bindings live here, not in an
old live taxonomy scenario envelope. A missing entry is relation-local; a
present but substituted entry is a fatal source error.

`phase1_candidate_record_digest` is reproducible even though the Phase 1 model
does not persist a per-record digest. It is the framed digest in domain
`asago.phase1-candidate-record.v1` over the complete canonical JSON value of
the exact `CandidateRecord` (including candidate ID, ingress, resource
bindings, disposition, reason, and evidence). The adapter recomputes it from
the row selected under `obligation_plan_pin`; callers cannot supply a detached
digest as authority.

### 5.3 Neutral canonical mechanism projection

`MechanismProjection` is a closed immutable inward model. The model layer must
not import pipeline types, filesystem code, provider clients, or generation
runners. It reuses the existing closed inward attack-pattern contracts instead
of translating them into a second step or condition language. Its exact
serialized fields are:

```text
MechanismProjection {
  schema_version = taxonomy-mechanism-projection-v1
  mechanism_projection_id
  obligation_id
  risk_id
  attack_pattern_id
  selected_candidate_id
  projection: ProjectionSnapshot
  canonical_ingress: EntryPointResourceReference
  ingress_controllability: direct | indirect
  execution_requirements: [ExecutionRequirement]
  execution_requirements_digest
  semantic_digest
}
```

`ProjectionSnapshot` retains the complete source chain, selected steps,
existing typed condition AST (`equality`, `membership`, `existence`,
`property_match`, `all`, `any`, and `not`), omissions, exact resource-slot
bindings, catalog/pattern/snapshot pins, and projection digest. The existing
`CanonicalChainStep` and `ExecutionRequirement` contracts retain action kind,
consumed/produced references, preconditions, observable postconditions,
resource links, mappings, and required operations. Their existing validators
remain authoritative. Phase 4 does not invent an `operation_id`, flatten a
condition to prose, or duplicate those reference rules.

An outer pipeline adapter may consume a **complete** current
`ProjectedCandidate` record (never only its ID) and verify its candidate-v2
identity, ingress, conditions, and resource bindings before constructing this
record. It copies and revalidates the `ProjectionSnapshot`, ingress, and
`ExecutionRequirement` model leaves, recomputes candidate and requirements
digests, and checks them against the Phase 1 candidate record. That adapter is
explicit and cannot silently fetch, rebuild, or substitute a candidate. No
current pipeline type is imported by the inward model.

### 5.4 Neutral canonical causal projection

`CausalProjection` is a closed immutable inward model. Its exact serialized
fields are:

```text
CausalProjection {
  schema_version = stpa-causal-projection-v1
  causal_projection_id
  loss_ids: [string]
  hazard_ids: [string]
  constraint_ids: [string]
  controller_id
  control_action_id
  uca_slot_id
  ica_id
  exec_candidate_id
  nodes: [CausalNode]
  edges: [CausalEdge]
  semantic_digest
}

CausalNode {
  node_id
  kind: loss | hazard | constraint | controller | control_action | feedback |
        process_model | coordination_link | coordination_mechanism | uca |
        ica | exec
  ordinal: non-negative integer
}

CausalEdge {
  edge_id
  from_node_id
  to_node_id
  kind: causal | control | feedback | projection
}
```

The exact STPA authorities are carried by this pinned wrapper:

```text
PinnedStpaProjectionAttestation {
  schema_version = pinned-stpa-projection-attestation-v1
  loss_analysis_pin: ArtifactPin
  control_structure_pin: ArtifactPin
  ica_enumeration_pin: ArtifactPin
  execution_projection_pin: ArtifactPin
  projections: [CausalProjection]
  source_pins: [ProjectionSourcePin]
  semantic_digest
}
```

The four pins resolve to the exact complete typed loss, control-structure, ICA,
slot, and canonical execution authorities needed by the projections. An outer
adapter may consume current `CandidateExecutionEnvelope` values and typed STPA
models to build the wrapper; the inward models do not import those pipeline
types. A raw or unpinned execution-envelope tuple is insufficient.

Node and edge IDs are unique within one causal projection and every edge
endpoint resolves locally. The closed edge-kind table is:

| Edge kind | Permitted source → target kinds |
|---|---|
| `projection` | `loss → hazard`, `hazard → constraint`, `constraint → controller/control_action/coordination_link/coordination_mechanism`, `controller/control_action/coordination_link/coordination_mechanism → uca`, `uca → ica`, `ica → exec` |
| `control` | `controller → control_action`, `coordination_link → coordination_mechanism`, `control_action/coordination_mechanism → uca` |
| `feedback` | `feedback → controller/process_model` |
| `causal` | `process_model/feedback/control_action → uca/ica` |

Every causal projection contains the exact referenced loss, hazard,
constraint, controller/control-action or coordination-link/mechanism, UCA,
ICA, and `EXEC:*` nodes and at
least one authoritative `projection` trace path through those identities in
the order shown. Optional process-model and feedback nodes join only through
the permitted causal/feedback edges. The `exec` node is unique and terminal;
the ICA and `EXEC:*` fields agree with it. Node ordinals are unique and edges
cannot reverse their order. Dangling nodes, wrong-kind edges, duplicate
semantic edges, missing trace members, multiple terminal `exec` nodes, and
cycles fail closed.

For a responsibility slot, `controller_id`/`control_action_id` contain exact
`RESP:*`/`CA:*` identities and their nodes use `controller`/`control_action`.
For a coordination slot, those same scalar role fields contain exact
`CL:*`/`CM:*` identities and their nodes use
`coordination_link`/`coordination_mechanism`; Phase 4 must not relabel CL/CM
records as RESP/CA records.

### 5.5 Correspondence authority and independent review

Phase 4 chooses the exact Phase 2 reconciliation as the sole authority for
accepted relations. The proposal set is not re-adjudicated here, but its
content pin and digest are required to detect substitution:

```text
HybridCorrespondenceAttestation {
  schema_version = hybrid-correspondence-attestation-v1
  proposal_set_pin: ArtifactPin
  proposal_set_digest
  reconciliation_pin: ArtifactPin
  reconciliation_digest
  accepted_relations: [AcceptedCorrespondenceRelation]
  semantic_digest
}
```

The `confirmed_reviews` field provides exact typed evidence independent of the
bridge claim:

```text
ConfirmedCoverageReview {
  schema_version = confirmed-coverage-review-v1
  relation_id
  adjudication = confirmed
  reviewer_id
  review_artifact_pin: ArtifactPin
  review_artifact_digest
  mechanism_evidence: MechanismEvidenceAttestation
  source_pins: [ProjectionSourcePin]
  semantic_digest
}

MechanismEvidenceAttestation {
  schema_version = mechanism-evidence-attestation-v1
  artifact_pin: ArtifactPin
  record_id
  evidence_kind: exact_id | curated_mechanism_mapping
  semantic_digest
}
```

The review factory consumes the existing
`ReviewedCorrespondenceAdjudications` and exact
`ReviewedCorrespondenceDecision`; it checks packet/proposal-set digests,
`status == confirmed`, relation kind, proposal ID, `adjudicated_by`, and
evidence references against the accepted relation. `review_artifact_pin` is
computed from that complete canonical reviewed-adjudications value; no deleted
browser-review packet or UI type is required. The separate mechanism evidence
record must be independently pinned and cannot be the bridge artifact itself.
Rejected, unresolved, contradictory, or unreviewed records cannot become
confirmed here.

### 5.6 Required source pins and historical Phase 3

The envelope retains and verifies pins for the plan, candidate materialization
set, capability/fact snapshot, taxonomy catalog/chain/mapping/lineage,
resource-map validation, Phase 2 assessment, proposal set, reconciliation,
confirmed review evidence, STPA wrapper and its four authorities, and each
bridge evidence record. The same source cannot appear twice with different
digests.

`closed_loop_run` is optional historical context. If supplied, it must be an
intact `stpa-obligation-closed-loop-run-v1` record with matching pins. It may
explain history or an exclusion, but can never create a relation, bridge,
projection, or coverage credit.

### 5.7 Verified construction boundary

These wrappers are attestations, not caller-authored summaries. The public
pipeline exposes verified factories and the builder accepts only their
validated outputs:

- `CandidateMaterializationSet.from_artifacts(...)` consumes the exact Phase 1
  plan, its pin, and explicit current `ProjectedCandidate` values; it
  recomputes every `cand:v2` identity and candidate-record digest.
- `HybridCorrespondenceAttestation.from_artifacts(...)` consumes the exact
  typed proposal set, reconciliation result, Phase 2 assessment, and their
  pins; it calls each artifact's integrity validator, verifies their shared
  digests/pins, and derives accepted relations only from
  `ReconciliationResult.accepted_relations`. It does not rerun reconciliation
  or accept a caller-supplied relation list.
- `PinnedStpaProjectionAttestation.from_artifacts(...)` consumes the exact
  typed loss analysis, control structure, ICA enumeration, execution
  projections, accepted-relation contexts, and their pins. It deep-copies and
  revalidates the mutable source models immediately, verifies each pin against
  canonical source content, and derives the loss/hazard/constraint path from
  typed references plus the slot/ICA/`EXEC:*` and causal-factor projection.
  The execution projection pin uses domain
  `asago.stpa-execution-projection.v1` over the existing canonical standalone
  execution-projection value; the source envelope is not assumed to contain a
  digest or a prebuilt causal DAG.
- `ConfirmedCoverageReview.from_artifacts(...)` consumes the exact typed
  existing `ReviewedCorrespondenceAdjudications`, its exact confirmed decision,
  and independently pinned `MechanismEvidenceAttestation`; it derives the
  relation/reviewer record and rejects a bridge artifact reused as mechanism
  evidence.

Deserialization may recreate a persisted attestation, but it must recompute
its semantic digest and is not sufficient by itself for a new build. The
builder revalidates the attestation against the exact source pins present in
the same `HybridProjectionInputs` envelope. A raw dictionary, arbitrary hash,
or directly assembled accepted-relation/projection list cannot bypass these
factories.

## 6. Exact relation and candidate rules

For each requested relation ID, the builder MUST verify all of the following:

1. The full relation exists in `ReconciliationResult.accepted_relations`. The
   matching Phase 2 `scenario_realization` row has the same
   obligation/candidate identity. For a coverage-bearing relation the row has
   `coverage_bearing: true` and the corresponding taxonomy row contains the
   relation ID in `accepted_relation_ids`. For
   `related_but_not_coverage`, the row has `coverage_bearing: false`, the
   taxonomy row does not claim that relation as accepted coverage, and Task 1
   retains a typed relation-local exclusion.
2. A relation emits a unit only when it is accepted, explicitly confirmed,
   and coverage-bearing under the closed Phase 2 relation vocabulary. An
   intact accepted noncoverage relation is not a malformed authority; it is
   excluded with `relation_not_coverage`.
3. The relation's obligation, risk, attack-pattern, selected candidate, ICA
   slot, ICA, `EXEC:*`, resource-link, hazard, and constraint identities agree
   across all supplied authorities.
4. The obligation exists and is applicable in the Phase 1 plan.
5. The selected candidate exists in the separate, pinned
   `CandidateMaterializationSet`, matches the Phase 1 candidate record, and is
   `projectable`.
6. Every cited resource link belongs to that selected candidate's own
   canonical bindings and to the validated resource-map attestation.
7. The ICA and slot exist in the exact ICA enumeration and agree with each
   other. Two ICAs sharing one `EXEC:*` identity remain separate.
8. The `EXEC:*` value is canonically derived from the exact controller, control
   action, and UCA type; it is not accepted because of a prefix or display
   name.
9. The risk → loss → hazard → constraint → controller/control-action → UCA/ICA
   path resolves through typed IDs.
10. A confirmed typed review exists for the relation, with reviewer identity,
    review digest, and independent mechanism evidence. A Phase 3 challenge
    outcome is treated only as historical evidence: it cannot upgrade an
    unresolved relation, create a relation, or replace an original STPA
    decision.

If a relation fails one of these per-relation checks, the set retains a typed
exclusion and does not emit that projection. If a top-level source artifact is
malformed, substituted, or digest-invalid, the entire operation fails before
publication. There is at most one emitted projection for each requested
relation ID; duplicate requested IDs are a fatal malformed request.

## 7. Closed bridge contract

### 7.1 Bridge kinds

The first release proposes this closed bridge vocabulary, derived from the
synthesis design:

| Bridge kind | Meaning |
|---|---|
| `corrupts_process_model` | A taxonomy step or postcondition changes, poisons, or misleads an exact STPA process-model factor. |
| `delays_feedback` | A taxonomy mechanism delays, suppresses, or makes stale an exact feedback factor needed by the controller. |
| `perturbs_control_action` | A taxonomy mechanism changes the content, target, or execution of an exact control action. |
| `enables_unsafe_action` | A taxonomy mechanism supplies the condition that allows the exact unsafe control action or ICA to occur. |
| `realizes_unsafe_outcome` | A taxonomy mechanism directly realizes the loss-relevant unsafe outcome represented by the exact causal path. |

No other bridge kind is accepted in v1. `accepted_resource_link` is identity
evidence only and is never a bridge. `related_but_not_coverage` is a Phase 2
relation kind, not a bridge kind.

### 7.2 Closed endpoints and bridge evidence

Every bridge is directed **taxonomy → STPA**. Endpoints are closed typed
unions, not arbitrary strings:

```text
TaxonomyEndpoint {
  namespace = taxonomy
  kind: mechanism_step | mechanism_precondition | mechanism_postcondition
  record_id
}

StpaEndpoint {
  namespace = stpa
  kind: process_model | feedback | control_action | uca | ica | hazard | loss
  record_id
}
```

`BridgeLink` has exactly these fields:

```text
BridgeLink {
  schema_version = hybrid-bridge-link-v1
  bridge_id
  relation_id
  bridge_kind
  taxonomy_endpoint: TaxonomyEndpoint
  stpa_endpoint: StpaEndpoint
  evidence: [BridgeEvidence]
  source_pins: [ProjectionSourcePin]
  semantic_digest
}
```

`BridgeEvidence` has exactly these fields:

```text
BridgeEvidence {
  schema_version = hybrid-bridge-evidence-v1
  evidence_id
  artifact_pin: ArtifactPin
  record_id
  evidence_kind: exact_taxonomy_record | exact_stpa_record |
                  operator_bridge_review | curated_bridge_mapping
  provenance: operator_declared | curated
  authority_identity: BridgeAuthorityIdentity
  rationale: string
  semantic_digest
}

BridgeAuthorityIdentity {
  kind: reviewer | curator
  id: string
}
```

`operator_declared` requires a reviewer identity and `curated` requires a
curator identity. `record_id` must resolve under the exact pinned artifact.
The `rationale` is explanatory audit text only; it cannot establish identity,
endpoint validity, or authorization. Relabelling model prose does not pass:
there is no model-authorizing evidence kind, and the exact record, digest, and
review/curation identity must resolve. A valid emitted projection needs at
least one `operator_bridge_review` or `curated_bridge_mapping` evidence item.

### 7.3 Fixed endpoint table and order semantics

The following table is normative; no endpoint rule remains open for
implementation:

| `bridge_kind` | Taxonomy source endpoint | STPA target endpoint | Required order meaning |
|---|---|---|---|
| `corrupts_process_model` | `mechanism_step`, `mechanism_precondition`, or `mechanism_postcondition` | `process_model` | The taxonomy node precedes the targeted process-model factor; STPA descendants retain authority order. |
| `delays_feedback` | `mechanism_step` or `mechanism_postcondition` | `feedback` | The feedback factor remains before any authorized control-action/UCA/ICA/EXEC descendant. |
| `perturbs_control_action` | `mechanism_step` or `mechanism_postcondition` | `control_action` | The control action remains before its authority-defined UCA/ICA/EXEC descendants. |
| `enables_unsafe_action` | `mechanism_step` or `mechanism_postcondition` | `uca` or `ica` | The exact unsafe-action slot/ICA remains before the terminal `exec` node. |
| `realizes_unsafe_outcome` | `mechanism_step` or `mechanism_postcondition` | `hazard` or `loss` | The exact loss-path outcome is retained; the loss/hazard path is not reordered. |

`accepted_resource_link` is identity evidence only and never a bridge.
`related_but_not_coverage` is a Phase 2 relation kind, not a bridge kind.
Model-proposed, model-assisted, unreviewed, keyword-derived, display-name, and
resource-only evidence may be retained as a typed diagnostic but cannot
authorize output.

## 8. Combined graph and ordering rules

The projection is a directed acyclic graph with three edge classes:

1. **Taxonomy edges** preserve the canonical attack-chain step order and any
   declared postcondition dependency order. Their order is `(ordinal, step_id)`.
2. **STPA edges** preserve the supplied causal-factor order and typed
   `CausalEdge` relationships. The terminal `exec_candidate_id` has no outgoing
   edge.
3. **Bridge edges** are exactly taxonomy-endpoint → STPA-endpoint links in the
   fixed table above. They annotate a causal connection and never create an
   STPA → taxonomy edge or rewrite either local order.

The validator constructs the union graph and MUST reject a directed cycle,
reverse local edge, dangling endpoint, duplicate semantic edge, or bridge to a
node outside the selected projections. A cycle includes any path returning to
its starting node, including one caused by malformed source edges. Every one
of the five bridge kinds uses this same global DAG check and its table-specific
target/order requirement; no kind bypasses it. At least one authorized valid
bridge must connect the two subgraphs for an emitted projection.

The validator may derive graph edges and a canonical traversal internally, but
it MUST NOT derive a semantic bridge from final narrative prose, resource
overlap, or coincidental IDs.

## 9. Output contract

### 9.1 One projection per relation

The set contains zero or more `HybridScenarioProjection` records, with at most
one record for each requested accepted relation, each with:

```text
schema_version = hybrid-scenario-projection-v1
projection_id
relation_id
obligation_id
risk_id
attack_pattern_id
selected_candidate_id
ica_slot_id
ica_id
exec_candidate_id
relation_kind
evidence_class
causal_projection
mechanism_projection
bridge_links[]
confirmed_review
risk_trace[]
source_pins[]
semantic_digest
```

`projection_id` is a deterministic, version-framed identity over the exact
unit identity, source projection digests, bridge links, confirmed review, and
contract version. The semantic digest covers the complete canonical projection
content and excludes only the digest field itself.

The causal and mechanism projections are complete typed/canonical values, not
summaries or references that require a second unpinned lookup. The projection
may retain compact artifact references for navigation, but those references
must agree with the embedded canonical values and their digests.

`risk_trace` is a closed list of `ProjectionTraceReference` values. The Phase 4
name is intentionally distinct from the existing Phase 2 `TraceReference`:

```text
ProjectionTraceReference {
  source_kind: phase1_obligation | phase1_candidate | phase2_relation |
                stpa_loss | stpa_hazard | stpa_constraint | stpa_slot |
                stpa_ica | stpa_exec | bridge_evidence
  record_id
  artifact_pin: ArtifactPin
}
```

`ProjectionExclusion` and `ProjectionDiagnostic` are closed records; neither
can be interpreted as a projection:

```text
ProjectionExclusion {
  exclusion_id
  relation_id
  unit_identity: [relation_id, obligation_id, selected_candidate_id, ica_id, exec_candidate_id]
  reason: ExclusionReason
  source_pins: [ProjectionSourcePin]
  trace: [ProjectionTraceReference]
}

ProjectionDiagnostic {
  diagnostic_id
  relation_id: string | null
  kind: bridge_unreviewed | bridge_not_authoritative |
        challenge_outcome_not_correspondence
  source_pins: [ProjectionSourcePin]
  trace: [ProjectionTraceReference]
}
```

`ExclusionReason` is exactly the enum listed in §9.3. `unit_identity` may use
an empty string only for the unknown member of a relation that failed before
that member could be resolved; the relation ID itself is always retained when
the request supplied one.

### 9.2 Projection set

The persisted adjacent artifact is:

```text
schema_version = hybrid-scenario-projection-set-v1
assessment_digest
projection_contract_version
source_pins[]
projections[]
exclusions[]
diagnostics[]
evidence_class
semantic_digest
```

It is written atomically as `hybrid-scenario-projection-set.yaml` in a
caller-chosen directory. A successful writer reloads the file through the
closed model and verifies its semantic digest before returning success.

The input envelope's required `evidence_class` is copied to every projection
and to the set. All members of one set must have the same class; mixing
`normative_bookkeeping_fixture` and `reviewed_semantic_evidence` is a fatal
input error. A downstream Phase 5 consumer MUST reject a set labelled
`normative_bookkeeping_fixture`.

Each projection inherits the relation-local pins for the Phase 1 plan and
matching materialization set, Phase 2 assessment/proposal-set/reconciliation
and review evidence, resource-map attestation, STPA wrapper and its exact
authority pins, and every bridge-evidence artifact it uses. The set's
`source_pins` is the canonical union of all envelope authority pins,
projection pins, exclusion pins, and any supplied Phase 3 history pins. A
projection may not introduce a pin absent from the set, and the set may not
omit a pin used by a projection or exclusion. Duplicate artifact identity with
different digests is fatal.

Input ordering MUST NOT affect projection ordering, IDs, digests, or serialized
bytes. Canonical ordering is by the exact unit identity, followed by canonical
bridge, pin, exclusion, and diagnostic ordering.

The set has no blended score, coverage rate, readiness verdict, admission
status, or execution result. Empty `projections[]` is valid when all requested
relations are explicitly excluded; the exclusions must explain why.

### 9.3 Typed exclusions and diagnostics

The first release uses this closed relation-local exclusion vocabulary:

```text
relation_not_accepted
relation_not_coverage
relation_unresolved
relation_contradictory
challenge_outcome_not_correspondence
obligation_not_applicable
candidate_materialization_missing
candidate_not_projectable
candidate_binding_mismatch
stpa_identity_missing
stpa_identity_mismatch
resource_link_mismatch
bridge_missing
bridge_unreviewed
bridge_not_authoritative
bridge_invalid_endpoint
bridge_duplicate
ordering_cycle
ordering_violation
```

An exclusion retains the requested relation/unit identity when known, the exact
reason, source pins, and trace references. It never silently becomes a missing
row. Top-level source-artifact defects remain fatal input errors rather than
per-relation exclusions.

### 9.4 Fatal input errors versus exclusions

Malformed closed input; unknown fields or schemas; missing/invalid semantic
digests; tampered or substituted `ArtifactPin` values; conflicting nested
source digests; proposal-set/reconciliation attestation mismatch;
plan/materialization-set pin mismatch; malformed STPA wrapper; invalid STPA
authority digest; duplicate requested relation IDs; or an unverifiable bridge
evidence artifact are fatal before publication. No partial set is written.

Only intact-source, relation-local ineligibility becomes an exclusion. Thus
`source_pin_mismatch`, `projection_digest_mismatch`, and
`projection_validation_failed` are not exclusion values: they are invalid-input
errors and cannot be downgraded to diagnostics. A missing candidate entry,
non-projectable candidate, invalid relation status, invalid bridge endpoint, or
missing bridge can be an exclusion only after every source pin and digest has
passed validation.

## 10. Canonical identity and digest rules

Digesting uses the repository's existing canonical JSON and version-framed
contract: recursively NFC-normalize strings, sort mapping keys, reject
non-string keys, key collisions, and non-finite numbers, encode compact UTF-8
JSON, and compute:

```text
sha256(UTF8(domain) + NUL + canonical_json_bytes(payload))
```

YAML is only the persistence representation; no digest is computed over YAML
bytes. Derived IDs and semantic digests use separate payloads so there is no
circular calculation:

- A derived ID is the stated prefix plus the full framed digest of the complete
  closed record with its own derived ID and `semantic_digest` omitted, under
  the semantic domain suffixed `.identity.v1`.
- A semantic digest is the full framed digest of the complete closed record,
  including its already verified derived ID and excluding only its own
  `semantic_digest`, under the stated semantic domain.
- A record without a derived ID has only the semantic calculation.

Lists are sorted by the stated canonical key before either payload is encoded:

| Value | Semantic domain | Derived-ID prefix | Canonical order |
|---|---|---|---|
| `MechanismProjection` | `asago.taxonomy-mechanism-projection.v1` | `mech:v1:` | Existing `ProjectionSnapshot` canonical order; execution requirements by `requirement_id` |
| `CausalProjection` | `asago.stpa-causal-projection.v1` | `causal:v1:` | Nodes by `(ordinal, node_id)`, edges by `edge_id` |
| `CapabilityFactAttestation` | `asago.capability-fact-attestation.v1` | none | Scalar digest/pin fields |
| `CandidateMaterialization` | `asago.taxonomy-candidate-materialization.v1` | `materialization:v1:` | Pins by artifact identity |
| `CandidateMaterializationSet` | `asago.taxonomy-candidate-materialization-set.v1` | none | Entries by `(obligation_id, selected_candidate_id)`, pins by artifact identity |
| `PinnedStpaProjectionAttestation` | `asago.pinned-stpa-projection-attestation.v1` | none | Projections by `(ica_id, exec_candidate_id)`, pins by artifact identity |
| `HybridCorrespondenceAttestation` | `asago.hybrid-correspondence-attestation.v1` | none | Accepted relations by `relation_id`; proposal/reconciliation pins and digests are scalar authority fields |
| `MechanismEvidenceAttestation` | `asago.mechanism-evidence-attestation.v1` | none | Scalar exact evidence fields |
| `ConfirmedCoverageReview` | `asago.confirmed-coverage-review.v1` | none | Source pins by artifact identity; all review and mechanism-evidence fields are semantic |
| `BridgeEvidence` | `asago.hybrid-bridge-evidence.v1` | `bridge-evidence:v1:` | Scalar fields; rationale remains part of the identity and digest |
| `BridgeLink` | `asago.hybrid-bridge-link.v1` | `bridge:v1:` | Evidence by `evidence_id`, pins by artifact identity |
| `HybridScenarioProjection` | `asago.hybrid-scenario-projection.v1` | `projection:v1:` | Bridges by `bridge_id`, trace and pins by `(source_kind, record_id, artifact identity)` |
| `HybridScenarioProjectionSet` | `asago.hybrid-scenario-projection-set.v1` | none | Projections by exact unit identity, exclusions by `(relation_id, exclusion_id)`, diagnostics by `diagnostic_id`, pins by artifact identity |

For every payload, artifact source pins sort by
`(kind, role, artifact_id, schema_version, semantic_digest)` and taxonomy
source pins by `(kind, role, taxonomy_id, release, digest)`. Relation IDs sort
lexicographically, bridge evidence sorts by
`evidence_id`, bridge links by `(relation_id, bridge_kind, bridge_id)`,
projections by the five-part unit identity, exclusions by
`(relation_id, reason, exclusion_id)`, and diagnostics by
`(relation_id-or-empty, kind, diagnostic_id)`. Tuples are encoded as JSON arrays
after this ordering. These rules also apply to nested `source_pins` and the
requested relation list.

The canonical source digest used by `execution_projection_pin` is separately
framed in domain `asago.stpa-execution-projection.v1` over the complete
standalone execution-projection value derived from the revalidated
`CandidateExecutionEnvelope`; it is not copied from the mutable source model.

`ProjectionExclusion.exclusion_id` and
`ProjectionDiagnostic.diagnostic_id` use the same complete-record identity
rule with prefixes `exclusion:v1:` and `diagnostic:v1:`. Their source pins and
trace are therefore protected by both their IDs and the enclosing set digest.

Every derived ID and digest is recomputed on load. A supplied value that
differs is a fatal input error. This recipe is sufficient for independent QA
and does not depend on serializer map ordering.

## 11. Evidence classes and pilot gate

The deterministic contract may use a small synthetic fixture to prove model,
digest, ordering, and persistence behavior. Such a fixture MUST say
`normative_bookkeeping_fixture`; it is not semantic truth and must not be used
to claim correspondence, coverage, or a meaningful hybrid scenario. A later
Phase 5 consumer MUST reject that class before generation/finalization.

### 11.1 Target-scoped semantic pilot

A semantic pilot requires an explicit expected list of
`(relation_id, selected_candidate_id)` targets. It is not a complete-plan or
complete-corpus claim. The current `generate` path is live, IBM-only filtered,
has no `--plan` option, and sees only 20/49 Klarna risk cards and 38/112 NHS
risk cards. Those limitations must be recorded in the pilot result.

The current audit records these pilot blockers:

- old Klarna taxonomy envelopes join the corrected plan 0/94;
- old NHS taxonomy envelopes join the corrected plan 0/27; and
- corrected Klarna and NHS assessments have zero accepted coverage-bearing
  relations.

The exact STPA lineage is clean (16/16 Klarna and 18/18 NHS), but that alone
does not create a Phase 2 relation. Superseded envelopes cannot be adapted and
synthetic all-confirmed evidence cannot pass this gate.

### 11.2 Required typed pilot provenance

Any later pilot must provide:

```text
PilotProvenanceBundle {
  schema_version = hybrid-pilot-provenance-v1
  run_id
  generate_run_manifest_pin: ArtifactPin
  use_case_digest
  risk_extraction_digest
  sssom_digest
  cross_taxonomy_mapping_digest
  threats_digest
  corrected_nested_capability_profile_digest
  qualification_facts_digest
  catalog_digest
  mappings_digest
  settings_digest
  model_profile_digest
  scenario_artifact_pins: [ArtifactPin]
  model_call_evidence: ModelCallEvidence
  expected_targets: [(relation_id, selected_candidate_id)]
  generated_targets: [(relation_id, selected_candidate_id)]
  admitted_targets: [(relation_id, selected_candidate_id)]
  quarantined_targets: [(relation_id, selected_candidate_id)]
  exact_join_counts
  semantic_digest
}
```

`generate_run_manifest_pin` and `run_id` identify one exact run. The manifest
and model-call evidence must account for settings/model profile and each
scenario artifact hash; secrets or raw prompts are not substitutes for these
typed hashes. The bundle also requires exact confirmed review/adjudication
evidence with reviewer identity/digest and independent mechanism evidence,
distinct from bridge evidence.

### 11.3 Exact candidate validation sequence

For each expected target, the later adapter MUST perform these checks in order:

1. Parse a typed `ScenarioEnvelope`.
2. Recompute its `cand:v2` ID from the attack pattern and canonical projection.
3. Require the envelope ID to equal the recomputed ID.
4. Resolve the full projectable candidate/materialization in the corrected
   Phase 1 plan and compare projection, ingress, and resource bindings exactly.
5. Reject duplicate IDs, old/superseded IDs, and extra unrequested entries.
6. Only then call `TaxonomyCoverageInput.from_scenario_envelopes`.

The result records expected/generated/admitted/quarantined/exact-join counts.
It cannot repair IDs, infer a relation, or convert shared-resource evidence
into coverage.

### 11.4 Required future live-pilot runbook

Before any semantic pilot, a separate **required future qualification
deliverable** must document corrected nested capability-profile and
qualification-facts extraction, every `PilotProvenanceBundle` input, the exact
run manifest/run ID, model-call evidence, target list, candidate admission,
human review/adjudication, and quarantine handling. Phase 4 remains offline and
does not implement or run this live runbook.

## 12. Compatibility invariants

Phase 4 MUST preserve:

- all Phase 1 obligation rows, dispositions, candidate records, pins, and
  digests;
- all Phase 2 structural, taxonomy, and scenario-realization matrices and
  their separate denominators;
- all accepted/rejected/unresolved/contradictory relation records;
- all Phase 3 original decisions, challenge outcomes, technical failures, and
  zero correspondence/coverage-change guarantees;
- ordinary `generate` and `stpa-run` prompts, call counts, decisions,
  artifacts, manifests, reports, and exit behavior; and
- the boundary that deterministic validation and persistence make no provider
  or network calls.

An unmapped structural ICA remains a valid STPA finding but has no Phase 4
projection without an accepted Phase 2 relation. A taxonomy obligation without
an accepted relation remains a typed exclusion/gap, not a scenario candidate.

## 13. Proposed acceptance examples

The committed Gherkin contract should demonstrate at least:

1. one exact accepted relation produces one round-trippable projection;
2. the projection retains the exact relation, obligation, selected candidate,
   ICA, and `EXEC:*` identities;
3. two ICAs sharing one `EXEC:*` remain two distinct projections/relations;
4. one obligation can retain separate projections for separate accepted
   relations without identity collapse;
5. a related-resource-only relation is excluded and never becomes a bridge or
   projection;
6. a Phase 3 challenge outcome cannot create a projection or coverage credit;
7. a missing, substituted, or non-projectable candidate fails closed;
8. a candidate link belonging to another candidate is rejected;
9. a missing, model-proposed, unreviewed, prose-only, or resource-only bridge
   is excluded;
10. an unknown endpoint, wrong namespace, duplicate edge, reversed edge, or
    bridge cycle fails closed;
11. changing any source pin or digest fails before publication;
12. reordered inputs produce identical canonical bytes and semantic digest;
13. every omitted relation is represented by an exact typed exclusion;
14. synthetic fixtures are labelled normative bookkeeping and are not treated
    as semantic truth;
15. deterministic model, graph, persistence, and acceptance paths make zero
    provider/network calls; and
16. ordinary `generate` and `stpa-run` remain behaviorally unchanged.

These examples are contract tests, not a replacement for the later semantic
pilot gate.

## 14. Quality and review gates

The Phase 4 work item is complete only when the six responsibilities have
independent evidence:

- **Specifier:** this proposal has explicit user approval for the deterministic
  Tasks 1–3, including bridge vocabulary, evidence authority, identity, and
  artifact decisions. Link that approval from the durable issue or PR before
  merge; the later semantic pilot still requires its own decision.
- **Coder:** the smallest typed model/validator/persistence slice is implemented
  test-first, without importing either generation runner.
- **Cleaner:** no duplicate relation identity, bridge logic, digest path, or
  coverage calculation exists; exclusions have one closed vocabulary.
- **Architect:** dependency direction is `Phase 2 assessment → exact
  projection inputs → bridge validator → projection set`; Phase 3 is history,
  not correspondence authority; ordinary workflows remain unaware.
- **Hardener:** stale/substituted/unknown/duplicate identities, candidate
  binding mismatch, bridge authority, endpoint, order, cycle, and digest
  attacks are covered by negative/property/mutation tests.
- **QA:** deterministic Gherkin and unit tests pass without an endpoint, the
  external QA reader independently verifies the artifact, the source quality
  sequence passes, and compatibility proves no existing workflow changed.

Required quality evidence is:

```text
Gherkin mutation: zero survivors and zero errors
source mutation: project threshold (>=80% overall; target all covered sites)
CRAP: every changed function <= 6
DRY: no duplicate acceptance/fixture contract or digest implementation
QA: independent typed-artifact checks and zero provider/network calls
compatibility: generate and stpa-run unchanged
```

## 15. Approved and deferred decisions

The Phase 4 approval fixes the following implementation choice:

1. The public symbol is `build_hybrid_scenario_projection_set` and accepts one
   closed `HybridProjectionInputs` value.

The following decisions are deliberately deferred and do not block the
deterministic Phase 4 tasks:

1. The first use case for a later target-scoped semantic pilot after its gate
   is met.
2. Whether a later consumer-facing projection artifact should receive a new
   version; artifact-generator work remains outside Phase 4.

The bridge endpoint table, bridge evidence authority, one-relation
cardinality, reconciliation authority, digest domains, fatal/exclusion
boundary, evidence classes, and Phase 5 exclusion are approved contract
choices, not unresolved implementation choices.

## 16. References and authority

- [`stpa-taxonomy-synthesis.md`](stpa-taxonomy-synthesis.md): recommended
  combined projection and bridge design, especially §§5–7 and the phased plan.
  It is explicitly investigative, not approved.
- [`stpa-taxonomy-phases-1-2-spec.md`](stpa-taxonomy-phases-1-2-spec.md): exact
  Phase 1/2 identity, matrix, evidence, and dependency rules.
- [`stpa-taxonomy-phase3-closed-loop-spec.md`](stpa-taxonomy-phase3-closed-loop-spec.md):
  approved Phase 3 boundary, historical challenge semantics, and prohibition on
  combined generation.
- [`stpa-taxonomy-phase3-swarmforge-tasks.md`](stpa-taxonomy-phase3-swarmforge-tasks.md):
  Phase 3 task exclusions and later fresh-corpus requirement.
- [`phase12-live-run-klarna-nhs-2026-08-29.md`](phase12-live-run-klarna-nhs-2026-08-29.md):
  corrected-plan lineage, review calibration, and pilot blockers.
- [`../../docs/architecture/overview.md`](../../docs/architecture/overview.md)
  and [`../../AGENTS.md`](../../AGENTS.md): dependency direction, offline
  behavior, persistence, and compatibility constraints.
- [`stpa-artifact-generator-integration-assessment.md`](stpa-artifact-generator-integration-assessment.md):
  proposed downstream consumer boundary; it is not a Phase 4 prerequisite
  unless a later issue explicitly expands scope.
