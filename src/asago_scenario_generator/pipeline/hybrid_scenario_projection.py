"""Verified Phase 4 Task 1 authority adapters and unit resolver.

This module is the outer boundary for the Phase 4 inward models.  It accepts
the current Phase 1/2/STPA objects only at explicit adapter functions, copies
and revalidates mutable values immediately, and returns neutral immutable
attestations.  Task 1 deliberately stops before bridge-DAG composition or
persistence; :func:`resolve_hybrid_projection_units` returns pre-composition
units and typed relation-local exclusions for Task 2.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal
import weakref

from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyPin
from asago_scenario_generator.models.candidate_materialization import (
    CandidateMaterialization,
    CandidateMaterializationSet,
)
from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)
from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
    ProposalSet,
    ReconciliationResult,
    ReviewedCorrespondenceAdjudications,
    ReviewedCorrespondenceDecision,
)
from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    ScenarioRealizationRow,
    TaxonomyCorrespondenceRow,
)
from asago_scenario_generator.models.hybrid_projection_inputs import (
    HybridProjectionInputs,
)
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    BridgeLink,
    CausalEdge,
    CausalNode,
    CausalProjection,
    CapabilityFactAttestation,
    ConfirmedCoverageReview,
    HybridCorrespondenceAttestation,
    HybridProjectionResolution,
    HybridProjectionUnit,
    HybridScenarioProjection,
    HybridScenarioProjectionSet,
    MechanismEvidenceAttestation,
    MechanismProjection,
    PinnedStpaProjectionAttestation,
    ProjectionExclusion,
    ProjectionSourcePin,
    ProjectionTraceReference,
    TaxonomyProjectionSourcePin,
    _canonical_projection_source_pins,
)
from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    TaxonomyObligation,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
    compute_control_structure_digest,
)
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    compute_execution_requirements_digest,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.models.correspondence import (
    compute_ica_enumeration_digest,
    compute_loss_analysis_digest,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    canonical_projection_data,
)


PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN = "asago.phase1-candidate-record.v1"
STPA_EXECUTION_PROJECTION_DIGEST_DOMAIN = "asago.stpa-execution-projection.v1"


# Attestations are deliberately runtime values produced by the typed adapter
# boundary.  A process-local identity registry records that provenance without
# pretending a serialized model can prove how it was constructed.  It also
# means ``model_copy(update=...)`` creates an untrusted value even when a
# caller recomputes its public digest.
_VERIFIED_VALUES: dict[int, weakref.ReferenceType[Any]] = {}
_CORRESPONDENCE_METADATA: dict[int, tuple[weakref.ReferenceType[Any], str, str]] = {}


def _mark_verified(value: Any) -> Any:
    """Register one factory output by object identity and return it."""
    key = id(value)

    def discard(_reference: weakref.ReferenceType[Any], *, key: int = key) -> None:
        """Remove a dead value without allowing object-id reuse."""
        _VERIFIED_VALUES.pop(key, None)

    _VERIFIED_VALUES[key] = weakref.ref(value, discard)
    return value


def _mark_correspondence_verified(
    value: Any, assessment_digest: str | None, resource_map_digest: str
) -> Any:
    """Seal the Phase 2 wrapper to the assessment and map used to build it."""
    if assessment_digest is None:
        raise ValueError("phase2 assessment must carry a semantic digest")
    _mark_verified(value)
    key = id(value)

    def discard(_reference: weakref.ReferenceType[Any], *, key: int = key) -> None:
        """Remove metadata for a collected correspondence wrapper."""
        _CORRESPONDENCE_METADATA.pop(key, None)

    _CORRESPONDENCE_METADATA[key] = (
        weakref.ref(value, discard),
        assessment_digest,
        resource_map_digest,
    )
    return value


def _correspondence_metadata(value: Any) -> tuple[str, str] | None:
    """Return the factory-bound assessment and resource-map digests."""
    metadata = _CORRESPONDENCE_METADATA.get(id(value))
    if metadata is None or metadata[0]() is not value:
        return None
    return metadata[1], metadata[2]


@dataclass(frozen=True)
class _StpaSources:
    """Copied STPA authorities used by the attestation factory."""

    loss: LossAnalysis
    structure: ControlStructure
    enumeration: ICAEnumeration
    envelopes: tuple[CandidateExecutionEnvelope, ...]
    relations: tuple[AcceptedCorrespondenceRelation, ...]


@dataclass(frozen=True)
class _StpaPins:
    """Content pins derived from one copied STPA authority set."""

    loss: ArtifactPin
    structure: ArtifactPin
    enumeration: ArtifactPin
    execution: ArtifactPin


@dataclass(frozen=True)
class _ResolvedRelationParts:
    """Authority values needed to build one resolved projection unit."""

    materialization: CandidateMaterialization
    causal: CausalProjection
    review: ConfirmedCoverageReview
    bridges: tuple[BridgeLink, ...]


@dataclass(frozen=True)
class _ResolutionContext:
    """Validated indexes shared by each requested-relation resolution."""

    inputs: HybridProjectionInputs
    plan: TaxonomyObligationPlan
    resource_links: dict[str, Any]
    relation_by_id: dict[str, AcceptedCorrespondenceRelation]
    materials: dict[tuple[str, str], CandidateMaterialization]
    stpa_by_identity: dict[tuple[str, str], tuple[CausalProjection, ...]]
    reviews: dict[str, ConfirmedCoverageReview]
    realization_rows: dict[str, ScenarioRealizationRow]
    taxonomy_rows: dict[str, TaxonomyCorrespondenceRow]
    plan_rows: dict[str, TaxonomyObligation]
    source_pins: tuple[ProjectionSourcePin, ...]


def _require_type(value: Any, expected: type[Any], name: str) -> Any:
    """Require one exact typed boundary value, never an implicit mapping."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be a {expected.__name__}")
    return value


def _copy_revalidated(value: Any, expected: type[Any], name: str) -> Any:
    """Deep-copy and revalidate one mutable upstream model immediately."""
    _require_type(value, expected, name)
    return expected.model_validate(deepcopy(value.model_dump(mode="python")))


def _validate_assessment_relation_rows(
    relation: AcceptedCorrespondenceRelation,
    realization: ScenarioRealizationRow | None,
    taxonomy: TaxonomyCorrespondenceRow | None,
) -> None:
    """Require both Phase 2 matrices to identify one exact relation.

    ``ReconciliationResult.accepted_relations`` is the authority for the full
    relation record.  The assessment must retain the exact realization row;
    coverage-bearing relations additionally need their taxonomy row's
    accepted-relation membership, while related-only relations must be absent
    from that membership.
    """
    realization = _require_realization_row(realization)
    taxonomy = _require_taxonomy_row(taxonomy)
    if not _realization_row_matches(relation, realization):
        raise ValueError("assessment rows do not match the accepted relation")
    if not _taxonomy_row_matches(relation, taxonomy):
        raise ValueError("assessment rows do not match the accepted relation")


def _require_realization_row(
    row: ScenarioRealizationRow | None,
) -> ScenarioRealizationRow:
    """Require the selected relation's realization row to exist."""
    if row is None:
        raise ValueError("assessment is missing the exact relation rows")
    return row


def _require_taxonomy_row(
    row: TaxonomyCorrespondenceRow | None,
) -> TaxonomyCorrespondenceRow:
    """Require the selected obligation's taxonomy row to exist."""
    if row is None:
        raise ValueError("assessment is missing the exact relation rows")
    return row


def _realization_row_matches(
    relation: AcceptedCorrespondenceRelation, row: ScenarioRealizationRow
) -> bool:
    """Match the exact coverage-bearing realization identity."""
    expected_coverage = relation.relation_kind != "related_but_not_coverage"
    return (
        row.relation_id,
        row.coverage_bearing,
        row.proposal_id,
        row.obligation_id,
        row.risk_id,
        row.attack_pattern_id,
        row.taxonomy_candidate_ids,
        row.correspondence_relation_kind,
    ) == (
        relation.relation_id,
        expected_coverage,
        relation.proposal_id,
        relation.obligation_id,
        relation.risk_id,
        relation.attack_pattern_id,
        relation.taxonomy_candidate_ids,
        relation.relation_kind,
    )


def _taxonomy_row_matches(
    relation: AcceptedCorrespondenceRelation, row: TaxonomyCorrespondenceRow
) -> bool:
    """Match the obligation row that explicitly retains the relation ID."""
    identity_matches = (
        row.obligation_id,
        row.risk_id,
        row.attack_pattern_id,
        row.taxonomy_candidate_ids,
    ) == (
        relation.obligation_id,
        relation.risk_id,
        relation.attack_pattern_id,
        relation.taxonomy_candidate_ids,
    )
    if not identity_matches:
        return False
    # Noncoverage is an intact Phase 2 observation, but it must not be
    # represented as accepted coverage in the taxonomy denominator.
    if relation.relation_kind == "related_but_not_coverage":
        return relation.relation_id not in row.accepted_relation_ids
    return relation.relation_id in row.accepted_relation_ids


def _artifact_pin(
    artifact_id: str, schema_version: str, semantic_digest: str
) -> ArtifactPin:
    """Build one ordinary content-addressed artifact pin."""
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=semantic_digest,
    )


def _checked_pin(
    supplied: ArtifactPin | None,
    *,
    artifact_id: str,
    schema_version: str,
    digest: str,
    name: str,
) -> ArtifactPin:
    """Use a supplied pin only when its exact digest is authoritative."""
    expected = _artifact_pin(artifact_id, schema_version, digest)
    if supplied is None:
        return expected
    _require_type(supplied, ArtifactPin, name)
    _validate_supplied_pin(supplied, expected, digest, name)
    return supplied


def _validate_supplied_pin(
    supplied: ArtifactPin,
    expected: ArtifactPin,
    digest: str,
    name: str,
) -> None:
    """Require a caller-provided pin to match the exact source authority."""
    if supplied.semantic_digest != digest:
        raise ValueError(f"{name} semantic digest does not match source content")
    # Artifact labels identify the source role.  A caller cannot silently use
    # a digest from a different role as this authority.
    if (
        supplied.artifact_id != expected.artifact_id
        or supplied.schema_version != expected.schema_version
    ):
        raise ValueError(f"{name} artifact identity does not match source content")


def _as_artifact_source_pin(pin: ArtifactPin, role: str) -> ArtifactProjectionSourcePin:
    """Label one ordinary artifact pin for the source-pin union."""
    return ArtifactProjectionSourcePin.from_artifact_pin(pin, role=role)


def _as_taxonomy_source_pin(
    taxonomy_id: str, pin: TaxonomyPin, role: str
) -> TaxonomyProjectionSourcePin:
    """Retain a Phase 1 taxonomy pin in its native shape."""
    if role not in {"catalog", "mapping"}:
        raise ValueError("taxonomy source pin role must be catalog or mapping")
    return TaxonomyProjectionSourcePin(
        role=role,
        taxonomy_id=taxonomy_id,
        pin=pin,
    )


def _canonical_source_pins(
    pins: Iterable[ProjectionSourcePin],
) -> tuple[ProjectionSourcePin, ...]:
    """Reuse the inward canonicalizer for every adapter source-pin union."""
    return _canonical_projection_source_pins(tuple(pins))


def _candidate_record_digest(record: CandidateRecord) -> str:
    """Compute the Phase 1 candidate-record digest from the complete row."""
    return compute_framed_digest(
        PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN,
        record.model_dump(mode="json"),
    )


def compute_candidate_record_digest(record: CandidateRecord) -> str:
    """Return the canonical digest for one typed Phase 1 candidate record."""
    if not isinstance(record, CandidateRecord):
        raise TypeError("record must be a CandidateRecord")
    return _candidate_record_digest(record)


def _qualification_facts_digest(snapshot: CapabilityFactSnapshot) -> str:
    """Reuse the Phase 1 qualification-facts canonical contract."""
    return QualificationFactsInput(
        facts=[item.model_dump(mode="python") for item in snapshot.facts]
    ).semantic_digest


def capability_fact_attestation_from_artifacts(
    capability_snapshot: CapabilityFactSnapshot,
    obligation_plan: TaxonomyObligationPlan,
    resource_map_validation: SystemResourceMapValidation | None = None,
) -> CapabilityFactAttestation:
    """Create the neutral capability/fact attestation from exact sources."""
    snapshot = _copy_revalidated(
        capability_snapshot, CapabilityFactSnapshot, "capability_snapshot"
    )
    plan = _require_type(obligation_plan, TaxonomyObligationPlan, "obligation_plan")
    plan.assert_integrity()
    snapshot.assert_integrity()
    qualification_digest = _qualification_facts_digest(snapshot)
    if snapshot.snapshot_digest != plan.capability_snapshot_digest:
        raise ValueError("capability snapshot does not match the obligation plan")
    if qualification_digest != plan.qualification_facts_digest:
        raise ValueError("qualification facts do not match the obligation plan")
    if resource_map_validation is not None:
        _validate_resource_map_attestation(resource_map_validation, snapshot)
    snapshot_pin = _artifact_pin(
        "capability-fact-snapshot",
        "capability-fact-snapshot-v1",
        snapshot.snapshot_digest,
    )
    result = CapabilityFactAttestation(
        capability_snapshot_digest=snapshot.snapshot_digest,
        qualification_facts_digest=qualification_digest,
        source_pin=snapshot_pin,
    )
    return _mark_verified(result)


def _validate_resource_map_attestation(
    validation: SystemResourceMapValidation,
    snapshot: CapabilityFactSnapshot | None = None,
) -> None:
    """Require a successful map and its canonical content integrity."""
    checked = _copy_resource_map_validation(validation)
    _require_successful_resource_map(checked)
    checked.canonical_map.assert_integrity()
    _validate_resource_map_snapshot(checked, snapshot)


def _copy_resource_map_validation(
    validation: SystemResourceMapValidation,
) -> SystemResourceMapValidation:
    """Copy and revalidate a mutable resource-map validation value."""
    _require_type(validation, SystemResourceMapValidation, "resource_map_validation")
    checked = SystemResourceMapValidation.model_validate(
        deepcopy(validation.model_dump(mode="python"))
    )
    if checked != validation:
        raise ValueError("system resource map validation integrity mismatch")
    return checked


def _require_successful_resource_map(
    validation: SystemResourceMapValidation,
) -> None:
    """Require successful map validation and both completeness attestations."""
    if not validation.is_valid:
        raise ValueError("system resource map validation must be successful")
    if validation.canonical_map is None:
        raise ValueError("system resource map validation must be successful")
    _require_resource_map_completeness(validation)


def _require_resource_map_completeness(
    validation: SystemResourceMapValidation,
) -> None:
    """Require both inventory completeness attestations on a successful map."""
    if (
        validation.entry_point_completeness is None
        or validation.tool_inventory_completeness is None
    ):
        raise ValueError("system resource map inventory attestation is incomplete")


def _validate_resource_map_snapshot(
    validation: SystemResourceMapValidation,
    snapshot: CapabilityFactSnapshot | None,
) -> None:
    """Match an optional capability snapshot to the validated map."""
    if snapshot is None:
        return
    snapshot.assert_integrity()
    if validation.canonical_map.capability_snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("resource map capability digest does not match snapshot")


def candidate_materialization_set_from_artifacts(
    obligation_plan: TaxonomyObligationPlan,
    candidates: Sequence[ProjectedCandidate],
    capability_snapshot: CapabilityFactSnapshot | None = None,
) -> CandidateMaterializationSet:
    """Materialize complete current candidates against one exact Phase 1 plan."""
    plan = _require_type(obligation_plan, TaxonomyObligationPlan, "obligation_plan")
    plan.assert_integrity()
    _require_candidate_sequence(candidates)
    snapshot = _validated_snapshot_for_plan(capability_snapshot, plan)
    rows_by_candidate = _candidate_rows_by_id(plan)
    plan_pin, source_pins = _materialization_sources(plan, snapshot)
    entries = tuple(
        _materialize_candidate(raw, plan, rows_by_candidate, source_pins)
        for raw in candidates
    )

    result = CandidateMaterializationSet(
        obligation_plan_pin=plan_pin,
        entries=entries,
        source_pins=_canonical_source_pins(source_pins),
    )
    return _mark_verified(result)


def _require_candidate_sequence(candidates: Sequence[ProjectedCandidate]) -> None:
    """Require a concrete sequence at the candidate materialization boundary."""
    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
        raise TypeError("candidates must be a sequence of ProjectedCandidate values")


def _validated_snapshot_for_plan(
    capability_snapshot: CapabilityFactSnapshot | None,
    plan: TaxonomyObligationPlan,
) -> CapabilityFactSnapshot:
    """Copy and validate capability and qualification facts against a plan."""
    if capability_snapshot is None:
        raise ValueError(
            "capability snapshot is required for candidate materialization"
        )
    snapshot = _copy_revalidated(
        capability_snapshot, CapabilityFactSnapshot, "capability_snapshot"
    )
    snapshot.assert_integrity()
    if snapshot.snapshot_digest != plan.capability_snapshot_digest:
        raise ValueError("capability snapshot does not match the obligation plan")
    if _qualification_facts_digest(snapshot) != plan.qualification_facts_digest:
        raise ValueError("qualification facts do not match the obligation plan")
    return snapshot


def _candidate_rows_by_id(
    plan: TaxonomyObligationPlan,
) -> dict[str, tuple[TaxonomyObligation, CandidateRecord]]:
    """Index each Phase 1 candidate row exactly once."""
    rows_by_candidate: dict[str, tuple[TaxonomyObligation, CandidateRecord]] = {}
    for row in plan.obligations:
        for record in row.candidate_records:
            if record.candidate_id in rows_by_candidate:
                raise ValueError("candidate identity appears in multiple plan rows")
            rows_by_candidate[record.candidate_id] = (row, record)
    return rows_by_candidate


def _materialization_sources(
    plan: TaxonomyObligationPlan, snapshot: CapabilityFactSnapshot
) -> tuple[ArtifactPin, list[ProjectionSourcePin]]:
    """Build the plan, native taxonomy, and capability source-pin set."""
    plan_pin = _artifact_pin(
        "taxonomy-obligation-plan", plan.schema_version, plan.semantic_digest
    )
    source_pins: list[ProjectionSourcePin] = [
        _as_artifact_source_pin(plan_pin, "obligation-plan")
    ]
    source_pins.extend(
        _as_taxonomy_source_pin(taxonomy_id, pin, "catalog")
        for taxonomy_id, pin in sorted(plan.catalog_pins.items())
    )
    source_pins.extend(
        _as_taxonomy_source_pin(taxonomy_id, pin, "mapping")
        for taxonomy_id, pin in sorted(plan.mapping_pins.items())
    )
    source_pins.extend(
        (
            _as_artifact_source_pin(
                _artifact_pin(
                    "capability-fact-snapshot",
                    "capability-fact-snapshot-v1",
                    snapshot.snapshot_digest,
                ),
                "capability-facts",
            ),
            _as_artifact_source_pin(
                _artifact_pin(
                    "qualification-facts",
                    "qualification-facts-v1",
                    _qualification_facts_digest(snapshot),
                ),
                "qualification-facts",
            ),
        )
    )
    return plan_pin, source_pins


def _materialize_candidate(
    raw_candidate: ProjectedCandidate,
    plan: TaxonomyObligationPlan,
    rows_by_candidate: dict[str, tuple[TaxonomyObligation, CandidateRecord]],
    source_pins: Sequence[ProjectionSourcePin],
) -> CandidateMaterialization:
    """Validate and materialize one complete candidate-v2 record."""
    candidate = _copy_revalidated(raw_candidate, ProjectedCandidate, "candidate")
    pair = rows_by_candidate.get(candidate.candidate_id)
    if pair is None:
        raise ValueError("candidate is not present in the obligation plan")
    row, record = pair
    _validate_candidate_against_record(candidate, row, record, plan)
    mechanism = MechanismProjection(
        obligation_id=row.obligation_id,
        risk_id=row.risk_ref.risk_id,
        attack_pattern_id=candidate.pattern_id,
        selected_candidate_id=candidate.candidate_id,
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        execution_requirements=candidate.execution_requirements,
        execution_requirements_digest=compute_execution_requirements_digest(
            candidate.execution_requirements
        ),
    )
    return CandidateMaterialization(
        obligation_id=row.obligation_id,
        risk_id=row.risk_ref.risk_id,
        attack_pattern_id=candidate.pattern_id,
        selected_candidate_id=candidate.candidate_id,
        phase1_candidate_record_digest=_candidate_record_digest(record),
        mechanism_projection=mechanism,
        source_pins=_canonical_source_pins(source_pins),
    )


def _validate_candidate_against_record(
    candidate: ProjectedCandidate,
    row: TaxonomyObligation,
    record: CandidateRecord,
    plan: TaxonomyObligationPlan,
) -> None:
    """Require candidate-v2 identity, snapshot, ingress, and bindings to agree."""
    if record.projection_disposition != "projectable":
        raise ValueError("only projectable Phase 1 candidates can materialize")
    _validate_candidate_identity(candidate, row)
    _validate_candidate_snapshot(candidate, plan)
    _validate_candidate_bindings(candidate, record)


def _validate_candidate_identity(
    candidate: ProjectedCandidate, row: TaxonomyObligation
) -> None:
    """Require a projected candidate to belong to the exact pattern row."""
    if row.attack_pattern_id != candidate.pattern_id:
        raise ValueError("candidate pattern identity does not match plan row")


def _validate_candidate_snapshot(
    candidate: ProjectedCandidate, plan: TaxonomyObligationPlan
) -> None:
    """Require a candidate projection to use the plan's capability snapshot."""
    if (
        candidate.projection.capability_fact_snapshot_digest
        != plan.capability_snapshot_digest
    ):
        raise ValueError("candidate projection snapshot digest does not match plan")


def _validate_candidate_bindings(
    candidate: ProjectedCandidate, record: CandidateRecord
) -> None:
    """Require ingress and resource bindings to remain exact from Phase 1."""
    if (
        record.canonical_ingress != candidate.canonical_ingress
        or record.resource_bindings != candidate.projection.bindings
    ):
        raise ValueError("candidate bindings do not match the Phase 1 record")


def build_candidate_materialization_set(
    obligation_plan: TaxonomyObligationPlan,
    candidates: Sequence[ProjectedCandidate],
    capability_snapshot: CapabilityFactSnapshot | None = None,
) -> CandidateMaterializationSet:
    """Descriptive alias for the verified candidate materialization factory."""
    return candidate_materialization_set_from_artifacts(
        obligation_plan, candidates, capability_snapshot
    )


def _canonical_execution_documents(
    envelopes: Sequence[CandidateExecutionEnvelope],
) -> list[dict[str, Any]]:
    """Derive the exact standalone execution-projection values for pinning."""
    documents = [canonical_projection_data(item) for item in envelopes]
    return sorted(
        documents,
        key=lambda item: (item.get("ica_id") or "", item["candidate_id"]),
    )


def _execution_projection_digest(
    envelopes: Sequence[CandidateExecutionEnvelope],
) -> str:
    """Compute the dedicated Phase 4 execution-projection source pin."""
    return compute_framed_digest(
        STPA_EXECUTION_PROJECTION_DIGEST_DOMAIN,
        _canonical_execution_documents(envelopes),
    )


def _slot_index(enumeration: ICAEnumeration) -> dict[str, ICASlot]:
    """Index exact ICA slots and reject duplicate identities."""
    result: dict[str, ICASlot] = {}
    for slot in enumeration.slots:
        if slot.slot_id in result:
            raise ValueError("ICA enumeration contains duplicate slot IDs")
        result[slot.slot_id] = slot
    return result


def _ica_in_slot(slot: ICASlot, ica_id: str) -> ICA:
    """Resolve one ICA only within its exact slot."""
    matches = [item for item in slot.icas if item.ica_id == ica_id]
    if len(matches) != 1:
        raise ValueError("accepted relation references an unknown ICA in its slot")
    return matches[0]


def _control_ids(control_structure: ControlStructure) -> dict[str, set[str]]:
    """Collect the exact control-structure namespaces needed by causal paths."""
    return {
        "controller": {item.resp_id for item in control_structure.responsibilities},
        "control_action": _responsibility_child_ids(
            control_structure, "control_actions", "ca_id"
        ),
        "process_model": _responsibility_child_ids(
            control_structure, "process_model_parts", "pm_id"
        ),
        "feedback": _responsibility_child_ids(
            control_structure, "feedback_channels", "fb_id"
        ),
        "coordination_link": {
            item.link_id for item in control_structure.coordination_links
        },
        "coordination_mechanism": {
            item.coordination_mechanism.cm_id
            for item in control_structure.coordination_links
        },
    }


def _responsibility_child_ids(
    control_structure: ControlStructure, collection: str, identifier: str
) -> set[str]:
    """Collect one child-ID namespace across all responsibilities."""
    return {
        getattr(item, identifier)
        for responsibility in control_structure.responsibilities
        for item in getattr(responsibility, collection)
    }


def _node_ordinal_map(nodes: Sequence[CausalNode]) -> dict[str, int]:
    return {node.node_id: node.ordinal for node in nodes}


def _stpa_relation_context(
    relation: AcceptedCorrespondenceRelation,
    ica: ICA,
    loss_analysis: LossAnalysis,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve relation context only from the exact ICA/loss authorities."""
    hazards_by_id = {item.hazard_id: item for item in loss_analysis.hazards}
    constraints_by_id = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    relation_hazards, relation_constraints = _validate_stpa_context_ids(
        relation, ica, hazards_by_id, constraints_by_id
    )
    _validate_constraint_hazard_links(
        relation_hazards, relation_constraints, constraints_by_id
    )
    loss_ids = _loss_ids_for_hazards(relation_hazards, hazards_by_id)
    losses_by_id = {
        item.loss_id: item
        for item in (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses)
    }
    _validate_loss_context(relation, loss_ids, losses_by_id)
    return (
        tuple(sorted(relation_hazards)),
        tuple(sorted(relation_constraints)),
        loss_ids,
    )


def _validate_stpa_context_ids(
    relation: AcceptedCorrespondenceRelation,
    ica: ICA,
    hazards_by_id: dict[str, Any],
    constraints_by_id: dict[str, Any],
) -> tuple[set[str], set[str]]:
    """Require relation hazard/constraint IDs to match the exact ICA."""
    relation_hazards, relation_constraints = _context_sets_for_ica(
        relation, ica, constraints_by_id
    )
    _require_context_members(relation_hazards, relation_constraints)
    _require_known_context_ids(
        relation_hazards, relation_constraints, hazards_by_id, constraints_by_id
    )
    return relation_hazards, relation_constraints


def _context_sets_for_ica(
    relation: AcceptedCorrespondenceRelation,
    ica: ICA,
    constraints_by_id: dict[str, Any],
) -> tuple[set[str], set[str]]:
    """Resolve the relation context sets and compare them to the ICA."""
    relation_hazards = set(relation.hazard_ids)
    relation_constraints = set(relation.constraint_ids)
    ica_constraints = {
        item for item in ica.related_constraints if item in constraints_by_id
    }
    checks = (
        relation_hazards == set(ica.related_hazards),
        relation_constraints == ica_constraints,
    )
    if not all(checks):
        raise ValueError("relation hazard/constraint context disagrees with ICA")
    return relation_hazards, relation_constraints


def _require_context_members(hazard_ids: set[str], constraint_ids: set[str]) -> None:
    """Require an accepted relation to retain both STPA context sets."""
    if not hazard_ids or not constraint_ids:
        raise ValueError("accepted relation lacks hazard or constraint context")


def _require_known_context_ids(
    hazard_ids: set[str],
    constraint_ids: set[str],
    hazards_by_id: dict[str, Any],
    constraints_by_id: dict[str, Any],
) -> None:
    """Require every relation context ID to resolve to loss authority."""
    checks = (
        (hazard_ids, hazards_by_id, "relation references an unknown hazard"),
        (
            constraint_ids,
            constraints_by_id,
            "relation references an unknown security constraint",
        ),
    )
    for identifiers, known, message in checks:
        if any(identifier not in known for identifier in identifiers):
            raise ValueError(message)


def _validate_constraint_hazard_links(
    hazard_ids: set[str],
    constraint_ids: set[str],
    constraints_by_id: dict[str, Any],
) -> None:
    """Require authoritative constraints to cover exactly the relation hazards."""
    linked_hazards = {
        hazard_id
        for constraint_id in constraint_ids
        for hazard_id in constraints_by_id[constraint_id].related_hazards
    }
    if linked_hazards != hazard_ids:
        raise ValueError(
            "relation hazard/constraint context disagrees with loss analysis"
        )


def _loss_ids_for_hazards(
    hazard_ids: set[str], hazards_by_id: dict[str, Any]
) -> tuple[str, ...]:
    """Resolve the exact loss identities below the selected hazards."""
    return tuple(
        sorted(
            {
                loss_id
                for hazard_id in hazard_ids
                for loss_id in hazards_by_id[hazard_id].related_losses
            }
        )
    )


def _validate_loss_context(
    relation: AcceptedCorrespondenceRelation,
    loss_ids: tuple[str, ...],
    losses_by_id: dict[str, Any],
) -> None:
    """Require hazards to resolve to losses carrying the relation risk source."""
    _require_resolved_losses(loss_ids, losses_by_id)
    _require_loss_risk_source(relation, loss_ids, losses_by_id)


def _require_resolved_losses(
    loss_ids: Sequence[str], losses_by_id: dict[str, Any]
) -> None:
    """Require every selected hazard to resolve to a known loss."""
    if not loss_ids or any(loss_id not in losses_by_id for loss_id in loss_ids):
        raise ValueError("relation hazards do not resolve to a loss")


def _require_loss_risk_source(
    relation: AcceptedCorrespondenceRelation,
    loss_ids: Sequence[str],
    losses_by_id: dict[str, Any],
) -> None:
    """Require the relation risk to be present on at least one selected loss."""
    if not any(
        relation.risk_id in losses_by_id[loss_id].source_risk_cards
        for loss_id in loss_ids
    ):
        raise ValueError("relation risk is not bound to a selected loss source")


def _causal_projection_for_relation(
    relation: AcceptedCorrespondenceRelation,
    envelope: CandidateExecutionEnvelope,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    enumeration: ICAEnumeration,
) -> CausalProjection:
    """Build one neutral causal path from typed STPA authority and relation IDs."""
    slot, controller_id, ids = _resolve_causal_structure(
        relation, envelope, control_structure, enumeration
    )
    hazard_ids, constraint_ids, loss_ids = _stpa_relation_context(
        relation, _ica_in_slot(slot, relation.ica_id), loss_analysis
    )
    hazards_by_id = {item.hazard_id: item for item in loss_analysis.hazards}
    constraints_by_id = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    factor_nodes = _causal_factor_nodes(envelope, ids, slot.control_action)
    nodes = _causal_nodes(
        loss_ids,
        hazard_ids,
        constraint_ids,
        factor_nodes,
        controller_id,
        slot,
        relation,
    )
    edge_specs = _causal_edge_specs(
        loss_ids,
        hazard_ids,
        constraint_ids,
        hazards_by_id,
        constraints_by_id,
        factor_nodes,
        controller_id,
        slot,
        relation,
    )
    _require_edge_order(edge_specs, _node_ordinal_map(nodes))
    return CausalProjection(
        loss_ids=loss_ids,
        hazard_ids=tuple(sorted(hazard_ids)),
        constraint_ids=tuple(sorted(constraint_ids)),
        controller_id=controller_id,
        control_action_id=slot.control_action,
        uca_slot_id=slot.slot_id,
        ica_id=relation.ica_id,
        exec_candidate_id=relation.exec_candidate_id,
        nodes=nodes,
        edges=tuple(
            CausalEdge(
                edge_id=edge_id,
                from_node_id=source,
                to_node_id=target,
                kind=kind,
            )
            for edge_id, source, target, kind in edge_specs
        ),
    )


def _resolve_causal_structure(
    relation: AcceptedCorrespondenceRelation,
    envelope: CandidateExecutionEnvelope,
    control_structure: ControlStructure,
    enumeration: ICAEnumeration,
) -> tuple[ICASlot, str, dict[str, set[str]]]:
    """Resolve and validate the exact ICA slot/controller structure."""
    slot, controller_id = _resolve_causal_slot(relation, enumeration)
    _validate_causal_envelope(relation, envelope, slot, controller_id)
    ids = _control_ids(control_structure)
    _validate_causal_control_ids(slot, controller_id, ids)
    return slot, controller_id, ids


def _resolve_causal_slot(
    relation: AcceptedCorrespondenceRelation, enumeration: ICAEnumeration
) -> tuple[ICASlot, str]:
    """Resolve one non-N/A slot and its controller identity."""
    slot = _causal_slot_for_relation(relation, enumeration)
    controller_id = _causal_controller_for_slot(slot)
    return slot, controller_id


def _causal_slot_for_relation(
    relation: AcceptedCorrespondenceRelation, enumeration: ICAEnumeration
) -> ICASlot:
    """Find the exact selected slot and ICA in the enumeration."""
    slot = _slot_index(enumeration).get(relation.ica_slot_id)
    if slot is None or slot.is_na:
        raise ValueError("accepted relation references a missing or N/A ICA slot")
    _ica_in_slot(slot, relation.ica_id)
    return slot


def _causal_controller_for_slot(slot: ICASlot) -> str:
    """Resolve the slot's responsible controller or coordination link."""
    controller_id = slot.responsibility or slot.coordination_link
    if not controller_id:
        raise ValueError("ICA slot has no controller identity")
    return controller_id


def _validate_causal_envelope(
    relation: AcceptedCorrespondenceRelation,
    envelope: CandidateExecutionEnvelope,
    slot: ICASlot,
    controller_id: str,
) -> None:
    """Require envelope and relation identities to derive from the slot."""
    expected_exec = f"EXEC:{controller_id}:{slot.control_action}:{slot.uca_type.value}"
    _require_canonical_exec_identity(
        relation, envelope, slot, controller_id, expected_exec
    )
    if envelope.ica_id != relation.ica_id:
        raise ValueError("execution envelope ICA identity does not match relation")


def _require_canonical_exec_identity(
    relation: AcceptedCorrespondenceRelation,
    envelope: CandidateExecutionEnvelope,
    slot: ICASlot,
    controller_id: str,
    expected_exec: str,
) -> None:
    """Require all envelope EXEC fields to equal the slot-derived identity."""
    actual = (
        relation.exec_candidate_id,
        envelope.candidate_id,
        envelope.controller_id,
        envelope.control_action_id,
    )
    expected = (expected_exec, expected_exec, controller_id, slot.control_action)
    if actual != expected:
        raise ValueError("EXEC identity is not canonically derived from the ICA slot")


def _validate_causal_control_ids(
    slot: ICASlot, controller_id: str, ids: dict[str, set[str]]
) -> None:
    """Require non-coordination STPA identities in the control structure."""
    _validate_causal_controller_id(slot, controller_id, ids)
    _validate_causal_action_id(slot, ids)


def _validate_causal_controller_id(
    slot: ICASlot, controller_id: str, ids: dict[str, set[str]]
) -> None:
    """Require the exact RESP or CL namespace used by the ICA slot."""
    if slot.coordination_link is None:
        _require_control_namespace_id(
            controller_id,
            ids["controller"],
            "relation controller is absent from the control structure",
        )
        return
    _require_control_namespace_id(
        controller_id,
        ids["coordination_link"],
        "relation coordination link is absent from the control structure",
    )
    _require_control_namespace_id(
        slot.control_action,
        ids["coordination_mechanism"],
        "relation coordination mechanism is absent from the control structure",
    )


def _require_control_namespace_id(
    identifier: str, known_ids: set[str], message: str
) -> None:
    """Require one exact control or coordination namespace identity."""
    if identifier not in known_ids:
        raise ValueError(message)


def _validate_causal_action_id(slot: ICASlot, ids: dict[str, set[str]]) -> None:
    """Require a control action when the slot is not coordinated."""
    namespace = "coordination_mechanism" if slot.coordination_link else "control_action"
    if slot.control_action not in ids[namespace]:
        raise ValueError("relation control action is absent from the control structure")


def _causal_factor_nodes(
    envelope: CandidateExecutionEnvelope,
    ids: dict[str, set[str]],
    control_action_id: str,
) -> list[tuple[str, str]]:
    """Resolve causal-factor namespaces against the control structure."""
    return [
        _validated_causal_factor_node(factor, ids, control_action_id)
        for factor in envelope.causal_factors
    ]


def _validated_causal_factor_node(
    factor: Any, ids: dict[str, set[str]], control_action_id: str
) -> tuple[str, str]:
    """Resolve and validate one exact causal-factor source namespace."""
    namespace = _causal_factor_namespace(factor.kind.value, control_action_id)
    if factor.source_id not in ids[namespace] | {control_action_id}:
        raise ValueError("execution envelope causal factor is not authoritative")
    return factor.source_id, namespace


def _causal_factor_namespace(kind: str, control_action_id: str) -> str:
    """Map one causal-factor kind to its authoritative control namespace."""
    namespaces = {
        "PROCESS_MODEL_FLAW": "process_model",
        "FEEDBACK_DELAY": "feedback",
        "SENSOR_ANOMALY": "feedback",
        "ACTUATOR_ANOMALY": (
            "coordination_mechanism"
            if control_action_id.startswith("CM-")
            else "control_action"
        ),
    }
    try:
        return namespaces[kind]
    except KeyError as exc:
        raise ValueError(
            "execution envelope causal factor is not authoritative"
        ) from exc


def _causal_nodes(
    loss_ids: tuple[str, ...],
    hazard_ids: set[str],
    constraint_ids: set[str],
    factor_nodes: Sequence[tuple[str, str]],
    controller_id: str,
    slot: ICASlot,
    relation: AcceptedCorrespondenceRelation,
) -> tuple[CausalNode, ...]:
    """Create causally ordered nodes from the exact authority identities."""
    return _nodes_from_specs(
        _causal_node_specs(
            loss_ids,
            hazard_ids,
            constraint_ids,
            factor_nodes,
            controller_id,
            slot,
            relation,
        )
    )


def _causal_node_specs(
    loss_ids: tuple[str, ...],
    hazard_ids: set[str],
    constraint_ids: set[str],
    factor_nodes: Sequence[tuple[str, str]],
    controller_id: str,
    slot: ICASlot,
    relation: AcceptedCorrespondenceRelation,
) -> list[tuple[str, str]]:
    """Build the ordered identity/kind specifications for one causal path."""
    controller_kind, action_kind = _causal_node_kinds(slot)
    return [
        *((identifier, "loss") for identifier in loss_ids),
        *((identifier, "hazard") for identifier in sorted(hazard_ids)),
        *((identifier, "constraint") for identifier in sorted(constraint_ids)),
        *factor_nodes,
        (controller_id, controller_kind),
        (slot.control_action, action_kind),
        (slot.slot_id, "uca"),
        (relation.ica_id, "ica"),
        (relation.exec_candidate_id, "exec"),
    ]


def _nodes_from_specs(specs: Sequence[tuple[str, str]]) -> tuple[CausalNode, ...]:
    """Deduplicate compatible node specifications and assign ordinals."""
    by_id: dict[str, str] = {}
    for identifier, kind in specs:
        previous = by_id.get(identifier)
        if previous is not None and previous != kind:
            raise ValueError("STPA identity is used across incompatible namespaces")
        by_id[identifier] = kind
    return tuple(
        CausalNode(node_id=identifier, kind=kind, ordinal=ordinal)
        for ordinal, (identifier, kind) in enumerate(by_id.items())
    )


def _causal_node_kinds(
    slot: ICASlot,
) -> tuple[
    Literal["controller", "coordination_link"],
    Literal["control_action", "coordination_mechanism"],
]:
    """Preserve the control or coordination namespace in neutral nodes."""
    if slot.coordination_link is not None:
        return "coordination_link", "coordination_mechanism"
    return "controller", "control_action"


def _append_edge(
    specs: list[tuple[str, str, str, str]],
    source: str,
    target: str,
    kind: str = "projection",
) -> None:
    """Append one canonically numbered causal edge specification."""
    specs.append((f"edge-{len(specs)}", source, target, kind))


def _causal_edge_specs(
    loss_ids: tuple[str, ...],
    hazard_ids: set[str],
    constraint_ids: set[str],
    hazards_by_id: dict[str, Any],
    constraints_by_id: dict[str, Any],
    factor_nodes: Sequence[tuple[str, str]],
    controller_id: str,
    slot: ICASlot,
    relation: AcceptedCorrespondenceRelation,
) -> list[tuple[str, str, str, str]]:
    """Build all local loss-to-EXEC edges in authority order."""
    specs: list[tuple[str, str, str, str]] = []
    _append_loss_hazard_edges(specs, loss_ids, hazard_ids, hazards_by_id)
    _append_hazard_constraint_edges(
        specs, hazard_ids, constraint_ids, constraints_by_id
    )
    _append_linear_stpa_edges(specs, constraint_ids, controller_id, slot, relation)
    for factor_id, _kind in factor_nodes:
        if factor_id != slot.control_action:
            _append_edge(specs, factor_id, slot.slot_id, "causal")
    return specs


def _append_loss_hazard_edges(
    specs: list[tuple[str, str, str, str]],
    loss_ids: tuple[str, ...],
    hazard_ids: set[str],
    hazards_by_id: dict[str, Any],
) -> None:
    """Append loss-to-hazard edges retained by each authoritative hazard."""
    for hazard_id in sorted(hazard_ids):
        for loss_id in loss_ids:
            if loss_id in hazards_by_id[hazard_id].related_losses:
                _append_edge(specs, loss_id, hazard_id)


def _append_hazard_constraint_edges(
    specs: list[tuple[str, str, str, str]],
    hazard_ids: set[str],
    constraint_ids: set[str],
    constraints_by_id: dict[str, Any],
) -> None:
    """Append exact hazard-to-constraint edges."""
    for constraint_id in sorted(constraint_ids):
        for hazard_id in sorted(hazard_ids):
            if hazard_id in constraints_by_id[constraint_id].related_hazards:
                _append_edge(specs, hazard_id, constraint_id)


def _append_linear_stpa_edges(
    specs: list[tuple[str, str, str, str]],
    constraint_ids: set[str],
    controller_id: str,
    slot: ICASlot,
    relation: AcceptedCorrespondenceRelation,
) -> None:
    """Append the structural constraint-to-EXEC path."""
    for constraint_id in sorted(constraint_ids):
        _append_edge(specs, constraint_id, controller_id)
    _append_edge(specs, controller_id, slot.control_action, "control")
    _append_edge(specs, slot.control_action, slot.slot_id)
    _append_edge(specs, slot.slot_id, relation.ica_id)
    _append_edge(specs, relation.ica_id, relation.exec_candidate_id)


def _require_edge_order(
    edge_specs: Sequence[tuple[str, str, str, str]], ordinals: dict[str, int]
) -> None:
    """Require every generated edge to follow the canonical node order."""
    if any(ordinals[source] >= ordinals[target] for _, source, target, _ in edge_specs):
        raise ValueError("STPA causal authority reverses local order")


def _copy_stpa_sources(
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
    execution_projections: Sequence[CandidateExecutionEnvelope],
    accepted_relation_contexts: Sequence[AcceptedCorrespondenceRelation],
) -> _StpaSources:
    """Copy and validate every mutable STPA input at the adapter seam."""
    envelopes = _copy_typed_sequence(
        execution_projections,
        CandidateExecutionEnvelope,
        "execution projection",
        "execution_projections must be a sequence of typed envelopes",
    )
    relations = _copy_typed_sequence(
        accepted_relation_contexts,
        AcceptedCorrespondenceRelation,
        "accepted relation context",
        "accepted_relation_contexts must be a sequence of typed relations",
    )
    return _StpaSources(
        loss=_copy_revalidated(loss_analysis, LossAnalysis, "loss_analysis"),
        structure=_copy_revalidated(
            control_structure, ControlStructure, "control_structure"
        ),
        enumeration=_copy_revalidated(
            ica_enumeration, ICAEnumeration, "ica_enumeration"
        ),
        envelopes=envelopes,
        relations=relations,
    )


def _copy_typed_sequence(
    values: Sequence[Any],
    expected: type[Any],
    item_name: str,
    type_error: str,
) -> tuple[Any, ...]:
    """Copy a required typed sequence and retain its original error category."""
    _require_sequence(values, type_error)
    result = tuple(_copy_revalidated(item, expected, item_name) for item in values)
    if not result:
        raise ValueError(f"at least one {item_name} is required")
    return result


def _require_sequence(values: Any, message: str) -> None:
    """Require a non-string sequence at a typed adapter seam."""
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise TypeError(message)


def _stpa_pins(
    sources: _StpaSources,
    loss_pin: ArtifactPin | None,
    structure_pin: ArtifactPin | None,
    enumeration_pin: ArtifactPin | None,
    execution_pin: ArtifactPin | None,
) -> _StpaPins:
    """Derive and verify all four STPA source pins from copied authorities."""
    return _StpaPins(
        loss=_checked_pin(
            loss_pin,
            artifact_id="loss-analysis",
            schema_version="loss-analysis-v1",
            digest=compute_loss_analysis_digest(sources.loss),
            name="loss_analysis_pin",
        ),
        structure=_checked_pin(
            structure_pin,
            artifact_id="control-structure",
            schema_version="control-structure-v1",
            digest=compute_control_structure_digest(sources.structure),
            name="control_structure_pin",
        ),
        enumeration=_checked_pin(
            enumeration_pin,
            artifact_id="ica-enumeration",
            schema_version="ica-enumeration-v1",
            digest=compute_ica_enumeration_digest(sources.enumeration),
            name="ica_enumeration_pin",
        ),
        execution=_checked_pin(
            execution_pin,
            artifact_id="stpa-execution-projection",
            schema_version="stpa-execution-projection-v1",
            digest=_execution_projection_digest(sources.envelopes),
            name="execution_projection_pin",
        ),
    )


def _index_relation_contexts(
    relations: Sequence[AcceptedCorrespondenceRelation],
) -> dict[tuple[str, str], tuple[AcceptedCorrespondenceRelation, ...]]:
    """Index every relation context without collapsing shared ICA/EXEC IDs."""
    grouped: dict[tuple[str, str], list[AcceptedCorrespondenceRelation]] = {}
    for relation in relations:
        key = (relation.ica_id, relation.exec_candidate_id)
        grouped.setdefault(key, []).append(relation)
    return {key: tuple(values) for key, values in grouped.items()}


def _derive_stpa_projections(
    sources: _StpaSources,
) -> tuple[CausalProjection, ...]:
    """Resolve each envelope against one exact accepted relation context."""
    relation_by_exec = _index_relation_contexts(sources.relations)
    projections: list[CausalProjection] = []
    for envelope in sources.envelopes:
        if envelope.ica_id is None:
            raise ValueError("every execution projection must name an ICA")
        relations = relation_by_exec.get((envelope.ica_id, envelope.candidate_id), ())
        if not relations:
            raise ValueError(
                "execution projection has no exact accepted relation context"
            )
        projections.extend(
            _causal_projection_for_relation(
                relation,
                envelope,
                sources.loss,
                sources.structure,
                sources.enumeration,
            )
            for relation in relations
        )
    unique = {item.causal_projection_id: item for item in projections}
    return tuple(unique.values())


def _stpa_source_pins(pins: _StpaPins) -> tuple[ProjectionSourcePin, ...]:
    """Label the four STPA pins for the neutral source-pin union."""
    return _canonical_source_pins(
        (
            _as_artifact_source_pin(pins.loss, "loss-analysis"),
            _as_artifact_source_pin(pins.structure, "control-structure"),
            _as_artifact_source_pin(pins.enumeration, "ica-enumeration"),
            _as_artifact_source_pin(pins.execution, "execution-projection"),
        )
    )


def pinned_stpa_projection_attestation_from_artifacts(
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
    execution_projections: Sequence[CandidateExecutionEnvelope],
    accepted_relation_contexts: Sequence[AcceptedCorrespondenceRelation],
    *,
    loss_analysis_pin: ArtifactPin | None = None,
    control_structure_pin: ArtifactPin | None = None,
    ica_enumeration_pin: ArtifactPin | None = None,
    execution_projection_pin: ArtifactPin | None = None,
) -> PinnedStpaProjectionAttestation:
    """Pin exact STPA authority and derive neutral causal projections."""
    sources = _copy_stpa_sources(
        loss_analysis,
        control_structure,
        ica_enumeration,
        execution_projections,
        accepted_relation_contexts,
    )
    pins = _stpa_pins(
        sources,
        loss_analysis_pin,
        control_structure_pin,
        ica_enumeration_pin,
        execution_projection_pin,
    )
    sources.enumeration.validate_against(sources.loss, sources.structure)
    projections = _derive_stpa_projections(sources)
    source_pins = _stpa_source_pins(pins)
    result = PinnedStpaProjectionAttestation(
        loss_analysis_pin=pins.loss,
        control_structure_pin=pins.structure,
        ica_enumeration_pin=pins.enumeration,
        execution_projection_pin=pins.execution,
        projections=projections,
        source_pins=source_pins,
    )
    return _mark_verified(result)


def build_pinned_stpa_projection_attestation(
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
    execution_projections: Sequence[CandidateExecutionEnvelope],
    accepted_relation_contexts: Sequence[AcceptedCorrespondenceRelation],
    **pins: ArtifactPin | None,
) -> PinnedStpaProjectionAttestation:
    """Descriptive alias for the verified STPA authority factory."""
    return pinned_stpa_projection_attestation_from_artifacts(
        loss_analysis,
        control_structure,
        ica_enumeration,
        execution_projections,
        accepted_relation_contexts,
        **pins,
    )


def _copy_correspondence_sources(
    proposal_set: ProposalSet,
    reconciliation: ReconciliationResult,
    assessment: HybridCoverageAssessment,
) -> tuple[ProposalSet, ReconciliationResult, HybridCoverageAssessment]:
    """Copy each Phase 2 source before any attestation checks."""
    return (
        _copy_revalidated(proposal_set, ProposalSet, "proposal_set"),
        _copy_revalidated(reconciliation, ReconciliationResult, "reconciliation"),
        _copy_revalidated(assessment, HybridCoverageAssessment, "phase2_assessment"),
    )


def _validate_correspondence_sources(
    proposals: ProposalSet,
    result: ReconciliationResult,
    observed: HybridCoverageAssessment,
) -> None:
    """Require intact, shared-digest Phase 2 authority and exact matrix rows."""
    proposals.assert_integrity()
    result.assert_integrity()
    observed.assert_integrity()
    _validate_correspondence_digests(proposals, result, observed)
    _validate_correspondence_rows(result, observed)


def _validate_correspondence_digests(
    proposals: ProposalSet,
    result: ReconciliationResult,
    observed: HybridCoverageAssessment,
) -> None:
    """Require successful reconciliation and matching Phase 2 source digests."""
    checks = (
        (result.is_valid, "reconciliation result must be successful"),
        (
            proposals.capability_snapshot_digest == result.capability_snapshot_digest,
            "proposal/reconciliation capability digests disagree",
        ),
        (
            proposals.resource_map_semantic_digest
            == result.resource_map_semantic_digest,
            "proposal/reconciliation resource-map digests disagree",
        ),
        (
            observed.capability_snapshot_digest == result.capability_snapshot_digest,
            "assessment/reconciliation capability digests disagree",
        ),
    )
    for valid, message in checks:
        if not valid:
            raise ValueError(message)
    _validate_proposal_pairing(proposals, result)


def _proposal_content_key(value: Any) -> bytes:
    """Canonicalize all content shared by proposal and reconciliation rows."""
    fields = (
        "proposal_id",
        "obligation_id",
        "risk_id",
        "attack_pattern_id",
        "taxonomy_candidate_ids",
        "selected_candidate_id",
        "ica_slot_id",
        "ica_id",
        "exec_candidate_id",
        "relation_kind",
        "resource_link_ids",
        "hazard_ids",
        "constraint_ids",
        "provenance",
        "confidence",
        "evidence_strength",
    )
    payload = {field: getattr(value, field) for field in fields}
    return canonical_json_bytes(payload)


def _validate_proposal_pairing(
    proposal_set: ProposalSet, reconciliation: ReconciliationResult
) -> None:
    """Require reconciliation rows to come from this exact proposal set."""
    proposals = {item.proposal_id: item for item in proposal_set.proposals}
    reconciled = {item.proposal_id: item for item in reconciliation.proposals}
    _require_matching_proposal_ids(proposals, reconciled)
    for proposal_id, proposal in proposals.items():
        _require_matching_proposal_content(proposal, reconciled[proposal_id])


def _require_matching_proposal_ids(
    proposals: dict[str, Any], reconciled: dict[str, Any]
) -> None:
    """Require the exact proposal identity set on both Phase 2 artifacts."""
    if set(proposals) != set(reconciled):
        raise ValueError("proposal set and reconciliation contain different proposals")


def _require_matching_proposal_content(proposal: Any, reconciled: Any) -> None:
    """Require one reconciled proposal to retain the exact source content."""
    if _proposal_content_key(proposal) != _proposal_content_key(reconciled):
        raise ValueError(
            "proposal set and reconciliation proposal content do not match"
        )


def _validate_correspondence_rows(
    result: ReconciliationResult, observed: HybridCoverageAssessment
) -> None:
    """Require each accepted relation in both exact Phase 2 matrices."""
    relation_rows, taxonomy_rows = _relation_rows(observed)
    for relation in result.accepted_relations:
        _validate_assessment_relation_rows(
            relation,
            relation_rows.get(relation.relation_id),
            taxonomy_rows.get(relation.obligation_id),
        )


def _correspondence_pins(
    proposals: ProposalSet,
    result: ReconciliationResult,
    proposal_set_pin: ArtifactPin | None,
    reconciliation_pin: ArtifactPin | None,
) -> tuple[ArtifactPin, ArtifactPin]:
    """Verify caller pins against the two complete Phase 2 source values."""
    proposal_digest = proposals.semantic_digest
    reconciliation_digest = result.semantic_digest
    if proposal_digest is None or reconciliation_digest is None:
        raise ValueError("proposal and reconciliation digests are required")
    return (
        _checked_pin(
            proposal_set_pin,
            artifact_id="correspondence-proposals",
            schema_version=proposals.schema_version,
            digest=proposal_digest,
            name="proposal_set_pin",
        ),
        _checked_pin(
            reconciliation_pin,
            artifact_id="correspondence-reconciliation",
            schema_version=result.schema_version,
            digest=reconciliation_digest,
            name="reconciliation_pin",
        ),
    )


def hybrid_correspondence_attestation_from_artifacts(
    proposal_set: ProposalSet,
    reconciliation: ReconciliationResult,
    assessment: HybridCoverageAssessment,
    *,
    proposal_set_pin: ArtifactPin | None = None,
    reconciliation_pin: ArtifactPin | None = None,
) -> HybridCorrespondenceAttestation:
    """Derive accepted relations only from an intact reconciliation result."""
    proposals, result, observed = _copy_correspondence_sources(
        proposal_set, reconciliation, assessment
    )
    _validate_correspondence_sources(proposals, result, observed)
    proposal_pin, reconciliation_pin_value = _correspondence_pins(
        proposals, result, proposal_set_pin, reconciliation_pin
    )
    attestation = HybridCorrespondenceAttestation(
        proposal_set_pin=proposal_pin,
        proposal_set_digest=proposal_pin.semantic_digest,
        reconciliation_pin=reconciliation_pin_value,
        reconciliation_digest=reconciliation_pin_value.semantic_digest,
        accepted_relations=tuple(result.accepted_relations),
    )
    return _mark_correspondence_verified(
        attestation,
        observed.semantic_digest,
        proposals.resource_map_semantic_digest,
    )


def build_hybrid_correspondence_attestation(
    proposal_set: ProposalSet,
    reconciliation: ReconciliationResult,
    assessment: HybridCoverageAssessment,
    **pins: ArtifactPin | None,
) -> HybridCorrespondenceAttestation:
    """Descriptive alias for correspondence authority construction."""
    return hybrid_correspondence_attestation_from_artifacts(
        proposal_set, reconciliation, assessment, **pins
    )


def mechanism_evidence_attestation_from_artifacts(
    proposal_set: ProposalSet,
    proposal_id: str,
    evidence_kind: str,
) -> MechanismEvidenceAttestation:
    """Build mechanism evidence from one exact typed proposal record.

    The proposal set is the evidence artifact and ``proposal_id`` is resolved
    inside its verified, canonical contents.  Callers cannot detach an
    arbitrary record ID from an unrelated digest; accepted-resource-link
    proposals are also rejected because they do not establish mechanism
    evidence.
    """
    _require_type(proposal_set, ProposalSet, "mechanism evidence proposal_set")
    proposal_set.assert_integrity()
    proposal = _proposal_for_evidence(proposal_set, proposal_id)
    _validate_mechanism_evidence_kind(proposal, evidence_kind)
    artifact_pin = _artifact_pin(
        "correspondence-proposals",
        proposal_set.schema_version,
        proposal_set.semantic_digest,
    )
    result = MechanismEvidenceAttestation(
        artifact_pin=artifact_pin,
        record_id=proposal.proposal_id,
        evidence_kind=evidence_kind,
    )
    return _mark_verified(result)


def _proposal_for_evidence(proposal_set: ProposalSet, proposal_id: str) -> Any:
    """Resolve one exact proposal record from the verified proposal set."""
    proposal = next(
        (item for item in proposal_set.proposals if item.proposal_id == proposal_id),
        None,
    )
    if proposal is None:
        raise ValueError("mechanism evidence proposal_id is not in proposal set")
    return proposal


def _validate_mechanism_evidence_kind(proposal: Any, evidence_kind: str) -> None:
    """Require the requested evidence kind to match proposal provenance."""
    expected_source = {
        "exact_id": "exact_id",
        "curated_mechanism_mapping": "curated_mapping",
    }.get(evidence_kind)
    if expected_source != proposal.provenance.evidence_source:
        raise ValueError("mechanism evidence kind does not match proposal evidence")


def _matching_review_decision(
    reviewed: ReviewedCorrespondenceAdjudications,
    accepted: AcceptedCorrespondenceRelation,
) -> ReviewedCorrespondenceDecision:
    """Find the single reviewed decision for the accepted proposal."""
    reviewed.assert_integrity()
    _require_accepted_relation_identity(accepted)
    matching = _review_decisions_for_proposal(reviewed, accepted)
    if len(matching) != 1:
        raise ValueError("reviewed outcomes do not identify the accepted proposal")
    return matching[0]


def _require_accepted_relation_identity(
    accepted: AcceptedCorrespondenceRelation,
) -> None:
    """Require the accepted relation to carry its canonical identity."""
    if accepted.relation_id is None:
        raise ValueError("accepted relation must have an identity")


def _review_decisions_for_proposal(
    reviewed: ReviewedCorrespondenceAdjudications,
    accepted: AcceptedCorrespondenceRelation,
) -> tuple[ReviewedCorrespondenceDecision, ...]:
    """Select reviewed decisions for the exact accepted proposal ID."""
    return tuple(
        decision
        for decision in reviewed.decisions
        if decision.proposal_id == accepted.proposal_id
    )


def _validate_confirmed_decision(
    decision: ReviewedCorrespondenceDecision,
    accepted: AcceptedCorrespondenceRelation,
    mechanism_evidence: MechanismEvidenceAttestation,
) -> None:
    """Require the reviewed decision to independently confirm the relation."""
    checks = (
        (
            decision.status == "confirmed",
            "accepted relation requires a confirmed reviewed decision",
        ),
        (
            decision.relation_kind == accepted.relation_kind,
            "review relation kind does not match accepted relation",
        ),
        (bool(decision.adjudicated_by), "confirmed review requires reviewer identity"),
        (
            set(decision.evidence_refs).issubset(set(accepted.evidence_refs)),
            "review evidence references do not match accepted relation",
        ),
        (
            mechanism_evidence.record_id == accepted.proposal_id,
            "mechanism evidence does not identify the accepted proposal",
        ),
        (
            mechanism_evidence.artifact_pin.schema_version
            == "correspondence-proposals-v1",
            "mechanism evidence must be pinned to the proposal artifact",
        ),
        (
            mechanism_evidence.artifact_pin.artifact_id == "correspondence-proposals",
            "mechanism evidence must identify the proposal artifact",
        ),
    )
    for valid, message in checks:
        if not valid:
            raise ValueError(message)


def _review_pin_and_source_pins(
    reviewed: ReviewedCorrespondenceAdjudications,
    evidence: MechanismEvidenceAttestation,
) -> tuple[ArtifactPin, tuple[ProjectionSourcePin, ...]]:
    """Pin complete review content and retain independent mechanism evidence."""
    review_digest = reviewed.semantic_digest
    if review_digest is None:
        raise ValueError("reviewed adjudications must have a semantic digest")
    review_pin = _artifact_pin(
        "reviewed-correspondence-adjudications",
        reviewed.schema_version,
        review_digest,
    )
    if evidence.artifact_pin == review_pin:
        raise ValueError("mechanism evidence must be independent of review artifact")
    source_pins = _canonical_source_pins(
        (
            _as_artifact_source_pin(review_pin, "review"),
            _as_artifact_source_pin(evidence.artifact_pin, "mechanism-evidence"),
        )
    )
    return review_pin, source_pins


def confirmed_coverage_review_from_artifacts(
    reviewed_adjudications: ReviewedCorrespondenceAdjudications,
    relation: AcceptedCorrespondenceRelation,
    mechanism_evidence: MechanismEvidenceAttestation,
) -> ConfirmedCoverageReview:
    """Derive one confirmed review from exact historical typed outcomes."""
    _assert_verified(mechanism_evidence, "mechanism_evidence")
    reviewed = _copy_revalidated(
        reviewed_adjudications,
        ReviewedCorrespondenceAdjudications,
        "reviewed_adjudications",
    )
    accepted = _copy_revalidated(
        relation, AcceptedCorrespondenceRelation, "accepted relation"
    )
    evidence = _copy_revalidated(
        mechanism_evidence,
        MechanismEvidenceAttestation,
        "mechanism_evidence",
    )
    decision = _matching_review_decision(reviewed, accepted)
    if reviewed.proposal_set_semantic_digest != evidence.artifact_pin.semantic_digest:
        raise ValueError(
            "reviewed outcomes do not match mechanism evidence proposal set"
        )
    _validate_confirmed_decision(decision, accepted, evidence)
    review_pin, source_pins = _review_pin_and_source_pins(reviewed, evidence)
    review = ConfirmedCoverageReview(
        relation_id=accepted.relation_id,
        reviewer_id=decision.adjudicated_by,
        review_artifact_pin=review_pin,
        review_artifact_digest=review_pin.semantic_digest,
        mechanism_evidence=evidence,
        source_pins=source_pins,
    )
    return _mark_verified(review)


def build_confirmed_coverage_review(
    reviewed_adjudications: ReviewedCorrespondenceAdjudications,
    relation: AcceptedCorrespondenceRelation,
    mechanism_evidence: MechanismEvidenceAttestation,
) -> ConfirmedCoverageReview:
    """Descriptive alias for independent confirmed-review construction."""
    return confirmed_coverage_review_from_artifacts(
        reviewed_adjudications, relation, mechanism_evidence
    )


def _assert_verified(value: Any, name: str) -> None:
    """Reject direct or copied authority wrappers at the resolver."""
    reference = _VERIFIED_VALUES.get(id(value))
    if reference is None or reference() is not value:
        raise ValueError(f"{name} must be produced by its verified artifact factory")


def _unit_identity(
    relation: AcceptedCorrespondenceRelation | None,
) -> tuple[str, str, str, str, str]:
    """Return the five-part identity, retaining empty unresolved members."""
    if relation is None:
        return ("", "", "", "", "")
    return (
        relation.relation_id,
        relation.obligation_id,
        relation.selected_candidate_id or "",
        relation.ica_id,
        relation.exec_candidate_id,
    )


def _relation_exclusion(
    relation_id: str,
    relation: AcceptedCorrespondenceRelation | None,
    reason: str,
    source_pins: Sequence[ProjectionSourcePin],
    trace: Sequence[ProjectionTraceReference] = (),
) -> ProjectionExclusion:
    """Construct one deterministic typed relation-local exclusion."""
    identity = _unit_identity(relation)
    if not relation_id:
        relation_id = identity[0]
    return ProjectionExclusion(
        relation_id=relation_id,
        unit_identity=(relation_id, identity[1], identity[2], identity[3], identity[4]),
        reason=reason,
        source_pins=tuple(source_pins),
        trace=tuple(trace),
    )


def _wrapper_source_pin(
    value: Any, artifact_id: str, role: str
) -> ArtifactProjectionSourcePin:
    """Pin one complete wrapper in addition to its leaf authorities."""
    digest = getattr(value, "semantic_digest", None)
    if not digest:
        raise ValueError(f"{role} wrapper must carry a semantic digest")
    return _as_artifact_source_pin(
        _artifact_pin(artifact_id, value.schema_version, digest), role
    )


def _source_pins_for_inputs(
    inputs: HybridProjectionInputs,
) -> tuple[ProjectionSourcePin, ...]:
    """Collect the exact envelope authority pin universe."""
    material = inputs.candidate_materializations
    stpa = inputs.stpa_projection_authority
    resource_map = inputs.resource_map_validation.canonical_map
    assert resource_map is not None
    plan = inputs.obligation_plan
    plan_pin = _artifact_pin(
        "taxonomy-obligation-plan", plan.schema_version, plan.semantic_digest
    )
    assessment_pin = _artifact_pin(
        "hybrid-coverage-assessment",
        inputs.phase2_assessment.schema_version,
        inputs.phase2_assessment.semantic_digest or "0" * 64,
    )
    resource_pin = _artifact_pin(
        "system-resource-map",
        resource_map.schema_version,
        resource_map.semantic_digest,
    )
    pins = (
        *_materialization_source_pins(material),
        *stpa.source_pins,
        _wrapper_source_pin(
            stpa, "pinned-stpa-projection-attestation", "stpa-attestation"
        ),
        *_review_source_pins(inputs.confirmed_reviews),
        *_bridge_source_pins(inputs.bridge_links),
        *_core_source_pins(
            inputs,
            plan_pin=plan_pin,
            assessment_pin=assessment_pin,
            resource_pin=resource_pin,
        ),
        *_taxonomy_source_pins(plan),
        *_closed_loop_source_pins(inputs.closed_loop_run),
    )
    return _canonical_source_pins(pins)


def _materialization_source_pins(
    material: CandidateMaterializationSet,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain materialization leaves, entries, and their set wrapper."""
    return (
        *material.source_pins,
        *(pin for entry in material.entries for pin in entry.source_pins),
        _wrapper_source_pin(
            material, "taxonomy-candidate-materialization-set", "materializations"
        ),
    )


def _review_source_pins(
    reviews: Sequence[ConfirmedCoverageReview],
) -> tuple[ProjectionSourcePin, ...]:
    """Retain every confirmed-review wrapper and independent evidence pin."""
    pins: list[ProjectionSourcePin] = []
    for review in reviews:
        pins.extend(review.source_pins)
        pins.extend(
            (
                _as_artifact_source_pin(review.review_artifact_pin, "review"),
                _as_artifact_source_pin(
                    review.mechanism_evidence.artifact_pin, "mechanism-evidence"
                ),
                _wrapper_source_pin(
                    review,
                    f"confirmed-coverage-review:{review.relation_id}",
                    "confirmed-review",
                ),
                _wrapper_source_pin(
                    review.mechanism_evidence,
                    f"mechanism-evidence-attestation:{review.relation_id}",
                    "mechanism-evidence",
                ),
            )
        )
    return tuple(pins)


def _bridge_source_pins(
    bridges: Sequence[BridgeLink],
) -> tuple[ProjectionSourcePin, ...]:
    """Retain bridge source declarations and exact evidence artifact pins."""
    return tuple(
        (
            *(pin for bridge in bridges for pin in bridge.source_pins),
            *(
                _as_artifact_source_pin(evidence.artifact_pin, "bridge-evidence")
                for bridge in bridges
                for evidence in bridge.evidence
            ),
        )
    )


def _core_source_pins(
    inputs: HybridProjectionInputs,
    *,
    plan_pin: ArtifactPin,
    assessment_pin: ArtifactPin,
    resource_pin: ArtifactPin,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain the plan, assessment, resource, and attestation authorities."""
    return (
        _wrapper_source_pin(
            inputs.capability_facts, "capability-fact-attestation", "capability-facts"
        ),
        _wrapper_source_pin(
            inputs.correspondence,
            "hybrid-correspondence-attestation",
            "correspondence-attestation",
        ),
        _as_artifact_source_pin(plan_pin, "obligation-plan"),
        _as_artifact_source_pin(assessment_pin, "phase2-assessment"),
        _as_artifact_source_pin(resource_pin, "resource-map"),
        _as_artifact_source_pin(inputs.correspondence.proposal_set_pin, "proposal-set"),
        _as_artifact_source_pin(
            inputs.correspondence.reconciliation_pin, "reconciliation"
        ),
        _as_artifact_source_pin(inputs.capability_facts.source_pin, "capability-facts"),
    )


def _taxonomy_source_pins(
    plan: TaxonomyObligationPlan,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain native catalog and mapping pins without changing their identity."""
    return tuple(
        [
            *(
                _as_taxonomy_source_pin(taxonomy_id, pin, "catalog")
                for taxonomy_id, pin in sorted(plan.catalog_pins.items())
            ),
            *(
                _as_taxonomy_source_pin(taxonomy_id, pin, "mapping")
                for taxonomy_id, pin in sorted(plan.mapping_pins.items())
            ),
        ]
    )


def _closed_loop_source_pins(
    run: ClosedLoopStpaRun | None,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain optional closed-loop history and its upstream source pins."""
    if run is None:
        return ()
    if run.semantic_digest is None:
        raise ValueError("closed-loop run must carry a semantic digest")
    return (
        _as_artifact_source_pin(
            _artifact_pin(
                "closed-loop-stpa-run", run.schema_version, run.semantic_digest
            ),
            "closed-loop-run",
        ),
        *(
            _as_artifact_source_pin(pin, "closed-loop-source")
            for pin in (*run.ledger.source_pins, run.ledger.assessment_pin)
        ),
    )


def _validate_closed_loop_history(
    run: Any,
    assessment: HybridCoverageAssessment,
    source_pins: Sequence[ProjectionSourcePin],
) -> None:
    """Validate optional Phase 3 history without using it as authority."""
    checked = _require_type(run, ClosedLoopStpaRun, "closed_loop_run")
    checked.assert_integrity()
    _validate_closed_loop_assessment_pin(checked, assessment)
    _validate_closed_loop_upstream_pins(checked, source_pins)


def _validate_closed_loop_assessment_pin(
    run: ClosedLoopStpaRun, assessment: HybridCoverageAssessment
) -> None:
    """Require closed-loop history to point at this exact assessment."""
    assessment_pin = _artifact_pin(
        "hybrid-coverage-assessment",
        assessment.schema_version,
        assessment.semantic_digest or "0" * 64,
    )
    if run.ledger.assessment_pin != assessment_pin:
        raise ValueError("closed-loop run assessment pin does not match inputs")


def _available_artifact_pins(
    source_pins: Sequence[ProjectionSourcePin],
) -> set[ArtifactPin]:
    """Index non-history artifact pins available to verify closed-loop inputs."""
    return {
        pin.pin
        for pin in source_pins
        if isinstance(pin, ArtifactProjectionSourcePin)
        and pin.role not in {"closed-loop-source", "closed-loop-run"}
    }


def _validate_closed_loop_upstream_pins(
    run: ClosedLoopStpaRun, source_pins: Sequence[ProjectionSourcePin]
) -> None:
    """Require every recorded closed-loop source to be in the input graph."""
    required = set(run.ledger.source_pins) | {run.ledger.assessment_pin}
    if not required.issubset(_available_artifact_pins(source_pins)):
        raise ValueError("closed-loop run upstream pins do not match inputs")


def _bridge_endpoint_is_local(
    bridge: BridgeLink,
    mechanism: MechanismProjection,
    causal: CausalProjection,
) -> bool:
    """Validate only local endpoint existence; Task 2 owns graph semantics."""
    return _taxonomy_endpoint_is_local(bridge, mechanism) and _stpa_endpoint_is_local(
        bridge, causal
    )


def _taxonomy_endpoint_is_local(
    bridge: BridgeLink, mechanism: MechanismProjection
) -> bool:
    """Check only the selected mechanism's exact step/pre/post IDs."""
    endpoint = bridge.taxonomy_endpoint
    return endpoint.record_id in _taxonomy_endpoint_ids(endpoint.kind, mechanism)


def _taxonomy_endpoint_ids(
    kind: str, mechanism: MechanismProjection
) -> tuple[str, ...]:
    """Return the selected mechanism IDs for one closed endpoint kind."""
    identifiers = {
        "mechanism_step": tuple(step.step_id for step in mechanism.steps),
        "mechanism_precondition": tuple(
            precondition.condition_id
            for step in mechanism.steps
            for precondition in step.preconditions
        ),
        "mechanism_postcondition": tuple(
            postcondition.postcondition_id
            for step in mechanism.steps
            for postcondition in step.observable_postconditions
        ),
    }
    return identifiers.get(kind, ())


def _stpa_endpoint_is_local(bridge: BridgeLink, causal: CausalProjection) -> bool:
    """Check an STPA endpoint against the causal projection's node kinds."""
    endpoint_kinds = {
        "control_action": {"control_action", "coordination_mechanism"},
    }.get(bridge.stpa_endpoint.kind, {bridge.stpa_endpoint.kind})
    return bridge.stpa_endpoint.record_id in {
        node.node_id for node in causal.nodes if node.kind in endpoint_kinds
    }


def _relation_rows(
    assessment: HybridCoverageAssessment,
) -> tuple[dict[str, ScenarioRealizationRow], dict[str, TaxonomyCorrespondenceRow]]:
    """Index the two Phase 2 rows used by Task 1 resolution."""
    return (
        {row.relation_id: row for row in assessment.scenario_realization},
        {row.obligation_id: row for row in assessment.taxonomy_correspondence},
    )


def _group_stpa_projections(
    projections: Sequence[CausalProjection],
) -> dict[tuple[str, str], list[CausalProjection]]:
    """Group causal projections while retaining every exact projection value."""
    grouped: dict[tuple[str, str], list[CausalProjection]] = {}
    for projection in projections:
        key = (projection.ica_id, projection.exec_candidate_id)
        grouped.setdefault(key, []).append(projection)
    return grouped


def _assert_resolution_authorities(inputs: HybridProjectionInputs) -> None:
    """Require every nested authority to come from its verified factory."""
    for value, name in (
        (inputs.capability_facts, "capability_facts"),
        (inputs.candidate_materializations, "candidate_materializations"),
        (inputs.correspondence, "correspondence"),
        (inputs.stpa_projection_authority, "stpa_projection_authority"),
    ):
        _assert_verified(value, name)
    for review in inputs.confirmed_reviews:
        _assert_verified(review, "confirmed_review")


def _assert_resolution_integrity(inputs: HybridProjectionInputs) -> None:
    """Validate all immutable source content before indexing it."""
    inputs.obligation_plan.assert_integrity()
    inputs.capability_facts.assert_integrity()
    inputs.candidate_materializations.assert_integrity()
    inputs.phase2_assessment.assert_integrity()
    inputs.correspondence.assert_integrity()
    inputs.stpa_projection_authority.assert_integrity()
    for bridge in inputs.bridge_links:
        bridge.assert_integrity()
    _validate_resource_map_attestation(inputs.resource_map_validation, None)


def _validate_resolution_pins(
    inputs: HybridProjectionInputs, resource_map: Any
) -> None:
    """Require capability, resource-map, STPA, and candidate pins to agree."""
    _validate_resolution_correspondence_authority(inputs, resource_map)
    plan = inputs.obligation_plan
    if (
        inputs.capability_facts.capability_snapshot_digest
        != plan.capability_snapshot_digest
        or resource_map.capability_snapshot_digest != plan.capability_snapshot_digest
    ):
        raise ValueError("capability snapshot authority does not match the plan")
    if (
        resource_map.control_structure_digest
        != inputs.stpa_projection_authority.control_structure_pin.semantic_digest
    ):
        raise ValueError("resource map/control structure authority does not match")
    plan_pin = _artifact_pin(
        "taxonomy-obligation-plan", plan.schema_version, plan.semantic_digest
    )
    if inputs.candidate_materializations.obligation_plan_pin != plan_pin:
        raise ValueError("candidate materialization set is pinned to another plan")


def _validate_resolution_correspondence_authority(
    inputs: HybridProjectionInputs, resource_map: Any
) -> None:
    """Bind the assessment and map to the exact Phase 2 factory inputs."""
    metadata = _correspondence_metadata(inputs.correspondence)
    if metadata is None:
        raise ValueError("correspondence authority metadata is unavailable")
    assessment_digest, expected_map_digest = metadata
    if inputs.phase2_assessment.semantic_digest != assessment_digest:
        raise ValueError("assessment authority does not match correspondence")
    if resource_map.semantic_digest != expected_map_digest:
        raise ValueError("resource map authority does not match correspondence")
    _require_assessment_source_pins(inputs, resource_map)
    _require_relation_resource_map_pins(inputs.correspondence, resource_map)
    _validate_resolution_assessment_rows(inputs)


def _require_assessment_source_pins(
    inputs: HybridProjectionInputs, resource_map: Any
) -> None:
    """Require the assessment to name the exact map and reconciliation pins."""
    expected = _expected_assessment_source_pins(inputs, resource_map)
    actual = _assessment_source_pins(inputs.phase2_assessment, expected)
    _require_matching_assessment_pins(actual, expected)


def _expected_assessment_source_pins(
    inputs: HybridProjectionInputs, resource_map: Any
) -> dict[str, ArtifactPin]:
    """Build the exact map and reconciliation pins required by the assessment."""
    return {
        "system-resource-map": _artifact_pin(
            "system-resource-map",
            resource_map.schema_version,
            resource_map.semantic_digest,
        ),
        "correspondence-reconciliation": _artifact_pin(
            "correspondence-reconciliation",
            inputs.correspondence.reconciliation_pin.schema_version,
            inputs.correspondence.reconciliation_digest,
        ),
    }


def _assessment_source_pins(
    assessment: HybridCoverageAssessment, expected: dict[str, ArtifactPin]
) -> dict[str, ArtifactPin]:
    """Select relevant source pins from one assessment without substitution."""
    return {
        pin.artifact_id: pin
        for pin in assessment.source_pins
        if pin.artifact_id in expected
    }


def _require_matching_assessment_pins(
    actual: dict[str, ArtifactPin], expected: dict[str, ArtifactPin]
) -> None:
    """Reject missing or substituted assessment source pins."""
    if actual != expected:
        raise ValueError("assessment authority pins do not match inputs")


def _require_relation_resource_map_pins(
    correspondence: HybridCorrespondenceAttestation, resource_map: Any
) -> None:
    """Require every retained relation to name the actual resource map."""
    expected = resource_map.semantic_digest
    if any(
        relation.source_pins.resource_map_semantic_digest != expected
        for relation in correspondence.accepted_relations
    ):
        raise ValueError("resource map authority does not match accepted relations")


def _validate_resolution_assessment_rows(inputs: HybridProjectionInputs) -> None:
    """Validate all relation rows before resolving any requested relation."""
    relation_rows, taxonomy_rows = _relation_rows(inputs.phase2_assessment)
    for relation in inputs.correspondence.accepted_relations:
        _validate_assessment_relation_rows(
            relation,
            relation_rows.get(relation.relation_id),
            taxonomy_rows.get(relation.obligation_id),
        )


def _resolution_context(inputs: HybridProjectionInputs) -> _ResolutionContext:
    """Build the validated indexes shared by all requested relations."""
    envelope = _require_type(inputs, HybridProjectionInputs, "inputs")
    _validate_resolution_envelope(envelope)
    resource_map = _resolution_resource_map(envelope)
    _validate_resolution_pins(envelope, resource_map)
    realization_rows, taxonomy_rows = _relation_rows(envelope.phase2_assessment)
    source_pins = _source_pins_for_inputs(envelope)
    _validate_optional_closed_loop(envelope, source_pins)
    return _build_resolution_context(
        envelope, resource_map, realization_rows, taxonomy_rows, source_pins
    )


def _validate_resolution_envelope(inputs: HybridProjectionInputs) -> None:
    """Validate factory provenance and content before building any indexes."""
    _assert_resolution_authorities(inputs)
    _assert_resolution_integrity(inputs)


def _resolution_resource_map(inputs: HybridProjectionInputs) -> Any:
    """Return the successful canonical resource map from the input envelope."""
    resource_map = inputs.resource_map_validation.canonical_map
    if resource_map is None:
        raise ValueError("system resource map validation must be successful")
    return resource_map


def _validate_optional_closed_loop(
    inputs: HybridProjectionInputs,
    source_pins: Sequence[ProjectionSourcePin],
) -> None:
    """Validate optional closed-loop history when the caller supplied it."""
    if inputs.closed_loop_run is not None:
        _validate_closed_loop_history(
            inputs.closed_loop_run,
            inputs.phase2_assessment,
            source_pins,
        )


def _build_resolution_context(
    envelope: HybridProjectionInputs,
    resource_map: Any,
    realization_rows: dict[str, ScenarioRealizationRow],
    taxonomy_rows: dict[str, TaxonomyCorrespondenceRow],
    source_pins: tuple[ProjectionSourcePin, ...],
) -> _ResolutionContext:
    """Build deterministic relation, candidate, STPA, and review indexes."""
    return _ResolutionContext(
        inputs=envelope,
        plan=envelope.obligation_plan,
        resource_links=_resource_link_index(resource_map),
        relation_by_id=_relation_index(envelope),
        materials=_materialization_index(envelope),
        stpa_by_identity=_stpa_identity_index(envelope),
        reviews=_review_index(envelope),
        realization_rows=realization_rows,
        taxonomy_rows=taxonomy_rows,
        plan_rows=_plan_row_index(envelope),
        source_pins=source_pins,
    )


def _resource_link_index(resource_map: Any) -> dict[str, Any]:
    """Index the exact resource links from the canonical map."""
    return {link.link_id: link for link in resource_map.links}


def _relation_index(
    envelope: HybridProjectionInputs,
) -> dict[str, AcceptedCorrespondenceRelation]:
    """Index each accepted correspondence relation by its exact ID."""
    return {
        relation.relation_id: relation
        for relation in envelope.correspondence.accepted_relations
    }


def _materialization_index(
    envelope: HybridProjectionInputs,
) -> dict[tuple[str, str], CandidateMaterialization]:
    """Index each materialization by its obligation/candidate identity."""
    return {
        (entry.obligation_id, entry.selected_candidate_id): entry
        for entry in envelope.candidate_materializations.entries
    }


def _stpa_identity_index(
    envelope: HybridProjectionInputs,
) -> dict[tuple[str, str], tuple[CausalProjection, ...]]:
    """Index STPA projections without collapsing shared ICA/EXEC pairs."""
    return {
        key: tuple(values)
        for key, values in _group_stpa_projections(
            envelope.stpa_projection_authority.projections
        ).items()
    }


def _review_index(
    envelope: HybridProjectionInputs,
) -> dict[str, ConfirmedCoverageReview]:
    """Index independently confirmed reviews by relation ID."""
    return {review.relation_id: review for review in envelope.confirmed_reviews}


def _plan_row_index(
    envelope: HybridProjectionInputs,
) -> dict[str, TaxonomyObligation]:
    """Index Phase 1 obligation rows by their exact obligation ID."""
    return {row.obligation_id: row for row in envelope.obligation_plan.obligations}


def _relation_authority_reason(
    relation: AcceptedCorrespondenceRelation,
    context: _ResolutionContext,
) -> str | None:
    """Return an exclusion reason for assessment or obligation authority."""
    try:
        _validate_assessment_relation_rows(
            relation,
            context.realization_rows.get(relation.relation_id),
            context.taxonomy_rows.get(relation.obligation_id),
        )
    except ValueError:
        return "relation_not_accepted"
    obligation = context.plan_rows.get(relation.obligation_id)
    if obligation is None or obligation.scope_disposition != "applicable":
        return "obligation_not_applicable"
    return None


def _materialization_matches(
    material: CandidateMaterialization,
    record: CandidateRecord,
    relation: AcceptedCorrespondenceRelation,
) -> bool:
    """Match materialization identity and complete mechanism bindings."""
    mechanism = material.mechanism_projection
    identity_matches = (
        material.phase1_candidate_record_digest,
        material.risk_id,
        material.attack_pattern_id,
        material.obligation_id,
    ) == (
        _candidate_record_digest(record),
        relation.risk_id,
        relation.attack_pattern_id,
        relation.obligation_id,
    )
    mechanism_matches = (
        mechanism.selected_candidate_id,
        mechanism.obligation_id,
        mechanism.risk_id,
        mechanism.attack_pattern_id,
        mechanism.canonical_ingress,
        mechanism.resource_bindings,
    ) == (
        relation.selected_candidate_id,
        relation.obligation_id,
        relation.risk_id,
        relation.attack_pattern_id,
        record.canonical_ingress,
        record.resource_bindings,
    )
    return identity_matches and mechanism_matches


def _materialization_for_relation(
    relation: AcceptedCorrespondenceRelation,
    obligation: TaxonomyObligation,
    context: _ResolutionContext,
) -> tuple[CandidateMaterialization | None, str | None]:
    """Resolve the selected Phase 1 candidate and its complete materialization."""
    selected = relation.selected_candidate_id
    if selected is None:
        return None, "candidate_materialization_missing"
    record = _candidate_record_for_relation(obligation, selected)
    material = context.materials.get((obligation.obligation_id, selected))
    if material is None or record is None:
        return None, "candidate_materialization_missing"
    return _validate_materialization_pair(material, record, relation, context)


def _validate_materialization_pair(
    material: CandidateMaterialization,
    record: CandidateRecord,
    relation: AcceptedCorrespondenceRelation,
    context: _ResolutionContext,
) -> tuple[CandidateMaterialization | None, str | None]:
    """Validate one candidate record/materialization pair and its links."""
    if record.projection_disposition != "projectable":
        return None, "candidate_not_projectable"
    if not _materialization_matches(material, record, relation):
        return None, "candidate_binding_mismatch"
    if _resource_link_mismatch(relation, material, context.resource_links):
        return None, "resource_link_mismatch"
    return material, None


def _candidate_record_for_relation(
    obligation: TaxonomyObligation, selected_candidate: str
) -> CandidateRecord | None:
    """Find the selected candidate record within its exact obligation row."""
    return next(
        (
            item
            for item in obligation.candidate_records
            if item.candidate_id == selected_candidate
        ),
        None,
    )


def _resource_link_mismatch(
    relation: AcceptedCorrespondenceRelation,
    material: CandidateMaterialization,
    resource_links: dict[str, Any],
) -> bool:
    """Require each relation resource link to resolve to this candidate's bindings."""
    bindings = material.mechanism_projection.resource_bindings
    return any(
        link_id not in resource_links
        or not any(
            resource_links[link_id].capability_resource_ref == binding.resource_ref
            for binding in bindings
        )
        for link_id in relation.resource_link_ids
    )


def _stpa_for_relation(
    relation: AcceptedCorrespondenceRelation,
    context: _ResolutionContext,
) -> tuple[CausalProjection | None, str | None]:
    """Resolve the exact STPA projection and cross-check relation identities."""
    candidates = context.stpa_by_identity.get(
        (relation.ica_id, relation.exec_candidate_id), ()
    )
    if not candidates:
        return None, "stpa_identity_missing"
    matching = _matching_stpa_projections(candidates, relation)
    if len(matching) != 1:
        return None, "stpa_identity_mismatch"
    return matching[0], None


def _matching_stpa_projections(
    candidates: Sequence[CausalProjection],
    relation: AcceptedCorrespondenceRelation,
) -> tuple[CausalProjection, ...]:
    """Filter shared ICA/EXEC projections by full slot/context identity."""
    expected = (
        relation.ica_slot_id,
        relation.ica_id,
        relation.exec_candidate_id,
        tuple(sorted(relation.hazard_ids)),
        tuple(sorted(relation.constraint_ids)),
    )
    return tuple(
        projection
        for projection in candidates
        if (
            projection.uca_slot_id,
            projection.ica_id,
            projection.exec_candidate_id,
            projection.hazard_ids,
            projection.constraint_ids,
        )
        == expected
    )


def _bridges_for_relation(
    relation: AcceptedCorrespondenceRelation,
    material: CandidateMaterialization,
    causal: CausalProjection,
    review: ConfirmedCoverageReview,
    context: _ResolutionContext,
) -> tuple[tuple[BridgeLink, ...], str | None]:
    """Resolve relation bridges and enforce local authority checks only."""
    bridges = tuple(
        link
        for link in context.inputs.bridge_links
        if link.relation_id == relation.relation_id
    )
    if not bridges:
        return (), "bridge_missing"
    for bridge in bridges:
        reason = _bridge_reason(bridge, material, causal, review, context)
        if reason is not None:
            return (), reason
    return bridges, None


def _bridge_reason(
    bridge: BridgeLink,
    material: CandidateMaterialization,
    causal: CausalProjection,
    review: ConfirmedCoverageReview,
    context: _ResolutionContext,
) -> str | None:
    """Return the first local bridge exclusion reason, if any."""
    if not _bridge_endpoint_is_local(bridge, material.mechanism_projection, causal):
        return "bridge_invalid_endpoint"
    if not bridge.is_authorized:
        return "bridge_unreviewed"
    if not _bridge_evidence_is_known(bridge, material, causal, context):
        return "bridge_not_authoritative"
    if _bridge_reuses_review_evidence(bridge, review):
        return "bridge_not_authoritative"
    return None


def _bridge_evidence_is_known(
    bridge: BridgeLink,
    material: CandidateMaterialization,
    causal: CausalProjection,
    context: _ResolutionContext,
) -> bool:
    """Resolve bridge evidence IDs against exact supplied authority records."""
    known = _known_bridge_records(material, causal, context)
    source_pins = {
        pin.pin
        for pin in bridge.source_pins
        if isinstance(pin, ArtifactProjectionSourcePin)
    }
    return all(
        _bridge_evidence_record_is_known(evidence, source_pins, known)
        for evidence in bridge.evidence
    )


def _bridge_evidence_record_is_known(
    evidence: Any,
    source_pins: set[ArtifactPin],
    known: dict[ArtifactPin, tuple[set[str], set[str]]],
) -> bool:
    """Check one bridge evidence record against its exact pin and namespace."""
    if evidence.artifact_pin not in source_pins:
        return False
    taxonomy, stpa = known.get(evidence.artifact_pin, (set(), set()))
    records = {
        "exact_taxonomy_record": taxonomy,
        "exact_stpa_record": stpa,
        "operator_bridge_review": taxonomy | stpa,
        "curated_bridge_mapping": taxonomy | stpa,
    }[evidence.evidence_kind]
    return evidence.record_id in records


def _known_bridge_records(
    material: CandidateMaterialization,
    causal: CausalProjection,
    context: _ResolutionContext,
) -> dict[ArtifactPin, tuple[set[str], set[str]]]:
    """Return exact taxonomy/STPA record IDs grouped by their artifact pin."""
    material_set = context.inputs.candidate_materializations
    material_pin = _artifact_pin(
        "taxonomy-candidate-materialization-set",
        material_set.schema_version,
        material_set.semantic_digest,
    )
    stpa_set = context.inputs.stpa_projection_authority
    stpa_pin = _artifact_pin(
        "pinned-stpa-projection-attestation",
        stpa_set.schema_version,
        stpa_set.semantic_digest,
    )
    return {
        material_pin: (_materialization_record_ids(material), set()),
        stpa_pin: (set(), _stpa_record_ids(causal)),
    }


def _materialization_record_ids(material: CandidateMaterialization) -> set[str]:
    """Return exact taxonomy record IDs available under one materialization."""
    steps = material.mechanism_projection.steps
    return {
        material.materialization_id,
        *(step.step_id for step in steps),
        *(
            precondition.condition_id
            for step in steps
            for precondition in step.preconditions
        ),
        *(
            postcondition.postcondition_id
            for step in steps
            for postcondition in step.observable_postconditions
        ),
    }


def _stpa_record_ids(causal: CausalProjection) -> set[str]:
    """Return exact STPA record IDs available under one causal projection."""
    return {causal.causal_projection_id, *(node.node_id for node in causal.nodes)}


def _bridge_reuses_review_evidence(
    bridge: BridgeLink, review: ConfirmedCoverageReview
) -> bool:
    """Detect bridge evidence that is not independent from the review."""
    forbidden = {review.review_artifact_pin, review.mechanism_evidence.artifact_pin}
    return any(evidence.artifact_pin in forbidden for evidence in bridge.evidence)


def _resolved_relation_parts(
    relation: AcceptedCorrespondenceRelation,
    obligation: TaxonomyObligation,
    context: _ResolutionContext,
) -> tuple[_ResolvedRelationParts | None, str | None]:
    """Resolve candidate, STPA, review, and bridge support for one relation."""
    material, reason = _materialization_for_relation(relation, obligation, context)
    if reason is not None or material is None:
        return None, reason
    causal, reason = _stpa_for_relation(relation, context)
    if reason is not None or causal is None:
        return None, reason
    return _resolve_review_and_bridges(relation, material, causal, context)


def _resolve_review_and_bridges(
    relation: AcceptedCorrespondenceRelation,
    material: CandidateMaterialization,
    causal: CausalProjection,
    context: _ResolutionContext,
) -> tuple[_ResolvedRelationParts | None, str | None]:
    """Resolve independent review and bridge support after core identities."""
    review = context.reviews.get(relation.relation_id)
    if review is None:
        return None, "relation_unresolved"
    bridges, reason = _bridges_for_relation(relation, material, causal, review, context)
    if reason is not None:
        return None, reason
    return _ResolvedRelationParts(material, causal, review, bridges), None


def _build_resolved_unit(
    relation: AcceptedCorrespondenceRelation,
    parts: _ResolvedRelationParts,
    context: _ResolutionContext,
) -> HybridProjectionUnit:
    """Build one unit after all exact authorities have passed."""
    return HybridProjectionUnit(
        relation_id=relation.relation_id,
        obligation_id=relation.obligation_id,
        risk_id=relation.risk_id,
        attack_pattern_id=relation.attack_pattern_id,
        selected_candidate_id=relation.selected_candidate_id,
        ica_slot_id=relation.ica_slot_id,
        ica_id=relation.ica_id,
        exec_candidate_id=relation.exec_candidate_id,
        relation_kind=relation.relation_kind,
        evidence_class=context.inputs.evidence_class,
        mechanism_projection=parts.materialization.mechanism_projection,
        causal_projection=parts.causal,
        confirmed_review=parts.review,
        bridge_links=parts.bridges,
        source_pins=context.source_pins,
    )


def _resolve_requested_relation(
    requested_id: str, context: _ResolutionContext
) -> tuple[AcceptedCorrespondenceRelation | None, HybridProjectionUnit | None, str]:
    """Resolve one requested relation or return its typed exclusion reason."""
    relation = context.relation_by_id.get(requested_id)
    if relation is None:
        return None, None, "relation_not_accepted"
    reason = _relation_authority_reason(relation, context)
    if reason is not None:
        return relation, None, reason
    if relation.relation_kind == "related_but_not_coverage":
        return relation, None, "relation_not_coverage"
    obligation = context.plan_rows[relation.obligation_id]
    return _resolve_coverage_relation(relation, obligation, context)


def _resolve_coverage_relation(
    relation: AcceptedCorrespondenceRelation,
    obligation: TaxonomyObligation,
    context: _ResolutionContext,
) -> tuple[AcceptedCorrespondenceRelation, HybridProjectionUnit | None, str]:
    """Resolve a coverage-bearing relation after its authority checks."""
    parts, reason = _resolved_relation_parts(relation, obligation, context)
    if reason is not None or parts is None:
        return relation, None, reason or "relation_not_accepted"
    return relation, _build_resolved_unit(relation, parts, context), ""


def _resolve_requested_relations(
    context: _ResolutionContext,
) -> tuple[tuple[HybridProjectionUnit, ...], tuple[ProjectionExclusion, ...]]:
    """Resolve all requested relations, retaining one exclusion per omission."""
    units: list[HybridProjectionUnit] = []
    exclusions: list[ProjectionExclusion] = []
    for requested_id in context.inputs.requested_relation_ids:
        relation, unit, reason = _resolve_requested_relation(requested_id, context)
        if unit is None:
            exclusions.append(
                _relation_exclusion(requested_id, relation, reason, context.source_pins)
            )
        else:
            units.append(unit)
    return tuple(units), tuple(exclusions)


def resolve_hybrid_projection_units(
    inputs: HybridProjectionInputs,
) -> HybridProjectionResolution:
    """Resolve exact accepted units without composing the combined graph."""
    context = _resolution_context(inputs)
    units, exclusions = _resolve_requested_relations(context)
    result = HybridProjectionResolution(
        assessment_digest=context.inputs.phase2_assessment.semantic_digest or "0" * 64,
        evidence_class=context.inputs.evidence_class,
        source_pins=context.source_pins,
        units=units,
        exclusions=exclusions,
        diagnostics=(),
    )
    result.assert_integrity()
    return result


def build_hybrid_scenario_projection_set(
    inputs: HybridProjectionInputs,
) -> HybridScenarioProjectionSet:
    """Compose resolved units into one closed in-memory projection set.

    Task 2 owns the composition boundary.  It first runs the Task 1 resolver,
    then creates one complete projection for each resolved relation.  No
    provider, network, persistence, or generation path is involved here.
    """
    envelope = _require_type(inputs, HybridProjectionInputs, "inputs")
    resolution = resolve_hybrid_projection_units(envelope)
    projections: list[HybridScenarioProjection] = []
    exclusions = list(resolution.exclusions)
    for unit in resolution.units:
        try:
            projections.append(_compose_projection(unit, envelope))
        except _CompositionFailure as failure:
            exclusions.append(
                _relation_exclusion(
                    unit.relation_id,
                    _relation_for_unit(unit, envelope),
                    failure.reason,
                    unit.source_pins,
                )
            )
    return HybridScenarioProjectionSet(
        assessment_digest=resolution.assessment_digest,
        source_pins=resolution.source_pins,
        projections=tuple(projections),
        exclusions=tuple(exclusions),
        diagnostics=resolution.diagnostics,
        evidence_class=resolution.evidence_class,
    )


def _compose_projection(
    unit: HybridProjectionUnit, inputs: HybridProjectionInputs
) -> HybridScenarioProjection:
    """Build one final projection from one already-authorized unit."""
    _validate_union_graph(unit)
    return HybridScenarioProjection(
        relation_id=unit.relation_id,
        obligation_id=unit.obligation_id,
        risk_id=unit.risk_id,
        attack_pattern_id=unit.attack_pattern_id,
        selected_candidate_id=unit.selected_candidate_id,
        ica_slot_id=unit.ica_slot_id,
        ica_id=unit.ica_id,
        exec_candidate_id=unit.exec_candidate_id,
        relation_kind=unit.relation_kind,
        evidence_class=unit.evidence_class,
        causal_projection=unit.causal_projection,
        mechanism_projection=unit.mechanism_projection,
        bridge_links=unit.bridge_links,
        confirmed_review=unit.confirmed_review,
        risk_trace=_projection_risk_trace(unit, inputs),
        source_pins=unit.source_pins,
    )


class _CompositionFailure(ValueError):
    """Internal relation-local graph failure with a closed exclusion reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _relation_for_unit(
    unit: HybridProjectionUnit, inputs: HybridProjectionInputs
) -> AcceptedCorrespondenceRelation | None:
    """Find the exact accepted relation retained by one resolved unit."""
    return next(
        (
            relation
            for relation in inputs.correspondence.accepted_relations
            if relation.relation_id == unit.relation_id
        ),
        None,
    )


_COMPOSITION_BRIDGE_KINDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "corrupts_process_model": (
        frozenset(
            {"mechanism_step", "mechanism_precondition", "mechanism_postcondition"}
        ),
        frozenset({"process_model"}),
    ),
    "delays_feedback": (
        frozenset({"mechanism_step", "mechanism_postcondition"}),
        frozenset({"feedback"}),
    ),
    "perturbs_control_action": (
        frozenset({"mechanism_step", "mechanism_postcondition"}),
        frozenset({"control_action"}),
    ),
    "enables_unsafe_action": (
        frozenset({"mechanism_step", "mechanism_postcondition"}),
        frozenset({"uca", "ica"}),
    ),
    "realizes_unsafe_outcome": (
        frozenset({"mechanism_step", "mechanism_postcondition"}),
        frozenset({"hazard", "loss"}),
    ),
}

_STPA_TARGET_ORDER: dict[str, tuple[str, ...]] = {
    "loss": (
        "hazard",
        "constraint",
        "controller",
        "coordination_link",
        "control_action",
        "coordination_mechanism",
        "uca",
        "ica",
        "exec",
    ),
    "hazard": (
        "constraint",
        "controller",
        "coordination_link",
        "control_action",
        "coordination_mechanism",
        "uca",
        "ica",
        "exec",
    ),
    "process_model": ("uca", "ica", "exec"),
    "feedback": ("control_action", "coordination_mechanism", "uca", "ica", "exec"),
    "control_action": ("uca", "ica", "exec"),
    "uca": ("ica", "exec"),
    "ica": ("exec",),
    "exec": (),
}


_GraphKey = tuple[str, str, str]
_GraphEdge = tuple[_GraphKey, _GraphKey, str]


def _validate_union_graph(unit: HybridProjectionUnit) -> None:
    """Validate both local graphs and their explicit taxonomy-to-STPA union."""
    unit.assert_integrity()
    taxonomy_nodes, taxonomy_edges = _taxonomy_graph(unit.mechanism_projection)
    stpa_nodes, stpa_edges = _stpa_graph(unit.causal_projection)
    edges: list[_GraphEdge] = [*taxonomy_edges, *stpa_edges]
    bridge_keys: set[tuple[_GraphKey, _GraphKey]] = set()
    authorized = False
    for bridge in unit.bridge_links:
        source, target = _validate_composition_bridge(
            bridge, taxonomy_nodes, stpa_nodes, unit.causal_projection
        )
        if not bridge.is_authorized:
            raise _CompositionFailure("bridge_unreviewed")
        authorized = True
        key = (source, target)
        if key in bridge_keys:
            raise _CompositionFailure("bridge_duplicate")
        bridge_keys.add(key)
        edges.append((source, target, "bridge"))
    if not authorized:
        raise _CompositionFailure("bridge_missing")
    _validate_unique_graph_edges(edges)
    _validate_acyclic_graph(edges)


def _taxonomy_graph(
    mechanism: MechanismProjection,
) -> tuple[dict[tuple[str, str], _GraphKey], tuple[_GraphEdge, ...]]:
    """Build typed taxonomy nodes and preserve canonical chain order."""
    steps = mechanism.steps
    nodes: dict[tuple[str, str], _GraphKey] = {}
    edges: list[_GraphEdge] = []
    for step in steps:
        step_key = _taxonomy_key("mechanism_step", step.step_id)
        nodes["mechanism_step", step.step_id] = step_key
        for precondition in step.preconditions:
            pre_key = _taxonomy_key("mechanism_precondition", precondition.condition_id)
            nodes["mechanism_precondition", precondition.condition_id] = pre_key
            edges.append((pre_key, step_key, "taxonomy"))
        for postcondition in step.observable_postconditions:
            post_key = _taxonomy_key(
                "mechanism_postcondition", postcondition.postcondition_id
            )
            nodes["mechanism_postcondition", postcondition.postcondition_id] = post_key
            edges.append((step_key, post_key, "taxonomy"))
    for previous, following in zip(steps, steps[1:], strict=False):
        edges.append(
            (
                _taxonomy_key("mechanism_step", previous.step_id),
                _taxonomy_key("mechanism_step", following.step_id),
                "taxonomy",
            )
        )
    return nodes, tuple(edges)


def _taxonomy_key(kind: str, record_id: str) -> _GraphKey:
    """Return a namespace-qualified taxonomy graph identity."""
    return ("taxonomy", kind, record_id)


def _stpa_graph(
    causal: CausalProjection,
) -> tuple[dict[tuple[str, str], _GraphKey], tuple[_GraphEdge, ...]]:
    """Copy exact STPA nodes and causal edges into the union namespace."""
    nodes_by_id = {node.node_id: node for node in causal.nodes}
    nodes = {
        (node.kind, node.node_id): ("stpa", node.kind, node.node_id)
        for node in causal.nodes
    }
    return nodes, tuple(_stpa_graph_edge(edge, nodes_by_id) for edge in causal.edges)


def _stpa_graph_edge(
    edge: CausalEdge, nodes_by_id: dict[str, CausalNode]
) -> _GraphEdge:
    """Translate one already-validated causal edge into union identities."""
    source = nodes_by_id[edge.from_node_id]
    target = nodes_by_id[edge.to_node_id]
    return (
        ("stpa", source.kind, source.node_id),
        ("stpa", target.kind, target.node_id),
        edge.kind,
    )


def _validate_composition_bridge(
    bridge: BridgeLink,
    taxonomy_nodes: dict[tuple[str, str], _GraphKey],
    stpa_nodes: dict[tuple[str, str], _GraphKey],
    causal: CausalProjection,
) -> tuple[_GraphKey, _GraphKey]:
    """Validate one exact endpoint-table bridge and its local order."""
    source_kind, target_kind = _validated_bridge_endpoint_kinds(bridge)
    source, target = _resolved_bridge_endpoints(
        bridge, source_kind, target_kind, taxonomy_nodes, stpa_nodes
    )
    target_node = _causal_node_for_key(causal, target)
    _validate_stpa_target_order(target_node, causal.nodes)
    return source, target


def _validated_bridge_endpoint_kinds(bridge: BridgeLink) -> tuple[str, str]:
    """Validate the bridge table before resolving either endpoint."""
    allowed = _COMPOSITION_BRIDGE_KINDS.get(bridge.bridge_kind)
    if allowed is None:
        raise _CompositionFailure("bridge_invalid_endpoint")
    source_kind = bridge.taxonomy_endpoint.kind
    target_kind = bridge.stpa_endpoint.kind
    if source_kind not in allowed[0] or target_kind not in allowed[1]:
        raise _CompositionFailure("bridge_invalid_endpoint")
    return source_kind, target_kind


def _resolved_bridge_endpoints(
    bridge: BridgeLink,
    source_kind: str,
    target_kind: str,
    taxonomy_nodes: dict[tuple[str, str], _GraphKey],
    stpa_nodes: dict[tuple[str, str], _GraphKey],
) -> tuple[_GraphKey, _GraphKey]:
    """Resolve the exact namespace-qualified endpoints from the table."""
    source = taxonomy_nodes.get((source_kind, bridge.taxonomy_endpoint.record_id))
    target = stpa_nodes.get((target_kind, bridge.stpa_endpoint.record_id))
    if source is None or target is None:
        raise _CompositionFailure("bridge_invalid_endpoint")
    return source, target


def _causal_node_for_key(causal: CausalProjection, key: _GraphKey) -> CausalNode:
    """Return the exact causal node represented by a namespaced graph key."""
    for node in causal.nodes:
        if node.kind == key[1] and node.node_id == key[2]:
            return node
    raise _CompositionFailure("bridge_invalid_endpoint")


def _validate_stpa_target_order(
    target: CausalNode, nodes: Sequence[CausalNode]
) -> None:
    """Require a bridged STPA target to precede its authority descendants."""
    required_followers = _STPA_TARGET_ORDER.get(target.kind, ())
    if any(
        target.ordinal >= node.ordinal
        for node in nodes
        if node.kind in required_followers
    ):
        raise _CompositionFailure("ordering_violation")


def _stpa_target_key(
    nodes: dict[tuple[str, str], _GraphKey], endpoint: Any
) -> _GraphKey | None:
    """Resolve a typed STPA endpoint without crossing namespaces."""
    return nodes.get((endpoint.kind, endpoint.record_id))


def _validate_unique_graph_edges(edges: Sequence[_GraphEdge]) -> None:
    """Reject duplicate semantic edges in the composed graph."""
    keys = {(source, target) for source, target, _kind in edges}
    if len(keys) != len(edges):
        raise _CompositionFailure("bridge_duplicate")


def _validate_acyclic_graph(edges: Sequence[_GraphEdge]) -> None:
    """Reject a cycle in the namespace-qualified union graph."""
    adjacency: dict[_GraphKey, list[_GraphKey]] = {}
    for source, target, _kind in edges:
        adjacency.setdefault(source, []).append(target)
    visiting: set[_GraphKey] = set()
    visited: set[_GraphKey] = set()
    for node in adjacency:
        _visit_union_node(node, adjacency, visiting, visited)


def _visit_union_node(
    node: _GraphKey,
    adjacency: dict[_GraphKey, list[_GraphKey]],
    visiting: set[_GraphKey],
    visited: set[_GraphKey],
) -> None:
    """Depth-first visit used by the union cycle guard."""
    if node in visiting:
        raise _CompositionFailure("ordering_cycle")
    if node in visited:
        return
    visiting.add(node)
    for child in adjacency.get(node, ()):
        _visit_union_node(child, adjacency, visiting, visited)
    visiting.remove(node)
    visited.add(node)


def _projection_risk_trace(
    unit: HybridProjectionUnit, inputs: HybridProjectionInputs
) -> tuple[ProjectionTraceReference, ...]:
    """Retain exact source records that explain one composed projection."""
    plan = inputs.obligation_plan
    materializations = inputs.candidate_materializations
    stpa = inputs.stpa_projection_authority
    plan_pin = _artifact_pin(
        "taxonomy-obligation-plan", plan.schema_version, plan.semantic_digest
    )
    materialization_pin = _artifact_pin(
        "taxonomy-candidate-materialization-set",
        materializations.schema_version,
        materializations.semantic_digest,
    )
    traces: list[ProjectionTraceReference] = [
        ProjectionTraceReference(
            source_kind="phase1_obligation",
            record_id=unit.obligation_id,
            artifact_pin=plan_pin,
        ),
        ProjectionTraceReference(
            source_kind="phase1_candidate",
            record_id=unit.selected_candidate_id,
            artifact_pin=materialization_pin,
        ),
        ProjectionTraceReference(
            source_kind="phase2_relation",
            record_id=unit.relation_id,
            artifact_pin=inputs.correspondence.reconciliation_pin,
        ),
    ]
    traces.extend(
        ProjectionTraceReference(
            source_kind="stpa_loss",
            record_id=record_id,
            artifact_pin=stpa.loss_analysis_pin,
        )
        for record_id in unit.causal_projection.loss_ids
    )
    traces.extend(
        ProjectionTraceReference(
            source_kind="stpa_hazard",
            record_id=record_id,
            artifact_pin=stpa.loss_analysis_pin,
        )
        for record_id in unit.causal_projection.hazard_ids
    )
    traces.extend(
        ProjectionTraceReference(
            source_kind="stpa_constraint",
            record_id=record_id,
            artifact_pin=stpa.loss_analysis_pin,
        )
        for record_id in unit.causal_projection.constraint_ids
    )
    traces.extend(
        (
            ProjectionTraceReference(
                source_kind="stpa_slot",
                record_id=unit.ica_slot_id,
                artifact_pin=stpa.ica_enumeration_pin,
            ),
            ProjectionTraceReference(
                source_kind="stpa_ica",
                record_id=unit.ica_id,
                artifact_pin=stpa.ica_enumeration_pin,
            ),
            ProjectionTraceReference(
                source_kind="stpa_exec",
                record_id=unit.exec_candidate_id,
                artifact_pin=stpa.execution_projection_pin,
            ),
        )
    )
    traces.extend(
        ProjectionTraceReference(
            source_kind="bridge_evidence",
            record_id=evidence.evidence_id,
            artifact_pin=evidence.artifact_pin,
        )
        for bridge in unit.bridge_links
        for evidence in bridge.evidence
    )
    return tuple(traces)


__all__ = [
    "PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN",
    "STPA_EXECUTION_PROJECTION_DIGEST_DOMAIN",
    "build_candidate_materialization_set",
    "build_confirmed_coverage_review",
    "build_hybrid_correspondence_attestation",
    "build_hybrid_scenario_projection_set",
    "build_pinned_stpa_projection_attestation",
    "candidate_materialization_set_from_artifacts",
    "capability_fact_attestation_from_artifacts",
    "compute_candidate_record_digest",
    "confirmed_coverage_review_from_artifacts",
    "hybrid_correspondence_attestation_from_artifacts",
    "mechanism_evidence_attestation_from_artifacts",
    "pinned_stpa_projection_attestation_from_artifacts",
    "resolve_hybrid_projection_units",
]
