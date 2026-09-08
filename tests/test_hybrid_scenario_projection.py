"""Contract tests for the Phase 4 Task 1 authority boundary."""

from __future__ import annotations

from types import SimpleNamespace
import weakref

import pytest
import asago_scenario_generator.models.hybrid_scenario_projection as projection_models
import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyPin
from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
    ProposalSet,
    ReviewedCorrespondenceAdjudications,
    ReviewedCorrespondenceDecision,
)
from asago_scenario_generator.models.challenge_ledger import (
    ChallengeLedgerDiagnostics,
    StpaChallengeLedger,
)
from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    BridgeAuthorityIdentity,
    BridgeEvidence,
    BridgeLink,
    CausalEdge,
    CausalNode,
    CausalProjection,
    CapabilityFactAttestation,
    ProjectionDiagnostic,
    ProjectionExclusion,
    StpaEndpoint,
    TaxonomyEndpoint,
    TaxonomyProjectionSourcePin,
    _causal_trace_kinds,
    _complete_stpa_source_pins,
    _has_control_action_trace,
    _identity_kinds_for_group,
    _require_causal_identity_group,
    _require_single_exec_node,
    _validate_causal_edge,
    _validate_bridge_authority,
    _visit_acyclic,
    _require_terminal_exec,
)
from asago_scenario_generator.models.system_resource_map import ResourceLink
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    _checked_pin,
    _context_sets_for_ica,
    _causal_edge_specs,
    _derive_stpa_projections,
    _correspondence_pins,
    _materialization_matches,
    _nodes_from_specs,
    _require_candidate_sequence,
    _require_context_members,
    _require_edge_order,
    _require_sequence,
    _relation_authority_reason,
    _resolve_coverage_relation,
    _resolved_relation_parts,
    _unit_identity,
    _causal_slot_for_relation,
    _validate_causal_controller_id,
    _require_known_context_ids,
    _StpaSources,
    _validate_loss_context,
    build_candidate_materialization_set,
    build_confirmed_coverage_review,
    build_hybrid_correspondence_attestation,
    build_pinned_stpa_projection_attestation,
    capability_fact_attestation_from_artifacts,
    mechanism_evidence_attestation_from_artifacts,
    resolve_hybrid_projection_units,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
)
from asago_scenario_generator.stpa.models.control_structure import (
    CoordinationLink,
    CoordinationMechanism,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.helpers.obligation_factory import make_inputs
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot
from tests.system_resource_map_support import make_control_structure, make_map


def _task1_authority_fixture(control_structure_override=None) -> tuple[object, ...]:
    """Build one complete Task 1 graph through current public model seams."""
    plan_inputs = make_inputs()
    plan = plan_taxonomy_obligations(plan_inputs)
    candidate = get_projected_candidate()
    snapshot = get_test_snapshot()
    control_structure = control_structure_override
    if control_structure is None:
        control_structure = make_control_structure()
        control_structure.responsibilities[0].security_constraint_refs = ["SC-1"]
    resource_map = make_map(
        ResourceLink(
            link_id="srm:v1:assessment-link",
            capability_resource_ref={
                "kind": "tool",
                "tool_id": snapshot.profile.tool_inventory[0].tool_id,
            },
            control_structure_ref={"kind": "CA", "id": "CA-1-1"},
            relation_kind="acts_on",
            provenance="operator_declared",
            evidence_refs=("review:assessment-link",),
            confidence=1.0,
            authority_status="authoritative",
        ),
        snapshot=snapshot,
        control=control_structure,
    )
    resource_map_validation = validate_system_resource_map(
        resource_map, snapshot, control_structure
    )

    # The correspondence helper supplies typed authority and exact rows.  The
    # selected candidate is the complete ProjectedCandidate, never its ID.
    from tests.test_hybrid_coverage_assessment import (
        _proposal_set,
        _stpa_input,
        _taxonomy_input,
    )

    proposal_set, _ = _proposal_set(plan, resource_map_validation)
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        resource_map_validation,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="reviewed exact identities",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map_validation,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    relation = reconciliation.accepted_relations[0]

    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Unauthorized payment",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-a"],
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="Payment is authorized without the required control",
                related_losses=["L-1"],
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Payments require the control action",
                related_hazards=["H-1"],
            ),
        ),
    )
    slot_id = "RESP-1:CA-1-1:WRONG_TIMING"
    ica_id = slot_id + ":1"
    exec_id = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    enumeration = ICAEnumeration(
        slots=(
            ICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=(
                    ICA(
                        ica_id=ica_id,
                        ica_text="Authorizes the payment at the wrong time",
                        hazardous_context="The payment is pending",
                        loss_scenario="The payment bypasses the required control",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    ),
                ),
            ),
        ),
    )
    execution = CandidateExecutionEnvelope(
        candidate_id=exec_id,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        control_action_description="Authorize payment",
        uca_type=UCAType.wrong_timing,
        uca_ref=slot_id,
        ica_id=ica_id,
    )
    capability = capability_fact_attestation_from_artifacts(
        snapshot, plan, resource_map_validation
    )
    materializations = build_candidate_materialization_set(plan, (candidate,), snapshot)
    correspondence = build_hybrid_correspondence_attestation(
        proposal_set, reconciliation, assessment
    )
    stpa = build_pinned_stpa_projection_attestation(
        loss_analysis,
        control_structure,
        enumeration,
        (execution,),
        (relation,),
    )
    reviewed = ReviewedCorrespondenceAdjudications.create(
        packet_digest="a" * 64,
        proposal_set_semantic_digest=proposal_set.semantic_digest,
        decisions=(
            ReviewedCorrespondenceDecision(
                proposal_id=proposal.proposal_id,
                relation_kind="same_mechanism",
                status="confirmed",
                reason="reviewed exact mechanism",
                adjudicated_by="operator-1",
            ),
        ),
    )
    mechanism_evidence = mechanism_evidence_attestation_from_artifacts(
        proposal_set,
        proposal.proposal_id,
        "exact_id",
    )
    review = build_confirmed_coverage_review(reviewed, relation, mechanism_evidence)
    bridge_evidence = BridgeEvidence(
        artifact_pin=ArtifactPin(
            artifact_id="taxonomy-candidate-materialization-set",
            schema_version=materializations.schema_version,
            semantic_digest=materializations.semantic_digest,
        ),
        record_id="step.1",
        evidence_kind="operator_bridge_review",
        provenance="operator_declared",
        authority_identity=BridgeAuthorityIdentity(kind="reviewer", id="operator-1"),
        rationale="The mechanism step perturbs the exact control action.",
    )
    bridge = BridgeLink(
        relation_id=relation.relation_id,
        bridge_kind="perturbs_control_action",
        taxonomy_endpoint=TaxonomyEndpoint(kind="mechanism_step", record_id="step.1"),
        stpa_endpoint=StpaEndpoint(kind="control_action", record_id="CA-1-1"),
        evidence=(bridge_evidence,),
        source_pins=(
            ArtifactProjectionSourcePin.from_artifact_pin(
                bridge_evidence.artifact_pin, role="bridge-evidence"
            ),
        ),
    )
    from asago_scenario_generator.models.hybrid_projection_inputs import (
        HybridProjectionInputs,
    )

    inputs = HybridProjectionInputs(
        obligation_plan=plan,
        capability_facts=capability,
        candidate_materializations=materializations,
        phase2_assessment=assessment,
        correspondence=correspondence,
        resource_map_validation=resource_map_validation,
        stpa_projection_authority=stpa,
        confirmed_reviews=(review,),
        bridge_links=(bridge,),
        requested_relation_ids=(relation.relation_id,),
        evidence_class="normative_bookkeeping_fixture",
    )
    return inputs, relation, candidate


_RELATION = "correlation:v1:" + "1" * 64
_OBLIGATION = "ob:v1:" + "2" * 64
_CANDIDATE = "cand:v2:" + "3" * 32
_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_ICA = _SLOT + ":1"
_EXEC = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"


def _causal(**changes: object) -> CausalProjection:
    """Build the smallest valid loss-to-EXEC projection."""
    payload: dict[str, object] = {
        "loss_ids": ("L-1",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "controller_id": "RESP-1",
        "control_action_id": "CA-1-1",
        "uca_slot_id": _SLOT,
        "ica_id": _ICA,
        "exec_candidate_id": _EXEC,
        "nodes": (
            CausalNode(node_id="L-1", kind="loss", ordinal=0),
            CausalNode(node_id="H-1", kind="hazard", ordinal=1),
            CausalNode(node_id="SC-1", kind="constraint", ordinal=2),
            CausalNode(node_id="RESP-1", kind="controller", ordinal=3),
            CausalNode(node_id="CA-1-1", kind="control_action", ordinal=4),
            CausalNode(node_id=_SLOT, kind="uca", ordinal=5),
            CausalNode(node_id=_ICA, kind="ica", ordinal=6),
            CausalNode(node_id=_EXEC, kind="exec", ordinal=7),
        ),
        "edges": (
            CausalEdge(
                edge_id="edge-1",
                from_node_id="L-1",
                to_node_id="H-1",
                kind="projection",
            ),
            CausalEdge(
                edge_id="edge-2",
                from_node_id="H-1",
                to_node_id="SC-1",
                kind="projection",
            ),
            CausalEdge(
                edge_id="edge-3",
                from_node_id="SC-1",
                to_node_id="RESP-1",
                kind="projection",
            ),
            CausalEdge(
                edge_id="edge-4",
                from_node_id="RESP-1",
                to_node_id="CA-1-1",
                kind="control",
            ),
            CausalEdge(
                edge_id="edge-5",
                from_node_id="CA-1-1",
                to_node_id=_SLOT,
                kind="control",
            ),
            CausalEdge(
                edge_id="edge-6", from_node_id=_SLOT, to_node_id=_ICA, kind="projection"
            ),
            CausalEdge(
                edge_id="edge-7", from_node_id=_ICA, to_node_id=_EXEC, kind="projection"
            ),
        ),
    }
    payload.update(changes)
    return CausalProjection.model_validate(payload)


def _artifact_pin(name: str = "source") -> ArtifactPin:
    return ArtifactPin(
        artifact_id=name,
        schema_version="v1",
        semantic_digest="a" * 64,
    )


def test_closed_causal_projection_computes_and_checks_digest() -> None:
    projection = _causal()

    assert projection.causal_projection_id.startswith("causal:v1:")
    assert len(projection.semantic_digest) == 64
    projection.assert_integrity()


def test_causal_projection_rejects_wrong_kind_and_dangling_edges() -> None:
    with pytest.raises(ValidationError, match="invalid source/target kind"):
        _causal(
            edges=(
                CausalEdge(
                    edge_id="edge-1",
                    from_node_id="L-1",
                    to_node_id="SC-1",
                    kind="projection",
                ),
            )
        )

    with pytest.raises(ValidationError, match="dangling node"):
        _causal(
            edges=(
                CausalEdge(
                    edge_id="edge-1",
                    from_node_id="L-1",
                    to_node_id="missing",
                    kind="projection",
                ),
            )
        )


def test_causal_projection_requires_a_terminal_exec_and_complete_trace() -> None:
    with pytest.raises(ValidationError, match="structural"):
        _causal(nodes=tuple(node for node in _causal().nodes if node.kind != "exec"))

    with pytest.raises(ValidationError, match="complete loss-to-exec"):
        _causal(
            edges=tuple(edge for edge in _causal().edges if edge.to_node_id != _ICA)
        )


@pytest.mark.parametrize(
    ("field_name", "node"),
    (
        ("loss_ids", CausalNode(node_id="L-2", kind="loss", ordinal=8)),
        ("hazard_ids", CausalNode(node_id="H-2", kind="hazard", ordinal=8)),
        (
            "constraint_ids",
            CausalNode(node_id="SC-2", kind="constraint", ordinal=8),
        ),
    ),
)
def test_causal_projection_rejects_disconnected_declared_context(
    field_name: str, node: CausalNode
) -> None:
    """Every declared loss, hazard, and constraint must join the path."""
    projection = _causal()
    payload = projection.model_dump(mode="python")
    payload[field_name] = (*payload[field_name], node.node_id)
    payload["nodes"] = (*projection.nodes, node)
    payload["causal_projection_id"] = ""
    payload["semantic_digest"] = None

    with pytest.raises(ValidationError, match="declared.*causal path"):
        CausalProjection.model_validate(payload)


def test_causal_projection_allows_multiple_context_branches() -> None:
    """Multiple declared contexts may share downstream structural nodes."""
    base = _causal()
    payload = base.model_dump(mode="python")
    payload.update(
        {
            "loss_ids": ("L-1", "L-2"),
            "hazard_ids": ("H-1", "H-2"),
            "constraint_ids": ("SC-1", "SC-2"),
            "nodes": (
                CausalNode(node_id="L-1", kind="loss", ordinal=0),
                CausalNode(node_id="L-2", kind="loss", ordinal=1),
                CausalNode(node_id="H-1", kind="hazard", ordinal=2),
                CausalNode(node_id="H-2", kind="hazard", ordinal=3),
                CausalNode(node_id="SC-1", kind="constraint", ordinal=4),
                CausalNode(node_id="SC-2", kind="constraint", ordinal=5),
                CausalNode(node_id="RESP-1", kind="controller", ordinal=6),
                CausalNode(node_id="CA-1-1", kind="control_action", ordinal=7),
                CausalNode(node_id=_SLOT, kind="uca", ordinal=8),
                CausalNode(node_id=_ICA, kind="ica", ordinal=9),
                CausalNode(node_id=_EXEC, kind="exec", ordinal=10),
            ),
            "edges": (
                CausalEdge(
                    edge_id="edge-1",
                    from_node_id="L-1",
                    to_node_id="H-1",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-2",
                    from_node_id="L-2",
                    to_node_id="H-2",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-3",
                    from_node_id="H-1",
                    to_node_id="SC-1",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-4",
                    from_node_id="H-2",
                    to_node_id="SC-2",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-5",
                    from_node_id="SC-1",
                    to_node_id="RESP-1",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-6",
                    from_node_id="SC-2",
                    to_node_id="RESP-1",
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-7",
                    from_node_id="RESP-1",
                    to_node_id="CA-1-1",
                    kind="control",
                ),
                CausalEdge(
                    edge_id="edge-8",
                    from_node_id="CA-1-1",
                    to_node_id=_SLOT,
                    kind="control",
                ),
                CausalEdge(
                    edge_id="edge-9",
                    from_node_id=_SLOT,
                    to_node_id=_ICA,
                    kind="projection",
                ),
                CausalEdge(
                    edge_id="edge-10",
                    from_node_id=_ICA,
                    to_node_id=_EXEC,
                    kind="projection",
                ),
            ),
            "causal_projection_id": "",
            "semantic_digest": None,
        }
    )

    result = CausalProjection.model_validate(payload)
    assert result.loss_ids == ("L-1", "L-2")
    assert result.hazard_ids == ("H-1", "H-2")
    assert result.constraint_ids == ("SC-1", "SC-2")


def test_taxonomy_source_pin_preserves_native_release_and_digest() -> None:
    taxonomy_pin = TaxonomyPin(release="2026.1", digest="b" * 64)
    wrapped = TaxonomyProjectionSourcePin(
        role="mapping", taxonomy_id="ATLAS", pin=taxonomy_pin
    )

    assert wrapped.release == "2026.1"
    assert wrapped.digest == "b" * 64
    assert wrapped.as_taxonomy_pin() == taxonomy_pin
    with pytest.raises(ValidationError):
        ArtifactProjectionSourcePin.model_validate(wrapped.model_dump(mode="json"))


def test_bridge_evidence_requires_matching_authority_kind() -> None:
    with pytest.raises(ValidationError, match="curator"):
        BridgeEvidence(
            artifact_pin=_artifact_pin("bridge"),
            record_id="step-1",
            evidence_kind="curated_bridge_mapping",
            provenance="curated",
            authority_identity=BridgeAuthorityIdentity(kind="reviewer", id="r-1"),
            rationale="reviewed mapping",
        )


def test_exclusion_is_closed_and_retains_exact_unit_identity() -> None:
    exclusion = ProjectionExclusion(
        relation_id=_RELATION,
        unit_identity=(_RELATION, _OBLIGATION, _CANDIDATE, _ICA, _EXEC),
        reason="bridge_missing",
    )

    assert exclusion.reason == "bridge_missing"
    assert exclusion.unit_identity[0] == exclusion.relation_id
    with pytest.raises(ValidationError):
        ProjectionExclusion(
            relation_id=_RELATION,
            unit_identity=(_RELATION, _OBLIGATION, _CANDIDATE, _ICA, _EXEC),
            reason="not-a-reason",
        )


def test_closed_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        CausalNode(node_id="x", kind="loss", ordinal=0, prose="not authority")


def test_bridge_link_keeps_typed_endpoint_and_source_pin_shapes() -> None:
    evidence = BridgeEvidence(
        artifact_pin=_artifact_pin("bridge"),
        record_id="step-1",
        evidence_kind="operator_bridge_review",
        provenance="operator_declared",
        authority_identity=BridgeAuthorityIdentity(kind="reviewer", id="r-1"),
        rationale="reviewed mapping",
    )
    link = BridgeLink(
        relation_id=_RELATION,
        bridge_kind="perturbs_control_action",
        taxonomy_endpoint=TaxonomyEndpoint(kind="mechanism_step", record_id="step-1"),
        stpa_endpoint={"kind": "control_action", "record_id": "CA-1-1"},
        evidence=(evidence,),
        source_pins=(
            ArtifactProjectionSourcePin.from_artifact_pin(_artifact_pin("bridge")),
        ),
    )

    assert link.is_authorized
    assert link.taxonomy_endpoint.namespace == "taxonomy"


def test_public_authority_resolver_emits_one_exact_normative_unit() -> None:
    """A complete Phase 1/2/STPA graph resolves through the public seam."""
    inputs, relation, candidate = _task1_authority_fixture()

    resolved = resolve_hybrid_projection_units(inputs)

    assert len(resolved.units) == 1
    unit = resolved.units[0]
    assert (
        unit.relation_id,
        unit.obligation_id,
        unit.selected_candidate_id,
        unit.ica_id,
        unit.exec_candidate_id,
    ) == (
        relation.relation_id,
        relation.obligation_id,
        candidate.candidate_id,
        relation.ica_id,
        relation.exec_candidate_id,
    )
    assert resolved.exclusions == ()


def test_resolver_retains_relation_local_missing_materialization_exclusion() -> None:
    """An intact plan with no selected materialization excludes one relation."""
    inputs, relation, _candidate = _task1_authority_fixture()
    empty_materializations = build_candidate_materialization_set(
        inputs.obligation_plan,
        (),
        get_test_snapshot(),
    )
    reduced = inputs.model_copy(
        update={
            "candidate_materializations": empty_materializations,
            "bridge_links": (),
        }
    )

    resolved = resolve_hybrid_projection_units(reduced)

    assert resolved.units == ()
    assert [(item.relation_id, item.reason) for item in resolved.exclusions] == [
        (relation.relation_id, "candidate_materialization_missing")
    ]


def test_resolver_retains_relation_local_missing_bridge_exclusion() -> None:
    """A relation without an explicit bridge is not silently emitted."""
    inputs, relation, _candidate = _task1_authority_fixture()
    reduced = inputs.model_copy(update={"bridge_links": ()})

    resolved = resolve_hybrid_projection_units(reduced)

    assert resolved.units == ()
    assert [(item.relation_id, item.reason) for item in resolved.exclusions] == [
        (relation.relation_id, "bridge_missing")
    ]


def test_resolver_rejects_recomputed_valid_resource_map_substitution() -> None:
    """A valid map with new content cannot replace the attested map."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    original_link = inputs.resource_map_validation.canonical_map.links[0]
    substituted_link = original_link.model_copy(
        update={"link_id": "srm:v1:substituted-map-link"}
    )
    substituted_map = make_map(
        substituted_link,
        snapshot=get_test_snapshot(),
        control=make_control_structure(),
    )
    substituted_validation = validate_system_resource_map(
        substituted_map,
        get_test_snapshot(),
        make_control_structure(),
    )
    assert substituted_validation.is_valid
    assert substituted_map.semantic_digest != (
        inputs.resource_map_validation.canonical_map.semantic_digest
    )

    with pytest.raises(ValueError, match="resource map authority"):
        resolve_hybrid_projection_units(
            inputs.model_copy(
                update={"resource_map_validation": substituted_validation}
            )
        )


def test_resolver_rejects_recomputed_valid_assessment_substitution() -> None:
    """An intact assessment from another identity is a fatal top-level mismatch."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    substituted = inputs.phase2_assessment.model_validate(
        {
            **inputs.phase2_assessment.model_dump(mode="python"),
            "structural_inventory_status": "partial",
            "semantic_digest": None,
        }
    )
    assert substituted.semantic_digest != inputs.phase2_assessment.semantic_digest

    with pytest.raises(ValueError, match="assessment authority"):
        resolve_hybrid_projection_units(
            inputs.model_copy(update={"phase2_assessment": substituted})
        )


def test_resolver_rejects_tampered_bridge_before_relation_resolution() -> None:
    """Bridge digest tampering is fatal, rather than a relation exclusion."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    tampered = inputs.bridge_links[0].model_copy(update={"semantic_digest": "0" * 64})

    with pytest.raises(ValueError, match="bridge link.*semantic"):
        resolve_hybrid_projection_units(
            inputs.model_copy(update={"bridge_links": (tampered,)})
        )


def test_resolver_rejects_raw_or_unverified_authority_substitution() -> None:
    """The input and verified attestation boundaries cannot be bypassed."""
    inputs, _relation, _candidate = _task1_authority_fixture()

    with pytest.raises(TypeError, match="inputs must be a HybridProjectionInputs"):
        resolve_hybrid_projection_units(inputs.model_dump(mode="python"))

    direct_capability = CapabilityFactAttestation(
        capability_snapshot_digest=inputs.capability_facts.capability_snapshot_digest,
        qualification_facts_digest=inputs.capability_facts.qualification_facts_digest,
        source_pin=inputs.capability_facts.source_pin,
    )
    substituted = inputs.model_copy(update={"capability_facts": direct_capability})
    with pytest.raises(ValueError, match="verified artifact factory"):
        resolve_hybrid_projection_units(substituted)


def test_resolver_rejects_verified_materialization_from_another_plan() -> None:
    """A separately verified candidate set remains bound to its Phase 1 plan."""
    inputs, _relation, candidate = _task1_authority_fixture()
    other_plan = plan_taxonomy_obligations(make_inputs(risk_ids=("risk-b",)))
    other_materializations = build_candidate_materialization_set(
        other_plan,
        (candidate,),
        get_test_snapshot(),
    )

    substituted = inputs.model_copy(
        update={"candidate_materializations": other_materializations}
    )
    with pytest.raises(ValueError, match="pinned to another plan"):
        resolve_hybrid_projection_units(substituted)


def test_resolver_rejects_conflicting_digest_for_one_bridge_source() -> None:
    """One source identity cannot carry two different artifact digests."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    bridge = inputs.bridge_links[0]
    conflicting = ArtifactProjectionSourcePin.from_artifact_pin(
        ArtifactPin(
            artifact_id="taxonomy-candidate-materialization-set",
            schema_version=bridge.evidence[0].artifact_pin.schema_version,
            semantic_digest="d" * 64,
        ),
        role="bridge-evidence-alias",
    )
    substituted_bridge = BridgeLink.model_validate(
        {
            **bridge.model_dump(mode="python"),
            "source_pins": (*bridge.source_pins, conflicting),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    substituted = inputs.model_copy(update={"bridge_links": (substituted_bridge,)})

    with pytest.raises(ValueError, match="conflicting digests"):
        resolve_hybrid_projection_units(substituted)


def test_closed_loop_history_is_validated_but_never_creates_a_unit() -> None:
    """A matching Phase 3 record is retained as history only."""
    inputs, relation, _candidate = _task1_authority_fixture()
    assessment_pin = ArtifactPin(
        artifact_id="hybrid-coverage-assessment",
        schema_version=inputs.phase2_assessment.schema_version,
        semantic_digest=inputs.phase2_assessment.semantic_digest,
    )
    plan_pin = ArtifactPin(
        artifact_id="taxonomy-obligation-plan",
        schema_version=inputs.obligation_plan.schema_version,
        semantic_digest=inputs.obligation_plan.semantic_digest,
    )
    ledger = StpaChallengeLedger(
        assessment_pin=assessment_pin,
        source_pins=(assessment_pin, plan_pin, inputs.capability_facts.source_pin),
        challenge_budget=0,
        records=(),
        diagnostics=ChallengeLedgerDiagnostics(
            eligible_targets=0,
            selected_targets=0,
            not_selected_budget=0,
        ),
    )
    history = ClosedLoopStpaRun(ledger=ledger, analysis_opt_in=False)

    resolved = resolve_hybrid_projection_units(
        inputs.model_copy(update={"closed_loop_run": history})
    )

    assert [unit.relation_id for unit in resolved.units] == [relation.relation_id]
    assert history.correspondence_changes == history.coverage_changes == 0


def test_correspondence_factory_rejects_cross_paired_proposal_set() -> None:
    """A matching map digest cannot pair a reconciliation with another set."""
    inputs, relation, _candidate = _task1_authority_fixture()
    from tests.test_hybrid_coverage_assessment import _proposal_set

    proposal_set, _ = _proposal_set(
        inputs.obligation_plan, inputs.resource_map_validation
    )
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        inputs.resource_map_validation,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="exact identities",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    replaced = proposal.model_copy(update={"confidence": 0.5})
    substituted = ProposalSet(
        resource_map_semantic_digest=proposal_set.resource_map_semantic_digest,
        capability_snapshot_digest=proposal_set.capability_snapshot_digest,
        authority=proposal_set.authority,
        proposals=(replaced,),
    )
    with pytest.raises(ValueError, match="proposal.*reconciliation"):
        build_hybrid_correspondence_attestation(
            substituted, reconciliation, inputs.phase2_assessment
        )


def test_correspondence_metadata_rejects_registry_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale registry entry cannot attest an unrelated correspondence object."""

    class RegistryProbe:
        """Weak-referenceable stand-ins for registry entries."""

    value = RegistryProbe()
    other = RegistryProbe()
    monkeypatch.setitem(
        projection_pipeline._CORRESPONDENCE_METADATA,
        id(value),
        (weakref.ref(other), "a" * 64, "b" * 64),
    )

    assert projection_pipeline._correspondence_metadata(value) is None


def test_noncoverage_relation_is_attested_and_excluded() -> None:
    """A valid related-only relation survives as a typed exclusion."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    from tests.test_hybrid_coverage_assessment import (
        _proposal_set,
        _stpa_input,
        _taxonomy_input,
    )

    proposal_set, candidate = _proposal_set(
        inputs.obligation_plan,
        inputs.resource_map_validation,
        relation_kind="related_but_not_coverage",
    )
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        inputs.resource_map_validation,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="shared-resource relation only",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    assessment = assess_hybrid_coverage(
        inputs.obligation_plan,
        inputs.resource_map_validation,
        reconciliation,
        _taxonomy_input(inputs.obligation_plan, candidate),
        _stpa_input(),
    )
    attestation = build_hybrid_correspondence_attestation(
        proposal_set, reconciliation, assessment
    )
    related_relation = attestation.accepted_relations[0]
    related_inputs = inputs.model_copy(
        update={
            "phase2_assessment": assessment,
            "correspondence": attestation,
            "confirmed_reviews": (),
            "bridge_links": (),
            "requested_relation_ids": (related_relation.relation_id,),
        }
    )
    resolved = resolve_hybrid_projection_units(related_inputs)
    assert attestation.accepted_relations[0].relation_kind == (
        "related_but_not_coverage"
    )
    assert resolved.units == ()
    assert resolved.exclusions[0].reason == "relation_not_coverage"


def test_mechanism_evidence_requires_exact_proposal_set_record() -> None:
    """An arbitrary pin/record pair cannot become mechanism evidence."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    with pytest.raises(TypeError, match="ProposalSet"):
        mechanism_evidence_attestation_from_artifacts(
            ArtifactPin(
                artifact_id="arbitrary",
                schema_version="v1",
                semantic_digest="b" * 64,
            ),
            "candidate-record",
            "exact_id",
        )


def test_review_rejects_proposal_set_digest_mismatch() -> None:
    """Reviewed outcomes cannot be paired with another proposal artifact."""
    inputs, relation, _candidate = _task1_authority_fixture()
    reviewed = ReviewedCorrespondenceAdjudications.create(
        packet_digest="a" * 64,
        proposal_set_semantic_digest="e" * 64,
        decisions=(
            ReviewedCorrespondenceDecision(
                proposal_id=relation.proposal_id,
                relation_kind=relation.relation_kind,
                status="confirmed",
                reason="reviewed exact mechanism",
                adjudicated_by="operator-1",
            ),
        ),
    )
    from tests.test_hybrid_coverage_assessment import _proposal_set

    proposal_set, _ = _proposal_set(
        inputs.obligation_plan, inputs.resource_map_validation
    )
    mechanism_evidence = mechanism_evidence_attestation_from_artifacts(
        proposal_set, relation.proposal_id, "exact_id"
    )
    with pytest.raises(ValueError, match="proposal set"):
        build_confirmed_coverage_review(reviewed, relation, mechanism_evidence)


def test_resolver_rejects_unknown_bridge_record_under_known_pin() -> None:
    """An authorized bridge cannot invent a record under a real artifact pin."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    bridge = inputs.bridge_links[0]
    evidence = BridgeEvidence.model_validate(
        {
            **bridge.evidence[0].model_dump(mode="python"),
            "record_id": "not-a-mechanism-record",
            "evidence_id": "",
            "semantic_digest": None,
        }
    )
    replaced_bridge = BridgeLink.model_validate(
        {
            **bridge.model_dump(mode="python"),
            "evidence": (evidence.model_dump(mode="python"),),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    resolved = resolve_hybrid_projection_units(
        inputs.model_copy(update={"bridge_links": (replaced_bridge,)})
    )
    assert resolved.units == ()
    assert resolved.exclusions[0].reason == "bridge_not_authoritative"


def test_resolver_rejects_updated_attestation_even_with_recomputed_digest() -> None:
    """A model_copy cannot retain the factory-only authority seal."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    copied = inputs.correspondence.model_copy(update={"semantic_digest": None})
    copied = type(copied).model_validate(copied.model_dump(mode="python"))
    substituted = inputs.model_copy(update={"correspondence": copied})
    with pytest.raises(ValueError, match="verified artifact factory"):
        resolve_hybrid_projection_units(substituted)


def test_resolution_source_pins_include_verified_wrappers() -> None:
    """The pin universe includes wrapper artifacts, not only leaf sources."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    resolved = resolve_hybrid_projection_units(inputs)
    artifact_ids = {
        pin.pin.artifact_id
        for pin in resolved.source_pins
        if isinstance(pin, ArtifactProjectionSourcePin)
    }
    assert {
        "taxonomy-candidate-materialization-set",
        "capability-fact-attestation",
        "pinned-stpa-projection-attestation",
        "hybrid-correspondence-attestation",
    }.issubset(artifact_ids)
    assert any(item.startswith("confirmed-coverage-review:") for item in artifact_ids)


def test_stpa_factory_keeps_multiple_relations_sharing_ica_and_exec() -> None:
    """Shared STPA identities do not collapse distinct relation contexts."""
    inputs, relation, _candidate = _task1_authority_fixture()
    from asago_scenario_generator.models.correspondence import (
        AcceptedCorrespondenceRelation,
        compute_relation_id,
    )

    second_payload = relation.model_dump(mode="python")
    second_payload["obligation_id"] = "ob:v1:" + "9" * 64
    second_payload["relation_id"] = compute_relation_id(
        obligation_id=second_payload["obligation_id"],
        ica_slot_id=second_payload["ica_slot_id"],
        ica_id=second_payload["ica_id"],
        exec_candidate_id=second_payload["exec_candidate_id"],
        relation_kind=second_payload["relation_kind"],
        resource_link_ids=second_payload["resource_link_ids"],
    )
    second = AcceptedCorrespondenceRelation.model_validate(second_payload)
    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Unauthorized payment",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-a"],
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="Payment hazard",
                related_losses=["L-1"],
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Payment constraint",
                related_hazards=["H-1"],
            ),
        ),
    )
    control_structure = make_control_structure()
    control_structure.responsibilities[0].security_constraint_refs = ["SC-1"]
    attestation = build_pinned_stpa_projection_attestation(
        loss_analysis,
        control_structure,
        ICAEnumeration(
            slots=(
                ICASlot(
                    slot_id=relation.ica_slot_id,
                    responsibility="RESP-1",
                    control_action="CA-1-1",
                    uca_type=UCAType.wrong_timing,
                    is_na=False,
                    icas=(
                        ICA(
                            ica_id=relation.ica_id,
                            ica_text="Payment at wrong time",
                            hazardous_context="Payment pending",
                            loss_scenario="Payment bypasses control",
                            related_hazards=["H-1"],
                            related_constraints=["SC-1"],
                        ),
                    ),
                ),
            ),
        ),
        (
            CandidateExecutionEnvelope(
                candidate_id=relation.exec_candidate_id,
                controller_id="RESP-1",
                control_action_id="CA-1-1",
                control_action_description="Authorize payment",
                uca_type=UCAType.wrong_timing,
                uca_ref=relation.ica_slot_id,
                ica_id=relation.ica_id,
            ),
        ),
        (relation, second),
    )
    assert len(attestation.projections) == 1


def test_stpa_factory_retains_coordination_namespaces_in_causal_nodes() -> None:
    """A coordination slot keeps CL/CM identities and node kinds distinct."""
    inputs, relation, _candidate = _task1_authority_fixture()
    from asago_scenario_generator.models.correspondence import compute_relation_id

    control_structure = make_control_structure()
    control_structure.responsibilities[0].security_constraint_refs = ["SC-1"]
    control_structure.coordination_links.append(
        CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-1",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1",
                description="Coordinate payment authorization",
                payload="payment-state",
            ),
            description="Payment coordination",
        )
    )
    slot_id = "CL-1:CM-1:WRONG_TIMING"
    ica_id = slot_id + ":1"
    exec_id = "EXEC:CL-1:CM-1:WRONG_TIMING"
    relation_payload = relation.model_dump(mode="python")
    relation_payload.update(
        {
            "ica_slot_id": slot_id,
            "ica_id": ica_id,
            "exec_candidate_id": exec_id,
        }
    )
    relation_payload["relation_id"] = compute_relation_id(
        obligation_id=relation_payload["obligation_id"],
        ica_slot_id=slot_id,
        ica_id=ica_id,
        exec_candidate_id=exec_id,
        relation_kind=relation_payload["relation_kind"],
        resource_link_ids=relation_payload["resource_link_ids"],
    )
    coordination_relation = type(relation).model_validate(relation_payload)
    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Unauthorized payment",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-a"],
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="Payment hazard",
                related_losses=["L-1"],
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Payment constraint",
                related_hazards=["H-1"],
            ),
        ),
    )
    attestation = build_pinned_stpa_projection_attestation(
        loss_analysis,
        control_structure,
        ICAEnumeration(
            slots=(
                ICASlot(
                    slot_id=slot_id,
                    responsibility=None,
                    coordination_link="CL-1",
                    control_action="CM-1",
                    uca_type=UCAType.wrong_timing,
                    is_na=False,
                    icas=(
                        ICA(
                            ica_id=ica_id,
                            ica_text="Payment at wrong time",
                            hazardous_context="Payment pending",
                            loss_scenario="Payment bypasses control",
                            related_hazards=["H-1"],
                            related_constraints=["SC-1"],
                        ),
                    ),
                ),
            ),
        ),
        (
            CandidateExecutionEnvelope(
                candidate_id=exec_id,
                controller_id="CL-1",
                control_action_id="CM-1",
                control_action_description="Coordinate payment authorization",
                uca_type=UCAType.wrong_timing,
                uca_ref=slot_id,
                ica_id=ica_id,
            ),
        ),
        (coordination_relation,),
    )
    projection = attestation.projections[0]
    nodes = {node.node_id: node.kind for node in projection.nodes}
    assert projection.controller_id == "CL-1"
    assert projection.control_action_id == "CM-1"
    assert nodes["CL-1"] == "coordination_link"
    assert nodes["CM-1"] == "coordination_mechanism"


def test_checked_pin_accepts_exact_optional_pin_and_rejects_substitution() -> None:
    """Optional pins must either be absent or exactly match their authority."""
    expected = ArtifactPin(
        artifact_id="authority",
        schema_version="authority-v1",
        semantic_digest="a" * 64,
    )
    assert (
        _checked_pin(
            None,
            artifact_id=expected.artifact_id,
            schema_version=expected.schema_version,
            digest=expected.semantic_digest,
            name="authority_pin",
        )
        == expected
    )
    assert (
        _checked_pin(
            expected,
            artifact_id=expected.artifact_id,
            schema_version=expected.schema_version,
            digest=expected.semantic_digest,
            name="authority_pin",
        )
        == expected
    )
    with pytest.raises(TypeError, match="ArtifactPin"):
        _checked_pin(
            object(),
            artifact_id=expected.artifact_id,
            schema_version=expected.schema_version,
            digest=expected.semantic_digest,
            name="authority_pin",
        )
    with pytest.raises(ValueError, match="semantic digest"):
        _checked_pin(
            expected,
            artifact_id=expected.artifact_id,
            schema_version=expected.schema_version,
            digest="b" * 64,
            name="authority_pin",
        )
    with pytest.raises(ValueError, match="artifact identity"):
        _checked_pin(
            expected,
            artifact_id="other-authority",
            schema_version=expected.schema_version,
            digest=expected.semantic_digest,
            name="authority_pin",
        )


def test_nested_bridge_and_mechanism_evidence_integrity_is_checked() -> None:
    """Nested authority records expose tampering through their public checks."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    evidence = inputs.bridge_links[0].evidence[0]
    bridge = inputs.bridge_links[0]
    mechanism_evidence = inputs.confirmed_reviews[0].mechanism_evidence

    evidence.assert_integrity()
    bridge.assert_integrity()
    mechanism_evidence.assert_integrity()

    with pytest.raises(ValueError, match="bridge evidence"):
        evidence.model_copy(update={"semantic_digest": "0" * 64}).assert_integrity()
    with pytest.raises(ValueError, match="bridge link"):
        bridge.model_copy(update={"semantic_digest": "0" * 64}).assert_integrity()
    with pytest.raises(ValueError, match="mechanism evidence"):
        mechanism_evidence.model_copy(
            update={"semantic_digest": "0" * 64}
        ).assert_integrity()


def test_bridge_evidence_accepts_curated_authority_and_rejects_derived_identity() -> (
    None
):
    """Curated evidence is closed and its ID/digest remain content-derived."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    base = inputs.bridge_links[0].evidence[0].model_dump(mode="python")
    curated = BridgeEvidence.model_validate(
        {
            **base,
            "evidence_id": "",
            "evidence_kind": "curated_bridge_mapping",
            "provenance": "curated",
            "authority_identity": {"kind": "curator", "id": "curator-1"},
            "semantic_digest": None,
        }
    )
    assert curated.authority_identity.kind == "curator"

    with pytest.raises(ValidationError, match="evidence ID"):
        BridgeEvidence.model_validate(
            {**curated.model_dump(mode="python"), "evidence_id": "wrong"}
        )
    with pytest.raises(ValidationError, match="evidence digest"):
        BridgeEvidence.model_validate(
            {**curated.model_dump(mode="python"), "semantic_digest": "0" * 64}
        )


def test_context_and_controller_authority_reject_unknown_namespaces() -> None:
    """STPA relation context and controller IDs must resolve to authority."""
    inputs, relation, _candidate = _task1_authority_fixture()
    ica = ICA(
        ica_id=relation.ica_id,
        ica_text="Payment at wrong time",
        hazardous_context="Payment pending",
        loss_scenario="Payment bypasses control",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    with pytest.raises(ValueError, match="context"):
        _context_sets_for_ica(
            relation.model_copy(update={"hazard_ids": ("H-2",)}),
            ica,
            {"SC-1": object()},
        )
    with pytest.raises(ValueError, match="context"):
        _context_sets_for_ica(
            relation.model_copy(update={"constraint_ids": ("SC-2",)}),
            ica,
            {"SC-1": object()},
        )
    with pytest.raises(ValueError, match="unknown hazard"):
        _require_known_context_ids(
            {"H-2"}, {"SC-1"}, {"H-1": object()}, {"SC-1": object()}
        )
    with pytest.raises(ValueError, match="unknown security constraint"):
        _require_known_context_ids(
            {"H-1"}, {"SC-2"}, {"H-1": object()}, {"SC-1": object()}
        )

    regular = ICASlot(
        slot_id=_SLOT,
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=(),
        na_justification="not applicable to this authority check",
    )
    ids = {
        "controller": {"RESP-1"},
        "coordination_link": {"CL-1"},
        "coordination_mechanism": {"CM-1"},
    }
    _validate_causal_controller_id(regular, "RESP-1", ids)
    with pytest.raises(ValueError, match="controller"):
        _validate_causal_controller_id(regular, "RESP-2", ids)

    coordinated = ICASlot(
        slot_id="CL-1:CM-1:NOT_PROVIDED",
        responsibility=None,
        coordination_link="CL-1",
        control_action="CM-1",
        uca_type=UCAType.not_provided,
        is_na=True,
        icas=(),
        na_justification="not applicable to this authority check",
    )
    _validate_causal_controller_id(coordinated, "CL-1", ids)
    with pytest.raises(ValueError, match="coordination link"):
        _validate_causal_controller_id(
            coordinated,
            "CL-2",
            {**ids, "coordination_link": set()},
        )
    with pytest.raises(ValueError, match="coordination mechanism"):
        _validate_causal_controller_id(
            coordinated,
            "CL-1",
            {**ids, "coordination_mechanism": set()},
        )


def test_causal_edge_and_terminal_exec_guards_cover_adversarial_paths() -> None:
    """Graph validation rejects reverse, duplicate, and outgoing EXEC edges."""
    projection = _causal()
    nodes_by_id = {node.node_id: node for node in projection.nodes}
    semantic: set[tuple[str, str, str]] = set()
    edge = projection.edges[0]
    _validate_causal_edge(edge, nodes_by_id, semantic)
    duplicate = CausalEdge(
        edge_id="edge-duplicate",
        from_node_id=edge.from_node_id,
        to_node_id=edge.to_node_id,
        kind=edge.kind,
    )
    with pytest.raises(ValueError, match="semantically unique"):
        _validate_causal_edge(duplicate, nodes_by_id, semantic)
    reverse_nodes = {
        "loss-reverse": CausalNode(node_id="loss-reverse", kind="loss", ordinal=2),
        "hazard-reverse": CausalNode(
            node_id="hazard-reverse", kind="hazard", ordinal=1
        ),
    }
    reverse = CausalEdge(
        edge_id="edge-reverse",
        from_node_id="loss-reverse",
        to_node_id="hazard-reverse",
        kind="projection",
    )
    with pytest.raises(ValueError, match="reverses"):
        _validate_causal_edge(reverse, reverse_nodes, set())

    exec_node = CausalNode(node_id="EXEC-1", kind="exec", ordinal=0)
    outgoing = CausalEdge(
        edge_id="edge-outgoing",
        from_node_id="EXEC-1",
        to_node_id="next",
        kind="projection",
    )
    _require_terminal_exec((exec_node,), ())
    with pytest.raises(ValueError, match="terminal"):
        _require_terminal_exec((exec_node,), (outgoing,))

    with pytest.raises(ValueError, match="one exact exec"):
        _require_single_exec_node(
            projection,
            {
                **nodes_by_id,
                "EXEC-extra": CausalNode(node_id="EXEC-extra", kind="exec", ordinal=8),
            },
        )
    with pytest.raises(ValueError, match="one exact exec"):
        _require_single_exec_node(
            projection,
            {
                **nodes_by_id,
                _EXEC: CausalNode(node_id="EXEC-other", kind="exec", ordinal=7),
            },
        )


def test_causal_edge_builder_retains_factor_edges_and_skips_action_self_edge() -> None:
    """Factor edges are added, while an actuator equal to the action is not."""
    _inputs, relation, _candidate = _task1_authority_fixture()
    slot = ICASlot(
        slot_id=relation.ica_slot_id,
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.wrong_timing,
        is_na=True,
        icas=(),
        na_justification="not applicable to edge construction",
    )
    specs = _causal_edge_specs(
        ("L-1",),
        {"H-1"},
        {"SC-1"},
        {"H-1": Hazard(hazard_id="H-1", description="hazard", related_losses=["L-1"])},
        {
            "SC-1": SecurityConstraint(
                constraint_id="SC-1",
                rule="constraint",
                related_hazards=["H-1"],
            )
        },
        (("PM-1-1", "process_model"), ("CA-1-1", "control_action")),
        "RESP-1",
        slot,
        relation,
    )
    assert ("PM-1-1", relation.ica_slot_id, "causal") in {
        (source, target, kind) for _id, source, target, kind in specs
    }
    assert ("CA-1-1", relation.ica_slot_id, "causal") not in {
        (source, target, kind) for _id, source, target, kind in specs
    }


def test_causal_identity_and_graph_guards_cover_shortcuts() -> None:
    """Identity groups and graph guards reject incomplete or ambiguous inputs."""
    assert _identity_kinds_for_group("controller", 2) == (
        "controller",
        "controller",
    )
    with pytest.raises(ValueError, match="inconsistent kinds"):
        _identity_kinds_for_group(("controller", "control_action", "extra"), 2)

    with pytest.raises(ValueError, match="one controller/action"):
        _causal_trace_kinds(
            {
                "resp": CausalNode(node_id="resp", kind="controller", ordinal=0),
                "link": CausalNode(node_id="link", kind="coordination_link", ordinal=1),
                "action": CausalNode(
                    node_id="action", kind="control_action", ordinal=2
                ),
            }
        )
    assert not _has_control_action_trace(
        {("constraint", "control_action", "constraint", "action")},
        "controller",
        "control_action",
    )

    equal_order_nodes = {
        "loss": CausalNode(node_id="loss", kind="loss", ordinal=1),
        "hazard": CausalNode(node_id="hazard", kind="hazard", ordinal=1),
    }
    with pytest.raises(ValueError, match="reverses"):
        _validate_causal_edge(
            CausalEdge(
                edge_id="equal-order",
                from_node_id="loss",
                to_node_id="hazard",
                kind="projection",
            ),
            equal_order_nodes,
            set(),
        )

    _visit_acyclic("A", {"A": ["A"]}, set(), {"A"})


def test_identity_group_requires_exact_kind_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The strict identity zip must not silently drop an identity."""
    monkeypatch.setattr(
        projection_models,
        "_identity_kinds_for_group",
        lambda *_args: ("controller",),
    )
    with pytest.raises(ValueError, match=r"zip\(\) argument"):
        _require_causal_identity_group(
            ("resp-1", "resp-2"),
            "controller",
            {"resp-1": CausalNode(node_id="resp-1", kind="controller", ordinal=0)},
            "controller identity",
        )


def test_stpa_source_pin_completion_and_resolution_digest_are_strict() -> None:
    """Required leaf pins and non-null resolution digests cannot be omitted."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    attestation = inputs.stpa_projection_authority
    loss_pin = ArtifactProjectionSourcePin.from_artifact_pin(
        attestation.loss_analysis_pin
    )
    reduced = attestation.model_copy(
        update={
            "source_pins": tuple(
                pin for pin in attestation.source_pins if pin != loss_pin
            )
        }
    )
    assert loss_pin in _complete_stpa_source_pins(reduced)

    resolved = resolve_hybrid_projection_units(inputs)
    tampered = resolved.model_copy(update={"semantic_digest": "0" * 64})
    with pytest.raises(ValueError, match="resolution digest"):
        tampered.canonicalize_and_verify()


def test_operator_bridge_authority_message_keeps_provenance() -> None:
    """Operator-declared bridge evidence must name the reviewer authority."""
    with pytest.raises(ValueError, match="operator-declared"):
        _validate_bridge_authority("operator_declared", "curator")


def test_stpa_derivation_rejects_missing_ica_and_relation_context() -> None:
    """Every execution envelope must resolve to an exact relation context."""
    _inputs, relation, _candidate = _task1_authority_fixture()
    no_ica = CandidateExecutionEnvelope(
        candidate_id=relation.exec_candidate_id,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        control_action_description="Authorize payment",
        uca_type=UCAType.wrong_timing,
        uca_ref=relation.ica_slot_id,
        ica_id=None,
    )
    with pytest.raises(ValueError, match="name an ICA"):
        _derive_stpa_projections(
            _StpaSources(
                loss=None,
                structure=None,
                enumeration=None,
                envelopes=(no_ica,),
                relations=(relation,),
            )
        )
    no_relation = no_ica.model_copy(update={"ica_id": relation.ica_id})
    with pytest.raises(ValueError, match="no exact accepted"):
        _derive_stpa_projections(
            _StpaSources(
                loss=None,
                structure=None,
                enumeration=None,
                envelopes=(no_relation,),
                relations=(),
            )
        )


def test_loss_context_requires_known_loss_and_matching_risk_source() -> None:
    """A hazard path must resolve to a loss carrying the relation risk."""
    _inputs, relation, _candidate = _task1_authority_fixture()
    with pytest.raises(ValueError, match="resolve to a loss"):
        _validate_loss_context(relation, (), {})
    with pytest.raises(ValueError, match="resolve to a loss"):
        _validate_loss_context(relation, ("L-1",), {})
    no_risk = Loss(
        loss_id="L-1",
        description="Payment loss",
        provenance=LossProvenance.risk_card,
        source_risk_cards=[],
    )
    with pytest.raises(ValueError, match="risk"):
        _validate_loss_context(relation, ("L-1",), {"L-1": no_risk})
    matching = no_risk.model_copy(update={"source_risk_cards": [relation.risk_id]})
    _validate_loss_context(relation, ("L-1",), {"L-1": matching})


def test_resolver_retains_invalid_endpoint_and_unreviewed_bridge_exclusions() -> None:
    """Bridge endpoint and review defects remain relation-local exclusions."""
    inputs, relation, _candidate = _task1_authority_fixture()
    invalid_endpoint = BridgeLink.model_validate(
        {
            **inputs.bridge_links[0].model_dump(mode="python"),
            "taxonomy_endpoint": TaxonomyEndpoint(
                kind="mechanism_step", record_id="missing-step"
            ),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    invalid = resolve_hybrid_projection_units(
        inputs.model_copy(update={"bridge_links": (invalid_endpoint,)})
    )
    assert invalid.exclusions[0].reason == "bridge_invalid_endpoint"

    base = inputs.bridge_links[0].evidence[0].model_dump(mode="python")
    unreviewed_evidence = BridgeEvidence.model_validate(
        {
            **base,
            "evidence_id": "",
            "evidence_kind": "exact_taxonomy_record",
            "provenance": "operator_declared",
            "authority_identity": {"kind": "reviewer", "id": "operator-1"},
            "record_id": "step.1",
            "semantic_digest": None,
        }
    )
    unreviewed_bridge = BridgeLink.model_validate(
        {
            **inputs.bridge_links[0].model_dump(mode="python"),
            "evidence": (unreviewed_evidence,),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    unreviewed = resolve_hybrid_projection_units(
        inputs.model_copy(update={"bridge_links": (unreviewed_bridge,)})
    )
    assert unreviewed.exclusions[0].reason == "bridge_unreviewed"


def test_projection_diagnostic_derives_identity_and_rejects_tampering() -> None:
    """Diagnostics are content-addressed trace records, not free-form IDs."""
    diagnostic = ProjectionDiagnostic(kind="bridge_unreviewed")
    assert diagnostic.diagnostic_id.startswith("diagnostic:v1:")
    with pytest.raises(ValidationError, match="diagnostic ID"):
        ProjectionDiagnostic.model_validate(
            {**diagnostic.model_dump(mode="python"), "diagnostic_id": "wrong"}
        )


def test_capability_attestation_validates_an_explicit_invalid_resource_map() -> None:
    """Supplying a map must activate its successful-attestation guard."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    invalid_map = inputs.resource_map_validation.model_copy(update={"is_valid": False})

    with pytest.raises(ValueError, match="resource map validation must be successful"):
        capability_fact_attestation_from_artifacts(
            get_test_snapshot(),
            inputs.obligation_plan,
            invalid_map,
        )


def test_typed_sequence_guards_reject_strings() -> None:
    """String values are not accepted as candidate or source sequences."""
    with pytest.raises(TypeError, match="sequence"):
        _require_candidate_sequence("not-a-candidate-sequence")
    with pytest.raises(TypeError, match="sequence"):
        _require_sequence("not-a-source-sequence", "values must be a sequence")


def test_context_guard_requires_each_stpa_context_set() -> None:
    """An accepted relation cannot omit only hazards or only constraints."""
    with pytest.raises(ValueError, match="hazard or constraint"):
        _require_context_members({"H-1"}, set())
    with pytest.raises(ValueError, match="hazard or constraint"):
        _require_context_members(set(), {"SC-1"})


def test_ica_slot_guard_rejects_an_existing_na_slot_before_ica_lookup() -> None:
    """An N/A slot is not a resolvable source even when its ID exists."""
    _inputs, relation, _candidate = _task1_authority_fixture()
    na_slot = ICASlot(
        slot_id=relation.ica_slot_id,
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.wrong_timing,
        is_na=True,
        icas=(),
        na_justification="not applicable to this test",
    )
    enumeration = ICAEnumeration(slots=[na_slot])

    with pytest.raises(ValueError, match="missing or N/A"):
        _causal_slot_for_relation(relation, enumeration)


def test_causal_nodes_reject_incompatible_namespace_reuse() -> None:
    """One identity cannot be assigned two incompatible causal namespaces."""
    with pytest.raises(ValueError, match="incompatible namespaces"):
        _nodes_from_specs((("shared", "loss"), ("shared", "hazard")))


def test_edge_order_guard_rejects_equal_ordinals() -> None:
    """Causal edges must move strictly forward in the canonical node order."""
    with pytest.raises(ValueError, match="reverses local order"):
        _require_edge_order(
            (("edge-1", "loss", "hazard", "projection"),),
            {"loss": 1, "hazard": 1},
        )


def test_correspondence_pins_require_both_digests() -> None:
    """A missing digest on either correspondence authority is fatal."""
    proposals = SimpleNamespace(semantic_digest=None, schema_version="v1")
    reconciliation = SimpleNamespace(semantic_digest="a" * 64, schema_version="v1")

    with pytest.raises(ValueError, match="digests are required"):
        _correspondence_pins(proposals, reconciliation, None, None)


def test_unit_identity_retains_empty_identity_for_missing_relation() -> None:
    """A missing relation still receives the closed five-part identity shape."""
    assert _unit_identity(None) == ("", "", "", "", "")


def test_relation_authority_checks_non_applicable_obligation_scope() -> None:
    """A valid assessment row still cannot authorize a non-applicable obligation."""
    inputs, relation, _candidate = _task1_authority_fixture()
    context = projection_pipeline._resolution_context(inputs)
    non_applicable = SimpleNamespace(scope_disposition="governance_only")
    reduced_context = SimpleNamespace(
        realization_rows=context.realization_rows,
        taxonomy_rows=context.taxonomy_rows,
        plan_rows={relation.obligation_id: non_applicable},
    )

    assert _relation_authority_reason(relation, reduced_context) == (
        "obligation_not_applicable"
    )


def test_materialization_match_requires_identity_and_mechanism_match() -> None:
    """A correct mechanism with a stale record digest is not a match."""
    inputs, relation, _candidate = _task1_authority_fixture()
    material = inputs.candidate_materializations.entries[0]
    record = inputs.obligation_plan.obligations[0].candidate_records[0]
    stale = material.model_copy(update={"phase1_candidate_record_digest": "0" * 64})

    assert not _materialization_matches(stale, record, relation)


def test_materialization_expands_a_shared_candidate_per_obligation() -> None:
    """One executable candidate can legitimately serve several risk obligations."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=("risk-a", "risk-b")))
    candidate = get_projected_candidate()

    materializations = build_candidate_materialization_set(
        plan,
        (candidate,),
        get_test_snapshot(),
    )

    assert len(materializations.entries) == 2
    assert {
        (item.obligation_id, item.risk_id, item.selected_candidate_id)
        for item in materializations.entries
    } == {
        (row.obligation_id, row.risk_ref.risk_id, candidate.candidate_id)
        for row in plan.obligations
    }


def test_resolved_parts_stops_when_materialization_is_missing_without_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing materialization is terminal even without a diagnostic reason."""
    monkeypatch.setattr(
        projection_pipeline,
        "_materialization_for_relation",
        lambda *_args: (None, None),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "_stpa_for_relation",
        lambda *_args: pytest.fail("STPA resolution must not run"),
    )

    assert _resolved_relation_parts(object(), object(), object()) == (None, None)


def test_resolved_parts_stops_when_causal_projection_is_missing_without_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing causal projection is terminal even without a diagnostic reason."""
    monkeypatch.setattr(
        projection_pipeline,
        "_materialization_for_relation",
        lambda *_args: (object(), None),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "_stpa_for_relation",
        lambda *_args: (None, None),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "_resolve_review_and_bridges",
        lambda *_args: pytest.fail("review resolution must not run"),
    )

    assert _resolved_relation_parts(object(), object(), object()) == (None, None)


def test_coverage_relation_returns_exclusion_when_parts_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coverage resolution retains a missing authority as a typed exclusion."""
    inputs, relation, _candidate = _task1_authority_fixture()
    obligation = inputs.obligation_plan.obligations[0]
    monkeypatch.setattr(
        projection_pipeline,
        "_resolved_relation_parts",
        lambda *_args: (None, None),
    )

    assert _resolve_coverage_relation(relation, obligation, object()) == (
        relation,
        None,
        "relation_not_accepted",
    )
