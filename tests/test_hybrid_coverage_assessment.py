"""Public-seam tests for the normative hybrid coverage assessment."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CandidateAuthorityRecord,
    CorrespondenceAdjudication,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
    ObligationAuthorityRecord,
    ReconciliationResult,
    SourceArtifactPins,
    StructuralAuthorityRecord,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    CoverageFinding,
    HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION,
    HybridCoverageAssessment,
    ProposalOutcome,
    ScenarioRealizationRow,
    StpaCoverageInput,
    StpaScenarioObservation,
    StructuralConsiderationRow,
    StructuralInapplicabilityDecision,
    StructuralSlotObservation,
    TaxonomyCorrespondenceRow,
    TaxonomyCoverageInput,
    TaxonomyScenarioObservation,
    TraceReference,
    compute_matrix_row_id,
)
from asago_scenario_generator.models.system_resource_map import (
    ResourceLink,
    SystemResourceMapValidation,
)
from asago_scenario_generator.models.scenario import (
    ScenarioEnvelope as TaxonomyScenarioEnvelope,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from asago_scenario_generator.pipeline.hybrid_coverage import (
    _has_inferred_relevant_inventory,
    assess_hybrid_coverage,
)
from asago_scenario_generator.pipeline.hybrid_coverage_persistence import (
    HYBRID_COVERAGE_ASSESSMENT_FILENAME,
    write_hybrid_coverage_assessment,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ScenarioEnvelope as StpaScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    ScenarioSpec as StpaScenarioSpec,
    ThreatSource,
)
from tests.helpers.obligation_factory import make_inputs
from tests.system_resource_map_support import make_control_structure, make_map

ICA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
NA_SLOT = "RESP-1:CA-1-1:WRONG_DURATION"
UNRESOLVED_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"

TAXONOMY_ARTIFACT = ArtifactPin(
    artifact_id="taxonomy-scenarios",
    schema_version="taxonomy-scenarios-v1",
    semantic_digest="7" * 64,
)
ICA_ARTIFACT = ArtifactPin(
    artifact_id="ica-enumeration",
    schema_version="ica-enumeration-v1",
    semantic_digest="3" * 64,
)
STPA_ARTIFACT = ArtifactPin(
    artifact_id="stpa-scenarios",
    schema_version="stpa-scenarios-v1",
    semantic_digest="8" * 64,
)
DECISION_ARTIFACT = ArtifactPin(
    artifact_id="correspondence-decisions",
    schema_version="correspondence-decisions-v1",
    semantic_digest="9" * 64,
)
REPRESENTATIVE_ARTIFACT = (
    Path(__file__).parent / "fixtures/hybrid-coverage-assessment.yaml"
)


def _plan_and_map(**input_overrides):
    inputs = make_inputs(**input_overrides)
    plan = plan_taxonomy_obligations(inputs)
    tool_ref = {
        "kind": "tool",
        "tool_id": inputs.capability_snapshot.profile.tool_inventory[0].tool_id,
    }
    link = ResourceLink(
        link_id="srm:v1:assessment-link",
        capability_resource_ref=tool_ref,
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        relation_kind="acts_on",
        provenance="operator_declared",
        evidence_refs=("review:assessment-link",),
        confidence=1.0,
        authority_status="authoritative",
    )
    control = make_control_structure()
    resource_map = make_map(
        link,
        snapshot=inputs.capability_snapshot,
        control=control,
    )
    return plan, validate_system_resource_map(
        resource_map, inputs.capability_snapshot, control
    )


def _canonical_map(resource_map_validation):
    resource_map = resource_map_validation.canonical_map
    assert resource_map is not None
    return resource_map


def _proposal_set(plan, resource_map_validation, *, relation_kind="same_mechanism"):
    resource_map = _canonical_map(resource_map_validation)
    obligation = plan.obligations[0]
    projectable = next(
        candidate
        for candidate in obligation.candidate_records
        if candidate.projection_disposition == "projectable"
    )
    pins = SourceArtifactPins(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        obligation_plan_semantic_digest=plan.semantic_digest,
        control_structure_digest=resource_map.control_structure_digest,
        ica_enumeration_digest=ICA_ARTIFACT.semantic_digest,
        loss_analysis_digest="4" * 64,
        taxonomy_version=plan.schema_version,
        stpa_version="stpa-v1",
    )
    authority = CorrespondenceAuthority(
        source_pins=pins,
        obligations=(
            ObligationAuthorityRecord(
                obligation_id=obligation.obligation_id,
                risk_id=obligation.risk_ref.risk_id,
                attack_pattern_id=obligation.attack_pattern_id,
                taxonomy_candidate_ids=tuple(
                    item.candidate_id for item in obligation.candidate_records
                ),
                candidate_resource_refs=tuple(
                    binding.resource_ref
                    for item in obligation.candidate_records
                    for binding in item.resource_bindings
                ),
                candidates=tuple(
                    CandidateAuthorityRecord(
                        candidate_id=item.candidate_id,
                        resource_bindings=item.resource_bindings,
                        projection_disposition=item.projection_disposition,
                    )
                    for item in obligation.candidate_records
                ),
            ),
        ),
        structural_findings=(
            StructuralAuthorityRecord(
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC_ID,
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                resource_link_ids=("srm:v1:assessment-link",),
            ),
        ),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
    )
    relation_kinds = (
        (relation_kind,) if isinstance(relation_kind, str) else tuple(relation_kind)
    )
    evidence = tuple(
        CorrespondenceEvidence(
            obligation_id=obligation.obligation_id,
            risk_id=obligation.risk_ref.risk_id,
            attack_pattern_id=obligation.attack_pattern_id,
            taxonomy_candidate_ids=tuple(
                candidate.candidate_id for candidate in obligation.candidate_records
            ),
            selected_candidate_id=projectable.candidate_id,
            ica_slot_id=ICA_SLOT,
            ica_id=ICA_ID,
            exec_candidate_id=EXEC_ID,
            relation_kind=item,
            resource_link_ids=("srm:v1:assessment-link",),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence_source="exact_id",
            evidence_refs=("id:obligation", "id:ica", f"kind:{item}"),
            confidence=1.0,
            evidence_strength="high",
            proposer_id="exact-id-v1",
            proposer_version="1",
            source_pins=pins,
            rationale="exact reviewed identities",
        )
        for item in relation_kinds
    )
    return (
        propose_correspondence(
            resource_map_validation,
            CorrespondenceSourceArtifacts(authority=authority, evidence=evidence),
        ),
        projectable,
    )


def _reconcile(
    plan,
    resource_map_validation,
    *,
    status="confirmed",
    relation_kind="same_mechanism",
):
    proposal_set, candidate = _proposal_set(
        plan, resource_map_validation, relation_kind=relation_kind
    )
    decisions = tuple(
        CorrespondenceAdjudication(
            proposal_id=proposal.proposal_id,
            status=status,
            reason="reviewed evidence",
            adjudicated_by="operator-1",
        )
        for proposal in proposal_set.proposals
    )
    result = reconcile_correspondence(
        resource_map_validation,
        proposal_set,
        AdjudicationSet(decisions=decisions),
    )
    return result, candidate


def _defective_reconciliation(plan, resource_map_validation, **overrides):
    proposal_set, _ = _proposal_set(plan, resource_map_validation)
    proposal = proposal_set.proposals[0]
    evidence = CorrespondenceEvidence(
        obligation_id=overrides.get("obligation_id", proposal.obligation_id),
        risk_id=overrides.get("risk_id", proposal.risk_id),
        attack_pattern_id=overrides.get(
            "attack_pattern_id", proposal.attack_pattern_id
        ),
        taxonomy_candidate_ids=overrides.get(
            "taxonomy_candidate_ids", proposal.taxonomy_candidate_ids
        ),
        selected_candidate_id=overrides.get(
            "selected_candidate_id", proposal.selected_candidate_id
        ),
        ica_slot_id=overrides.get("ica_slot_id", proposal.ica_slot_id),
        ica_id=overrides.get("ica_id", proposal.ica_id),
        exec_candidate_id=overrides.get(
            "exec_candidate_id", proposal.exec_candidate_id
        ),
        relation_kind=proposal.relation_kind,
        resource_link_ids=overrides.get(
            "resource_link_ids", proposal.resource_link_ids
        ),
        hazard_ids=proposal.hazard_ids,
        constraint_ids=proposal.constraint_ids,
        evidence_source=proposal.provenance.evidence_source,
        evidence_refs=proposal.provenance.evidence_refs,
        confidence=proposal.confidence,
        evidence_strength=proposal.evidence_strength,
        proposer_id=proposal.provenance.proposer_id,
        proposer_version=proposal.provenance.proposer_version,
        source_pins=overrides.get("source_pins", proposal.provenance.source_pins),
        rationale=proposal.provenance.rationale,
    )
    defective_set = propose_correspondence(
        resource_map_validation,
        CorrespondenceSourceArtifacts(
            authority=proposal_set.authority, evidence=(evidence,)
        ),
    )
    decision = CorrespondenceAdjudication(
        proposal_id=defective_set.proposals[0].proposal_id,
        status="confirmed",
        reason="review attempted",
        adjudicated_by="operator-1",
    )
    return reconcile_correspondence(
        resource_map_validation,
        defective_set,
        AdjudicationSet(decisions=(decision,)),
    )


def _taxonomy_input(plan, candidate=None, *, decisions=()):
    scenarios = ()
    if candidate is not None:
        scenarios = (
            TaxonomyScenarioObservation(
                scenario_id="scenario:v2:" + "a" * 64,
                obligation_id=plan.obligations[0].obligation_id,
                candidate_id=candidate.candidate_id,
                source_artifact=TAXONOMY_ARTIFACT,
                trace_refs=("scenario.yaml",),
            ),
        )
    return TaxonomyCoverageInput(
        scenarios=scenarios,
        structural_inapplicability_decisions=decisions,
    )


def _ica_slot() -> StructuralSlotObservation:
    return StructuralSlotObservation(
        slot_id=ICA_SLOT,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type="WRONG_TIMING",
        ica_ids=(ICA_ID,),
        disposition="ica",
        evidence=("ica-enumeration.yaml#" + ICA_ID,),
        source_artifact=ICA_ARTIFACT,
        trace_refs=("ica-enumeration.yaml#" + ICA_SLOT,),
    )


def _stpa_input(*, scenarios=True, extra_slots=()) -> StpaCoverageInput:
    observed = ()
    if scenarios:
        observed = (
            StpaScenarioObservation(
                scenario_id="STPA-SCENARIO-1",
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC_ID,
                source_artifact=STPA_ARTIFACT,
                trace_refs=("stpa/scenarios.yaml#STPA-SCENARIO-1",),
            ),
        )
    return StpaCoverageInput(
        slots=(_ica_slot(), *extra_slots),
        scenarios=observed,
        inventory_status="complete",
    )


def _empty_reconciliation(resource_map_validation) -> ReconciliationResult:
    resource_map = _canonical_map(resource_map_validation)
    return ReconciliationResult(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        is_valid=True,
    )


def test_source_spec_matrices_use_slots_obligations_and_accepted_relations() -> None:
    """The three denominators are exactly those defined by source spec §8.11."""
    plan, resource_map = _plan_and_map()
    justified = StructuralSlotObservation(
        slot_id=NA_SLOT,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type="WRONG_DURATION",
        disposition="justified_na",
        evidence=("review:continuous-action-not-applicable",),
        source_artifact=ICA_ARTIFACT,
        trace_refs=("ica-enumeration.yaml#" + NA_SLOT,),
    )
    unresolved = StructuralSlotObservation(
        slot_id=UNRESOLVED_SLOT,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type="NOT_PROVIDED",
        disposition="unresolved",
        evidence=("gap:slot-not-reviewed",),
        source_artifact=ICA_ARTIFACT,
        trace_refs=("ica-enumeration.yaml#" + UNRESOLVED_SLOT,),
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(),
        _stpa_input(scenarios=False, extra_slots=(justified, unresolved)),
    )

    assert assessment.schema_version == HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION
    assert assessment.capability_snapshot_digest == plan.capability_snapshot_digest
    assert any(
        pin.artifact_id == "capability-fact-snapshot"
        and pin.semantic_digest == plan.capability_snapshot_digest
        for pin in assessment.source_pins
    )
    assert [row.slot_id for row in assessment.structural_consideration] == sorted(
        (ICA_SLOT, NA_SLOT, UNRESOLVED_SLOT)
    )
    assert {row.disposition for row in assessment.structural_consideration} == {
        "ica",
        "justified_na",
        "unresolved",
    }
    assert tuple(row.obligation_id for row in assessment.taxonomy_correspondence) == (
        plan.obligations[0].obligation_id,
    )
    assert assessment.taxonomy_correspondence[0].correspondence_disposition == (
        "unresolved_no_proposal"
    )
    assert assessment.scenario_realization == ()
    assert assessment.network_calls == assessment.model_calls == 0


def test_real_ica_enumeration_adapter_preserves_complete_slot_denominator() -> None:
    """The production adapter derives exact slot fields and a content pin."""
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=ICA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=ICA_ID,
                        ica_text="Unsafe timing",
                        hazardous_context="Payment pending",
                        loss_scenario="Unauthorized payment",
                    )
                ],
            ),
            ICASlot(
                slot_id=NA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_duration,
                is_na=True,
                na_justification="The action is discrete and has no duration",
            ),
        ]
    )

    adapted = StpaCoverageInput.from_ica_enumeration(enumeration)

    assert tuple(item.slot_id for item in adapted.slots) == tuple(
        sorted((ICA_SLOT, NA_SLOT))
    )
    assert {item.disposition for item in adapted.slots} == {"ica", "justified_na"}
    assert len({item.source_artifact for item in adapted.slots}) == 1
    assert adapted.slots[0].source_artifact.semantic_digest != "0" * 64


def test_real_ica_enumeration_adapter_preserves_unresolved_slot_disposition() -> None:
    """A failed ICA analysis reaches the structural matrix as unresolved."""
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=UNRESOLVED_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[],
                unresolved_reason="The provider response failed validation.",
            )
        ]
    )

    adapted = StpaCoverageInput.from_ica_enumeration(enumeration)

    assert adapted.slots[0].disposition == "unresolved"
    assert adapted.slots[0].ica_ids == ()
    assert adapted.slots[0].evidence == (
        "The provider response failed validation.",
    )


def test_real_taxonomy_envelopes_join_through_candidate_and_obligation_identity() -> (
    None
):
    """One admitted candidate can truthfully realize several risk obligations."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=("risk-a", "risk-b")))
    candidate_id = plan.obligations[0].candidate_records[0].candidate_id
    scenario = TaxonomyScenarioEnvelope.model_construct(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id=candidate_id,
    )

    adapted = TaxonomyCoverageInput.from_scenario_envelopes(plan, (scenario,))

    assert len(adapted.scenarios) == 2
    assert {item.obligation_id for item in adapted.scenarios} == {
        item.obligation_id for item in plan.obligations
    }
    assert {item.scenario_id for item in adapted.scenarios} == {scenario.scenario_id}
    assert {item.candidate_id for item in adapted.scenarios} == {candidate_id}
    assert len({item.source_artifact for item in adapted.scenarios}) == 1


def test_taxonomy_envelope_adapter_rejects_unplanned_candidates() -> None:
    """An admitted envelope cannot be attached by prose or approximate identity."""
    plan = plan_taxonomy_obligations(make_inputs())
    scenario = TaxonomyScenarioEnvelope.model_construct(
        scenario_id="scenario:v2:" + "b" * 64,
        candidate_id="cand:v2:" + "f" * 32,
    )

    with pytest.raises(ValueError, match="unknown projectable candidate"):
        TaxonomyCoverageInput.from_scenario_envelopes(plan, (scenario,))


def test_taxonomy_envelope_adapter_requires_typed_unique_scenario_identities() -> None:
    """The real-envelope seam rejects loose, missing, and duplicate identities."""
    plan = plan_taxonomy_obligations(make_inputs())
    candidate_id = plan.obligations[0].candidate_records[0].candidate_id
    scenario = TaxonomyScenarioEnvelope.model_construct(
        scenario_id="scenario:v2:" + "c" * 64,
        candidate_id=candidate_id,
    )

    with pytest.raises(TypeError, match="ScenarioEnvelope records"):
        TaxonomyCoverageInput.from_scenario_envelopes(plan, ({},))
    with pytest.raises(ValueError, match="requires scenario_id"):
        TaxonomyCoverageInput.from_scenario_envelopes(
            plan,
            (TaxonomyScenarioEnvelope.model_construct(candidate_id=candidate_id),),
        )
    with pytest.raises(ValueError, match="IDs must be unique"):
        TaxonomyCoverageInput.from_scenario_envelopes(plan, (scenario, scenario))


def test_real_stpa_envelopes_join_through_slot_ica_and_exec_identity() -> None:
    """The adapter extracts only exact structural identities from real envelopes."""
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=ICA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=ICA_ID,
                        ica_text="Unsafe timing",
                        hazardous_context="Payment pending",
                        loss_scenario="Unauthorized payment",
                    )
                ],
            )
        ]
    )
    scenario = StpaScenarioEnvelope.model_construct(
        scenario_id="SCN-001",
        scenario_spec=StpaScenarioSpec.model_construct(
            threat_source=ThreatSource(
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                provenance="structural",
            )
        ),
    )

    adapted = StpaCoverageInput.from_scenario_envelopes(enumeration, (scenario,))

    assert adapted.scenarios[0].scenario_id == "SCN-001"
    assert adapted.scenarios[0].ica_slot_id == ICA_SLOT
    assert adapted.scenarios[0].ica_id == ICA_ID
    assert adapted.scenarios[0].exec_candidate_id == EXEC_ID
    assert adapted.scenarios[0].source_artifact.artifact_id == "stpa-scenarios"


@pytest.mark.parametrize(
    ("scenario_spec", "message"),
    (
        (None, "typed scenario_spec"),
        (StpaScenarioSpec.model_construct(), "typed threat_source"),
        (
            StpaScenarioSpec.model_construct(
                threat_source=ThreatSource.model_construct()
            ),
            "exact ICA slot and ICA identities",
        ),
        (
            StpaScenarioSpec.model_construct(
                threat_source=ThreatSource.model_construct(ica_slot_id=ICA_SLOT)
            ),
            "exact ICA slot and ICA identities",
        ),
        (
            StpaScenarioSpec.model_construct(
                threat_source=ThreatSource(
                    ica_slot_id="RESP-UNKNOWN:CA-1-1:WRONG_TIMING",
                    ica_id=ICA_ID,
                    provenance="structural",
                )
            ),
            "unknown ICA slot",
        ),
    ),
)
def test_stpa_envelope_adapter_rejects_incomplete_structural_lineage(
    scenario_spec: object, message: str
) -> None:
    """No STPA scenario is observed without its exact slot and ICA lineage."""
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=ICA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=ICA_ID,
                        ica_text="Unsafe timing",
                        hazardous_context="Payment pending",
                        loss_scenario="Unauthorized payment",
                    )
                ],
            )
        ]
    )
    scenario_kwargs = {} if scenario_spec is None else {"scenario_spec": scenario_spec}
    scenario = StpaScenarioEnvelope.model_construct(
        scenario_id="SCN-INVALID", **scenario_kwargs
    )

    with pytest.raises(ValueError, match=message):
        StpaCoverageInput.from_scenario_envelopes(enumeration, (scenario,))


def test_real_ica_adapter_and_scenario_identity_graph_fail_closed() -> None:
    """The adapter requires the real type and scenarios resolve exact ICA/EXEC IDs."""
    with pytest.raises(TypeError, match="must be an ICAEnumeration"):
        StpaCoverageInput.from_ica_enumeration(object())

    base = StpaScenarioObservation(
        scenario_id="STPA-SCENARIO-1",
        ica_slot_id=ICA_SLOT,
        ica_id=ICA_ID,
        exec_candidate_id=EXEC_ID,
        source_artifact=STPA_ARTIFACT,
        trace_refs=("stpa/scenarios.yaml#STPA-SCENARIO-1",),
    )
    with pytest.raises(ValueError, match="unknown ICA"):
        StpaCoverageInput(
            slots=(_ica_slot(),),
            scenarios=(base.model_copy(update={"ica_id": ICA_ID + "-unknown"}),),
            inventory_status="complete",
        )
    with pytest.raises(ValueError, match="canonical EXEC identity"):
        StpaCoverageInput(
            slots=(_ica_slot(),),
            scenarios=(
                base.model_copy(
                    update={"exec_candidate_id": "EXEC:RESP-1:CA-1-1:INCORRECT"}
                ),
            ),
            inventory_status="complete",
        )


def test_confirmed_relation_satisfies_taxonomy_and_is_not_hybrid_realization() -> None:
    """Accepted confirmation creates correspondence but hybrid execution stays pending."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )

    taxonomy_row = assessment.taxonomy_correspondence[0]
    realization = assessment.scenario_realization[0]
    relation = reconciliation.accepted_relations[0]
    assert taxonomy_row.accepted_relation_ids == (relation.relation_id,)
    assert taxonomy_row.correspondence_disposition == "satisfied"
    assert taxonomy_row.gap_reason is None
    assert taxonomy_row.risk_id == plan.obligations[0].risk_ref.risk_id
    assert taxonomy_row.taxonomy_candidate_ids == relation.taxonomy_candidate_ids
    assert taxonomy_row.scope_disposition == "applicable"
    assert taxonomy_row.qualification_disposition == "ready"
    assert realization.relation_id == relation.relation_id
    assert realization.proposal_id == relation.proposal_id
    assert realization.obligation_id == relation.obligation_id
    assert realization.risk_id == relation.risk_id
    assert realization.attack_pattern_id == relation.attack_pattern_id
    assert realization.taxonomy_candidate_ids == relation.taxonomy_candidate_ids
    assert realization.legacy_scenario_ids == ("STPA-SCENARIO-1",)
    assert realization.hybrid_generation_status == "not_attempted"
    assert realization.hybrid_admission_status == "not_assessed"
    assert realization.trace_refs


def test_related_but_not_coverage_is_realized_but_never_satisfies() -> None:
    """An accepted noncoverage relation remains an explicit finding only."""
    plan, resource_map = _plan_and_map()
    reconciliation, _ = _reconcile(
        plan, resource_map, relation_kind="related_but_not_coverage"
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        TaxonomyCoverageInput(),
        _stpa_input(),
    )

    row = assessment.taxonomy_correspondence[0]
    assert row.accepted_relation_ids == ()
    assert row.correspondence_disposition == "unresolved_ambiguous"
    assert row.gap_reason == "related_but_not_coverage"
    assert len(assessment.scenario_realization) == 1
    assert assessment.scenario_realization[0].coverage_bearing is False
    assert {finding.kind for finding in assessment.findings} == {
        "related_but_not_coverage"
    }


@pytest.mark.parametrize(
    ("status", "disposition", "gap"),
    (
        ("rejected", "unresolved_rejected_proposals", "rejected_proposals"),
        ("unresolved", "unresolved_ambiguous", "ambiguous_proposals"),
    ),
)
def test_nonconfirmed_proposals_are_diagnostics_not_coverage(
    status: str, disposition: str, gap: str
) -> None:
    """Rejected and unresolved proposals remain traceable without coverage credit."""
    plan, resource_map = _plan_and_map()
    reconciliation, _ = _reconcile(plan, resource_map, status=status)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        TaxonomyCoverageInput(),
        _stpa_input(),
    )

    assert assessment.taxonomy_correspondence[0].accepted_relation_ids == ()
    assert (
        assessment.taxonomy_correspondence[0].correspondence_disposition == disposition
    )
    assert assessment.taxonomy_correspondence[0].gap_reason == gap
    assert assessment.scenario_realization == ()
    assert {item.status for item in assessment.proposal_outcomes} == {status}
    assert plan.obligations[0].obligation_id in {
        trace.record_id for trace in assessment.proposal_outcomes[0].trace_refs
    }


@pytest.mark.parametrize(
    "overrides",
    (
        {
            "obligation_id": "ob:v1:" + "f" * 64,
            "risk_id": "RISK-UNKNOWN",
            "attack_pattern_id": "PATTERN-UNKNOWN",
            "taxonomy_candidate_ids": ("cand:v2:" + "f" * 32,),
        },
        {
            "ica_slot_id": "RESP-X:CA-X:WRONG_TIMING",
            "ica_id": "RESP-X:CA-X:WRONG_TIMING:1",
            "exec_candidate_id": "EXEC:RESP-X:CA-X:WRONG_TIMING",
        },
        {"resource_link_ids": ("srm:v1:missing-link",)},
        {
            "source_pins": SourceArtifactPins(
                resource_map_semantic_digest="f" * 64,
                capability_snapshot_digest="a" * 64,
                obligation_plan_semantic_digest="e" * 64,
                control_structure_digest="d" * 64,
                ica_enumeration_digest="c" * 64,
                loss_analysis_digest="b" * 64,
                taxonomy_version="taxonomy-obligation-plan-v1",
                stpa_version="stpa-v1",
            )
        },
    ),
)
def test_defective_proposals_survive_as_global_noncoverage_diagnostics(
    overrides: dict,
) -> None:
    """Dangling rejected evidence remains auditable without becoming coverage."""
    plan, resource_map = _plan_and_map()
    reconciliation = _defective_reconciliation(plan, resource_map, **overrides)

    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        TaxonomyCoverageInput(),
        _stpa_input(),
    )

    outcome = assessment.proposal_outcomes[0]
    assert outcome.status == "rejected"
    assert outcome.proposal_id == reconciliation.proposals[0].proposal_id
    assert any(
        trace.artifact_id == "correspondence-reconciliation"
        and trace.record_id == outcome.proposal_id
        for trace in outcome.trace_refs
    )
    assert assessment.scenario_realization == ()
    assert assessment.diagnostics.accepted_relations == 0


def test_missing_resource_map_is_assessed_per_obligation_resource_refs() -> None:
    """An unrelated authoritative map link cannot close an obligation's map gap."""
    inputs = make_inputs()
    plan = plan_taxonomy_obligations(inputs)
    unrelated_ref = {
        "kind": "entry_point",
        "entry_point_id": inputs.capability_snapshot.profile.entry_points[
            1
        ].entry_point_id,
    }
    unrelated_link = ResourceLink(
        link_id="srm:v1:unrelated-link",
        capability_resource_ref=unrelated_ref,
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        relation_kind="acts_on",
        provenance="operator_declared",
        evidence_refs=("review:unrelated-link",),
        confidence=1.0,
        authority_status="authoritative",
    )
    control = make_control_structure()
    unrelated_map = make_map(
        unrelated_link, snapshot=inputs.capability_snapshot, control=control
    )
    validation = validate_system_resource_map(
        unrelated_map, inputs.capability_snapshot, control
    )

    assessment = assess_hybrid_coverage(
        plan,
        validation,
        _empty_reconciliation(validation),
        TaxonomyCoverageInput(),
        _stpa_input(scenarios=False),
    )

    row = assessment.taxonomy_correspondence[0]
    assert row.correspondence_disposition == "unresolved_missing_resource_map"
    assert row.gap_reason == "missing_resource_map"


def test_contradictory_proposals_are_explicit_and_unsatisfied() -> None:
    """Conflicting proposal kinds remain a typed unresolved finding."""
    plan, resource_map = _plan_and_map()
    proposal_set, _ = _proposal_set(
        plan,
        resource_map,
        relation_kind=("same_mechanism", "mechanism_enables_ica"),
    )
    reconciliation = reconcile_correspondence(resource_map, proposal_set)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        TaxonomyCoverageInput(),
        _stpa_input(),
    )

    row = assessment.taxonomy_correspondence[0]
    assert row.correspondence_disposition == "unresolved_ambiguous"
    assert row.gap_reason == "contradictory_proposals"
    assert {item.kind for item in assessment.findings} == {"contradictory_proposals"}
    assert assessment.scenario_realization == ()


def test_structural_inapplicability_requires_reviewed_complete_evidence() -> None:
    """Absence never implies inapplicability; only an eligible decision can do so."""
    plan, resource_map = _plan_and_map()
    obligation_id = plan.obligations[0].obligation_id
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:1",
        obligation_id=obligation_id,
        rationale="No control path reaches the required resource",
        evidence_refs=("review:resource-path:1",),
        other_authoritative_evidence_refs=("review:capability-inventory:1",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:1",),
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(structural_inapplicability_decisions=(decision,)),
        _stpa_input(scenarios=False),
    )
    row = assessment.taxonomy_correspondence[0]
    assert row.correspondence_disposition == "structurally_inapplicable"
    assert row.gap_reason == "reviewed_structural_inapplicability"
    assert decision.decision_id in row.structural_inapplicability_decision_ids

    payload = decision.model_dump(mode="json")
    payload["inventory_status"] = "partial"
    payload["other_authoritative_evidence_refs"] = []
    with pytest.raises(Exception, match="partial.*authoritative"):
        StructuralInapplicabilityDecision.model_validate(payload)


def test_relevant_inferred_partial_capability_inventory_fails_closed() -> None:
    """A reviewed STPA inventory cannot turn inferred capability absence into fact."""
    plan, resource_map = _plan_and_map()
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:partial-capability",
        obligation_id=plan.obligations[0].obligation_id,
        rationale="No structural path reaches the required tool",
        evidence_refs=("review:resource-path:partial-capability",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:partial-capability",),
    )

    with pytest.raises(ValueError, match="inferred-partial capability inventory"):
        assess_hybrid_coverage(
            plan,
            resource_map,
            _empty_reconciliation(resource_map),
            TaxonomyCoverageInput(structural_inapplicability_decisions=(decision,)),
            _stpa_input(scenarios=False),
        )

    authoritative = decision.model_copy(
        update={
            "other_authoritative_evidence_refs": (
                "review:capability-non-absence:partial-capability",
            )
        }
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(structural_inapplicability_decisions=(authoritative,)),
        _stpa_input(scenarios=False),
    )
    assert (
        assessment.taxonomy_correspondence[0].correspondence_disposition
        == "structurally_inapplicable"
    )


def test_capability_inventory_completeness_is_resource_category_specific() -> None:
    """An incomplete unrelated category cannot create a false-absence failure."""
    _plan, validation = _plan_and_map()
    payload = validation.model_dump(mode="json")
    payload["tool_inventory_completeness"] = "operator_confirmed_complete"
    entry_partial = SystemResourceMapValidation.model_validate(payload)

    assert _has_inferred_relevant_inventory({"entry_point"}, entry_partial)
    assert not _has_inferred_relevant_inventory({"agent_internal"}, entry_partial)

    payload["entry_point_completeness"] = "operator_confirmed_complete"
    payload["tool_inventory_completeness"] = "inferred_partial"
    tool_partial = SystemResourceMapValidation.model_validate(payload)
    assert _has_inferred_relevant_inventory({"tool"}, tool_partial)


def test_public_assessment_revalidates_copied_resource_map_attestation() -> None:
    """A model_copy bypass cannot erase completeness before false-absence checks."""
    plan, validation = _plan_and_map()
    tampered = validation.model_copy(
        update={
            "entry_point_completeness": None,
            "tool_inventory_completeness": None,
        }
    )
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:copied-attestation",
        obligation_id=plan.obligations[0].obligation_id,
        rationale="No structural path reaches the required tool",
        evidence_refs=("review:resource-path:copied-attestation",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:copied-attestation",),
    )

    with pytest.raises(ValueError, match="inventory completeness"):
        assess_hybrid_coverage(
            plan,
            tampered,
            _empty_reconciliation(validation),
            TaxonomyCoverageInput(structural_inapplicability_decisions=(decision,)),
            _stpa_input(scenarios=False),
        )


def test_structural_inapplicability_is_pinned_to_actual_inventory_status() -> None:
    """A decision cannot relabel a partial structural inventory as complete."""
    plan, resource_map = _plan_and_map()
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:inventory-pin",
        obligation_id=plan.obligations[0].obligation_id,
        rationale="No reviewed structural path",
        evidence_refs=("review:resource-path:inventory-pin",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:inventory-pin",),
    )
    partial_stpa = StpaCoverageInput(
        slots=(_ica_slot(),), scenarios=(), inventory_status="partial"
    )
    with pytest.raises(ValueError, match="inventory status"):
        assess_hybrid_coverage(
            plan,
            resource_map,
            _empty_reconciliation(resource_map),
            TaxonomyCoverageInput(structural_inapplicability_decisions=(decision,)),
            partial_stpa,
        )

    payload = decision.model_dump(mode="json")
    payload["inventory_status"] = "partial"
    payload["other_authoritative_evidence_refs"] = ["review:external-control-path"]
    partial_decision = StructuralInapplicabilityDecision.model_validate(payload)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(structural_inapplicability_decisions=(partial_decision,)),
        partial_stpa,
    )
    assert (
        assessment.taxonomy_correspondence[0].correspondence_disposition
        == "structurally_inapplicable"
    )


def test_structural_inapplicability_cannot_override_confirmed_coverage() -> None:
    """Contradictory accepted and inapplicable claims fail closed."""
    plan, resource_map = _plan_and_map()
    reconciliation, _ = _reconcile(plan, resource_map)
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:1",
        obligation_id=plan.obligations[0].obligation_id,
        rationale="reviewed absence",
        evidence_refs=("review:1",),
        other_authoritative_evidence_refs=("review:capability-inventory:1",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:1",),
    )
    with pytest.raises(
        ValueError, match="both satisfied and structurally inapplicable"
    ):
        assess_hybrid_coverage(
            plan,
            resource_map,
            reconciliation,
            TaxonomyCoverageInput(structural_inapplicability_decisions=(decision,)),
            _stpa_input(),
        )


def test_governance_only_obligation_keeps_phase1_disposition() -> None:
    """Non-applicable Phase 1 rows remain outside the correspondence denominator."""
    plan, resource_map = _plan_and_map(include_mapping=False)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(),
        _stpa_input(scenarios=False),
    )
    row = assessment.taxonomy_correspondence[0]
    assert row.correspondence_disposition == "governance_only"
    assert row.gap_reason == "phase1_not_applicable"


def test_canonical_assessment_is_invariant_under_reordered_inputs() -> None:
    """All set-like source collections serialize independently of input order."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    taxonomy = _taxonomy_input(plan, candidate)
    extra = StructuralSlotObservation(
        slot_id=NA_SLOT,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type="WRONG_DURATION",
        disposition="justified_na",
        evidence=("review:na",),
        source_artifact=ICA_ARTIFACT,
        trace_refs=("ica.yaml#" + NA_SLOT,),
    )
    stpa = _stpa_input(extra_slots=(extra,))
    reversed_stpa = StpaCoverageInput(
        slots=tuple(reversed(stpa.slots)),
        scenarios=tuple(reversed(stpa.scenarios)),
        inventory_status="complete",
    )
    first = assess_hybrid_coverage(plan, resource_map, reconciliation, taxonomy, stpa)
    second = assess_hybrid_coverage(
        plan, resource_map, reconciliation, taxonomy, reversed_stpa
    )

    assert first.to_yaml() == second.to_yaml()
    assert type(first).from_yaml(first.to_yaml()) == first
    assert type(first).from_json(first.to_json()) == first


def test_public_seam_rejects_dangling_and_substituted_identities() -> None:
    """Scenario, slot, resource-map, and capability identities fail closed."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    dangling_taxonomy = TaxonomyCoverageInput(
        scenarios=(
            TaxonomyScenarioObservation(
                scenario_id="scenario:v2:" + "a" * 64,
                obligation_id=plan.obligations[0].obligation_id,
                candidate_id="cand:v2:" + "f" * 32,
                source_artifact=TAXONOMY_ARTIFACT,
                trace_refs=("dangling.yaml",),
            ),
        )
    )
    with pytest.raises(ValueError, match="unknown candidate"):
        assess_hybrid_coverage(
            plan, resource_map, reconciliation, dangling_taxonomy, _stpa_input()
        )

    no_slots = StpaCoverageInput(slots=(), scenarios=(), inventory_status="complete")
    with pytest.raises(ValueError, match="unknown ICA slot"):
        assess_hybrid_coverage(
            plan,
            resource_map,
            reconciliation,
            _taxonomy_input(plan, candidate),
            no_slots,
        )

    canonical_map = _canonical_map(resource_map)
    substituted_map = make_map(
        *canonical_map.links,
        capability_digest="f" * 64,
        control_digest=canonical_map.control_structure_digest,
    )
    invalid_attestation = validate_system_resource_map(
        substituted_map, make_inputs().capability_snapshot, make_control_structure()
    )
    with pytest.raises(ValueError, match="valid resource-map attestation"):
        assess_hybrid_coverage(
            plan,
            invalid_attestation,
            _empty_reconciliation(resource_map),
            TaxonomyCoverageInput(),
            _stpa_input(scenarios=False),
        )


@pytest.mark.parametrize(
    ("field", "substitute", "message"),
    (
        ("risk_id", "RISK-SUBSTITUTED", "obligation risk"),
        ("attack_pattern_id", "PATTERN-SUBSTITUTED", "attack pattern"),
        (
            "taxonomy_candidate_ids",
            ["cand:v2:" + "f" * 32],
            "taxonomy candidates",
        ),
    ),
)
def test_public_seam_rejects_accepted_taxonomy_identity_substitution(
    field: str, substitute: object, message: str
) -> None:
    """Internally supported relations still resolve to exact Phase 1 authority."""
    plan, resource_map = _plan_and_map()
    reconciliation, _candidate = _reconcile(plan, resource_map)
    payload = reconciliation.model_dump(mode="json")
    payload["semantic_digest"] = None
    payload["proposals"][0][field] = substitute
    payload["accepted_relations"][0][field] = substitute
    substituted = ReconciliationResult.model_validate(payload)

    with pytest.raises(ValueError, match=message):
        assess_hybrid_coverage(
            plan,
            resource_map,
            substituted,
            TaxonomyCoverageInput(),
            _stpa_input(),
        )


def test_assessment_fails_closed_on_capability_pin_substitution() -> None:
    plan, resource_map = _plan_and_map()
    reconciliation = _empty_reconciliation(resource_map)
    payload = reconciliation.model_dump(mode="json")
    payload["capability_snapshot_digest"] = "f" * 64
    payload["semantic_digest"] = None
    substituted = ReconciliationResult.model_validate(payload)

    with pytest.raises(ValueError, match="capability snapshot"):
        assess_hybrid_coverage(
            plan,
            resource_map,
            substituted,
            TaxonomyCoverageInput(),
            _stpa_input(scenarios=False),
        )


def test_closed_models_reconcile_rows_and_reject_false_claims() -> None:
    """Persisted rows are immutable, closed, and cannot assert unsupported credit."""
    plan, resource_map = _plan_and_map()
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        _empty_reconciliation(resource_map),
        TaxonomyCoverageInput(),
        _stpa_input(scenarios=False),
    )
    with pytest.raises(Exception):
        assessment.taxonomy_correspondence[0].gap_reason = None  # type: ignore[misc]

    extra = assessment.model_dump(mode="json")
    extra["matrix_a"] = []
    with pytest.raises(Exception):
        type(assessment).model_validate(extra)

    applicable_nonapplicable = assessment.model_dump(mode="json")
    applicable_nonapplicable["semantic_digest"] = None
    applicable_nonapplicable["taxonomy_correspondence"][0][
        "correspondence_disposition"
    ] = "governance_only"
    applicable_nonapplicable["taxonomy_correspondence"][0]["gap_reason"] = (
        "phase1_not_applicable"
    )
    with pytest.raises(ValueError, match="applicable obligation"):
        type(assessment).model_validate(applicable_nonapplicable)

    false_claim = assessment.model_dump(mode="json")
    false_claim["taxonomy_correspondence"][0]["correspondence_disposition"] = (
        "satisfied"
    )
    false_claim["semantic_digest"] = None
    with pytest.raises(Exception, match="satisfied"):
        type(assessment).model_validate(false_claim)


def test_atomic_persistence_projects_only_domain_rows(tmp_path) -> None:
    """Canonical YAML retains the three traceable denominators."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    artifact = write_hybrid_coverage_assessment(tmp_path, assessment)

    assert artifact.name == HYBRID_COVERAGE_ASSESSMENT_FILENAME
    assert HybridCoverageAssessment.from_yaml(artifact.read_bytes()) == assessment
    assert not tuple(tmp_path.glob("*.tmp"))

    tampered = deepcopy(assessment.model_dump(mode="json"))
    tampered["semantic_digest"] = "f" * 64
    with pytest.raises(ValueError, match="semantic_digest"):
        type(assessment).model_validate(tampered)


def test_every_required_domain_field_rejects_an_empty_value() -> None:
    """The normative wire contract keeps every required identity traceable."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    trace = assessment.structural_consideration[0].trace_refs[0]
    decision = StructuralInapplicabilityDecision(
        decision_id="structural-na:required-fields",
        obligation_id=plan.obligations[0].obligation_id,
        rationale="reviewed absence",
        evidence_refs=("review:required-fields",),
        adjudicated_by="operator-1",
        inventory_status="complete",
        source_artifact=DECISION_ARTIFACT,
        trace_refs=("decisions.yaml#structural-na:required-fields",),
    )
    cases = (
        (ArtifactPin, ICA_ARTIFACT, ("artifact_id", "schema_version")),
        (TraceReference, trace, ("artifact_id", "schema_version", "record_id")),
        (
            TaxonomyScenarioObservation,
            _taxonomy_input(plan, candidate).scenarios[0],
            ("scenario_id", "trace_refs"),
        ),
        (
            StructuralInapplicabilityDecision,
            decision,
            (
                "decision_id",
                "rationale",
                "evidence_refs",
                "adjudicated_by",
                "trace_refs",
            ),
        ),
        (
            StpaScenarioObservation,
            _stpa_input().scenarios[0],
            ("scenario_id", "ica_slot_id", "ica_id", "trace_refs"),
        ),
        (
            StructuralSlotObservation,
            _ica_slot(),
            (
                "slot_id",
                "controller_id",
                "control_action_id",
                "ica_ids",
                "evidence",
                "trace_refs",
            ),
        ),
        (
            StructuralConsiderationRow,
            assessment.structural_consideration[0],
            (
                "row_id",
                "slot_id",
                "controller_id",
                "control_action_id",
                "evidence",
                "source_pins",
                "trace_refs",
            ),
        ),
        (
            TaxonomyCorrespondenceRow,
            assessment.taxonomy_correspondence[0],
            ("row_id", "risk_id", "source_pins", "trace_refs"),
        ),
        (
            ScenarioRealizationRow,
            assessment.scenario_realization[0],
            (
                "row_id",
                "relation_id",
                "proposal_id",
                "obligation_id",
                "risk_id",
                "attack_pattern_id",
                "taxonomy_candidate_ids",
                "source_pins",
                "trace_refs",
            ),
        ),
    )
    for model, value, fields in cases:
        for field in fields:
            payload = value.model_dump(mode="json")
            payload[field] = [] if isinstance(payload[field], list) else ""
            with pytest.raises(Exception):
                model.model_validate(payload)

    rejected, _ = _reconcile(plan, resource_map, status="rejected")
    diagnostic = assess_hybrid_coverage(
        plan,
        resource_map,
        rejected,
        TaxonomyCoverageInput(),
        _stpa_input(),
    ).proposal_outcomes[0]
    diagnostic_cases = (
        (
            ProposalOutcome,
            diagnostic,
            (
                "risk_id",
                "attack_pattern_id",
                "taxonomy_candidate_ids",
                "ica_slot_id",
                "ica_id",
                "relation_kind",
                "trace_refs",
            ),
        ),
    )

    related, _ = _reconcile(
        plan, resource_map, relation_kind="related_but_not_coverage"
    )
    finding = assess_hybrid_coverage(
        plan,
        resource_map,
        related,
        TaxonomyCoverageInput(),
        _stpa_input(),
    ).findings[0]
    diagnostic_cases += ((CoverageFinding, finding, ("detail", "trace_refs")),)
    for model, value, fields in diagnostic_cases:
        for field in fields:
            payload = value.model_dump(mode="json")
            payload[field] = [] if isinstance(payload[field], list) else ""
            with pytest.raises(Exception):
                model.model_validate(payload)


def test_diagnostics_and_satisfied_rollup_reject_boundary_substitution() -> None:
    """Zero is valid, negatives are not, and satisfaction requires a relation."""
    plan, resource_map = _plan_and_map()
    reconciliation, candidate = _reconcile(plan, resource_map)
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    diagnostics = assessment.diagnostics.model_dump(mode="json")
    diagnostics["structural_ica"] = 0
    type(assessment.diagnostics).model_validate(diagnostics)
    diagnostics["structural_ica"] = -1
    with pytest.raises(Exception):
        type(assessment.diagnostics).model_validate(diagnostics)

    satisfied = assessment.taxonomy_correspondence[0].model_dump(mode="json")
    satisfied["accepted_relation_ids"] = []
    with pytest.raises(Exception, match="satisfied correspondence"):
        TaxonomyCorrespondenceRow.model_validate(satisfied)

    structural = assessment.structural_consideration[0].model_dump(mode="json")
    structural["slot_id"] = ""
    structural["row_id"] = compute_matrix_row_id("struct", "")
    with pytest.raises(Exception):
        StructuralConsiderationRow.model_validate(structural)


def test_representative_complete_artifact_remains_current() -> None:
    """The committed artifact uses exactly the normative matrices."""
    from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment

    artifact = HybridCoverageAssessment.from_yaml(REPRESENTATIVE_ARTIFACT.read_bytes())

    assert artifact.structural_consideration
    assert artifact.taxonomy_correspondence
    assert artifact.scenario_realization
    assert (
        artifact.to_yaml()
        == "\n".join(
            REPRESENTATIVE_ARTIFACT.read_text(encoding="utf-8").splitlines()[1:]
        )
        + "\n"
    )
