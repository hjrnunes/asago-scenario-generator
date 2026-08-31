"""Vertical contract tests for the source-spec §8.7 hybrid facade."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
)
from asago_scenario_generator.models.hybrid_coverage import TaxonomyCoverageInput
from asago_scenario_generator.models.hybrid_reconciliation import (
    HybridReconciliationInputs,
)
from asago_scenario_generator.pipeline.correspondence import propose_correspondence
from asago_scenario_generator.pipeline.hybrid_reconciliation import (
    reconcile_taxonomy_and_stpa,
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
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.helpers.obligation_factory import make_inputs
from tests.system_resource_map_support import (
    make_control_structure,
    make_link,
    make_map,
)

ICA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _source_artifacts():
    obligation_inputs = make_inputs()
    plan = plan_taxonomy_obligations(obligation_inputs)
    control = make_control_structure()
    obligation = plan.obligations[0]
    selected_candidate, selected_binding = next(
        (candidate, binding)
        for candidate in obligation.candidate_records
        for binding in candidate.resource_bindings
        if binding.resource_ref.kind == "tool"
    )
    resource_ref = selected_binding.resource_ref.model_dump(mode="json")
    resource_map = make_map(
        make_link(capability_resource_ref=resource_ref),
        snapshot=obligation_inputs.capability_snapshot,
        control=control,
    )
    validation = validate_system_resource_map(
        resource_map, obligation_inputs.capability_snapshot, control
    )
    loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Payment loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=[obligation.risk_ref.risk_id],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constrain payment",
                related_hazards=["H-1"],
            )
        ],
    )
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
                        ica_text="Payment occurs at the wrong time",
                        hazardous_context="Payment pending",
                        loss_scenario="Payment is lost",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            )
        ]
    )
    authority = CorrespondenceAuthority.from_artifacts(
        resource_map, plan, control, enumeration, loss_analysis
    )
    authority_obligation = authority.obligations[0]
    finding = authority.structural_findings[0]
    evidence = CorrespondenceEvidence(
        obligation_id=authority_obligation.obligation_id,
        risk_id=authority_obligation.risk_id,
        attack_pattern_id=authority_obligation.attack_pattern_id,
        taxonomy_candidate_ids=authority_obligation.taxonomy_candidate_ids,
        selected_candidate_id=selected_candidate.candidate_id,
        ica_slot_id=finding.ica_slot_id,
        ica_id=finding.ica_id,
        exec_candidate_id=finding.exec_candidate_id,
        relation_kind="same_mechanism",
        resource_link_ids=finding.resource_link_ids,
        hazard_ids=finding.hazard_ids,
        constraint_ids=("SC-1",),
        evidence_source="exact_id",
        evidence_refs=("id:obligation", "id:ica"),
        confidence=1.0,
        evidence_strength="high",
        proposer_id="exact-id-v1",
        proposer_version="1",
        source_pins=authority.source_pins,
        rationale="exact reviewed identities",
    )
    proposals = propose_correspondence(
        validation,
        CorrespondenceSourceArtifacts(authority=authority, evidence=(evidence,)),
    )
    adjudications = AdjudicationSet(
        decisions=(
            CorrespondenceAdjudication(
                proposal_id=proposals.proposals[0].proposal_id,
                status="confirmed",
                reason="reviewed exact evidence",
                adjudicated_by="operator-1",
            ),
        )
    )
    return {
        "obligation_plan": plan,
        "loss_analysis": loss_analysis,
        "control_structure": control,
        "ica_enumeration": enumeration,
        "resource_map_validation": validation,
        "correspondence_proposals": proposals,
        "adjudications": adjudications,
        "taxonomy_scenarios": TaxonomyCoverageInput(),
    }


def test_facade_reconciles_and_constructs_all_three_matrices() -> None:
    inputs = HybridReconciliationInputs(**_source_artifacts())

    assessment = reconcile_taxonomy_and_stpa(inputs)

    assert assessment.diagnostics.accepted_relations == 1
    assert len(assessment.structural_consideration) == 1
    assert assessment.taxonomy_correspondence[0].correspondence_disposition == (
        "satisfied"
    )
    assert len(assessment.scenario_realization) == 1
    assert assessment.network_calls == assessment.model_calls == 0
    assert (
        assessment.capability_snapshot_digest
        == inputs.obligation_plan.capability_snapshot_digest
    )


def test_facade_rejects_proposals_pinned_to_another_capability_snapshot() -> None:
    fields = _source_artifacts()
    proposals = fields["correspondence_proposals"]
    substituted = proposals.model_copy(
        update={"capability_snapshot_digest": "f" * 64, "semantic_digest": None}
    )
    substituted = substituted.model_copy(
        update={"semantic_digest": substituted.compute_semantic_digest()}
    )
    inputs = HybridReconciliationInputs(**fields).model_copy(
        update={"correspondence_proposals": substituted}
    )

    with pytest.raises(ValueError, match="capability snapshot"):
        reconcile_taxonomy_and_stpa(inputs)


def test_facade_fails_closed_when_proposal_authority_pins_other_artifacts() -> None:
    fields = _source_artifacts()
    loss = fields["loss_analysis"]
    fields["loss_analysis"] = loss.model_copy(
        update={
            "risk_card_losses": [
                loss.risk_card_losses[0].model_copy(
                    update={"description": "Substituted loss content"}
                )
            ]
        }
    )

    with pytest.raises(ValueError, match="proposal authority does not match"):
        reconcile_taxonomy_and_stpa(HybridReconciliationInputs(**fields))


def test_facade_preserves_uncertainty_without_explicit_adjudication() -> None:
    fields = _source_artifacts()
    fields["adjudications"] = AdjudicationSet()

    assessment = reconcile_taxonomy_and_stpa(HybridReconciliationInputs(**fields))

    assert assessment.diagnostics.accepted_relations == 0
    assert assessment.diagnostics.unresolved_proposals == 1
    assert assessment.taxonomy_correspondence[0].correspondence_disposition == (
        "unresolved_ambiguous"
    )


@pytest.mark.parametrize(
    "updates",
    (
        {"is_valid": False},
        {"canonical_map": None},
    ),
)
def test_facade_requires_successful_validated_map_attestation(updates) -> None:
    fields = _source_artifacts()
    fields["resource_map_validation"] = fields["resource_map_validation"].model_copy(
        update=updates
    )

    with pytest.raises(ValueError, match="valid resource-map attestation"):
        reconcile_taxonomy_and_stpa(HybridReconciliationInputs(**fields))


def test_facade_rejects_non_envelope_calls() -> None:
    with pytest.raises(TypeError, match="HybridReconciliationInputs"):
        reconcile_taxonomy_and_stpa(object())


def test_facade_binds_structural_inventory_completeness_into_authority() -> None:
    fields = _source_artifacts()
    fields["structural_inventory_status"] = "unknown"

    with pytest.raises(ValueError, match="proposal authority does not match"):
        reconcile_taxonomy_and_stpa(HybridReconciliationInputs(**fields))


def test_facade_input_is_closed_immutable_and_requires_typed_artifacts() -> None:
    fields = _source_artifacts()
    with pytest.raises(ValidationError, match="extra_forbidden"):
        HybridReconciliationInputs(**fields, prose="infer a match")

    inputs = HybridReconciliationInputs(**fields)
    with pytest.raises(ValidationError, match="frozen"):
        inputs.structural_inventory_status = "unknown"

    with pytest.raises(ValidationError):
        HybridReconciliationInputs(**(fields | {"ica_enumeration": {"slots": []}}))

    with pytest.raises(ValidationError, match="typed StpaScenarioObservation"):
        HybridReconciliationInputs(**(fields | {"stpa_scenarios": ({},)}))

    with pytest.raises(ValidationError, match="typed StpaScenarioObservation"):
        HybridReconciliationInputs(**(fields | {"stpa_scenarios": object()}))

    with pytest.raises(ValidationError, match="typed mapping"):
        HybridReconciliationInputs.model_validate("free-form prose")
