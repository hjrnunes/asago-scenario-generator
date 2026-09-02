"""Automatic Phase 2 verification at the end of synthesis."""

from __future__ import annotations

from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccountingRow,
)
from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis_phase2 import (
    run_synthesis_phase2_verification,
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
from tests.system_resource_map_support import make_control_structure

SLOT_ID = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = SLOT_ID + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _artifacts():
    obligation_inputs = make_inputs()
    plan = plan_taxonomy_obligations(obligation_inputs)
    obligation = plan.obligations[0]
    loss = LossAnalysis(
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
                slot_id=SLOT_ID,
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
    consideration = ObligationIcaConsideration(
        route_id="route:review-candidate",
        obligation_id=obligation.obligation_id,
        slot_id=SLOT_ID,
        disposition="finding",
        ica_ids=(ICA_ID,),
        exec_candidate_ids=(EXEC_ID,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("synthesis:test",),
    )
    accounting = ObligationAccountingRow(
        obligation_id=obligation.obligation_id,
        disposition="addressed",
        stop_reason="addressed",
        slot_ids=(SLOT_ID,),
        ica_ids=(ICA_ID,),
        exec_candidate_ids=(EXEC_ID,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        route_refs=("route:review-candidate",),
        evidence=("synthesis:test",),
    )
    return obligation_inputs, plan, loss, enumeration, consideration, accounting


def test_synthesis_phase2_publishes_unreviewed_assessment_without_coverage(
    tmp_path,
) -> None:
    inputs, plan, loss, enumeration, consideration, accounting = _artifacts()

    result = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=make_control_structure(),
        ica_enumeration=enumeration,
        ica_considerations=(consideration,),
        accounting_rows=(accounting,),
        output_dir=tmp_path,
    )

    assert result.status == "awaiting_evidence"
    assert result.proposals.proposals
    assert all(
        proposal.relation_kind == "mechanism_enables_ica"
        for proposal in result.proposals.proposals
    )
    assert result.reconciliation.accepted_relations == ()
    assert result.assessment.diagnostics.accepted_relations == 0
    assert result.assessment.diagnostics.taxonomy_unresolved > 0
    assert set(result.artifact_paths) == {
        "system-resource-map.yaml",
        "correspondence-proposals.yaml",
        "correspondence-reconciliation.yaml",
        "hybrid-coverage-assessment.yaml",
    }
    assert all(path.exists() for path in result.artifact_paths.values())


def test_synthesis_phase2_retains_all_rows_when_no_route_can_be_proposed(
    tmp_path,
) -> None:
    inputs, plan, loss, enumeration, _consideration, _accounting = _artifacts()

    result = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=make_control_structure(),
        ica_enumeration=enumeration,
        output_dir=tmp_path,
    )

    assert result.status == "awaiting_evidence"
    assert result.proposals.proposals == ()
    assert len(result.assessment.taxonomy_correspondence) == len(plan.obligations)
    assert len(result.assessment.structural_consideration) == len(enumeration.slots)


def test_review_alone_cannot_confirm_a_route_without_resource_evidence(
    tmp_path,
) -> None:
    inputs, plan, loss, enumeration, consideration, accounting = _artifacts()
    first = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=make_control_structure(),
        ica_enumeration=enumeration,
        ica_considerations=(consideration,),
        accounting_rows=(accounting,),
        output_dir=tmp_path / "unreviewed",
    )
    decisions = AdjudicationSet(
        decisions=tuple(
            CorrespondenceAdjudication(
                proposal_id=item.proposal_id,
                status="confirmed",
                reason="Reviewed synthesis mechanism and exact STPA path",
                adjudicated_by="reviewer-1",
            )
            for item in first.proposals.proposals
        )
    )

    reviewed = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=make_control_structure(),
        ica_enumeration=enumeration,
        ica_considerations=(consideration,),
        accounting_rows=(accounting,),
        adjudications=decisions,
        output_dir=tmp_path / "reviewed",
    )

    assert reviewed.status == "awaiting_evidence"
    assert reviewed.reconciliation.accepted_relations == ()
    assert any(
        error.code == "resource_link_required"
        for error in reviewed.reconciliation.errors
    )
    assert reviewed.assessment.diagnostics.accepted_relations == 0
