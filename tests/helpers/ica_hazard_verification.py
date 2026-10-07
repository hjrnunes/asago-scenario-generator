"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaConstraintContext,
    IcaHazardContext,
    IcaHazardVerificationRequest,
    IcaLossContext,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def _request() -> IcaHazardVerificationRequest:
    return IcaHazardVerificationRequest(
        slot_id="RESP-1:CA-1:INCORRECT",
        ica_id="RESP-1:CA-1:INCORRECT:1",
        responsibility_id="RESP-1",
        responsibility_description="The controller maintains the release gate.",
        control_action_id="CA-1",
        control_action_description="Approve a release for the controlled process.",
        uca_type="INCORRECT",
        uca_definition="The control action is provided in an unsafe form.",
        deviation="Approve a release without checking the release gate.",
        hazardous_context="The release gate is not satisfied.",
        loss_consequence="An unsafe release reaches the production process.",
        hazards=(
            IcaHazardContext(
                hazard_id="H-1",
                description="An unsafe release is accepted.",
                related_loss_ids=("L-1",),
            ),
        ),
        constraints=(
            IcaConstraintContext(
                constraint_id="SC-1",
                description="The release gate must be satisfied before approval.",
                related_hazard_ids=("H-1",),
            ),
        ),
        losses=(
            IcaLossContext(loss_id="L-1", description="Production integrity is lost."),
        ),
    )


def _stpa_inputs() -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Integrity loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1", description="Unsafe release", related_losses=["L-1"]
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Gate releases",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Release controller",
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Approve release",
                        target={"type": "controlled_process", "id": "CP-1"},
                    )
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Production")
        ],
    )
    slot = ICASlot(
        slot_id="RESP-1:CA-1-1:INCORRECT",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type="INCORRECT",
        is_na=False,
        icas=[
            ICA(
                ica_id="RESP-1:CA-1-1:INCORRECT:1",
                ica_text="Approve without the gate",
                hazardous_context="The gate is unsatisfied",
                loss_scenario="Integrity is lost",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
            ICA(
                ica_id="RESP-1:CA-1-1:INCORRECT:2",
                ica_text="Approve with the gate",
                hazardous_context="The gate is unsatisfied",
                loss_scenario="Integrity is lost",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
        ],
    )
    return ICAEnumeration(slots=[slot]), loss_analysis, control_structure


def _single_ica_inputs() -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    slot = enumeration.slots[0].model_copy(
        update={"icas": [enumeration.slots[0].icas[0]]}
    )
    return (
        enumeration.model_copy(update={"slots": [slot]}),
        loss_analysis,
        control_structure,
    )


def _finding_pair(enumeration: ICAEnumeration) -> ObligationIcaConsideration:
    slot = enumeration.slots[0]
    ica = slot.icas[0]
    return ObligationIcaConsideration(
        route_id="route:ica-verification-test",
        obligation_id="ob:v1:" + "a" * 64,
        slot_id=slot.slot_id,
        disposition="finding",
        ica_ids=(ica.ica_id,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=tuple(ica.related_hazards),
        constraint_ids=tuple(ica.related_constraints),
        evidence=("ica-verification:test",),
        rationale="The STPA finding selects the exact ICA.",
    )
