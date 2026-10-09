"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    ObligationRoute,
    SlotIcaDraft,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    mapping_strength_for_brief,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationSemanticAssessment,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots


def _control_structure(*, coordination: bool = False) -> ControlStructure:
    """Build a small valid structure that exercises responsibility routing."""
    resp = Responsibility(
        resp_id="RESP-1",
        description="Validate incoming requests.",
        responsibility_constraints=(
            ResponsibilityConstraint(
                rc_id="RC-1-1", description="Requests must be validated."
            ),
        ),
        process_model_parts=(
            ProcessModelPart(pm_id="PM-1-1", description="Request state."),
        ),
        control_actions=(
            ControlAction(
                ca_id="CA-1-1",
                description="Validate request.",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ),
        feedback_channels=(
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Request feedback.",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ),
    )
    return ControlStructure(
        responsibilities=(resp,),
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Request process."),
        ),
        coordination_links=(),
    )


def _loss_analysis() -> LossAnalysis:
    """Build authoritative hazards and security constraints for routing."""
    return LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="A protected operation is harmed.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-a",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="An unsafe request is accepted.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Requests must satisfy policy.",
                related_hazards=("H-1",),
            ),
        ),
    )


def _controls() -> AnalysisControls:
    """Return explicit deterministic controls for provider-capable seams."""
    return AnalysisControls(
        model_profile="synthesis-test",
        model_name="fake-stpa-analyst",
        deadline_seconds=30.0,
        temperature=0.0,
    )


def provider_slot_payload(draft: SlotIcaDraft) -> dict:
    """Dump a typed slot draft as the provider wire carries it.

    The wire schema gives each finding's ``deviation`` as one string; the typed
    draft nests it in a type-specific object.
    """
    payload = draft.model_dump(mode="json")
    for wire, typed in zip(payload["findings"], draft.findings, strict=True):
        wire["deviation"] = typed.deviation.text
    return payload


def route_assessment(
    brief,
    *,
    mechanism: str = "plausible_in_system",
    risk: str = "supported",
) -> ObligationSemanticAssessment:
    """Build the pair judgement a routed brief carries, with its exact strength."""
    return ObligationSemanticAssessment(
        mechanism_assessment=mechanism,
        risk_alignment=risk,
        mapping_strength=mapping_strength_for_brief(brief),
        mechanism_rationale="The supplied control path permits the mechanism.",
        risk_alignment_rationale="The mechanism can realize the reviewed risk.",
    )


_DEVIATION_FIELDS = {
    UCAType.not_provided: "not_provided_context",
    UCAType.incorrect: "incorrect_value_or_effect",
    UCAType.wrong_timing: "timing_deviation",
    UCAType.wrong_duration: "duration_deviation",
}


def _routed_slot_draft(slot, routes) -> SlotIcaDraft:
    """Answer one slot with a finding for its routed obligations, else N/A."""
    if not routes:
        return SlotIcaDraft(
            slot_id=slot.slot_id,
            is_na=True,
            na_rationale="No routed concern applies.",
        )
    return SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    **{_DEVIATION_FIELDS[slot.uca_type]: "the request is not reviewed"}
                ),
                hazardous_context="the unreviewed request reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=tuple(
            ObligationIcaDraft(
                obligation_handle=route.obligation_id,
                disposition="finding",
                finding_indexes=(0,),
                rationale="The routed concern is addressed by this finding.",
            )
            for route in routes
        ),
    )


def _provider_slot_request(
    *,
    routed_routes: tuple[ObligationRoute, ...] = (),
    validation_retries: int = 0,
) -> SynthesisSlotRequest:
    """Build one target-scoped request for provider payload contract tests."""
    slot = create_slots(_control_structure())[0]
    controls = AnalysisControls(
        model_profile="synthesis-test",
        model_name="fake-stpa-analyst",
        deadline_seconds=30.0,
        temperature=0.0,
        validation_retries=validation_retries,
    )
    return SynthesisSlotRequest(
        target_id=slot.responsibility or slot.coordination_link or "",
        target_kind="responsibility",
        slots=(slot,),
        routed_routes=routed_routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
    )
