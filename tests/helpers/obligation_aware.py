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

    The wire schema gives each finding's ``deviation`` as one string and its
    constraints and hazards as ``governing_pairs``, and keys
    ``consideration_results`` by obligation handle; the typed draft nests the
    deviation in a type-specific object, keeps the two ID lists, and lists the
    results.
    """
    payload = draft.model_dump(mode="json")
    for wire, typed in zip(payload["findings"], draft.findings, strict=True):
        wire["deviation"] = typed.deviation.text
        wire["governing_pairs"] = wire_pairs(
            typed.related_constraint_ids, typed.related_hazard_ids
        )
        del wire["related_constraint_ids"], wire["related_hazard_ids"]
    payload["consideration_results"] = keyed_results(payload["consideration_results"])
    return payload


def wire_pairs(constraint_ids, hazard_ids, loss_analysis=None) -> list[str]:
    """Join constraints and hazards as the fill wire's governing pairs.

    With *loss_analysis*, keep each constraint with the hazards it governs, in
    written order. When those pairs leave a written ID out, or without
    *loss_analysis*, keep every constraint with every hazard, so the reply
    still names each ID and the fill validator judges the ungoverned pairs.
    """
    every = [f"{c}/{h}" for c in constraint_ids for h in hazard_ids]
    if loss_analysis is None:
        return every
    governs = {
        item.constraint_id: set(item.related_hazards)
        for item in loss_analysis.security_constraints
    }
    governed = [
        f"{c}/{h}"
        for c in constraint_ids
        for h in hazard_ids
        if h in governs.get(c, ())
    ]
    covered = {part for pair in governed for part in pair.split("/")}
    if covered != {*constraint_ids, *hazard_ids}:
        return every
    return governed


def current_fill_reply(recorded: dict, loss_analysis=None) -> dict:
    """Recast a fill reply recorded in the earlier wire in today's wire.

    Each finding's constraints and hazards become ``governing_pairs``
    (``wire_pairs``),
    and the ``consideration_results`` list becomes an object keyed by
    ``obligation_handle``; every other value is copied unchanged. A list that
    names one handle twice has no keyed form and raises ``ValueError``.
    """
    slots = []
    for slot in recorded["filled_slots"]:
        findings = []
        for finding in slot.get("findings", []):
            wire = {
                key: value
                for key, value in finding.items()
                if key not in {"related_constraint_ids", "related_hazard_ids"}
            }
            wire["governing_pairs"] = wire_pairs(
                finding["related_constraint_ids"],
                finding["related_hazard_ids"],
                loss_analysis,
            )
            findings.append(wire)
        slots.append(
            {
                **slot,
                "findings": findings,
                "consideration_results": keyed_results(
                    slot.get("consideration_results", [])
                ),
            }
        )
    return {**recorded, "filled_slots": slots}


def keyed_results(results) -> dict:
    """Key a consideration-result list by its ``obligation_handle``."""
    keyed: dict = {}
    for item in results:
        handle = item["obligation_handle"]
        if handle in keyed:
            raise ValueError(f"consideration_results names {handle} twice")
        keyed[handle] = {
            key: value for key, value in item.items() if key != "obligation_handle"
        }
    return keyed


TARGETING_FIELDS = (
    "slot_ids",
    "controller_ids",
    "control_action_ids",
    "responsibility_ids",
    "process_model_part_ids",
    "feedback_channel_ids",
    "controlled_process_ids",
    "coordination_link_ids",
    "hazard_ids",
    "constraint_ids",
)


def provider_route_payload(route: dict) -> dict:
    """Return a route dump as the routing provider wire carries it.

    The wire nests a targeted route's ID lists in its ``targeting`` object and
    has no ID list on any other route.
    """
    wire = {k: v for k, v in route.items() if k not in TARGETING_FIELDS}
    if route.get("disposition") == "targeted":
        wire["targeting"] = {k: route[k] for k in TARGETING_FIELDS if k in route}
    return wire


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
