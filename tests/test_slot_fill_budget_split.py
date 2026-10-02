"""Prompt-budget splitting of slot-filling requests."""

from __future__ import annotations

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    estimate_prompt_tokens,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    candidate_id_for,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    ObligationRoute,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
    fill_synthesis_slots,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
)

_COMPLETION = 8192


def _routes_to_first_slot():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(
        make_plan(risk_ids=("risk-a", "risk-b", "risk-c")), (pattern,)
    )
    slot = create_slots(_control_structure())[0]
    routes = tuple(
        ObligationRoute(
            obligation_id=brief.obligation_id,
            disposition="targeted",
            slot_ids=(slot.slot_id,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=(f"route-{index}",),
        )
        for index, brief in enumerate(briefs)
    )
    return briefs, routes, slot


def _prompt_tokens(briefs, routes, slot) -> int:
    """Estimate the rendered single-slot prompt for the given routes."""
    request = next(
        item
        for item in build_synthesis_slot_requests(
            briefs=briefs,
            routes=routes,
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            controls=_controls(),
        )
        if slot.slot_id in {candidate.slot_id for candidate in item.slots}
    )
    route_ids = {route.obligation_id for route in routes}
    system_prompt, user_prompt = build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=(slot,),
        routed_briefs=tuple(
            brief for brief in request.routed_briefs if brief.obligation_id in route_ids
        ),
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )
    return estimate_prompt_tokens(f"{system_prompt}\n{user_prompt}")


class _Adapter:
    """Answer each part deterministically and record its routed obligations."""

    def __init__(self, usable_input_tokens: int) -> None:
        self.prompt_budget = PromptBudget(
            context_window=_COMPLETION + usable_input_tokens,
            maximum_completion_tokens=_COMPLETION,
            safety_margin=0,
        )
        self.parts: list[tuple[str, tuple[str, ...]]] = []

    def fill(self, request):
        self.parts.append(
            (
                request.slots[0].slot_id,
                tuple(route.obligation_id for route in request.routed_routes),
            )
        )
        filled = []
        considerations = []
        for slot in request.slots:
            routed = [r for r in request.routed_routes if slot.slot_id in r.slot_ids]
            filled.append(
                ICASlot(
                    slot_id=slot.slot_id,
                    responsibility=slot.responsibility,
                    coordination_link=slot.coordination_link,
                    control_action=slot.control_action,
                    uca_type=slot.uca_type,
                    is_na=not routed,
                    na_justification=None if routed else "No routed concern.",
                    icas=[
                        ICA(
                            ica_id="placeholder",
                            ica_text="The action is issued with an unsafe value.",
                            hazardous_context="The request has unsafe state.",
                            loss_scenario="The protected operation is harmed.",
                            related_hazards=["H-1"],
                            related_constraints=["SC-1"],
                        )
                    ]
                    if routed
                    else [],
                )
            )
            considerations.extend(
                ObligationIcaConsideration(
                    route_id=route.route_id,
                    obligation_id=route.obligation_id,
                    slot_id=slot.slot_id,
                    disposition="finding",
                    ica_ids=(f"{slot.slot_id}:1",),
                    exec_candidate_ids=(
                        candidate_id_for(
                            slot.responsibility, slot.control_action, slot.uca_type
                        ),
                    ),
                    hazard_ids=("H-1",),
                    constraint_ids=("SC-1",),
                    evidence=("ica-analysis",),
                )
                for route in routed
            )
        return SynthesisSlotResponse(
            request_digest=request.semantic_digest,
            filled_slots=tuple(filled),
            considerations=tuple(considerations),
        )


def _fill(adapter, briefs, routes):
    return fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )


def test_oversized_routed_slot_is_split_greedily_by_route() -> None:
    """Routes fill each part in order until the next one would not fit."""
    briefs, routes, slot = _routes_to_first_slot()
    adapter = _Adapter(_prompt_tokens(briefs, routes[:2], slot))

    result = _fill(adapter, briefs, routes)

    ids = [route.obligation_id for route in routes]
    assert [part for part in adapter.parts if part[0] == slot.slot_id] == [
        (slot.slot_id, (ids[0], ids[1])),
        (slot.slot_id, (ids[2],)),
    ]
    assert sorted(item.obligation_id for item in result.considerations) == sorted(ids)
    # Unrouted slots fit the same budget and stay one request each.
    unrouted = [part for part in adapter.parts if part[0] != slot.slot_id]
    assert unrouted and all(obligations == () for _, obligations in unrouted)
    assert len({slot_id for slot_id, _ in unrouted}) == len(unrouted)


def test_indivisible_requests_are_left_whole_for_provider_preflight() -> None:
    """A budget below one route or one slot leaves every request unchanged."""
    briefs, routes, slot = _routes_to_first_slot()
    adapter = _Adapter(1)

    _fill(adapter, briefs, routes)

    ids = tuple(route.obligation_id for route in routes)
    assert [part for part in adapter.parts if part[0] == slot.slot_id] == [
        (slot.slot_id, ids)
    ]
    # Every slot, routed or not, is still sent exactly once.
    assert len(adapter.parts) == len({slot_id for slot_id, _ in adapter.parts})
