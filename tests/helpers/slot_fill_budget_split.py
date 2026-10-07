"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.infra.prompt_preflight import estimate_prompt_tokens
from asago_scenario_generator.stpa.obligation_aware.contracts import ObligationRoute
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import build_neutral_briefs
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.obligation_aware import _control_structure, _controls, _loss_analysis


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
