"""Slot prompts name each obligation with a short request-local handle."""

from __future__ import annotations

import re

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
)
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
)
from tests.test_slot_fill_budget_split import _routes_to_first_slot

_FULL_HANDLE = re.compile(r"(ob|route):v1:[0-9a-f]{64}")


def _na_answer(slot_id: str, handles) -> dict:
    return {
        "filled_slots": [
            {
                "slot_id": slot_id,
                "is_na": True,
                "na_rationale": "No routed concern applies.",
                "findings": [],
                "consideration_results": [
                    {
                        "obligation_handle": handle,
                        "disposition": "proposed_not_applicable",
                        "rationale": "The structure excludes it.",
                    }
                    for handle in handles
                ],
            }
        ]
    }


class _ScriptedClient:
    model = "scripted-slot-handles"

    def __init__(self, answers) -> None:
        self.answers = list(answers)
        self.user_prompts: list[str] = []

    def complete(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        return LLMResult(
            content=self.answers[len(self.user_prompts) - 1],
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def test_slot_prompt_shows_short_handles_and_no_content_addressed_ids() -> None:
    """Questions, routes, and required pairs carry R1..Rn, never a 64-hex handle."""
    briefs, routes, slot = _routes_to_first_slot()
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

    _system, user = build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=(slot,),
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )

    assert not _FULL_HANDLE.search(user)
    shown = re.findall(r"obligation_handle: (\S+)", user)
    assert shown[:3] == ["R1", "R2", "R3"]
    assert set(shown) == {"R1", "R2", "R3"}


def test_local_handles_map_back_to_the_routed_obligations(tmp_path) -> None:
    """A response that copies R1..Rn resolves to the supplied obligation ids."""
    _briefs, routes, _slot = _routes_to_first_slot()
    request = _provider_slot_request(routed_routes=routes)
    order = sorted(route.obligation_id for route in routes)
    client = _ScriptedClient([_na_answer(request.slots[0].slot_id, ["R1", "R2", "R3"])])

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=request.controls
    ).fill(request)

    assert len(client.user_prompts) == 1
    assert sorted(item.obligation_id for item in response.considerations) == order
    assert {item.disposition for item in response.considerations} == {
        "proposed_not_applicable"
    }


def test_unknown_local_handle_gets_exact_feedback_in_local_terms(tmp_path) -> None:
    """A handle the prompt never showed is repaired with a message naming R-handles."""
    _briefs, routes, _slot = _routes_to_first_slot()
    request = _provider_slot_request(routed_routes=routes, validation_retries=1)
    slot_id = request.slots[0].slot_id
    client = _ScriptedClient(
        [
            _na_answer(slot_id, ["R1", "R2", "R9"]),
            _na_answer(slot_id, ["R1", "R2", "R3"]),
        ]
    )

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=request.controls
    ).fill(request)

    assert len(client.user_prompts) == 2
    repair = client.user_prompts[1]
    assert "R9" in repair and "R3" in repair
    assert not _FULL_HANDLE.search(repair)
    assert len(response.considerations) == 3
