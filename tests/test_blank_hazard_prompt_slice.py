"""A listed hazard whose description is blank stays inside the prompt slice.

A recorded OcciAI run kept hazard H-10 with a one-space description in its
final loss analysis.  Every routing, governance-routing, and ICA fill request
of that run lists H-10 among its hazards, and the pre-send reference check
rejected each one at ``hazards[1].id``: the authoritative slice held only the
identities with a non-blank description, so the hazard the request itself
lists was outside it, and no request was sent.

The requests here are the recorded OcciAI requests of
``test_obligation_prompt_bytes`` with that hazard added as recorded.  A
reference the request does not list still fails the check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from asago_scenario_generator.stpa.infra.prompt_preflight import PromptContractError
from asago_scenario_generator.stpa.models.loss_analysis import Hazard
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingRequest,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernanceRoutingRequest,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
    final_slot_universe,
)
from tests.test_obligation_prompt_bytes import _RecordingClient, _controls, _inputs

_BLANK_ADDITION = json.loads(
    (
        Path(__file__).parent
        / "fixtures"
        / "unit_loss"
        / "miniocciai-1-blank-hazard-revision.json"
    ).read_text(encoding="utf-8")
)["hazard_addition"]
_BLANK_HAZARD = Hazard(
    hazard_id="H-10",
    description=_BLANK_ADDITION["description"],
    related_losses=_BLANK_ADDITION["related_losses"],
)
_STAGES = ("route", "governance_route", "fill")


def _with_blank_hazard(inputs: dict[str, Any]) -> dict[str, Any]:
    loss = inputs["loss_analysis"]
    return {
        **inputs,
        "loss_analysis": loss.model_copy(
            update={"hazards": [*loss.hazards, _BLANK_HAZARD]}
        ),
    }


def _with_unlisted_mention(inputs: dict[str, Any]) -> dict[str, Any]:
    """Name a process-model part the structure does not hold in RESP-1's prose."""
    structure = inputs["control_structure"]
    first, *rest = structure.responsibilities
    mentioned = first.model_copy(
        update={"description": f"{first.description} It also updates PM-404."}
    )
    return {
        **inputs,
        "control_structure": structure.model_copy(
            update={"responsibilities": [mentioned, *rest]}
        ),
    }


def _call(inputs: dict[str, Any], stage: str) -> Callable[[Any], Any]:
    loss = inputs["loss_analysis"]
    structure = inputs["control_structure"]
    slots = final_slot_universe(structure)
    if stage == "route":
        request = StructuralRoutingRequest(
            batch_id="initial-batch-1",
            briefs=inputs["briefs"],
            loss_analysis=loss,
            control_structure=structure,
            slots=slots,
            controls=_controls(),
        )
        return lambda adapter: adapter.route(request)
    if stage == "governance_route":
        governance = GovernanceRoutingRequest(
            batch_id="governance-batch-1",
            briefs=inputs["governance_briefs"],
            loss_analysis=loss,
            control_structure=structure,
            slots=slots,
            controls=_controls(),
        )
        return lambda adapter: adapter.route_governance(governance)
    fill = next(
        item
        for item in build_synthesis_slot_requests(
            briefs=inputs["briefs"],
            routes=inputs["routes"],
            loss_analysis=loss,
            control_structure=structure,
            controls=_controls(),
        )
        if item.target_id == "RESP-1"
    )
    return lambda adapter: adapter.fill(fill)


def _send(tmp_path: Path, inputs: dict[str, Any], stage: str):
    """Send one request; return the requests sent and the error raised."""
    client = _RecordingClient()
    adapter = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path / stage, controls=_controls()
    )
    try:
        _call(inputs, stage)(adapter)
    except Exception as exc:  # noqa: BLE001 - the recording client never parses
        return client.requests, exc
    return client.requests, None


@pytest.mark.parametrize("stage", _STAGES)
def test_a_listed_blank_hazard_does_not_block_the_request(tmp_path, stage) -> None:
    requests, error = _send(tmp_path, _with_blank_hazard(_inputs()), stage)

    assert not isinstance(error, PromptContractError), error
    assert len(requests) == 1
    assert "H-10" in requests[0]["user_prompt"]


@pytest.mark.parametrize("stage", _STAGES)
def test_a_reference_the_request_does_not_list_still_blocks_it(tmp_path, stage) -> None:
    inputs = _with_unlisted_mention(_with_blank_hazard(_inputs()))

    requests, error = _send(tmp_path, inputs, stage)

    assert isinstance(error, PromptContractError)
    assert "'PM-404' is not in the authoritative slice" in str(error)
    assert "'H-10'" not in str(error)
    assert requests == []
