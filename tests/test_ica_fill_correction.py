"""One fill correction names every failed rule and quotes the rejected reply."""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationRoute,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    _SlotProviderPayload,
    _validate_slot_payload_semantics,
)
from asago_scenario_generator.stpa.obligation_aware import slot_filling
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _provider_slot_request,
)
from tests.helpers.scripted_client import ScriptedClient
from tests.test_ica_fill_pair import _two_constraint_analysis

_SAFEGUARD = "ensure the request is reviewed before it is accepted"


def _route() -> ObligationRoute:
    slot = create_slots(_control_structure())[0]
    return ObligationRoute(
        obligation_id="ob:v1:" + "d" * 64,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )


def _finding(deviation: str) -> dict[str, Any]:
    return {
        "deviation": deviation,
        "hazardous_context": "an unreviewed request reaches the process",
        "loss_consequence": "the protected operation is harmed",
        "governing_pair": "SC-1/H-1",
        "process_model_refs": [],
        "feedback_refs": [],
        "context_row": None,
    }


def _reply(deviation: str, finding_index: int) -> dict[str, Any]:
    slot = create_slots(_control_structure())[0]
    return {
        "filled_slots": [
            {
                "slot_id": slot.slot_id,
                "is_na": False,
                "na_rationale": None,
                "findings": [_finding(deviation)],
                "consideration_results": {
                    "R1": {
                        "disposition": "finding",
                        "finding_indexes": [finding_index],
                        "rationale": "finding 0 expresses the routed concern",
                    }
                },
            }
        ]
    }


def _corrected(tmp_path) -> tuple[ScriptedClient, Any]:
    client = ScriptedClient(
        [
            _reply(_SAFEGUARD, 3),
            _reply("the request is accepted before it is reviewed", 0),
        ],
        model="fill-correction",
    )
    request = _provider_slot_request(routed_routes=(_route(),), validation_retries=1)
    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(request)
    return client, response


def test_the_correction_lists_every_failed_rule(tmp_path) -> None:
    client, response = _corrected(tmp_path)

    correction = client.prompts[1].split("Exact validation error", 1)[1]
    assert "finding 0: finding describes a safeguard" in correction
    assert "R1: structured consideration finding index is outside" in correction
    assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [False, True]
    assert response.filled_slots[0].icas


def test_the_correction_quotes_the_rejected_reply(tmp_path) -> None:
    client, _response = _corrected(tmp_path)

    correction = client.prompts[1]
    quoted = correction.split("Prior structured response to correct", 1)[1]
    assert _SAFEGUARD in quoted.split("Exact validation error", 1)[0]
    order = [
        "correct every failed rule the exact validation error lists below.",
        "Prior structured response to correct in place:",
        "Exact validation error from the prior response:\nValueError: 2 failed rules:",
    ]
    positions = [correction.index(marker) for marker in order]
    assert positions == sorted(positions)


def _sc1_with_h2(**changes: Any) -> IcaFindingDraft:
    return IcaFindingDraft(
        deviation=IcaDeviationDraft(incorrect_value_or_effect="a wrong value"),
        hazardous_context="an unsafe request is delayed",
        loss_consequence="the protected operation is harmed",
        related_hazard_ids=("H-2",),
        related_constraint_ids=("SC-1",),
        **changes,
    )


def test_reference_errors_name_the_valid_alternatives() -> None:
    errors = slot_filling.finding_reference_errors(
        _sc1_with_h2(process_model_refs=("PM-9",)),
        valid_process_models={"PM-1-1", "PM-1-2"},
        valid_feedback=set(),
        loss_analysis=_two_constraint_analysis(),
    )

    assert errors == [
        "constraint SC-1 does not govern the finding hazards (SC-1 governs H-1)",
        "finding references process-model parts outside the target: PM-9 "
        "(the slot may cite PM-1-1, PM-1-2)",
    ]


def test_the_raising_check_still_stops_at_the_first_reference_error() -> None:
    finding = _sc1_with_h2(process_model_refs=("PM-9",))
    with pytest.raises(ValueError, match="SC-1 governs H-1"):
        slot_filling._validate_finding_references(
            finding,
            valid_process_models=set(),
            valid_feedback=set(),
            loss_analysis=_two_constraint_analysis(),
        )


def test_semantic_errors_of_two_findings_are_reported_together() -> None:
    slot = create_slots(_control_structure())[0]
    payload = _SlotProviderPayload.model_validate(
        {
            "filled_slots": [
                {
                    "slot_id": slot.slot_id,
                    "is_na": False,
                    "findings": [_finding(_SAFEGUARD), _finding(_SAFEGUARD)],
                }
            ]
        }
    )

    with pytest.raises(ValueError) as caught:
        _validate_slot_payload_semantics(payload, _provider_slot_request())

    message = str(caught.value)
    assert f"{slot.slot_id} finding 0: finding describes a safeguard" in message
    assert f"{slot.slot_id} finding 1: finding describes a safeguard" in message
