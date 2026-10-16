"""The fill schema requires every slot field, and code drops stray indexes.

Row 104 of a recorded MiniKlarna run's calls.jsonl (gemma-4-26b-a4b-it,
producer fa33a907) gave an ``unresolved`` result ``finding_indexes``;
the provider rejected the reply for that alone, and the correction lost
the slot.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.obligation_aware.fill_reply import fill_scope
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    _required_pair_keys,
    _slot_provider_payload_type,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import _controls, _provider_slot_request
from tests.helpers.scripted_client import ScriptedClient
from tests.test_ica_fill_correction import _reply, _route


def _wire(request) -> type:
    return _slot_provider_payload_type(
        len(request.slots),
        len(_required_pair_keys(request)),
        scope=fill_scope(request),
    )


def _slot_schema(request) -> dict[str, Any]:
    schema = _wire(request).model_json_schema()
    return next(
        item
        for item in schema["$defs"].values()
        if "consideration_results" in item.get("properties", {})
    )


def _unresolved_with_indexes() -> dict[str, Any]:
    reply = _reply("the request is accepted before it is reviewed", 0)
    result = reply["filled_slots"][0]["consideration_results"]["R1"]
    result["disposition"] = "unresolved"
    result["rationale"] = "the slot does not settle the routed concern"
    return reply


def test_the_fill_schema_requires_every_slot_field() -> None:
    request = _provider_slot_request(routed_routes=(_route(),))

    required = _slot_schema(request)["required"]

    assert sorted(required) == sorted(
        ["slot_id", "is_na", "na_rationale", "findings", "consideration_results"]
    )


def test_a_reply_without_findings_or_na_rationale_fails_the_schema() -> None:
    request = _provider_slot_request(routed_routes=(_route(),))
    reply = _reply("the request is accepted before it is reviewed", 0)
    slot = reply["filled_slots"][0]
    del slot["findings"], slot["na_rationale"]

    with pytest.raises(ValidationError) as caught:
        _wire(request).model_validate(reply)

    missing = {error["loc"][-1] for error in caught.value.errors()}
    assert missing == {"findings", "na_rationale"}


def test_fill_drops_finding_indexes_from_a_non_finding_result(tmp_path) -> None:
    request = _provider_slot_request(routed_routes=(_route(),), validation_retries=0)
    client = ScriptedClient([_unresolved_with_indexes()], model="fill-shape")

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(request)

    assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [True]
    (result,) = response.considerations
    assert result.disposition == "unresolved"
    assert result.ica_ids == ()


def test_a_finding_result_still_needs_its_indexes() -> None:
    request = _provider_slot_request(routed_routes=(_route(),))
    reply = _reply("the request is accepted before it is reviewed", 0)
    reply["filled_slots"][0]["consideration_results"]["R1"]["finding_indexes"] = []

    with pytest.raises(ValidationError, match="requires finding_indexes"):
        _wire(request).model_validate(reply)
