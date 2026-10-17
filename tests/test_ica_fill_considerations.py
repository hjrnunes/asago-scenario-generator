"""A fill reply gives each routed obligation exactly one consideration result.

The fixture is row 81 of a recorded MiniKlarna run's calls.jsonl
(gemma-4-26b-a4b-it, producer fa33a907): one slot, six routed obligations,
and a reply that lists every handle three times with conflicting R4
dispositions. The provider accepted it because it compared pair sets, and the
contract rejected it after the request had ended, with no correction.

The fixture names each evidence source by its path inside the policy
repository rather than by the recording machine's absolute path. The routed
briefs' digests and ``source.request_semantic_digest`` are recomputed for that
change; the other ``source`` fields describe the recorded row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.fill_reply import fill_scope
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    local_obligation_handles,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _listed_results,
    _required_pair_keys,
    _resolve_slot_handles,
    _slot_provider_payload_type,
    _SlotProviderPayload,
    _validate_slot_provider_payload,
)
from tests.helpers.obligation_aware import current_fill_reply, wire_pairs

_FIXTURE = Path(__file__).parent / "fixtures" / "ica_fill" / "miniklarna-2-row81.json"


def _fixture() -> tuple[SynthesisSlotRequest, dict[str, Any]]:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    request = SynthesisSlotRequest.model_validate(raw["request"])
    assert request.semantic_digest == raw["source"]["request_semantic_digest"]
    return request, raw["reply"]


def _pair_form(reply: dict[str, Any]) -> dict[str, Any]:
    """Give each finding its governing pair; leave the result list as recorded."""
    slots = []
    for slot in reply["filled_slots"]:
        findings = []
        for finding in slot["findings"]:
            wire = {
                key: value
                for key, value in finding.items()
                if key not in {"related_constraint_ids", "related_hazard_ids"}
            }
            wire["governing_pairs"] = wire_pairs(
                finding["related_constraint_ids"], finding["related_hazard_ids"]
            )
            findings.append(wire)
        slots.append({**slot, "findings": findings})
    return {"filled_slots": slots}


def _validate(request: SynthesisSlotRequest, payload: Any) -> None:
    by_local = {
        handle: obligation_id
        for obligation_id, handle in local_obligation_handles(
            request.routed_routes
        ).items()
    }
    _validate_slot_provider_payload(
        _resolve_slot_handles(payload, by_local),
        expected_slot_ids=frozenset(slot.slot_id for slot in request.slots),
        expected_pair_keys=_required_pair_keys(request),
        request=request,
    )


def test_duplicate_obligation_pairs_fail_in_the_provider_validator() -> None:
    request, reply = _fixture()
    payload = _SlotProviderPayload.model_validate(_pair_form(reply))

    with pytest.raises(ValueError, match="more than once"):
        _validate(request, payload)


def _keyed_schema(request: SynthesisSlotRequest) -> dict[str, Any]:
    wire = _slot_provider_payload_type(
        len(request.slots),
        len(_required_pair_keys(request)),
        scope=fill_scope(request),
    )
    schema = wire.model_json_schema()
    slot = next(
        item
        for item in schema["$defs"].values()
        if "consideration_results" in item.get("properties", {})
    )
    reference = slot["properties"]["consideration_results"]["$ref"]
    return schema["$defs"][reference.rsplit("/", 1)[1]]


def test_the_fill_schema_keys_consideration_results_by_handle() -> None:
    request, _reply = _fixture()

    keyed = _keyed_schema(request)

    handles = ["R1", "R2", "R3", "R4", "R5", "R6"]
    assert list(keyed["properties"]) == handles
    assert keyed["required"] == handles
    assert keyed["additionalProperties"] is False
    result = keyed["properties"]["R4"]
    assert "obligation_handle" not in json.dumps(result)


def _first_results(reply: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keyed: dict[str, dict[str, Any]] = {}
    for item in reply["filled_slots"][0]["consideration_results"]:
        body = {key: value for key, value in item.items() if key != "obligation_handle"}
        keyed.setdefault(item["obligation_handle"], body)
    return keyed


def test_a_keyed_reply_yields_one_result_per_handle() -> None:
    request, reply = _fixture()
    wire = _slot_provider_payload_type(
        len(request.slots),
        len(_required_pair_keys(request)),
        scope=fill_scope(request),
    )
    keyed = _pair_form(reply)
    keyed["filled_slots"][0]["consideration_results"] = _first_results(reply)

    payload = _listed_results(wire.model_validate(keyed))
    _validate(request, payload)

    results = payload.filled_slots[0].consideration_results
    assert [item.obligation_handle for item in results] == [
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
    ]
    assert results[3].disposition == "finding"
    assert results[3].finding_indexes == (0,)


def test_a_keyed_reply_without_one_handle_fails_the_schema() -> None:
    request, reply = _fixture()
    wire = _slot_provider_payload_type(
        len(request.slots),
        len(_required_pair_keys(request)),
        scope=fill_scope(request),
    )
    keyed = _pair_form(reply)
    results = _first_results(reply)
    del results["R6"]
    keyed["filled_slots"][0]["consideration_results"] = results

    with pytest.raises(ValueError, match="R6"):
        wire.model_validate(keyed)


def test_a_recorded_list_that_repeats_a_handle_has_no_keyed_form() -> None:
    _request, reply = _fixture()

    with pytest.raises(ValueError, match="R1"):
        current_fill_reply(reply)
