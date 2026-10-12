"""A targeted route carries its structural placement in one ``targeting`` object.

The routing request schema is sent flat, so every field a single disposition
uses becomes nullable.  The placement lists of a targeted route sit in one
object so that only the object, not each list, can be null: once a model
writes the object, the schema itself requires at least one slot, hazard, and
constraint.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.request_schema import (
    portable_request_schema,
    restore_flat_reply_for,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _materialize_routing_route,
    _routing_provider_payload_type,
)

_OB = "ob:v1:" + "0" * 64
_PAYLOAD = _routing_provider_payload_type(1)
_REQUIRED_LISTS = ("slot_ids", "hazard_ids", "constraint_ids")
_OPTIONAL_LISTS = (
    "controller_ids",
    "control_action_ids",
    "responsibility_ids",
    "process_model_part_ids",
    "feedback_channel_ids",
    "controlled_process_ids",
    "coordination_link_ids",
)
_TARGETING = {
    "slot_ids": ["RESP-1:CA-1-1:NOT_PROVIDED"],
    "controller_ids": ["RESP-1"],
    "control_action_ids": ["CA-1-1"],
    "responsibility_ids": ["RESP-1"],
    "process_model_part_ids": [],
    "feedback_channel_ids": [],
    "controlled_process_ids": ["CP-1"],
    "coordination_link_ids": [],
    "hazard_ids": ["H-1"],
    "constraint_ids": ["SC-1"],
}


def _flat_route(disposition: str, **fields: Any) -> dict[str, Any]:
    return {
        "routes": [
            {
                "obligation_id": _OB,
                "semantic_assessment": {
                    "mechanism_assessment": "plausible_in_system",
                    "risk_alignment": "supported",
                    "mechanism_rationale": "The path exists.",
                    "risk_alignment_rationale": "It realizes the risk.",
                },
                "rationale": "Why this disposition.",
                "evidence": ["RESP-1 handles refunds."],
                "disposition": disposition,
                "targeting": None,
                "missing_concepts": None,
                **fields,
            }
        ]
    }


def _parse(reply: dict[str, Any]) -> Any:
    return _PAYLOAD.model_validate(restore_flat_reply_for(_PAYLOAD, reply))


def _flat_schema() -> tuple[dict[str, Any], dict[str, Any]]:
    schema = portable_request_schema(_PAYLOAD.model_json_schema())
    return schema["properties"]["routes"]["items"], schema.get("$defs", {})


def test_the_flat_route_has_one_nullable_targeting_object_and_no_loose_lists() -> None:
    route, _ = _flat_schema()
    assert "targeting" in route["required"]
    for name in (*_REQUIRED_LISTS, *_OPTIONAL_LISTS):
        assert name not in route["properties"]
    options = route["properties"]["targeting"]["anyOf"]
    assert {"type": "null"} in options
    assert len(options) == 2


def test_the_targeting_object_requires_non_empty_slot_hazard_and_constraint_lists() -> (
    None
):
    route, defs = _flat_schema()
    (ref,) = [o for o in route["properties"]["targeting"]["anyOf"] if "$ref" in o]
    targeting = defs[ref["$ref"].rsplit("/", 1)[-1]]
    assert set(targeting["required"]) == set(_REQUIRED_LISTS)
    for name in _REQUIRED_LISTS:
        field = targeting["properties"][name]
        assert field["type"] == "array"
        assert field["minItems"] == 1
        assert "anyOf" not in field
    for name in _OPTIONAL_LISTS:
        assert targeting["properties"][name]["type"] == "array"
        assert "anyOf" not in targeting["properties"][name]


def test_a_targeted_route_materializes_its_targeting_lists_on_the_route() -> None:
    payload = _parse(_flat_route("targeted", targeting=_TARGETING))
    route = _materialize_routing_route(
        payload.routes[0], mapping_strength="direct_curated_pair"
    )
    for name, value in _TARGETING.items():
        assert getattr(route, name) == tuple(value)
    assert route.disposition == "targeted"


def test_a_targeted_route_with_null_targeting_fails_as_missing() -> None:
    with pytest.raises(ValidationError) as caught:
        _parse(_flat_route("targeted"))
    errors = caught.value.errors()
    assert [e["type"] for e in errors] == ["missing"]
    assert errors[0]["loc"][-1] == "targeting"


@pytest.mark.parametrize("name", _REQUIRED_LISTS)
def test_a_targeting_object_with_an_empty_required_list_fails(name: str) -> None:
    with pytest.raises(ValidationError):
        _parse(_flat_route("targeted", targeting={**_TARGETING, name: []}))


@pytest.mark.parametrize("disposition", ["proposed_not_applicable", "unresolved"])
def test_a_route_of_another_disposition_leaves_targeting_null(disposition: str) -> None:
    payload = _parse(_flat_route(disposition))
    route = _materialize_routing_route(
        payload.routes[0], mapping_strength="direct_curated_pair"
    )
    assert route.disposition == disposition
    assert route.slot_ids == ()
