"""The scenario-handoff-v5 envelope and its required ``attack_shape`` key.

The producer emits v5 through its one handoff model. These tests pin the
constants, the pairing of ``kind`` with the shape (R7), the digest domain,
null-preserving serialization, and the JSON schema a schema-only reader uses.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.models import attack_shape as shape_module
from asago_scenario_generator.stpa.models.attack_shape import ShapeSource
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    _FORBIDDEN_KEYS,
    HANDOFF_DIGEST_DOMAIN_V5,
    HANDOFF_SCHEMA_VERSION_V5,
    ScenarioHandoffV5,
    finalize_handoff,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
)

KIT_VALID = (
    Path(__file__).resolve().parents[2]
    / "data/contracts/scenario-handoff/handoff-v5/valid"
)
OTHER_VERSION_CODES = [
    "schema_violation:schema_version",
    "schema_violation:attack_shape",
]


DIRECT_SHAPE: dict[str, Any] = {
    "channel": "direct",
    "turn_count": 1,
    "turn_plan": [
        {"position": 1, "speaker": "attacker_user", "purpose": "request_action"}
    ],
    "indirect": None,
    "threat_label": None,
    "source": "code_default",
    "downgrade_reason": None,
}


def _kit_payload(name: str, shape: dict[str, Any] | None) -> dict[str, Any]:
    """Return a kit payload with *shape* as its shape, without its digest."""

    payload = json.loads((KIT_VALID / f"{name}.json").read_text(encoding="utf-8"))
    payload["attack_shape"] = copy.deepcopy(shape)
    payload.pop("content_digest")
    return payload


def _adversarial(shape: dict[str, Any] | None = DIRECT_SHAPE) -> dict[str, Any]:
    return _kit_payload("adversarial-observed-record", shape)


def _functional(shape: dict[str, Any] | None = None) -> dict[str, Any]:
    return _kit_payload("functional-not-called", shape)


def test_constants_name_v5() -> None:
    assert HANDOFF_SCHEMA_VERSION_V5 == "scenario-handoff-v5"
    assert HANDOFF_DIGEST_DOMAIN_V5 == "scenario-handoff-v5"


@pytest.mark.parametrize(
    "version", ["scenario-handoff-v4", "scenario-handoff-v9", None], ids=str
)
def test_any_other_version_gets_the_kits_unknown_version_codes(
    version: str | None,
) -> None:
    payload = _adversarial()
    if version is None:
        del payload["schema_version"]
    else:
        payload["schema_version"] = version

    assert handoff_schema_violations(payload) == OTHER_VERSION_CODES


def test_the_envelope_accepts_a_shape_for_adversarial_and_null_for_functional() -> None:
    assert handoff_schema_violations(_adversarial()) == []
    assert handoff_schema_violations(_functional()) == []


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        (_adversarial(None), "adversarial without a shape"),
        (_functional(DIRECT_SHAPE), "functional with a shape"),
    ],
    ids=["adversarial-null", "functional-shape"],
)
def test_r7_pairs_the_scenario_kind_with_the_shape(
    payload: dict[str, Any], label: str
) -> None:
    with pytest.raises(ValueError, match=r"\bR7\b"):
        ScenarioHandoffV5.model_validate(payload)
    assert handoff_schema_violations(payload) == ["schema_violation:<root>"], label


def test_attack_shape_is_a_required_key() -> None:
    payload = _adversarial()
    del payload["attack_shape"]

    assert handoff_schema_violations(payload) == ["schema_violation:attack_shape"]


def test_a_malformed_shape_is_reported_under_attack_shape() -> None:
    payload = _adversarial({**DIRECT_SHAPE, "turn_count": 2})

    assert handoff_schema_violations(payload) == ["schema_violation:attack_shape"]


def test_a_bound_status_requires_a_tool_call_condition() -> None:
    payload = _adversarial()
    del payload["tool_call_condition"]

    assert handoff_schema_violations(payload) == ["schema_violation:<root>"]


def test_a_finalized_handoff_keeps_null_shape_values_in_the_digested_payload() -> None:
    adversarial = finalize_handoff(ScenarioHandoffV5.model_validate(_adversarial()))
    functional = finalize_handoff(ScenarioHandoffV5.model_validate(_functional()))

    payload = adversarial.model_dump(mode="json", exclude_none=True)
    assert payload["attack_shape"] == DIRECT_SHAPE
    assert functional.model_dump(mode="json", exclude_none=True)["attack_shape"] is None


def test_the_digest_uses_its_own_domain_and_verifies() -> None:
    handoff = finalize_handoff(ScenarioHandoffV5.model_validate(_adversarial()))
    payload = handoff.model_dump(mode="json", exclude_none=True)
    payload.pop("content_digest")

    assert handoff.content_digest == compute_framed_digest(
        HANDOFF_DIGEST_DOMAIN_V5, payload
    )
    assert handoff.content_digest == handoff_payload_digest(payload)
    verify_handoff_digest(handoff)


def test_a_finalized_payload_round_trips_through_the_model() -> None:
    handoff = finalize_handoff(ScenarioHandoffV5.model_validate(_adversarial()))
    dumped = handoff.model_dump(mode="json", exclude_none=True)

    again = ScenarioHandoffV5.model_validate(dumped)

    assert again == handoff
    verify_handoff_digest(again)


def test_a_tampered_shape_fails_digest_verification() -> None:
    handoff = finalize_handoff(ScenarioHandoffV5.model_validate(_adversarial()))
    tampered = handoff.model_copy(
        update={
            "attack_shape": handoff.attack_shape.model_copy(
                update={"source": ShapeSource.STAGE5_VALIDATED}
            )
        }
    )

    with pytest.raises(ValueError, match="content_digest"):
        verify_handoff_digest(tampered)


def test_a_valid_payload_passes_the_ownership_scan() -> None:
    payload = _adversarial()
    payload["attack_shape"] = {
        **DIRECT_SHAPE,
        "channel": "indirect",
        "turn_count": 2,
        "turn_plan": [
            {"position": 1, "speaker": "benign_user", "purpose": "ask_to_read_item"},
            {"position": 2, "speaker": "benign_user", "purpose": "follow_up_on_item"},
        ],
        "indirect": {
            "carrier_operation": "get_listing",
            "data_item": {"content_kind": "listing_content", "record_ref": "LST-104"},
            "party_relation": {
                "controller": "third_party",
                "benign_user_actor_ref": "GST001",
            },
        },
    }

    assert handoff_ownership_violations(payload) == []
    assert handoff_schema_violations(payload) == []


def _schema_keys(node: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            keys.update(properties)
        for value in node.values():
            keys |= _schema_keys(value)
    elif isinstance(node, list):
        for value in node:
            keys |= _schema_keys(value)
    return keys


def test_no_schema_key_name_is_forbidden_by_the_ownership_scan() -> None:
    keys = _schema_keys(ScenarioHandoffV5.model_json_schema())

    assert {"attack_shape", "channel", "turn_plan", "carrier_operation"} <= keys
    assert not {key.lower() for key in keys} & _FORBIDDEN_KEYS
    assert not {name.lower() for name in _shape_field_names()} & _FORBIDDEN_KEYS


def _shape_field_names() -> set[str]:
    return {
        name
        for model in (
            shape_module.AttackShape,
            shape_module.TurnShape,
            shape_module.IndirectShape,
            shape_module.PlantedItem,
            shape_module.PartyRelation,
        )
        for name in model.model_fields
    }


def test_the_schema_requires_the_shape_and_carries_its_pairings() -> None:
    schema = ScenarioHandoffV5.model_json_schema()

    assert schema["title"] == "ScenarioHandoff"
    assert schema["properties"]["schema_version"]["const"] == HANDOFF_SCHEMA_VERSION_V5
    assert (
        schema["properties"]["schema_version"]["default"] == HANDOFF_SCHEMA_VERSION_V5
    )
    assert "attack_shape" in schema["required"]
    assert schema["additionalProperties"] is False
    assert {"if", "then", "else"}.isdisjoint(schema)
    assert len(schema["allOf"]) == 2
    assert {"AttackShape", "TurnShape", "IndirectShape"} <= set(schema["$defs"])
    key = schema["$defs"]["ScenarioDeduplicationKey"]
    assert "constraint_ids" in key["properties"]
    assert "constraint_ids" not in key["required"]


def _schema_errors(payload: dict[str, Any]) -> list[Any]:
    return list(
        Draft202012Validator(ScenarioHandoffV5.model_json_schema()).iter_errors(payload)
    )


def _finalized(payload: dict[str, Any]) -> dict[str, Any]:
    return finalize_handoff(ScenarioHandoffV5.model_validate(payload)).model_dump(
        mode="json", exclude_none=True
    )


def test_the_json_schema_accepts_valid_payloads_and_enforces_the_pairings() -> None:
    assert _schema_errors(_finalized(_adversarial())) == []
    assert _schema_errors(_finalized(_functional())) == []
    assert _schema_errors(_adversarial(None))
    assert _schema_errors(_functional(DIRECT_SHAPE))
    missing_condition = _adversarial()
    del missing_condition["tool_call_condition"]
    assert _schema_errors(missing_condition)
    missing_shape = _adversarial()
    del missing_shape["attack_shape"]
    assert _schema_errors(missing_shape)
