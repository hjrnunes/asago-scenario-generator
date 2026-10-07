"""The scenario-handoff-v4 envelope: v3 plus the required ``attack_shape`` key.

The producer still emits v3. These tests pin what v4 adds: the constants, the
pairing of ``kind`` with the shape (R7), the digest domain, null-preserving
serialization, and the JSON schema a schema-only reader uses.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.scenario_prod import attack_shape as shape_module
from asago_scenario_generator.stpa.scenario_prod.attack_shape import ShapeSource
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    _FORBIDDEN_KEYS,
    HANDOFF_DIGEST_DOMAIN,
    HANDOFF_DIGEST_DOMAIN_V4,
    HANDOFF_DIGEST_DOMAINS,
    HANDOFF_SCHEMA_VERSION,
    HANDOFF_SCHEMA_VERSION_V4,
    HANDOFF_SCHEMA_VERSIONS,
    ScenarioHandoff,
    ScenarioHandoffV4,
    finalize_handoff,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
)

V3_VALID = (
    Path(__file__).resolve().parents[2]
    / "data/contracts/scenario-handoff/handoff-v3/valid"
)

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


def _v4(name: str, shape: dict[str, Any] | None) -> dict[str, Any]:
    """Return a v3 kit payload re-versioned as v4, without its digest."""

    payload = json.loads((V3_VALID / f"{name}.json").read_text(encoding="utf-8"))
    payload["schema_version"] = HANDOFF_SCHEMA_VERSION_V4
    payload["attack_shape"] = copy.deepcopy(shape)
    payload.pop("content_digest")
    return payload


def _adversarial(shape: dict[str, Any] | None = DIRECT_SHAPE) -> dict[str, Any]:
    return _v4("adversarial-observed-record", shape)


def _functional(shape: dict[str, Any] | None = None) -> dict[str, Any]:
    return _v4("functional-not-called", shape)


def test_constants_name_v4_and_leave_v3_as_the_emitted_version() -> None:
    assert HANDOFF_SCHEMA_VERSION_V4 == "scenario-handoff-v4"
    assert HANDOFF_DIGEST_DOMAIN_V4 == "scenario-handoff-v4"
    assert HANDOFF_SCHEMA_VERSION == "scenario-handoff-v3"
    assert HANDOFF_DIGEST_DOMAIN == "scenario-handoff-v3"
    assert HANDOFF_SCHEMA_VERSIONS[-1] == HANDOFF_SCHEMA_VERSION_V4
    assert HANDOFF_DIGEST_DOMAINS[HANDOFF_SCHEMA_VERSION_V4] == HANDOFF_DIGEST_DOMAIN_V4


def test_the_v3_model_still_refuses_an_attack_shape() -> None:
    assert "attack_shape" not in ScenarioHandoff.model_fields
    payload = _adversarial()
    payload["schema_version"] = HANDOFF_SCHEMA_VERSION

    assert handoff_schema_violations(payload) == ["schema_violation:attack_shape"]


def test_v4_accepts_a_shape_for_adversarial_and_null_for_functional() -> None:
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
        ScenarioHandoffV4.model_validate(payload)
    assert handoff_schema_violations(payload) == ["schema_violation:<root>"], label


def test_attack_shape_is_a_required_key() -> None:
    payload = _adversarial()
    del payload["attack_shape"]

    assert handoff_schema_violations(payload) == ["schema_violation:attack_shape"]


def test_a_malformed_shape_is_reported_under_attack_shape() -> None:
    payload = _adversarial({**DIRECT_SHAPE, "turn_count": 2})

    assert handoff_schema_violations(payload) == ["schema_violation:attack_shape"]


def test_v4_keeps_the_v3_tool_call_pairing() -> None:
    payload = _adversarial()
    del payload["tool_call_condition"]

    assert handoff_schema_violations(payload) == ["schema_violation:<root>"]


def test_finalized_v4_keeps_null_shape_values_in_the_digested_payload() -> None:
    adversarial = finalize_handoff(ScenarioHandoffV4.model_validate(_adversarial()))
    functional = finalize_handoff(ScenarioHandoffV4.model_validate(_functional()))

    payload = adversarial.model_dump(mode="json", exclude_none=True)
    assert payload["attack_shape"] == DIRECT_SHAPE
    assert adversarial.canonical_payload()["attack_shape"] == DIRECT_SHAPE
    assert functional.model_dump(mode="json", exclude_none=True)["attack_shape"] is None
    assert "attack_shape" in functional.canonical_payload()


def test_v4_digest_uses_its_own_domain_and_verifies() -> None:
    handoff = finalize_handoff(ScenarioHandoffV4.model_validate(_adversarial()))
    payload = handoff.model_dump(mode="json", exclude_none=True)
    payload.pop("content_digest")

    assert handoff.content_digest == compute_framed_digest(
        HANDOFF_DIGEST_DOMAIN_V4, payload
    )
    assert handoff.content_digest == handoff_payload_digest(payload)
    assert handoff.content_digest != compute_framed_digest(
        HANDOFF_DIGEST_DOMAIN, payload
    )
    verify_handoff_digest(handoff)


def test_a_finalized_v4_payload_round_trips_through_the_model() -> None:
    handoff = finalize_handoff(ScenarioHandoffV4.model_validate(_adversarial()))
    dumped = handoff.model_dump(mode="json", exclude_none=True)

    again = ScenarioHandoffV4.model_validate(dumped)

    assert again == handoff
    verify_handoff_digest(again)


def test_a_tampered_shape_fails_digest_verification() -> None:
    handoff = finalize_handoff(ScenarioHandoffV4.model_validate(_adversarial()))
    tampered = handoff.model_copy(
        update={
            "attack_shape": handoff.attack_shape.model_copy(
                update={"source": ShapeSource.STAGE5_VALIDATED}
            )
        }
    )

    with pytest.raises(ValueError, match="content_digest"):
        verify_handoff_digest(tampered)


def test_a_valid_v4_payload_passes_the_ownership_scan() -> None:
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


def test_no_v4_key_name_is_forbidden_by_the_ownership_scan() -> None:
    v3_keys = _schema_keys(ScenarioHandoff.model_json_schema())
    v4_only = _schema_keys(ScenarioHandoffV4.model_json_schema()) - v3_keys

    assert {"attack_shape", "channel", "turn_plan", "carrier_operation"} <= v4_only
    assert not {key.lower() for key in v4_only} & _FORBIDDEN_KEYS
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


def test_the_v4_schema_differs_from_v3_only_where_the_design_says() -> None:
    v3 = ScenarioHandoff.model_json_schema()
    v4 = ScenarioHandoffV4.model_json_schema()

    assert v4["title"] == v3["title"] == "ScenarioHandoff"
    assert v4["properties"]["schema_version"]["const"] == HANDOFF_SCHEMA_VERSION_V4
    assert v4["properties"]["schema_version"]["default"] == HANDOFF_SCHEMA_VERSION_V4
    assert v4["required"] == [*v3["required"], "attack_shape"]
    assert v4["additionalProperties"] is False
    assert {"if", "then", "else"}.isdisjoint(v4)
    assert len(v4["allOf"]) == 2
    assert {"AttackShape", "TurnShape", "IndirectShape"} <= set(v4["$defs"])
    unchanged = {
        name: definition
        for name, definition in v3["$defs"].items()
        if v4["$defs"].get(name) != definition
    }
    assert unchanged == {}
    other = {
        key: value
        for key, value in v4["properties"].items()
        if key not in {"schema_version", "attack_shape"}
    }
    assert other == {
        key: value for key, value in v3["properties"].items() if key != "schema_version"
    }


def _schema_errors(payload: dict[str, Any]) -> list[Any]:
    return list(
        Draft202012Validator(ScenarioHandoffV4.model_json_schema()).iter_errors(payload)
    )


def _finalized(payload: dict[str, Any]) -> dict[str, Any]:
    return finalize_handoff(ScenarioHandoffV4.model_validate(payload)).model_dump(
        mode="json", exclude_none=True
    )


def test_the_v4_json_schema_accepts_valid_payloads_and_enforces_the_pairings() -> None:
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
