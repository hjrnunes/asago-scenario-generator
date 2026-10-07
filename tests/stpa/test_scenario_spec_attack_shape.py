"""ScenarioSpec carries the attack shape the shape step proposes.

The field is optional and omitted when absent, so every spec digest and dump
written before the shape step existed stays byte-identical.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.attack_shape import (
    AttackShape,
    ShapeDowngradeReason,
    ShapeSource,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from tests.stpa.helpers import make_scenario_spec


def _shape() -> AttackShape:
    return AttackShape.model_validate(
        {
            "channel": "direct",
            "turn_count": 1,
            "turn_plan": [
                {"position": 1, "speaker": "attacker_user", "purpose": "request_action"}
            ],
            "indirect": None,
            "threat_label": None,
            "source": "code_default",
            "downgrade_reason": "shape_call_failed",
        }
    )


def test_a_spec_without_a_shape_dumps_no_attack_shape_key() -> None:
    spec = make_scenario_spec()

    assert spec.attack_shape is None
    assert "attack_shape" not in spec.model_dump(mode="json")


def test_a_spec_carries_its_shape_through_a_dump_and_reload() -> None:
    spec = make_scenario_spec().model_copy(update={"attack_shape": _shape()})

    dumped = spec.model_dump(mode="json")
    reloaded = ScenarioSpec.model_validate(dumped)

    assert dumped["attack_shape"]["downgrade_reason"] == "shape_call_failed"
    assert reloaded.attack_shape == spec.attack_shape
    assert reloaded.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert (
        reloaded.attack_shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED
    )


def test_a_spec_rejects_a_shape_with_unknown_keys() -> None:
    payload = make_scenario_spec().model_dump(mode="json")
    payload["attack_shape"] = {**_shape().model_dump(mode="json"), "text": "hello"}

    with pytest.raises(ValueError):
        ScenarioSpec.model_validate(payload)
