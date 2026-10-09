"""Pin how observed interface JSON is closed into frozen containers."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.canonical import (
    FrozenDict,
    FrozenList,
    freeze_json,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    McpToolObservation,
)


def test_nested_json_closes_into_frozen_containers() -> None:
    frozen = freeze_json({"nested": [1, ("a", {"enabled": True})], "empty": None})
    assert frozen == {"nested": [1, ["a", {"enabled": True}]], "empty": None}
    assert type(frozen) is FrozenDict
    assert type(frozen["nested"]) is FrozenList
    assert type(frozen["nested"][1]) is FrozenList
    assert type(frozen["nested"][1][1]) is FrozenDict
    with pytest.raises(TypeError, match="immutable"):
        frozen["nested"][1][1]["enabled"] = False


@pytest.mark.parametrize("scalar", (None, "text", 3, 1.5, True))
def test_scalars_pass_through(scalar) -> None:
    assert freeze_json(scalar) is scalar


def test_frozen_containers_pass_through_unchanged_and_unchecked() -> None:
    opaque = object()
    frozen_dict = FrozenDict({"bad": opaque})
    frozen_list = FrozenList([opaque, float("nan")])
    assert freeze_json(frozen_dict) is frozen_dict
    assert freeze_json(frozen_list) is frozen_list
    nested = freeze_json({"inner": frozen_dict, "items": [frozen_list]})
    assert nested["inner"] is frozen_dict
    assert nested["items"][0] is frozen_list


@pytest.mark.parametrize(
    ("value", "error", "message"),
    (
        (object(), TypeError, "JSON data must contain only JSON values"),
        ({"enum": [{"value"}]}, TypeError, "JSON data must contain only JSON values"),
        (
            {"default": float("nan")},
            ValueError,
            "JSON data cannot contain NaN or infinity",
        ),
        (
            {"maximum": float("inf")},
            ValueError,
            "JSON data cannot contain NaN or infinity",
        ),
        (
            {"minimum": float("-inf")},
            ValueError,
            "JSON data cannot contain NaN or infinity",
        ),
        (
            {"allOf": [{"items": [float("inf")]}]},
            ValueError,
            "JSON data cannot contain NaN or infinity",
        ),
        ({"properties": {1: "x"}}, TypeError, "JSON mapping keys must be strings"),
    ),
)
def test_rejected_values_name_the_failure_kind(value, error, message) -> None:
    with pytest.raises(error) as raised:
        freeze_json(value)
    assert str(raised.value) == message


@pytest.mark.parametrize("scalar", (float("inf"), float("-inf"), float("nan")))
def test_non_finite_scalars_are_rejected(scalar) -> None:
    with pytest.raises(ValueError, match="NaN or infinity"):
        freeze_json(scalar)


@pytest.mark.parametrize(
    ("schema", "error", "message"),
    (
        ({"enum": [{"value"}]}, TypeError, "only JSON values"),
        ({"default": float("nan")}, ValueError, "NaN"),
        ({"maximum": float("inf")}, ValueError, "infinity"),
        ({"minimum": float("-inf")}, ValueError, "infinity"),
        ({"properties": {1: {}}}, TypeError, "keys must be strings"),
    ),
)
def test_mcp_tool_observation_closes_its_input_schema_through_it(
    schema, error, message
) -> None:
    # TargetOperationObservation's twin cases sit in
    # tests/test_target_realization.py.
    with pytest.raises(error, match=message):
        McpToolObservation(
            name="lookup", source_observation_sha256="1" * 64, input_schema=schema
        )
