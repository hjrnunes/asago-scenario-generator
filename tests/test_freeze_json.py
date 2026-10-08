"""Characterize how observed interface JSON is closed into frozen containers."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.canonical import FrozenDict, FrozenList
from asago_scenario_generator.models.target_realization import _freeze_interface_json
from asago_scenario_generator.stpa.models.execution_classification import _freeze_json

FREEZERS = (_freeze_json, _freeze_interface_json)


@pytest.mark.parametrize("freeze", FREEZERS)
def test_nested_json_closes_into_frozen_containers(freeze) -> None:
    frozen = freeze({"nested": [1, ("a", {"enabled": True})], "empty": None})
    assert frozen == {"nested": [1, ["a", {"enabled": True}]], "empty": None}
    assert type(frozen) is FrozenDict
    assert type(frozen["nested"]) is FrozenList
    assert type(frozen["nested"][1]) is FrozenList
    assert type(frozen["nested"][1][1]) is FrozenDict
    with pytest.raises(TypeError, match="immutable"):
        frozen["nested"][1][1]["enabled"] = False


@pytest.mark.parametrize("freeze", FREEZERS)
@pytest.mark.parametrize("scalar", (None, "text", 3, 1.5, True))
def test_scalars_pass_through(freeze, scalar) -> None:
    assert freeze(scalar) is scalar


@pytest.mark.parametrize("freeze", FREEZERS)
def test_frozen_containers_pass_through_unchanged_and_unchecked(freeze) -> None:
    opaque = object()
    frozen_dict = FrozenDict({"bad": opaque})
    frozen_list = FrozenList([opaque, float("nan")])
    assert freeze(frozen_dict) is frozen_dict
    assert freeze(frozen_list) is frozen_list
    assert (
        freeze({"inner": frozen_dict, "items": [frozen_list]})["inner"] is frozen_dict
    )
    assert freeze({"items": [frozen_list]})["items"][0] is frozen_list


@pytest.mark.parametrize("freeze", FREEZERS)
def test_rejected_values_keep_their_exception_types(freeze) -> None:
    with pytest.raises(TypeError, match="only JSON values"):
        freeze(object())
    with pytest.raises(TypeError, match="only JSON values"):
        freeze({"enum": [{"value"}]})
    with pytest.raises(ValueError, match="NaN"):
        freeze({"default": float("nan")})
    with pytest.raises(TypeError, match="keys must be strings"):
        freeze({"properties": {1: {"type": "string"}}})


@pytest.mark.parametrize("freeze", FREEZERS)
def test_infinity_is_not_rejected_here(freeze) -> None:
    assert freeze({"maximum": float("inf")}) == {"maximum": float("inf")}
