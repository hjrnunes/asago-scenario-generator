"""The request-local temporal draft requires the fields of its condition type."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _ContextTemporalConditionDraft,
)

_COMPLETE = {
    "ordering": {"reference_handle": "cause_1", "relation": "before"},
    "delay": {"reference_handle": "cause_1", "delay_ms": 500},
    "duration": {"reference_handle": "cause_1", "duration_ms": 1000},
    "window": {
        "reference_handle": "cause_1",
        "window_from_ms": 0,
        "window_to_ms": 2000,
    },
    "absence": {"reference_handle": "cause_1", "until_step_handle": "cause_2"},
}


@pytest.mark.parametrize("condition_type", sorted(_COMPLETE))
def test_complete_condition_is_accepted(condition_type: str) -> None:
    fields = _COMPLETE[condition_type]

    draft = _ContextTemporalConditionDraft(type=condition_type, **fields)

    assert draft.model_dump(exclude_none=True) == {"type": condition_type, **fields}


@pytest.mark.parametrize(
    ("condition_type", "missing"),
    [
        (condition_type, field)
        for condition_type, fields in sorted(_COMPLETE.items())
        for field in fields
    ],
)
def test_missing_required_field_is_rejected(condition_type: str, missing: str) -> None:
    fields = {
        name: value
        for name, value in _COMPLETE[condition_type].items()
        if name != missing
    }

    with pytest.raises(
        ValidationError,
        match=f"{missing} is required for the selected temporal condition",
    ):
        _ContextTemporalConditionDraft(type=condition_type, **fields)


def test_blank_string_counts_as_missing() -> None:
    with pytest.raises(ValidationError, match="until_step_handle is required"):
        _ContextTemporalConditionDraft(
            type="absence", reference_handle="cause_1", until_step_handle="   "
        )
