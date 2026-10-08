"""Model output may defer ID formats to normalization through a validation context."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    ASSEMBLY_DEFERRED,
    ControlAction,
    ControlledProcess,
    CoordinationLink,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)

_MALFORMED = [
    (ResponsibilityConstraint, {"rc_id": "rc-first", "description": "d"}),
    (ProcessModelPart, {"pm_id": "PM-1", "description": "d"}),
    (ControlAction, {"ca_id": "CA-1", "description": "d"}),
    (FeedbackChannel, {"fb_id": "FB-x", "description": "d", "updates": "PM-1-1"}),
    (Responsibility, {"resp_id": "RESP-T_S", "description": "d"}),
    (ControlledProcess, {"cp_id": "CP-RESERVATIONS", "description": "d"}),
    (
        CoordinationLink,
        {
            "link_id": "CL-a",
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": "PM-1-1",
            "coordination_mechanism": {
                "cm_id": "CM-a",
                "description": "d",
                "payload": "",
            },
            "description": "d",
        },
    ),
]


@pytest.mark.parametrize(("model", "data"), _MALFORMED)
def test_malformed_ids_fail_without_the_context(model, data):
    with pytest.raises(ValidationError, match="must match format"):
        model.model_validate(data)


@pytest.mark.parametrize(("model", "data"), _MALFORMED)
def test_deferred_context_keeps_malformed_ids_as_written(model, data):
    parsed = model.model_validate(data, context=ASSEMBLY_DEFERRED)

    id_field = next(iter(data))
    assert getattr(parsed, id_field) == data[id_field]
    if model is CoordinationLink:
        assert parsed.coordination_mechanism.cm_id == "CM-a"


def test_deferred_context_still_applies_other_field_rules():
    with pytest.raises(ValidationError, match="at least 1 character"):
        ControlledProcess.model_validate(
            {"cp_id": "CP-RESERVATIONS", "description": ""},
            context=ASSEMBLY_DEFERRED,
        )


_MISTYPED = [
    (ElementRef, {"type": "user_message", "id": "RESP-1"}, "type"),
    (
        ControlAction,
        {"ca_id": "CA-1-1", "description": "d", "temporality": "x"},
        "temporality",
    ),
    (
        ControlAction,
        {"ca_id": "CA-1-1", "description": "d", "effect_kind": "x"},
        "effect_kind",
    ),
    (
        ControlAction,
        {
            "ca_id": "CA-1-1",
            "description": "d",
            "target": {"type": "responsibility", "id": "RESP-2"},
            "effect_kind": "tool_call",
        },
        "effect_kind",
    ),
]


@pytest.mark.parametrize(("model", "data", "field"), _MISTYPED)
def test_deferred_context_leaves_unknown_kinds_for_assembly(model, data, field):
    with pytest.raises(ValidationError):
        model.model_validate(data)

    parsed = model.model_validate(data, context=ASSEMBLY_DEFERRED)

    assert getattr(parsed, field) == data[field]
