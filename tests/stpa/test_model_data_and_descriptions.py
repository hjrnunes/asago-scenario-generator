"""Guards for raw model copies and control-structure description rules.

``raw_model_data`` has one owner that every Stage 2 boundary shares, and the
non-empty description rule lives on the control-structure models.
"""

from __future__ import annotations

from pathlib import Path
from typing import get_args, get_origin

import pytest
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa import _model_data
from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model import id_normalization

CONTROL_STRUCTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "models"
    / "control_structure.py"
)

_DESCRIPTION_MODELS = (
    ControlAction,
    FeedbackChannel,
    Responsibility,
    ControlledProcess,
    CoordinationMechanism,
    CoordinationLink,
    ResponsibilityConstraint,
    ProcessModelPart,
)


def _placeholder_for(annotation):
    """Return a structurally valid value so only description is empty."""
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (list, tuple, set, dict):
        return origin()
    if origin is not None and type(None) in args:
        return None
    if annotation is str:
        return "x"
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        nested = {
            name: _placeholder_for(field.annotation)
            for name, field in annotation.model_fields.items()
        }
        return nested
    return None


class TestRawModelData:
    """One shared copy of raw model data serves every boundary."""

    def test_raw_copy_has_one_shared_owner(self):
        assert id_normalization.raw_model_data is _model_data.raw_model_data

    def test_raw_copy_preserves_raw_container_shapes_and_isolation(self):
        class _Nested(BaseModel):
            value: int

        opaque = bytearray(b"x")
        source = {
            "list": [{"value": 1}],
            "tuple": ("checkpoint",),
            "set": {"tag"},
            "model": _Nested(value=1),
            "opaque": opaque,
        }

        copied = raw_model_data(source)

        assert copied["list"] == [{"value": 1}]
        assert copied["tuple"] == ("checkpoint",)
        assert copied["set"] == {"tag"}
        assert copied["model"] == {"value": 1}
        assert copied["opaque"] == bytearray(b"x")
        assert copied["opaque"] is not opaque

        source["list"][0]["value"] = 2
        opaque[0] = ord("y")
        assert copied["list"] == [{"value": 1}]
        assert copied["opaque"] == bytearray(b"x")


class TestDescriptionPolicyLivesOnModels:
    """Every control-structure description field rejects empty content."""

    def test_all_description_fields_require_non_empty_text(self):
        missing: list[str] = []
        for model in _DESCRIPTION_MODELS:
            field = model.model_fields["description"]
            metadata = field.metadata
            has_min_length = any(
                getattr(constraint, "min_length", None) == 1 for constraint in metadata
            )
            if not has_min_length:
                missing.append(model.__name__)
        assert missing == [], (
            "control-structure models missing non-empty description: "
            + ", ".join(missing)
        )

    def test_control_structure_source_declares_min_length_on_descriptions(self):
        source = CONTROL_STRUCTURE_PATH.read_text(encoding="utf-8")
        assert source.count("description: str = Field(min_length=1)") == len(
            _DESCRIPTION_MODELS
        )

    @pytest.mark.parametrize("model", _DESCRIPTION_MODELS)
    def test_empty_description_fails_model_validation(self, model):
        payload = {
            name: _placeholder_for(field.annotation)
            for name, field in model.model_fields.items()
            if name != "description"
        }
        payload["description"] = ""
        with pytest.raises(ValidationError, match="description"):
            model.model_validate(payload)
