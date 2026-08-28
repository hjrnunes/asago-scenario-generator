"""Architecture guards for policy-free unvalidated decode.

The decode layer may invent attribute-safe sentinels from type
annotations and copy a generic ``id`` onto an omitted required field
whose name ends in ``_id``.  Content-vs-ID policy and non-empty
description rules live on the control-structure models, not here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from typing import get_args, get_origin

from pydantic import BaseModel, Field, ValidationError
import pytest

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

STPA_ROOT = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
)
DECODE_PATH = STPA_ROOT / "infra" / "unvalidated_decode.py"
HELPERS_PATH = STPA_ROOT / "infra" / "llm_helpers.py"
CONTROL_STRUCTURE_PATH = STPA_ROOT / "models" / "control_structure.py"

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

_FORBIDDEN_POLICY_TOKENS = (
    "ca_id",
    "fb_id",
    "resp_id",
    "cp_id",
    "pm_id",
    "rc_id",
    "link_id",
    "cm_id",
    "description",
    "min_length",
)


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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


def _imported_names(path: Path) -> set[str]:
    tree = ast.parse(_source(path), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class TestDecodeLayerIsPolicyFree:
    """Decode helpers must not encode ID-vs-content policy."""

    def test_decode_module_does_not_name_content_or_id_fields(self):
        source = _source(DECODE_PATH)
        leaks = [token for token in _FORBIDDEN_POLICY_TOKENS if token in source]
        assert leaks == [], f"decode layer leaked field policy: {leaks}"

    def test_generic_id_alias_is_suffix_only(self):
        source = _source(DECODE_PATH)
        assert 'name.endswith("_id")' in source
        assert 'and "id" in value' in source

    def test_llm_adapter_does_not_choose_sentinels(self):
        source = _source(HELPERS_PATH)
        assert "construct_model_unvalidated" in source
        assert "_required_field_sentinel" not in source
        assert "_required_scalar_sentinel" not in source

    def test_decode_module_does_not_import_domain_models(self):
        imports = _imported_names(DECODE_PATH)
        leaks = [
            name
            for name in imports
            if name.startswith("asago_scenario_generator.stpa.models")
        ]
        assert leaks == [], f"decode layer imported domain models: {leaks}"

    def test_decode_module_does_not_import_llm_adapter(self):
        imports = _imported_names(DECODE_PATH)
        assert "asago_scenario_generator.stpa.infra.llm_helpers" not in imports
        assert "asago_scenario_generator.stpa.infra.llm" not in imports

    def test_tolerant_copy_has_one_shared_owner(self):
        from asago_scenario_generator.stpa import _model_data
        from asago_scenario_generator.stpa.infra import unvalidated_decode
        from asago_scenario_generator.stpa.system_model import id_normalization

        assert unvalidated_decode.raw_model_data is _model_data.raw_model_data
        assert id_normalization.raw_model_data is _model_data.raw_model_data

    def test_tolerant_copy_preserves_raw_container_shapes_and_isolation(self):
        from asago_scenario_generator.stpa._model_data import raw_model_data

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
        source = _source(CONTROL_STRUCTURE_PATH)
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


class TestDecodeDoesNotInspectFieldNames:
    """Sentinels depend on annotations, not on whether a field is an ID."""

    def test_identically_typed_fields_share_the_same_sentinel_path(self):
        class _TwinStrings(BaseModel):
            ca_id: str
            description: str
            count: int = 7
            target: str | None = None

        from asago_scenario_generator.stpa.infra.unvalidated_decode import (
            construct_model_unvalidated,
        )

        decoded = construct_model_unvalidated({}, _TwinStrings)
        assert decoded.ca_id == decoded.description == ""
        assert decoded.count == 7
        assert decoded.target is None

    def test_field_constraint_metadata_is_ignored_by_decode(self):
        class _Constrained(BaseModel):
            description: str = Field(min_length=1)

        from asago_scenario_generator.stpa.infra.unvalidated_decode import (
            construct_model_unvalidated,
        )

        decoded = construct_model_unvalidated({}, _Constrained)
        assert decoded.description == ""
