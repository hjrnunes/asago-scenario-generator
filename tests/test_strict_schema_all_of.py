"""``allOf`` handling in the OpenAI strict-schema conversion."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import AliasChoices, AliasPath, BaseModel, Field

from asago_scenario_generator.strict_schema import (
    _field_aliases,
    strip_null_fields,
    to_openai_strict_schema,
)

_NULLABLE_INT = {"anyOf": [{"type": "integer"}, {"type": "null"}]}


def test_merge_keeps_first_required_position_across_branches() -> None:
    schema = {
        "required": ["c", "a"],
        "properties": {"c": {"type": "string"}},
        "allOf": [
            {
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["a"],
            },
            {
                "type": "object",
                "properties": {"b": {"type": "string"}},
                "required": ["b", "a"],
            },
        ],
    }

    assert to_openai_strict_schema(schema)["required"] == ["a", "b", "c"]


def test_object_branches_merge_into_one_strict_object() -> None:
    """Object-only branches flatten; the outer schema's own keys win."""
    schema = {
        "description": "Merged record.",
        "allOf": [
            {
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "required": ["a"],
            },
            {
                "type": "object",
                "properties": {"b": {"type": "integer"}, "c": {"type": "string"}},
                "required": ["a", "c"],
            },
        ],
        "properties": {"c": {"type": "boolean"}},
    }

    original = deepcopy(schema)

    result = to_openai_strict_schema(schema)

    assert schema == original
    assert result == {
        "description": "Merged record.",
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": _NULLABLE_INT,
            "c": {"type": "boolean"},
        },
        "required": ["a", "b", "c"],
        "additionalProperties": False,
    }


def test_branch_optionality_survives_and_outer_required_applies_to_outer() -> None:
    """Each branch decides its own nullability; the outer list governs its own."""
    schema = {
        "allOf": [
            {"type": "object", "properties": {"a": {"type": "integer"}}},
            {
                "type": "object",
                "properties": {"b": {"type": "integer"}},
                "required": ["b"],
            },
        ],
        "properties": {"c": {"type": "integer"}, "d": {"type": "integer"}},
        "required": ["a", "c"],
    }

    result = to_openai_strict_schema(schema)

    assert result["properties"] == {
        "a": _NULLABLE_INT,
        "b": {"type": "integer"},
        "c": {"type": "integer"},
        "d": _NULLABLE_INT,
    }
    assert result["required"] == ["a", "b", "c", "d"]


def test_non_object_branches_become_any_of() -> None:
    """A mixed intersection cannot be flattened and keeps its branches."""
    schema = {
        "allOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"type": "string"},
        ]
    }

    result = to_openai_strict_schema(schema)

    assert result == {
        "anyOf": [
            {
                "type": "object",
                "properties": {"a": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
                "required": ["a"],
                "additionalProperties": False,
            },
            {"type": "string"},
        ]
    }


def test_single_branch_absorbs_the_outer_keywords() -> None:
    """One ``allOf`` branch is inlined and the outer keywords override it."""
    schema = {
        "allOf": [{"type": "string", "description": "inner"}],
        "description": "outer",
    }

    assert to_openai_strict_schema(schema) == {
        "type": "string",
        "description": "outer",
    }


def test_strip_null_fields_keeps_collection_types_and_unknown_keys() -> None:
    class Leaf(BaseModel):
        name: str
        note: str | None = None

    class Holder(BaseModel):
        leaves: tuple[Leaf, ...] = ()
        tags: set[str] = set()
        frozen: frozenset[str] = frozenset()
        raw: dict = {}
        extra: Any = None

    payload = {
        "leaves": ({"name": "a", "note": None},),
        "tags": {"x"},
        "frozen": frozenset({"y"}),
        "raw": {"kept": None},
        "unknown": {"inner": None},
        "extra": None,
    }

    stripped = strip_null_fields(payload, Holder)

    assert stripped == {
        "leaves": ({"name": "a"},),
        "tags": {"x"},
        "frozen": frozenset({"y"}),
        "raw": {"kept": None},
        "unknown": {"inner": None},
    }
    assert isinstance(stripped["leaves"], tuple)
    assert isinstance(stripped["tags"], set)
    assert isinstance(stripped["frozen"], frozenset)


def test_strip_null_fields_rejects_a_non_model_class() -> None:
    with pytest.raises(TypeError, match="model must be a Pydantic BaseModel class"):
        strip_null_fields({}, dict)  # type: ignore[arg-type]


class _Aliased(BaseModel):
    plain: int = 0
    named: int = Field(default=0, alias="Named")
    both: int = Field(
        default=0,
        serialization_alias="bothOut",
        validation_alias=AliasChoices("both", "bothIn", AliasPath("x", 0), "bothIn"),
    )
    single: int = Field(default=0, validation_alias="singleIn")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("plain", ("plain",)),
        ("named", ("named", "Named")),
        ("both", ("both", "bothOut", "bothIn")),
        ("single", ("single", "singleIn")),
    ],
)
def test_field_aliases_list_each_provider_name_once(
    name: str, expected: tuple[str, ...]
) -> None:
    field = _Aliased.model_fields[name]

    assert _field_aliases(name, field) == expected
