"""``allOf`` handling in the OpenAI strict-schema conversion."""

from __future__ import annotations

from copy import deepcopy

from asago_scenario_generator.strict_schema import to_openai_strict_schema

_NULLABLE_INT = {"anyOf": [{"type": "integer"}, {"type": "null"}]}


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
