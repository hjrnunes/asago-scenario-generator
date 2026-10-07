"""``$ref`` handling in the OpenAI strict-schema conversion.

A strict schema cannot keep keywords next to a ``$ref``; the conversion
inlines a resolvable, non-recursive local reference under its siblings.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, Field

from asago_scenario_generator.strict_schema import (
    _resolve_ref,
    to_openai_strict_schema,
)


class _Leaf(BaseModel):
    value: str


class _Holder(BaseModel):
    leaf: _Leaf = Field(description="The one leaf.")


def _unrefed(schema: dict[str, Any]) -> dict[str, Any]:
    return schema["properties"]["leaf"]


def test_a_model_field_with_a_description_inlines_its_reference() -> None:
    schema = to_openai_strict_schema(_Holder)

    leaf = _unrefed(schema)
    assert "$ref" not in leaf
    assert leaf["description"] == "The one leaf."
    assert leaf["properties"] == {"value": {"title": "Value", "type": "string"}}
    assert leaf["required"] == ["value"]
    assert leaf["additionalProperties"] is False


def test_ref_siblings_win_over_the_referenced_schema() -> None:
    source = {
        "$defs": {
            "Thing": {
                "type": "object",
                "description": "From the definition.",
                "properties": {"a": {"type": "string"}},
                "required": ["a"],
            }
        },
        "type": "object",
        "properties": {
            "thing": {"$ref": "#/$defs/Thing", "description": "From the field."}
        },
        "required": ["thing"],
    }

    thing = to_openai_strict_schema(source)["properties"]["thing"]

    assert thing["description"] == "From the field."
    assert thing["properties"] == {"a": {"type": "string"}}


def test_a_bare_reference_is_left_for_the_provider_to_resolve() -> None:
    source = {
        "$defs": {"Thing": {"type": "object", "properties": {}}},
        "type": "object",
        "properties": {"thing": {"$ref": "#/$defs/Thing"}},
        "required": ["thing"],
    }

    assert to_openai_strict_schema(source)["properties"]["thing"] == {
        "$ref": "#/$defs/Thing"
    }


@pytest.mark.parametrize(
    "reference",
    ("https://example.test/schema.json", "#/$defs/Missing", "#/$defs/Thing/nope"),
)
def test_an_unresolvable_reference_drops_its_siblings(reference: str) -> None:
    source = {
        "$defs": {"Thing": {"type": "string"}},
        "type": "object",
        "properties": {"thing": {"$ref": reference, "description": "dropped"}},
        "required": ["thing"],
    }

    assert to_openai_strict_schema(source)["properties"]["thing"] == {"$ref": reference}


def test_a_recursive_reference_with_siblings_stays_a_bare_leaf() -> None:
    """Inlining a reference to a schema being inlined would never end."""
    source = {
        "$defs": {
            "Tree": {
                "type": "object",
                "properties": {
                    "child": {
                        "$ref": "#/$defs/Tree",
                        "description": "dropped to end the recursion",
                    }
                },
                "required": ["child"],
            }
        },
        "$ref": "#/$defs/Tree",
    }

    schema = to_openai_strict_schema(source)

    assert schema["properties"]["child"] == {"$ref": "#/$defs/Tree"}
    assert schema["$defs"]["Tree"]["properties"]["child"] == {"$ref": "#/$defs/Tree"}


def test_resolve_ref_walks_a_local_pointer_and_unescapes_components() -> None:
    root = {"$defs": {"a/b": {"c~d": {"type": "string"}}}}

    assert _resolve_ref(root, "#/$defs/a~1b/c~0d") == {"type": "string"}


@pytest.mark.parametrize(
    "reference",
    ("other.json#/x", "#/missing", "#/$defs/a~1b/c~0d/deeper"),
)
def test_resolve_ref_returns_none_when_the_pointer_does_not_resolve(
    reference: str,
) -> None:
    root = {"$defs": {"a/b": {"c~d": {"type": "string"}}}}

    assert _resolve_ref(root, reference) is None
