"""Request schemas carry no object union: each becomes one flat object.

GLM's structured-output endpoint decodes a ``oneOf`` by always taking its last
branch, so the producer sends every object union as one object whose
discriminator is an enum of every branch's values.  These tests pin the merge
rule on synthetic unions; ``test_schema_union_guard.py`` pins the production
response types.
"""

from __future__ import annotations

import copy
import json
from typing import Annotated, Any, Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.request_schema import portable_request_schema
from asago_scenario_generator.schema_unions import (
    UnionMergeError,
    find_unions,
    flatten_unions,
)

_NULL = {"type": "null"}


def _union_schema(*branches: dict[str, Any], key: str = "oneOf", **extra: Any):
    return {
        "type": "object",
        "properties": {"item": {key: list(branches), **extra}},
        "required": ["item"],
    }


def _obj(properties: dict[str, Any], required: list[str], **extra: Any):
    return {"type": "object", "properties": properties, "required": required, **extra}


def test_a_schema_without_a_union_comes_out_unchanged() -> None:
    schema = {
        "type": "object",
        "properties": {
            "a": {"anyOf": [{"type": "string"}, _NULL], "title": "A"},
            "b": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            "c": {"$ref": "#/$defs/C"},
        },
        "$defs": {"C": _obj({"x": {"type": "string"}}, ["x"])},
    }
    before = json.dumps(schema)
    out = flatten_unions(schema)
    assert out is schema
    assert json.dumps(out) == before
    assert find_unions(schema) == []


def test_a_oneof_is_a_union_and_an_anyof_needs_two_object_branches() -> None:
    nullable_ref = {"anyOf": [{"$ref": "#/$defs/C"}, _NULL]}
    two_objects = {"anyOf": [{"$ref": "#/$defs/C"}, _obj({}, [])]}
    schema = {
        "type": "object",
        "properties": {
            "one": {"oneOf": [{"type": "string"}]},
            "nullable": nullable_ref,
            "two": two_objects,
        },
        "$defs": {"C": _obj({"x": {"type": "string"}}, ["x"])},
    }
    assert find_unions(schema) == ["/properties/one", "/properties/two"]


def test_the_discriminator_becomes_one_enum_in_branch_order() -> None:
    schema = _union_schema(
        _obj(
            {"kind": {"enum": ["a", "b"], "type": "string", "title": "Kind"}},
            ["kind"],
        ),
        _obj({"kind": {"const": "c", "type": "string"}}, ["kind"]),
        discriminator={"propertyName": "kind"},
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert "oneOf" not in item and "discriminator" not in item
    assert item["type"] == "object"
    assert item["properties"]["kind"] == {
        "title": "Kind",
        "type": "string",
        "enum": ["a", "b", "c"],
    }
    assert item["required"] == ["kind"]


def test_a_shared_identical_property_keeps_its_schema_and_required_ness() -> None:
    shared = {"type": "string", "minLength": 1, "description": "Why."}
    schema = _union_schema(
        _obj(
            {"kind": {"const": "a", "type": "string"}, "why": shared, "opt": shared},
            ["kind", "why"],
        ),
        _obj(
            {"kind": {"const": "b", "type": "string"}, "why": shared, "opt": shared},
            ["kind", "why", "opt"],
        ),
        discriminator={"propertyName": "kind"},
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert item["properties"]["why"] == shared
    assert item["properties"]["opt"] == shared
    assert item["required"] == ["kind", "why"]


def test_a_branch_only_property_becomes_nullable_and_required_with_a_sentence() -> None:
    schema = _union_schema(
        _obj(
            {
                "kind": {"const": "a", "type": "string"},
                "x": {
                    "type": "integer",
                    "title": "X",
                    "description": "How many.",
                    "default": 0,
                },
            },
            ["kind"],
        ),
        _obj({"kind": {"const": "b", "type": "string"}}, ["kind"]),
        _obj(
            {
                "kind": {"const": "c", "type": "string"},
                "x": {
                    "type": "integer",
                    "title": "X",
                    "description": "How many.",
                    "default": 0,
                },
            },
            ["kind", "x"],
        ),
        discriminator={"propertyName": "kind"},
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert item["properties"]["x"] == {
        "anyOf": [{"type": "integer"}, _NULL],
        "title": "X",
        "description": "How many. Applies when `kind` is `a` or `c`; null otherwise.",
    }
    assert item["required"] == ["kind", "x"]


def test_a_branch_only_property_that_is_already_nullable_keeps_its_anyof() -> None:
    nullable = {"anyOf": [{"type": "string"}, _NULL], "default": None, "title": "S"}
    schema = _union_schema(
        _obj({"kind": {"const": "a", "type": "string"}, "s": nullable}, ["kind"]),
        _obj({"kind": {"const": "b", "type": "string"}}, ["kind"]),
        discriminator={"propertyName": "kind"},
    )
    prop = flatten_unions(schema)["properties"]["item"]["properties"]["s"]
    assert prop == {
        "anyOf": [{"type": "string"}, _NULL],
        "title": "S",
        "description": "Applies when `kind` is `a`; null otherwise.",
    }


def test_a_property_and_its_nullable_form_merge_to_the_nullable_form() -> None:
    schema = _union_schema(
        _obj(
            {
                "kind": {"enum": ["x", "y"], "type": "string"},
                "gain": {"minLength": 1, "title": "Gain", "type": "string"},
            },
            ["kind", "gain"],
        ),
        _obj(
            {
                "kind": {"const": "none", "type": "string"},
                "gain": {
                    "anyOf": [{"minLength": 1, "type": "string"}, _NULL],
                    "default": None,
                    "title": "Gain",
                },
            },
            ["kind"],
        ),
        discriminator={"propertyName": "kind"},
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert item["properties"]["gain"] == {
        "anyOf": [{"minLength": 1, "type": "string"}, _NULL],
        "title": "Gain",
    }
    assert item["required"] == ["kind", "gain"]


def test_string_choices_merge_into_one_enum_across_refs() -> None:
    schema = {
        "type": "object",
        "properties": {
            "item": {
                "anyOf": [
                    _obj({"effect": {"const": "msg", "type": "string"}}, ["effect"]),
                    _obj({"effect": {"$ref": "#/$defs/Effect"}}, ["effect"]),
                ]
            }
        },
        "$defs": {
            "Effect": {
                "enum": ["out", "msg", "call"],
                "type": "string",
                "title": "Effect",
                "description": "What the action does.",
            }
        },
    }
    out = flatten_unions(schema)
    assert out["properties"]["item"]["properties"]["effect"] == {
        "description": "What the action does.",
        "type": "string",
        "enum": ["msg", "out", "call"],
    }
    assert "$defs" not in out


def test_object_properties_merge_recursively() -> None:
    schema = {
        "type": "object",
        "properties": {
            "item": {
                "anyOf": [
                    _obj({"target": {"$ref": "#/$defs/A"}}, ["target"]),
                    _obj({"target": {"$ref": "#/$defs/B"}}, ["target"]),
                ]
            }
        },
        "$defs": {
            "A": _obj(
                {"type": {"const": "a", "type": "string"}, "id": {"type": "string"}},
                ["type", "id"],
                title="A",
            ),
            "B": _obj(
                {"type": {"const": "b", "type": "string"}, "id": {"type": "string"}},
                ["type", "id"],
                title="B",
            ),
        },
    }
    target = flatten_unions(schema)["properties"]["item"]["properties"]["target"]
    assert target == {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["a", "b"]},
            "id": {"type": "string"},
        },
        "required": ["type", "id"],
    }


def test_any_other_conflict_stops_the_union_with_both_schemas() -> None:
    schema = _union_schema(
        _obj(
            {"kind": {"const": "a", "type": "string"}, "v": {"type": "string"}},
            ["kind"],
        ),
        _obj(
            {"kind": {"const": "b", "type": "string"}, "v": {"type": "integer"}},
            ["kind"],
        ),
        discriminator={"propertyName": "kind"},
    )
    with pytest.raises(UnionMergeError) as caught:
        flatten_unions(schema)
    message = str(caught.value)
    assert "/properties/item" in message and "'v'" in message
    assert "{'type': 'string'}" in message and "{'type': 'integer'}" in message


def test_a_union_with_a_non_object_branch_stops() -> None:
    schema = {
        "type": "object",
        "properties": {"item": {"oneOf": [{"type": "string"}, _obj({}, [])]}},
    }
    with pytest.raises(UnionMergeError, match="not an object"):
        flatten_unions(schema)


def test_property_order_follows_first_appearance_in_branch_order() -> None:
    schema = _union_schema(
        _obj(
            {"kind": {"const": "a", "type": "string"}, "p": {"type": "string"}},
            ["kind", "p"],
        ),
        _obj(
            {
                "q": {"type": "string"},
                "kind": {"const": "b", "type": "string"},
                "p": {"type": "string"},
            },
            ["kind", "q", "p"],
        ),
        discriminator={"propertyName": "kind"},
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert list(item["properties"]) == ["kind", "p", "q"]
    assert item["required"] == ["kind", "p", "q"]


def test_nested_unions_flatten_and_unused_defs_are_removed() -> None:
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "oneOf": [{"$ref": "#/$defs/Cmp"}, {"$ref": "#/$defs/Never"}],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {"cmp": "#/$defs/Cmp", "never": "#/$defs/Never"},
                    },
                },
            },
        },
        "$defs": {
            "Arg": _obj(
                {
                    "source": {"const": "arg", "type": "string"},
                    "name": {"type": "string"},
                },
                ["source", "name"],
            ),
            "Lit": _obj(
                {
                    "source": {"const": "lit", "type": "string"},
                    "value": {"$ref": "#/$defs/Scalar"},
                },
                ["source", "value"],
            ),
            "Scalar": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            "Cmp": _obj(
                {
                    "kind": {"const": "cmp", "type": "string"},
                    "left": {
                        "oneOf": [{"$ref": "#/$defs/Arg"}, {"$ref": "#/$defs/Lit"}],
                        "discriminator": {"propertyName": "source"},
                        "title": "Left",
                    },
                },
                ["kind", "left"],
                additionalProperties=False,
            ),
            "Never": _obj(
                {"kind": {"const": "never", "type": "string"}},
                ["kind"],
                additionalProperties=False,
            ),
            "Unused": _obj({}, []),
        },
    }
    original = copy.deepcopy(schema)
    out = flatten_unions(schema)
    assert schema == original
    assert find_unions(out) == []
    item = out["properties"]["items"]["items"]
    assert item["additionalProperties"] is False
    # ``left`` belongs to the ``cmp`` branch only, so it is nullable.
    assert item["properties"]["left"]["title"] == "Left"
    left = item["properties"]["left"]["anyOf"][0]
    assert left["properties"]["source"]["enum"] == ["arg", "lit"]
    assert left["properties"]["value"]["anyOf"][0] == {"$ref": "#/$defs/Scalar"}
    assert list(out["$defs"]) == ["Scalar"]


def test_branch_descriptions_stay_on_the_flat_object() -> None:
    schema = _union_schema(
        _obj({"kind": {"const": "a", "type": "string"}}, ["kind"], description="An a."),
        _obj(
            {"kind": {"enum": ["b", "c"], "type": "string"}},
            ["kind"],
            description="A b or c.",
        ),
        discriminator={"propertyName": "kind"},
        description="One item.",
    )
    item = flatten_unions(schema)["properties"]["item"]
    assert item["description"] == (
        "One item.\nWhen `kind` is `a`: An a.\nWhen `kind` is `b` or `c`: A b or c."
    )


def test_an_undiscriminated_branch_description_appears_once() -> None:
    schema = _union_schema(
        _obj({"x": {"const": "a", "type": "string"}}, ["x"], description="Same."),
        _obj({"x": {"const": "b", "type": "string"}}, ["x"], description="Same."),
        key="anyOf",
    )
    assert flatten_unions(schema)["properties"]["item"]["description"] == "Same."


def test_a_nullable_union_flattens_inside_its_anyof() -> None:
    inner = {
        "oneOf": [
            _obj({"type": {"const": "a", "type": "string"}}, ["type"]),
            _obj(
                {"type": {"const": "b", "type": "string"}, "n": {"type": "integer"}},
                ["type", "n"],
            ),
        ],
        "discriminator": {"propertyName": "type"},
    }
    schema = {
        "type": "object",
        "properties": {"t": {"anyOf": [inner, _NULL], "title": "T"}},
    }
    prop = flatten_unions(schema)["properties"]["t"]
    assert prop["title"] == "T"
    assert prop["anyOf"][1] == _NULL
    assert prop["anyOf"][0]["properties"]["type"]["enum"] == ["a", "b"]
    assert find_unions(prop) == []


class _Fact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["fact"]
    path: str = Field(min_length=1, pattern=r"^T\.")


class _Lit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["literal"]
    value: str


class _Pair(BaseModel):
    left: Annotated[_Fact | _Lit, Field(discriminator="source")]


def test_portable_request_schema_flattens_after_its_pattern_rewrite() -> None:
    out = portable_request_schema(_Pair.model_json_schema())
    left = out["properties"]["left"]
    assert find_unions(out) == []
    assert left["properties"]["path"]["anyOf"][0] == {
        "pattern": r"^T\.",
        "type": "string",
    }
    assert "$defs" not in out
