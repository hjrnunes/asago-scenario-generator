"""The graph-revision `applies_when` items carry no string bound.

Probe p-schema2 sent the revision request schema to the Gemma endpoint with
`pattern: "\\S"` on each `applies_when` item.  The endpoint matches a pattern
against the whole string, so every condition came back as exactly one
character.  `minLength: 1` blocks only the empty string, and xgrammar rejects
a string schema that combines `pattern` with `minLength`.  The request schema
therefore bounds neither: the list length stays, and a blank condition reaches
the revision's blank-condition drop.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
)

_RECORDS = ("_RevisionConstraintEdit", "_RevisionConstraintAddition")
_RECORDED_EDIT = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "stpa"
        / "revision_blank_applies_when_g2_klarna.json"
    ).read_text(encoding="utf-8")
)["security_constraint_edit"]


def _sent_schema() -> dict:
    """The schema as the client sends it, after the portability rewrite."""
    return _json_schema_response_format(_Stage1aRevisionPatch)["json_schema"]["schema"]


def _nodes(node: Any) -> Iterator[dict]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _nodes(value)


@pytest.mark.parametrize("record", _RECORDS)
def test_condition_items_carry_no_pattern_because_the_endpoint_matches_the_whole_string(
    record: str,
) -> None:
    applies_when = _sent_schema()["$defs"][record]["properties"]["applies_when"]

    assert applies_when["items"] == {"type": "string"}
    assert applies_when["maxItems"] == 4
    assert not [
        node
        for node in _nodes(applies_when)
        if {"pattern", "minLength", "maxLength"} & set(node)
    ]


def test_sent_schema_is_valid_and_xgrammar_compatible() -> None:
    schema = _sent_schema()

    Draft202012Validator.check_schema(schema)
    assert not [
        node
        for node in _nodes(schema)
        if "pattern" in node and {"minLength", "maxLength"} & set(node)
    ]


@pytest.mark.parametrize(
    "conditions", [[""], [" "], ["\t\n"]], ids=["empty", "space", "tab"]
)
def test_a_blank_condition_still_parses_locally(conditions: list[str]) -> None:
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The assistant must verify the customer.",
                    "applies_when": conditions,
                    "related_hazards": ["H-1"],
                }
            ],
            "security_constraint_additions": [],
        }
    )

    assert patch.security_constraint_edits[0].applies_when == conditions


def test_the_recorded_blank_condition_edit_still_parses_locally() -> None:
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [_RECORDED_EDIT],
            "security_constraint_additions": [],
        }
    )

    assert patch.security_constraint_edits[0].applies_when == [""]
