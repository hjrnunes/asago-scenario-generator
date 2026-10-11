"""Each graph-revision `applies_when` entry must hold a non-blank character.

The revision request schema gives every `applies_when` item of a constraint
edit and addition the pattern `\\S`. It does not use `minLength`: a length of
one still admits a lone space, and xgrammar rejects a string schema that
combines `pattern` with `minLength` or `maxLength`. The bound lives in the
request schema only, so a reply from a server that does not enforce it still
parses and reaches the existing drop of a record with a blank condition.
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
def test_each_condition_item_needs_a_non_blank_character(record: str) -> None:
    items = _sent_schema()["$defs"][record]["properties"]["applies_when"]["items"]

    assert items == {"type": "string", "pattern": r"\S"}


def test_sent_schema_is_valid_and_xgrammar_compatible() -> None:
    schema = _sent_schema()

    Draft202012Validator.check_schema(schema)
    assert not [
        node
        for node in _nodes(schema)
        if "pattern" in node and {"minLength", "maxLength"} & set(node)
    ]


@pytest.mark.parametrize(
    ("conditions", "valid"),
    [
        (["The customer is verified"], True),
        ([], True),
        ([""], False),
        ([" "], False),
        (["\t\n"], False),
    ],
    ids=["text", "no-condition", "empty", "space", "whitespace"],
)
def test_sent_schema_rejects_blank_conditions(conditions, valid: bool) -> None:
    patch = {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [
            {
                "constraint_id": "SC-1",
                "rule": "The assistant must verify the customer.",
                "applies_when": conditions,
                "behavior_class": None,
                "related_hazards": ["H-1"],
            }
        ],
        "security_constraint_additions": [],
    }

    errors = list(Draft202012Validator(_sent_schema()).iter_errors(patch))

    assert (not errors) is valid


def _patch_with(edit: dict) -> dict:
    return {
        "hazard_edits": [],
        "hazard_additions": [],
        "security_constraint_edits": [edit],
        "security_constraint_additions": [],
    }


def test_sent_schema_rejects_the_recorded_blank_condition_edit() -> None:
    validator = Draft202012Validator(_sent_schema())
    kept = {**_RECORDED_EDIT, "applies_when": ["A regulated topic is asked"]}

    assert [
        e.validator for e in validator.iter_errors(_patch_with(_RECORDED_EDIT))
    ] == ["pattern"]
    assert not list(validator.iter_errors(_patch_with(kept)))


def test_a_blank_condition_still_parses_locally() -> None:
    patch = _Stage1aRevisionPatch.model_validate(
        {
            "hazard_edits": [],
            "hazard_additions": [],
            "security_constraint_edits": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The assistant must verify the customer.",
                    "applies_when": [""],
                    "related_hazards": ["H-1"],
                }
            ],
            "security_constraint_additions": [],
        }
    )

    assert patch.security_constraint_edits[0].applies_when == [""]
