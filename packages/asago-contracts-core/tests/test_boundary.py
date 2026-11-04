"""The ownership walker reports the producer's codes at the producer's paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_contracts_core import (
    ContractError,
    iter_boundary_strings,
    load_ownership_rules,
    ownership_violations,
)

from asago_contracts_core.contract import DATA_DIR

CONTRACT_DIR = DATA_DIR


def _codes(payload: Any) -> list[str]:
    return [violation.code for violation in ownership_violations(payload)]


def test_a_forbidden_key_is_reported_once_by_its_leaf() -> None:
    assert _codes({"role": "writer", "nested": {"roles": ["a", "b"]}}) == [
        "artifact_design_field:role",
        "artifact_design_field:roles",
    ]


def test_the_first_place_a_code_appears_names_its_path() -> None:
    (violation,) = ownership_violations({"outer": {"role": "writer"}, "role": "writer"})
    assert violation.path == "outer.role"


def test_a_prose_pattern_is_reported_by_its_slug() -> None:
    (violation,) = ownership_violations(
        {"narrative": "Deliver this message to the customer."}
    )
    assert violation.code == "prose_hiding:ready_to_send_instruction"
    assert violation.path == "narrative"
    assert violation.reason == "matches the ready_to_send_instruction pattern"


def test_a_key_is_walked_before_its_value() -> None:
    payload = {"message": "hello", "list": [{"role": "x"}]}
    assert _codes(payload) == [
        "artifact_design_field:message",
        "artifact_design_field:role",
    ]


def test_the_walker_numbers_sequence_items() -> None:
    found = iter_boundary_strings({"a": [{"b": "text"}]})
    assert found == [(".a", "a"), (".a[0].b", "b"), (".a[0].b", "text")]


def test_no_forbidden_key_or_pattern_is_skipped() -> None:
    document = json.loads(
        (CONTRACT_DIR / "ownership-rules.json").read_text(encoding="utf-8")
    )
    keys, patterns = load_ownership_rules(CONTRACT_DIR / "ownership-rules.json")
    assert keys == frozenset(document["forbidden_keys"])
    assert [slug for slug, _ in patterns] == [
        entry["code"] for entry in document["forbidden_value_patterns"]
    ]


def test_an_unknown_regex_flag_is_refused(tmp_path: Path) -> None:
    document = json.loads(
        (CONTRACT_DIR / "ownership-rules.json").read_text(encoding="utf-8")
    )
    document["forbidden_value_patterns"][0]["flags"] = ["DOTALL"]
    path = tmp_path / "ownership-rules.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ContractError, match="unknown flags"):
        load_ownership_rules(path)
