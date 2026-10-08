"""The ownership boundary is producer-owned contract data.

``data/contracts/scenario-handoff/ownership-rules.json`` lists the forbidden
keys and prose patterns. The handoff module reads it, the contract lock pins
it, and the consumer mirrors it byte for byte, so both sides enforce one list.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.scenario_prod.handoff import (
    _FORBIDDEN_KEYS,
    _FORBIDDEN_VALUE_PATTERNS,
    load_ownership_rules,
)

RULES = (
    Path(__file__).resolve().parents[2]
    / "data/contracts/scenario-handoff/ownership-rules.json"
)


def _rules() -> dict:
    return json.loads(RULES.read_text(encoding="utf-8"))


def test_the_forbidden_keys_are_the_contract_data() -> None:
    keys = _rules()["forbidden_keys"]

    assert keys == sorted(set(keys))
    assert _FORBIDDEN_KEYS == frozenset(keys)


def test_the_forbidden_value_patterns_are_the_contract_data_in_order() -> None:
    expected = [
        (entry["code"], entry["pattern"], entry["flags"])
        for entry in _rules()["forbidden_value_patterns"]
    ]

    assert [
        (code, pattern.pattern, ["IGNORECASE"] if pattern.flags & re.IGNORECASE else [])
        for code, pattern in _FORBIDDEN_VALUE_PATTERNS
    ] == expected


def test_a_rules_file_is_read_into_keys_and_compiled_patterns(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "forbidden_keys": ["alpha"],
                "forbidden_value_patterns": [
                    {"code": "beta", "pattern": r"\bbeta\b", "flags": ["IGNORECASE"]},
                    {"code": "gamma", "pattern": "gamma", "flags": []},
                ],
            }
        ),
        encoding="utf-8",
    )

    keys, patterns = load_ownership_rules(path)

    assert keys == frozenset({"alpha"})
    assert [code for code, _ in patterns] == ["beta", "gamma"]
    assert patterns[0][1].search("BETA")
    assert not patterns[1][1].search("GAMMA")


def test_a_rules_file_with_an_unknown_flag_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "forbidden_keys": [],
                "forbidden_value_patterns": [
                    {"code": "beta", "pattern": "beta", "flags": ["DOTALL"]}
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="DOTALL"):
        load_ownership_rules(path)
