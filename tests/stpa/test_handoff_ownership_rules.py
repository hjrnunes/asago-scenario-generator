"""The ownership boundary and the five duplicated rules are contract data.

``data/contracts/scenario-handoff/ownership-rules.json`` lists the forbidden
keys and prose patterns. The handoff module reads it, the contract lock pins
it, and the consumer mirrors it byte for byte, so both sides enforce one list.

``scenario-handoff-v5/cases/conformance-cases.json`` names the cases for the five rules the
consumer re-implements: safe-call arguments, the procedure chain, reference
order, the ownership walker, and the feature companion. Each rule carries at
least one valid and one invalid case, and the consumer runs the same manifest.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from asago_scenario_generator.report.scenario_panels import feature_matches
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    _FORBIDDEN_KEYS,
    _FORBIDDEN_VALUE_PATTERNS,
    HandoffGherkin,
    ScenarioHandoffV5,
    handoff_ownership_violations,
    handoff_schema_violations,
    load_ownership_rules,
)

RULES = (
    Path(__file__).resolve().parents[2]
    / "data/contracts/scenario-handoff/ownership-rules.json"
)
KIT = RULES.parent / "scenario-handoff-v5" / "cases"
RULE_NAMES = frozenset(
    {
        "safe-call-arguments",
        "procedure-chain",
        "reference-order",
        "ownership-walker",
        "feature-companion",
    }
)


def _rules() -> dict:
    return json.loads(RULES.read_text(encoding="utf-8"))


def _manifest_cases(verdict: str, kind: str) -> list[str]:
    manifest = json.loads((KIT / "conformance-cases.json").read_text(encoding="utf-8"))
    return [
        relative
        for rule in manifest["rules"]
        if rule["kind"] == kind
        for relative in rule[verdict]
    ]


def _companion_gherkin(case: dict) -> HandoffGherkin:
    payload = json.loads((KIT / case["handoff"]).read_text(encoding="utf-8"))
    return ScenarioHandoffV5.model_validate(payload).gherkin


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


def test_the_kit_carries_a_case_for_each_of_the_five_rules() -> None:
    manifest = json.loads((KIT / "conformance-cases.json").read_text(encoding="utf-8"))
    rules = manifest["rules"]

    assert manifest["contract"] == "scenario-handoff"
    assert manifest["kit"] == "scenario-handoff-v5"
    assert {rule["name"] for rule in rules} == RULE_NAMES
    assert len(rules) == len(RULE_NAMES)
    for rule in rules:
        assert rule["valid"], rule["name"]
        assert rule["invalid"], rule["name"]
        assert rule["kind"] in {"handoff", "companion"}


def test_every_named_case_is_a_file_in_the_kit() -> None:
    manifest = json.loads((KIT / "conformance-cases.json").read_text(encoding="utf-8"))

    for rule in manifest["rules"]:
        for relative in [*rule["valid"], *rule["invalid"]]:
            assert (KIT / relative).is_file(), relative


@pytest.mark.parametrize("relative", _manifest_cases("valid", "handoff"))
def test_a_valid_rule_case_passes_the_producers_checks(relative: str) -> None:
    payload = json.loads((KIT / relative).read_text(encoding="utf-8"))

    assert handoff_ownership_violations(payload) == []
    assert handoff_schema_violations(payload) == []
    ScenarioHandoffV5.model_validate(payload)


@pytest.mark.parametrize("relative", _manifest_cases("invalid", "handoff"))
def test_an_invalid_rule_case_is_refused_with_the_kits_codes(relative: str) -> None:
    payload = json.loads((KIT / relative).read_text(encoding="utf-8"))
    expected = json.loads(
        (KIT / "expected-violations.json").read_text(encoding="utf-8")
    )

    found = handoff_ownership_violations(payload) + handoff_schema_violations(payload)

    assert found
    assert found == expected[relative]


@pytest.mark.parametrize("relative", _manifest_cases("valid", "companion"))
def test_a_valid_companion_case_holds_the_handoff_gherkin(relative: str) -> None:
    case = json.loads((KIT / relative).read_text(encoding="utf-8"))
    gherkin = _companion_gherkin(case)

    assert feature_matches(gherkin, case["text"])
    assert case["text"] == gherkin.to_feature_text()


@pytest.mark.parametrize("relative", _manifest_cases("invalid", "companion"))
def test_an_invalid_companion_case_breaks_the_feature_rule(relative: str) -> None:
    case = json.loads((KIT / relative).read_text(encoding="utf-8"))

    assert not feature_matches(_companion_gherkin(case), case["text"])
