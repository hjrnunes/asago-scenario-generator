"""The conformance runner reads a kit and reports exactly the cases that fail."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from asago_handoff import (
    feature_violations,
    load_conformance_cases,
    render_feature_text,
    run_conformance,
)

CONTRACT_DIR = (
    Path(__file__).resolve().parents[3] / "data" / "contracts" / "scenario-handoff"
)
KIT_DIR = CONTRACT_DIR / "handoff-v5"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _copy_kit(tmp_path: Path) -> Path:
    kit = tmp_path / "scenario-handoff"
    shutil.copytree(KIT_DIR, kit / "handoff-v5")
    shutil.copy(CONTRACT_DIR / "ownership-rules.json", kit / "ownership-rules.json")
    return kit


def test_every_conformance_case_passes() -> None:
    results = run_conformance(CONTRACT_DIR)
    assert [result.case.path for result in results if not result.passed] == []
    assert len(results) == 33


def test_the_manifest_names_the_five_rules() -> None:
    manifest = _load(KIT_DIR / "conformance-cases.json")
    assert [(rule["name"], rule["kind"]) for rule in manifest["rules"]] == [
        ("safe-call-arguments", "handoff"),
        ("procedure-chain", "handoff"),
        ("reference-order", "handoff"),
        ("ownership-walker", "handoff"),
        ("feature-companion", "companion"),
    ]
    for rule in manifest["rules"]:
        assert rule["valid"] and rule["invalid"]


def test_a_valid_case_is_checked_by_the_rules_it_names() -> None:
    cases = {case.path: case for case in load_conformance_cases(CONTRACT_DIR)}
    assert cases["invalid/safe-call-argument-blank-name.json"].valid is False
    assert cases["valid/safe-call-arguments.json"].valid is True


def test_the_renderer_writes_the_companion_the_kit_holds() -> None:
    entry = _load(KIT_DIR / "companions" / "feature-companion-holds.json")
    handoff = _load(KIT_DIR / entry["handoff"])
    assert render_feature_text(handoff["gherkin"]) == entry["text"]
    assert feature_violations(handoff["gherkin"], entry["text"]) == []


def test_a_companion_rule_names_the_first_break() -> None:
    entry = _load(KIT_DIR / "companions" / "feature-companion-holds.json")
    handoff = _load(KIT_DIR / entry["handoff"])
    broken = entry["text"].replace("Feature: ", "Feature: not ", 1)
    (violation,) = feature_violations(handoff["gherkin"], broken)
    assert violation.code == "feature_companion:feature_line"
    assert violation.path == "gherkin.feature"


def test_a_broken_companion_fails_only_its_own_case(tmp_path: Path) -> None:
    kit = _copy_kit(tmp_path)
    path = kit / "handoff-v5" / "companions" / "feature-companion-holds.json"
    entry = _load(path)
    entry["text"] = "Feature: something else\n"
    path.write_text(json.dumps(entry), encoding="utf-8")

    failed = [result.case.path for result in run_conformance(kit) if not result.passed]
    assert failed == ["companions/feature-companion-holds.json"]
