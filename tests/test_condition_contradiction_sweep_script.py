"""The offline report of the tool-call condition check over saved handoffs."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "condition_contradiction_sweep.py"
)


def _script() -> ModuleType:
    name = "condition_contradiction_sweep_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _row(scenario_id: str, *, refused: bool) -> dict:
    return {
        "scenario_id": scenario_id,
        "ica_slot_id": "ICA-1:INCORRECT",
        "condition": {"comparisons": []},
        "refused": (
            [{"rule": "b", "code": "code", "detail": "different kinds"}]
            if refused
            else []
        ),
        "undecidable": [] if refused else [{"rule": "a", "detail": "unknown"}],
    }


def _summaries() -> list[dict]:
    script = _script()
    return [
        script._summary(
            Path("first"),
            Path("first/profile.json"),
            5,
            [_row("SCN-001", refused=True), _row("SCN-002", refused=False)],
        ),
        script._summary(
            Path("second"),
            Path("second/profile.json"),
            3,
            [_row("SCN-003", refused=True)],
        ),
    ]


def test_report_counts_the_scenarios_at_risk_per_directory_and_in_total() -> None:
    report = _script().report(_summaries())

    assert [item["at_risk_of_losing_condition"] for item in report["directories"]] == [
        ["SCN-001"],
        ["SCN-003"],
    ]
    assert report["total"] == {
        "directories": 2,
        "handoffs": 8,
        "checked": 3,
        "refused_by_rule": {"a": 0, "b": 2, "c": 0},
        "undecidable_by_rule": {"a": 1, "b": 0, "c": 0},
        "at_risk_of_losing_condition": 2,
        "dropped_scenarios": 0,
    }


def test_rendered_report_states_what_happens_to_a_refused_condition() -> None:
    script = _script()
    rendered = script.render(_summaries())

    assert script.RECOVERY == (
        "A refused condition fails Stage 5 validation, so the scenario goes "
        "through the existing Stage 5 condition correction request, with a "
        "second correction only when the scenario would otherwise publish as "
        "analytical_only. If the condition still fails, the scenario is "
        "published without a tool_call_condition and records the reason in "
        "condition_omitted_reason. No scenario is dropped: each refused "
        "scenario is at risk of losing its tool-call condition, nothing more. "
        "An undecidable case is reported only, in the run's candidate "
        "diagnostics (synthesis-manifest.yaml) and in this sweep; it changes "
        "nothing in the scenario."
    )
    assert f"## What happens to a refused condition\n\n{script.RECOVERY}\n" in rendered
    assert (
        "## Total\n\n- directories: 2; handoffs: 8; bound conditions checked: 3\n"
        "- refused scenarios by rule: rule a: 0, rule b: 2, rule c: 0\n"
        "- undecidable cases by rule: rule a: 1, rule b: 0, rule c: 0\n"
        "- scenarios at risk of losing their tool_call_condition: 2 of 8 "
        "handoffs; scenarios dropped: 0\n"
    ) in rendered
    assert "| first | 5 | 2 | 0/1/0 | 1/0/0 | 1 | 0 |\n" in rendered
    assert (
        "- scenarios at risk of losing their tool_call_condition: 1 of 5 "
        "handoffs (SCN-001); scenarios dropped: 0\n"
    ) in rendered
    assert rendered.count("  - recovery: the existing Stage 5 condition") == 2
