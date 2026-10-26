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


def _fixture_profile_and_universe(target: str):
    import json

    import yaml

    from asago_scenario_generator.stpa.models.execution_classification import (
        ExecutionTargetProfile,
    )
    from asago_scenario_generator.stpa.scenario_prod.condition_check import (
        build_condition_universe,
    )
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

    directory = (
        Path(__file__).resolve().parent / "fixtures/condition_contradictions" / target
    )
    profile = ExecutionTargetProfile.model_validate(
        json.loads((directory / "execution-target-profile.json").read_text())
    )
    observations = TargetObservationSnapshot.model_validate(
        yaml.safe_load((directory / "target-observations.yaml").read_text())
    )
    universe = build_condition_universe(
        execution_target_profile=profile,
        target_operation=None,
        target_observations=observations,
    )
    return profile, universe


def test_a_profiles_own_value_facts_come_before_an_overlay() -> None:
    from asago_scenario_generator.stpa.models.value_facts import TargetValueFacts

    profile, universe = _fixture_profile_and_universe("refund_assistant")
    overlay = {profile.target_id: TargetValueFacts()}

    checked, source = _script().with_declared_facts(universe, profile, overlay)

    assert source == "profile"
    assert checked.value_facts == profile.value_facts


def test_an_overlay_declares_facts_for_a_profile_without_them() -> None:
    from dataclasses import replace

    from asago_scenario_generator.stpa.models.value_facts import TargetValueFacts

    profile, universe = _fixture_profile_and_universe("refund_assistant")
    bare = profile.model_copy(update={"value_facts": None})
    universe = replace(universe, value_facts=None)
    facts = TargetValueFacts.model_validate(
        {"state_keys": [{"path": "orders", "record_kind": "order_id"}]}
    )

    overlaid, source = _script().with_declared_facts(
        universe, bare, {bare.target_id: facts}
    )
    other, none = _script().with_declared_facts(universe, bare, {"elsewhere": facts})

    assert (source, overlaid.value_facts) == ("overlay", facts)
    assert (none, other.value_facts) == ("none", None)
