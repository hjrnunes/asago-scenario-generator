"""Which slots the model decided, and what each finding became."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.slot_view import slot_views
from tests.helpers.generate_report_fixture import copy_run, edit_calls


def views(output: Path):
    return {v.slot_id: v for v in slot_views(load_run(output))}


def test_every_offered_slot_has_one_decision(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    slots = slot_views(run)

    assert len(slots) == len(run.offers.slots) == 52
    assert Counter(s.decision for s in slots) == {
        "findings": 30,
        "na": 20,
        "unresolved": 2,
    }


def test_a_not_applicable_slot_carries_the_models_reason(tmp_path: Path) -> None:
    na = [v for v in views(copy_run(tmp_path)).values() if v.decision == "na"]

    assert na and all(v.rationale for v in na)


def test_a_slot_names_its_action_and_failure_type(tmp_path: Path) -> None:
    slot = views(copy_run(tmp_path))["RESP-1:CA-1-1:WRONG_TIMING"]

    assert (slot.owner, slot.action_id, slot.uca) == (
        "RESP-1",
        "CA-1-1",
        "WRONG_TIMING",
    )


def test_a_supported_finding_lists_the_scenarios_it_became(tmp_path: Path) -> None:
    slot = views(copy_run(tmp_path))["CL-1:CM-1:INCORRECT"]

    finding = next(f for f in slot.findings if f.ica_id == "CL-1:CM-1:INCORRECT:1")
    assert finding.disposition == "supported"
    assert finding.scenarios == ["SCN-001"]


def test_an_excluded_finding_keeps_the_verifiers_reason(tmp_path: Path) -> None:
    excluded = [
        f
        for v in views(copy_run(tmp_path)).values()
        for f in v.findings
        if f.disposition == "excluded"
    ]

    assert excluded and all(f.rationale and f.scenarios == [] for f in excluded)


def test_without_a_target_the_models_slot_answers_come_from_the_call_log(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    (output / "target-realization.yaml").unlink()
    answer = {
        "filled_slots": [
            {
                "slot_id": "RESP-1:CA-1-1:WRONG_DURATION",
                "is_na": True,
                "na_rationale": "The action is instantaneous.",
            }
        ]
    }

    def add(calls: list[dict]) -> None:
        calls.append(
            {
                "stage": "synthesis_obligation_aware_icas",
                "step": "RESP-1",
                "success": True,
                "response_content": json.dumps(answer),
            }
        )

    edit_calls(output, add)

    slots = views(output)

    assert slots["RESP-1:CA-1-1:WRONG_DURATION"].decision == "na"
    assert slots["RESP-1:CA-1-1:WRONG_DURATION"].rationale == (
        "The action is instantaneous."
    )
    assert slots["RESP-1:CA-1-1:WRONG_TIMING"].decision == "findings"
