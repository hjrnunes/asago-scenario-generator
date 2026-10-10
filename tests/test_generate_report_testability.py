"""The testability section: which scenarios authoring takes, and with what condition."""

from __future__ import annotations

import re
from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.testability_section import (
    testability_section as render_section,
)
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def shown(output: Path) -> tuple[str, dict]:
    html = str(render_section(load_run(output)))
    return html, {k: int(v["value"]) for k, v in read_metrics(html).items()}


def test_the_bar_counts_sent_duplicate_and_analytical_scenarios(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["testability.bar.sent"] == 6
    assert n["testability.bar.duplicate"] == 1
    assert n["testability.bar.analytical"] == 1
    assert n["testability.total"] == 8


def test_the_lead_sentence_repeats_the_bar_counts(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["testability.sent"] == n["testability.bar.sent"] == 6
    assert n["testability.duplicate"] == n["testability.bar.duplicate"] == 1
    assert n["testability.analytical"] == n["testability.bar.analytical"] == 1


def test_removing_a_scenario_lowers_the_total_by_one(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    def drop(testability: dict) -> None:
        testability["scenarios"] = [
            s for s in testability["scenarios"] if s["scenario_id"] != "SCN-004"
        ]

    edit_yaml(output / "testability.yaml", drop)
    for suffix in ("yaml", "feature"):
        (output / "scenarios" / f"SCN-004.{suffix}").unlink()

    _, n = shown(output)

    assert n["testability.total"] == 7
    assert n["testability.bar.sent"] == 5


def test_a_duplicate_names_the_scenario_it_duplicates(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="dup-SCN-012".*?</tr>', html, re.S).group(0)
    assert 'href="#SCN-011"' in row


def test_a_duplicate_that_governs_a_different_rule_is_flagged(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    path = output / "scenarios" / "SCN-012.yaml"
    edit_yaml(path, lambda y: y["governing_rules"][0].update(constraint_id="SC-9"))

    html, n = shown(output)

    assert n["testability.rule_differs"] == 1
    assert "governs SC-9; kept SC-2" in html


def test_an_analytical_only_scenario_states_why(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="analytical-SCN-002".*?</tr>', html, re.S).group(0)
    assert "analytical-only" in row


def test_each_constraint_counts_its_scenarios_by_testability(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="rule-SC-2".*?</tr>', html, re.S).group(0)
    assert row.count('data-v="1"') == 2
    assert "The assistant must" in row


def test_the_condition_grid_crosses_check_result_with_tool_call_status(
    tmp_path: Path,
) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["conditions.satisfied.bound"] == 3
    assert n["conditions.not_checkable.bound"] == 3
    assert n["conditions.none.not_executable"] == 2
    assert sum(v for k, v in n.items() if k.startswith("conditions.")) == 8


def test_a_scenario_sent_without_a_condition_is_listed_as_weak(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="weak-SCN-023".*?</tr>', html, re.S).group(0)
    assert "No discriminating condition" in row
    assert "failed validation after one correction" in row


def test_a_run_without_testability_says_so(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "testability.yaml").unlink()

    html, n = shown(output)

    assert "testability.yaml: not in this run" in html
    assert n == {}
