"""Target mapping: control actions, operations, and capabilities, counted apart."""

from __future__ import annotations

import re
from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.target_section import target_section
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def shown(output: Path) -> tuple[str, dict]:
    html = str(target_section(load_run(output)))
    return html, {k: int(v["value"]) for k, v in read_metrics(html).items()}


def test_actions_operations_and_capabilities_are_three_separate_counts(
    tmp_path: Path,
) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["target.actions"] == 8
    assert n["target.operations"] == 7
    assert n["target.capabilities"] == 8


def test_each_count_breaks_down_by_its_own_dispositions(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    actions = sum(v for k, v in n.items() if k.startswith("target.actions."))
    operations = sum(v for k, v in n.items() if k.startswith("target.operations."))
    assert actions == 8
    assert operations == 7
    assert n["target.operations.supported"] == 5


def test_a_control_action_row_names_its_selected_operation(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="target-action-CA-5-1".*?</tr>', html, re.S).group(0)
    assert "escalate_to_human" in row
    assert "supported" in row


def test_a_capability_row_says_whether_it_was_declared_and_observed(
    tmp_path: Path,
) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "Klarna Backend Systems API" in html
    assert "declared not observed" in html


def test_the_context_table_budget_and_rows_shown_per_action(tmp_path: Path) -> None:
    html, n = shown(copy_run(tmp_path))

    assert n["context.budget"] == 12
    assert n["context.hidden"] == 0
    assert 'id="context-CA-4-1"' in html


def test_an_action_with_more_combinations_than_rows_is_flagged(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    def hide(manifest: dict) -> None:
        action = manifest["context_tables"]["actions"][0]
        action.update(
            combinations=30,
            rows_shown=12,
            hidden_values=[{"process_model_id": "PM-1", "value": "balance"}],
        )

    edit_yaml(output / "synthesis-manifest.yaml", hide)

    html, n = shown(output)

    assert n["context.hidden"] == 1
    assert "18 combinations not shown" in html
    assert "PM-1: balance" in html


def test_a_run_without_a_target_says_so(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "target-realization.yaml").unlink()

    html, n = shown(output)

    assert "target-realization.yaml: not in this run" in html
    assert "target.actions" not in n
