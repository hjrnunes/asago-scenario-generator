"""The policy-risk section: where each risk went, and why it dropped."""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.report.policy_section import policy_section
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def shown(output: Path) -> tuple[str, dict]:
    html = str(policy_section(load_run(output)))
    values = {k: int(v["value"]) for k, v in read_metrics(html).items()}
    return html, values


def edit_policy(output: Path, change) -> None:
    path = output / "policy-coverage.json"
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value, sort_keys=True))


def test_each_step_takes_in_what_the_one_before_passed_on(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["policy.boundary.in"] == 47
    assert n["policy.boundary.out"] == 20
    assert n["policy.boundary.outside-boundary"] == 23
    assert n["policy.boundary.not-applicable"] == 4
    assert n["policy.loss.in"] == 20
    assert n["policy.loss.not-applicable"] == 3
    assert n["policy.scenarios.in"] == 17
    assert n["policy.scenarios.not-reached"] == 3
    assert n["policy.scenarios.out"] == 14


def test_the_testability_step_counts_risks_with_a_scenario_authoring_takes(
    tmp_path: Path,
) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["policy.testability.in"] == 14
    assert n["policy.testability.out"] + n["policy.testability.unsendable"] == 14
    assert 0 < n["policy.testability.out"] <= 14


def test_removing_one_risk_lowers_the_first_row_by_one(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    def drop(policy: dict) -> None:
        index = next(
            i for i, r in enumerate(policy["risks"]) if r["coverage"] == "scenarios"
        )
        del policy["risks"][index]

    edit_policy(output, drop)
    _, n = shown(output)

    assert n["policy.boundary.in"] == 46
    assert n["policy.scenarios.out"] == 13


def test_a_risk_the_boundary_kept_and_loss_analysis_dropped_is_called_out(
    tmp_path: Path,
) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "Kept by the boundary decision, dropped by loss analysis" in html
    assert "Over or under-reliance and unsafe use" in html
    assert "describes user behavior patterns" in html


def test_the_reason_for_each_out_of_scope_risk_is_listed(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "Generated content ownership and IP" in html
    assert "an action by an external actor outside the system boundary" in html


def test_a_review_that_did_not_complete_is_named_beside_the_callout(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    edit_yaml(
        output / "loss-analysis-risk-coverage-review.yaml",
        lambda v: v.update(status="unavailable", failure_reason="rows must be a list"),
    )

    html, _ = shown(output)

    assert "The risk coverage review ended unavailable: rows must be a list" in html


def test_a_run_without_policy_coverage_says_so(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "policy-coverage.json").unlink()

    html, n = shown(output)

    assert "policy-coverage.json: not in this run" in html
    assert n == {}
