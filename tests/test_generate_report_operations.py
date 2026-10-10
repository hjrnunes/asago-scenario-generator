"""Failed requests, warnings, and effort: what the run's operations cost."""

from __future__ import annotations

import re
from pathlib import Path

from asago_scenario_generator.report.effort_section import effort_section
from asago_scenario_generator.report.failure_section import failure_section
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.warning_section import warning_section
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_calls, edit_yaml


def numbers(html: str) -> dict[str, int]:
    return {k: int(v["value"]) for k, v in read_metrics(html).items()}


def row(html: str, ident: str) -> str:
    return re.search(rf'<tr id="{ident}".*?</tr>', html, re.S).group(0)


def test_failed_requests_are_counted_against_all_requests(tmp_path: Path) -> None:
    n = numbers(str(failure_section(load_run(copy_run(tmp_path)))))

    assert (n["failures.failed"], n["failures.requests"], n["failures.chains"]) == (
        10,
        161,
        9,
    )
    assert (n["failures.lost"], n["failures.degraded"], n["failures.recovered"]) == (
        1,
        1,
        7,
    )


def test_a_failure_fixed_by_a_repair_request_is_counted_as_repaired(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.append(
            {
                "stage": "stage_2",
                "step": "revision_repair",
                "attempt_number": 1,
                "success": True,
            }
        ),
    )

    n = numbers(str(failure_section(load_run(output))))

    assert (n["failures.repaired"], n["failures.lost"]) == (1, 0)


def test_a_chain_row_lists_its_requests_error_code_and_effect(tmp_path: Path) -> None:
    html = str(failure_section(load_run(copy_run(tmp_path))))

    chain = row(html, "failure-155")
    assert "#155" in chain and "#156" in chain
    assert "discriminating_condition_check_failed" in chain
    assert "published without a discriminating condition" in chain
    assert "SCN-023" in chain


def test_lost_chains_come_first(tmp_path: Path) -> None:
    html = str(failure_section(load_run(copy_run(tmp_path))))

    ids = re.findall(r'<tr id="failure-(\d+)"', html)
    assert ids[0] == "34"
    assert ids[1] == "155"


def test_a_run_without_failures_says_so(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.__setitem__(
            slice(None), [c for c in calls if c["success"]]
        ),
    )

    html = str(failure_section(load_run(output)))

    assert "No model request failed." in html


def test_warnings_that_differ_only_in_an_id_share_a_row(tmp_path: Path) -> None:
    html = str(warning_section(load_run(copy_run(tmp_path))))
    n = numbers(html)

    assert n["warnings.total"] == 14
    assert len(re.findall(r"<tr id=\"warning-", html)) == 7
    assert "Hazard states no system condition" in html
    assert (
        "<code>H-1</code> <code>H-2</code> <code>H-3</code> <code>H-5</code> <code>H-8</code>"
        in html
    )


def test_a_constraint_warning_lists_each_constraint_once(tmp_path: Path) -> None:
    html = str(warning_section(load_run(copy_run(tmp_path))))

    assert "<code>SC-2</code> <code>SC-4</code> <code>SC-6</code>" in html


def test_no_warnings_is_stated(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_yaml(output / "synthesis-manifest.yaml", lambda m: m.update(stage_warnings=[]))

    html = str(warning_section(load_run(output)))

    assert "No warnings." in html


def test_effort_groups_requests_by_step_and_foots_to_the_total(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))
    html = str(effort_section(run))
    n = numbers(html)

    assert n["effort.requests"] == len(run.calls)
    assert n["effort.tokens"] == sum(c.tokens for c in run.calls)
    groups = [
        int(m)
        for m in re.findall(
            r'<tr id="effort-[a-z-]+"[^>]*><td>[^<]*</td><td class="n" data-v="(\d+)"',
            html,
        )
    ]
    assert sum(groups) == len(run.calls)


def test_effort_counts_failed_requests_and_adds_up_the_seconds(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: [c.update(duration_ms=2000) for c in calls],
    )
    run = load_run(output)

    n = numbers(str(effort_section(run)))

    assert n["effort.failed"] == 10
    assert n["effort.seconds"] == 2 * len(run.calls)


def test_effort_lists_steps_in_pipeline_order(tmp_path: Path) -> None:
    html = str(effort_section(load_run(copy_run(tmp_path))))

    order = [m for m in re.findall(r'<tr id="effort-([a-z-]+)"', html)]
    assert (
        order.index("loss-analysis")
        < order.index("slot-analysis")
        < order.index("scenario-writing")
    )


def test_a_request_of_an_unknown_step_lands_in_other(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.append(
            {"stage": "new_stage", "step": "x", "attempt_number": 1, "success": True}
        ),
    )

    html = str(effort_section(load_run(output)))

    assert 'id="effort-other"' in html
