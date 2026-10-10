"""The scenario section: a filterable list and, per scenario, the text and its lineage."""

from __future__ import annotations

import re
from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.scenario_section import scenario_section
from tests.helpers.generate_report_fixture import copy_run, edit_calls


def shown(output: Path) -> str:
    (output / "report").mkdir(exist_ok=True)
    return str(scenario_section(load_run(output)))


def detail(html: str, scenario: str) -> str:
    chunk = html.split(f'<details id="{scenario}"', 1)[1]
    return re.split(r'<details id="SCN-\d+"', chunk)[0]


def test_every_scenario_has_one_list_row_and_one_detail(tmp_path: Path) -> None:
    html = shown(copy_run(tmp_path))

    assert len(re.findall(r'<tr id="row-SCN-\d+"', html)) == 8
    assert len(re.findall(r'<details id="SCN-\d+"', html)) == 8


def test_removing_a_scenario_removes_its_row(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    for suffix in ("yaml", "feature"):
        (output / "scenarios" / f"SCN-006.{suffix}").unlink()

    html = shown(output)

    assert len(re.findall(r'<tr id="row-SCN-\d+"', html)) == 7
    assert 'id="row-SCN-006"' not in html


def test_a_row_carries_the_facets_the_filters_use(tmp_path: Path) -> None:
    html = shown(copy_run(tmp_path))

    row = re.search(r'<tr id="row-SCN-002"[^>]*>', html).group(0)
    assert 'data-f-kind="everyday"' in row
    assert 'data-f-test="analytical"' in row
    assert 'data-f-cond="none"' in row
    assert 'data-f-kind="attack"' in re.search(
        r'<tr id="row-SCN-001"[^>]*>', html
    ).group(0)


def test_a_scenario_opens_with_three_panels_with_their_anchors(tmp_path: Path) -> None:
    body = detail(shown(copy_run(tmp_path)), "SCN-001")

    for panel in ("narrative", "tree", "gherkin"):
        assert f'id="SCN-001-{panel}"' in body


def test_the_lineage_runs_from_policy_risk_to_testability(tmp_path: Path) -> None:
    body = detail(shown(copy_run(tmp_path)), "SCN-001")

    for level in (
        "Policy risks",
        "Loss",
        "Hazard",
        "Constraint",
        "Slot",
        "Finding",
        "Kind",
        "Condition",
        "Testability",
        "Requests",
    ):
        assert f'<span class="lvl">{level}</span>' in body
    assert (
        "Unauthorized exposure or distribution of customer Personally Identifiable Information"
        in body
    )
    assert "H-5" in body and "SC-4" in body
    assert "CL-1:CM-1:INCORRECT" in body
    assert "Verifier: " in body


def test_the_policy_risks_of_a_scenario_are_named_not_numbered(tmp_path: Path) -> None:
    body = detail(shown(copy_run(tmp_path)), "SCN-001")

    risks = body.split('<span class="lvl">Policy risks</span>')[1].split(
        '<span class="lvl">Loss</span>'
    )[0]
    assert "Confidential data in prompt" in risks
    assert "Revealing confidential information" in risks
    assert "atlas-confidential-data-in-prompt" not in risks


def test_an_attack_and_an_everyday_check_say_why_they_are_so(tmp_path: Path) -> None:
    html = shown(copy_run(tmp_path))

    assert "Published as an attack" in detail(html, "SCN-001")
    assert "no adversary gains from this unsafe outcome" in detail(html, "SCN-004")


def test_a_scenario_lists_its_own_requests_with_their_errors(tmp_path: Path) -> None:
    body = detail(shown(copy_run(tmp_path)), "SCN-023")

    assert body.count("discriminating_condition_check_failed") >= 2
    assert "#155" in body and "#156" in body


def test_the_introduction_counts_flat_trees_and_matching_features(
    tmp_path: Path,
) -> None:
    html = shown(copy_run(tmp_path))

    assert "8 of 8 attack trees are flat" in html
    assert "6 have exactly one leaf" in html
    assert "8 of 8 feature files match" in html


def test_links_to_the_handoff_files_point_out_of_the_report_folder(
    tmp_path: Path,
) -> None:
    body = detail(shown(copy_run(tmp_path)), "SCN-001")

    assert 'href="../scenarios/SCN-001.yaml"' in body
    assert 'href="../scenarios/SCN-001.feature"' in body


def test_a_missing_feature_file_reads_not_in_this_run(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "scenarios" / "SCN-001.feature").unlink()

    body = detail(shown(output), "SCN-001")

    assert "not in this run" in body


def test_a_scenario_without_a_request_says_none_recorded(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.__setitem__(
            slice(None), [c for c in calls if c.get("scenario_id") != "SCN-001"]
        ),
    )

    body = detail(shown(output), "SCN-001")

    assert "none recorded per scenario" in body
