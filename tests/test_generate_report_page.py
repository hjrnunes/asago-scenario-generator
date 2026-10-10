"""The assembled generate report and its stage summary."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.report import generate_report
from asago_scenario_generator.report.generate_report import (
    build_report,
    write_report,
)
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report_kit import (
    check_headline,
    check_offline,
    read_metrics,
)
from tests.helpers.generate_report_fixture import copy_run, edit_calls, edit_yaml

SCHEMA = (
    Path(generate_report.__file__).parent.parent
    / "report_kit"
    / "stage-summary-v1.schema.json"
)
SECTIONS = (
    "answer how risks slots testability obligations failed warnings scenarios "
    "target handoff effort"
).split()


def built(output: Path) -> tuple[str, dict]:
    html, summary = build_report(load_run(output))
    return str(html), summary


def metric(html: str, key: str) -> tuple[int, int | None]:
    found = read_metrics(html)[key]
    return int(found["value"]), None if found["of"] is None else int(found["of"])


def test_the_page_has_every_section_in_order(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    ids = re.findall(r'<section id="([^"]+)"', html)
    assert ids == SECTIONS


def test_the_headline_tiles_state_what_each_number_counts(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    assert metric(html, "scenarios.written") == (8, None)
    assert metric(html, "scenarios.sent") == (6, 8)
    assert metric(html, "policy.reached") == (14, 47)
    assert metric(html, "requests.failed") == (10, 161)
    for key in (
        "scenarios.written",
        "scenarios.sent",
        "policy.reached",
        "requests.failed",
    ):
        assert re.search(rf'data-metric="{key}".*?<span class="u"> \w+', html, re.S)


def test_the_first_sentence_gives_the_outcome(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    assert (
        "8 scenarios written from 47 policy risks: 5 attack scenarios and 3 everyday "
        "checks. 6 go to authoring." in html
    )
    assert "1 failure cost output" in html


def test_every_metric_key_appears_once(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    assert len(read_metrics(html)) > 40


def test_the_stage_summary_validates_against_the_kit_schema(tmp_path: Path) -> None:
    html, summary = built(copy_run(tmp_path))

    Draft202012Validator(json.loads(SCHEMA.read_text())).validate(summary)
    check_headline(summary, html)


def test_the_stage_summary_headline_equals_the_page_tiles(tmp_path: Path) -> None:
    html, summary = built(copy_run(tmp_path))

    keys = [h["key"] for h in summary["headline"]]
    assert keys == ["scenarios.written", "scenarios.sent", "policy.reached"]
    for entry in summary["headline"]:
        assert metric(html, entry["key"]) == (entry["value"], entry.get("of"))


def test_the_stage_summary_lists_one_item_per_scenario_with_its_fate(
    tmp_path: Path,
) -> None:
    _, summary = built(copy_run(tmp_path))

    items = {i["scenario_id"]: i for i in summary["items"]}
    assert len(items) == 8
    assert items["SCN-001"]["label"] == "Sent to authoring"
    assert items["SCN-012"]["label"] == "Duplicate of SCN-011"
    assert items["SCN-002"]["label"] == "Analytical only"
    assert items["SCN-001"]["href"] == "index.html#SCN-001"
    assert all(not i["href"].startswith("/") for i in items.values())


def test_a_lost_request_and_a_degraded_scenario_are_alerts(tmp_path: Path) -> None:
    _, summary = built(copy_run(tmp_path))

    by_status = {a["status"]: a for a in summary["alerts"]}
    assert by_status["fail"]["href"] == "index.html#failed"
    assert "Request #34" in by_status["fail"]["text"]
    assert "SCN-023" in by_status["warn"]["text"]
    assert summary["status"] == "warn"


def test_a_clean_run_has_status_pass_and_no_alerts(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.__setitem__(
            slice(None), [c for c in calls if c["success"]]
        ),
    )

    _, summary = built(output)

    assert summary["alerts"] == []
    assert summary["status"] == "pass"


def test_the_summary_usage_counts_requests_and_tokens(tmp_path: Path) -> None:
    _, summary = built(copy_run(tmp_path))

    assert summary["usage"]["model_requests"] == 161
    assert summary["usage"]["failed_requests"] == 10
    assert summary["usage"]["tokens"] > 0


def test_a_policy_risks_missing_run_drops_that_tile_and_headline(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    (output / "policy-coverage.json").unlink()

    html, summary = built(output)

    assert "policy.reached" not in read_metrics(html)
    assert [h["key"] for h in summary["headline"]] == [
        "scenarios.written",
        "scenarios.sent",
    ]


def test_how_generation_works_defines_slot_and_finding(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    for word in ("slot", "finding"):
        assert f'href="#term-{word}"' in html
        assert f'id="term-{word}"' in html


def test_the_handoff_lists_files_with_schema_versions(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    handoff = html.split('<section id="handoff">')[1].split("</section>")[0]
    for text in (
        "scenario-handoff-v4",
        "scenario-testability-v1",
        "execution-target-profile-v1",
        "testability.yaml",
        "8 files",
    ):
        assert text in handoff


def test_the_handoff_omits_counts_that_are_zero(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    handoff = html.split('<section id="handoff">')[1].split("</section>")[0]
    assert "functional test" in handoff
    assert "skipped" not in handoff
    assert "diagnostic" not in handoff


def test_a_manifest_that_counts_other_scenarios_than_the_files_is_flagged(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    edit_yaml(
        output / "synthesis-manifest.yaml",
        lambda m: m["scenario_counts"].update(generated=28),
    )

    html, _ = built(output)

    assert "The manifest counts 28 generated scenarios" in html
    assert "8 scenario files" in html


def test_the_page_loads_nothing_from_outside(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    check_offline(html)
    assert not re.search(r'(?:src|href)="https?:', html)


def test_two_builds_of_one_run_are_identical(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    assert built(output) == built(output)


def test_the_page_stays_inside_the_size_budget(tmp_path: Path) -> None:
    html, _ = built(copy_run(tmp_path))

    per_hundred = len(html.encode()) / 8 * 100
    assert per_hundred <= 5_000_000


def test_write_report_puts_both_files_beside_the_report(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    written = write_report(output)

    assert written.index == output / "report" / "index.html"
    assert (
        json.loads((output / "report" / "stage-summary.json").read_text())["report"]
        == "index.html"
    )
    assert 'href="../scenarios/SCN-001.yaml"' in written.index.read_text()


def test_a_summary_that_disagrees_with_the_page_is_not_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = copy_run(tmp_path)
    real = generate_report.build_report

    def wrong(run):
        html, summary = real(run)
        summary["headline"][0]["value"] += 1
        return html, summary

    monkeypatch.setattr(generate_report, "build_report", wrong)

    with pytest.raises(Exception, match="scenarios.written"):
        write_report(output)

    assert not (output / "report" / "stage-summary.json").exists()
