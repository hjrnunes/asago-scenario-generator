"""The slot section: a matrix of actions by ways to go wrong."""

from __future__ import annotations

import re
from html import escape
from pathlib import Path

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.slot_section import slot_section
from asago_scenario_generator.report.slot_view import slot_views
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def shown(output: Path) -> tuple[str, dict]:
    html = str(slot_section(load_run(output)))
    return html, {k: int(v["value"]) for k, v in read_metrics(html).items()}


def row_of(html: str, action: str) -> str:
    return re.search(rf'<tr id="action-{action}".*?</tr>', html, re.S).group(0)


def test_slots_are_tallied_by_decision_and_the_tally_foots(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["slots.total"] == 52
    assert (n["slots.na"], n["slots.findings"], n["slots.unresolved"]) == (20, 30, 2)
    assert n["slots.none"] == 0
    assert (
        n["slots.na"] + n["slots.findings"] + n["slots.unresolved"] + n["slots.none"]
        == 52
    )


def test_findings_are_tallied_by_the_verifiers_disposition(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["findings.total"] == 64
    assert (n["findings.supported"], n["findings.excluded"]) == (57, 7)
    assert n["findings.failed"] == 0
    assert n["findings.scenarios"] == 8


def test_the_matrix_has_one_row_per_action_and_four_ways_to_go_wrong(
    tmp_path: Path,
) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert len(re.findall(r'<tr id="action-', html)) == 13
    for head in ("Not done", "Done unsafely", "Wrong time or order", "Wrong duration"):
        assert head in html


def test_a_supported_finding_links_the_scenarios_it_became(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert 'href="#SCN-001"' in row_of(html, "CM-1")


def test_an_action_row_names_its_responsibility_and_tool(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "RESP-1" in row_of(html, "CA-1-1")
    assert "reply" in row_of(html, "CA-1-1")
    assert "coordination" in row_of(html, "CM-1")


def test_a_not_applicable_cell_keeps_the_models_reason_on_hover(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))
    na = next(v for v in slot_views(run) if v.decision == "na")

    html = str(slot_section(run))

    assert f'title="{escape(na.rationale, quote=True)}"' in html


def test_every_not_applicable_reason_is_listed(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert html.count('class="na-reason"') == 20


def test_findings_the_verifier_rejected_are_listed_with_its_rationale(
    tmp_path: Path,
) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert html.count('class="rejected"') == 7


def test_an_undecided_slot_shows_a_no_decision_badge(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "target-realization.yaml").unlink()

    def forget(manifest: dict) -> None:
        records = manifest["provider_evidence"]["ica"]["ica_hazard_verification"][
            "records"
        ]
        records[:] = [r for r in records if r["slot_id"] != "CL-1:CM-1:INCORRECT"]

    edit_yaml(output / "synthesis-manifest.yaml", forget)

    html, n = shown(output)

    assert n["slots.none"] >= 1
    assert "no decision" in row_of(html, "CM-1")


def test_slots_whose_hazard_offer_shrank_are_counted_and_named(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    def shrink(report: dict) -> None:
        report["slots"][0]["missing_own_hazard_ids"] = ["H-1"]
        report["summary"]["shrunk_slots"] = 1

    edit_yaml(output / "slot-hazard-offers.yaml", shrink)

    html, n = shown(output)

    assert n["slots.shrunk"] == 1
    assert "lost hazard <code>H-1</code>" in html


def test_no_shrunk_slot_is_stated_as_zero(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n["slots.shrunk"] == 0
