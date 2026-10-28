"""The mechanism-suggestion section: one row per mechanism and slot, apart from obligations."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml

from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
    STOP_REASONS,
    MechanismSuggestionAccounting,
    MechanismSuggestionRow,
    summarize_mechanism_rows,
)
from asago_scenario_generator.report.generate_report import build_report
from asago_scenario_generator.report.mechanism_section import (
    STOP_MEANING,
    mechanism_section,
)
from asago_scenario_generator.report.run_data import load_run
from tests.helpers.generate_report_fixture import body_rows, copy_run, metrics

RECORDED = (
    Path(__file__).parent
    / "fixtures"
    / "mechanism_suggestion_accounting"
    / "recorded-run.yaml"
)
SLOTS = ("RESP-1:CA-1-1:INCORRECT", "RESP-1:CA-1-1:NOT_PROVIDED", "RESP-2:CA-2-1:<b>")
# (mechanism, slot index, stop reason, detail, ICA ids)
PAIRS = (
    ("user_claim", 0, "finding", None, ("ICA-1",)),
    ("user_claim", 1, "slot_fill_unresolved", "no <reply>", ()),
    ("user_claim", 2, "not_proposed", None, ()),
    ("retrieved_instructions", 0, "verifier_rejected", None, ()),
    ("retrieved_instructions", 1, "not_proposed", None, ()),
    ("retrieved_instructions", 2, "not_proposed", None, ()),
    ("stale_history", 0, "authority_filtered", "no authority", ()),
    ("stale_history", 1, "not_proposed", None, ()),
    ("stale_history", 2, "slot_fill_unresolved", None, ()),
)


def _hand_written() -> MechanismSuggestionAccounting:
    rows = tuple(
        MechanismSuggestionRow(
            mechanism_id=mechanism,
            slot_id=SLOTS[slot],
            stop_reason=reason,
            detail=detail,
            ica_ids=icas,
        )
        for mechanism, slot, reason, detail, icas in PAIRS
    )
    return MechanismSuggestionAccounting(
        rows=rows, summary=summarize_mechanism_rows(rows)
    )


def _run_with(tmp_path: Path, accounting: MechanismSuggestionAccounting) -> Path:
    output = copy_run(tmp_path)
    (output / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME).write_text(
        accounting.to_yaml(), encoding="utf-8"
    )
    return output


def shown(output: Path) -> tuple[str, dict[str, int]]:
    html = str(mechanism_section(load_run(output)))
    return html, metrics(html)


def _cells(html: str, row_id: str) -> list[str]:
    row = re.search(rf'<tr id="{row_id}">(.*?)</tr>', html, re.S).group(1)
    return re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)


def _section(html: str, section_id: str) -> str:
    return html.split(f'<section id="{section_id}">')[1].split("</section>")[0]


def test_every_stop_reason_has_a_plain_meaning() -> None:
    assert list(STOP_MEANING) == list(STOP_REASONS)


def test_the_summary_counts_every_stop_reason_zero_included(tmp_path: Path) -> None:
    _, n = shown(_run_with(tmp_path, _hand_written()))

    assert n == {
        "mechanism_suggestions.rows": 9,
        "mechanism_suggestions.not_proposed": 4,
        "mechanism_suggestions.authority_filtered": 1,
        "mechanism_suggestions.slot_not_analyzed": 0,
        "mechanism_suggestions.verifier_rejected": 1,
        "mechanism_suggestions.verifier_unresolved": 0,
        "mechanism_suggestions.over_cap": 0,
        "mechanism_suggestions.prompt_budget_exceeded": 0,
        "mechanism_suggestions.slot_fill_unresolved": 2,
        "mechanism_suggestions.slot_fill_not_applicable": 0,
        "mechanism_suggestions.ica_verifier_rejected": 0,
        "mechanism_suggestions.finding": 1,
    }


def test_the_breakdown_counts_rows_per_mechanism_and_stop_reason(
    tmp_path: Path,
) -> None:
    html, _ = shown(_run_with(tmp_path, _hand_written()))

    header = re.search(
        r'<table id="mechanism-suggestions-breakdown-table".*?<thead>(.*?)</thead>',
        html,
        re.S,
    ).group(1)
    assert re.findall(r"<th[^>]*>(.*?)</th>", header) == [
        "Stop reason",
        "user_claim",
        "retrieved_instructions",
        "stale_history",
        "All mechanisms",
    ]
    numbers = {
        reason: [
            int(c.replace(",", ""))
            for c in _cells(html, f"mech-breakdown-{reason.replace('_', '-')}")[1:]
        ]
        for reason in STOP_REASONS
    }
    assert numbers["not_proposed"] == [1, 2, 1, 4]
    assert numbers["slot_fill_unresolved"] == [1, 0, 1, 2]
    assert numbers["finding"] == [1, 0, 0, 1]
    assert numbers["authority_filtered"] == [0, 0, 1, 1]
    assert numbers["verifier_rejected"] == [0, 1, 0, 1]
    assert numbers["over_cap"] == [0, 0, 0, 0]


def test_every_row_is_listed_once_under_its_stop_reason(tmp_path: Path) -> None:
    html, _ = shown(_run_with(tmp_path, _hand_written()))

    for reason in {reason for _, _, reason, _, _ in PAIRS}:
        expected = sum(r == reason for _, _, r, _, _ in PAIRS)
        table_id = f"mechanism-suggestions-{reason.replace('_', '-')}-table"
        assert body_rows(html, table_id) == expected, reason
    assert "mechanism-suggestions-over-cap-table" not in html
    finding = re.search(
        r'id="mechanism-suggestions-finding-table".*?</table>', html, re.S
    ).group(0)
    assert "<code>user_claim</code>" in finding
    assert "<code>RESP-1:CA-1-1:INCORRECT</code>" in finding
    assert "<code>ICA-1</code>" in finding


def test_the_not_proposed_bulk_comes_last_and_collapsed(tmp_path: Path) -> None:
    html, _ = shown(_run_with(tmp_path, _hand_written()))

    groups = re.findall(r'<details id="mech-([a-z-]+)"( open)?>', html)
    assert groups == [
        ("authority-filtered", " open"),
        ("verifier-rejected", " open"),
        ("slot-fill-unresolved", " open"),
        ("finding", " open"),
        ("not-proposed", ""),
    ]


def test_values_are_escaped(tmp_path: Path) -> None:
    html, _ = shown(_run_with(tmp_path, _hand_written()))

    assert "<b>" not in html.replace('<b data-metric="', "")
    assert "RESP-2:CA-2-1:&lt;b&gt;" in html
    assert "no &lt;reply&gt;" in html


def test_the_section_stands_apart_from_obligation_coverage(tmp_path: Path) -> None:
    output = _run_with(tmp_path, _hand_written())
    without = copy_run(tmp_path / "without")

    html, summary = build_report(load_run(output))
    plain_html, plain_summary = build_report(load_run(without))

    obligations = _section(str(html), "obligations")
    assert obligations == _section(str(plain_html), "obligations")
    assert "mechanism_suggestions." not in obligations
    mechanisms = _section(str(html), "mechanism-suggestions")
    assert 'data-metric="obligations.' not in mechanisms
    assert summary == plain_summary


def test_a_run_without_the_file_renders_a_short_note(tmp_path: Path) -> None:
    output = copy_run(tmp_path)

    run = load_run(output)
    html, n = shown(output)

    assert run.mechanisms is None
    assert MECHANISM_SUGGESTION_ACCOUNTING_FILENAME not in run.unreadable
    assert f"{MECHANISM_SUGGESTION_ACCOUNTING_FILENAME}: not in this run" in html
    assert n == {}
    page, _ = build_report(run)
    assert '<section id="mechanism-suggestions">' in str(page)


def test_an_invalid_file_is_named_like_any_unreadable_sidecar(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    document = yaml.safe_load(_hand_written().to_yaml())
    document["summary"]["rows"] = 10
    (output / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME).write_text(
        yaml.safe_dump(document), encoding="utf-8"
    )

    run = load_run(output)
    html, _ = shown(output)

    assert run.mechanisms is None
    assert (
        "does not reconcile" in run.unreadable[MECHANISM_SUGGESTION_ACCOUNTING_FILENAME]
    )
    assert f"{MECHANISM_SUGGESTION_ACCOUNTING_FILENAME}: could not be read" in html
    answer = _section(str(build_report(run)[0]), "answer")
    assert MECHANISM_SUGGESTION_ACCOUNTING_FILENAME in answer


def test_a_recorded_accounting_renders_its_summary(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    shutil.copyfile(RECORDED, output / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME)

    html, n = shown(output)

    assert n == {
        "mechanism_suggestions.rows": 504,
        "mechanism_suggestions.not_proposed": 424,
        "mechanism_suggestions.authority_filtered": 12,
        "mechanism_suggestions.slot_not_analyzed": 17,
        "mechanism_suggestions.verifier_rejected": 12,
        "mechanism_suggestions.verifier_unresolved": 3,
        "mechanism_suggestions.over_cap": 0,
        "mechanism_suggestions.prompt_budget_exceeded": 0,
        "mechanism_suggestions.slot_fill_unresolved": 33,
        "mechanism_suggestions.slot_fill_not_applicable": 2,
        "mechanism_suggestions.ica_verifier_rejected": 0,
        "mechanism_suggestions.finding": 1,
    }
    listed = {
        reason: body_rows(
            html, f"mechanism-suggestions-{reason.replace('_', '-')}-table"
        )
        for reason in STOP_REASONS
        if n[f"mechanism_suggestions.{reason}"]
    }
    assert sum(listed.values()) == 504
    assert listed == {reason: n[f"mechanism_suggestions.{reason}"] for reason in listed}
    totals = [
        int(_cells(html, f"mech-breakdown-{reason.replace('_', '-')}")[-1])
        for reason in STOP_REASONS
    ]
    assert sum(totals) == 504
