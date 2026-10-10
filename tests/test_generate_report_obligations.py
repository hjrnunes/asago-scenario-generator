"""The attack-pattern section: one row per stop reason, in plain words."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import get_args

from asago_scenario_generator.models.obligation_funnel import ObligationStopReason
from asago_scenario_generator.report.obligation_section import (
    STOP_MEANING,
    obligation_section,
)
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report_kit import read_metrics
from tests.helpers.generate_report_fixture import copy_run, edit_yaml


def shown(output: Path) -> tuple[str, dict]:
    html = str(obligation_section(load_run(output)))
    return html, {k: int(v["value"]) for k, v in read_metrics(html).items()}


def test_every_producer_stop_reason_has_a_plain_meaning() -> None:
    codes = set(get_args(ObligationStopReason)) | {"governance_only"}

    assert codes - set(STOP_MEANING) == set()


def test_each_stop_reason_is_one_row_with_its_obligation_count(tmp_path: Path) -> None:
    _, n = shown(copy_run(tmp_path))

    assert n == {
        "obligations.governance_only": 24,
        "obligations.no_structural_route": 46,
        "obligations.risk_pattern_mismatch": 28,
        "obligations.mechanism_path_unsubstantiated": 11,
        "obligations.ica_consideration_unresolved": 6,
        "obligations.not_applicable_evidence_incomplete": 2,
        "obligations.scenario_realized": 2,
    }


def test_the_accounting_and_manifest_names_for_a_realized_obligation_meet(
    tmp_path: Path,
) -> None:
    html, n = shown(copy_run(tmp_path))

    assert "obligations.addressed" not in n
    assert "Realized by a scenario" in html


def test_a_row_names_the_attack_pattern_not_the_obligation_digest(
    tmp_path: Path,
) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "ob:v1:" not in html
    assert "AP-T8-01" in html or "AP-" in html
    assert "the routed mechanism may support an ordinary STPA finding" in html


def test_the_lead_separates_obligations_from_scenarios(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "119 attack-pattern obligations" in html
    assert "95 were routed" in html
    assert "2 were realized" in html
    assert "scenarios come from the loss analysis alone" in html


def test_routed_obligations_of_out_of_scope_risks_are_counted(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "belong to risks the boundary decision put outside" in html


def test_a_manifest_count_that_disagrees_with_the_accounting_is_flagged(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    edit_yaml(
        output / "synthesis-manifest.yaml",
        lambda m: m["obligation_stop_reason_counts"].update(no_structural_route=45),
    )

    html, _ = shown(output)

    assert "The manifest counts 45 no_structural_route obligations" in html


def test_counts_that_agree_raise_no_flag(tmp_path: Path) -> None:
    html, _ = shown(copy_run(tmp_path))

    assert "The manifest counts" not in html


def test_the_stop_reasons_of_a_run_are_all_known(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    codes = Counter(r.stop_reason or r.disposition for r in run.accounting.rows)

    assert set(codes) - set(STOP_MEANING) == set()
