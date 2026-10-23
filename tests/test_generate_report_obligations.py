"""The attack-pattern section: one row per stop reason, in plain words."""

from __future__ import annotations

import re
from collections import Counter
from html import unescape
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import yaml

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.obligation_funnel import ObligationStopReason
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_resolution_funnel,
    _obligation_stop_reason_counts,
)
from asago_scenario_generator.report.obligation_section import (
    REALIZED,
    STOP_MEANING,
    obligation_rows,
    stop_key,
    obligation_section,
)
from asago_scenario_generator.report.run_data import load_run
from tests.helpers.generate_report_fixture import (
    body_rows,
    copy_run,
    edit_yaml,
    metrics,
)


def shown(output: Path) -> tuple[str, dict]:
    html = str(obligation_section(load_run(output)))
    return html, metrics(html)


def test_every_stop_reason_table_lists_one_row_per_obligation(tmp_path: Path) -> None:
    html, n = shown(copy_run(tmp_path))

    for key, count in n.items():
        stop = key.removeprefix("obligations.").replace("_", "-")
        assert body_rows(html, f"obligations-{stop}-table") == count, key


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


def test_a_functional_test_obligation_is_counted_apart_from_a_realized_one() -> None:
    assert stop_key("scenario_functional_test") == "scenario_functional_test"
    assert stop_key("addressed") == stop_key("scenario_realized")
    assert "scenario_functional_test" not in REALIZED
    assert STOP_MEANING["scenario_functional_test"][0] == "Became an everyday check"


# Accounting rows the scoped fixture edits, keyed by the start of their ID.
_SCOPE_EDITS: dict[str, dict] = {
    # Addressed, out of scope, though policy coverage says reachable.
    "ob:v1:74d37fbf": {"scope": "outside_boundary"},
    "ob:v1:94edcaa9": {"scope": "actionable"},
    # In scope: keeps its mismatch.
    "ob:v1:18b39b11": {"scope": "actionable"},
    # Out of scope: the scope takes precedence as the stop reason.
    "ob:v1:0c46ef6b": {"scope": "outside_boundary", "stop_reason": "risk_out_of_scope"},
    # Capability-excluded, out of scope and in scope.
    "ob:v1:028c34ec": {
        "disposition": "capability_excluded",
        "stop_reason": "risk_out_of_scope",
        "scope": "not_applicable",
        "route_refs": [],
    },
    "ob:v1:2b30af4c": {
        "disposition": "capability_excluded",
        "stop_reason": None,
        "scope": "actionable",
        "route_refs": [],
    },
    # In scope by its own decision, though policy coverage says outside.
    "ob:v1:05ed7cad": {"scope": "actionable"},
}


def _scoped_run(tmp_path: Path) -> tuple[Path, ObligationAccounting, dict]:
    """Copy the fixture, scope some rows, and rewrite the manifest to match.

    The manifest counts come from the manifest's own functions over the
    edited accounting, so the report is checked against what a run writes.
    """
    output = copy_run(tmp_path)
    path = output / "obligation-accounting.yaml"
    data = yaml.safe_load(path.read_text())
    for row in data["rows"]:
        row.update(_SCOPE_EDITS.get(row["obligation_id"][:14], {}))
    rows = [ObligationAccountingRow.model_validate(row) for row in data["rows"]]
    accounting = ObligationAccounting.model_validate(
        {
            **data,
            "rows": rows,
            "summary": derive_obligation_accounting_summary(rows),
            "semantic_digest": None,
        }
    )
    path.write_text(accounting.to_yaml())
    plan = load_run(output).plan
    funnel = _obligation_resolution_funnel(
        plan=SimpleNamespace(obligations=plan),
        accounting=accounting,
        realization=SimpleNamespace(records=()),
        scenario_count=0,
    )
    counts = {
        stop_key(reason): count
        for reason, count in _obligation_stop_reason_counts(
            accounting, SimpleNamespace(records=())
        ).items()
    }

    def rewrite(manifest: dict) -> None:
        manifest["obligation_stop_reason_counts"] = counts
        manifest["obligation_resolution_funnel"].update(
            capability_excluded=funnel["capability_excluded"],
            applicable_and_considered=funnel["applicable_and_considered"],
        )

    edit_yaml(output / "synthesis-manifest.yaml", rewrite)
    return output, accounting, funnel


def test_a_scoped_run_shows_every_category_with_its_meaning(tmp_path: Path) -> None:
    output, _, _ = _scoped_run(tmp_path)

    html, n = shown(output)

    assert n == {
        "obligations.governance_only": 24,
        "obligations.capability_excluded": 2,
        "obligations.no_structural_route": 44,
        "obligations.risk_out_of_scope": 1,
        "obligations.risk_pattern_mismatch": 27,
        "obligations.mechanism_path_unsubstantiated": 11,
        "obligations.ica_consideration_unresolved": 6,
        "obligations.not_applicable_evidence_incomplete": 2,
        "obligations.scenario_realized": 2,
    }
    text = unescape(html)
    for key in (
        "scenario_realized",
        "risk_pattern_mismatch",
        "risk_out_of_scope",
        "capability_excluded",
        "governance_only",
    ):
        label, meaning = STOP_MEANING[key]
        assert label in text, key
        assert meaning in text, key
    assert body_rows(html, "obligations-capability-excluded-table") == 2
    assert "Counts disagree" not in html


def test_the_lead_and_callout_count_routed_rows_as_the_manifest_does(
    tmp_path: Path,
) -> None:
    output, accounting, funnel = _scoped_run(tmp_path)
    run = load_run(output)
    coverage = {
        rid: risk["coverage"]
        for risk in run.policy["risks"]
        for rid in [risk["risk_id"], *risk["merged_ids"]]
    }
    risk_of = {o.obligation_id: o.risk_ref.risk_id for o in run.plan}
    routed = [
        row
        for row in accounting.rows
        if row.disposition not in {"governance_only", "capability_excluded"}
    ]
    outside = sum(
        row.scope in {"outside_boundary", "not_applicable"}
        if row.scope is not None
        else coverage.get(risk_of[row.obligation_id]) == "outside_boundary"
        for row in routed
    )

    html, _ = shown(output)

    assert len(routed) == funnel["applicable_and_considered"] == 93
    assert "24 map to no attack pattern" in html
    assert f"{funnel['capability_excluded']} need a capability" in html
    assert "and 93 were routed to the control structure" in html
    assert "the other 91 stopped" in html
    assert f"{outside} of the 93 routed obligations belong to risks" in html


def test_a_row_scope_decides_the_outside_badge_over_policy_coverage(
    tmp_path: Path,
) -> None:
    output, accounting, _ = _scoped_run(tmp_path)

    rows = dict(
        zip(
            (row.obligation_id[:14] for row in accounting.rows),
            obligation_rows(load_run(output)),
        )
    )
    html, _ = shown(output)

    # Addressed, scoped out, while policy coverage says reachable.
    assert rows["ob:v1:74d37fbf"].outside is True
    assert rows["ob:v1:94edcaa9"].outside is False
    realized = re.search(
        r'<table[^>]*id="obligations-scenario-realized-table".*?</table>', html, re.S
    ).group(0)
    assert realized.count("outside boundary") == 1
    # Scoped in, while policy coverage says outside.
    assert rows["ob:v1:05ed7cad"].outside is False
    # Rows written without a scope still follow policy coverage.
    assert rows["ob:v1:0a181c27"].outside is True
