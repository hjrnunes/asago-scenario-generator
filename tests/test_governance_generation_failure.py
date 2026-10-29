"""A credited governance row none of whose findings became a scenario.

A governance-only obligation is credited when its routed slots produced a
finding.  When scenario writing then failed for every one of its findings,
accounting still counted it under ``governance_credited``.  Once the run's
scenarios are known, such a row keeps its ``governance_only`` disposition and
its identities, stops at ``scenario_generation_failure``, and the summary
counts it under ``governance_generation_failed`` instead of
``governance_credited``.  The new count is left out when zero, so an
accounting without such a row keeps its bytes.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    ObligationAccountingSummary,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    account_generation_failures,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_resolution_funnel,
)
from tests.helpers.governance import (
    _ICA_ID,
    _OBLIGATION_ID,
    _SLOT_ID,
    _accounting,
    _governance_scenario,
    _scenario,
)

_OTHER_ICA_ID = "RESP-1:CA-1-1:INCORRECT:9"
_DISPOSITIONS = (
    "addressed",
    "generation_failed",
    "proposed_not_applicable",
    "unresolved",
    "upstream_gap",
    "capability_excluded",
    "governance_only",
)
_GOVERNANCE_SUBSETS = (
    "governance_credited",
    "governance_routed_no_finding",
    "governance_generation_failed",
)


def _credited_row(*ica_ids: str) -> ObligationAccountingRow:
    return ObligationAccountingRow(
        obligation_id=_OBLIGATION_ID,
        disposition="governance_only",
        slot_ids=(_SLOT_ID,),
        ica_ids=ica_ids or (_ICA_ID,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        route_refs=("route-1",),
        evidence=("phase1:governance", "pair-1"),
    )


def _with_rows(*rows: ObligationAccountingRow) -> ObligationAccounting:
    return ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=rows,
        summary=derive_obligation_accounting_summary(rows),
    )


def _assert_totals_sum(accounting: ObligationAccounting) -> None:
    summary = accounting.summary.model_dump()
    assert summary["total"] == len(accounting.rows)
    assert sum(summary.get(name, 0) for name in _DISPOSITIONS) == summary["total"]
    assert (
        sum(summary.get(name, 0) for name in _GOVERNANCE_SUBSETS)
        <= summary["governance_only"]
    )


def test_a_credited_governance_row_no_scenario_carries_failed_generation() -> None:
    credited = _credited_row()
    # Another obligation's scenario exists; none carries the governance finding.
    accounting = account_generation_failures(
        _with_rows(credited), scenario_specs=(_scenario(include_obligation=False),)
    )

    [row] = accounting.rows
    assert row.disposition == "governance_only"
    assert row.stop_reason == "scenario_generation_failure"
    assert row.ica_ids == credited.ica_ids
    assert row.exec_candidate_ids == credited.exec_candidate_ids
    assert row.route_refs == credited.route_refs
    assert accounting.summary.governance_only == 1
    assert accounting.summary.governance_credited == 0
    assert accounting.summary.governance_generation_failed == 1
    assert accounting.summary.generation_failed == 0
    _assert_totals_sum(accounting)
    accounting.assert_integrity()
    reloaded = ObligationAccounting.model_validate(accounting.model_dump(mode="json"))
    assert reloaded.semantic_digest == accounting.semantic_digest
    assert reloaded.summary.governance_generation_failed == 1


def test_a_credited_governance_row_with_one_carried_finding_stays_credited() -> None:
    rows = (_credited_row(_ICA_ID, _OTHER_ICA_ID),)
    accounting = account_generation_failures(
        _with_rows(*rows),
        scenario_specs=(
            _governance_scenario(),
            _scenario(include_obligation=False, scenario_id="SCN-002"),
        ),
    )

    [row] = accounting.rows
    assert row.disposition == "governance_only"
    assert row.stop_reason is None
    assert accounting.summary.governance_credited == 1
    assert accounting.summary.governance_generation_failed == 0
    _assert_totals_sum(accounting)


def test_an_accounting_without_a_governance_failure_keeps_its_bytes() -> None:
    before = _with_rows(_credited_row())
    accounting = account_generation_failures(
        before, scenario_specs=(_governance_scenario(),)
    )

    dumped = accounting.model_dump(mode="json")
    assert "governance_generation_failed" not in dumped["summary"]
    assert dumped == before.model_dump(mode="json")
    assert accounting.semantic_digest == before.semantic_digest
    assert (
        "governance_generation_failed"
        not in (_accounting().model_dump(mode="json")["summary"])
    )


def test_a_failed_governance_row_and_an_addressed_failure_count_apart() -> None:
    governance = _credited_row().model_copy(
        update={"obligation_id": "ob:v1:" + "2" * 64}
    )
    accounting = account_generation_failures(
        _with_rows(*_accounting().rows, governance), scenario_specs=()
    )

    assert accounting.summary.generation_failed == 1
    assert accounting.summary.governance_generation_failed == 1
    assert accounting.summary.governance_credited == 0
    assert accounting.summary.addressed == 0
    _assert_totals_sum(accounting)


def test_a_failed_governance_row_requires_its_findings() -> None:
    with pytest.raises(ValueError, match="governance-only rows"):
        ObligationAccountingRow(
            obligation_id=_OBLIGATION_ID,
            disposition="governance_only",
            stop_reason="scenario_generation_failure",
            evidence=("phase1:governance",),
        )


def test_the_summary_refuses_governance_counts_beyond_governance_only() -> None:
    with pytest.raises(ValueError, match="governance_only"):
        ObligationAccountingSummary(
            total=1,
            addressed=0,
            proposed_not_applicable=0,
            unresolved=0,
            upstream_gap=0,
            capability_excluded=0,
            governance_only=1,
            governance_credited=1,
            governance_generation_failed=1,
        )


def test_the_summary_refuses_dispositions_that_do_not_sum_to_total() -> None:
    with pytest.raises(ValueError, match="total"):
        ObligationAccountingSummary(
            total=2,
            addressed=1,
            proposed_not_applicable=0,
            unresolved=0,
            upstream_gap=0,
            capability_excluded=0,
            governance_only=0,
        )


def _funnel(accounting: ObligationAccounting) -> dict[str, Any]:
    return _obligation_resolution_funnel(
        plan=SimpleNamespace(obligations=accounting.rows),
        accounting=accounting,
        realization=SimpleNamespace(records=()),
        scenario_count=0,
    )


def test_the_funnel_counts_a_failed_governance_row_apart_from_credits() -> None:
    accounting = account_generation_failures(
        _with_rows(_credited_row()), scenario_specs=()
    )

    funnel = _funnel(accounting)
    assert funnel["governance_only"] == 1
    assert funnel["governance_generation_failed"] == 1
    assert "governance_credited" not in funnel
    assert funnel["terminal_reasons"] == {}
    assert funnel["reconciles"] is True


def test_the_funnel_without_a_failed_governance_row_keeps_its_shape() -> None:
    funnel = _funnel(_with_rows(_credited_row()))

    assert funnel["governance_credited"] == 1
    assert "governance_generation_failed" not in funnel
