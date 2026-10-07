"""A credited governance row realizes scenarios and shows in the funnel."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_resolution_funnel,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
    ScenarioObligationConsideration,
)
from tests.test_scenario_realization import (
    _ICA_ID,
    _OBLIGATION_ID,
    _SLOT_ID,
    _accounting,
    _context,
    _enumeration,
    _pair,
    _scenario,
)


def _row(*, credited: bool) -> ObligationAccountingRow:
    if not credited:
        return ObligationAccountingRow(
            obligation_id=_OBLIGATION_ID,
            disposition="governance_only",
            evidence=("phase1:governance",),
        )
    return ObligationAccountingRow(
        obligation_id=_OBLIGATION_ID,
        disposition="governance_only",
        slot_ids=(_SLOT_ID,),
        ica_ids=(_ICA_ID,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        route_refs=("route-1",),
        evidence=("phase1:governance", "pair-1"),
    )


def _governance_accounting(*, credited: bool) -> ObligationAccounting:
    rows = (_row(credited=credited),)
    return ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=rows,
        summary=derive_obligation_accounting_summary(rows),
    )


def _governance_scenario() -> Any:
    base = _context()
    context = ScenarioGenerationContext.create(
        source_pins=base.source_pins,
        scenario_identity=base.scenario_identity,
        ica=base.ica,
        target_control_path=base.target_control_path,
        losses=base.losses,
        hazards=base.hazards,
        constraints=base.constraints,
        obligation_considerations=(
            ScenarioObligationConsideration(
                obligation_id=_OBLIGATION_ID,
                kind="governance",
                risk_id="risk-governance",
                risk_name="Governance risk",
                concise_concern="A reviewed risk with no catalogued attack pattern.",
                disposition="finding",
                rationale="The selected ICA expresses the reviewed risk.",
                finding_ica_id=_ICA_ID,
            ),
        ),
    )
    return _scenario().model_copy(update={"scenario_context": context})


def _realize(
    accounting: ObligationAccounting, scenario: Any, *, requested: bool = True
) -> Any:
    return build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(scenario,),
        requested_ica_ids=(_ICA_ID,) if requested else (),
    )


def test_credited_governance_finding_realizes_its_scenario() -> None:
    result = _realize(_governance_accounting(credited=True), _governance_scenario())

    assert result.summary.model_dump() == {
        "total": 1,
        "realized": 1,
        "unresolved": 0,
        "not_requested": 0,
    }
    assert result.records[0].obligation_id == _OBLIGATION_ID
    assert result.records[0].stop_reason == "scenario_realized"
    assert result.records[0].scenario_ids == ("SCN-001",)


def test_credited_governance_finding_without_scenario_is_unresolved() -> None:
    result = _realize(
        _governance_accounting(credited=True),
        _scenario(include_obligation=False),
    )

    assert result.records[0].status == "unresolved"
    assert result.records[0].stop_reason == "scenario_generation_failure"


def test_bare_governance_row_keeps_its_finding_as_trace_only() -> None:
    result = _realize(
        _governance_accounting(credited=False),
        _governance_scenario(),
        requested=False,
    )

    assert result.records == ()
    assert result.summary.total == 0


def _funnel(accounting: ObligationAccounting, realization: Any) -> dict[str, Any]:
    plan = SimpleNamespace(obligations=accounting.rows)
    return _obligation_resolution_funnel(
        plan=plan,
        accounting=accounting,
        realization=realization,
        scenario_count=1,
    )


def test_funnel_counts_credited_and_realized_governance_rows_apart() -> None:
    accounting = _governance_accounting(credited=True)
    funnel = _funnel(accounting, _realize(accounting, _governance_scenario()))

    assert funnel["governance_only"] == 1
    assert funnel["governance_credited"] == 1
    assert funnel["governance_realized"] == 1
    assert funnel["applicable_and_considered"] == 0
    assert funnel["terminal_reasons"] == {}
    assert funnel["reconciles"] is True
    assert funnel["realized_obligation_denominator"] == 1


def test_funnel_without_a_credit_keeps_its_exact_shape() -> None:
    accounting = _governance_accounting(credited=False)
    realization = _realize(accounting, _governance_scenario(), requested=False)
    funnel = _funnel(accounting, realization)

    assert funnel == {
        "all_plan_rows": 1,
        "governance_only": 1,
        "capability_excluded": 0,
        "applicable_and_considered": 0,
        "terminal_reasons": {},
        "terminal_reason_total": 0,
        "reconciles": True,
        "realized_obligation_denominator": 0,
        "admitted_scenario_denominator": 1,
    }


def test_report_row_names_the_governance_credit_and_its_route() -> None:
    from asago_scenario_generator.report.synthesis import _obligation_row

    plan_row = {
        "obligation_id": _OBLIGATION_ID,
        "scope_disposition": "governance_only",
        "qualification_disposition": "not_attempted",
    }
    credited = _obligation_row(plan_row, None, _row(credited=True))
    bare = _obligation_row(plan_row, None, _row(credited=False))

    assert "credited with an STPA finding" in credited
    assert "governance route: route-1" in credited
    assert _ICA_ID in credited
    assert "credited" not in bare
    assert "not applicable to this row" in bare


def test_report_summary_rows_appear_only_with_a_credit() -> None:
    from asago_scenario_generator.report.synthesis import _governance_summary_rows

    assert _governance_summary_rows({"obligation_resolution_funnel": {}}) == []
    rows = _governance_summary_rows(
        {
            "obligation_resolution_funnel": {
                "governance_credited": 2,
                "governance_realized": 1,
            }
        }
    )
    assert any("credited" in row and "2" in row for row in rows)
    assert any("realized" in row and "1" in row for row in rows)


def test_funnel_accepts_rows_that_carry_no_finding_fields() -> None:
    """Callers outside the accounting model pass bare row-like objects."""
    bare = SimpleNamespace(
        obligation_id=_OBLIGATION_ID, disposition="governance_only", stop_reason=None
    )
    funnel = _obligation_resolution_funnel(
        plan=SimpleNamespace(obligations=(bare,)),
        accounting=SimpleNamespace(rows=(bare,)),
        realization=SimpleNamespace(records=()),
        scenario_count=0,
    )

    assert funnel["governance_only"] == 1
    assert "governance_credited" not in funnel


def test_pattern_rows_are_unaffected_beside_a_credited_governance_row() -> None:
    pattern = _accounting().rows[0]
    rows = (
        pattern,
        _row(credited=True).model_copy(update={"obligation_id": "ob:v1:" + "2" * 64}),
    )
    accounting = ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=rows,
        summary=derive_obligation_accounting_summary(rows),
    )

    assert accounting.summary.governance_credited == 1
    assert accounting.summary.addressed == 1
    assert accounting.summary.governance_only == 1
