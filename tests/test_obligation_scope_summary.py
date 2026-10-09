"""The synthesis manifest splits obligation outcomes by the boundary decision."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_scope_summary,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)


def _record(decisions: dict[str, str]) -> RiskActionabilityRecord:
    entries = [
        RiskActionabilityEntry(
            risk_id=risk_id, decision=decision, reason="r", source="model"
        )
        for risk_id, decision in decisions.items()
    ]
    return RiskActionabilityRecord(
        status="completed", call_count=1, counts={}, entries=entries
    )


def _plan(risks: dict[str, str]) -> Any:
    return SimpleNamespace(
        obligations=[
            SimpleNamespace(
                obligation_id=obligation_id,
                risk_ref=SimpleNamespace(risk_id=risk_id),
            )
            for obligation_id, risk_id in risks.items()
        ]
    )


def _row(obligation_id: str, disposition: str, stop_reason: str | None) -> Any:
    return SimpleNamespace(
        obligation_id=obligation_id, disposition=disposition, stop_reason=stop_reason
    )


def _summary(rows: list[Any], risks: dict[str, str], record: Any) -> dict[str, Any]:
    return _obligation_scope_summary(
        plan=_plan(risks),
        accounting=SimpleNamespace(rows=rows),
        realization=SimpleNamespace(records=()),
        risk_actionability=record,
    )


RISKS = {"ob-a": "R-1", "ob-b": "R-2", "ob-c": "R-3", "ob-d": "R-4", "ob-e": "R-5"}
DECISIONS = {
    "R-1": "actionable",
    "R-2": "outside_boundary",
    "R-3": "not_applicable",
    "R-4": "outside_boundary",
}


def test_summary_counts_applicable_addressed_and_stop_reasons_per_scope() -> None:
    rows = [
        _row("ob-a", "addressed", "addressed"),
        _row("ob-b", "proposed_not_applicable", "risk_pattern_mismatch"),
        _row("ob-c", "addressed", "addressed"),
        _row("ob-d", "unresolved", "risk_pattern_mismatch"),
        _row("ob-e", "unresolved", "no_structural_route"),
    ]

    summary = _summary(rows, RISKS, _record(DECISIONS))

    assert summary == {
        "decision_source": "completed",
        "in_scope": {
            "applicable": 2,
            "addressed": 1,
            "stop_reasons": {"addressed": 1, "no_structural_route": 1},
        },
        "out_of_scope": {
            "applicable": 3,
            "addressed": 1,
            "stop_reasons": {"addressed": 1, "risk_pattern_mismatch": 2},
            "outside_boundary": 2,
            "not_applicable": 1,
        },
    }


def test_obligation_of_an_unclassified_risk_counts_as_in_scope() -> None:
    summary = _summary(
        [_row("ob-e", "unresolved", "no_structural_route")],
        RISKS,
        _record({"R-1": "actionable"}),
    )

    assert summary["in_scope"]["applicable"] == 1
    assert summary["out_of_scope"]["applicable"] == 0


def test_governance_rows_and_rows_without_a_stop_reason_are_not_counted() -> None:
    rows = [
        _row("ob-b", "governance_only", "governance_routed_no_finding"),
        _row("ob-c", "capability_excluded", None),
    ]

    summary = _summary(rows, RISKS, _record(DECISIONS))

    assert summary["in_scope"]["applicable"] == 0
    assert summary["out_of_scope"]["applicable"] == 0


def test_run_without_a_boundary_decision_puts_every_obligation_in_scope() -> None:
    summary = _summary([_row("ob-b", "unresolved", "no_structural_route")], RISKS, None)

    assert summary["decision_source"] == "absent"
    assert summary["in_scope"]["applicable"] == 1
    assert summary["out_of_scope"]["applicable"] == 0
