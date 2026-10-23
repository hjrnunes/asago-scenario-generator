"""Accounting rows record the Stage 1a scope of their risk.

An out-of-scope scope takes precedence as the stop reason of a row the
analysis did not credit, so ``risk_pattern_mismatch`` and the other reasons
count in-scope misses only.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_briefs,
    build_obligation_accounting,
)
from asago_scenario_generator.pipeline.synthesis import run_synthesis
from asago_scenario_generator.pipeline.synthesis_scenarios import _run_accounting
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)
from asago_scenario_generator.stpa.system_model.run import SP1RunResult

from tests.helpers.governance import _accounting_pins, _plan_with_non_stpa_rows
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.synthesis import _FakeAdapters, _inputs

_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_EXEC = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"
_GOVERNANCE_ID = "ob:v1:" + "b" * 64
_EXCLUDED_ID = "ob:v1:" + "c" * 64
# Both the applicable pattern row and the capability-excluded row carry this
# risk; the governance-only row carries its own.
_PATTERN_RISK = "risk-a"
_GOVERNANCE_RISK = "governance-risk"


def _mismatch() -> ObligationSemanticAssessment:
    return ObligationSemanticAssessment(
        mechanism_assessment="plausible_in_system",
        risk_alignment="mismatch",
        mapping_strength="broad_category_expansion",
        mechanism_rationale="The mechanism exists in the system.",
        risk_alignment_rationale="The mechanism does not realize the risk.",
    )


def _build(
    *,
    route_kind: str = "finding",
    risk_scopes: dict[str, str] | None = None,
    governance_route: bool = False,
) -> ObligationAccounting:
    """Account the fixture plan with one pattern route of *route_kind*.

    ``finding`` credits the row, ``mismatch`` stops it at
    ``risk_pattern_mismatch``, and ``unresolved`` leaves it with an unresolved
    route, which stops at ``no_structural_route``.
    """
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    routes: tuple[ObligationRoute, ...] = (
        ObligationRoute(
            obligation_id=briefs[0].obligation_id,
            disposition="unresolved",
            rationale="No control action bears on the mechanism.",
            evidence=("route evidence",),
        ),
    )
    pairs: tuple[ObligationIcaConsideration, ...] = ()
    if route_kind != "unresolved":
        route = ObligationRoute(
            obligation_id=briefs[0].obligation_id,
            disposition="targeted",
            semantic_assessment=_mismatch() if route_kind == "mismatch" else None,
            slot_ids=(_SLOT,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("route evidence",),
        )
        routes = (route,)
        pairs = (
            ObligationIcaConsideration(
                route_id=route.route_id,
                obligation_id=route.obligation_id,
                slot_id=_SLOT,
                disposition="finding",
                ica_ids=("ica-1",),
                exec_candidate_ids=(_EXEC,),
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                evidence=("ica evidence",),
            ),
        )
    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=routes, final_routes=routes
    )
    kwargs: dict[str, Any] = {}
    if governance_route:
        kwargs["governance_routes"] = (
            ObligationRoute(
                obligation_id=_GOVERNANCE_ID,
                disposition="targeted",
                slot_ids=(_SLOT,),
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                rationale="The control action could bring about the risk.",
                evidence=("governance: reviewed risk",),
            ),
        )
    if risk_scopes is not None:
        kwargs["risk_scopes"] = risk_scopes
    return build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=pairs,
        source_pins=_accounting_pins(plan),
        **kwargs,
    )


def _pattern_row(accounting: ObligationAccounting) -> ObligationAccountingRow:
    return next(
        row
        for row in accounting.rows
        if row.obligation_id not in {_GOVERNANCE_ID, _EXCLUDED_ID}
    )


def _row(accounting: ObligationAccounting, obligation_id: str) -> Any:
    return next(row for row in accounting.rows if row.obligation_id == obligation_id)


def test_accounting_without_scopes_keeps_its_rows_and_bytes() -> None:
    plain = _build(route_kind="mismatch")
    empty = _build(route_kind="mismatch", risk_scopes={})

    assert empty == plain
    assert all(row.scope is None for row in plain.rows)
    assert all("scope" not in row for row in plain.model_dump(mode="json")["rows"])


def test_every_row_records_the_scope_of_its_risk() -> None:
    accounting = _build(
        risk_scopes={_PATTERN_RISK: "actionable", _GOVERNANCE_RISK: "not_applicable"}
    )

    assert _pattern_row(accounting).scope == "actionable"
    assert _row(accounting, _EXCLUDED_ID).scope == "actionable"
    assert _row(accounting, _GOVERNANCE_ID).scope == "not_applicable"
    dumped = accounting.model_dump(mode="json")["rows"]
    assert {row["scope"] for row in dumped} == {"actionable", "not_applicable"}


def test_a_risk_without_a_decision_leaves_its_rows_unscoped() -> None:
    accounting = _build(risk_scopes={_GOVERNANCE_RISK: "actionable"})

    assert _pattern_row(accounting).scope is None
    assert _row(accounting, _GOVERNANCE_ID).scope == "actionable"


@pytest.mark.parametrize("scope", ("outside_boundary", "not_applicable"))
def test_out_of_scope_takes_precedence_over_a_pattern_mismatch(scope: str) -> None:
    accounting = _build(route_kind="mismatch", risk_scopes={_PATTERN_RISK: scope})

    row = _pattern_row(accounting)
    assert row.scope == scope
    assert row.stop_reason == "risk_out_of_scope"
    assert row.disposition == "unresolved"
    # Only the stop reason changes; the analysis trace stays on the row.
    assert row.diagnostics == _pattern_row(_build(route_kind="mismatch")).diagnostics
    accounting.assert_integrity()


def test_an_in_scope_mismatch_keeps_its_stop_reason() -> None:
    accounting = _build(
        route_kind="mismatch", risk_scopes={_PATTERN_RISK: "actionable"}
    )

    row = _pattern_row(accounting)
    assert row.scope == "actionable"
    assert row.stop_reason == "risk_pattern_mismatch"


def test_out_of_scope_takes_precedence_over_a_missing_structural_route() -> None:
    plain = _pattern_row(_build(route_kind="unresolved"))
    scoped = _pattern_row(
        _build(route_kind="unresolved", risk_scopes={_PATTERN_RISK: "outside_boundary"})
    )

    assert plain.stop_reason == "no_structural_route"
    assert scoped.stop_reason == "risk_out_of_scope"


def test_an_addressed_row_keeps_its_credit_when_out_of_scope() -> None:
    accounting = _build(risk_scopes={_PATTERN_RISK: "outside_boundary"})

    row = _pattern_row(accounting)
    assert row.disposition == "addressed"
    assert row.stop_reason == "addressed"
    assert row.scope == "outside_boundary"
    assert accounting.summary.addressed == 1


def test_rows_without_a_stop_reason_and_governance_rows_keep_theirs() -> None:
    accounting = _build(
        risk_scopes={
            _PATTERN_RISK: "outside_boundary",
            _GOVERNANCE_RISK: "outside_boundary",
        },
        governance_route=True,
    )

    excluded = _row(accounting, _EXCLUDED_ID)
    assert excluded.disposition == "capability_excluded"
    assert excluded.stop_reason is None
    governance = _row(accounting, _GOVERNANCE_ID)
    assert governance.stop_reason == "governance_routed_no_finding"
    assert governance.scope == "outside_boundary"


def test_scoped_accounting_round_trips_with_its_digest() -> None:
    accounting = _build(
        route_kind="mismatch", risk_scopes={_PATTERN_RISK: "not_applicable"}
    )

    reloaded = ObligationAccounting.model_validate(accounting.model_dump(mode="json"))

    assert reloaded == accounting
    assert reloaded.semantic_digest == accounting.semantic_digest
    assert reloaded.semantic_digest != _build(route_kind="mismatch").semantic_digest


@pytest.mark.parametrize("scope", (None, "actionable"))
def test_the_out_of_scope_stop_reason_needs_an_out_of_scope_risk(
    scope: str | None,
) -> None:
    with pytest.raises(ValidationError, match="risk_out_of_scope belongs to rows"):
        ObligationAccountingRow(
            obligation_id="ob:v1:" + "d" * 64,
            disposition="unresolved",
            stop_reason="risk_out_of_scope",
            evidence=("consideration:missing-final-route",),
            scope=scope,
        )


def test_run_accounting_hands_the_adapter_the_risk_scopes() -> None:
    received: dict[str, object] = {}

    def account(**kwargs: object) -> object:
        received.update(kwargs)
        return object()

    def run(risk_scopes: dict[str, str] | None) -> None:
        received.clear()
        _run_accounting(
            plan=SimpleNamespace(),
            consideration=SimpleNamespace(),
            routes=(),
            ica_enumeration=ICAEnumeration(slots=[]),
            scenario_result=SimpleNamespace(),
            loss_analysis=SimpleNamespace(),
            control_structure=SimpleNamespace(),
            inputs=SimpleNamespace(output_dir=Path(".")),
            snapshot=SimpleNamespace(),
            adapters=SynthesisAdapters(account=account),
            slot_evidence=ICAEnumeration(slots=[]),
            risk_scopes=risk_scopes,
        )

    run({"risk-a": "outside_boundary"})
    assert received["risk_scopes"] == {"risk-a": "outside_boundary"}
    run(None)
    assert "risk_scopes" not in received


def test_run_synthesis_hands_accounting_the_baseline_scope_decisions(
    tmp_path: Path,
) -> None:
    received: dict[str, object] = {}
    record = RiskActionabilityRecord(
        status="completed",
        call_count=1,
        counts={},
        entries=[
            RiskActionabilityEntry(
                risk_id=_PATTERN_RISK,
                decision="outside_boundary",
                reason="Only staff outside the system act.",
                source="model",
            )
        ],
    )

    class Adapters(_FakeAdapters):
        def baseline(self, **kwargs: object) -> object:
            result = super().baseline(**kwargs)
            assert isinstance(result, SP1RunResult)
            result.risk_actionability = record
            return result

        def account(self, **kwargs: object) -> object:
            received.update(kwargs)
            return super().account(**kwargs)

    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(Adapters(calls=[])))

    assert received["risk_scopes"] == {_PATTERN_RISK: "outside_boundary"}
