"""A governance-only obligation is credited when its routed slot has a finding."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_obligation_briefs,
    build_obligation_accounting,
)
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_accounting_contracts import (
    _accounting_pins,
    _plan_with_non_stpa_rows,
)

_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_EXEC = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"
_GOVERNANCE_ID = "ob:v1:" + "b" * 64

# Digest and bytes of the accounting built below without a governance route,
# recorded from 04a926bd before the credit existed.
_PRE_CREDIT_DIGEST = "0c2db171b128a1b204faf704e7aea0a2b9ee7d0fa17d43b3f4a47eda03ff00ba"
_PRE_CREDIT_JSON_SHA256 = (
    "aee332e6c02993c729857e6c514dd67175b26394e0d9bd7eb41dbd7ba99707a0"
)
_PRE_CREDIT_JSON_LEN = 2059


def _inputs() -> tuple[Any, Any, ObligationIcaConsideration]:
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_obligation_briefs(plan, (pattern,))
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=(_SLOT,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route evidence",),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=_SLOT,
        disposition="finding",
        ica_ids=("ica-1",),
        exec_candidate_ids=(_EXEC,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("ica evidence",),
    )
    return plan, consideration, pair


def _governance_route(*, disposition: str = "targeted") -> ObligationRoute:
    return ObligationRoute(
        obligation_id=_GOVERNANCE_ID,
        disposition=disposition,
        slot_ids=(_SLOT,) if disposition == "targeted" else (),
        hazard_ids=("H-1",) if disposition == "targeted" else (),
        constraint_ids=("SC-1",) if disposition == "targeted" else (),
        rationale="The control action could bring about the reviewed risk.",
        evidence=("governance: reviewed risk",),
    )


def _governance_pair(
    route: ObligationRoute, *, disposition: str = "finding"
) -> ObligationIcaConsideration:
    if disposition == "finding":
        return ObligationIcaConsideration(
            route_id=route.route_id,
            obligation_id=_GOVERNANCE_ID,
            slot_id=_SLOT,
            disposition="finding",
            ica_ids=("ica-gov-1",),
            exec_candidate_ids=("EXEC:RESP-1:CA-1-1:NOT_PROVIDED",),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("call:ica:gov",),
        )
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=_GOVERNANCE_ID,
        slot_id=_SLOT,
        disposition="unresolved",
        rationale="The slot evidence cannot decide.",
        evidence=("call:ica:gov",),
    )


def _build(*, pairs: tuple[Any, ...] = (), governance_routes: tuple[Any, ...] = ()):
    plan, consideration, pair = _inputs()
    kwargs: dict[str, Any] = {}
    if governance_routes:
        kwargs["governance_routes"] = governance_routes
    return build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair, *pairs),
        source_pins=_accounting_pins(plan),
        **kwargs,
    )


def _row(accounting: ObligationAccounting, obligation_id: str) -> Any:
    return next(row for row in accounting.rows if row.obligation_id == obligation_id)


def test_accounting_without_a_governance_route_keeps_its_bytes() -> None:
    accounting = _build()
    text = json.dumps(
        accounting.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )

    assert accounting.semantic_digest == _PRE_CREDIT_DIGEST
    assert hashlib.sha256(text.encode()).hexdigest() == _PRE_CREDIT_JSON_SHA256
    assert len(text) == _PRE_CREDIT_JSON_LEN
    assert "governance_credited" not in text
    assert accounting.summary.governance_credited == 0


def test_governance_finding_credits_the_row_and_keeps_its_disposition() -> None:
    route = _governance_route()
    accounting = _build(pairs=(_governance_pair(route),), governance_routes=(route,))

    row = _row(accounting, _GOVERNANCE_ID)
    assert row.disposition == "governance_only"
    assert row.stop_reason is None
    assert row.slot_ids == (_SLOT,)
    assert row.ica_ids == ("ica-gov-1",)
    assert row.exec_candidate_ids == (_EXEC,)
    assert row.hazard_ids == ("H-1",)
    assert row.constraint_ids == ("SC-1",)
    assert row.route_refs == (route.route_id,)
    assert accounting.summary.governance_only == 1
    assert accounting.summary.governance_credited == 1
    assert accounting.summary.addressed == 1
    accounting.assert_integrity()
    reloaded = ObligationAccounting.model_validate(accounting.model_dump(mode="json"))
    assert reloaded.semantic_digest == accounting.semantic_digest


def test_other_rows_are_unchanged_by_a_governance_credit() -> None:
    plain = _build()
    route = _governance_route()
    credited = _build(pairs=(_governance_pair(route),), governance_routes=(route,))

    for row in plain.rows:
        if row.obligation_id != _GOVERNANCE_ID:
            assert _row(credited, row.obligation_id) == row


@pytest.mark.parametrize("case", ("unresolved_pair", "no_pair", "declined_route"))
def test_governance_route_without_a_finding_is_not_credited(case: str) -> None:
    if case == "declined_route":
        route = _governance_route(disposition="unresolved")
        pairs: tuple[Any, ...] = ()
    elif case == "no_pair":
        route = _governance_route()
        pairs = ()
    else:
        route = _governance_route()
        pairs = (_governance_pair(route, disposition="unresolved"),)

    accounting = _build(pairs=pairs, governance_routes=(route,))

    row = _row(accounting, _GOVERNANCE_ID)
    assert row.disposition == "governance_only"
    assert row.ica_ids == ()
    assert row.route_refs == ()
    assert accounting.summary.governance_credited == 0
    assert accounting.semantic_digest == _PRE_CREDIT_DIGEST


def test_governance_pair_without_a_governance_route_is_rejected() -> None:
    route = _governance_route()

    with pytest.raises(ValueError, match="final route"):
        _build(pairs=(_governance_pair(route),))


def test_governance_route_cannot_reuse_a_pattern_obligation() -> None:
    plan, consideration, pair = _inputs()
    pattern_route = consideration.final_routes[0]

    with pytest.raises(ValueError, match="governance"):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=(pair,),
            source_pins=_accounting_pins(plan),
            governance_routes=(pattern_route,),
        )


def test_governance_route_for_an_applicable_row_is_rejected() -> None:
    plan, consideration, pair = _inputs()
    route = ObligationRoute(
        obligation_id=next(
            row.obligation_id
            for row in plan.obligations
            if row.scope_disposition == "capability_excluded"
        ),
        disposition="targeted",
        slot_ids=(_SLOT,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("x",),
    )

    with pytest.raises(ValueError, match="governance"):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=(pair,),
            source_pins=_accounting_pins(plan),
            governance_routes=(route,),
        )


def test_row_model_accepts_governance_findings_only_when_complete() -> None:
    complete = {
        "obligation_id": _GOVERNANCE_ID,
        "disposition": "governance_only",
        "slot_ids": (_SLOT,),
        "ica_ids": ("ica-gov-1",),
        "exec_candidate_ids": (_EXEC,),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "route_refs": ("route-1",),
        "evidence": ("e",),
    }
    ObligationAccountingRow(**complete)

    for field in ("slot_ids", "ica_ids", "exec_candidate_ids", "hazard_ids"):
        with pytest.raises(ValueError, match="governance"):
            ObligationAccountingRow(**{**complete, field: ()})
    with pytest.raises(ValueError, match="governance"):
        ObligationAccountingRow(**{**complete, "stop_reason": "addressed"})


def test_capability_excluded_rows_still_reject_findings() -> None:
    with pytest.raises(ValueError, match="cannot contain STPA findings"):
        ObligationAccountingRow(
            obligation_id=_GOVERNANCE_ID,
            disposition="capability_excluded",
            ica_ids=("ica-1",),
            evidence=("e",),
        )
