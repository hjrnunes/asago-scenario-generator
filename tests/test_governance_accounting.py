"""A governance-only obligation is credited when its routed slot has a finding."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
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
    _gather_unique,
    _governance_route_map,
    build_consideration_artifact,
    build_neutral_briefs,
    build_obligation_accounting,
)
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.governance import _accounting_pins, _plan_with_non_stpa_rows

_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_EXEC = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"
_GOVERNANCE_ID = "ob:v1:" + "b" * 64

# Digest and bytes of the accounting built below without a governance route,
# recorded from 04a926bd before the credit existed.
_PRE_CREDIT_DIGEST = "83c22f08e72669479c47041219c013349ae3ab6170c5637d87187d8226ee5537"
_PRE_CREDIT_JSON_SHA256 = (
    "22490eaf9bf36283cb866dd8d7116cfadc5161682e543f29d2e33c2533a84b71"
)
_PRE_CREDIT_JSON_LEN = 2059


def _inputs() -> tuple[Any, Any, ObligationIcaConsideration]:
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
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


def _governance_route(
    *, disposition: str = "targeted", slots: tuple[str, ...] = (_SLOT,)
) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=_GOVERNANCE_ID,
        disposition=disposition,
        slot_ids=slots if disposition == "targeted" else (),
        hazard_ids=("H-1",) if disposition == "targeted" else (),
        constraint_ids=("SC-1",) if disposition == "targeted" else (),
        rationale="The control action could bring about the reviewed risk.",
        evidence=("governance: reviewed risk",),
    )


def _governance_pair(
    route: ObligationRoute, *, disposition: str = "finding", slot: str = _SLOT
) -> ObligationIcaConsideration:
    if disposition == "finding":
        return ObligationIcaConsideration(
            route_id=route.route_id,
            obligation_id=_GOVERNANCE_ID,
            slot_id=slot,
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
        slot_id=slot,
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


@pytest.mark.parametrize("case", ("unresolved_pair", "no_pair"))
def test_governance_route_without_a_finding_records_its_route(case: str) -> None:
    route = _governance_route()
    pairs: tuple[Any, ...] = (
        ()
        if case == "no_pair"
        else (_governance_pair(route, disposition="unresolved"),)
    )

    accounting = _build(pairs=pairs, governance_routes=(route,))

    row = _row(accounting, _GOVERNANCE_ID)
    assert row.disposition == "governance_only"
    assert row.stop_reason == "governance_routed_no_finding"
    assert row.slot_ids == (_SLOT,)
    assert row.route_refs == (route.route_id,)
    assert row.ica_ids == row.exec_candidate_ids == ()
    assert row.hazard_ids == row.constraint_ids == ()
    assert "governance: reviewed risk" in row.evidence
    assert accounting.summary.governance_credited == 0
    assert accounting.summary.governance_routed_no_finding == 1
    accounting.assert_integrity()
    reloaded = ObligationAccounting.model_validate(accounting.model_dump(mode="json"))
    assert reloaded.semantic_digest == accounting.semantic_digest


def test_a_governance_route_for_an_unknown_row_is_rejected() -> None:
    stray = _governance_route().model_copy(
        update={"obligation_id": "ob:v1:" + "e" * 64}
    )

    with pytest.raises(ValueError, match="is not a governance-only row"):
        _build(governance_routes=(stray,))


def test_a_governance_route_for_a_pattern_row_is_rejected() -> None:
    _, consideration, _ = _inputs()
    pattern_route = _governance_route().model_copy(
        update={"obligation_id": consideration.final_routes[0].obligation_id}
    )

    with pytest.raises(ValueError, match="is not a governance-only row"):
        _build(governance_routes=(pattern_route,))


def test_a_governance_row_cannot_share_a_final_route_with_a_pattern_row() -> None:
    _, consideration, _ = _inputs()
    colliding = _governance_route().model_copy(
        update={"obligation_id": consideration.final_routes[0].obligation_id}
    )
    plan = SimpleNamespace(
        obligations=(
            SimpleNamespace(
                obligation_id=colliding.obligation_id,
                scope_disposition="governance_only",
            ),
        )
    )

    with pytest.raises(ValueError, match="duplicates another final route"):
        _governance_route_map(plan, consideration, (colliding,))


def test_two_governance_routes_for_one_row_are_rejected() -> None:
    route = _governance_route()
    again = route.model_copy(update={"rationale": "A second route for the same row."})

    with pytest.raises(ValueError, match="duplicates another final route"):
        _build(governance_routes=(route, again))


def test_a_routed_row_is_distinguishable_from_an_unrouted_row() -> None:
    route = _governance_route()
    unrouted = _row(_build(), _GOVERNANCE_ID)
    routed = _row(_build(governance_routes=(route,)), _GOVERNANCE_ID)

    assert unrouted.stop_reason is None
    assert unrouted.route_refs == ()
    assert routed.stop_reason == "governance_routed_no_finding"
    assert routed.route_refs == (route.route_id,)


def test_a_declined_governance_route_stays_bare() -> None:
    route = _governance_route(disposition="unresolved")

    accounting = _build(governance_routes=(route,))

    row = _row(accounting, _GOVERNANCE_ID)
    assert row.stop_reason is None
    assert row.route_refs == ()
    assert accounting.summary.governance_routed_no_finding == 0
    assert accounting.semantic_digest == _PRE_CREDIT_DIGEST


def test_a_route_with_only_some_slots_found_keeps_its_finding_as_trace_only() -> None:
    other = "RESP-1:CA-1-1:INCORRECT"
    route = _governance_route(slots=(_SLOT, other))
    found = _governance_pair(route)
    unresolved = _governance_pair(route, disposition="unresolved", slot=other)

    accounting = _build(pairs=(found, unresolved), governance_routes=(route,))

    row = _row(accounting, _GOVERNANCE_ID)
    assert row.stop_reason is None
    assert row.route_refs == ()
    assert row.ica_ids == ()
    assert accounting.semantic_digest == _PRE_CREDIT_DIGEST


def test_the_summary_leaves_out_a_zero_routed_count() -> None:
    plain = _build().summary.model_dump(mode="json")
    routed = _build(governance_routes=(_governance_route(),)).summary.model_dump(
        mode="json"
    )

    assert "governance_routed_no_finding" not in plain
    assert routed["governance_routed_no_finding"] == 1


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


def test_row_model_accepts_a_routed_row_only_with_its_route_and_no_findings() -> None:
    routed = {
        "obligation_id": _GOVERNANCE_ID,
        "disposition": "governance_only",
        "stop_reason": "governance_routed_no_finding",
        "slot_ids": (_SLOT,),
        "route_refs": ("route-1",),
        "evidence": ("e",),
    }
    ObligationAccountingRow(**routed)

    for field in ("slot_ids", "route_refs"):
        with pytest.raises(ValueError, match="routed governance"):
            ObligationAccountingRow(**{**routed, field: ()})
    for field in ("ica_ids", "hazard_ids", "constraint_ids"):
        with pytest.raises(ValueError, match="routed governance"):
            ObligationAccountingRow(**{**routed, field: ("x",)})
    with pytest.raises(ValueError, match="routed governance"):
        ObligationAccountingRow(**{**routed, "exec_candidate_ids": (_EXEC,)})


def test_the_routed_stop_reason_belongs_to_governance_rows_only() -> None:
    with pytest.raises(ValueError, match="governance-only"):
        ObligationAccountingRow(
            obligation_id=_GOVERNANCE_ID,
            disposition="unresolved",
            stop_reason="governance_routed_no_finding",
            evidence=("e",),
        )


def test_capability_excluded_rows_still_reject_findings() -> None:
    with pytest.raises(ValueError, match="cannot contain STPA findings"):
        ObligationAccountingRow(
            obligation_id=_GOVERNANCE_ID,
            disposition="capability_excluded",
            ica_ids=("ica-1",),
            evidence=("e",),
        )


# Trimmed from the governance obligation of the airbnb-r1 L4 fill recording:
# its ICA findings, one per routed slot, repeat H-8 and SC-4 across slots.
_REPEATED_FINDINGS_FIXTURE = {
    "source": "airbnb-r1 L4 fill recording, governance obligation, trimmed",
    "findings": (
        {
            "slot_id": "RESP-1:CA-1-1:NOT_PROVIDED",
            "ica_ids": ("ica-gov-1",),
            "hazard_ids": ("H-8", "H-2"),
            "constraint_ids": ("SC-4",),
        },
        {
            "slot_id": "RESP-1:CA-1-1:INCORRECT",
            "ica_ids": ("ica-gov-2",),
            "hazard_ids": ("H-8",),
            "constraint_ids": ("SC-4", "SC-7"),
        },
        {
            "slot_id": "RESP-1:CA-1-1:WRONG_TIMING",
            "ica_ids": ("ica-gov-3",),
            "hazard_ids": ("H-6", "H-8"),
            "constraint_ids": ("SC-4",),
        },
    ),
}


_TWO_SLOTS = ("RESP-1:CA-1-1:NOT_PROVIDED", "RESP-1:CA-1-1:INCORRECT")


def _finding(
    route: ObligationRoute,
    *,
    slot: str,
    ica_ids: tuple[str, ...] = ("ica-1",),
    exec_ids: tuple[str, ...] | None = None,
    hazard_ids: tuple[str, ...] = ("H-1",),
    constraint_ids: tuple[str, ...] = ("SC-1",),
) -> ObligationIcaConsideration:
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot,
        disposition="finding",
        ica_ids=ica_ids,
        exec_candidate_ids=exec_ids if exec_ids is not None else (f"EXEC:{slot}",),
        hazard_ids=hazard_ids,
        constraint_ids=constraint_ids,
        evidence=("ica evidence",),
    )


def _route_for(obligation_id: str, slots: tuple[str, ...]) -> ObligationRoute:
    return _governance_route(slots=slots).model_copy(
        update={"obligation_id": obligation_id}
    )


def _account(
    *, governance: bool, slots: tuple[str, ...], make_pairs: Any
) -> tuple[Any, ObligationAccounting]:
    """Account findings for a governance row or for the pattern row."""
    plan, consideration, _ = _inputs()
    pattern_id = consideration.final_routes[0].obligation_id
    obligation_id = _GOVERNANCE_ID if governance else pattern_id
    kwargs: dict[str, Any] = {}
    if governance:
        route = ObligationRoute.model_validate(
            _route_for(obligation_id, slots).model_dump(mode="json")
        )
        kwargs["governance_routes"] = (route,)
    else:
        route = ObligationRoute(
            obligation_id=pattern_id,
            disposition="targeted",
            slot_ids=slots,
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("route evidence",),
        )
        consideration = build_consideration_artifact(
            plan=plan,
            briefs=consideration.briefs,
            initial_routes=(route,),
            final_routes=(route,),
        )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=make_pairs(route),
        source_pins=_accounting_pins(plan),
        **kwargs,
    )
    return _row(accounting, obligation_id), accounting


def _shared_pairs(route: ObligationRoute) -> tuple[ObligationIcaConsideration, ...]:
    return tuple(
        _finding(
            route,
            slot=slot,
            ica_ids=("ica-shared",),
            exec_ids=("EXEC:shared",),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
        )
        for slot in _TWO_SLOTS
    )


@pytest.mark.parametrize("governance", (False, True), ids=("addressed", "governance"))
def test_findings_that_cite_the_same_ids_give_each_id_once(governance: bool) -> None:
    row, accounting = _account(
        governance=governance, slots=_TWO_SLOTS, make_pairs=_shared_pairs
    )

    assert row.ica_ids == ("ica-shared",)
    assert row.exec_candidate_ids == ("EXEC:shared",)
    assert row.hazard_ids == ("H-1",)
    assert row.constraint_ids == ("SC-1",)
    assert row.slot_ids == tuple(sorted(_TWO_SLOTS))
    accounting.assert_integrity()


@pytest.mark.parametrize("governance", (False, True), ids=("addressed", "governance"))
def test_the_recorded_findings_account_without_a_repeat(governance: bool) -> None:
    findings = _REPEATED_FINDINGS_FIXTURE["findings"]

    def pairs(route: ObligationRoute) -> tuple[ObligationIcaConsideration, ...]:
        return tuple(
            _finding(
                route,
                slot=item["slot_id"],
                ica_ids=item["ica_ids"],
                hazard_ids=item["hazard_ids"],
                constraint_ids=item["constraint_ids"],
            )
            for item in findings
        )

    row, _ = _account(
        governance=governance,
        slots=tuple(item["slot_id"] for item in findings),
        make_pairs=pairs,
    )

    assert row.hazard_ids == ("H-2", "H-6", "H-8")
    assert row.constraint_ids == ("SC-4", "SC-7")
    assert len(row.ica_ids) == 3
    assert len(row.exec_candidate_ids) == 3


def test_a_gathered_id_list_keeps_the_order_of_first_sight() -> None:
    findings = [
        SimpleNamespace(hazard_ids=("H-9", "H-2")),
        SimpleNamespace(hazard_ids=("H-2", "H-5", "H-9")),
        SimpleNamespace(hazard_ids=("H-1", "H-5")),
    ]

    assert _gather_unique(findings, "hazard_ids") == ("H-9", "H-2", "H-5", "H-1")


def test_a_repeat_inside_one_finding_still_fails() -> None:
    route = _governance_route()

    with pytest.raises(ValueError, match="unique"):
        _finding(route, slot=_SLOT, hazard_ids=("H-8", "H-8"))
    with pytest.raises(ValueError, match="unique"):
        ObligationAccountingRow(
            obligation_id=_GOVERNANCE_ID,
            disposition="governance_only",
            hazard_ids=("H-8", "H-8"),
            evidence=("e",),
        )
