"""Each semantic stop reason means one thing, applied in a fixed order.

Scope comes first (``risk_out_of_scope``), then risk alignment
(``risk_pattern_mismatch``), then mechanism: ``mechanism_absent`` when the
system lacks the capability the pattern needs, and
``mechanism_path_unsubstantiated`` when a targeted path does not establish it.
A row is counted and labelled under its one reason only.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    SEMANTIC_STOP_REASONS,
    build_consideration_artifact,
    build_neutral_briefs,
    build_obligation_accounting,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_resolution_funnel,
)
from asago_scenario_generator.report.obligation_section import (
    STOP_MEANING,
    obligation_rows,
)

from tests.helpers.governance import _accounting_pins, _plan_with_non_stpa_rows
from tests.helpers.projection_factory import get_test_raw_pattern

_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_EXEC = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"
_GOVERNANCE_ID = "ob:v1:" + "b" * 64
_EXCLUDED_ID = "ob:v1:" + "c" * 64
_PATTERN_RISK = "risk-a"


def _assessment(mechanism: str, alignment: str) -> ObligationSemanticAssessment:
    return ObligationSemanticAssessment(
        mechanism_assessment=mechanism,
        risk_alignment=alignment,
        mapping_strength="broad_category_expansion",
        mechanism_rationale="The mechanism judgement.",
        risk_alignment_rationale="The alignment judgement.",
    )


def _route(
    obligation_id: str,
    disposition: str,
    assessment: ObligationSemanticAssessment,
    diagnostics: tuple[ConsiderationDiagnostic, ...] = (),
) -> ObligationRoute:
    if disposition == "targeted":
        return ObligationRoute(
            obligation_id=obligation_id,
            disposition="targeted",
            semantic_assessment=assessment,
            slot_ids=(_SLOT,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("route evidence",),
            diagnostics=diagnostics,
        )
    return ObligationRoute(
        obligation_id=obligation_id,
        disposition=disposition,
        semantic_assessment=assessment,
        rationale="The routing rationale.",
        evidence=("route evidence",),
        diagnostics=diagnostics,
    )


def _finding(route: ObligationRoute) -> ObligationIcaConsideration:
    return ObligationIcaConsideration(
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


def _account(
    disposition: str,
    mechanism: str,
    alignment: str,
    *,
    scope: str | None = None,
    route_diagnostics: tuple[str, ...] = (),
) -> ObligationAccounting:
    """Account the fixture plan's pattern row through one assessed route.

    A targeted route carries a finding on its slot, so without a semantic stop
    it would be addressed.
    """
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    obligation_id = briefs[0].obligation_id
    diagnostics = tuple(
        ConsiderationDiagnostic(
            code=code, detail=f"route {code}", obligation_ids=(obligation_id,)
        )
        for code in route_diagnostics
    )
    route = _route(
        obligation_id, disposition, _assessment(mechanism, alignment), diagnostics
    )
    pairs = (_finding(route),) if disposition == "targeted" else ()
    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=(route,), final_routes=(route,)
    )
    return build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=pairs,
        source_pins=_accounting_pins(plan),
        risk_scopes=None if scope is None else {_PATTERN_RISK: scope},
    )


def _pattern_row(accounting: ObligationAccounting) -> ObligationAccountingRow:
    return next(
        row
        for row in accounting.rows
        if row.obligation_id not in {_GOVERNANCE_ID, _EXCLUDED_ID}
    )


def _stop(
    disposition: str,
    mechanism: str,
    alignment: str,
    *,
    scope: str | None = None,
    route_diagnostics: tuple[str, ...] = (),
) -> ObligationAccountingRow:
    accounting = _account(
        disposition,
        mechanism,
        alignment,
        scope=scope,
        route_diagnostics=route_diagnostics,
    )
    accounting.assert_integrity()
    return _pattern_row(accounting)


def _semantic_codes(row: ObligationAccountingRow) -> list[str]:
    return [item.code for item in row.diagnostics if item.code in SEMANTIC_STOP_REASONS]


# Each reason on its own.


def test_a_plausible_aligned_targeted_route_is_addressed() -> None:
    row = _stop("targeted", "plausible_in_system", "supported")

    assert row.disposition == "addressed"
    assert row.stop_reason == "addressed"
    assert _semantic_codes(row) == []


@pytest.mark.parametrize("scope", ("outside_boundary", "not_applicable"))
def test_an_out_of_scope_risk_stops_at_out_of_scope(scope: str) -> None:
    row = _stop(
        "unresolved", "insufficient_evidence", "insufficient_evidence", scope=scope
    )

    assert row.stop_reason == "risk_out_of_scope"
    assert _semantic_codes(row) == []


@pytest.mark.parametrize("disposition", ("targeted", "unresolved"))
def test_a_misaligned_pair_stops_at_mismatch(disposition: str) -> None:
    row = _stop(disposition, "plausible_in_system", "mismatch")

    assert row.disposition == "unresolved"
    assert row.stop_reason == "risk_pattern_mismatch"
    assert _semantic_codes(row) == ["risk_pattern_mismatch"]


@pytest.mark.parametrize("alignment", ("supported", "insufficient_evidence"))
def test_a_not_misaligned_pair_without_the_mechanism_stops_at_mechanism_absent(
    alignment: str,
) -> None:
    row = _stop("proposed_not_applicable", "absent_from_system", alignment)

    assert row.disposition == "unresolved"
    assert row.stop_reason == "mechanism_absent"
    assert _semantic_codes(row) == ["mechanism_absent"]


def test_a_targeted_path_without_mechanism_evidence_is_unsubstantiated() -> None:
    row = _stop("targeted", "insufficient_evidence", "supported")

    assert row.disposition == "unresolved"
    assert row.stop_reason == "mechanism_path_unsubstantiated"
    assert row.ica_ids == ()
    assert _semantic_codes(row) == ["mechanism_path_unsubstantiated"]


def test_an_untargeted_route_without_mechanism_evidence_keeps_its_route_reason() -> (
    None
):
    row = _stop("unresolved", "insufficient_evidence", "supported")

    assert row.stop_reason == "no_structural_route"
    assert _semantic_codes(row) == []


# Pairwise precedence: scope beats alignment beats mechanism.


@pytest.mark.parametrize(
    ("disposition", "mechanism", "alignment"),
    (
        ("targeted", "plausible_in_system", "mismatch"),
        ("proposed_not_applicable", "absent_from_system", "mismatch"),
        ("proposed_not_applicable", "absent_from_system", "supported"),
        ("targeted", "insufficient_evidence", "supported"),
        ("targeted", "insufficient_evidence", "mismatch"),
    ),
)
def test_scope_beats_every_semantic_reason(
    disposition: str, mechanism: str, alignment: str
) -> None:
    in_scope = _stop(disposition, mechanism, alignment, scope="actionable")
    out_of_scope = _stop(disposition, mechanism, alignment, scope="outside_boundary")

    assert in_scope.stop_reason in SEMANTIC_STOP_REASONS
    assert out_of_scope.stop_reason == "risk_out_of_scope"
    assert out_of_scope.disposition == in_scope.disposition == "unresolved"
    assert _semantic_codes(out_of_scope) == []


@pytest.mark.parametrize("disposition", ("proposed_not_applicable", "unresolved"))
def test_alignment_beats_an_absent_mechanism(disposition: str) -> None:
    row = _stop(disposition, "absent_from_system", "mismatch")

    assert row.stop_reason == "risk_pattern_mismatch"
    assert _semantic_codes(row) == ["risk_pattern_mismatch"]


def test_alignment_beats_an_unsubstantiated_path() -> None:
    row = _stop("targeted", "insufficient_evidence", "mismatch")

    assert row.stop_reason == "risk_pattern_mismatch"
    assert _semantic_codes(row) == ["risk_pattern_mismatch"]


def test_an_absent_mechanism_beats_an_unsubstantiated_path() -> None:
    """Routing rejects a targeted absent route; accounting still orders them."""
    row = _stop("targeted", "absent_from_system", "supported")

    assert row.stop_reason == "mechanism_absent"
    assert _semantic_codes(row) == ["mechanism_absent"]


def test_an_absent_mechanism_beats_incomplete_non_applicability() -> None:
    row = _stop("proposed_not_applicable", "absent_from_system", "supported")

    assert row.stop_reason == "mechanism_absent"
    assert "incomplete_non_applicability" not in {item.code for item in row.diagnostics}


def test_an_absent_mechanism_beats_a_missing_structural_route() -> None:
    row = _stop("unresolved", "absent_from_system", "supported")

    assert row.stop_reason == "mechanism_absent"


# The whole table: every alignment, mechanism and disposition, in and out of scope.

_ALIGNMENTS = ("supported", "mismatch", "insufficient_evidence")
_MECHANISMS = ("plausible_in_system", "absent_from_system", "insufficient_evidence")
_DISPOSITIONS = ("targeted", "proposed_not_applicable", "unresolved")
# The reason a route keeps when no semantic reason applies.
_ROUTE_REASON = {
    "targeted": "addressed",
    "proposed_not_applicable": "not_applicable_evidence_incomplete",
    "unresolved": "no_structural_route",
}


def _ordered_reason(disposition: str, mechanism: str, alignment: str) -> str:
    """The decided order: alignment, then an absent mechanism, then the path."""
    if alignment == "mismatch":
        return "risk_pattern_mismatch"
    if mechanism == "absent_from_system":
        return "mechanism_absent"
    if disposition == "targeted" and mechanism != "plausible_in_system":
        return "mechanism_path_unsubstantiated"
    return _ROUTE_REASON[disposition]


_TABLE = tuple(
    (disposition, mechanism, alignment)
    for disposition in _DISPOSITIONS
    for mechanism in _MECHANISMS
    for alignment in _ALIGNMENTS
)


@pytest.mark.parametrize("disposition", _DISPOSITIONS)
def test_a_misaligned_pair_without_the_mechanism_stops_at_mismatch(
    disposition: str,
) -> None:
    row = _stop(disposition, "absent_from_system", "mismatch")

    assert row.stop_reason == "risk_pattern_mismatch"
    assert _semantic_codes(row) == ["risk_pattern_mismatch"]


@pytest.mark.parametrize(("disposition", "mechanism", "alignment"), _TABLE)
def test_every_combination_stops_at_one_reason(
    disposition: str, mechanism: str, alignment: str
) -> None:
    reason = _ordered_reason(disposition, mechanism, alignment)

    row = _stop(disposition, mechanism, alignment)

    assert row.stop_reason == reason
    expected = [reason] if reason in SEMANTIC_STOP_REASONS else []
    assert _semantic_codes(row) == expected


@pytest.mark.parametrize(("disposition", "mechanism", "alignment"), _TABLE)
@pytest.mark.parametrize("scope", ("outside_boundary", "not_applicable"))
def test_an_out_of_scope_risk_overrides_every_combination(
    disposition: str, mechanism: str, alignment: str, scope: str
) -> None:
    reason = _ordered_reason(disposition, mechanism, alignment)

    row = _stop(disposition, mechanism, alignment, scope=scope)

    # A credited row keeps its own outcome; every other stops at the scope.
    assert row.stop_reason == (
        "addressed" if reason == "addressed" else "risk_out_of_scope"
    )
    assert _semantic_codes(row) == []


# One label per row.


def test_the_verifier_diagnostic_is_the_one_unsubstantiated_label() -> None:
    row = _stop(
        "targeted",
        "insufficient_evidence",
        "supported",
        route_diagnostics=("mechanism_path_unsubstantiated",),
    )

    assert row.stop_reason == "mechanism_path_unsubstantiated"
    assert _semantic_codes(row) == ["mechanism_path_unsubstantiated"]
    assert row.diagnostics[0].detail == "route mechanism_path_unsubstantiated"


def test_an_out_of_scope_row_drops_the_verifier_label() -> None:
    row = _stop(
        "targeted",
        "insufficient_evidence",
        "supported",
        scope="not_applicable",
        route_diagnostics=("mechanism_path_unsubstantiated", "slot_pair_unresolved"),
    )

    assert row.stop_reason == "risk_out_of_scope"
    assert [item.code for item in row.diagnostics] == ["slot_pair_unresolved"]


# A targeted route assessed to each semantic reason.
_SEMANTIC_CASES = {
    "risk_pattern_mismatch": ("targeted", "plausible_in_system", "mismatch"),
    "mechanism_absent": ("targeted", "absent_from_system", "supported"),
    "mechanism_path_unsubstantiated": (
        "targeted",
        "insufficient_evidence",
        "supported",
    ),
}


@pytest.mark.parametrize("reason", SEMANTIC_STOP_REASONS)
def test_a_stale_competing_semantic_diagnostic_is_dropped(reason: str) -> None:
    stale = tuple(code for code in SEMANTIC_STOP_REASONS if code != reason)
    row = _stop(
        *_SEMANTIC_CASES[reason],
        route_diagnostics=(*stale, "slot_pair_unresolved"),
    )

    assert row.stop_reason == reason
    assert [item.code for item in row.diagnostics] == [
        "slot_pair_unresolved",
        reason,
    ]
    assert row.diagnostics[1].detail != f"route {reason}"


@pytest.mark.parametrize("reason", SEMANTIC_STOP_REASONS)
def test_a_duplicated_selected_diagnostic_keeps_its_first_copy(reason: str) -> None:
    row = _stop(
        *_SEMANTIC_CASES[reason],
        route_diagnostics=(reason, "slot_pair_unresolved", reason),
    )

    assert row.stop_reason == reason
    assert [item.code for item in row.diagnostics] == [reason, "slot_pair_unresolved"]
    assert row.diagnostics[0].detail == f"route {reason}"


def test_the_funnel_counts_each_row_under_its_one_reason() -> None:
    plan = _plan_with_non_stpa_rows()
    cases = {
        ("proposed_not_applicable", "absent_from_system", "mismatch"): (
            "risk_pattern_mismatch"
        ),
        ("proposed_not_applicable", "absent_from_system", "supported"): (
            "mechanism_absent"
        ),
        ("targeted", "insufficient_evidence", "supported"): (
            "mechanism_path_unsubstantiated"
        ),
    }
    for args, reason in cases.items():
        funnel = _obligation_resolution_funnel(
            plan=plan,
            accounting=_account(*args),
            realization=SimpleNamespace(records=()),
            scenario_count=0,
        )

        assert funnel["terminal_reasons"] == {reason: 1}
        assert funnel["reconciles"] is True


def test_the_report_groups_a_missing_capability_under_its_own_label() -> None:
    accounting = _account("proposed_not_applicable", "absent_from_system", "supported")
    run = SimpleNamespace(
        plan=_plan_with_non_stpa_rows().obligations, policy=None, accounting=accounting
    )

    row = next(
        item for item in obligation_rows(run) if item.disposition == "unresolved"
    )

    assert row.stop == "mechanism_absent"
    assert "lacks the surface its mechanism needs" in row.detail
    assert (
        STOP_MEANING["mechanism_absent"][0] != STOP_MEANING["risk_pattern_mismatch"][0]
    )
