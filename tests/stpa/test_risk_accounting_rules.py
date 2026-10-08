"""The risk-accounting rules read the same way in the validator, selector and gate.

The provider validator, the disposition repair selector and the persisted-graph
gate each report their own message but share one reading of the dispositions:
which supplied cards lack a row, which are disposed twice, which rows cite
undeclared losses, and which not_applicable cards a loss cites.  These tables
pin the text and the differences each keeps.
"""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.models.loss_analysis import (
    Loss,
    LossAnalysis,
    LossAnalysisDraft,
    RiskDisposition,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _DraftReferenceValidationError,
    _validate_risk_accounting,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    LossAnalysisGateError,
    _raise_accounting_failure,
    check_hazard_graph_density,
    check_risk_accounting,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    select_disposition_repairs,
)
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import valid_risk_draft_dict

PREFIX = "risk_derivation risk accounting is incomplete: "


def _loss(loss_id: str, *sources: str) -> Loss:
    return Loss(
        loss_id=loss_id,
        description=f"Loss {loss_id}",
        provenance="risk_card" if sources else "use_case",
        source_risk_cards=list(sources),
    )


def _cited(ref: str, *loss_ids: str) -> RiskDisposition:
    return RiskDisposition(risk_ref=ref, disposition="cited", loss_ids=list(loss_ids))


def _not_applicable(ref: str, reason: str | None = "Out of scope.") -> RiskDisposition:
    # model_construct skips the wire check that rejects a blank reason.
    return RiskDisposition.model_construct(
        risk_ref=ref, disposition="not_applicable", loss_ids=[], reason=reason
    )


def _draft(
    losses: list[Loss], dispositions: list[RiskDisposition]
) -> LossAnalysisDraft:
    return LossAnalysisDraft.model_construct(
        risk_card_losses=[loss for loss in losses if loss.source_risk_cards],
        use_case_losses=[loss for loss in losses if not loss.source_risk_cards],
        risk_dispositions=dispositions,
    )


def _validator_message(draft: LossAnalysisDraft, *card_ids: str) -> str:
    with pytest.raises(_DraftReferenceValidationError) as exc_info:
        _validate_risk_accounting(
            draft, risk_cards=make_risk_cards(card_ids), context="risk_derivation"
        )
    return str(exc_info.value)


VALIDATOR_CASES: list[tuple[str, list[Loss], list[RiskDisposition], tuple, str]] = [
    (
        "unsupplied ref listed twice",
        [_loss("L-1", "atlas-001")],
        [_cited("atlas-001", "L-1"), _cited("ghost", "L-1"), _cited("ghost", "L-1")],
        ("atlas-001",),
        "'ghost' is not a supplied risk card ID; "
        "'ghost' is not a supplied risk card ID; "
        "duplicate risk_dispositions entries for: ghost",
    ),
    (
        "blank reason",
        [_loss("L-1")],
        [_not_applicable("atlas-001", " ")],
        ("atlas-001",),
        "not_applicable 'atlas-001' has an empty reason",
    ),
    (
        "missing reason",
        [_loss("L-1")],
        [_not_applicable("atlas-001", None)],
        ("atlas-001",),
        "not_applicable 'atlas-001' has an empty reason",
    ),
    (
        "undeclared losses keep row order",
        [_loss("L-1", "atlas-001")],
        [_cited("atlas-001", "L-8", "L-1", "L-7")],
        ("atlas-001",),
        "cited 'atlas-001' names undeclared losses: L-8, L-7",
    ),
    (
        "contradiction sits between entry problems and missing cards",
        [_loss("L-1", "atlas-001")],
        [
            _cited("ghost", "L-1"),
            _not_applicable("atlas-001"),
            _not_applicable("atlas-002"),
            _not_applicable("atlas-002"),
        ],
        ("atlas-001", "atlas-002", "atlas-003"),
        "'ghost' is not a supplied risk card ID; "
        "'atlas-001' is marked not_applicable but is cited by loss L-1; "
        "missing risk_dispositions entries for: atlas-003; "
        "duplicate risk_dispositions entries for: atlas-002",
    ),
    (
        "contradiction names every citing loss in sorted order",
        [_loss("L-3", "atlas-001"), _loss("L-2", "atlas-001")],
        [_not_applicable("atlas-001")],
        ("atlas-001",),
        "'atlas-001' is marked not_applicable but is cited by loss L-2, L-3",
    ),
    (
        "duplicates are listed in sorted order",
        [_loss("L-1", "atlas-002", "atlas-001")],
        [
            _cited("atlas-002", "L-1"),
            _cited("atlas-002", "L-1"),
            _cited("atlas-001", "L-1"),
            _cited("atlas-001", "L-1"),
        ],
        ("atlas-001", "atlas-002"),
        "duplicate risk_dispositions entries for: atlas-001, atlas-002",
    ),
]


@pytest.mark.parametrize(
    ("losses", "dispositions", "cards", "problems"),
    [case[1:] for case in VALIDATOR_CASES],
    ids=[case[0] for case in VALIDATOR_CASES],
)
def test_validator_reports_the_problems_in_order(
    losses: list[Loss], dispositions: list[RiskDisposition], cards: tuple, problems: str
) -> None:
    message = _validator_message(_draft(losses, dispositions), *cards)

    assert message == PREFIX + problems


def test_validator_passes_a_complete_accounting() -> None:
    draft = _draft(
        [_loss("L-1", "atlas-001")],
        [_cited("atlas-001", "L-1"), _not_applicable("atlas-002")],
    )

    _validate_risk_accounting(
        draft, risk_cards=make_risk_cards(("atlas-001", "atlas-002")), context="x"
    )


def test_selector_names_each_card_with_its_reasons_and_drops_unknown_rows() -> None:
    draft = _draft(
        [_loss("L-1", "atlas-001")],
        [
            _cited("zeta", "L-1"),
            _cited("atlas-002", "L-1"),
            _cited("atlas-002", "L-1"),
            _cited("atlas-003", "L-9", "L-8", "L-9"),
            _cited("atlas-004", "L-1"),
            _cited("atlas-004", "L-9"),
            _cited("atlas-005", "L-1"),
            _cited("ghost", "L-1"),
        ],
    )
    cards = make_risk_cards(tuple(f"atlas-00{n}" for n in range(1, 6)))

    selected, reason_pairs, unknown = select_disposition_repairs(draft, cards)

    assert selected == ("atlas-001", "atlas-002", "atlas-003", "atlas-004")
    assert reason_pairs == (
        (
            "atlas-001",
            "no risk_dispositions entry was returned for this supplied card",
        ),
        (
            "atlas-002",
            "2 duplicate risk_dispositions entries were returned; "
            "exactly one is required",
        ),
        (
            "atlas-003",
            "the cited entry names losses the response never declared: L-8, L-9",
        ),
        (
            "atlas-004",
            "2 duplicate risk_dispositions entries were returned; "
            "exactly one is required; the cited entry names losses the "
            "response never declared: L-9",
        ),
    )
    assert unknown == ("ghost", "zeta")


def test_selector_ignores_contradictions_and_blank_reasons() -> None:
    draft = _draft(
        [_loss("L-1", "atlas-001")],
        [_not_applicable("atlas-001"), _not_applicable("atlas-002", " ")],
    )

    assert select_disposition_repairs(
        draft, make_risk_cards(("atlas-001", "atlas-002"))
    ) == ((), (), ())


def _analysis(
    *, sources: list[str], dispositions: list[dict[str, Any]]
) -> LossAnalysis:
    payload = valid_risk_draft_dict()
    payload["risk_card_losses"][0]["source_risk_cards"] = sources
    payload["risk_dispositions"] = dispositions
    return LossAnalysis.model_validate(payload)


CITED_1 = {"risk_ref": "atlas-001", "disposition": "cited", "loss_ids": ["L-1"]}
NOT_APPLICABLE_1 = {
    "risk_ref": "atlas-001",
    "disposition": "not_applicable",
    "reason": "Out of scope.",
}
CONTRADICTION = "'atlas-001' is marked not_applicable but is cited by loss L-1"

# (case, sources, dispositions, cards, missing, unaccounted, contradictions)
GATE_CASES = [
    ("disposed card", ["atlas-001"], [CITED_1], ("atlas-001",), (), (), ()),
    (
        "card with no row and no citation",
        ["atlas-001"],
        [CITED_1],
        ("atlas-001", "atlas-002"),
        ("atlas-002",),
        ("atlas-002",),
        (),
    ),
    (
        "card cited only by a loss is not unaccounted",
        ["atlas-001"],
        [],
        ("atlas-001",),
        ("atlas-001",),
        (),
        (),
    ),
    (
        "not_applicable card cited by a loss",
        ["atlas-001"],
        [NOT_APPLICABLE_1],
        ("atlas-001",),
        (),
        (),
        (CONTRADICTION,),
    ),
    (
        "missing card beside a contradiction",
        ["atlas-001"],
        [NOT_APPLICABLE_1],
        ("atlas-001", "atlas-002"),
        ("atlas-002",),
        ("atlas-002",),
        (CONTRADICTION,),
    ),
]


@pytest.mark.parametrize(
    ("sources", "dispositions", "cards", "missing", "unaccounted", "contradictions"),
    [case[1:] for case in GATE_CASES],
    ids=[case[0] for case in GATE_CASES],
)
def test_gate_report_for_each_kind_of_card(
    sources, dispositions, cards, missing, unaccounted, contradictions
) -> None:
    analysis = _analysis(sources=sources, dispositions=dispositions)

    report = check_risk_accounting(analysis, make_risk_cards(cards))

    assert report.missing_dispositions == missing
    assert report.unaccounted_risk_refs == unaccounted
    assert report.contradictions == contradictions
    assert report.passed is not bool(missing or unaccounted or contradictions)


def test_gate_and_validator_both_fail_a_card_that_only_a_loss_cites() -> None:
    analysis = _analysis(sources=["atlas-001"], dispositions=[])

    report = check_risk_accounting(analysis, make_risk_cards(("atlas-001",)))
    message = _validator_message(
        _draft(list(analysis.risk_card_losses), []), "atlas-001"
    )

    assert not report.passed
    assert report.missing_dispositions == ("atlas-001",)
    assert report.unaccounted_risk_refs == ()
    assert message == PREFIX + "missing risk_dispositions entries for: atlas-001"


GATE_FAILURES = [
    (
        "unaccounted card",
        ["atlas-001"],
        [CITED_1],
        ("atlas-001", "atlas-002"),
        "stage_1a/gap_analysis: risk accounting gate failed: atlas-002",
        ("atlas-002", "atlas-002"),
    ),
    (
        "contradiction alone",
        ["atlas-001"],
        [NOT_APPLICABLE_1],
        ("atlas-001",),
        "stage_1a/gap_analysis: risk accounting gate failed: " + CONTRADICTION,
        (CONTRADICTION,),
    ),
    (
        "unaccounted card beside a contradiction",
        ["atlas-001"],
        [NOT_APPLICABLE_1],
        ("atlas-001", "atlas-002"),
        "stage_1a/gap_analysis: risk accounting gate failed: atlas-002; "
        + CONTRADICTION,
        ("atlas-002", "atlas-002", CONTRADICTION),
    ),
]


@pytest.mark.parametrize(
    ("sources", "dispositions", "cards", "message", "failing_checks"),
    [case[1:] for case in GATE_FAILURES],
    ids=[case[0] for case in GATE_FAILURES],
)
def test_gate_failure_message_and_failing_checks(
    tmp_path, sources, dispositions, cards, message, failing_checks
) -> None:
    analysis = _analysis(sources=sources, dispositions=dispositions)
    accounting = check_risk_accounting(analysis, make_risk_cards(cards))

    with pytest.raises(LossAnalysisGateError) as exc_info:
        _raise_accounting_failure(
            tmp_path, accounting, check_hazard_graph_density(analysis), None
        )

    assert str(exc_info.value) == message
    assert exc_info.value.gate == "risk_accounting"
    assert exc_info.value.failing_checks == failing_checks
