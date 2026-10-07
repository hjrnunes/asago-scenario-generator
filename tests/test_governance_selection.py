"""Which governance-only plan rows reach routing."""

from __future__ import annotations

from asago_scenario_generator.pipeline.governance_rows import (
    select_governance_risks,
)
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition
from tests.helpers.obligation_factory import make_plan
from tests.stpa.helpers import make_minimal_loss_analysis
from tests.test_governance_brief import _pattern


def _plan(*risk_ids: str):
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": _pattern().id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    return make_plan(risk_ids=("risk-a", *risk_ids), mappings=mappings)


def _loss_analysis(*dispositions: RiskDisposition):
    return make_minimal_loss_analysis().model_copy(
        update={"risk_dispositions": list(dispositions)}
    )


def _cited(risk_id: str, *loss_ids: str) -> RiskDisposition:
    return RiskDisposition(
        risk_ref=risk_id, disposition="cited", loss_ids=list(loss_ids or ["L-1"])
    )


def _not_applicable(risk_id: str) -> RiskDisposition:
    return RiskDisposition(
        risk_ref=risk_id,
        disposition="not_applicable",
        reason="the system has no such surface",
    )


def test_a_cited_governance_risk_is_selected_with_its_hazard_and_constraint_path():
    selection = select_governance_risks(
        _plan("risk-b"), _loss_analysis(_cited("risk-b"))
    )

    assert selection.risk_ids == ("risk-b",)
    path = selection.paths["risk-b"]
    assert path.hazard_ids == ("H-1",)
    assert path.constraint_ids == ("SC-1",)
    assert selection.skipped == {}


def test_a_risk_without_a_loss_analysis_entry_is_skipped():
    selection = select_governance_risks(_plan("risk-b"), _loss_analysis())

    assert selection.risk_ids == ()
    assert selection.skipped == {"risk-b": "no_risk_disposition"}


def test_a_not_applicable_risk_is_skipped():
    selection = select_governance_risks(
        _plan("risk-b"), _loss_analysis(_not_applicable("risk-b"))
    )

    assert selection.risk_ids == ()
    assert selection.skipped == {"risk-b": "not_applicable"}


def test_a_cited_risk_whose_losses_have_no_hazard_is_skipped():
    loss_analysis = _loss_analysis(_cited("risk-b"))
    loss_analysis = loss_analysis.model_copy(update={"hazards": []})

    selection = select_governance_risks(_plan("risk-b"), loss_analysis)

    assert selection.risk_ids == ()
    assert selection.skipped == {"risk-b": "no_hazard_path"}


def test_pattern_rows_are_never_selected():
    selection = select_governance_risks(
        _plan("risk-b"), _loss_analysis(_cited("risk-a"), _cited("risk-b"))
    )

    assert selection.risk_ids == ("risk-b",)
    assert "risk-a" not in selection.skipped
