"""The pure Stage 1a check layer reads a graph and reports findings.

The gate escalates an accounting failure before a density failure, and it
never asks a model about either.  These cases pin the check module's one
entry point: a persisted graph in, both reports out, no client, no template
loader and no run directory in the interface.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model import (
    loss_analysis_gate_checks,
    loss_analysis_gates,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    RiskAccountingReport,
)
from tests.helpers.stpa_builders import make_risk_cards

ATLAS = ("atlas-001", "atlas-002", "atlas-003")
# The contract's check: the module may not borrow a private name from
# ``loss_analysis``, because those names change with the provider models.
PRIVATE_LOSS_ANALYSIS_IMPORT = re.compile(r"from [^\n]*loss_analysis import [^\n]*\b_")


def _loss(loss_id: str, card_id: str) -> dict:
    return {
        "loss_id": loss_id,
        "description": f"Loss {loss_id}.",
        "provenance": "risk_card",
        "source_risk_cards": [card_id],
    }


def _constraint(
    rule: str = "Do not disclose the customer account balance.",
    hazards: list[str] | None = None,
) -> dict:
    return {
        "constraint_id": "SC-1",
        "rule": rule,
        "applies_when": [],
        "related_hazards": ["H-1"] if hazards is None else hazards,
        "behavior_class": "disclosure",
    }


def _passing_graph(
    *,
    hazard_description: str = "Customer account balance is disclosed.",
    rule: str = "Do not disclose the customer account balance.",
) -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [_loss("L-1", "atlas-001")],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": hazard_description,
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [_constraint(rule)],
            "risk_dispositions": [
                {
                    "risk_ref": "atlas-001",
                    "disposition": "cited",
                    "loss_ids": ["L-1"],
                }
            ],
        }
    )


def _failing_graph() -> LossAnalysis:
    """Two losses, two hazards and one constraint: L-2 and H-2 have no partner."""
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [
                _loss("L-1", "atlas-001"),
                _loss("L-2", "atlas-002"),
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Customer account balance is disclosed.",
                    "related_losses": ["L-1"],
                },
                {
                    "hazard_id": "H-2",
                    "description": "Shipping label shows the wrong address.",
                    "related_losses": [],
                },
            ],
            "security_constraints": [_constraint()],
            "risk_dispositions": [],
        }
    )


def test_passing_graph_reports_no_findings() -> None:
    findings = loss_analysis_gate_checks.check_loss_analysis_graph(
        _passing_graph(), make_risk_cards(("atlas-001",))
    )

    assert findings.passed
    assert findings.failing_checks == ()
    assert findings.advisory_checks == ()
    assert findings.accounting == RiskAccountingReport(
        missing_dispositions=(),
        unaccounted_risk_refs=(),
        not_applicable_refs=(),
        cited_refs=("atlas-001",),
    )


def test_graph_without_supplied_cards_still_checks_its_own_rows() -> None:
    findings = loss_analysis_gate_checks.check_loss_analysis_graph(_passing_graph())

    assert findings.passed
    assert findings.accounting.missing_dispositions == ()
    assert findings.accounting.cited_refs == ("atlas-001",)


def test_failing_graph_reports_accounting_before_density() -> None:
    findings = loss_analysis_gate_checks.check_loss_analysis_graph(
        _failing_graph(), make_risk_cards(ATLAS)
    )

    assert not findings.passed
    assert findings.failing_checks == (
        "atlas-001",
        "atlas-002",
        "atlas-003",
        "atlas-003",
        "loss L-2 has no hazard",
        "hazard H-2 has no constraint",
    )
    assert findings.advisory_checks == ()


def test_subject_phrase_mismatch_is_advisory_only() -> None:
    findings = loss_analysis_gate_checks.check_loss_analysis_graph(
        _passing_graph(
            hazard_description="Shipping label shows the wrong address.",
        ),
        make_risk_cards(("atlas-001",)),
    )

    assert findings.passed
    assert findings.failing_checks == ()
    assert findings.advisory_checks == (
        "constraint SC-1 and hazard H-1 share no subject phrase",
    )


def test_entry_point_takes_a_graph_and_no_model_client() -> None:
    parameters = inspect.signature(
        loss_analysis_gate_checks.check_loss_analysis_graph
    ).parameters

    assert list(parameters) == ["analysis", "risk_cards"]
    assert parameters["analysis"].default is inspect.Parameter.empty
    assert parameters["risk_cards"].default == ()


def test_check_module_imports_no_private_loss_analysis_name() -> None:
    source = Path(loss_analysis_gate_checks.__file__).read_text()

    assert PRIVATE_LOSS_ANALYSIS_IMPORT.findall(source) == []
    assert "infra.llm" not in source


def test_gate_module_still_exports_the_check_layer() -> None:
    for name in (
        "UNCLASSIFIED",
        "ConstraintSubjectCheck",
        "BehaviorClassOwnHazardCheck",
        "HazardGraphDensityReport",
        "RiskAccountingReport",
        "check_hazard_graph_density",
        "check_risk_accounting",
        "extract_subject_phrases",
    ):
        assert getattr(loss_analysis_gates, name) is getattr(
            loss_analysis_gate_checks, name
        ), name
