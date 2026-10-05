"""Regression tests for the Stage 2 to Stage 3 trace boundary.

These tests reproduce the live-run defect without contacting a model:
Call 2a silently discarded extra responsibility collections and omitted the
security-constraint references needed to trace hazards.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
    ControlElementSet,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from tests.stpa.sp1_helpers import MockLLMClient, valid_empty_coordination_analysis_dict


def _loss_analysis() -> LossAnalysis:
    """Return one loss, hazard, and security constraint for Stage 2 tests."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-1"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Hazard",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _requirement_response() -> dict:
    """Return the minimum valid Call 1 response."""
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Apply the control",
                "classification": "control",
                "source_constraint": "SC-1",
            }
        ]
    }


def _responsibility_response(*, include_refs: bool = True) -> dict:
    """Return a Call 2a response with an optionally omitted trace field."""
    responsibility = {
        "resp_id": "RESP-1",
        "description": "Controller",
        "responsibility_constraints": [
            {"rc_id": "RC-1-1", "description": "Apply the control"}
        ],
        "process_model_parts": [{"pm_id": "PM-1-1", "description": "Control state"}],
    }
    if include_refs:
        responsibility["security_constraint_refs"] = ["SC-1"]
    return {"responsibilities": [responsibility]}


def _control_element_response() -> dict:
    """Return the minimum valid Call 2b response."""
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Apply control",
                "target": {"type": "responsibility", "id": "RESP-1"},
            }
        ],
        "feedback_channels": [
            {
                "fb_id": "FB-1-1",
                "description": "Control result",
                "updates": "PM-1-1",
                "source": {"type": "responsibility", "id": "RESP-1"},
            }
        ],
        "controlled_processes": [],
    }


def _coordination_response() -> dict:
    """Return the minimum valid Call 3 response."""
    return valid_empty_coordination_analysis_dict()


def _stage2_client(responsibility_response: dict) -> MockLLMClient:
    """Configure a mock for the four Stage 2 calls."""
    client = MockLLMClient()
    client.set_response_for(RequirementSet, _requirement_response())
    client.set_response_for(ResponsibilitySet, responsibility_response)
    client.set_response_for(ControlElementSet, _control_element_response())
    client.set_response_for(CoordinationAnalysis, _coordination_response())
    return client


def test_stage2_rejects_unexpected_responsibility_collection(tmp_path) -> None:
    """Call 2a must not silently discard a second responsibility collection."""
    response = _responsibility_response()
    response["responsibilities_additional"] = [
        {
            "resp_id": "RESP-2",
            "description": "Unexpected second collection",
            "security_constraint_refs": ["SC-1"],
            "responsibility_constraints": [],
            "process_model_parts": [{"pm_id": "PM-2-1", "description": "State"}],
        }
    ]

    with pytest.raises(StageError, match="responsibilit"):
        derive_control_structure(
            llm_client=_stage2_client(response),
            use_case_text="Test",
            loss_analysis=_loss_analysis(),
            run_dir=tmp_path,
        )


def test_stage2_requires_and_preserves_security_constraint_refs(tmp_path) -> None:
    """Each Call 2a responsibility must carry its explicit SC references."""
    client = _stage2_client(_responsibility_response(include_refs=False))

    with pytest.raises(StageError, match="security_constraint_refs"):
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_loss_analysis(),
            run_dir=tmp_path,
        )


def test_stage2_preserves_security_constraint_refs(tmp_path) -> None:
    """The explicit Call 2a trace survives control-structure assembly."""
    result = derive_control_structure(
        llm_client=_stage2_client(_responsibility_response()),
        use_case_text="Test",
        loss_analysis=_loss_analysis(),
        run_dir=tmp_path,
    )
    control_structure = result.control_structure

    assert control_structure.responsibilities[0].security_constraint_refs == ["SC-1"]
