"""Unit tests for SP1 minItems constraints on critical arrays.

Covers MinItems-01 through MinItems-04 from the Gherkin feature file:
  features/sp1_minitems_constraints.feature
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def _make_loss(
    loss_id: str = "L-1",
    provenance: LossProvenance = LossProvenance.use_case,
) -> Loss:
    return Loss(
        loss_id=loss_id,
        description="A loss",
        provenance=provenance,
        source_risk_cards=[],
    )


def _make_hazard(hazard_id: str = "H-1") -> Hazard:
    return Hazard(
        hazard_id=hazard_id,
        description="A hazard",
        related_losses=["L-1"],
    )


def _make_constraint(constraint_id: str = "SC-1") -> SecurityConstraint:
    return SecurityConstraint(
        constraint_id=constraint_id,
        rule="A constraint",
        related_hazards=["H-1"],
    )


def _make_responsibility(resp_id: str = "RESP-1") -> Responsibility:
    return Responsibility(
        resp_id=resp_id,
        description="Controller",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="State"),
        ],
        control_actions=[
            ControlAction(ca_id="CA-1-1", description="Action"),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            ),
        ],
    )


class TestMinItemsEmptyCriticalArrayFails:
    """MinItems-01: empty critical array fails validation."""

    def test_minitems_01_empty_hazards_fails(self):
        """Empty hazards fails validation."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[_make_loss()],
                hazards=[],
                security_constraints=[_make_constraint()],
            )

    def test_minitems_01_empty_hazards_fails_without_constraint_refs(self):
        """Empty hazards fails on min_length alone (no constraint referencing missing hazard)."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[_make_loss()],
                hazards=[],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1",
                        rule="No refs",
                        related_hazards=[],
                    )
                ],
            )

    def test_minitems_01_empty_security_constraints_fails(self):
        """Empty security_constraints fails validation."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[_make_loss()],
                hazards=[_make_hazard()],
                security_constraints=[],
            )

    def test_minitems_01_empty_responsibilities_fails(self):
        """Empty responsibilities fails validation."""
        with pytest.raises(ValidationError):
            ControlStructure(
                responsibilities=[],
            )


class TestMinItemsEmptyOptionalArrayPasses:
    """MinItems-02: empty optional array passes validation."""

    def test_minitems_02_empty_risk_card_losses_passes(self):
        """Empty risk_card_losses passes validation."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[_make_loss()],
            hazards=[_make_hazard()],
            security_constraints=[_make_constraint()],
        )
        assert la is not None

    def test_minitems_02_empty_use_case_losses_passes(self):
        """Empty use_case_losses passes validation."""
        la = LossAnalysis(
            risk_card_losses=[
                Loss(
                    loss_id="L-1",
                    description="Risk loss",
                    provenance=LossProvenance.risk_card,
                    source_risk_cards=["atlas-001"],
                ),
            ],
            use_case_losses=[],
            hazards=[_make_hazard()],
            security_constraints=[_make_constraint()],
        )
        assert la is not None


class TestMinItemsNonEmptyCriticalPasses:
    """MinItems-03 and MinItems-04: non-empty critical arrays pass validation."""

    def test_minitems_03_non_empty_hazards_and_constraints_pass(self):
        """LossAnalysis with non-empty hazards and security_constraints passes."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[_make_loss()],
            hazards=[_make_hazard()],
            security_constraints=[_make_constraint()],
        )
        assert la is not None

    def test_minitems_04_non_empty_responsibilities_pass(self):
        """ControlStructure with non-empty responsibilities passes validation."""
        cs = ControlStructure(
            responsibilities=[_make_responsibility()],
        )
        assert cs is not None
