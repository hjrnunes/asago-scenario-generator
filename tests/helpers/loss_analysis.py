"""Shared loss-analysis builders for tests."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def single_hazard_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorised disclosure of customer records",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Retrieval returns records outside the session scope",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Retrieval must be scoped to the active session",
                related_hazards=["H-1"],
            )
        ],
    )
