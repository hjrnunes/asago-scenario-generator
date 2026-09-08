"""Tests for LossAnalysis boundary schema validation.

Covers LossAnalysis-01 through LossAnalysis-10 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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
    source_risk_cards: list[str] | None = None,
) -> Loss:
    if source_risk_cards is None:
        source_risk_cards = (
            [] if provenance != LossProvenance.risk_card else ["atlas-001"]
        )
    return Loss(
        loss_id=loss_id,
        description="A loss",
        provenance=provenance,
        source_risk_cards=source_risk_cards,
    )


def _make_hazard(
    hazard_id: str = "H-1",
    related_losses: list[str] | None = None,
) -> Hazard:
    return Hazard(
        hazard_id=hazard_id,
        description="A hazard",
        related_losses=related_losses or ["L-1"],
    )


def _make_constraint(
    constraint_id: str = "SC-1",
    related_hazards: list[str] | None = None,
) -> SecurityConstraint:
    return SecurityConstraint(
        constraint_id=constraint_id,
        rule="A constraint",
        related_hazards=related_hazards or ["H-1"],
    )


def _make_loss_analysis(
    risk_card_losses: list[Loss] | None = None,
    use_case_losses: list[Loss] | None = None,
    hazards: list[Hazard] | None = None,
    security_constraints: list[SecurityConstraint] | None = None,
) -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=risk_card_losses or [],
        use_case_losses=use_case_losses or [_make_loss()],
        hazards=hazards or [_make_hazard()],
        security_constraints=security_constraints or [_make_constraint()],
    )


class TestLossAnalysisValidation:
    """LossAnalysis boundary schema validation rules."""

    def test_la_01_valid_loss_analysis_passes(self):
        """LossAnalysis-01: valid loss analysis with two losses passes."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                _make_loss("L-1"),
                _make_loss("L-2"),
            ],
            hazards=[_make_hazard("H-1", related_losses=["L-1"])],
            security_constraints=[_make_constraint("SC-1", related_hazards=["H-1"])],
        )
        assert la is not None

    def test_source_risk_cards_are_canonicalized_as_set_like_provenance(self):
        loss = _make_loss(
            provenance=LossProvenance.risk_card,
            source_risk_cards=["risk-b", "risk-a", "risk-b"],
        )

        assert loss.source_risk_cards == ["risk-a", "risk-b"]

    @pytest.mark.parametrize("bad_ref", ["L-99", "NONEXIST"])
    def test_la_02_hazard_referencing_nonexistent_loss_fails(self, bad_ref):
        """LossAnalysis-02: hazard referencing non-existent loss fails."""
        with pytest.raises(ValidationError) as exc_info:
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[_make_loss("L-1")],
                hazards=[_make_hazard("H-1", related_losses=[bad_ref])],
                security_constraints=[
                    _make_constraint("SC-1", related_hazards=["H-1"])
                ],
            )
        assert "related_losses" in str(exc_info.value)

    @pytest.mark.parametrize("bad_ref", ["H-99", "NONEXIST"])
    def test_la_03_constraint_referencing_nonexistent_hazard_fails(self, bad_ref):
        """LossAnalysis-03: constraint referencing non-existent hazard fails."""
        with pytest.raises(ValidationError) as exc_info:
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[_make_loss("L-1")],
                hazards=[_make_hazard("H-1")],
                security_constraints=[
                    _make_constraint("SC-1", related_hazards=[bad_ref])
                ],
            )
        assert "related_hazards" in str(exc_info.value)

    def test_la_04_risk_card_loss_with_correct_provenance_passes(self):
        """LossAnalysis-04: risk card loss with correct provenance passes."""
        la = LossAnalysis(
            risk_card_losses=[
                _make_loss("L-1", LossProvenance.risk_card, ["atlas-001"])
            ],
            use_case_losses=[],
            hazards=[_make_hazard("H-1")],
            security_constraints=[_make_constraint("SC-1")],
        )
        assert la is not None

    def test_la_05_risk_card_loss_with_empty_source_fails(self):
        """LossAnalysis-05: risk card loss with empty source_risk_cards fails."""
        with pytest.raises(ValidationError) as exc_info:
            LossAnalysis(
                risk_card_losses=[_make_loss("L-1", LossProvenance.risk_card, [])],
                use_case_losses=[],
                hazards=[_make_hazard("H-1")],
                security_constraints=[_make_constraint("SC-1")],
            )
        assert "source_risk_cards" in str(exc_info.value)

    def test_la_06_risk_card_loss_with_wrong_provenance_fails(self):
        """LossAnalysis-06: risk card loss with wrong provenance fails."""
        with pytest.raises(ValidationError) as exc_info:
            LossAnalysis(
                risk_card_losses=[
                    _make_loss("L-1", LossProvenance.use_case, ["atlas-001"])
                ],
                use_case_losses=[],
                hazards=[_make_hazard("H-1")],
                security_constraints=[_make_constraint("SC-1")],
            )
        assert "provenance" in str(exc_info.value)

    def test_la_07_use_case_loss_with_empty_source_passes(self):
        """LossAnalysis-07: use case loss with empty source_risk_cards passes."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[_make_loss("L-1", LossProvenance.use_case, [])],
            hazards=[_make_hazard("H-1")],
            security_constraints=[_make_constraint("SC-1")],
        )
        assert la is not None

    def test_la_08_use_case_loss_with_nonempty_source_fails(self):
        """LossAnalysis-08: use case loss with non-empty source_risk_cards fails."""
        with pytest.raises(ValidationError) as exc_info:
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    _make_loss("L-1", LossProvenance.use_case, ["atlas-001"])
                ],
                hazards=[_make_hazard("H-1")],
                security_constraints=[_make_constraint("SC-1")],
            )
        assert "source_risk_cards" in str(exc_info.value)

    def test_la_09_critic_derived_loss_with_empty_source_passes(self):
        """LossAnalysis-09: critic derived loss with empty source_risk_cards passes."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[_make_loss("L-1", LossProvenance.critic_derived, [])],
            hazards=[_make_hazard("H-1")],
            security_constraints=[_make_constraint("SC-1")],
        )
        assert la is not None

    @pytest.mark.parametrize(
        "id_field,dup_value,error_fragment",
        [
            ("loss_id", "L-1", "duplicate"),
            ("hazard_id", "H-1", "duplicate"),
            ("constraint_id", "SC-1", "duplicate"),
        ],
    )
    def test_la_10_duplicate_ids_fail(self, id_field, dup_value, error_fragment):
        """LossAnalysis-10: duplicate IDs fail validation."""
        with pytest.raises(ValidationError) as exc_info:
            if id_field == "loss_id":
                LossAnalysis(
                    risk_card_losses=[],
                    use_case_losses=[
                        _make_loss(dup_value),
                        _make_loss(dup_value),
                    ],
                    hazards=[_make_hazard("H-1")],
                    security_constraints=[_make_constraint("SC-1")],
                )
            elif id_field == "hazard_id":
                LossAnalysis(
                    risk_card_losses=[],
                    use_case_losses=[_make_loss("L-1")],
                    hazards=[
                        _make_hazard(dup_value),
                        _make_hazard(dup_value),
                    ],
                    security_constraints=[_make_constraint("SC-1")],
                )
            elif id_field == "constraint_id":
                LossAnalysis(
                    risk_card_losses=[],
                    use_case_losses=[_make_loss("L-1")],
                    hazards=[_make_hazard("H-1")],
                    security_constraints=[
                        _make_constraint(dup_value),
                        _make_constraint(dup_value),
                    ],
                )
        assert error_fragment in str(exc_info.value).lower()
