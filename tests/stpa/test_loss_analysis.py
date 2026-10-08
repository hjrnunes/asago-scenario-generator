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


def _analysis(**overrides) -> LossAnalysis:
    """A valid analysis (one use-case loss, hazard and constraint) with fields replaced."""
    fields = {
        "risk_card_losses": [],
        "use_case_losses": [_make_loss("L-1")],
        "hazards": [_make_hazard("H-1")],
        "security_constraints": [_make_constraint("SC-1")],
    }
    return LossAnalysis(**{**fields, **overrides})


def _loss_with(provenance: LossProvenance, sources: list[str]) -> Loss:
    return _make_loss("L-1", provenance, sources)


class TestLossAnalysisValidation:
    """LossAnalysis boundary schema validation rules."""

    def test_la_01_valid_loss_analysis_passes(self):
        """LossAnalysis-01: valid loss analysis with two losses passes."""
        la = _analysis(use_case_losses=[_make_loss("L-1"), _make_loss("L-2")])
        assert [loss.loss_id for loss in la.use_case_losses] == ["L-1", "L-2"]

    def test_source_risk_cards_are_canonicalized_as_set_like_provenance(self):
        loss = _make_loss(
            provenance=LossProvenance.risk_card,
            source_risk_cards=["risk-b", "risk-a", "risk-b"],
        )

        assert loss.source_risk_cards == ["risk-a", "risk-b"]

    @pytest.mark.parametrize(
        ("overrides", "error_fragment"),
        [
            (
                {"hazards": [_make_hazard("H-1", related_losses=["L-99"])]},
                "related_losses",
            ),
            (
                {"hazards": [_make_hazard("H-1", related_losses=["NONEXIST"])]},
                "related_losses",
            ),
            (
                {
                    "security_constraints": [
                        _make_constraint("SC-1", related_hazards=["H-99"])
                    ]
                },
                "related_hazards",
            ),
            (
                {
                    "security_constraints": [
                        _make_constraint("SC-1", related_hazards=["NONEXIST"])
                    ]
                },
                "related_hazards",
            ),
        ],
        ids=[
            "la_02_hazard_unknown_loss",
            "la_02_hazard_unknown_loss_word",
            "la_03_constraint_unknown_hazard",
            "la_03_constraint_unknown_hazard_word",
        ],
    )
    def test_la_02_03_dangling_references_fail(self, overrides, error_fragment):
        """LossAnalysis-02/03: a reference to a missing loss or hazard fails."""
        with pytest.raises(ValidationError) as exc_info:
            _analysis(**overrides)
        assert error_fragment in str(exc_info.value)

    @pytest.mark.parametrize(
        ("collection", "provenance", "sources", "error_fragment"),
        [
            ("risk_card_losses", LossProvenance.risk_card, ["atlas-001"], None),
            ("risk_card_losses", LossProvenance.risk_card, [], "source_risk_cards"),
            ("risk_card_losses", LossProvenance.use_case, ["atlas-001"], "provenance"),
            ("use_case_losses", LossProvenance.use_case, [], None),
            (
                "use_case_losses",
                LossProvenance.use_case,
                ["atlas-001"],
                "source_risk_cards",
            ),
            ("use_case_losses", LossProvenance.critic_derived, [], None),
        ],
        ids=[
            "la_04_risk_card_correct_provenance",
            "la_05_risk_card_empty_source",
            "la_06_risk_card_wrong_provenance",
            "la_07_use_case_empty_source",
            "la_08_use_case_nonempty_source",
            "la_09_critic_derived_empty_source",
        ],
    )
    def test_la_04_09_loss_provenance_rules(
        self, collection, provenance, sources, error_fragment
    ):
        """LossAnalysis-04..09: provenance and source_risk_cards must agree."""
        other = (
            "use_case_losses"
            if collection == "risk_card_losses"
            else "risk_card_losses"
        )
        overrides = {collection: [_loss_with(provenance, sources)], other: []}
        if error_fragment is None:
            la = _analysis(**overrides)
            [loss] = getattr(la, collection)
            assert loss.provenance == provenance
        else:
            with pytest.raises(ValidationError) as exc_info:
                _analysis(**overrides)
            assert error_fragment in str(exc_info.value)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"use_case_losses": [_make_loss("L-1"), _make_loss("L-1")]},
            {"hazards": [_make_hazard("H-1"), _make_hazard("H-1")]},
            {
                "security_constraints": [
                    _make_constraint("SC-1"),
                    _make_constraint("SC-1"),
                ]
            },
        ],
        ids=["loss_id", "hazard_id", "constraint_id"],
    )
    def test_la_10_duplicate_ids_fail(self, overrides):
        """LossAnalysis-10: duplicate IDs fail validation."""
        with pytest.raises(ValidationError) as exc_info:
            _analysis(**overrides)
        assert "duplicate" in str(exc_info.value).lower()
