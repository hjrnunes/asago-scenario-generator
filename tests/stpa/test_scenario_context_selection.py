"""Hazard and loss selection for one scenario generation context."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.scenario_prod.context import (
    _selected_hazards_and_losses,
)

from tests.helpers.obligation_aware import _loss_analysis


def _threat(*hazard_ids: str) -> SimpleNamespace:
    return SimpleNamespace(related_hazards=list(hazard_ids))


def _hazard(hazard_id: str, *loss_ids: str) -> SimpleNamespace:
    return SimpleNamespace(
        hazard_id=hazard_id,
        description=f"{hazard_id} description",
        related_losses=list(loss_ids),
    )


def _loss(loss_id: str) -> SimpleNamespace:
    return SimpleNamespace(loss_id=loss_id, description=f"{loss_id} description")


def _analysis(hazards, risk_card=(), use_case=()) -> SimpleNamespace:
    return SimpleNamespace(
        hazards=tuple(hazards),
        risk_card_losses=tuple(risk_card),
        use_case_losses=tuple(use_case),
    )


class TestSelectedHazardsAndLosses:
    def test_projects_the_hazard_and_its_loss_from_a_real_analysis(self) -> None:
        hazards, losses = _selected_hazards_and_losses(_threat("H-1"), _loss_analysis())

        assert [(item.hazard_id, item.related_loss_ids) for item in hazards] == [
            ("H-1", ("L-1",))
        ]
        assert [item.loss_id for item in losses] == ["L-1"]

    def test_deduplicates_hazards_and_losses_in_first_seen_order(self) -> None:
        analysis = _analysis(
            [_hazard("H-2", "L-2", "L-1"), _hazard("H-1", "L-1")],
            risk_card=[_loss("L-1")],
            use_case=[_loss("L-2")],
        )

        hazards, losses = _selected_hazards_and_losses(
            _threat("H-2", "H-1", "H-2"), analysis
        )

        assert [item.hazard_id for item in hazards] == ["H-2", "H-1"]
        assert [item.loss_id for item in losses] == ["L-2", "L-1"]

    def test_threat_without_hazards_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="no exact related hazard"):
            _selected_hazards_and_losses(_threat(), _loss_analysis())

    def test_unknown_hazard_is_named_in_the_error(self) -> None:
        with pytest.raises(ValueError, match="unknown hazard 'H-9'"):
            _selected_hazards_and_losses(_threat("H-1", "H-9"), _loss_analysis())

    def test_hazard_without_losses_is_rejected(self) -> None:
        analysis = _analysis([_hazard("H-1")], risk_card=[_loss("L-1")])

        with pytest.raises(ValueError, match="does not reach an exact loss"):
            _selected_hazards_and_losses(_threat("H-1"), analysis)

    def test_hazard_citing_an_unknown_loss_is_rejected(self) -> None:
        analysis = _analysis([_hazard("H-1", "L-1", "L-9")], risk_card=[_loss("L-1")])

        with pytest.raises(ValueError, match="does not reach an exact loss"):
            _selected_hazards_and_losses(_threat("H-1"), analysis)
