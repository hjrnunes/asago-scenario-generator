"""Contracts for the Stage 1a gap-draft option of the shared mock client."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aGapProviderDraft,
)
from tests.fixtures.sp1 import load_sp1_fixture
from tests.stpa.sp1_helpers import MockLLMClient


def _complete(client: MockLLMClient, response_format: type | None) -> object:
    return client.complete("system", "user", response_format=response_format).content


def test_gap_drafts_drop_the_risk_dispositions_when_gap_extras_are_not_preserved():
    payload = load_sp1_fixture("loss_analysis", "three_losses")
    keeping = MockLLMClient()
    dropping = MockLLMClient(preserve_gap_extras=False)
    for client in (keeping, dropping):
        client.set_response_for(LossAnalysisDraft, payload)

    assert "risk_dispositions" in _complete(keeping, _Stage1aGapProviderDraft)
    assert "risk_dispositions" not in _complete(dropping, _Stage1aGapProviderDraft)
