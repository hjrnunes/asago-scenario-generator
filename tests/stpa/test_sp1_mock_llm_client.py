"""Contracts for the options the acceptance runtime adds to the shared mock client."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.critic import CriticFindings
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aGapProviderDraft,
)
from tests.fixtures.sp1 import load_sp1_fixture
from tests.stpa.sp1_helpers import MockLLMClient


def _complete(client: MockLLMClient, response_format: type | None) -> object:
    return client.complete("system", "user", response_format=response_format).content


def test_delayed_invalid_response_starts_after_the_configured_call_count():
    client = MockLLMClient()
    client.set_response_for(CriticFindings, {"gaps": []})
    client.set_invalid_response_after_n_calls(CriticFindings, 2)

    contents = [_complete(client, CriticFindings) for _ in range(3)]

    assert contents == [{"gaps": []}, {"gaps": []}, "THIS_IS_NOT_VALID_JSON{{{"]


def test_delayed_invalid_response_counts_only_its_own_type():
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, {"hazards": []})
    client.set_invalid_response_after_n_calls(CriticFindings, 0)

    assert _complete(client, LossAnalysisDraft) == {"hazards": []}
    assert _complete(client, CriticFindings) == "THIS_IS_NOT_VALID_JSON{{{"


def test_content_adapter_reshapes_the_response_with_the_wire_type_and_prompt():
    seen: list[tuple[object, object, str]] = []

    def adapt(content, wire_format, user_prompt):
        seen.append((content, wire_format, user_prompt))
        return {"adapted": content}

    client = MockLLMClient(adapt_content=adapt)
    client.set_response_for(CriticFindings, {"gaps": []})

    assert _complete(client, CriticFindings) == {"adapted": {"gaps": []}}
    assert seen == [({"gaps": []}, CriticFindings, "user")]


def test_gap_drafts_drop_the_risk_dispositions_when_gap_extras_are_not_preserved():
    payload = load_sp1_fixture("loss_analysis", "three_losses")
    keeping = MockLLMClient()
    dropping = MockLLMClient(preserve_gap_extras=False)
    for client in (keeping, dropping):
        client.set_response_for(LossAnalysisDraft, payload)

    assert "risk_dispositions" in _complete(keeping, _Stage1aGapProviderDraft)
    assert "risk_dispositions" not in _complete(dropping, _Stage1aGapProviderDraft)
