"""Risk actionability classification before Stage 1a."""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    ARTIFACT_FILENAME,
    RiskActionabilityResponse,
    classify_risk_actionability,
)

from tests.helpers.prompt_budget import block_every_prompt
from tests.stpa.sp1_helpers import MockLLMClient


def _card(risk_id: str) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description of {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _decision(risk_id: str, decision: str) -> dict[str, str]:
    return {"risk_id": risk_id, "decision": decision, "reason": "Stated reason."}


def _classify(client: MockLLMClient, cards: list[RiskCard], run_dir: Path):
    return classify_risk_actionability(
        llm_client=client,
        use_case_text="A clinic assistant answers patient questions.",
        risk_cards=cards,
        run_dir=run_dir,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )


def test_only_actionable_cards_reach_stage_1a(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse,
        {
            "decisions": [
                _decision("r-1", "actionable"),
                _decision("r-2", "outside_boundary"),
                _decision("r-3", "not_applicable"),
            ]
        },
    )

    outcome = _classify(client, [_card("r-1"), _card("r-2"), _card("r-3")], tmp_path)

    assert [card.risk_id for card in outcome.actionable_cards] == ["r-1"]
    assert outcome.record.status == "completed"
    assert outcome.record.counts == {
        "actionable": 1,
        "outside_boundary": 1,
        "not_applicable": 1,
        "fallback": 0,
    }
    assert len(client.calls) == 1
    persisted = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
    assert [entry["risk_id"] for entry in persisted["entries"]] == ["r-1", "r-2", "r-3"]


def test_missing_cards_are_retried_then_kept_actionable(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse,
        [
            {"decisions": [_decision("r-1", "outside_boundary")]},
            {"decisions": [_decision("r-9", "actionable")]},
        ],
    )

    outcome = _classify(client, [_card("r-1"), _card("r-2")], tmp_path)

    assert len(client.calls) == 2
    assert "r-1" not in client.calls[1].user_prompt.split("## Organizational Risks")[-1]
    assert [card.risk_id for card in outcome.actionable_cards] == ["r-2"]
    entries = {entry.risk_id: entry for entry in outcome.record.entries}
    assert entries["r-2"].source == "fallback"
    assert outcome.record.status == "partial"
    assert any("unrequested card 'r-9'" in item for item in outcome.record.warnings)


def test_failed_calls_keep_every_card_actionable(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_invalid_response_for(RiskActionabilityResponse)

    outcome = _classify(client, [_card("r-1")], tmp_path)

    assert [card.risk_id for card in outcome.actionable_cards] == ["r-1"]
    assert outcome.record.counts["fallback"] == 1
    assert outcome.record.warnings


def test_json_decode_retry_counts_as_a_sent_request(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse,
        ["not json {", {"decisions": [_decision("r-1", "actionable")]}],
    )

    outcome = _classify(client, [_card("r-1")], tmp_path)

    assert len(client.calls) == 2
    assert outcome.record.status == "completed"
    assert outcome.record.call_count == 2
    persisted = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
    assert persisted["call_count"] == 2


def test_failed_steps_count_every_sent_request(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_invalid_response_for(RiskActionabilityResponse)

    outcome = _classify(client, [_card("r-1")], tmp_path)

    # Each step sends its request and one JSON-decode retry.
    assert len(client.calls) == 4
    assert outcome.record.call_count == 4


def test_blocked_steps_record_zero_calls(tmp_path: Path, monkeypatch) -> None:
    block_every_prompt(monkeypatch)
    client = MockLLMClient()

    outcome = _classify(client, [_card("r-1")], tmp_path)

    assert client.calls == []
    assert [card.risk_id for card in outcome.actionable_cards] == ["r-1"]
    assert outcome.record.status == "partial"
    assert outcome.record.call_count == 0
    assert any("prompt_budget_exceeded" in item for item in outcome.record.warnings)


def test_boundary_test_weighs_the_description_not_only_the_threat(
    tmp_path: Path,
) -> None:
    """Cards whose threat names an outside actor stay actionable when the
    system's own actions can produce the described harm."""
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse, {"decisions": [_decision("r-1", "actionable")]}
    )

    _classify(client, [_card("r-1")], tmp_path)

    system = " ".join(client.calls[0].system_prompt.split())
    assert "Judge the risk's description, threat, and consequence together" in system
    assert "actionable` even when the stated threat names an outside actor" in system
    assert "makes a risk `not_applicable`, not `outside_boundary`" in system


def test_no_cards_makes_no_call(tmp_path: Path) -> None:
    client = MockLLMClient()

    outcome = _classify(client, [], tmp_path)

    assert client.calls == []
    assert outcome.record.status == "empty"
    assert (tmp_path / ARTIFACT_FILENAME).exists()
