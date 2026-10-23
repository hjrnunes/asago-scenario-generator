"""Risk actionability classification before Stage 1a."""

from __future__ import annotations

from pathlib import Path

import pytest
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


def _card(risk_id: str, **causal_chain: str) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description of {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
        **causal_chain,
    )


def _decision(
    risk_id: str,
    decision: str,
    *,
    action: str | None = None,
    stakeholder: str | None = None,
) -> dict[str, str | None]:
    """Return one reply row; an actionable row names its action by default."""
    if decision == "actionable":
        action = action if action is not None else "The assistant's reply."
        stakeholder = stakeholder if stakeholder is not None else "The patient."
    return {
        "risk_id": risk_id,
        "system_action": action,
        "affected_stakeholder": stakeholder,
        "decision": decision,
        "reason": "Stated reason.",
    }


def _classify(client: MockLLMClient, cards: list[RiskCard], run_dir: Path):
    return classify_risk_actionability(
        llm_client=client,
        use_case_text="A clinic assistant answers patient questions.",
        risk_cards=cards,
        run_dir=run_dir,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )


def test_every_card_is_recorded_with_its_scope(tmp_path: Path) -> None:
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

    assert [entry.decision.value for entry in outcome.record.entries] == [
        "actionable",
        "outside_boundary",
        "not_applicable",
    ]
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
    assert persisted["entries"][0]["system_action"] == "The assistant's reply."
    assert persisted["entries"][0]["affected_stakeholder"] == "The patient."
    assert "system_action" not in persisted["entries"][1]


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
    entries = {entry.risk_id: entry for entry in outcome.record.entries}
    assert entries["r-1"].decision.value == "outside_boundary"
    assert entries["r-2"].decision.value == "actionable"
    assert entries["r-2"].source == "fallback"
    assert outcome.record.status == "partial"
    assert any("unrequested card 'r-9'" in item for item in outcome.record.warnings)


def test_failed_calls_keep_every_card_actionable(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_invalid_response_for(RiskActionabilityResponse)

    outcome = _classify(client, [_card("r-1")], tmp_path)

    assert outcome.record.counts == {
        "actionable": 1,
        "outside_boundary": 0,
        "not_applicable": 0,
        "fallback": 1,
    }
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
    assert outcome.record.entries[0].source == "fallback"
    assert outcome.record.status == "partial"
    assert outcome.record.call_count == 0
    assert any("prompt_budget_exceeded" in item for item in outcome.record.warnings)


def test_request_shows_the_risk_class_and_hides_the_stated_scenario(
    tmp_path: Path,
) -> None:
    """The scope question sees the class; the card's story is provenance only."""
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse, {"decisions": [_decision("r-1", "actionable")]}
    )
    card = _card(
        "r-1",
        threat="Staff paste patient files into an outside chat tool.",
        threat_source="Clinic staff.",
        consequence="Patient files reach the outside tool's provider.",
    )

    outcome = _classify(client, [card], tmp_path)

    user = " ".join(client.calls[0].user_prompt.split())
    assert (
        "- `r-1`: Risk r-1 (taxonomy: ibm-risk-atlas). "
        "Class description: Description of r-1"
    ) in user
    for hidden in (
        "Staff paste patient files",
        "Clinic staff",
        "outside tool's provider",
        "Threat:",
        "Consequence:",
    ):
        assert hidden not in user
        assert hidden not in client.calls[0].system_prompt
    entry = outcome.record.entries[0]
    assert entry.stated_threat == card.threat
    assert entry.stated_consequence == card.consequence
    persisted = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
    assert persisted["entries"][0]["stated_threat"] == card.threat


def test_system_prompt_asks_the_class_question(tmp_path: Path) -> None:
    """The class decides: partly is actionable, and an outside actor in the
    policy's threat does not move the risk out of scope."""
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse, {"decisions": [_decision("r-1", "actionable")]}
    )

    _classify(client, [_card("r-1")], tmp_path)

    system = " ".join(client.calls[0].system_prompt.split())
    assert (
        "can this system's own actions (its replies, its tool calls, or the data "
        "it stores or retrieves) produce harm of this class to someone"
    ) in system
    assert "`actionable`: yes, or partly." in system
    assert (
        "A risk is `actionable` even when the policy's stated threat names an "
        "outside actor"
    ) in system
    assert "that story is kept as provenance and is not shown to you" in system
    assert "makes a risk `not_applicable`, not `outside_boundary`" in system
    assert "When the evidence does not settle the decision, choose `actionable`." in (
        system
    )
    for field_name in (
        "risk_id",
        "system_action",
        "affected_stakeholder",
        "decision",
        "reason",
    ):
        assert f"- `{field_name}`:" in system
    assert '"system_action": null, "affected_stakeholder": null' in system


def test_reply_schema_requires_the_action_and_stakeholder_keys() -> None:
    schema = RiskActionabilityResponse.model_json_schema()
    row = schema["$defs"]["RiskActionabilityDecision"]

    assert set(row["required"]) == {
        "risk_id",
        "system_action",
        "affected_stakeholder",
        "decision",
        "reason",
    }
    assert row["additionalProperties"] is False
    for field_name in ("system_action", "affected_stakeholder"):
        assert {"type": "null"} in row["properties"][field_name]["anyOf"]


@pytest.mark.parametrize(
    ("first", "problem"),
    (
        (
            _decision("r-1", "actionable", action="", stakeholder="The patient."),
            "an actionable decision names no system action or stakeholder",
        ),
        (
            _decision("r-1", "actionable", action="A reply.", stakeholder=" "),
            "an actionable decision names no system action or stakeholder",
        ),
        (
            _decision("r-1", "outside_boundary", action="A reply."),
            "the outside_boundary decision names a system action or stakeholder",
        ),
        (
            _decision("r-1", "not_applicable", stakeholder="The patient."),
            "the not_applicable decision names a system action or stakeholder",
        ),
    ),
)
def test_a_decision_that_contradicts_its_action_fields_goes_to_the_retry(
    tmp_path: Path, first: dict, problem: str
) -> None:
    client = MockLLMClient()
    client.set_response_for(
        RiskActionabilityResponse,
        [
            {"decisions": [first]},
            {"decisions": [_decision("r-1", "outside_boundary")]},
        ],
    )

    outcome = _classify(client, [_card("r-1")], tmp_path)

    assert len(client.calls) == 2
    assert f"risk_actionability: rejected decision for 'r-1': {problem}" in (
        outcome.record.warnings
    )
    entry = outcome.record.entries[0]
    assert entry.decision.value == "outside_boundary"
    assert entry.source == "model"
    assert outcome.record.status == "completed"


def test_a_decision_still_contradictory_after_the_retry_stays_actionable(
    tmp_path: Path,
) -> None:
    client = MockLLMClient()
    contradictory = {"decisions": [_decision("r-1", "outside_boundary", action="x")]}
    client.set_response_for(
        RiskActionabilityResponse, [contradictory, dict(contradictory)]
    )

    outcome = _classify(client, [_card("r-1")], tmp_path)

    entry = outcome.record.entries[0]
    assert entry.decision.value == "actionable"
    assert entry.source == "fallback"
    assert outcome.record.status == "partial"


def test_no_cards_makes_no_call(tmp_path: Path) -> None:
    client = MockLLMClient()

    outcome = _classify(client, [], tmp_path)

    assert client.calls == []
    assert outcome.record.status == "empty"
    assert (tmp_path / ARTIFACT_FILENAME).exists()
