"""Stage 1a: one targeted repair for a risk-derivation reply with no grounded loss.

The fixture is the recorded reply (GLM, an Airbnb unit, 2026-10-10) that
spent its tokens on reasoning and then wrote all five collections empty
while risk cards were supplied.  The loss-presence validator already writes
exact feedback for that failure; the repair sends it once with the prior
reply.  Card texts are neutralized.  Every test uses a fake client and
contacts no network.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    LOSS_PRESENCE_REPAIR_IDENTITY,
)
from tests.helpers.stage1a_targeted_repair import (
    _USE_CASE,
    _attempt_two_response,
    _occiai_cards,
    _repair_record,
    _stage1a_entries,
)
from tests.stpa.sp1_helpers import MockLLMClient

# The recorded reply, byte for byte.
_EMPTY_REPLY = (
    "{\n"
    '  "hazards": [],\n'
    '  "risk_card_losses": [],\n'
    '  "risk_dispositions": [],\n'
    '  "security_constraints": [],\n'
    '  "use_case_losses": []\n'
    "}"
)

_FEEDBACK = (
    "Declare at least one grounded risk-card loss with non-empty "
    "source_risk_cards before writing hazards or security constraints."
)

_CARD_IDS = ("mit-ai-risk-subdomain-2.2", "credo-risk-037", "credo-risk-050")


def _cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id=risk_id,
            risk_name=f"Neutralized risk {index}",
            risk_description=f"Neutralized description {index} for analysis.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
            consequence=f"Neutralized consequence {index}.",
        )
        for index, risk_id in enumerate(_CARD_IDS, start=1)
    ]


def _corrected_reply() -> str:
    """One grounded loss and every supplied card accounted for."""
    return json.dumps(
        {
            "hazards": [],
            "risk_card_losses": [
                {
                    "handle": "reservation_privacy_loss",
                    "description": "Reservation data reaches a non-party.",
                    "provenance": "risk_card",
                    "source_risk_cards": list(_CARD_IDS[:2]),
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": _CARD_IDS[0],
                    "disposition": "cited",
                    "loss_ids": ["reservation_privacy_loss"],
                },
                {
                    "risk_ref": _CARD_IDS[1],
                    "disposition": "cited",
                    "loss_ids": ["reservation_privacy_loss"],
                },
                {
                    "risk_ref": _CARD_IDS[2],
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "Neutralized reason: no declared loss here.",
                },
            ],
            "security_constraints": [],
            "use_case_losses": [],
        }
    )


def _gap_reply() -> str:
    return json.dumps(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "privacy_exposure_hazard",
                    "description": "The assistant returns a record to a non-party.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "privacy_constraint",
                    "rule": "The assistant must return a record only to a party.",
                    "applies_when": [],
                    "behavior_class": "disclosure",
                    "related_hazards": ["privacy_exposure_hazard"],
                    "obligations": [],
                }
            ],
        }
    )


class _RawClient(MockLLMClient):
    """Return string replies verbatim, as the provider client does."""

    def _adapt_legacy_stage1a(self, content, response_format):
        if isinstance(content, str):
            return content
        return super()._adapt_legacy_stage1a(content, response_format)


def _client(*replies: str) -> MockLLMClient:
    client = _RawClient()
    client.set_response_for(LossAnalysisDraft, list(replies))
    return client


def _derive(client: MockLLMClient, tmp_path):
    return derive_loss_analysis(
        llm_client=client,
        use_case_text="A neutralized lodging assistant answers guest questions.",
        risk_cards=_cards(),
        run_dir=tmp_path,
    )


def _repair_entries(tmp_path) -> list[dict]:
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["identity"] == LOSS_PRESENCE_REPAIR_IDENTITY
    ]


def test_empty_reply_gets_one_correction_carrying_the_feedback(tmp_path):
    client = _client(_EMPTY_REPLY, _corrected_reply(), _gap_reply())

    result = _derive(client, tmp_path)

    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    first, correction = client.calls[0], client.calls[1]
    assert correction.system_prompt == first.system_prompt
    assert correction.response_format is first.response_format
    assert correction.user_prompt.startswith(first.user_prompt)
    feedback = correction.user_prompt[len(first.user_prompt) :]
    assert _FEEDBACK in " ".join(feedback.split())
    assert "no grounded losses were declared" in feedback
    assert _EMPTY_REPLY in feedback
    assert [loss.loss_id for loss in result.risk_card_losses] == ["L-1"]
    assert {row.risk_ref for row in result.risk_dispositions} == set(_CARD_IDS)
    (record,) = _repair_entries(tmp_path)
    assert record["stage"] == "risk_derivation"
    assert record["attempt"] == "repair"
    assert record["kind"] == "repair"
    assert record["outcome"] == "repaired"
    assert record["raw_step"] == "risk_derivation_repair"
    assert "no grounded losses were declared" in record["reason"]
    assert not [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["outcome"] == "unsupported"
    ]


def test_second_empty_reply_stops_typed_after_two_requests(tmp_path):
    client = _client(_EMPTY_REPLY, _EMPTY_REPLY, _gap_reply())

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    message = str(exc_info.value)
    assert "targeted repair failed" in message
    assert "no grounded losses were declared" in message
    assert "loss_presence failure class" in message
    assert len(client.calls) == 2
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
    ]
    (record,) = _repair_entries(tmp_path)
    assert record["outcome"] == "failed"
    assert record["applied"] == {}


def test_other_semantic_failures_still_get_no_repair(tmp_path):
    draft = _attempt_two_response()
    draft["hazards"][6]["description"] = (
        "The model fails and the service becomes unavailable."
    )
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [draft])

    with pytest.raises(StageError) as exc_info:
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

    assert "targeted repair unsupported" in str(exc_info.value)
    assert "draft_semantics failure class" in str(exc_info.value)
    assert len(client.calls) == 1
