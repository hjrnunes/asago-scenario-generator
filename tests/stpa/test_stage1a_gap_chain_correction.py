"""Stage 1a: one correction when the gap call returns no hazard chain.

The fixtures are trimmed from a recorded batch-fill unit (GLM, a
buy-now-pay-later support assistant, 2026-10-10): the risk-derivation reply
declared five grounded losses and no hazards or constraints, and the gap
reply that followed added two use-case losses and again no hazards or
constraints.  The fixtures keep two of the losses and three of the risk
cards.  Every test uses a fake client and contacts no network.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    LossAnalysisDraft,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _DraftSemanticValidationError,
    _MissingHazardChainError,
    _validate_complete_chain,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    MISSING_HAZARD_CHAIN_REPAIR_KIND,
)
from tests.helpers.stage1a_targeted_repair import _repair_record, _stage1a_entries
from tests.stpa.sp1_helpers import MockLLMClient

_CARD_IDS = ("credo-risk-026", "atlas-hallucination", "credo-risk-034")

_CHAIN_FINDING = (
    "no hazards were declared or supplied; no security constraints were declared"
)

# Source: batch fill L3 klarna-r1, call 24 (risk_derivation), trimmed to two
# losses and three cards.  Grounded losses, no hazards, no constraints.
_RISK_REPLY = json.dumps(
    {
        "hazards": [],
        "risk_card_losses": [
            {
                "description": (
                    "Customers of the buy-now-pay-later platform suffer monetary "
                    "loss or unfair financial outcomes through the assistant's "
                    "refund processing (process_refund) or payment rescheduling "
                    "(schedule_payment)."
                ),
                "handle": "customer_financial_harm",
                "provenance": "risk_card",
                "source_risk_cards": [_CARD_IDS[0]],
            },
            {
                "description": (
                    "Customers act on confident-but-wrong or ungrounded answers "
                    "about fees, refund eligibility, or payment terms and make "
                    "poor financial decisions."
                ),
                "handle": "ungrounded_answer_harm",
                "provenance": "risk_card",
                "source_risk_cards": [_CARD_IDS[1]],
            },
        ],
        "risk_dispositions": [
            {
                "risk_ref": _CARD_IDS[0],
                "disposition": "cited",
                "loss_ids": ["customer_financial_harm"],
                "reason": None,
            },
            {
                "risk_ref": _CARD_IDS[1],
                "disposition": "cited",
                "loss_ids": ["ungrounded_answer_harm"],
                "reason": None,
            },
            {
                "risk_ref": _CARD_IDS[2],
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": (
                    "This risk concerns oversight of internal employee "
                    "generative-AI adoption, not the customer-facing assistant."
                ),
            },
        ],
        "security_constraints": [],
        "use_case_losses": [],
    },
    indent=2,
)

# Source: batch fill L3 klarna-r1, call 25 (gap_analysis), byte for byte
# apart from one dropped use-case loss.
_CHAINLESS_GAP_REPLY = (
    "{\n"
    '  "hazards": [],\n'
    '  "risk_card_losses": [],\n'
    '  "security_constraints": [],\n'
    '  "use_case_losses": [\n'
    "    {\n"
    '      "description": "Customers with complex, nuanced, or ambiguous cases '
    "receive generic, unhelpful service and leave the interaction without their "
    "issue resolved, because the assistant neither resolves the case nor hands "
    'it to a human agent.",\n'
    '      "handle": "unresolved_complex_case_loss",\n'
    '      "provenance": "use_case",\n'
    '      "source_risk_cards": []\n'
    "    }\n"
    "  ]\n"
    "}"
)


def _hazard(related_losses: list[str]) -> dict:
    return {
        "handle": "wrong_refund_hazard",
        "description": (
            "The assistant issues a refund or reschedules a payment that the "
            "customer's verified case does not support."
        ),
        "related_losses": related_losses,
    }


def _constraint() -> dict:
    return {
        "handle": "refund_constraint",
        "rule": (
            "The assistant must issue a refund only for an order the verified "
            "customer owns and that the refund policy covers."
        ),
        "applies_when": [],
        "behavior_class": "unauthorized_write",
        "related_hazards": ["wrong_refund_hazard"],
        "obligations": [],
    }


def _gap_reply(*, hazards: list[dict], constraints: list[dict]) -> str:
    return json.dumps(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": hazards,
            "security_constraints": constraints,
        }
    )


_COMPLETE_GAP_REPLY = _gap_reply(
    hazards=[_hazard(["L-1"])], constraints=[_constraint()]
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


def _derive(client: MockLLMClient, tmp_path):
    return derive_loss_analysis(
        llm_client=client,
        use_case_text=(
            "A neutralized payments support assistant answers customer "
            "questions and can process refunds and reschedule payments."
        ),
        risk_cards=_cards(),
        run_dir=tmp_path,
    )


def _chain_entries(tmp_path) -> list[dict]:
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == MISSING_HAZARD_CHAIN_REPAIR_KIND
    ]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_chainless_gap_reply_gets_one_correction_carrying_the_feedback(tmp_path):
    client = _client(_RISK_REPLY, _CHAINLESS_GAP_REPLY, _COMPLETE_GAP_REPLY)

    result = _derive(client, tmp_path)

    assert len(client.calls) == 3
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "gap_analysis",
        "gap_analysis_repair",
    ]
    gap, correction = client.calls[1], client.calls[2]
    assert correction.system_prompt == gap.system_prompt
    assert correction.response_format is gap.response_format
    assert correction.max_completion_tokens == gap.max_completion_tokens
    assert correction.user_prompt.startswith(gap.user_prompt)
    feedback = correction.user_prompt[len(gap.user_prompt) :]
    assert _CHAIN_FINDING in feedback
    assert "Declare grounded losses before referencing them in hazards" in feedback
    assert _CHAINLESS_GAP_REPLY in feedback
    assert '"properties"' not in feedback
    assert [hazard.related_losses for hazard in result.hazards] == [["L-1"]]
    assert [item.related_hazards for item in result.security_constraints] == [
        [result.hazards[0].hazard_id]
    ]
    (record,) = _chain_entries(tmp_path)
    assert record["stage"] == "gap_analysis"
    assert record["attempt"] == "repair"
    assert record["outcome"] == "repaired"
    assert record["raw_step"] == "gap_analysis_repair"
    assert _CHAIN_FINDING in record["reason"]
    assert not [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["outcome"] == "unsupported"
    ]


def test_second_chainless_reply_stops_typed_after_three_requests(tmp_path):
    client = _client(_RISK_REPLY, _CHAINLESS_GAP_REPLY, _CHAINLESS_GAP_REPLY)

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    message = str(exc_info.value)
    assert "missing-hazard-chain correction failed" in message
    assert _CHAIN_FINDING in message
    assert "missing_hazard_chain failure class" in message
    assert len(client.calls) == 3
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "gap_analysis",
        "gap_analysis_repair",
    ]
    (record,) = _chain_entries(tmp_path)
    assert record["outcome"] == "failed"
    assert record["applied"] == {}
    assert not (tmp_path / "loss-analysis.yaml").exists()


@pytest.mark.parametrize(
    "gap_reply",
    [
        pytest.param(
            _gap_reply(hazards=[_hazard([])], constraints=[_constraint()]),
            id="hazard-cites-no-loss",
        ),
        pytest.param(
            _gap_reply(hazards=[_hazard(["L-1"])], constraints=[]),
            id="hazards-without-constraints",
        ),
    ],
)
def test_other_chain_failures_still_get_no_correction(tmp_path, gap_reply):
    client = _client(_RISK_REPLY, gap_reply, _COMPLETE_GAP_REPLY)

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    assert "targeted repair unsupported" in str(exc_info.value)
    assert len(client.calls) == 2
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "gap_analysis",
    ]
    assert not _chain_entries(tmp_path)


# Request digests at producer f704e000, before the correction existed.  The
# risk system digest follows later edits of that prompt, which this
# correction does not touch.
_RISK_SYSTEM_DIGEST = "215d6d8b8f96327b589d2ab2d03718d3abc6ee3b0374500cf07719ddc10efecd"
_RISK_USER_DIGEST = "ee6f683a5c3af1cc3dadf9657cd75ab4a5616a612c7a37e7d2f10f349db6791c"
_GAP_SYSTEM_DIGEST = "a9f69e438586a6902c2d5ec174ca421e407e1fe5f65db4d767c62aa6ba7c97cd"
_GAP_USER_DIGEST = "df41179e9d22db69444b21756396ed73ddb795575a50e31d408184db30eb53a5"


def test_complete_first_gap_reply_sends_the_same_two_requests(tmp_path):
    client = _client(_RISK_REPLY, _COMPLETE_GAP_REPLY)

    result = _derive(client, tmp_path)

    assert len(client.calls) == 2
    risk, gap = client.calls
    assert [
        _digest(risk.system_prompt),
        _digest(risk.user_prompt),
        _digest(gap.system_prompt),
        _digest(gap.user_prompt),
    ] == [_RISK_SYSTEM_DIGEST, _RISK_USER_DIGEST, _GAP_SYSTEM_DIGEST, _GAP_USER_DIGEST]
    assert len(result.hazards) == 1
    assert not (tmp_path / "loss-analysis-repair.yaml").exists()


def _draft(**collections: list) -> LossAnalysisDraft:
    return LossAnalysisDraft.model_validate(collections)


_LOSS = {
    "loss_id": "L-9",
    "description": "Customers lose money.",
    "provenance": "use_case",
    "source_risk_cards": [],
}


@pytest.mark.parametrize(
    ("draft", "allowed_loss_ids", "allowed_hazard_ids", "missing_chain"),
    [
        pytest.param(_draft(), {"L-1"}, set(), True, id="supplied-losses-only"),
        pytest.param(
            _draft(use_case_losses=[_LOSS]), set(), set(), True, id="declared-loss"
        ),
        pytest.param(_draft(), set(), set(), False, id="no-losses-at-all"),
        pytest.param(
            _draft(), {"L-1"}, {"H-1"}, False, id="supplied-hazard-no-constraint"
        ),
        pytest.param(
            _draft(
                hazards=[
                    Hazard(hazard_id="H-2", description="State.", related_losses=[])
                ]
            ),
            {"L-1"},
            set(),
            False,
            id="hazard-with-no-loss",
        ),
        pytest.param(
            _draft(
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-2",
                        rule="The agent must not.",
                        related_hazards=[],
                    )
                ]
            ),
            {"L-1"},
            set(),
            False,
            id="constraint-with-no-hazard",
        ),
    ],
)
def test_only_the_absent_hazard_chain_raises_the_dedicated_error(
    draft, allowed_loss_ids, allowed_hazard_ids, missing_chain
):
    with pytest.raises(_DraftSemanticValidationError) as exc_info:
        _validate_complete_chain(
            draft,
            context="gap_analysis",
            allowed_loss_ids=allowed_loss_ids,
            allowed_hazard_ids=allowed_hazard_ids,
        )

    assert isinstance(exc_info.value, _MissingHazardChainError) is missing_chain
