"""Stage 1a recovery of a risk-derivation reply cut off inside a loss list.

The fixture is a trimmed copy of a recorded risk-derivation reply (Gemma, an
Airbnb unit, 2026-10-10) that stopped at the 8,192-token completion cap
while the sixth loss record counted invented ``credo-risk-NNN`` IDs in its
``source_risk_cards``.  The five loss records before it were complete.  Only
the fields the code reads are kept: each complete loss cites two supplied
cards, the cut record counts a short run, and card texts are neutralized.
Every test uses a fake client and contacts no network.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE1A_MAX_COMPLETION_TOKENS,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    TRUNCATED_DISPOSITION_RECOVERY_KIND,
    TRUNCATED_LOSS_RECOVERY_KIND,
    DispositionRepairResponse,
    recover_truncated_risk_dispositions,
    recover_truncated_risk_losses,
)
from tests.helpers.stage1a_targeted_repair import _repair_record, _stage1a_entries
from tests.stpa.sp1_helpers import MockLLMClient

_CAP = STAGE1A_MAX_COMPLETION_TOKENS

_USE_CASE = (
    "A neutralized lodging assistant answers guest and host questions about "
    "reservations and listings and escalates safety concerns."
)

# (handle, cited cards) of the five complete loss records, in reply order.
_COMPLETE_LOSSES = (
    ("pii_disclosure_loss", ("credo-risk-036", "mit-ai-risk-subdomain-2.1")),
    ("unauthorized_modification_loss", ("credo-risk-041", "credo-risk-002")),
    ("biased_outcome_loss", ("mit-ai-risk-subdomain-1.1", "credo-risk-012")),
    ("misinformation_loss", ("mit-ai-risk-subdomain-3.1", "credo-risk-021")),
    ("loss_of_human_agency_loss", ("mit-ai-risk-subdomain-5.2", "credo-risk-019")),
)
_CUT_HANDLE = "safety_and_trust_violation_loss"
# Cards only the cut record cites, plus one no record cites.
_OTHER_CARDS = ("mit-ai-risk-subdomain-7.2", "credo-risk-003", "credo-risk-050")
_CARD_IDS = (
    tuple(card for _, cards in _COMPLETE_LOSSES for card in cards) + _OTHER_CARDS
)
# Canonical loss IDs follow the sorted handles.
_LOSS_IDS = {
    handle: f"L-{number}"
    for number, handle in enumerate(
        sorted(handle for handle, _ in _COMPLETE_LOSSES), start=1
    )
}


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


def _loss(handle: str, cards) -> dict:
    return {
        "handle": handle,
        "description": f"Neutralized stakeholder loss {handle}.",
        "provenance": "risk_card",
        "source_risk_cards": list(cards),
    }


def _cut_record_text(*, count: int = 40) -> str:
    """The cut sixth record: a counting run stopped inside one string."""
    head = json.dumps(_loss(_CUT_HANDLE, ("mit-ai-risk-subdomain-7.2",)))
    head = head[: head.rfind("]")]
    run = ", ".join(f'"credo-risk-{number:03d}"' for number in range(3, 3 + count))
    return head + ", " + run + ', "credo-'


def _cut_reply(*, complete: int = len(_COMPLETE_LOSSES)) -> str:
    """The trimmed recorded reply, in schema order, cut inside its loss list."""
    rows = [json.dumps(_loss(*loss)) for loss in _COMPLETE_LOSSES[:complete]]
    rows.append(_cut_record_text())
    return '{"risk_card_losses": [' + ", ".join(rows)


def _result(content: str, *, completion_tokens: int = _CAP) -> LLMResult:
    return LLMResult(
        content=content,
        completion_tokens=completion_tokens,
        duration_ms=1,
        request_controls={"max_completion_tokens": _CAP},
    )


class _CapClient(MockLLMClient):
    """Report a completion-cap stop for undecodable string bodies."""

    def __init__(self, *, completion_tokens: int = _CAP) -> None:
        super().__init__()
        self._stop_tokens = completion_tokens

    def complete(self, *args, **kwargs) -> LLMResult:
        result = super().complete(*args, **kwargs)
        if isinstance(result.content, str):
            try:
                json.loads(result.content)
            except json.JSONDecodeError:
                return result.model_copy(
                    update={
                        "completion_tokens": self._stop_tokens,
                        "request_controls": {
                            "max_completion_tokens": kwargs.get("max_completion_tokens")
                        },
                    }
                )
        return result


def _repair_rows() -> list[dict]:
    """One row per supplied card: cited by its complete loss, else not applicable."""
    citing = {card: handle for handle, cards in _COMPLETE_LOSSES for card in cards}
    rows = []
    for card in _CARD_IDS:
        if card in citing:
            rows.append(
                {
                    "risk_ref": card,
                    "disposition": "cited",
                    "loss_ids": [_LOSS_IDS[citing[card]]],
                    "reason": None,
                }
            )
        else:
            rows.append(
                {
                    "risk_ref": card,
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "Neutralized reason: no declared loss here.",
                }
            )
    return rows


def _gap_reply() -> dict:
    """A gap reply that derives one hazard and one constraint per loss."""
    hazards, constraints = [], []
    for number, loss_id in enumerate(sorted(_LOSS_IDS.values()), start=1):
        hazards.append(
            {
                "handle": f"gap_hazard_{number}",
                "description": f"The neutralized system reaches unsafe state {number}.",
                "related_losses": [loss_id],
            }
        )
        constraints.append(
            {
                "handle": f"gap_constraint_{number}",
                "rule": f"The neutralized system must uphold control {number}.",
                "applies_when": [],
                "behavior_class": None,
                "related_hazards": [f"gap_hazard_{number}"],
                "obligations": [],
            }
        )
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": hazards,
        "security_constraints": constraints,
    }


def _derive(client: MockLLMClient, tmp_path):
    return derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_cards(),
        run_dir=tmp_path,
    )


def test_cut_loss_list_keeps_complete_losses_and_reaches_the_accounting_repair(
    tmp_path,
):
    client = _CapClient()
    client.set_response_for(LossAnalysisDraft, [_cut_reply(), _gap_reply()])
    client.set_response_for(
        DispositionRepairResponse, {"risk_dispositions": _repair_rows()}
    )

    result = _derive(client, tmp_path)

    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    assert client.calls[1].response_format.__name__ == "DispositionRepairResponse"
    repair_prompt = entries[1]["user_prompt_text"]
    for risk_id in _CARD_IDS:
        assert risk_id in repair_prompt
    assert sorted(loss.loss_id for loss in result.risk_card_losses) == sorted(
        _LOSS_IDS.values()
    )
    assert _CUT_HANDLE not in json.dumps(
        [loss.description for loss in result.risk_card_losses]
    )
    assert {row.risk_ref for row in result.risk_dispositions} == set(_CARD_IDS)
    cleanup_names = [
        item["name"] for item in entries[0].get("cleanup_transformations", [])
    ]
    assert TRUNCATED_LOSS_RECOVERY_KIND in cleanup_names
    (record,) = [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == TRUNCATED_LOSS_RECOVERY_KIND
    ]
    assert record["stage"] == "risk_derivation"
    assert record["identity"] == "risk_card_losses"
    assert record["outcome"] == "applied"
    assert record["applied"] == {
        "kept_losses": 5,
        "dropped_record": _CUT_HANDLE,
        "emptied": [
            "use_case_losses",
            "hazards",
            "security_constraints",
            "risk_dispositions",
        ],
    }


def test_cut_loss_list_below_the_cap_stays_terminal(tmp_path):
    client = _CapClient(completion_tokens=_CAP - 1)
    client.set_response_for(LossAnalysisDraft, [_cut_reply(), _gap_reply()])

    with pytest.raises(StageError, match="never decoded as JSON"):
        _derive(client, tmp_path)
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation"
    ]


def test_cut_inside_the_first_loss_record_stays_terminal(tmp_path):
    client = _CapClient()
    client.set_response_for(LossAnalysisDraft, [_cut_reply(complete=0), _gap_reply()])

    with pytest.raises(StageError, match="never decoded as JSON"):
        _derive(client, tmp_path)
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation"
    ]


def _cut_disposition_reply() -> str:
    """A complete graph whose disposition list is cut mid-row."""
    body = {
        "risk_card_losses": [_loss(*loss) for loss in _COMPLETE_LOSSES],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
        "risk_dispositions": _repair_rows(),
    }
    text = json.dumps(body)
    return text[: text.rfind("]")] + ', {"risk_ref": "cut'


def test_cut_inside_dispositions_keeps_the_disposition_recovery():
    text = _cut_disposition_reply()

    assert recover_truncated_risk_losses(_result(text)) is None
    recovered = recover_truncated_risk_dispositions(_result(text))
    assert recovered is not None
    assert recovered[1].kept_rows == len(_CARD_IDS)
    assert TRUNCATED_DISPOSITION_RECOVERY_KIND == "truncated_disposition_recovery"


def _alphabetical_cut_in_use_case_losses() -> str:
    """Alphabetical key order (as one model writes it), cut in the last list."""
    head = {
        "hazards": [
            {
                "handle": "exposure_hazard",
                "description": "The neutralized system exposes a record.",
                "related_losses": ["pii_disclosure_loss"],
            }
        ],
        "risk_card_losses": [_loss(*_COMPLETE_LOSSES[0])],
        "risk_dispositions": _repair_rows()[:2],
        "security_constraints": [],
    }
    text = json.dumps(head)
    use_case = dict(_loss("use_case_loss", ()), provenance="use_case")
    return (
        text[:-1]
        + ', "use_case_losses": ['
        + json.dumps(use_case)
        + ', {"handle": "cut_use_case_loss", "descr'
    )


def test_cut_in_a_later_loss_list_keeps_every_complete_collection():
    recovered = recover_truncated_risk_losses(
        _result(_alphabetical_cut_in_use_case_losses())
    )

    assert recovered is not None
    result, recovery = recovered
    body = json.loads(result.content)
    assert [loss["handle"] for loss in body["risk_card_losses"]] == [
        "pii_disclosure_loss"
    ]
    assert [loss["handle"] for loss in body["use_case_losses"]] == ["use_case_loss"]
    assert [hazard["handle"] for hazard in body["hazards"]] == ["exposure_hazard"]
    assert body["risk_dispositions"] == []
    assert recovery.collection == "use_case_losses"
    assert recovery.kept_losses == 1
    assert recovery.dropped_record == "cut_use_case_loss"
    assert recovery.emptied == ("risk_dispositions",)


@pytest.mark.parametrize(
    "text,completion_tokens",
    [
        pytest.param(_cut_reply(), _CAP - 1, id="below-cap"),
        pytest.param(_cut_reply(complete=0), _CAP, id="no-complete-loss"),
        pytest.param(json.dumps({"risk_card_losses": []}), _CAP, id="decodes"),
        pytest.param(
            '{"risk_card_losses": [], "hazards": [{"ha', _CAP, id="cut-elsewhere"
        ),
        pytest.param('{"risk_card_losses": [', _CAP, id="cut-at-list-start"),
    ],
)
def test_loss_recovery_applies_only_to_a_cut_loss_list(text, completion_tokens):
    result = _result(text, completion_tokens=completion_tokens)
    assert recover_truncated_risk_losses(result) is None


def test_cut_record_without_a_written_handle_is_named_by_position():
    text = '{"risk_card_losses": [' + json.dumps(_loss(*_COMPLETE_LOSSES[0]))
    text += ', {"descr'

    recovered = recover_truncated_risk_losses(_result(text))

    assert recovered is not None
    assert recovered[1].dropped_record == "row 1"
