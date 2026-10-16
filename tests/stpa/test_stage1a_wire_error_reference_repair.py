"""A first reply with a record-level wire error and a dangling reference.

A recorded MiniKlarna ``risk_derivation`` reply carries an obligation entry
whose ``rule_span`` does not quote its rule (a record-level wire error) and
cites ``loss_customer_trust``, a loss it never declared, from two hazards
and two ``risk_dispositions`` rows.  Salvage removes the failing obligation
entry, and the dangling reference goes to the one reference repair, which
may now also edit a disposition row's ``loss_ids``.  The repair reply
chooses to remove or replace each unknown entry.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionReferenceRepairResponse,
    ReferenceRepairResponse,
)
from tests.helpers.calls_log import read_calls_jsonl, stage1a_steps
from tests.stpa.sp1_helpers import MockLLMClient, valid_gap_draft_dict

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "stpa"
    / "pr25_klarna_r1_risk_derivation.json"
)
RECORDED_REPLY = json.loads(FIXTURE.read_text(encoding="utf-8"))
DANGLING = "loss_customer_trust"

# Canonical IDs the compiled first reply carries.
FINANCIAL_HARM = "L-2"
SERVICE_QUALITY = "L-4"
REGULATORY_PENALTY = "L-7"
UNGROUNDED_ANSWER = "H-8"
OVERRELIANCE = "H-5"
CITING_CARDS = ("atlas-hallucination", "credo-risk-021")

# The first reply's handles, which the repair request shows and its reply names.
HANDLES = {
    FINANCIAL_HARM: "loss_customer_financial_harm",
    SERVICE_QUALITY: "loss_customer_service_quality",
    REGULATORY_PENALTY: "loss_regulatory_penalty",
    UNGROUNDED_ANSWER: "h_ungrounded_policy_answer",
    OVERRELIANCE: "h_overreliance_no_human_option",
}


def _cards(reply: dict) -> list[RiskCard]:
    return [
        RiskCard(
            risk_id=row["risk_ref"],
            risk_name=row["risk_ref"],
            risk_description=f"Risk {row['risk_ref']}",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
        for row in reply["risk_dispositions"]
    ]


def _derive(
    tmp_path: Path, repairs: list[dict], reply: dict = RECORDED_REPLY
) -> tuple[LossAnalysis, MockLLMClient]:
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft, [json.dumps(reply), valid_gap_draft_dict()]
    )
    client.set_response_for(ReferenceRepairResponse, repairs)
    analysis = derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=_cards(reply),
        run_dir=tmp_path,
    )
    return analysis, client


def _repair(hazards: dict[str, list[str]], dispositions: dict[str, list[str]]) -> dict:
    """A repair reply that names each record by the handle the request shows."""

    def shown(ids: list[str]) -> list[str]:
        return [HANDLES.get(value, value) for value in ids]

    return {
        "hazards": [
            {"hazard_id": HANDLES[hazard_id], "related_losses": shown(losses)}
            for hazard_id, losses in hazards.items()
        ],
        "security_constraints": [],
        "risk_dispositions": [
            {"risk_ref": risk_ref, "loss_ids": shown(losses)}
            for risk_ref, losses in dispositions.items()
        ],
    }


def _hazard(analysis: LossAnalysis, hazard_id: str) -> list[str]:
    return next(h.related_losses for h in analysis.hazards if h.hazard_id == hazard_id)


def _disposition(analysis: LossAnalysis, risk_ref: str) -> list[str]:
    return next(
        row.loss_ids for row in analysis.risk_dispositions if row.risk_ref == risk_ref
    )


def _records(run_dir: Path) -> list[dict]:
    record = yaml.safe_load((run_dir / "loss-analysis-repair.yaml").read_text())
    return record["records"]


def _repair_request(run_dir: Path) -> dict:
    return next(
        entry
        for entry in read_calls_jsonl(run_dir)
        if entry["step"] == "risk_derivation_repair"
    )


REPLACE = _repair(
    {
        UNGROUNDED_ANSWER: [FINANCIAL_HARM, REGULATORY_PENALTY, SERVICE_QUALITY],
        OVERRELIANCE: [SERVICE_QUALITY],
    },
    {
        card: [FINANCIAL_HARM, REGULATORY_PENALTY, SERVICE_QUALITY]
        for card in CITING_CARDS
    },
)
REMOVE = _repair(
    {
        UNGROUNDED_ANSWER: [FINANCIAL_HARM, REGULATORY_PENALTY],
        OVERRELIANCE: [SERVICE_QUALITY],
    },
    {card: [FINANCIAL_HARM, REGULATORY_PENALTY] for card in CITING_CARDS},
)


class TestWireErrorWithDanglingReference:
    def test_sends_exactly_one_reference_repair(self, tmp_path) -> None:
        _, client = _derive(tmp_path, [REPLACE])

        assert stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        assert [call.response_format for call in client.calls] == [
            client.calls[0].response_format,
            DispositionReferenceRepairResponse,
            client.calls[2].response_format,
        ]

    def test_request_selects_the_hazard_and_disposition_lists(self, tmp_path) -> None:
        _derive(tmp_path, [REPLACE])

        prompt = _repair_request(tmp_path)["user_prompt_text"]
        for identity in (
            f"{HANDLES[UNGROUNDED_ANSWER]}.related_losses",
            f"{HANDLES[OVERRELIANCE]}.related_losses",
            *(f"{card}.loss_ids" for card in CITING_CARDS),
        ):
            assert f"### {identity}\n" in prompt
        assert f"**Unknown IDs:** {DANGLING}" in prompt
        assert prompt.count("### ") == 4
        system = _repair_request(tmp_path)["system_prompt_text"]
        assert "risk disposition's `loss_ids`" in system
        assert '"risk_dispositions": [' in system

    def test_replacing_the_reference_continues(self, tmp_path) -> None:
        analysis, _ = _derive(tmp_path, [REPLACE])

        assert _hazard(analysis, UNGROUNDED_ANSWER) == [
            FINANCIAL_HARM,
            REGULATORY_PENALTY,
            SERVICE_QUALITY,
        ]
        assert _hazard(analysis, OVERRELIANCE) == [SERVICE_QUALITY]
        for card in CITING_CARDS:
            assert _disposition(analysis, card) == [
                FINANCIAL_HARM,
                REGULATORY_PENALTY,
                SERVICE_QUALITY,
            ]
        repaired = [r for r in _records(tmp_path) if r["kind"] == "repair"]
        assert {r["identity"] for r in repaired} == {
            f"{UNGROUNDED_ANSWER}.related_losses",
            f"{OVERRELIANCE}.related_losses",
            *(f"{card}.loss_ids" for card in CITING_CARDS),
        }
        assert {r["outcome"] for r in repaired} == {"repaired"}

    def test_salvage_removes_the_failing_obligation_entry(self, tmp_path) -> None:
        _derive(tmp_path, [REPLACE])

        [salvage] = [r for r in _records(tmp_path) if r["kind"] == "salvage"]
        assert salvage["outcome"] == "removed"
        assert salvage["identity"].endswith("/O2")
        assert "rule_span" in salvage["reason"]

    def test_removing_the_reference_continues(self, tmp_path) -> None:
        analysis, _ = _derive(tmp_path, [REMOVE])

        assert _hazard(analysis, UNGROUNDED_ANSWER) == [
            FINANCIAL_HARM,
            REGULATORY_PENALTY,
        ]
        for card in CITING_CARDS:
            assert _disposition(analysis, card) == [FINANCIAL_HARM, REGULATORY_PENALTY]
        assert not any(DANGLING in hazard.related_losses for hazard in analysis.hazards)

    def test_a_rejected_repair_drops_the_unknown_entries_of_every_list(
        self, tmp_path
    ) -> None:
        outside = copy.deepcopy(REPLACE)
        outside["risk_dispositions"][0]["loss_ids"].append("L-99")

        analysis, _ = _derive(tmp_path, [outside])

        assert _hazard(analysis, UNGROUNDED_ANSWER) == [
            FINANCIAL_HARM,
            REGULATORY_PENALTY,
        ]
        for card in CITING_CARDS:
            assert _disposition(analysis, card) == [FINANCIAL_HARM, REGULATORY_PENALTY]
        dropped = {
            r["identity"]
            for r in _records(tmp_path)
            if r["kind"] == "reference_dropped"
        }
        assert dropped == {
            f"{UNGROUNDED_ANSWER}.related_losses",
            f"{OVERRELIANCE}.related_losses",
            *(f"{card}.loss_ids" for card in CITING_CARDS),
        }

    def test_removal_that_empties_a_hazard_stops_with_a_named_error(
        self, tmp_path
    ) -> None:
        reply = copy.deepcopy(RECORDED_REPLY)
        overreliance = next(
            h
            for h in reply["hazards"]
            if h["handle"] == "h_overreliance_no_human_option"
        )
        overreliance["related_losses"] = [DANGLING]
        emptied = copy.deepcopy(REMOVE)
        emptied["hazards"][1]["related_losses"] = []

        with pytest.raises(StageError) as stop:
            _derive(tmp_path, [emptied], reply=reply)

        assert stop.value.message.startswith("targeted repair failed")
        assert "hazards.1.related_losses" in stop.value.message
        assert stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
        ]
