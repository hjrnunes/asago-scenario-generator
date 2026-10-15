"""A failed Stage 1a reply reaches repair in its own handles and compiles once.

The repair input keeps every handle the reply chose; the allocation that names
a first reply's records names the repair input's records too.  Salvage reads
the reply in handles and names what it reports by canonical ID.
"""

from __future__ import annotations

import copy
from typing import Any

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _handle_repair_input,
    _ProviderSecurityConstraint,
    _Stage1aGapProviderDraft,
    _Stage1aGapRepairDraft,
    _Stage1aRiskProviderDraft,
    _Stage1aRiskRepairDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    salvage_provider_response,
)
from asago_scenario_generator.stpa.system_model.repair_ids import IdSpace


def _loss(handle: str) -> dict[str, Any]:
    return {
        "handle": handle,
        "description": f"Harm {handle}",
        "provenance": "risk_card",
        "source_risk_cards": ["R1"],
    }


def _obligation(**fields: Any) -> dict[str, Any]:
    return {
        "obligation_id": "O1",
        "kind": "forbidden",
        "behavior": "disclose the record",
        "rule_span": "Protect harm",
        "violated_via": "reply",
        **fields,
    }


BODY: dict[str, Any] = {
    "risk_card_losses": [_loss("loss_10"), _loss("loss_2")],
    "use_case_losses": [],
    "hazards": [
        {
            "handle": "hazard",
            "description": "A state",
            "related_losses": ["loss_2", "loss_10"],
        }
    ],
    "security_constraints": [
        {
            "handle": "constraint",
            "rule": "Protect harm",
            "applies_when": [],
            "related_hazards": ["hazard"],
            "obligations": [_obligation()],
        }
    ],
    "risk_dispositions": [
        {
            "risk_ref": "R1",
            "disposition": "cited",
            "loss_ids": ["loss_10"],
        }
    ],
}


def _result(content: Any) -> LLMResult:
    return LLMResult(
        content=content, prompt_tokens=1, completion_tokens=1, duration_ms=1
    )


def _risk_input(body: dict[str, Any]) -> Any:
    return _handle_repair_input(
        _result(body), response_format=_Stage1aRiskProviderDraft, prior=None
    )


def test_the_repair_input_keeps_every_handle_of_the_reply() -> None:
    repair_input = _risk_input(copy.deepcopy(BODY))

    assert repair_input is not None
    content = repair_input.result.content
    assert [row["loss_id"] for row in content["risk_card_losses"]] == [
        "loss_10",
        "loss_2",
    ]
    assert content["hazards"][0]["hazard_id"] == "hazard"
    assert content["hazards"][0]["related_losses"] == ["loss_2", "loss_10"]
    assert content["security_constraints"][0]["constraint_id"] == "constraint"
    assert content["security_constraints"][0]["related_hazards"] == ["hazard"]
    assert content["risk_dispositions"][0]["loss_ids"] == ["loss_10"]
    assert all("handle" not in row for row in content["risk_card_losses"])
    assert repair_input.response_format is _Stage1aRiskRepairDraft


def test_the_first_reply_allocation_names_the_repair_input() -> None:
    repair_input = _risk_input(copy.deepcopy(BODY))

    assert repair_input is not None
    assert repair_input.ids == IdSpace(
        losses={"loss_2": "L-1", "loss_10": "L-2"},
        hazards={"hazard": "H-1"},
        constraints={"constraint": "SC-1"},
    )


def test_the_repair_input_leaves_the_callers_body_alone() -> None:
    body = copy.deepcopy(BODY)

    _risk_input(body)

    assert body == BODY


def test_a_gap_reply_keeps_the_earlier_canonical_ids_it_cites() -> None:
    prior = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Harm",
                    "provenance": "risk_card",
                    "source_risk_cards": ["R1"],
                }
            ],
            "hazards": [
                {"hazard_id": "H-1", "description": "A", "related_losses": ["L-1"]}
            ],
        }
    )
    body = {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {"handle": "new_hazard", "description": "B", "related_losses": ["L-1"]}
        ],
        "security_constraints": [
            {
                "handle": "guard",
                "rule": "Guard the record",
                "applies_when": [],
                "related_hazards": ["H-1", "new_hazard"],
                "obligations": [],
            }
        ],
    }

    repair_input = _handle_repair_input(
        _result(body), response_format=_Stage1aGapProviderDraft, prior=prior
    )

    assert repair_input is not None
    assert repair_input.response_format is _Stage1aGapRepairDraft
    assert repair_input.ids.hazards == {"new_hazard": "H-2"}
    assert repair_input.ids.constraints == {"guard": "SC-1"}
    constraint = repair_input.result.content["security_constraints"][0]
    assert constraint["related_hazards"] == ["H-1", "new_hazard"]
    assert repair_input.result.content["risk_dispositions"] == []


def test_a_reply_without_local_handles_gets_no_repair_input() -> None:
    body = copy.deepcopy(BODY)
    for row in body["risk_card_losses"]:
        row["loss_id"] = row.pop("handle")

    assert _risk_input(body) is None


def test_the_compile_keeps_an_unknown_reference() -> None:
    ids = IdSpace(losses={"loss": "L-1"}, hazards={"hazard": "H-1"})
    draft = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "loss",
                    "description": "Harm",
                    "provenance": "risk_card",
                    "source_risk_cards": ["R1"],
                }
            ],
            "hazards": [
                {
                    "hazard_id": "hazard",
                    "description": "A",
                    "related_losses": ["loss", "missing", "L-9"],
                }
            ],
        }
    )

    compiled = ids.compile(draft)

    assert compiled.risk_card_losses[0].loss_id == "L-1"
    assert compiled.hazards[0].hazard_id == "H-1"
    assert compiled.hazards[0].related_losses == ["L-1", "missing", "L-9"]
    assert ids.to_handles(compiled) == draft


def test_salvage_reads_handles_and_names_its_findings_by_canonical_id() -> None:
    body = copy.deepcopy(BODY)
    body["security_constraints"][0]["obligations"] = [
        _obligation(violated_via=None, realized_by="reply")
    ]
    repair_input = _risk_input(body)
    assert repair_input is not None

    draft, report = salvage_provider_response(
        repair_input.result.content,
        constraint_wire_model=_ProviderSecurityConstraint,
        response_format=repair_input.response_format,
        ids=repair_input.ids,
    )

    assert [loss.loss_id for loss in draft.risk_card_losses] == ["L-2", "L-1"]
    assert draft.hazards[0].related_losses == ["L-1", "L-2"]
    assert draft.security_constraints[0].constraint_id == "SC-1"
    assert draft.security_constraints[0].related_hazards == ["H-1"]
    assert draft.risk_dispositions[0].loss_ids == ["L-2"]
    assert report.obligation_constraint_ids == ("SC-1",)
    assert report.warnings[0].startswith("salvaged constraint 'SC-1'")


def test_salvage_names_a_dropped_record_by_canonical_id() -> None:
    body = copy.deepcopy(BODY)
    repair_input = _risk_input(body)
    assert repair_input is not None
    content = copy.deepcopy(repair_input.result.content)
    del content["hazards"][0]["description"]

    _, report = salvage_provider_response(
        content,
        constraint_wire_model=_ProviderSecurityConstraint,
        response_format=repair_input.response_format,
        ids=repair_input.ids,
    )

    assert report.dropped_hazards[0].startswith("H-1: ")
