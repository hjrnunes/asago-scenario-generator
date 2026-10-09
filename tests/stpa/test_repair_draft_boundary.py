"""The repair draft classes add only requiredness to the domain draft.

A repaired Stage 1a draft is a canonical-ID ``LossAnalysisDraft``.  Every
shape rule a repaired draft can break (row limits, ``applies_when`` limit,
empty rule, obligation channels and spans, disposition shape) belongs to the
domain models, so the repair classes must reject exactly what the domain
draft rejects, with the domain's message.  What the repair classes add is the
closed key set and, on the risk wire, the required ``risk_dispositions``.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _prepare_current_provider_repair_input,
    _Stage1aGapProviderDraft,
    _Stage1aGapRepairDraft,
    _Stage1aRiskProviderDraft,
    _Stage1aRiskRepairDraft,
)

LOSS = {
    "loss_id": "L-1",
    "description": "A loss.",
    "provenance": "risk_card",
    "source_risk_cards": ["atlas-001"],
}
HAZARD = {"hazard_id": "H-1", "description": "A hazard.", "related_losses": ["L-1"]}
OBLIGATION = {
    "obligation_id": "O1",
    "kind": "required",
    "behavior": "confirm the owner",
    "rule_span": "owner",
    "realized_by": "tool_call",
}
CONSTRAINT = {
    "constraint_id": "SC-1",
    "rule": "Only the owner may change a booking.",
    "applies_when": [],
    "related_hazards": ["H-1"],
    "behavior_class": None,
    "obligations": [],
}
DISPOSITION = {"risk_ref": "atlas-001", "disposition": "cited", "loss_ids": ["L-1"]}
ID_KEYS = {"loss_id": "L-", "hazard_id": "H-", "constraint_id": "SC-"}


def _body() -> dict[str, Any]:
    return {
        "risk_card_losses": [copy.deepcopy(LOSS)],
        "use_case_losses": [],
        "hazards": [copy.deepcopy(HAZARD)],
        "security_constraints": [copy.deepcopy(CONSTRAINT)],
        "risk_dispositions": [copy.deepcopy(DISPOSITION)],
    }


def _rows(row: dict, key: str, count: int) -> list[dict]:
    return [
        {**copy.deepcopy(row), key: f"{ID_KEYS[key]}{n}"} for n in range(1, count + 1)
    ]


def _with_obligation(**fields: Any) -> dict[str, Any]:
    body = _body()
    body["security_constraints"][0]["obligations"] = [{**OBLIGATION, **fields}]
    return body


def _with_constraint(**fields: Any) -> dict[str, Any]:
    body = _body()
    body["security_constraints"][0].update(fields)
    return body


def _with_disposition(**fields: Any) -> dict[str, Any]:
    body = _body()
    body["risk_dispositions"][0].update(fields)
    return body


def _with(**collections: Any) -> dict[str, Any]:
    body = _body()
    body.update(collections)
    return body


DOMAIN_REJECTED: list[tuple[str, dict[str, Any], str]] = [
    (
        "17 risk-card losses",
        _with(risk_card_losses=_rows(LOSS, "loss_id", 17)),
        "at most 16 items",
    ),
    ("17 hazards", _with(hazards=_rows(HAZARD, "hazard_id", 17)), "at most 16 items"),
    (
        "17 constraints",
        _with(security_constraints=_rows(CONSTRAINT, "constraint_id", 17)),
        "at most 16 items",
    ),
    (
        "5 applies_when entries",
        _with_constraint(applies_when=["a", "b", "c", "d", "e"]),
        "at most 4 items",
    ),
    ("empty rule", _with_constraint(rule=""), "at least 1 character"),
    (
        "rule_span outside the rule",
        _with_obligation(rule_span="zebra"),
        "rule_span must be a contiguous substring of the constraint",
    ),
    (
        "required entry with violated_via",
        _with_obligation(violated_via="reply"),
        "is required but carries violated_via",
    ),
    (
        "forbidden entry with realized_by",
        _with_obligation(kind="forbidden"),
        "is forbidden but carries realized_by",
    ),
    (
        "proxy observation without a source outcome",
        _with_obligation(kind="forbidden", realized_by=None, observation_role="proxy"),
        "must name its source_outcome",
    ),
    (
        "cited disposition without loss_ids",
        _with_disposition(loss_ids=[]),
        "is cited but names no loss_ids",
    ),
    (
        "cited disposition with a reason",
        _with_disposition(reason="why"),
        "is cited but also carries a reason",
    ),
    (
        "not_applicable disposition without a reason",
        _with_disposition(disposition="not_applicable", loss_ids=[]),
        "requires a non-empty reason",
    ),
]

REPAIR_CLASSES = [_Stage1aGapRepairDraft, _Stage1aRiskRepairDraft]


@pytest.mark.parametrize(("name", "body", "message"), DOMAIN_REJECTED)
@pytest.mark.parametrize("repair_class", REPAIR_CLASSES)
def test_a_shape_defect_is_rejected_by_the_domain_draft_with_its_message(
    name: str, body: dict[str, Any], message: str, repair_class: type
) -> None:
    with pytest.raises(ValidationError) as domain:
        LossAnalysisDraft.model_validate(copy.deepcopy(body))
    with pytest.raises(ValidationError) as repair:
        repair_class.model_validate(copy.deepcopy(body))

    assert message in domain.value.errors()[0]["msg"]
    assert repair.value.errors()[0]["msg"] == domain.value.errors()[0]["msg"]


@pytest.mark.parametrize("repair_class", REPAIR_CLASSES)
def test_a_clean_draft_is_accepted(repair_class: type) -> None:
    assert repair_class.model_validate(_body()).hazards[0].hazard_id == "H-1"


@pytest.mark.parametrize("repair_class", REPAIR_CLASSES)
def test_a_key_outside_the_draft_is_rejected(repair_class: type) -> None:
    body = _with(bogus=[])

    LossAnalysisDraft.model_validate(copy.deepcopy(body))
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        repair_class.model_validate(body)


def test_the_risk_class_requires_risk_dispositions() -> None:
    body = _body()
    del body["risk_dispositions"]

    LossAnalysisDraft.model_validate(copy.deepcopy(body))
    with pytest.raises(ValidationError, match="risk_dispositions"):
        _Stage1aRiskRepairDraft.model_validate(body)


def test_the_gap_class_does_not_require_risk_dispositions() -> None:
    body = _body()
    del body["risk_dispositions"]

    assert _Stage1aGapRepairDraft.model_validate(body).risk_dispositions == []


def test_the_gap_class_carries_disposition_rows_without_judging_accounting() -> None:
    body = _with_disposition(loss_ids=["L-9"])

    draft = _Stage1aGapRepairDraft.model_validate(body)

    assert draft.risk_dispositions[0].loss_ids == ["L-9"]


@pytest.mark.parametrize("repair_class", REPAIR_CLASSES)
def test_unresolved_references_are_left_to_the_stage_validators(
    repair_class: type,
) -> None:
    body = _body()
    body["hazards"][0]["related_losses"] = ["L-9"]
    body["security_constraints"][0]["related_hazards"] = ["H-9"]
    body["risk_dispositions"][0]["loss_ids"] = ["L-9"]

    draft = repair_class.model_validate(body)

    assert draft.hazards[0].related_losses == ["L-9"]


@pytest.mark.parametrize("repair_class", REPAIR_CLASSES)
def test_the_declared_behavior_class_survives_the_repair_class(
    repair_class: type,
) -> None:
    body = _with_constraint(behavior_class="manipulation")

    draft = repair_class.model_validate(body)

    assert draft.security_constraints[0].behavior_class == "manipulation"


def _handle_wire() -> dict[str, Any]:
    return {
        "risk_card_losses": [
            {
                "handle": "loss",
                "description": "Harm",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {"handle": "hazard", "description": "A state", "related_losses": ["loss"]}
        ],
        "security_constraints": [
            {
                "handle": "constraint",
                "rule": "Only the owner may change a booking.",
                "applies_when": [],
                "behavior_class": None,
                "related_hazards": ["hazard"],
                "obligations": [],
            }
        ],
    }


def _adapt(wire: dict[str, Any], response_format: type) -> Any:
    return _prepare_current_provider_repair_input(
        LLMResult(content=wire, prompt_tokens=1, completion_tokens=1, duration_ms=1),
        response_format=response_format,
        prior=None,
    )


@pytest.mark.parametrize("collection", ["hazards", "security_constraints"])
def test_a_repeated_local_handle_never_reaches_a_repair_class(
    collection: str,
) -> None:
    # Repair input is the failed first response's own handles mapped to
    # allocated canonical IDs, and no repair adds or renames a row, so the
    # canonical IDs a repair class sees are distinct.  A repeated handle
    # stops at the wire check before any repair is planned.
    wire = _handle_wire()
    wire[collection].append(copy.deepcopy(wire[collection][0]))

    assert _adapt(wire, _Stage1aGapProviderDraft) is None
    wire["risk_dispositions"] = []
    assert _adapt(wire, _Stage1aRiskProviderDraft) is None


def test_distinct_local_handles_map_to_distinct_canonical_ids() -> None:
    wire = _handle_wire()
    second = copy.deepcopy(wire["hazards"][0])
    second["handle"] = "hazard_two"
    wire["hazards"].append(second)
    wire["risk_dispositions"] = []

    adapted = _adapt(wire, _Stage1aRiskProviderDraft)

    assert adapted is not None
    translated, repair_model = adapted
    ids = [row["hazard_id"] for row in translated.content["hazards"]]
    assert len(set(ids)) == 2
    repair_model.model_validate(translated.content)
