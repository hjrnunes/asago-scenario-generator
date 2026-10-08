"""A failed Stage 1a response body decodes one way on every repair path.

The first attempt decodes a body leniently (one outer Markdown fence, trailing
commas).  The repair that follows must read the same bodies, so a fenced body
that only failed the wire check is repaired instead of being reported as
"never decoded as JSON".
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysisDraft,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _missing_repair_input_reason,
    _prepare_current_provider_repair_input,
    _Stage1aRiskProviderDraft,
    _Stage1aRiskRepairDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    UnsupportedRepair,
    _salvage_first_response,
)
from tests.stpa.sp1_helpers import valid_risk_draft_dict

HANDLE_BODY: dict[str, Any] = {
    "risk_card_losses": [
        {
            "handle": "loss",
            "description": "Harm",
            "provenance": "risk_card",
            "source_risk_cards": ["R1"],
        }
    ],
    "use_case_losses": [],
    "hazards": [
        {"handle": "hazard", "description": "A state", "related_losses": ["loss"]}
    ],
    "security_constraints": [
        {
            "handle": "constraint",
            "rule": "Protect harm",
            "applies_when": [],
            "related_hazards": ["hazard"],
            "obligations": [],
        }
    ],
    "risk_dispositions": [
        {
            "risk_ref": "R1",
            "disposition": "cited",
            "loss_ids": ["loss"],
            "reason": "cited",
        }
    ],
}
DEFAULT_REASON = (
    "the failed response did not contain a valid current local-handle "
    "wire that can be adapted for the approved repair scope"
)
NEVER_DECODED = "the response body never decoded as JSON"


def _result(content: Any) -> LLMResult:
    return LLMResult(
        content=content, prompt_tokens=1, completion_tokens=1, duration_ms=1
    )


def _adapt(content: Any) -> Any:
    return _prepare_current_provider_repair_input(
        _result(content), response_format=_Stage1aRiskProviderDraft, prior=None
    )


def _plain() -> str:
    return json.dumps(HANDLE_BODY)


def _fenced() -> str:
    return f"```json\n{json.dumps(HANDLE_BODY, indent=1)}\n```"


def _trailing_comma() -> str:
    return json.dumps(HANDLE_BODY)[:-1] + ",}"


def _assert_adapted(adapted: Any) -> None:
    assert adapted is not None
    translated, repair_model = adapted
    assert repair_model is _Stage1aRiskRepairDraft
    assert translated.content["risk_card_losses"][0]["loss_id"] == "L-1"
    assert translated.content["risk_dispositions"][0]["loss_ids"] == ["L-1"]


def test_plain_json_text_is_adapted() -> None:
    _assert_adapted(_adapt(_plain()))


def test_dict_body_is_adapted_without_touching_the_callers_dict() -> None:
    body = copy.deepcopy(HANDLE_BODY)

    _assert_adapted(_adapt(body))

    assert body == HANDLE_BODY


def test_model_body_is_adapted() -> None:
    body = copy.deepcopy(HANDLE_BODY)
    del body["risk_dispositions"][0]["reason"]
    model = _Stage1aRiskProviderDraft.model_validate(body)

    _assert_adapted(_adapt(model))


@pytest.mark.parametrize("content", ["{broken", "[1, 2]", "7", "", 7, None])
def test_undecodable_or_non_object_bodies_are_not_adapted(content: Any) -> None:
    assert _adapt(content) is None


def test_reason_names_an_undecodable_text_body() -> None:
    assert _missing_repair_input_reason(None, _result("{broken")) == NEVER_DECODED


@pytest.mark.parametrize("content", ["[1, 2]", _plain(), {"hazards": []}, 7, None])
def test_reason_stays_the_default_for_a_body_that_decodes(content: Any) -> None:
    assert _missing_repair_input_reason(None, _result(content)) == DEFAULT_REASON


def test_reason_stays_the_default_without_a_result() -> None:
    assert _missing_repair_input_reason(None, None) == DEFAULT_REASON


def _salvage(content: Any) -> Any:
    return _salvage_first_response(
        _result(content),
        constraint_wire_model=SecurityConstraint,
        response_format=LossAnalysisDraft,
        gap_wire=False,
    )


def test_salvage_reads_cleanable_text_like_the_dict_it_encodes() -> None:
    body = valid_risk_draft_dict()
    expected = _salvage(body)

    assert not isinstance(expected, UnsupportedRepair)
    assert _salvage(json.dumps(body)) == expected
    assert _salvage(f"```json\n{json.dumps(body)}\n```") == expected
    assert _salvage(json.dumps(body)[:-1] + ",}") == expected


def test_salvage_reports_the_decoder_error_for_undecodable_text() -> None:
    outcome = _salvage("{broken")

    assert isinstance(outcome, UnsupportedRepair)
    assert outcome.reason == (
        f"{NEVER_DECODED} (Expecting property name enclosed in double quotes: "
        "line 1 column 2 (char 1))"
    )


def test_salvage_refuses_text_that_is_not_an_object() -> None:
    outcome = _salvage("[1]")

    assert isinstance(outcome, UnsupportedRepair)
    assert outcome.reason == (
        "the response body is not a JSON object, so no rows can be salvaged"
    )
