"""Call 3 rejects a coordination description that names an ID that does not exist.

The fixture is coordination link CL-7 from a recorded OcciAI run: its
description names "PM-3" and "PM-4", which the prompt-reference check reads
as references, and every synthesis routing prompt failed that check.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    count_requests,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.control_structure import (
    _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK,
    PROMPTS_DIR,
    _call_3_coordination,
    _validate_semantic_review_response,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_control_structure_semantic_review import (
    response_payload,
    review_payload,
)

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "unit_loss"
        / "miniocciai-1-call3-short-pm-ids.json"
    ).read_text(encoding="utf-8")
)
_LOSSES = LossAnalysis.model_validate(_FIXTURE["loss_analysis"])
_STRUCTURE = ControlStructure.model_validate(_FIXTURE["control_structure"])
_LINK = _FIXTURE["coordination_link"]
_EXACT = (
    "Order-dependent actions on the same draft resource: a draft must exist "
    "and carry REVIEWED status before commit; exchanging draft existence and "
    "status prevents committing unreviewed drafts (SC-8) and resolves the "
    "shared draft state between PM-3-2 and PM-4-3."
)
_ERROR_LABEL = "Exact validation error from the prior response:"
_NOT_EXACT = (
    "which is not an exact ID in the supplied control structure or loss analysis"
)


def _reply(description: str = _LINK["description"], mechanism: str | None = None):
    link = deepcopy(_LINK)
    link["description"] = description
    if mechanism is not None:
        link["coordination_mechanism"]["description"] = mechanism
    payload = response_payload(review_payload(_LOSSES, _STRUCTURE))
    payload["coordination_links"] = [link]
    return payload


def _call(tmp_path: Path, replies: list):
    client = MockLLMClient()
    client.set_response_queue(replies)
    result = _call_3_coordination(
        llm_client=client,
        use_case_text="Clinicians review EHR drafts before the assistant commits them.",
        control_structure=_STRUCTURE,
        loss_analysis=_LOSSES,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    return result, client


def _error_text(client: MockLLMClient) -> str:
    correction = client.calls[1].user_prompt
    return correction[correction.index(_ERROR_LABEL) :]


class TestShortenedIdsThenExactIds:
    def test_a_valid_correction_passes_after_exactly_two_requests(
        self, tmp_path
    ) -> None:
        with count_requests() as tally:
            result, client = _call(tmp_path, [_reply(), _reply(_EXACT)])

        assert tally.requests == 2
        assert len(client.calls) == 2
        assert [link.description for link in result.coordination_links] == [_EXACT]

    def test_the_correction_names_both_tokens_and_the_one_probable_id(
        self, tmp_path
    ) -> None:
        _, client = _call(tmp_path, [_reply(), _reply(_EXACT)])

        first, correction = (call.user_prompt for call in client.calls)
        assert correction.startswith(first + _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK)
        error = _error_text(client)
        assert "coordination link CL-7 description names 'PM-3', " + _NOT_EXACT in error
        assert "coordination link CL-7 description names 'PM-4', " + _NOT_EXACT in error
        # Only PM-4-3 starts with PM-4; PM-3-1 and PM-3-2 both start with PM-3.
        assert "'PM-4', " + _NOT_EXACT + "; it probably means 'PM-4-3'" in error
        assert "'PM-3', " + _NOT_EXACT + "; it probably means" not in error
        assert "'SC-8'" not in error


def test_a_description_naming_exact_ids_passes_with_one_request(tmp_path) -> None:
    with count_requests() as tally:
        result, client = _call(tmp_path, [_reply(_EXACT)])

    assert tally.requests == 1
    assert len(client.calls) == 1
    assert result.coordination_links[0].description == _EXACT


def test_a_description_naming_ids_the_reply_adds_passes() -> None:
    _validate_semantic_review_response(
        _reply(_EXACT + " See CL-7 and CM-7."), _STRUCTURE, _LOSSES
    )


class TestTokenMatchingNoRealId:
    def test_the_mechanism_description_is_checked_and_offers_no_guess(self) -> None:
        reply = _reply(_EXACT, mechanism="RESP-3 sends PM-9 to RESP-4.")

        with pytest.raises(ValueError) as caught:
            _validate_semantic_review_response(reply, _STRUCTURE, _LOSSES)

        message = str(caught.value)
        assert (
            "coordination link CL-7 coordination_mechanism description names "
            "'PM-9', " + _NOT_EXACT + "." in message
        )
        assert "probably means" not in message

    def test_it_still_fails_after_the_correction(self, tmp_path) -> None:
        bad = _reply(_EXACT.replace("PM-4-3", "PM-9-9"))

        with count_requests() as tally, pytest.raises(StageError) as raised:
            _call(tmp_path, [bad, bad, _reply(_EXACT)])

        assert tally.requests == 2
        assert "'PM-9-9', " + _NOT_EXACT in str(raised.value)
