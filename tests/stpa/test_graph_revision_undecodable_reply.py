"""An undecodable graph-revision reply gets the step's one correction.

GLM sometimes answers with a whitespace runaway: the reply starts as JSON, then
emits only blank lines and spaces until the completion cap. The Stage 1a
``hazard_graph_revision`` step has one correction, and an undecodable reply
used to end the step before it ran. The correction now carries the instruction
text, the exact decode error, and the prior reply without its trailing
whitespace. The step keeps its limit of two requests.

The recorded reply is the trimmed last row of a recorded MiniKlarna
call log: it stops decoding at character 2,291 and then runs only
whitespace.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    count_requests,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    REVISION_CORRECTION_FEEDBACK,
    _RevisionAttempt,
    _run_graph_revision_call,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.scripted_client import ScriptedClient

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "unit_loss"
_PRIOR = json.loads(
    (_FIXTURES / "g2-klarna-r2-graph-revision.json").read_text(encoding="utf-8")
)["prior_loss_analysis"]
_RUNAWAY = json.loads(
    (_FIXTURES / "p-r22-glm-whitespace-runaway-revision.json").read_text(
        encoding="utf-8"
    )
)["reply"]
_VALID = {
    "hazard_edits": [],
    "hazard_additions": [],
    "security_constraint_edits": [],
    "security_constraint_additions": [],
}
# A schema failure: the decoded body is not a revision patch.
_SCHEMA_FAILURE = {"hazard_edits": "none"}
_DECODE_ERROR = "JSONDecodeError at line 45, column 4: Expecting ',' delimiter"
_INSTRUCTION = (
    "Correction request: the prior graph revision response did not decode as JSON"
)
_PRIOR_LABEL = "Prior structured response to correct in place:"
_ERROR_LABEL = "Exact validation error from the prior response:"


def _call(
    tmp_path: Path,
    replies: list,
    *,
    attempts: list[_RevisionAttempt] | None = None,
    drop_defective_records: bool = False,
):
    client = ScriptedClient(replies)
    revised = _run_graph_revision_call(
        llm_client=client,
        loss_analysis=LossAnalysis.model_validate(_PRIOR),
        use_case_text="A Klarna customer-service assistant.",
        failing_checks=["hazard H-1 has no constraint"],
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
        attempts_out=[] if attempts is None else attempts,
        drop_defective_records=drop_defective_records,
    )
    return revised, client


class TestRunawayThenValidReply:
    def test_the_revision_succeeds_after_exactly_two_requests(self, tmp_path) -> None:
        with count_requests() as tally:
            revised, client = _call(tmp_path, [_RUNAWAY, _VALID])

        assert revised.hazards == LossAnalysis.model_validate(_PRIOR).hazards
        assert len(client.calls) == 2
        assert tally.requests == 2

    def test_the_correction_carries_instruction_error_and_stripped_reply(
        self, tmp_path
    ) -> None:
        _, client = _call(tmp_path, [_RUNAWAY, _VALID])

        first, correction = client.prompts
        assert correction.startswith(first)
        suffix = correction[len(first) :]
        stripped = _RUNAWAY.rstrip()
        assert len(stripped) == 2291
        assert suffix.startswith("\n\n" + _INSTRUCTION)
        assert f"{_PRIOR_LABEL}\n```json\n{stripped}\n```\n\n{_ERROR_LABEL}\n" in suffix
        assert _RUNAWAY not in correction
        assert (
            suffix.index(_INSTRUCTION)
            < suffix.index(_PRIOR_LABEL)
            < suffix.index(_ERROR_LABEL + "\n" + _DECODE_ERROR)
        )
        assert suffix.endswith(
            "Return one JSON object matching the response schema already supplied."
        )

    def test_the_instruction_text_is_kept_apart_from_the_decode_error(
        self, tmp_path
    ) -> None:
        _, client = _call(tmp_path, [_RUNAWAY, _VALID])

        correction = client.prompts[1]
        instruction = correction[
            correction.index(_INSTRUCTION) : correction.index(_PRIOR_LABEL)
        ]
        assert "JSONDecodeError" not in instruction
        assert "line 45" not in instruction

    def test_the_call_log_records_both_attempts_and_links_the_correction(
        self, tmp_path
    ) -> None:
        _call(tmp_path, [_RUNAWAY, _VALID])

        entries = read_calls_jsonl(tmp_path)
        assert [e["step"] for e in entries] == ["hazard_graph_revision"] * 2
        assert [e["success"] for e in entries] == [False, True]
        assert [e["attempt_number"] for e in entries] == [1, 2]
        assert entries[1]["retry_of"] == entries[0]["attempt_id"]
        assert entries[0]["failure_class"] == "answered_malformed"
        assert "line 45 column 4 (char 2291)" in entries[0]["error"]

    def test_the_attempt_record_marks_the_undecodable_reply_failed(
        self, tmp_path
    ) -> None:
        attempts: list[_RevisionAttempt] = []

        _call(tmp_path, [_RUNAWAY, _VALID], attempts=attempts)

        assert [attempt.failed for attempt in attempts] == [True, False]


class TestBothRepliesUndecodable:
    @pytest.mark.parametrize("drop_defective_records", [False, True])
    def test_the_step_ends_after_two_requests_and_names_the_correction(
        self, tmp_path, drop_defective_records
    ) -> None:
        replies = [_RUNAWAY, _RUNAWAY, _VALID]
        with count_requests() as tally, pytest.raises(StageError) as raised:
            _call(tmp_path, replies, drop_defective_records=drop_defective_records)

        message = str(raised.value)
        assert tally.requests == 2
        assert "graph revision call failed after one correction request" in message
        assert "undecodable" in message
        assert "JSONDecodeError" in message
        assert [e["success"] for e in read_calls_jsonl(tmp_path)] == [False, False]

    def test_a_corrected_reply_that_fails_validation_also_ends_the_step(
        self, tmp_path
    ) -> None:
        with count_requests() as tally, pytest.raises(StageError) as raised:
            _call(tmp_path, [_RUNAWAY, _SCHEMA_FAILURE, _VALID])

        assert tally.requests == 2
        assert "after one correction request" in str(raised.value)
        assert "ValidationError" in str(raised.value)


# SHA-256 of the first request's keyword arguments as the current revision
# prompt sends them for ``_call``'s inputs; a valid first reply sends exactly
# this.
_FIRST_REQUEST_DIGEST = (
    "7f95b8e0f4dbb07d6273bbcfdf07ae4d362ed83674559f881a896ea2784c1e6b"
)


def _request_digest(call: dict) -> str:
    shape = {
        key: value.__name__ if isinstance(value, type) else value
        for key, value in call.items()
    }
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True, default=repr).encode("utf-8")
    ).hexdigest()


class TestValidFirstReply:
    def test_one_request_goes_out_and_its_bytes_match_the_start_commit(
        self, tmp_path
    ) -> None:
        with count_requests() as tally:
            _, client = _call(tmp_path, [_VALID, _VALID])

        assert tally.requests == 1
        assert len(client.calls) == 1
        assert _request_digest(client.calls[0]) == _FIRST_REQUEST_DIGEST


class TestFirstReplyFailingValidation:
    def test_it_keeps_the_existing_correction_unchanged(self, tmp_path) -> None:
        reply = json.dumps(_SCHEMA_FAILURE) + "\n\n\n   "

        _, client = _call(tmp_path, [reply, _VALID])

        first, correction = client.prompts
        assert len(client.calls) == 2
        assert correction.startswith(
            first
            + REVISION_CORRECTION_FEEDBACK
            + f"\n\n{_PRIOR_LABEL}\n```json\n{reply}\n```"
            + f"\n\n{_ERROR_LABEL}\nValidationError:\n"
        )
        assert correction.endswith(
            "\n\nReturn one JSON object matching the response schema already supplied."
        )
        assert _INSTRUCTION not in correction

    def test_a_second_failure_keeps_the_existing_error_text(self, tmp_path) -> None:
        with pytest.raises(StageError) as raised:
            _call(tmp_path, [_SCHEMA_FAILURE, _SCHEMA_FAILURE])

        assert str(raised.value).startswith(
            "stage_1a/hazard_graph_revision: graph revision call failed: "
            "ValidationError"
        )
