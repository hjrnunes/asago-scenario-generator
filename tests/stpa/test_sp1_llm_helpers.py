"""Tests for the shared LLM helpers: parsing, calls and logs.

Covers ``parse_llm_result``, ``call_with_policy`` (compatibility retry,
corrections, preflight, request counting), the call log, and the compact
validation-error text.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError, field_validator

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    RequestTally,
    StageError,
    _stringify_response_content,
    call_with_policy,
    compact_validation_error,
    correction_prompt,
    count_requests,
    log_llm_call,
    log_llm_call_failure,
    parse_llm_result,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.scripted_client import ScriptedClient


class _SampleModel(BaseModel):
    name: str
    value: int = 0


class _NestedModel(BaseModel):
    """Nested model with a validator that rejects one source ID."""

    item_id: str

    @field_validator("item_id")
    @classmethod
    def reject_malformed(cls, value: str) -> str:
        if value == "malformed":
            raise ValueError("malformed source ID")
        return value


class _OptionalDumpModel(BaseModel):
    """Model whose default is not None, so omit-None dumps change meaning."""

    name: str
    unused: str | None = "present"


def _result(content) -> LLMResult:
    return LLMResult(
        content=content, prompt_tokens=0, completion_tokens=0, duration_ms=0
    )


def _send(client, tmp_path: Path, response_format=_NestedModel, **extra):
    """Send one request through call_with_policy with the shared test labels."""
    extra.setdefault("policy", CorrectionPolicy())
    extra.setdefault("user_prompt", "user")
    extra.setdefault("stage", "stage_test")
    extra.setdefault("step", "step_test")
    return call_with_policy(
        llm_client=client,
        system_prompt="system",
        response_format=response_format,
        run_dir=tmp_path,
        **extra,
    )


class TestParseLlmResult:
    """parse_llm_result handles all content types."""

    def test_content_is_already_model_instance(self):
        """When content is already the target type, it is returned as-is."""
        model = _SampleModel(name="direct")
        assert parse_llm_result(_result(model), _SampleModel) is model

    def test_content_is_dict(self):
        """When content is a dict, it is validated into the model."""
        parsed = parse_llm_result(
            _result({"name": "from_dict", "value": 42}), _SampleModel
        )
        assert parsed.name == "from_dict"
        assert parsed.value == 42

    def test_content_is_json_string(self):
        """When content is a JSON string, it is parsed and validated."""
        parsed = parse_llm_result(
            _result(json.dumps({"name": "from_string"})), _SampleModel
        )
        assert parsed.name == "from_string"
        assert parsed.value == 0

    def test_content_is_exact_fenced_json_document(self):
        """OpenAI-compatible gateways may wrap an otherwise exact JSON body."""
        parsed = parse_llm_result(
            _result('```json\n{"name": "from_fence"}\n```'), _SampleModel
        )
        assert parsed.name == "from_fence"

    def test_fenced_json_with_trailing_prose_is_rejected(self):
        """Tolerance does not extract a JSON fragment from surrounding prose."""
        result = _result('```json\n{"name": "unsafe"}\n```\nextra prose')
        with pytest.raises(json.JSONDecodeError):
            parse_llm_result(result, _SampleModel)

    def test_content_is_unexpected_type_raises(self):
        """When content is an unexpected type, TypeError is raised."""
        with pytest.raises(TypeError, match="Unexpected LLM result content type"):
            parse_llm_result(_result(12345), _SampleModel)


class TestCallWithPolicyRequestShape:
    """allow_unvalidated shapes the request only; a client TypeError is not retried."""

    def test_json_object_mode_is_passed_and_still_validates(self, tmp_path):
        client = ScriptedClient([{"item_id": "malformed"}])

        outcome = _send(client, tmp_path, allow_unvalidated=True)

        assert client.calls[0]["allow_unvalidated"] is True
        assert outcome.value is None
        assert "malformed source ID" in outcome.error

    def test_max_completion_tokens_is_forwarded(self, tmp_path):
        client = ScriptedClient([{"name": "ok", "unused": None}])

        outcome = _send(
            client,
            tmp_path,
            _OptionalDumpModel,
            max_completion_tokens=10,
            allow_unvalidated=True,
        )

        assert outcome.error is None
        assert outcome.value.name == "ok"
        assert client.calls[0]["max_completion_tokens"] == 10
        assert client.calls[0]["allow_unvalidated"] is True

    def test_default_validates_against_the_response_model(self, tmp_path):
        outcome = _send(ScriptedClient([{"item_id": "malformed"}]), tmp_path)

        assert outcome.value is None
        assert outcome.error is not None
        assert "malformed source ID" in outcome.error

    @pytest.mark.parametrize("allow_unvalidated", [True, False])
    @pytest.mark.parametrize(
        "error",
        [
            "unexpected keyword argument 'allow_unvalidated'",
            "unexpected keyword argument 'response_format'",
            "response_format is the wrong type",
        ],
    )
    def test_a_client_type_error_is_not_retried(
        self, tmp_path, error, allow_unvalidated
    ):
        client = ScriptedClient([TypeError(error), {"item_id": "valid"}])

        outcome = _send(client, tmp_path, allow_unvalidated=allow_unvalidated)

        assert len(client.calls) == 1
        assert outcome.value is None
        assert outcome.error == f"TypeError: {error}"
        [entry] = read_calls_jsonl(tmp_path)
        assert "compatibility_fallback" not in entry.get("request_controls", {})


class TestCallWithPolicyLogging:
    """The call log keeps usage, lifecycle flags and request identity."""

    def test_usage_is_kept_when_response_parsing_fails(self, tmp_path):
        client = ScriptedClient(
            [
                LLMResult(
                    content={"item_id": "malformed"},
                    prompt_tokens=17,
                    completion_tokens=4,
                    duration_ms=230,
                )
            ]
        )

        outcome = _send(client, tmp_path)

        assert outcome.value is None
        assert outcome.result is not None
        assert outcome.error is not None
        entry = read_calls_jsonl(tmp_path)[0]
        assert entry["prompt_tokens"] == 17
        assert entry["completion_tokens"] == 4
        assert entry["duration_ms"] == 230
        assert entry["provider_response_received"] is True
        assert entry["draft_parsed"] is False
        assert entry["semantic_validation_passed"] is False
        assert entry["compiled"] is False
        assert entry["published"] is False
        assert entry["terminal_error_codes"] == ["provider_contract_failure"]

    def test_semantic_validation_failure_is_not_a_call_failure(self, tmp_path):
        """A parsed response that fails a stage rule is a semantic failure."""

        def reject(model: _OptionalDumpModel) -> None:
            raise ValueError("stage rule rejected the row")

        outcome = _send(
            ScriptedClient([{"name": "ok", "unused": None}]),
            tmp_path,
            _OptionalDumpModel,
            result_validator=reject,
        )

        assert outcome.value is None
        assert outcome.result is not None
        assert outcome.error is not None
        entry = read_calls_jsonl(tmp_path)[0]
        assert entry["provider_response_received"] is True
        assert entry["draft_parsed"] is True
        assert entry["semantic_validation_passed"] is False
        assert entry["terminal_error_codes"] == ["provider_semantic_validation_failure"]

    def test_a_validator_may_publish_a_corrected_model(self, tmp_path):
        """The model a validator returns is logged and returned, not the parsed one."""
        corrected = _OptionalDumpModel(name="corrected")

        outcome = _send(
            ScriptedClient([{"name": "ok", "unused": None}]),
            tmp_path,
            _OptionalDumpModel,
            result_validator=lambda model: corrected,
        )

        assert outcome.error is None
        assert outcome.value is corrected
        logged = "".join(
            path.read_text() for path in tmp_path.rglob("*") if path.is_file()
        )
        assert '"corrected"' in logged

    def test_failed_response_and_request_identity_are_preserved(self, tmp_path):
        outcome = _send(
            ScriptedClient([{"item_id": "malformed"}]),
            tmp_path,
            stage="stage_5",
            step="scenario_context",
            slot_id="RESP-1:CA-1-1:INCORRECT",
            scenario_id="SCN-007",
        )

        assert outcome.value is None
        assert outcome.result is not None
        assert outcome.error is not None
        entry = read_calls_jsonl(tmp_path)[0]
        assert entry["response_content"] == '{"item_id": "malformed"}'
        assert entry["slot_id"] == "RESP-1:CA-1-1:INCORRECT"
        assert entry["scenario_id"] == "SCN-007"


class TestLogLlmCall:
    """log_llm_call writes a call-log entry to calls.jsonl."""

    def test_entry_written_with_stage_and_step(self, tmp_path: Path):
        """A call-log entry is appended with the given stage and step."""
        result = LLMResult(
            content=None,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt="sys",
            user_prompt="usr",
        )
        log_llm_call(result, "test-model", tmp_path, "stage_test", "step_test")

        entries = read_calls_jsonl(tmp_path)
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_test"
        assert entries[0]["step"] == "step_test"
        assert entries[0]["model"] == "test-model"
        assert entries[0]["prompt_tokens"] == 100
        assert entries[0]["completion_tokens"] == 50
        assert entries[0]["success"] is True

    def test_none_content_logs_as_empty_string(self, tmp_path: Path):
        """Kill: content is None -> is not None in _stringify_response_content."""
        assert _stringify_response_content(None) == ""
        log_llm_call(_result(None), "test-model", tmp_path, "stage_test", "step_test")
        assert read_calls_jsonl(tmp_path)[0]["response_content"] == ""

    def test_dict_and_other_content_are_stringified(self):
        assert _stringify_response_content({"name": "ok"}) == '{"name": "ok"}'
        assert _stringify_response_content(12) == "12"

    def test_failure_log_defaults_are_unavailable(self, tmp_path: Path):
        log_llm_call_failure("test-model", tmp_path, "stage_test", "step_test", "boom")
        entry = read_calls_jsonl(tmp_path)[0]
        assert entry["success"] is False
        assert entry["prompt_tokens"] is None
        assert entry["completion_tokens"] is None
        assert entry["usage"]["status"] == "unavailable"
        assert entry["duration_ms"] == 0
        assert entry["error"] == "boom"


def _validation_error() -> ValidationError:
    try:
        _SampleModel.model_validate({"value": "x"})
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a validation error")


class _ParentModel(BaseModel):
    child: _SampleModel


def _model_type_error() -> ValidationError:
    try:
        _ParentModel.model_validate({"child": "not an object"})
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a validation error")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            _validation_error(),
            "ValidationError:\n- name: Field required (missing)\n"
            "- value: Input should be a valid integer, unable to parse string as an"
            " integer (int_parsing)",
        ),
        (
            _model_type_error(),
            "ValidationError:\n- child: Input should be an object (model_type)",
        ),
        (
            json.JSONDecodeError("Expecting value", "{x", 1),
            "JSONDecodeError at line 1, column 2: Expecting value",
        ),
        (
            ExactFeedbackError("first   item\n" + "y" * 4000),
            "ValueError: first item\n" + "y" * 3986 + "...",
        ),
        (ExactFeedbackError("one\n two  words"), "ValueError: one\ntwo words"),
        (RuntimeError("z" * 801), "RuntimeError: " + "z" * 797 + "..."),
        (RuntimeError("a\n  b"), "RuntimeError: a b"),
    ],
    ids=[
        "validation",
        "model-type",
        "json",
        "exact-long",
        "exact",
        "generic-long",
        "generic",
    ],
)
def test_compact_validation_error_describes_each_error_kind(
    error: Exception, expected: str
) -> None:
    assert compact_validation_error(error) == expected


class TestStageErrorAndCorrectionPrompt:
    def test_stage_error_keeps_stage_and_step(self) -> None:
        error = StageError(stage="stage_2", step="call_1", message="offline")

        assert error.stage == "stage_2"
        assert error.step == "call_1"
        assert str(error) == "stage_2/call_1: offline"

    def test_retry_prompt_reports_fields_without_echoing_invalid_input(self) -> None:
        with pytest.raises(ValidationError) as captured:
            _NestedModel.model_validate({"item_id": "malformed"})

        prompt = correction_prompt(
            original_prompt="original",
            feedback="Correct the named field.",
            error=captured.value,
            response_format=_NestedModel,
            include_schema=False,
        )

        assert "item_id" in prompt
        assert "malformed source ID" in prompt
        assert "input_value" not in prompt
        assert '"malformed"' not in prompt
        assert "Expected response schema" not in prompt
        assert "response schema already supplied" in prompt


class TestCallWithPolicy:
    """The policy decides each extra request; the outcome counts dispatches."""

    def test_a_validation_failure_earns_one_correction(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "malformed"}, {"item_id": "ok"}])
        policy = CorrectionPolicy(
            validation_retries=1, feedback=" Fix it.", include_schema=False
        )

        outcome = _send(client, tmp_path, policy=policy, user_prompt="Return JSON.")

        assert outcome.value == _NestedModel(item_id="ok")
        assert outcome.error is None
        assert outcome.calls == 2
        assert client.prompts[1].startswith("Return JSON. Fix it.")
        assert "malformed source ID" in client.prompts[1]
        assert "Expected response schema" not in client.prompts[1]

    def test_an_error_note_follows_the_field_lines_of_the_correction(
        self, tmp_path
    ) -> None:
        client = ScriptedClient([{"item_id": "malformed"}, {"item_id": "ok"}])
        policy = CorrectionPolicy(
            validation_retries=1,
            include_schema=False,
            error_note=lambda error: f"Note for {type(error).__name__}.",
        )

        _send(client, tmp_path, policy=policy)

        tail = client.prompts[1].split(
            "Exact validation error from the prior response:\n"
        )[1]
        assert tail.index("- item_id:") < tail.index("Note for ValidationError.")
        assert tail.index("Note for ValidationError.") < tail.index(
            "Return one JSON object"
        )

    def test_a_correction_without_an_error_note_adds_nothing(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "malformed"}, {"item_id": "ok"}])
        policy = CorrectionPolicy(validation_retries=1, include_schema=False)

        _send(client, tmp_path, policy=policy)

        assert client.prompts[1].endswith(
            "(value_error)\n\nReturn one JSON object matching the response schema "
            "already supplied."
        )

    def test_undecodable_bodies_repeat_the_prompt_until_exhausted(
        self, tmp_path
    ) -> None:
        client = ScriptedClient(["{not json", "{not json", "{not json"])

        outcome = _send(
            client,
            tmp_path,
            policy=CorrectionPolicy(json_retries=2),
            user_prompt="Return JSON.",
        )

        assert outcome.value is None
        assert outcome.error.startswith("JSONDecodeError")
        assert outcome.calls == 3
        assert client.prompts == ["Return JSON."] * 3

    def test_a_transport_failure_ends_the_call(self, tmp_path) -> None:
        client = ScriptedClient([RuntimeError("offline"), {"item_id": "ok"}])

        outcome = _send(
            client,
            tmp_path,
            policy=CorrectionPolicy(json_retries=1, validation_retries=1),
            user_prompt="Return JSON.",
        )

        assert outcome.error == "RuntimeError: offline"
        assert outcome.calls == 1

    def test_a_prompt_blocked_by_preflight_dispatches_nothing(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "ok"}], context_window=32768)

        outcome = _send(
            client,
            tmp_path,
            policy=CorrectionPolicy(validation_retries=1),
            user_prompt="Neutralized use-case sentence. " * 4200,
        )

        assert outcome.value is None
        assert outcome.calls == 0
        assert client.prompts == []

    def test_negative_retry_counts_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="retry counts must be non-negative"):
            CorrectionPolicy(validation_retries=-1)


class _UsageClient:
    """Serves scripted contents, each reporting the same stable usage."""

    model = "usage-model"

    def __init__(self, *contents) -> None:
        self.contents = list(contents)
        self.prompts: list[str] = []

    def complete(self, **kwargs):
        self.prompts.append(kwargs["user_prompt"])
        return LLMResult(
            content=self.contents.pop(0),
            prompt_tokens=17,
            completion_tokens=4,
            duration_ms=230,
        )


class _ValueModel(BaseModel):
    value: str


class TestRetryAttemptLog:
    """LLM-HELPER-FAILURE-DEFENSES-03, 05, 06, 09, 11: every attempt is logged."""

    def _call(self, client, tmp_path: Path, policy, **extra):
        return call_with_policy(
            llm_client=client,
            system_prompt="system",
            user_prompt="user",
            response_format=_ValueModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            policy=policy,
            **extra,
        )

    def test_json_object_mode_is_off_by_default(self) -> None:
        parameter = inspect.signature(call_with_policy).parameters["allow_unvalidated"]

        assert parameter.default is False

    def test_malformed_json_is_retried_once_and_both_attempts_are_logged(
        self, tmp_path: Path
    ) -> None:
        client = _UsageClient("not valid JSON", {"value": "recovered"})

        outcome = self._call(client, tmp_path, CorrectionPolicy(json_retries=1))

        assert outcome.error is None
        assert outcome.calls == 2
        entries = read_calls_jsonl(tmp_path)
        assert [entry["success"] for entry in entries] == [False, True]
        for entry in entries:
            assert entry["prompt_tokens"] == 17
            assert entry["completion_tokens"] == 4
            assert entry["duration_ms"] == 230

    def test_two_malformed_json_responses_log_two_failed_attempts(
        self, tmp_path: Path
    ) -> None:
        client = _UsageClient("not valid JSON", "still not JSON")

        outcome = self._call(client, tmp_path, CorrectionPolicy(json_retries=1))

        assert outcome.value is None
        assert outcome.error is not None
        assert outcome.calls == 2
        assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
            False,
            False,
        ]

    def test_schema_validation_retry_carries_feedback_and_logs_both_attempts(
        self, tmp_path: Path
    ) -> None:
        client = _UsageClient({"value": None}, {"value": "recovered"})
        policy = CorrectionPolicy(validation_retries=1, feedback="\n\ncorrective")

        outcome = self._call(client, tmp_path, policy)

        assert outcome.error is None
        assert outcome.calls == 2
        assert "corrective" not in client.prompts[0]
        assert "corrective" in client.prompts[1]
        assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
            False,
            True,
        ]

    def test_result_validator_rejection_is_retried_with_feedback(
        self, tmp_path: Path
    ) -> None:
        def reject_first(model: _ValueModel) -> None:
            if model.value == "reject":
                raise ValueError("result rejected")

        client = _UsageClient({"value": "reject"}, {"value": "recovered"})
        policy = CorrectionPolicy(validation_retries=1, feedback="\n\ncorrective")

        outcome = self._call(client, tmp_path, policy, result_validator=reject_first)

        assert outcome.error is None
        assert outcome.value == _ValueModel(value="recovered")
        assert outcome.calls == 2
        assert "corrective" not in client.prompts[0]
        assert "corrective" in client.prompts[1]
        assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
            False,
            True,
        ]


class TestCountRequests:
    """A tally counts the requests dispatched inside its scope, and no others."""

    def test_it_counts_every_request_of_a_corrected_call(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "malformed"}, {"item_id": "ok"}])

        with count_requests() as tally:
            _send(client, tmp_path, policy=CorrectionPolicy(validation_retries=1))

        assert tally.requests == 2

    def test_a_blocked_prompt_adds_nothing(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "ok"}], context_window=32768)

        with count_requests() as tally:
            _send(
                client, tmp_path, user_prompt="Neutralized use-case sentence. " * 4200
            )

        assert tally.requests == 0

    def test_requests_outside_the_scope_are_not_counted(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "ok"}, {"item_id": "ok"}])
        _send(client, tmp_path)

        with count_requests() as tally:
            _send(client, tmp_path)
        _send(ScriptedClient([{"item_id": "ok"}]), tmp_path)

        assert tally.requests == 1

    def test_the_tally_survives_an_error_raised_in_the_scope(self, tmp_path) -> None:
        client = ScriptedClient([RuntimeError("offline")])

        with pytest.raises(LookupError):
            with count_requests() as tally:
                _send(client, tmp_path)
                raise LookupError("later failure")

        assert tally.requests == 1

    def test_an_outer_scope_includes_its_inner_scopes(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "ok"}, {"item_id": "ok"}])

        with count_requests() as outer:
            with count_requests() as inner:
                _send(client, tmp_path)
            _send(client, tmp_path)

        assert (inner.requests, outer.requests) == (1, 2)

    def test_one_tally_accumulates_across_scopes(self, tmp_path) -> None:
        client = ScriptedClient([{"item_id": "ok"}, {"item_id": "ok"}])
        tally = RequestTally()

        with count_requests(tally):
            _send(client, tmp_path)
        with count_requests(tally):
            _send(client, tmp_path)

        assert tally.requests == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
        ('  ```JSON\n{"a": 1}\n[2]\n```  \n', '{"a": 1}\n[2]'),
        ('```\n{"a": 1}\n```', '{"a": 1}'),
        ('  {"a": 1}\n', '{"a": 1}'),
        ('```json\n{"a": 1}', '```json\n{"a": 1}'),
        ('```python\n{"a": 1}\n```', '```python\n{"a": 1}\n```'),
        ("```json\n```", "```json\n```"),
    ],
)
def test_strip_json_fence_returns_the_fenced_body_or_the_stripped_text(
    text: str, expected: str
) -> None:
    from asago_scenario_generator.stpa.infra.llm_helpers import strip_json_fence

    assert strip_json_fence(text) == expected
