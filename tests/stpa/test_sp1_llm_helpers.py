"""Tests for the shared LLM helpers: parsing, tolerant decoding, calls and logs.

Covers ``parse_llm_result``, the tolerant ``parse_llm_result_unvalidated`` path
used before ID normalization, ``call_with_policy`` (compatibility retry,
corrections, preflight, request counting), the call log, and the compact
validation-error text.
"""

from __future__ import annotations

import json
from enum import Enum
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
    parse_llm_result_unvalidated,
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


class _ContainerModel(BaseModel):
    """Container used to verify tolerant nested construction."""

    items: list[_NestedModel]


class _RequiredNestedContainer(BaseModel):
    """Container whose omitted nested model must not be fabricated."""

    nested: _NestedModel


class _Mode(str, Enum):
    READY = "ready"


class _CollectionModel(BaseModel):
    """Model covering collection, enum, and union tolerant decoding."""

    labels: set[str]
    checkpoints: tuple[str, ...]
    mode: _Mode
    note: str | None = None


class _MissingRequiredFieldsModel(BaseModel):
    """Model covering every scalar and collection missing-field sentinel."""

    text: str
    count: int
    ratio: float
    enabled: bool
    labels: list[str]
    checkpoints: tuple[str, ...]
    tags: set[str]
    metadata: dict[str, int]


class _RequiredUnionFieldsModel(BaseModel):
    """Model covering Optional and non-optional Union sentinels."""

    optional_text: str | None
    text_or_count: str | int


class _OptionalDumpModel(BaseModel):
    """Model whose default is not None, so omit-None dumps change meaning."""

    name: str
    unused: str | None = "present"


class _ConstructFilterModel(BaseModel):
    """Model used to verify unknown decoded fields are not constructed."""

    name: str
    optional: str | None = "default"


class _UnionItemModel(BaseModel):
    """Union field that should construct a nested model, not keep a dict."""

    item: _NestedModel | None = None


class _NoneFirstUnionModel(BaseModel):
    """Union with None first so the None-candidate branch is executed."""

    item: None | _NestedModel = None


class _LegacyClient:
    """Minimal client without the optional compatibility argument."""

    model = "legacy-model"

    def complete(
        self,
        *,
        system_prompt,
        user_prompt,
        response_format,
        temperature,
        max_completion_tokens=None,
    ):
        return LLMResult(
            content={"name": "legacy"},
            prompt_tokens=1,
            completion_tokens=2,
            duration_ms=3,
        )


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


class TestParseLlmResultUnvalidated:
    """The tolerant path defers validation and keeps the response attribute-safe."""

    def test_nested_invalid_source_id_is_preserved(self):
        """Tolerant decoding defers nested validation to post-processing."""
        result = _result({"items": [{"item_id": "malformed"}]})
        parsed = parse_llm_result_unvalidated(result, _ContainerModel)
        assert parsed.items[0].item_id == "malformed"

    def test_nested_missing_required_fields_are_filled(self):
        """Nested model construction also supplies required-field sentinels."""
        parsed = parse_llm_result_unvalidated(_result({"items": [{}]}), _ContainerModel)
        assert parsed.items[0].item_id == ""

    def test_collections_and_enums_are_constructed(self):
        """Tolerant decoding preserves supported nested annotation shapes."""
        result = _result(
            {
                "labels": ["one", "two"],
                "checkpoints": ["first", "second"],
                "mode": "ready",
                "note": "optional",
            }
        )

        parsed = parse_llm_result_unvalidated(result, _CollectionModel)

        assert parsed.labels == {"one", "two"}
        assert parsed.checkpoints == ("first", "second")
        assert parsed.mode is _Mode.READY
        assert parsed.note == "optional"

    def test_missing_required_fields_get_typed_sentinels(self):
        """Missing required fields remain attribute-safe with typed sentinels."""
        parsed = parse_llm_result_unvalidated(_result({}), _MissingRequiredFieldsModel)

        assert parsed.text == ""
        assert parsed.count == 0
        assert parsed.ratio == 0.0
        assert parsed.enabled is False
        assert parsed.labels == []
        assert parsed.checkpoints == ()
        assert parsed.tags == set()
        assert parsed.metadata == {}

    def test_missing_nested_models_are_not_fabricated(self):
        """Missing required nested models become None for later validation."""
        parsed = parse_llm_result_unvalidated(_result({}), _RequiredNestedContainer)

        assert parsed.nested is None
        with pytest.raises(ValidationError, match="nested"):
            _RequiredNestedContainer.model_validate(parsed.model_dump())

    def test_union_sentinels(self):
        """Optional unions use None and other unions use their first member."""
        parsed = parse_llm_result_unvalidated(_result({}), _RequiredUnionFieldsModel)

        assert parsed.optional_text is None
        assert parsed.text_or_count == ""

    def test_json_and_model_content_are_accepted(self):
        """Tolerant decoding handles JSON strings and Pydantic content."""
        content = {"name": "decoded"}
        for encoded in (json.dumps(content), _SampleModel(**content)):
            parsed = parse_llm_result_unvalidated(_result(encoded), _SampleModel)
            assert parsed.name == "decoded"

    def test_non_mapping_content_is_rejected(self):
        """Tolerant decoding still requires a mapping-shaped response.

        ``decode_content`` always returns a dumped mapping, JSON
        object, or raises.  The later ``isinstance(content, model_class)``
        branch is therefore defensive and unreachable from this public
        helper.
        """
        result = _result(["not", "a", "mapping"])

        with pytest.raises(TypeError, match="Unexpected LLM result content type"):
            parse_llm_result_unvalidated(result, _SampleModel)

        result.content = json.dumps(["not", "a", "mapping"])
        with pytest.raises(TypeError, match="Expected a mapping"):
            parse_llm_result_unvalidated(result, _SampleModel)

    def test_decode_keeps_an_explicit_none(self):
        """Kill: exclude_none=False -> True in decode_content."""
        result = _result(_OptionalDumpModel(name="decoded", unused=None))
        parsed = parse_llm_result_unvalidated(result, _OptionalDumpModel)
        assert parsed.unused is None

    def test_unknown_fields_are_filtered_out(self):
        """Unknown response fields must not become model attributes."""
        result = _result({"name": "decoded", "unmodeled": "ignore me"})

        parsed = parse_llm_result_unvalidated(result, _ConstructFilterModel)

        assert parsed.model_dump() == {"name": "decoded", "optional": "default"}
        assert not hasattr(parsed, "unmodeled")

    @pytest.mark.parametrize(
        "model_class",
        [_UnionItemModel, _NoneFirstUnionModel],
        ids=["none_last", "none_first"],
    )
    def test_union_constructs_the_nested_model_member(self, model_class):
        """Kill: candidate is type(None) -> is not type(None)."""
        parsed = parse_llm_result_unvalidated(
            _result({"item": {"item_id": "ok"}}), model_class
        )
        assert isinstance(parsed.item, _NestedModel)
        assert parsed.item.item_id == "ok"

    @pytest.mark.parametrize(
        ("content", "model_class", "field"),
        [
            pytest.param(
                {"nested": "not-a-dict"},
                _RequiredNestedContainer,
                "nested",
                id="model_field_given_a_non_dict",
            ),
            pytest.param(
                {"labels": ["one"], "checkpoints": ["first"], "mode": "not-a-mode"},
                _CollectionModel,
                "mode",
                id="malformed_enum",
            ),
            pytest.param(
                {"item": ["not", "a", "model"]},
                _UnionItemModel,
                "item",
                id="union_no_member_accepts",
            ),
        ],
    )
    def test_a_value_that_cannot_be_constructed_is_kept_as_sent(
        self, content, model_class, field
    ):
        """Kill: the model check `and` -> `or`; enum and union fall back to the raw value."""
        parsed = parse_llm_result_unvalidated(_result(content), model_class)
        assert getattr(parsed, field) == content[field]


class TestCallWithPolicyTolerantMode:
    """allow_unvalidated defers validation and falls back for legacy clients."""

    def test_tolerant_mode_is_passed_and_defers_validation(self, tmp_path):
        client = ScriptedClient([{"items": [{"item_id": "malformed"}]}])

        outcome = _send(client, tmp_path, _ContainerModel, allow_unvalidated=True)

        assert outcome.error is None
        assert client.calls[0]["allow_unvalidated"] is True
        assert outcome.value.items[0].item_id == "malformed"

    def test_a_client_that_rejects_the_flag_is_retried_without_it(self, tmp_path):
        outcome = _send(_LegacyClient(), tmp_path, _SampleModel, allow_unvalidated=True)

        assert outcome.error is None
        assert outcome.result is not None
        assert outcome.value.name == "legacy"

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

    def test_validation_error_falls_back_to_the_raw_model(self, tmp_path):
        outcome = _send(
            ScriptedClient([{"item_id": "malformed"}]),
            tmp_path,
            allow_unvalidated=True,
        )

        assert outcome.error is None
        assert outcome.value.item_id == "malformed"
        with pytest.raises(ValidationError):
            _NestedModel.model_validate({"item_id": "malformed"})

    def test_default_does_not_use_the_tolerant_fallback(self, tmp_path):
        outcome = _send(ScriptedClient([{"item_id": "malformed"}]), tmp_path)

        assert outcome.value is None
        assert outcome.error is not None
        assert "malformed source ID" in outcome.error

    @pytest.mark.parametrize(
        ("error", "allow_unvalidated", "attempts", "succeeds"),
        [
            pytest.param(
                "unexpected keyword argument 'allow_unvalidated'",
                True,
                2,
                True,
                id="flag_rejected_and_requested",
            ),
            pytest.param(
                "unexpected keyword argument 'allow_unvalidated'",
                False,
                1,
                False,
                id="flag_rejected_but_not_requested",
            ),
            pytest.param(
                "unexpected keyword argument 'response_format'",
                True,
                1,
                False,
                id="other_keyword_rejected",
            ),
            pytest.param(
                "response_format is the wrong type",
                True,
                1,
                False,
                id="other_type_error",
            ),
        ],
    )
    def test_compatibility_retry_is_tightly_gated(
        self, tmp_path, error, allow_unvalidated, attempts, succeeds
    ):
        client = ScriptedClient([TypeError(error), {"item_id": "valid"}])

        outcome = _send(client, tmp_path, allow_unvalidated=allow_unvalidated)

        assert len(client.calls) == attempts
        assert (outcome.error is None) is succeeds
        assert (outcome.value is not None) is succeeds
        if not succeeds:
            assert outcome.error == f"TypeError: {error}"


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
    ids=["validation", "json", "exact-long", "exact", "generic-long", "generic"],
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
