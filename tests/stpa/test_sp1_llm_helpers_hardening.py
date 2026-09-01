"""Mutation hardening tests for the SP1 tolerant LLM parsing path.

These stay separate from unit and acceptance tests. They kill surviving
mutants in ``llm_helpers`` decode/construct helpers used before ID
normalization.

Four remaining mutate4py sites sit on keyword-only default literals
(``log_llm_call_failure`` token/duration defaults and
``safe_llm_call(..., allow_unvalidated=False)``). LCOV does not emit DA
records for those signature lines, so scan reports them uncovered. The
default paths are already exercised by
``test_failure_log_defaults_are_zero`` and
``test_safe_call_default_does_not_use_tolerant_fallback``.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError, field_validator

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    _is_unsupported_unvalidated_error,
    _stringify_response_content,
    log_llm_call,
    log_llm_call_failure,
    parse_llm_result_unvalidated,
    safe_llm_call,
    safe_llm_call_raw,
)


class _NestedModel(BaseModel):
    """Nested model used to observe construct-vs-raw-value behavior."""

    item_id: str


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


class _HolderModel(BaseModel):
    """Model field that may receive a non-dict value from a malformed payload."""

    nested: _NestedModel


class _Mode(str, Enum):
    READY = "ready"


class _CollectionModel(BaseModel):
    """Collection and enum shapes used by the tolerant constructor."""

    labels: set[str]
    checkpoints: tuple[str, ...]
    mode: _Mode
    note: str | None = None


class _ValidatedModel(BaseModel):
    """Model that fails normal validation so the unvalidated fallback runs."""

    item_id: str

    @field_validator("item_id")
    @classmethod
    def reject_malformed(cls, value: str) -> str:
        if value == "malformed":
            raise ValueError("malformed source ID")
        return value


class _KwargsClient:
    """Client that records structured-completion kwargs."""

    model = "kwargs-model"

    def __init__(self) -> None:
        self.kwargs = None

    def complete(self, **kwargs):
        self.kwargs = kwargs
        return LLMResult(
            content={"name": "ok", "unused": None},
            prompt_tokens=1,
            completion_tokens=2,
            duration_ms=3,
        )


class _FailingClient:
    """Client that fails before returning a result."""

    model = "failing-model"

    def complete(self, **kwargs):
        raise RuntimeError("offline")


class _ParseFailureClient:
    """Client that returns usage telemetry with invalid model content."""

    model = "parse-failure-model"

    def complete(self, **kwargs):
        return LLMResult(
            content={"item_id": "malformed"},
            prompt_tokens=17,
            completion_tokens=4,
            duration_ms=230,
        )


class TestStringifyNoneContent:
    """Kill: content is None -> is not None in _stringify_response_content."""

    def test_none_content_logs_as_empty_string(self, tmp_path: Path) -> None:
        assert _stringify_response_content(None) == ""
        result = LLMResult(
            content=None,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        log_llm_call(result, "test-model", tmp_path, "stage_test", "step_test")
        entry = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
        assert entry["response_content"] == ""

    def test_dict_and_other_content_are_stringified(self) -> None:
        assert _stringify_response_content({"name": "ok"}) == '{"name": "ok"}'
        assert _stringify_response_content(12) == "12"


class TestDecodePreservesExplicitNone:
    """Kill: exclude_none=False -> True in _decode_llm_content."""

    def test_model_dump_keeps_explicit_none(self) -> None:
        result = LLMResult(
            content=_OptionalDumpModel(name="decoded", unused=None),
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _OptionalDumpModel)

        assert parsed.unused is None


class TestDecodeConstructsDeclaredFieldsOnly:
    """Unknown response fields must not become model attributes."""

    def test_unknown_fields_are_filtered_from_unvalidated_model(self) -> None:
        result = LLMResult(
            content={"name": "decoded", "unmodeled": "ignore me"},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _ConstructFilterModel)

        assert parsed.model_dump() == {"name": "decoded", "optional": "default"}
        assert not hasattr(parsed, "unmodeled")


class TestConstructUnionSkipsNoneCandidate:
    """Kill: candidate is type(None) -> is not type(None)."""

    def test_union_constructs_nested_model_member(self) -> None:
        result = LLMResult(
            content={"item": {"item_id": "ok"}},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _UnionItemModel)

        assert isinstance(parsed.item, _NestedModel)
        assert parsed.item.item_id == "ok"


class TestConstructTypedValueRequiresDictForModels:
    """Kill: BaseModel check `and` -> `or` in _construct_typed_value."""

    def test_non_dict_model_value_is_retained(self) -> None:
        result = LLMResult(
            content={"nested": "not-a-dict"},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _HolderModel)

        assert parsed.nested == "not-a-dict"


class TestConstructEnumAndUnionFallbacks:
    """Cover malformed enum values and union construction failures."""

    def test_malformed_enum_is_retained(self) -> None:
        result = LLMResult(
            content={
                "labels": ["one"],
                "checkpoints": ["first"],
                "mode": "not-a-mode",
            },
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _CollectionModel)

        assert parsed.mode == "not-a-mode"

    def test_union_falls_back_when_no_member_accepts_value(self) -> None:
        result = LLMResult(
            content={"item": ["not", "a", "model"]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _UnionItemModel)

        assert parsed.item == ["not", "a", "model"]

    def test_none_first_union_still_constructs_model(self) -> None:
        result = LLMResult(
            content={"item": {"item_id": "ok"}},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _NoneFirstUnionModel)

        assert isinstance(parsed.item, _NestedModel)
        assert parsed.item.item_id == "ok"


class TestSafeCallKwargsAndFailureUsage:
    """Kill completion-kwarg and zero-usage mutants on the call wrappers."""

    def test_safe_call_forwards_max_completion_tokens(self, tmp_path: Path) -> None:
        client = _KwargsClient()

        parsed, _, error = safe_llm_call(
            llm_client=client,
            system_prompt="system",
            user_prompt="user",
            response_format=_OptionalDumpModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            max_completion_tokens=10,
            allow_unvalidated=True,
        )

        assert error is None
        assert parsed.name == "ok"
        assert client.kwargs["max_completion_tokens"] == 10
        assert client.kwargs["allow_unvalidated"] is True

    def test_safe_call_falls_back_after_validation_error(self, tmp_path: Path) -> None:
        class _InvalidThenRawClient:
            model = "invalid-model"

            def complete(self, **kwargs):
                return LLMResult(
                    content={"item_id": "malformed"},
                    prompt_tokens=1,
                    completion_tokens=1,
                    duration_ms=1,
                )

        parsed, _, error = safe_llm_call(
            llm_client=_InvalidThenRawClient(),
            system_prompt="system",
            user_prompt="user",
            response_format=_ValidatedModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=True,
        )

        assert error is None
        assert parsed.item_id == "malformed"
        with pytest.raises(ValidationError):
            _ValidatedModel.model_validate({"item_id": "malformed"})

    def test_failed_raw_call_logs_zero_usage(self, tmp_path: Path) -> None:
        _, result, error = safe_llm_call_raw(
            llm_client=_FailingClient(),
            system_prompt="system",
            user_prompt="user",
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
        )

        assert result is None
        assert error == "RuntimeError: offline"
        entry = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
        assert entry["success"] is False
        assert entry["prompt_tokens"] == 0
        assert entry["completion_tokens"] == 0
        assert entry["duration_ms"] == 0

    @pytest.mark.parametrize(
        ("error", "allow_unvalidated", "attempts", "succeeds"),
        [
            (
                "unexpected keyword argument 'allow_unvalidated'",
                True,
                2,
                True,
            ),
            (
                "unexpected keyword argument 'allow_unvalidated'",
                False,
                1,
                False,
            ),
            (
                "unexpected keyword argument 'response_format'",
                True,
                1,
                False,
            ),
            ("response_format is the wrong type", True, 1, False),
        ],
    )
    def test_compatibility_retry_is_tightly_gated(
        self,
        tmp_path: Path,
        error: str,
        allow_unvalidated: bool,
        attempts: int,
        succeeds: bool,
    ) -> None:
        class _CompatibilityClient:
            model = "compatibility-model"

            def __init__(self) -> None:
                self.attempt_count = 0

            def complete(self, **kwargs):
                self.attempt_count += 1
                if self.attempt_count == 1:
                    raise TypeError(error)
                return LLMResult(
                    content={"item_id": "valid"},
                    prompt_tokens=1,
                    completion_tokens=1,
                    duration_ms=1,
                )

        client = _CompatibilityClient()
        parsed, _, call_error = safe_llm_call(
            llm_client=client,
            system_prompt="system",
            user_prompt="user",
            response_format=_ValidatedModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=allow_unvalidated,
        )

        assert client.attempt_count == attempts
        assert (call_error is None) is succeeds
        assert (parsed is not None) is succeeds

    def test_safe_call_default_does_not_use_tolerant_fallback(
        self, tmp_path: Path
    ) -> None:
        class _InvalidClient:
            model = "invalid-model"

            def complete(self, **kwargs):
                return LLMResult(
                    content={"item_id": "malformed"},
                    prompt_tokens=1,
                    completion_tokens=1,
                    duration_ms=1,
                )

        parsed, _, error = safe_llm_call(
            llm_client=_InvalidClient(),
            system_prompt="system",
            user_prompt="user",
            response_format=_ValidatedModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
        )

        assert parsed is None
        assert error is not None
        assert "malformed source ID" in error

    def test_safe_call_keeps_usage_when_response_parsing_fails(
        self, tmp_path: Path
    ) -> None:
        parsed, result, error = safe_llm_call(
            llm_client=_ParseFailureClient(),
            system_prompt="system",
            user_prompt="user",
            response_format=_ValidatedModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
        )

        assert parsed is None
        assert result is not None
        assert error is not None
        entry = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
        assert entry["prompt_tokens"] == 17
        assert entry["completion_tokens"] == 4
        assert entry["duration_ms"] == 230
        assert entry["provider_response_received"] is True
        assert entry["draft_parsed"] is False
        assert entry["semantic_validation_passed"] is False
        assert entry["compiled"] is False
        assert entry["published"] is False
        assert entry["terminal_error_codes"] == ["provider_contract_failure"]

    def test_unexpected_type_error_is_not_treated_as_compat(
        self, tmp_path: Path
    ) -> None:
        class _BrokenClient:
            model = "broken-model"

            def complete(self, **kwargs):
                raise TypeError("response_format is the wrong type")

        parsed, _, error = safe_llm_call(
            llm_client=_BrokenClient(),
            system_prompt="system",
            user_prompt="user",
            response_format=_ValidatedModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=True,
        )

        assert parsed is None
        assert error == "TypeError: response_format is the wrong type"

    def test_failure_log_defaults_are_zero(self, tmp_path: Path) -> None:
        log_llm_call_failure(
            "test-model",
            tmp_path,
            "stage_test",
            "step_test",
            "boom",
        )
        entry = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
        assert entry["success"] is False
        assert entry["prompt_tokens"] == 0
        assert entry["completion_tokens"] == 0
        assert entry["duration_ms"] == 0
        assert entry["error"] == "boom"


class TestCompatGateAndStageError:
    """Cover the compatibility predicate and StageError attributes."""

    def test_compat_gate_requires_flag_and_message(self) -> None:
        unexpected = TypeError("unexpected keyword argument 'allow_unvalidated'")
        other = TypeError("response_format is the wrong type")

        assert _is_unsupported_unvalidated_error(unexpected, True) is True
        assert _is_unsupported_unvalidated_error(unexpected, False) is False
        assert _is_unsupported_unvalidated_error(other, True) is False
        assert (
            _is_unsupported_unvalidated_error(
                TypeError("unexpected keyword argument 'response_format'"),
                True,
            )
            is False
        )

    def test_stage_error_keeps_stage_and_step(self) -> None:
        error = StageError(stage="stage_2", step="call_1", message="offline")

        assert error.stage == "stage_2"
        assert error.step == "call_1"
        assert str(error) == "stage_2/call_1: offline"
