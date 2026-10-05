"""Tests for shared LLM helpers (parse_llm_result, log_llm_call).

These improve coverage of the infra helpers extracted during cleanup.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError, field_validator

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    ExactFeedbackError,
    _compact_validation_error,
    log_llm_call,
    parse_llm_result,
    parse_llm_result_unvalidated,
    safe_llm_call,
)


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


class _RequiredNestedContainer(BaseModel):
    """Container whose omitted nested model must not be fabricated."""

    nested: _NestedModel


class _RequiredUnionFieldsModel(BaseModel):
    """Model covering Optional and non-optional Union sentinels."""

    optional_text: str | None
    text_or_count: str | int


class _TolerantClient:
    """Minimal client exposing the raw structured-response escape hatch."""

    model = "test-model"

    def __init__(self) -> None:
        self.allow_unvalidated = False

    def complete(
        self,
        *,
        system_prompt,
        user_prompt,
        response_format,
        temperature,
        max_completion_tokens=None,
        allow_unvalidated=False,
    ):
        self.allow_unvalidated = allow_unvalidated
        return LLMResult(
            content={"items": [{"item_id": "malformed"}]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )


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


class TestParseLlmResult:
    """parse_llm_result handles all content types."""

    def test_content_is_already_model_instance(self):
        """When content is already the target type, it is returned as-is."""
        model = _SampleModel(name="direct")
        result = LLMResult(
            content=model, prompt_tokens=0, completion_tokens=0, duration_ms=0
        )
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed is model

    def test_content_is_dict(self):
        """When content is a dict, it is validated into the model."""
        result = LLMResult(
            content={"name": "from_dict", "value": 42},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed.name == "from_dict"
        assert parsed.value == 42

    def test_content_is_json_string(self):
        """When content is a JSON string, it is parsed and validated."""
        result = LLMResult(
            content=json.dumps({"name": "from_string"}),
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed.name == "from_string"
        assert parsed.value == 0

    def test_content_is_exact_fenced_json_document(self):
        """OpenAI-compatible gateways may wrap an otherwise exact JSON body."""
        result = LLMResult(
            content='```json\n{"name": "from_fence"}\n```',
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result(result, _SampleModel)

        assert parsed.name == "from_fence"

    def test_fenced_json_with_trailing_prose_is_rejected(self):
        """Tolerance does not extract a JSON fragment from surrounding prose."""
        result = LLMResult(
            content='```json\n{"name": "unsafe"}\n```\nextra prose',
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        with pytest.raises(json.JSONDecodeError):
            parse_llm_result(result, _SampleModel)

    def test_content_is_unexpected_type_raises(self):
        """When content is an unexpected type, TypeError is raised."""
        result = LLMResult(
            content=12345,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        with pytest.raises(TypeError, match="Unexpected LLM result content type"):
            parse_llm_result(result, _SampleModel)

    def test_unvalidated_parser_preserves_nested_invalid_source_id(self):
        """Tolerant decoding defers nested validation to post-processing."""
        result = LLMResult(
            content={"items": [{"item_id": "malformed"}]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _ContainerModel)

        assert parsed.items[0].item_id == "malformed"

    def test_unvalidated_parser_fills_nested_missing_required_fields(self):
        """Nested model construction also supplies required-field sentinels."""
        result = LLMResult(
            content={"items": [{}]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _ContainerModel)

        assert parsed.items[0].item_id == ""

    def test_unvalidated_parser_constructs_collections_and_enums(self):
        """Tolerant decoding preserves supported nested annotation shapes."""
        result = LLMResult(
            content={
                "labels": ["one", "two"],
                "checkpoints": ["first", "second"],
                "mode": "ready",
                "note": "optional",
            },
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _CollectionModel)

        assert parsed.labels == {"one", "two"}
        assert parsed.checkpoints == ("first", "second")
        assert parsed.mode is _Mode.READY
        assert parsed.note == "optional"

    def test_unvalidated_parser_fills_missing_required_fields_with_sentinels(self):
        """Missing required fields remain attribute-safe with typed sentinels."""
        parsed = parse_llm_result_unvalidated(
            LLMResult(
                content={},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            _MissingRequiredFieldsModel,
        )

        assert parsed.text == ""
        assert parsed.count == 0
        assert parsed.ratio == 0.0
        assert parsed.enabled is False
        assert parsed.labels == []
        assert parsed.checkpoints == ()
        assert parsed.tags == set()
        assert parsed.metadata == {}

    def test_unvalidated_parser_does_not_fabricate_missing_nested_models(self):
        """Missing required nested models become None for later validation."""
        parsed = parse_llm_result_unvalidated(
            LLMResult(
                content={},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            _RequiredNestedContainer,
        )

        assert parsed.nested is None
        with pytest.raises(ValidationError, match="nested"):
            _RequiredNestedContainer.model_validate(parsed.model_dump())

    def test_unvalidated_parser_uses_union_sentinels(self):
        """Optional unions use None and other unions use their first member."""
        parsed = parse_llm_result_unvalidated(
            LLMResult(
                content={},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            _RequiredUnionFieldsModel,
        )

        assert parsed.optional_text is None
        assert parsed.text_or_count == ""

    def test_unvalidated_parser_accepts_json_and_model_content(self):
        """Tolerant decoding handles JSON strings and Pydantic content."""
        content = {"name": "decoded"}
        for encoded in (json.dumps(content), _SampleModel(**content)):
            parsed = parse_llm_result_unvalidated(
                LLMResult(
                    content=encoded,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
                _SampleModel,
            )
            assert parsed.name == "decoded"

    def test_unvalidated_parser_rejects_non_mapping_content(self):
        """Tolerant decoding still requires a mapping-shaped response.

        ``_decode_llm_content`` always returns a dumped mapping, JSON
        object, or raises.  The later ``isinstance(content, model_class)``
        branch is therefore defensive and unreachable from this public
        helper.
        """
        result = LLMResult(
            content=["not", "a", "mapping"],
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        with pytest.raises(
            TypeError,
            match="Unexpected LLM result content type",
        ):
            parse_llm_result_unvalidated(result, _SampleModel)

        result.content = json.dumps(["not", "a", "mapping"])
        with pytest.raises(TypeError, match="Expected a mapping"):
            parse_llm_result_unvalidated(result, _SampleModel)

    def test_safe_call_passes_tolerant_mode_and_defers_validation(self, tmp_path):
        """safe_llm_call exposes malformed nested IDs to post-processing."""
        client = _TolerantClient()

        parsed, _, error = safe_llm_call(
            llm_client=client,
            system_prompt="system",
            user_prompt="user",
            response_format=_ContainerModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=True,
        )

        assert error is None
        assert client.allow_unvalidated is True
        assert parsed.items[0].item_id == "malformed"

    def test_safe_call_retries_for_legacy_client(self, tmp_path):
        """safe_llm_call falls back when a client rejects the optional flag."""
        parsed, result, error = safe_llm_call(
            llm_client=_LegacyClient(),
            system_prompt="system",
            user_prompt="user",
            response_format=_SampleModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=True,
        )

        assert error is None
        assert result is not None
        assert parsed.name == "legacy"


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

        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_test"
        assert entries[0]["step"] == "step_test"
        assert entries[0]["model"] == "test-model"
        assert entries[0]["prompt_tokens"] == 100
        assert entries[0]["completion_tokens"] == 50
        assert entries[0]["success"] is True


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
    assert _compact_validation_error(error) == expected
