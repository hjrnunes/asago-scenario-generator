from hypothesis import given, strategies as st

from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
)
from asago_scenario_generator.models.scenario import CallName


@given(
    field=st.sampled_from(["response_schema", "max_completion_tokens", "temperature"]),
    retry_value=st.one_of(
        st.text(min_size=1, max_size=16),
        st.integers(min_value=1, max_value=20_000),
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    ),
)
def test_provider_retry_value_is_scoped_to_length_retries(
    field: str, retry_value: str | int | float
) -> None:
    control = CausalRetryControl(
        control_id="fixture-control",
        field=field,
        initial_value="standard",
        retry_value=retry_value,
    )
    length_retry = RetryDirective(
        reason=StageAttemptFailure.COMPLETION_LENGTH_CODE,
        causal_control=control,
    )
    semantic_retry = RetryDirective(reason="semantic", causal_control=control)

    assert length_retry.provider_retry_value(field) == retry_value
    assert length_retry.provider_retry_value("unrelated") is None
    assert semantic_retry.provider_retry_value(field) == retry_value


def test_provider_retry_value_requires_a_matching_control() -> None:
    control = CausalRetryControl(
        control_id="fixture-control",
        field="temperature",
        initial_value=0.7,
        retry_value=0.2,
    )

    assert RetryDirective().provider_retry_value("temperature") is None
    retry = RetryDirective(causal_control=control)
    assert retry.provider_retry_value("max_completion_tokens") is None
    assert retry.provider_retry_value("temperature") == 0.2


def test_stage_attempt_failure_preserves_request_controls() -> None:
    request_controls = {"max_completion_tokens": 8192}
    failure = StageAttemptFailure(
        call_name=CallName.narrative,
        exception=RuntimeError("fixture"),
        phase="invocation",
        invoked=True,
        request_controls=request_controls,
    )

    assert failure.request_controls is request_controls


class TestStageAttemptFailureHelpers:
    """Direct coverage for the decomposed stage-attempt failure builders."""

    def test_completion_length_error_maps_to_typed_code(self):
        from asago_scenario_generator.llm.client import CompletionLengthError
        from asago_scenario_generator.pipeline.generation_contracts import (
            stage_attempt_failure,
        )

        exc = CompletionLengthError(
            prompt_tokens=12,
            completion_tokens=34,
            finish_reason="length",
            usage_details={"total_tokens": 46},
            response_id="resp-1",
            model="fixture-model",
            partial_character_count=7,
            partial_sha256="ab" * 32,
            partial_preview_prefix="pre",
            partial_preview_suffix="suf",
            elapsed_ms=123,
        )
        failure = stage_attempt_failure(
            CallName.narrative,
            exc,
            phase="post_response",
            invoked=True,
            request_controls={"max_completion_tokens": 8192},
        )

        assert failure.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        assert failure.retryable is True
        assert failure.finish_reason == "length"
        assert failure.prompt_tokens == 12
        assert failure.completion_tokens == 34
        assert failure.total_tokens == 46
        assert failure.usage_details == {"total_tokens": 46}
        assert failure.response_id == "resp-1"
        assert failure.model == "fixture-model"
        assert failure.partial_character_count == 7
        assert failure.partial_sha256 == "ab" * 32
        assert failure.partial_preview_prefix == "pre"
        assert failure.partial_preview_suffix == "suf"
        assert failure.elapsed_ms == 123
        assert failure.request_controls == {"max_completion_tokens": 8192}

    def test_generic_failure_adopts_exception_code_and_retryable(self):
        from asago_scenario_generator.pipeline.generation_contracts import (
            stage_attempt_failure,
        )

        class _Coded(RuntimeError):
            stage_failure_code = "coded_failure"
            stage_failure_retryable = False

        failure = stage_attempt_failure(
            CallName.actor_profile,
            _Coded("boom"),
            phase="invocation",
            invoked=True,
        )

        assert failure.code == "coded_failure"
        assert failure.retryable is False
        assert failure.exception_type == "_Coded"
        assert failure.detail == "boom"

    def test_invoked_validation_error_maps_to_protocol_code(self):
        from pydantic import ValidationError

        from asago_scenario_generator.pipeline.generation_contracts import (
            stage_attempt_failure,
        )

        exc = ValidationError.from_exception_data("fixture", [])
        failure = stage_attempt_failure(
            CallName.actor_profile,
            exc,
            phase="invocation",
            invoked=True,
        )
        assert failure.code == StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE
        assert failure.retryable is True

    def test_non_invoked_validation_error_stays_generic(self):
        from pydantic import ValidationError

        from asago_scenario_generator.pipeline.generation_contracts import (
            stage_attempt_failure,
        )

        exc = ValidationError.from_exception_data("fixture", [])
        failure = stage_attempt_failure(
            CallName.actor_profile,
            exc,
            phase="before_invocation",
            invoked=False,
        )
        assert failure.code == StageAttemptFailure.DEFAULT_CODE
        assert failure.retryable is True

    def test_defaults_and_explicit_overrides(self):
        from asago_scenario_generator.pipeline.generation_contracts import (
            stage_attempt_failure,
        )

        failure = stage_attempt_failure(
            CallName.attack_tree,
            RuntimeError("x"),
            phase="before_invocation",
            invoked=False,
        )
        assert failure.code == StageAttemptFailure.DEFAULT_CODE
        assert failure.retryable is True

        explicit = stage_attempt_failure(
            CallName.attack_tree,
            RuntimeError("x"),
            phase="before_invocation",
            invoked=False,
            code="explicit",
            retryable=False,
        )
        assert explicit.code == "explicit"
        assert explicit.retryable is False

    def test_resolved_failure_code_helper(self):
        from pydantic import ValidationError

        from asago_scenario_generator.pipeline.generation_contracts import (
            _resolved_failure_code,
        )

        assert _resolved_failure_code(RuntimeError("x"), None, None, False) == (
            None,
            None,
        )

        class _Coded(RuntimeError):
            stage_failure_code = "coded"
            stage_failure_retryable = False

        assert _resolved_failure_code(_Coded("x"), None, None, False) == (
            "coded",
            False,
        )

        exc = ValidationError.from_exception_data("fixture", [])
        assert _resolved_failure_code(exc, None, None, True) == (
            StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE,
            True,
        )
        assert _resolved_failure_code(RuntimeError("x"), "pinned", None, True) == (
            "pinned",
            None,
        )

    def test_completion_length_failure_helper(self):
        from asago_scenario_generator.llm.client import CompletionLengthError
        from asago_scenario_generator.pipeline.generation_contracts import (
            _completion_length_failure,
        )

        exc = CompletionLengthError(prompt_tokens=1, completion_tokens=2)
        failure = _completion_length_failure(
            CallName.behavior_spec,
            exc,
            phase="post_response",
            invoked=True,
            request_controls={"x": 1},
        )

        assert failure.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        assert failure.total_tokens == 3
        assert failure.retryable is True
        assert failure.request_controls == {"x": 1}
