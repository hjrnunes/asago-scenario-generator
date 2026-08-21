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
