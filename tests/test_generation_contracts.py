from hypothesis import given, strategies as st

from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
)


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
