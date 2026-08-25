"""Property tests for the inward eval scorecard helpers.

These properties pin ratio and zero-gate construction. They are offline
and deterministic.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.eval.scorecard import (
    MetricStatus,
    ratio_metric,
    zero_gate,
)

_MAX_EXAMPLES = 60
_COUNTS = st.integers(min_value=0, max_value=32)
_IDS = st.lists(
    st.from_regex(r"[a-z][a-z0-9-]{0,11}", fullmatch=True),
    max_size=6,
    unique=True,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(denominator=_COUNTS, numerator=_COUNTS, affected=_IDS)
def test_ratio_metric_is_na_when_denominator_is_zero(
    denominator: int, numerator: int, affected: list[str]
) -> None:
    """A zero denominator is always not_applicable and carries no value."""
    if denominator:
        numerator = min(numerator, denominator)
    result = ratio_metric(
        numerator,
        denominator,
        evidence=["test"],
        affected_ids=affected,
    )
    if denominator == 0:
        assert result.status is MetricStatus.NOT_APPLICABLE
        assert result.value is None
        return
    assert result.value == numerator / denominator
    assert result.numerator == numerator
    assert result.denominator == denominator
    if result.value >= 1.0:
        assert result.status is MetricStatus.PASS
    else:
        assert result.status is MetricStatus.FAIL
    assert result.affected_ids == sorted(affected)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(count=_COUNTS, affected=_IDS)
def test_zero_gate_passes_only_on_zero(count: int, affected: list[str]) -> None:
    """A zero-count gate passes exactly when the observed count is zero."""
    result = zero_gate(count, evidence=["test"], affected_ids=affected)
    if count == 0:
        assert result.status is MetricStatus.PASS
    else:
        assert result.status is MetricStatus.FAIL
    assert result.numerator == count
    assert result.affected_ids == sorted(affected)
