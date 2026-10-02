"""A thresholded scorecard metric's status agrees with its bounded value."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.scorecard import MetricResult, MetricStatus


def _metric(
    status: MetricStatus, numerator: int, threshold: float | None
) -> MetricResult:
    return MetricResult(
        status=status,
        threshold=threshold,
        numerator=numerator,
        denominator=4,
        value=numerator / 4,
        evidence=[],
        affected_ids=[],
    )


@pytest.mark.parametrize(
    ("status", "numerator", "threshold"),
    [
        pytest.param(MetricStatus.PASS, 3, 0.75, id="pass-at-threshold"),
        pytest.param(MetricStatus.PASS, 4, 0.75, id="pass-above-threshold"),
        pytest.param(MetricStatus.FAIL, 2, 0.75, id="fail-below-threshold"),
        pytest.param(MetricStatus.NOT_APPLICABLE, 1, 0.75, id="other-status"),
        pytest.param(MetricStatus.FAIL, 4, None, id="no-threshold"),
    ],
)
def test_status_consistent_with_threshold_is_accepted(
    status: MetricStatus, numerator: int, threshold: float | None
) -> None:
    metric = _metric(status, numerator, threshold)

    assert metric.status is status
    assert metric.value == numerator / 4


def test_pass_below_threshold_is_rejected() -> None:
    with pytest.raises(ValidationError, match="pass metric is below threshold"):
        _metric(MetricStatus.PASS, 2, 0.75)


def test_fail_at_threshold_is_rejected() -> None:
    with pytest.raises(ValidationError, match="fail metric is at or above threshold"):
        _metric(MetricStatus.FAIL, 3, 0.75)
