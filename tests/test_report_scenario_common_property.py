"""Property tests for the taxonomy report shared leaf helpers.

Hypothesis-driven invariants over the pure helpers in
``asago_scenario_generator.report.scenario_common`` — the shared leaf the
section builders all import:

- **Priority thresholds**: ``_priority_label`` and ``_priority_color``
  agree on the same cutoffs (0.7 / 0.4), are monotone non-decreasing in the
  composite score, and never emit an unknown tier.
- **Hex-to-RGB round trip**: any ``#rrggbb`` color string parses to three
  integer components in [0, 255] and re-formatting from those components
  recovers the same ``r,g,b`` CSS value (parsing/formatting stability).
- **Usage-metric conservation**: normalizing call-log entries preserves
  finite numeric values verbatim and keeps ``None`` telemetry as ``None``,
  while ``_usage_totals`` sums available values treating ``None`` as zero
  (totals never grow by unavailable fields).
- **Usage-metric rejection**: bools, non-numeric containers, and
  non-finite floats fail loudly with a diagnostic naming the field and the
  call, rather than being coerced silently.

The helpers are pure and offline; no LLM endpoint is contacted.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

from asago_scenario_generator.report.scenario_common import (
    _hex_to_rgb_css,
    _is_valid_usage_metric,
    _priority_color,
    _priority_label,
    _usage_metrics,
    _usage_summary,
    _usage_totals,
)

# ---------------------------------------------------------------------------
# Generation pools
# ---------------------------------------------------------------------------

_COMPOSITE = st.floats(
    min_value=-1.0,
    max_value=2.0,
    allow_nan=False,
    allow_infinity=False,
)
_BOUNDARY_COMPOSITE = st.sampled_from([-0.5, 0.0, 0.39, 0.4, 0.69, 0.7, 0.71, 1.0, 2.0])

_RGB = st.integers(min_value=0, max_value=255)
_FINITE_NUMBER = st.one_of(
    st.integers(min_value=0, max_value=10**9),
    st.floats(
        min_value=0.0,
        max_value=10**9,
        allow_nan=False,
        allow_infinity=False,
    ),
)
_INVALID_METRIC = st.sampled_from(
    [
        True,
        False,
        "many",
        {"count": 4},
        [300],
        float("nan"),
        float("inf"),
        float("-inf"),
    ]
)
_FIELD_INDICES = st.sampled_from([0, 1, 2])
_NONE_FIELD_INDICES = st.lists(_FIELD_INDICES, min_size=0, max_size=3, unique=True)

# ---------------------------------------------------------------------------
# Priority thresholds
# ---------------------------------------------------------------------------

_COLOR_TIERS = {"#22c55e": 0, "#f59e0b": 1, "#ef4444": 2}
_LABEL_TIERS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@settings(max_examples=200)
@given(composite=_COMPOSITE)
def test_priority_label_and_color_agree_on_tier(composite: float) -> None:
    """Label and color select the same severity tier on every score."""
    label = _priority_label(composite)
    color = _priority_color(composite)
    assert label in _LABEL_TIERS
    assert color in _COLOR_TIERS
    assert _LABEL_TIERS[label] == _COLOR_TIERS[color]


@settings(max_examples=200)
@given(a=_COMPOSITE, b=_COMPOSITE)
def test_priority_tiers_are_monotone_in_score(a: float, b: float) -> None:
    """A higher composite never yields a lower severity tier."""
    if a > b:
        a, b = b, a
    assert _LABEL_TIERS[_priority_label(a)] <= _LABEL_TIERS[_priority_label(b)]
    assert _COLOR_TIERS[_priority_color(a)] <= _COLOR_TIERS[_priority_color(b)]


@given(composite=_BOUNDARY_COMPOSITE)
def test_priority_boundaries_match_pinned_cutoffs(composite: float) -> None:
    """0.7 / 0.4 cutoffs hold exactly at the boundary."""
    if composite >= 0.7:
        assert _priority_label(composite) == "HIGH"
    elif composite >= 0.4:
        assert _priority_label(composite) == "MEDIUM"
    else:
        assert _priority_label(composite) == "LOW"


# ---------------------------------------------------------------------------
# Hex-to-RGB round trip
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(r=_RGB, g=_RGB, b=_RGB)
def test_hex_to_rgb_round_trip(r: int, g: int, b: int) -> None:
    """#rrggbb parses to r,g,b and reformatting recovers the same string."""
    hex_color = f"#{r:02x}{g:02x}{b:02x}"
    assert _hex_to_rgb_css(hex_color) == f"{r},{g},{b}"
    # Leading '#' is optional; parse must be identical.
    assert _hex_to_rgb_css(hex_color.lstrip("#")) == f"{r},{g},{b}"


@settings(max_examples=200)
@given(r=_RGB, g=_RGB, b=_RGB)
def test_hex_to_rgb_components_in_range(r: int, g: int, b: int) -> None:
    """Every parsed component stays within the CSS rgb() byte range."""
    css = _hex_to_rgb_css(f"#{r:02x}{g:02x}{b:02x}")
    components = [int(part) for part in css.split(",")]
    assert len(components) == 3
    assert all(0 <= part <= 255 for part in components)


# ---------------------------------------------------------------------------
# Usage metrics
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    fields=_NONE_FIELD_INDICES,
)
def test_usage_metrics_preserves_none_telemetry(fields: list[int]) -> None:
    """Explicit None stays None (unavailable telemetry, displayed as such)."""
    entry: dict[str, Any] = {}
    for idx in fields:
        entry[("prompt_tokens", "completion_tokens", "duration_ms")[idx]] = None
    metrics = _usage_metrics(entry, call_label="call-0")
    for field, value in metrics.items():
        if field in entry and entry[field] is None:
            assert value is None
        else:
            assert value == 0  # missing fields default to the zero total


@settings(max_examples=100)
@given(values=st.lists(_FINITE_NUMBER, min_size=3, max_size=3))
def test_usage_metrics_preserves_finite_numbers(
    values: list[int | float],
) -> None:
    """Finite numeric values pass through verbatim, never rounded."""
    fields = ("prompt_tokens", "completion_tokens", "duration_ms")
    entry = dict(zip(fields, values))
    metrics = _usage_metrics(entry, call_label="call-0")
    assert [metrics[f] for f in fields] == values


@settings(max_examples=100)
@given(
    invalid_value=_INVALID_METRIC,
    field_index=_FIELD_INDICES,
)
def test_usage_metrics_rejects_invalid_values(
    invalid_value: Any,
    field_index: int,
) -> None:
    """Non-numeric or non-finite values raise a call-specific diagnostic."""
    field = ("prompt_tokens", "completion_tokens", "duration_ms")[field_index]
    entry = {field: invalid_value}
    with pytest.raises(ValueError) as exc_info:
        _usage_metrics(entry, call_label="failed_profile")
    message = str(exc_info.value)
    assert field in message
    assert "failed_profile" in message


@settings(max_examples=100)
@given(
    present=st.lists(_FINITE_NUMBER, min_size=0, max_size=3),
    none_indices=_NONE_FIELD_INDICES,
)
def test_usage_totals_treat_none_as_zero(
    present: list[int | float],
    none_indices: list[int],
) -> None:
    """Totals equal the sum of available values; None contributes zero."""
    fields = ("prompt_tokens", "completion_tokens", "duration_ms")
    normalized: list[dict[str, int | float | None]] = []
    for _ in range(3):
        entry: dict[str, int | float | None] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "duration_ms": 0,
        }
        for idx in none_indices:
            entry[fields[idx]] = None
        normalized.append(entry)
    for idx, value in enumerate(present):
        normalized[idx % 3][fields[idx]] = value
    totals = _usage_totals(normalized)
    for field, total in zip(fields, totals):
        expected = sum(entry[field] or 0 for entry in normalized)
        assert total == expected


@settings(max_examples=100)
@given(values=st.lists(_FINITE_NUMBER, min_size=3, max_size=3))
def test_usage_summary_formats_present_metrics(
    values: list[int | float],
) -> None:
    """All-present metrics render the compact pinned layout."""
    fields = ("prompt_tokens", "completion_tokens", "duration_ms")
    metrics = dict(zip(fields, values))
    summary = _usage_summary(metrics)
    assert summary == (
        f"{values[0]} prompt / {values[1]} completion tokens, {values[2]}ms"
    )


@settings(max_examples=100)
@given(none_fields=_NONE_FIELD_INDICES)
def test_usage_summary_marks_unavailable_fields(none_fields: list[int]) -> None:
    """Any unavailable field switches the summary to the verbose layout."""
    fields = ("prompt_tokens", "completion_tokens", "duration_ms")
    metrics: dict[str, int | float | None] = {}
    for idx, field in enumerate(fields):
        metrics[field] = None if idx in none_fields else 5
    summary = _usage_summary(metrics)
    if none_fields:
        for field in fields:
            expected = "unavailable" if metrics[field] is None else str(metrics[field])
            assert f"{field}={expected}" in summary
    else:
        assert summary == "5 prompt / 5 completion tokens, 5ms"


@settings(max_examples=100)
@given(value=_FINITE_NUMBER)
def test_is_valid_usage_metric_accepts_finite_numbers(value: int | float) -> None:
    """Finite ints and floats are valid usage metrics."""
    assert _is_valid_usage_metric(value)


@settings(max_examples=100)
@given(value=_INVALID_METRIC)
def test_is_valid_usage_metric_rejects_invalid_values(value: Any) -> None:
    """Bools, containers, and non-finite floats are invalid metrics."""
    assert not _is_valid_usage_metric(value)
