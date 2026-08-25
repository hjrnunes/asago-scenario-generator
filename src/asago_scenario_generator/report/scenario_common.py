"""Shared scenario-card helpers: signals, usage metrics, priorities, CSS.

Leaf module for the taxonomy report section builders: no dependency on the
``sections_*`` modules, so any of them can import these helpers safely.
"""

from __future__ import annotations

import math
from numbers import Real
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc

_SIGNAL_TOOLTIPS: dict[str, str] = {
    "technique_maturity": (
        "How proven this attack technique is: feasible (theoretically possible), "
        "demonstrated (shown in lab), realized (observed in the wild)"
    ),
    "architecture_match": (
        "How the threat maps to this system: explicit (directly matches a "
        "declared capability) or inferred (indirectly relevant based on "
        "system profile)"
    ),
    "attack_complexity": "Difficulty of executing this attack: low/medium/high",
    "risk_impact": "Potential damage if attack succeeds: low/medium/high/critical",
    "risk_likelihood": "Probability of this attack being attempted: low/medium/high",
    "structural_exposure": (
        "How exposed this attack path is based on the defensive architecture"
    ),
}


_SIGNAL_NUMERIC: dict[str, dict[str, float]] = {
    "technique_maturity": {
        "theoretical": 0.17,
        "feasible": 0.33,
        "demonstrated": 0.67,
        "realized": 1.0,
    },
    "risk_impact": {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75,
        "critical": 1.0,
    },
    "risk_likelihood": {
        "low": 0.33,
        "medium": 0.67,
        "high": 1.0,
    },
    "attack_complexity": {
        # INVERTED — high complexity = harder = lower score contribution
        "high": 0.33,
        "medium": 0.67,
        "low": 1.0,
    },
    "architecture_match": {
        "none": 0.0,
        "inferred": 0.5,
        "implicit": 0.5,
        "explicit": 1.0,
    },
    "structural_exposure": {
        "none": 0.0,
        "defense_in_depth_claim": 0.25,
        "probabilistic_control": 0.5,
        "convergence_point": 0.75,
        "single_point_of_failure": 1.0,
    },
}


_SIGNAL_COLORS: list[tuple[str, str, str]] = [
    ("technique_maturity", "#6366f1", "Technique Maturity"),
    ("risk_impact", "#ef4444", "Risk Impact"),
    ("risk_likelihood", "#f59e0b", "Risk Likelihood"),
    ("attack_complexity", "#06b6d4", "Attack Complexity"),
    ("architecture_match", "#8b5cf6", "Architecture Match"),
    ("structural_exposure", "#ec4899", "Structural Exposure"),
]


_USAGE_METRIC_FIELDS: tuple[str, ...] = (
    "prompt_tokens",
    "completion_tokens",
    "duration_ms",
)

_CALL_DISPLAY_NAMES: dict[str, str] = {
    "actor_profile": "Actor Profile",
    "narrative": "Narrative",
    "attack_tree": "Attack Tree",
    "behavior_spec": "Behavior Spec",
}


def _is_valid_usage_metric(value: Any) -> bool:
    """Return whether a usage value is a finite real number."""
    if isinstance(value, bool):
        return False
    if not isinstance(value, Real):
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    return True


def _usage_metrics(
    entry: dict[str, Any],
    *,
    call_label: str,
) -> dict[str, int | float | None]:
    """Validate and normalize usage metrics from one call-log entry.

    Missing fields retain the historical zero default.  Explicit ``None``
    means that telemetry was unavailable and is kept as ``None`` for display,
    while totals treat it as zero.  Values of any other nonnumeric type are
    rejected before report rendering can attempt arithmetic on them.
    """
    metrics: dict[str, int | float | None] = {}
    for field in _USAGE_METRIC_FIELDS:
        value = entry.get(field, 0)
        if value is None:
            metrics[field] = None
            continue
        if not _is_valid_usage_metric(value):
            raise ValueError(
                f"Invalid usage metric {field}={value!r} for call "
                f"{call_label!r}; expected a finite number or null."
            )
        metrics[field] = value
    return metrics


def _usage_call_label(entry: dict[str, Any], index: int) -> str:
    """Return a stable, user-facing label for a call-log entry."""
    return str(entry.get("call") or entry.get("step") or f"call {index}")


def _usage_warning_html(
    call_label: str,
    metrics: dict[str, int | float | None],
) -> str:
    """Render a warning for the unavailable fields in one call."""
    unavailable = [field for field in _USAGE_METRIC_FIELDS if metrics[field] is None]
    if not unavailable:
        return ""
    fields = ", ".join(unavailable)
    return (
        '<div class="warning-banner" role="status">'
        '<span class="warning-banner-icon">!</span>'
        f"<span>Warning: call <strong>{_esc(call_label)}</strong> has "
        f"unavailable usage metrics: {_esc(fields)}.</span>"
        "</div>"
    )


def _usage_summary(metrics: dict[str, int | float | None]) -> str:
    """Format usage metrics, preserving the established numeric layout."""
    if all(metrics[field] is not None for field in _USAGE_METRIC_FIELDS):
        return (
            f"{metrics['prompt_tokens']} prompt / "
            f"{metrics['completion_tokens']} completion tokens, "
            f"{metrics['duration_ms']}ms"
        )
    return ", ".join(
        f"{field}={'unavailable' if metrics[field] is None else metrics[field]}"
        for field in _USAGE_METRIC_FIELDS
    )


def _usage_failure_suffix(entry: dict[str, Any]) -> str:
    """Format the failure marker for a call-log entry when needed."""
    if entry.get("success", True):
        return ""
    error = _esc(str(entry.get("error", "")))
    return f" FAILED{f': {error}' if error else ''}"


def _priority_color(composite: float) -> str:
    if composite >= 0.7:
        return "#ef4444"
    if composite >= 0.4:
        return "#f59e0b"
    return "#22c55e"


def _priority_label(composite: float) -> str:
    if composite >= 0.7:
        return "HIGH"
    if composite >= 0.4:
        return "MEDIUM"
    return "LOW"


def _hex_to_rgb_css(hex_color: str) -> str:
    """Convert #rrggbb to 'r,g,b' for rgba."""
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def _usage_total(
    normalized_usage: list[dict[str, int | float | None]],
    field: str,
) -> int | float:
    """Sum one usage metric across calls, treating None telemetry as zero."""
    return sum((usage[field] or 0) for usage in normalized_usage)


def _usage_totals(
    normalized_usage: list[dict[str, int | float | None]],
) -> tuple[int | float, int | float, int | float]:
    """Sum available metrics while treating unavailable telemetry as zero."""
    return (
        _usage_total(normalized_usage, "prompt_tokens"),
        _usage_total(normalized_usage, "completion_tokens"),
        _usage_total(normalized_usage, "duration_ms"),
    )
