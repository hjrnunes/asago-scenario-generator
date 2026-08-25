"""Run Summary section builder."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc

# Accepted ISO-8601 timestamp formats, most specific first.
_FUNNEL_TS_FORMATS: list[str] = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
]

_FUNNEL_STEP_COLORS: list[tuple[str, str]] = [
    ("Seeds Generated", "#3b82f6"),
    ("Candidates Expanded", "#8b5cf6"),
    ("Candidates Accepted", "#22c55e"),
    ("Scenarios Generated", "#f59e0b"),
    ("In Report", "#6366f1"),
]
"""Display names and colors for the pipeline funnel steps."""


def _parse_dt(value: Any) -> datetime | None:
    """Parse *value* with the accepted timestamp formats, or None."""
    for fmt in _FUNNEL_TS_FORMATS:
        try:
            return datetime.strptime(str(value), fmt)  # noqa: DTZ007
        except ValueError:
            continue
    return None


def _format_duration(ts_start: Any, ts_end: Any) -> str:
    """Format the run duration between two timestamps, or empty on failure."""
    try:
        dt_start = _parse_dt(ts_start)
        dt_end = _parse_dt(ts_end)
        if dt_start and dt_end:
            delta = dt_end - dt_start
            total_secs = int(delta.total_seconds())
            mins, secs = divmod(abs(total_secs), 60)
            hours, mins = divmod(mins, 60)
            if hours > 0:
                return f"{hours}h {mins}m {secs}s"
            return f"{mins}m {secs}s"
    except Exception:  # noqa: BLE001, S110
        pass
    return ""


def _build_funnel_html(
    funnel_steps: list[tuple[str, Any, str]],
) -> str:
    """Render funnel stat cards separated by arrow glyphs."""
    funnel_html = ""
    for i, (label, count, color) in enumerate(funnel_steps):
        arrow = (
            '<span style="color:var(--text-muted);font-size:18px;'
            'margin:0 4px;">&#8594;</span>'
            if i < len(funnel_steps) - 1
            else ""
        )
        funnel_html += (
            f'<div class="stat-card" style="border-left-color:{color};">'
            f'<span class="stat-number">{count}</span>'
            f'<span class="stat-label">{_esc(label)}</span>'
            f"</div>"
            f"{arrow}"
        )
    return funnel_html


def _display_timestamp(value: Any) -> str:
    """Format a run timestamp (strip microseconds), or 'N/A'."""
    return str(value).split(".")[0] if value else "N/A"


def _rejection_rate_label(rejected: int, expanded: int) -> str:
    """Format the funnel rejection rate, or 'N/A' when nothing was expanded."""
    return f"{rejected / expanded * 100:.1f}%" if expanded > 0 else "N/A"


def _duration_card_html(duration_str: str) -> str:
    """Render the duration stat card, or empty when unavailable."""
    if not duration_str:
        return ""
    return (
        '<div class="stat-card" style="border-left-color:#6b7280;">'
        f'<span class="stat-number" style="font-size:20px;">'
        f"{_esc(duration_str)}</span>"
        '<span class="stat-label">Duration</span>'
        "</div>"
    )


def _outcome_summary_html(
    high_count: int,
    medium_count: int,
    low_count: int,
    coverage_gaps: int | None,
) -> str:
    """Render the outcome summary card with priority donut and gap card."""
    total_priority = high_count + medium_count + low_count
    high_pct = (high_count / total_priority * 100) if total_priority else 0
    medium_pct = (medium_count / total_priority * 100) if total_priority else 0
    donut_gradient = (
        f"conic-gradient("
        f"var(--high) 0% {high_pct:.1f}%, "
        f"var(--medium) {high_pct:.1f}% {high_pct + medium_pct:.1f}%, "
        f"var(--low) {high_pct + medium_pct:.1f}% 100%"
        f")"
    )
    coverage_card = ""
    if coverage_gaps is not None:
        coverage_card = (
            '<div class="coverage-gap-card">'
            f'<span class="stat-number">{coverage_gaps}</span>'
            '<span class="stat-label">Coverage Gaps</span>'
            "</div>"
        )

    return f"""
      <div class="card">
        <div class="scenario-section-title">Outcome Summary</div>
        <div class="stats-bar">
          <div class="stat-card" style="border-left-color:var(--high);">
            <span class="stat-number">{high_count}</span>
            <span class="stat-label">High Priority</span>
          </div>
          <div class="stat-card" style="border-left-color:var(--medium);">
            <span class="stat-number">{medium_count}</span>
            <span class="stat-label">Medium Priority</span>
          </div>
          <div class="stat-card" style="border-left-color:var(--low);">
            <span class="stat-number">{low_count}</span>
            <span class="stat-label">Low Priority</span>
          </div>
          <div class="severity-donut" style="background:{donut_gradient};" data-tooltip="High: {high_count} | Medium: {medium_count} | Low: {low_count}"></div>
          {coverage_card}
        </div>
      </div>
    """


def build_run_summary_section(
    manifest: dict[str, Any],
    scenarios_in_report: int,
    *,
    high_count: int = 0,
    medium_count: int = 0,
    low_count: int = 0,
    coverage_gaps: int | None = None,
) -> str:
    """Build a Run Summary section showing pipeline funnel metrics.

    Args:
        manifest: Parsed ``run-manifest.yaml`` dict.
        scenarios_in_report: Count of scenarios actually rendered in the report.
        high_count: Number of HIGH priority scenarios (composite >= 0.7).
        medium_count: Number of MEDIUM priority scenarios (0.4 <= composite < 0.7).
        low_count: Number of LOW priority scenarios (composite < 0.4).
        coverage_gaps: Total coverage gaps count, or *None* if unavailable.

    Returns:
        HTML string for the run summary section, or empty string if manifest
        is empty/None.
    """
    if not manifest:
        return ""

    seeds = manifest.get("seeds_generated", 0)
    funnel = manifest.get("funnel", {})
    expanded = funnel.get("expanded_instances", manifest.get("candidates_expanded", 0))
    accepted = funnel.get("filter_accepted", manifest.get("candidates_accepted", 0))
    # Derive rejected count from funnel fields, not list lengths.
    rejected = funnel.get(
        "rule_rejected",
        0,
    ) + max(funnel.get("filter_submitted", 0) - funnel.get("filter_accepted", 0), 0)
    generated = manifest.get("scenarios_generated", 0)
    failed = manifest.get("scenarios_failed", 0)

    # Rejection rate
    rejection_rate = _rejection_rate_label(rejected, expanded)

    # Config
    config = manifest.get("config", {})
    model_name = _esc(str(config.get("model", "unknown")))
    temperature = config.get("temperature", "N/A")

    # Timestamps & duration
    ts_start = manifest.get("timestamp_start", "")
    ts_end = manifest.get("timestamp_end", "")
    duration_str = _format_duration(ts_start, ts_end)

    # Format timestamps for display (strip microseconds)
    display_start = _display_timestamp(ts_start)
    display_end = _display_timestamp(ts_end)

    # Build funnel steps
    funnel_steps = [
        ("Seeds Generated", seeds, "#3b82f6"),
        ("Candidates Expanded", expanded, "#8b5cf6"),
        ("Candidates Accepted", accepted, "#22c55e"),
        ("Scenarios Generated", generated, "#f59e0b"),
        ("In Report", scenarios_in_report, "#6366f1"),
    ]

    funnel_html = _build_funnel_html(funnel_steps)

    # Secondary stats
    duration_card = _duration_card_html(duration_str)

    priority_html = _outcome_summary_html(
        high_count, medium_count, low_count, coverage_gaps
    )

    return f"""
    <div id="sec-run-summary" class="section">
      <div class="section-header">
        <h2>Run Summary</h2>
      </div>

      <div class="card">
        <div class="scenario-section-title">Pipeline Funnel</div>
        <div class="stats-bar" style="align-items:center;">
          {funnel_html}
        </div>
      </div>

      {priority_html}

      <div class="stats-bar">
        <div class="stat-card" style="border-left-color:#ef4444;">
          <span class="stat-number">{failed}</span>
          <span class="stat-label">Failed</span>
        </div>
        <div class="stat-card" style="border-left-color:#f97316;">
          <span class="stat-number">{rejected}</span>
          <span class="stat-label">Rejected</span>
        </div>
        <div class="stat-card" style="border-left-color:#f97316;">
          <span class="stat-number" style="font-size:20px;">{rejection_rate}</span>
          <span class="stat-label">Rejection Rate</span>
        </div>
        {duration_card}
      </div>

      <div class="card" style="background:var(--bg-secondary);">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;font-size:13px;">
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Model</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{model_name}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Temperature</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{temperature}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Start</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{_esc(display_start)}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">End</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{_esc(display_end)}</div>
          </div>
        </div>
      </div>
    </div>
    """
