"""Scenario dashboard, filters, and coverage matrix builders."""

from __future__ import annotations

import math
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    THREAT_NAMES,
    ZONE_COLORS,
    ZONE_DISPLAY_NAMES,
    _normalize_zone,
)
from asago_scenario_generator.report.scenario_common import (
    _SIGNAL_COLORS,
    _SIGNAL_NUMERIC,
    _hex_to_rgb_css,
    _priority_label,
    _usage_call_label,
    _usage_metrics,
)
from asago_scenario_generator.report.sections_scenario_cards import _build_scenario_card


def _priority_counts(scenarios: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Count scenarios by HIGH/MEDIUM/LOW composite priority."""
    high_count = 0
    medium_count = 0
    low_count = 0
    for s in scenarios:
        composite = s.get("priority", {}).get("composite", 0)
        label = _priority_label(composite)
        if label == "HIGH":
            high_count += 1
        elif label == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1
    return high_count, medium_count, low_count


def _donut_gradient(high_count: int, medium_count: int, total_count: int) -> str:
    """Build the conic-gradient CSS used by the severity donut."""
    high_pct = (high_count / total_count * 100) if total_count else 0
    medium_pct = (medium_count / total_count * 100) if total_count else 0
    return (
        f"conic-gradient("
        f"var(--high) 0% {high_pct:.1f}%, "
        f"var(--medium) {high_pct:.1f}% {high_pct + medium_pct:.1f}%, "
        f"var(--low) {high_pct + medium_pct:.1f}% 100%"
        f")"
    )


def _record_scenario_coverage(
    coverage_counts: dict[tuple[str, str], int],
    all_threat_ids: list[str],
    all_zones: set[str],
    scenario_threats: list[str],
    scenario_zones: list[str],
) -> None:
    """Record one scenario's threat/zone coverage and dedupe the id lists."""
    for tid in scenario_threats:
        if tid not in all_threat_ids:
            all_threat_ids.append(tid)
    for z in scenario_zones:
        all_zones.add(z)
    # Build coverage matrix counts
    for tid in scenario_threats:
        for z in scenario_zones:
            coverage_counts[(tid, z)] = coverage_counts.get((tid, z), 0) + 1


def _canonical_zone_order(all_zones: set[str]) -> list[str]:
    """Return the canonical zone order filtered to present zones."""
    return [z for z in ZONE_COLORS if z in all_zones]


def _covered_combos(
    coverage_counts: dict[tuple[str, str], int],
    sorted_threats: list[str],
    canonical_zones: list[str],
) -> int:
    """Count threat x zone combos that have at least one scenario."""
    covered = 0
    for t in sorted_threats:
        for z in canonical_zones:
            if coverage_counts.get((t, z), 0) > 0:
                covered += 1
    return covered


def _collect_coverage_metrics(
    scenarios: list[dict[str, Any]],
) -> tuple[list[str], list[str], dict[tuple[str, str], int], int]:
    """Collect threat/zone coverage sets, counts, and the gap count."""
    all_threat_ids: list[str] = []
    all_zones: set[str] = set()
    # Per-scenario threat-zone pairs for coverage matrix
    coverage_counts: dict[tuple[str, str], int] = {}
    for s in scenarios:
        fac = s.get("faceting", {})
        tc = fac.get("taxonomy_chain", {})
        cp = fac.get("capability_profile", {})
        scenario_threats = tc.get("agentic_threat_ids", [])
        scenario_zones = [_normalize_zone(z) for z in cp.get("zones_traversed", [])]
        _record_scenario_coverage(
            coverage_counts,
            all_threat_ids,
            all_zones,
            scenario_threats,
            scenario_zones,
        )

    sorted_threats = sorted(all_threat_ids)
    # Use canonical zone order, filtered to zones present in scenarios
    canonical_zones = _canonical_zone_order(all_zones)

    # Coverage gap: threat x zone combos with 0 scenarios
    total_combos = len(sorted_threats) * len(canonical_zones) if canonical_zones else 0
    covered_combos = _covered_combos(coverage_counts, sorted_threats, canonical_zones)
    coverage_gaps = total_combos - covered_combos
    return sorted_threats, canonical_zones, coverage_counts, coverage_gaps


def _dashboard_html(
    total_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    coverage_gaps: int,
    scenarios_generated: int | None,
) -> str:
    """Build the dashboard header HTML (Bead 1)."""
    donut_gradient = _donut_gradient(high_count, medium_count, total_count)
    return f"""
      <div class="stats-bar">
        <div class="stat-card" style="border-left-color:var(--accent);">
          <span class="stat-number">{total_count}</span>
          <span class="stat-label">In Report</span>
          {"" if scenarios_generated is None or scenarios_generated == total_count else f'<span class="stat-sublabel" style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">of {scenarios_generated} generated</span>'}
        </div>
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
        <div class="coverage-gap-card">
          <span class="stat-number">{coverage_gaps}</span>
          <span class="stat-label">Coverage Gaps</span>
        </div>
      </div>
    """


def _signal_segments_html(signals: dict[str, Any]) -> str:
    """Build the stacked signal segments for one scenario's bar."""
    segments = ""
    total_numeric = 0.0
    segment_values: list[tuple[str, str, str, float, str]] = []
    for sig_key, sig_color, sig_label in _SIGNAL_COLORS:
        raw_val = str(signals.get(sig_key, ""))
        mapping = _SIGNAL_NUMERIC.get(sig_key, {})
        numeric = mapping.get(raw_val, 0.0)
        total_numeric += numeric
        segment_values.append((sig_key, sig_color, sig_label, numeric, raw_val))

    # Normalise segment widths so total bar fills proportional to
    # composite score — each segment is (numeric / total) * 100% of
    # the bar track, and the track itself is scaled by composite.
    for sig_key, sig_color, sig_label, numeric, raw_val in segment_values:
        if total_numeric > 0 and numeric > 0:
            pct = (numeric / total_numeric) * 100
            display_val = raw_val.replace("_", " ") if raw_val else "n/a"
            segments += (
                f'<div class="signal-segment"'
                f' style="width:{pct:.1f}%;background:{sig_color};">'
                f'<span class="tooltip">'
                f"{_esc(sig_label)}: {_esc(display_val)}"
                f"</span>"
                f"</div>"
            )
    return segments


def _signal_rows_html(sorted_scenarios: list[dict[str, Any]]) -> str:
    """Build the per-scenario priority signal bar rows."""
    signal_rows = ""
    for s in sorted_scenarios:
        sid = s.get("scenario_id", "")
        priority = s.get("priority", {})
        composite = priority.get("composite", 0)
        signals = priority.get("signals", {})
        short_id = sid.split("-")[-1][:6] if "-" in sid else sid[:6]

        segments = _signal_segments_html(signals)
        bar_width_pct = composite * 100

        signal_rows += (
            f'<div class="signal-bar-row">'
            f'<div class="signal-bar-label"'
            f' title="{_esc(s.get("narrative", {}).get("title", sid))}">'
            f"{_esc(short_id)}</div>"
            f'<div class="signal-bar-track"'
            f' style="max-width:{bar_width_pct:.0f}%;">'
            f"{segments}</div>"
            f'<div class="signal-bar-score">{composite:.2f}</div>'
            f"</div>"
        )
    return signal_rows


def _signal_legend_html() -> str:
    """Build the signal legend items."""
    signal_legend_items = ""
    for _key, color, label in _SIGNAL_COLORS:
        signal_legend_items += (
            f'<span class="signal-legend-item">'
            f'<span class="signal-legend-dot"'
            f' style="background:{color};"></span>'
            f"{_esc(label)}</span>"
        )
    return signal_legend_items


def _matrix_header_html(canonical_zones: list[str]) -> str:
    """Build the coverage matrix header row (corner + zone names)."""
    header = '<div class="matrix-header"></div>'
    for z in canonical_zones:
        zcolor = ZONE_COLORS.get(z, "#666")
        display = ZONE_DISPLAY_NAMES.get(z, z)
        header += (
            f'<div class="matrix-header"'
            f' style="background:rgba({_hex_to_rgb_css(zcolor)},0.15);'
            f'color:{zcolor};">{_esc(display)}</div>'
        )
    return header


def _matrix_row_html(
    tid: str,
    canonical_zones: list[str],
    coverage_counts: dict[tuple[str, str], int],
    max_count: int,
) -> str:
    """Build one coverage matrix data row for a threat."""
    tname = THREAT_NAMES.get(tid, "")
    row_label = f"{tid}"
    row_tooltip = f"{tid} — {tname}" if tname else tid
    row_html = (
        f'<div class="matrix-row-label"'
        f' data-tooltip="{_esc(row_tooltip)}">{_esc(row_label)}</div>'
    )
    for z in canonical_zones:
        count = coverage_counts.get((tid, z), 0)
        zcolor = ZONE_COLORS.get(z, "#666")
        if count > 0:
            opacity = 0.2 + 0.8 * (count / max_count)
            row_html += (
                f'<div class="matrix-cell"'
                f" onclick=\"filterByCell('{_esc(tid)}','{_esc(z)}')\""
                f' style="background:rgba({_hex_to_rgb_css(zcolor)},'
                f'{opacity:.2f});"'
                f' data-tooltip="{_esc(tid)} x'
                f" {_esc(ZONE_DISPLAY_NAMES.get(z, z))}:"
                f' {count} scenario{"s" if count != 1 else ""}">'
                f"{count}</div>"
            )
        else:
            row_html += (
                f'<div class="matrix-cell empty"'
                f' data-tooltip="{_esc(tid)} x'
                f" {_esc(ZONE_DISPLAY_NAMES.get(z, z))}:"
                f' no scenarios">0</div>'
            )
    return row_html


def _coverage_matrix_html(
    sorted_threats: list[str],
    canonical_zones: list[str],
    coverage_counts: dict[tuple[str, str], int],
) -> str:
    """Build the coverage heatmap matrix (Bead 2), or empty when absent."""
    matrix_html = ""
    if sorted_threats and canonical_zones:
        max_count = max(coverage_counts.values()) if coverage_counts else 1
        matrix_html += (
            f'<div class="scenario-section-title" style="margin-top:24px;"'
            f' data-tooltip="Click a cell to filter scenarios by that threat'
            f' and zone combination">Threat x Zone Coverage</div>'
            f'<div class="coverage-matrix" style="grid-template-columns:'
            f' 140px repeat({len(canonical_zones)}, 1fr);">'
        )
        matrix_html += _matrix_header_html(canonical_zones)
        for tid in sorted_threats:
            matrix_html += _matrix_row_html(
                tid, canonical_zones, coverage_counts, max_count
            )
        matrix_html += "</div>"
    return matrix_html


def _ep_distribution_html(scenarios: list[dict[str, Any]]) -> str:
    """Build the entry point distribution card, or empty when absent."""
    ep_counts: dict[str, int] = {}
    for s in scenarios:
        ep = s.get("narrative", {}).get("entry_point", "")
        if ep:
            ep_counts[ep] = ep_counts.get(ep, 0) + 1

    ep_dist_items = ""
    for ep_name, ep_count in sorted(
        ep_counts.items(), key=lambda x: x[1], reverse=True
    ):
        ep_dist_items += (
            f'<div class="ep-dist-item">'
            f'<span class="ep-dist-name" data-tooltip="{_esc(ep_name)}">'
            f"{_esc(ep_name)}</span>"
            f'<span class="ep-dist-count">{ep_count}</span>'
            f"</div>"
        )

    if ep_counts:
        return f"""
      <div class="card" style="margin-bottom:24px;">
        <div class="scenario-section-title">Entry Point Distribution</div>
        <div class="ep-dist-grid">{ep_dist_items}</div>
      </div>"""
    return ""


def _threat_chips_html(sorted_threats: list[str]) -> str:
    """Build the threat filter chips (Bead 3)."""
    threat_chips = ""
    for tid in sorted_threats:
        tname = THREAT_NAMES.get(tid, "")
        chip_label = f"{tid} — {tname}" if tname else tid
        threat_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="threat" data-filter-value="{_esc(tid)}"'
            f' data-active-bg="rgba({_hex_to_rgb_css("#6366f1")},0.25)"'
            f' data-active-color="#6366f1"'
            f' style="border-color:#6366f1;color:#6366f1;background:transparent;">'
            f"{_esc(chip_label)}</span>"
        )
    return threat_chips


def _zone_chips_html(canonical_zones: list[str]) -> str:
    """Build the zone filter chips (Bead 3)."""
    zone_chips = ""
    for z in canonical_zones:
        zcolor = ZONE_COLORS.get(z, "#666")
        display = ZONE_DISPLAY_NAMES.get(z, z)
        zone_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="zone" data-filter-value="{_esc(z)}"'
            f' data-active-bg="rgba({_hex_to_rgb_css(zcolor)},0.25)"'
            f' data-active-color="{zcolor}"'
            f' style="border-color:{zcolor};color:{zcolor};background:transparent;">'
            f"{_esc(display)}</span>"
        )
    return zone_chips


def _priority_chips_html() -> str:
    """Build the priority filter chips (Bead 3)."""
    priority_chip_data = [
        ("high", "High", "#ef4444"),
        ("medium", "Medium", "#f59e0b"),
        ("low", "Low", "#22c55e"),
    ]
    priority_chips = ""
    for pval, plabel, pcolor in priority_chip_data:
        priority_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="priority" data-filter-value="{pval}"'
            f' data-active-bg="rgba({_hex_to_rgb_css(pcolor)},0.25)"'
            f' data-active-color="{pcolor}"'
            f' style="border-color:{pcolor};color:{pcolor};background:transparent;">'
            f"{plabel}</span>"
        )
    return priority_chips


def _filter_bar_html(
    threat_chips: str,
    zone_chips: str,
    priority_chips: str,
) -> str:
    """Build the chip/tag filter bar (Bead 3)."""
    return f"""
      <div class="filter-bar" style="margin-top:24px;flex-direction:column;align-items:flex-start;gap:10px;">
        <div style="display:flex;align-items:center;gap:8px;width:100%;justify-content:space-between;">
          <span style="font-size:12px;font-weight:600;color:var(--text-primary);">Filters</span>
          <button class="filter-btn" onclick="resetFilters()">Clear All</button>
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Threats</span>
          {threat_chips}
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Zones</span>
          {zone_chips}
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Priority</span>
          {priority_chips}
        </div>
      </div>
    """


def _collect_call_metrics(
    call_logs: dict[str, list[dict]],
) -> tuple[list[float], list[float], list[float]]:
    """Collect duration/token samples across all call-log entries."""
    all_durations: list[float] = []
    all_prompt_tokens: list[float] = []
    all_completion_tokens: list[float] = []
    for _sid, _entries in call_logs.items():
        for _idx, _e in enumerate(_entries):
            _metrics = _usage_metrics(
                _e,
                call_label=_usage_call_label(_e, _idx),
            )
            if _metrics["duration_ms"] is not None:
                all_durations.append(float(_metrics["duration_ms"]))
            if _metrics["prompt_tokens"] is not None:
                all_prompt_tokens.append(float(_metrics["prompt_tokens"]))
            if _metrics["completion_tokens"] is not None:
                all_completion_tokens.append(float(_metrics["completion_tokens"]))
    return all_durations, all_prompt_tokens, all_completion_tokens


def _mean_std(vals: list[float]) -> tuple[float, float]:
    """Return the (mean, population standard deviation) of *vals*."""
    n = len(vals)
    m = sum(vals) / n
    variance = sum((v - m) ** 2 for v in vals) / n
    return m, math.sqrt(variance)


def _sufficient_samples(
    durations: list[float], prompt_tokens: list[float], completion_tokens: list[float]
) -> bool:
    """Return whether at least three samples exist per anomaly metric."""
    return (
        len(durations) >= 3 and len(prompt_tokens) >= 3 and len(completion_tokens) >= 3
    )


def _call_stats(call_logs: dict[str, list[dict]] | None) -> dict[str, float] | None:
    """Compute duration/token anomaly thresholds, or None when insufficient."""
    _call_logs = call_logs or {}
    all_durations, all_prompt_tokens, all_completion_tokens = _collect_call_metrics(
        _call_logs
    )
    if not _sufficient_samples(all_durations, all_prompt_tokens, all_completion_tokens):
        return None
    dur_mean, dur_std = _mean_std(all_durations)
    pt_mean, pt_std = _mean_std(all_prompt_tokens)
    ct_mean, ct_std = _mean_std(all_completion_tokens)
    return {
        "dur_mean": dur_mean,
        "dur_std": dur_std,
        "pt_mean": pt_mean,
        "pt_std": pt_std,
        "ct_mean": ct_mean,
        "ct_std": ct_std,
    }


def build_scenarios_section(
    scenarios: list[dict[str, Any]],
    feature_files: dict[str, str],
    call_logs: dict[str, list[dict]] | None = None,
    threat_surface: dict[str, Any] | None = None,
    capability_profile: dict[str, Any] | None = None,
    scenarios_generated: int | None = None,
    scorecard_data: dict[str, Any] | None = None,
) -> str:
    if not scenarios:
        return (
            '<div id="sec-scenarios" class="section">'
            '<div class="section-header"><h2>Scenarios</h2></div>'
            '<p style="color:var(--text-muted);">No scenarios generated.</p>'
            "</div>"
        )

    # ------------------------------------------------------------------
    # Pre-compute priority counts for the dashboard header.
    # ------------------------------------------------------------------
    total_count = len(scenarios)
    high_count, medium_count, low_count = _priority_counts(scenarios)

    # ------------------------------------------------------------------
    # Collect all threat IDs, zones, and build coverage matrix (Bead 2)
    # ------------------------------------------------------------------
    sorted_threats, canonical_zones, coverage_counts, coverage_gaps = (
        _collect_coverage_metrics(scenarios)
    )

    # ------------------------------------------------------------------
    # Dashboard header HTML (Bead 1)
    # ------------------------------------------------------------------
    dashboard_html = _dashboard_html(
        total_count,
        high_count,
        medium_count,
        low_count,
        coverage_gaps,
        scenarios_generated,
    )

    # ------------------------------------------------------------------
    # Priority signal decomposition chart
    # ------------------------------------------------------------------
    sorted_scenarios = sorted(
        scenarios,
        key=lambda sc: sc.get("priority", {}).get("composite", 0),
        reverse=True,
    )
    signal_rows = _signal_rows_html(sorted_scenarios)
    signal_chart_html = (
        f'<div class="signal-chart">{signal_rows}</div>'
        f'<div class="signal-legend">{_signal_legend_html()}</div>'
    )

    # ------------------------------------------------------------------
    # Coverage heatmap matrix (Bead 2)
    # ------------------------------------------------------------------
    matrix_html = _coverage_matrix_html(
        sorted_threats, canonical_zones, coverage_counts
    )

    # ------------------------------------------------------------------
    # Entry point distribution (existing)
    # ------------------------------------------------------------------
    ep_dist_html = _ep_distribution_html(scenarios)

    # ------------------------------------------------------------------
    # Chip/tag filters (Bead 3) — replaces the old <select> dropdowns
    # ------------------------------------------------------------------
    filter_html = _filter_bar_html(
        _threat_chips_html(sorted_threats),
        _zone_chips_html(canonical_zones),
        _priority_chips_html(),
    )

    # ------------------------------------------------------------------
    # Pre-compute LLM call stats for anomaly detection
    # ------------------------------------------------------------------
    call_stats = _call_stats(call_logs)

    # ------------------------------------------------------------------
    # Scenario cards (existing + Bead 4: collapse indicator)
    # ------------------------------------------------------------------
    cards_html = ""
    for s in scenarios:
        cards_html += _build_scenario_card(
            s,
            feature_files,
            call_logs,
            threat_surface=threat_surface,
            capability_profile=capability_profile,
            scorecard_data=scorecard_data,
            call_stats=call_stats,
        )

    return f"""
    <div id="sec-scenarios" class="section">
      <div class="section-header">
        <h2>Scenarios</h2>
        <span class="badge" id="scenario-counter">Showing all {len(scenarios)}</span>
        <button class="toggle-all-btn" id="toggle-all-btn" onclick="toggleAllCards()">Collapse All</button>
      </div>

      {dashboard_html}

      <div class="scenario-section-title" data-tooltip="Each bar decomposes a scenario's composite priority score into its 6 contributing signals. Bar width is proportional to the composite score.">Priority Signal Decomposition</div>
      {signal_chart_html}

      {matrix_html}

      {ep_dist_html}

      {filter_html}

      {cards_html}
    </div>
    """
