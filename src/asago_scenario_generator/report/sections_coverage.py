"""Coverage Analysis section and helper builders."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    ZONE_DISPLAY_NAMES,
    _normalize_zone,
)


def _coverage_status(count: int) -> tuple[str, str]:
    """Return (css_class, label) based on the number of uncovered items."""
    if count == 0:
        return "coverage-status-green", "Covered"
    if count <= 2:
        return "coverage-status-amber", f"{count} gap{'s' if count != 1 else ''}"
    return "coverage-status-red", f"{count} gaps"


_GAP_REASON_LABELS: dict[str, str] = {
    "deterministic_rule_rejection": "rejected by deterministic rules",
    "filter_rejection": "filtered out by LLM filter",
    "projection_rejection": "no compatible projection",
    "selection_limitation": "cap overflow (coverage preserved)",
    "generation_exhaustion": "generation exhausted",
    "admission_failure": "admission failure",
    "projection_limitation": "projection budget limit",
    "no_seed": "no seed generated",
    "no_candidate": "no candidate expanded",
    "rejected": "filtered out",
    "generation_failed": "generation failed",
    "out_of_scope": "out of scope",
}

# Category cards for the cmps.4 coverage summary, in render order.
_COVERAGE_CATEGORY_SPECS: list[tuple[str, str, str]] = [
    ("Covered Feasible Targets", "covered_feasible", "coverage-status-green"),
    ("Policy Exclusions", "policy_exclusions", ""),
    ("Structural / Projection Gaps", "structural_gaps", "coverage-status-red"),
    ("Selection Limitations", "selection_limitations", "coverage-status-amber"),
    ("Runtime Generation Gaps", "runtime_generation_gaps", "coverage-status-red"),
    (
        "Quarantine / Admission Failures",
        "quarantine_admission_failures",
        "coverage-status-red",
    ),
    ("Projection Limitations", "projection_limitations", "coverage-status-amber"),
]

_EMPTY_COVERAGE_MESSAGES: dict[str, str] = {
    "uncovered_zones": "All active zones are traversed by scenarios.",
    "uncovered_threats": "All in-scope threats have scenario coverage.",
    "uncovered_attack_patterns": "All in-scope attack patterns have scenario coverage.",
}


def _attribution_span(reason: str) -> str:
    """Return an HTML span with a human-readable attribution label."""
    label = _GAP_REASON_LABELS.get(reason, reason)
    return f' <span class="coverage-reason">{_esc(label)}</span>'


def _ep_item_html(ep: Any, ep_attributions: dict[str, str]) -> str:
    """Render one uncovered entry-point list item with attribution span."""
    if isinstance(ep, dict):
        name = ep.get("name", "")
        ep_id = ep.get("entry_point_id", "")
        attr = ep_attributions.get(ep_id, "")
    else:
        # Legacy string fallback.
        name = str(ep)
        attr = ep_attributions.get(ep, "")
    attr_span = _attribution_span(attr) if attr else ""
    return f"<li>{_esc(name)}{attr_span}</li>"


def _entry_point_body_html(
    uncovered_eps: list[Any],
    ep_attributions: dict[str, str],
    completeness: str,
) -> str:
    """Render the entry-point card body for uncovered or covered states."""
    if uncovered_eps:
        ep_items = "".join(_ep_item_html(ep, ep_attributions) for ep in uncovered_eps)
        return f'<ul class="coverage-list">{ep_items}</ul>'
    if completeness == "confirmed_complete":
        message = "All confirmed entry points have scenario coverage."
    else:
        message = (
            "All identified feasible entry points have scenario coverage; "
            "inventory completeness is not confirmed."
        )
    return f'<div class="coverage-empty">{message}</div>'


def _zone_items_body_html(uncovered_zones: list[Any]) -> str:
    """Render the zone card body for uncovered or covered states."""
    if uncovered_zones:
        z_items = "".join(
            f"<li>{_esc(ZONE_DISPLAY_NAMES.get(_normalize_zone(z), str(z)))}</li>"
            for z in uncovered_zones
        )
        return f'<ul class="coverage-list">{z_items}</ul>'
    return (
        '<div class="coverage-empty">All active zones are traversed by scenarios.</div>'
    )


def _plain_items_body_html(items: list[Any], empty_message: str) -> str:
    """Render a name-list card body for uncovered or covered states."""
    if items:
        item_html = "".join(f"<li>{_esc(item)}</li>" for item in items)
        return f'<ul class="coverage-list">{item_html}</ul>'
    return f'<div class="coverage-empty">{empty_message}</div>'


def _coverage_card_html(title: str, cls: str, label: str, body: str) -> str:
    """Render one coverage summary card."""
    return f"""
        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">{title}</span>
            <span class="coverage-status {cls}">{label}</span>
          </div>
          {body}
        </div>"""


def _cat_item_primary(item: dict[str, Any]) -> str:
    """Return the display name of a categorized coverage summary item."""
    return (
        item.get("entry_point_name")
        or item.get("name")
        or item.get("entry_point_id")
        or ""
    )


def _cat_item_html(item: Any) -> str:
    """Render one categorized coverage summary list item."""
    if isinstance(item, dict):
        reason = item.get("reason")
        reason_span = _attribution_span(reason) if reason else ""
        detail = item.get("detail")
        detail_span = (
            f' <span class="coverage-reason">{_esc(detail)}</span>' if detail else ""
        )
        candidate_ids = item.get("candidate_ids") or []
        cand_span = (
            f' <code class="candidate-id">{_esc(", ".join(candidate_ids))}</code>'
            if candidate_ids
            else ""
        )
        return (
            f"<li>{_esc(_cat_item_primary(item))}{reason_span}"
            f"{detail_span}{cand_span}</li>"
        )
    return f"<li>{_esc(str(item))}</li>"


def _cat_card(title: str, items: list, css_cls: str = "") -> str:
    """Render one classified coverage card (policy/structural/selection/...)."""
    if not items:
        return ""
    parts = "".join(_cat_item_html(item) for item in items)
    return (
        f'<div class="coverage-card">'
        f'<div class="coverage-card-header">'
        f'<span class="coverage-card-title">{_esc(title)}</span>'
        f'<span class="coverage-status {css_cls}">{len(items)}</span>'
        f'</div><ul class="coverage-list">{parts}</ul></div>'
    )


def _build_coverage_summary_html(summary: dict[str, Any]) -> str:
    """Render the categorized coverage summary grid, or empty when absent."""
    if not summary:
        return ""
    cat_cards = []
    for title, key, css_cls in _COVERAGE_CATEGORY_SPECS:
        items = summary.get(key, [])
        if items:
            cat_cards.append(_cat_card(title, items, css_cls))
    if not cat_cards:
        return ""
    return (
        '<div class="coverage-grid" style="margin-top:1rem">'
        + "".join(cat_cards)
        + "</div>"
    )


def _build_coverage_plan_html(plan: dict[str, Any]) -> str:
    """Render the coverage plan table, or empty when absent."""
    if not plan or not plan.get("targets"):
        return ""
    plan_rows = []
    for entry in plan["targets"]:
        ep_name = entry.get("entry_point_name", "")
        primary = entry.get("primary_candidate_id") or "—"
        state = entry.get("primary_state", "—")
        fb_count = len(entry.get("fallback_available", []))
        choices = entry.get("ordered_choices", [])
        choice_ids = [c.get("candidate_id", "") for c in choices]
        plan_rows.append(
            f"<tr><td>{_esc(ep_name)}</td><td>{_esc(primary)}</td>"
            f"<td>{_esc(state)}</td>"
            f"<td>{_esc(', '.join(choice_ids))}</td>"
            f"<td>{fb_count}</td></tr>"
        )
    return (
        '<div style="margin-top:1rem">'
        "<h3>Coverage Plan (schema v"
        + _esc(str(plan.get("schema_version", "")))
        + ")</h3>"
        '<table class="data-table"><thead><tr>'
        "<th>Target</th><th>Primary Candidate</th><th>State</th>"
        "<th>Ordered Choices</th><th>Fallback Available</th>"
        "</tr></thead><tbody>" + "".join(plan_rows) + "</tbody></table></div>"
    )


def _feasible_target_items(feasible_targets: list[dict[str, Any]]) -> str:
    """Render the feasible-target coverage list items."""
    return "".join(
        f"<li>{_esc(t.get('name', t.get('entry_point_id', '')))}"
        f" <code>{_esc(t.get('entry_point_id', ''))}</code>"
        f" <span class='coverage-status coverage-status-green'>"
        f"{_esc(t.get('direction', ''))}/{_esc(t.get('controllability', ''))}"
        f"</span></li>"
        for t in feasible_targets
    )


def _excluded_target_items(excluded_targets: list[dict[str, Any]]) -> str:
    """Render the excluded-target coverage list items."""
    return "".join(
        f"<li>{_esc(e.get('name', e.get('entry_point_id', '')))}"
        f" <span class='coverage-status coverage-status-red'>"
        f"{_esc(e.get('reason', ''))}</span></li>"
        for e in excluded_targets
    )


def _universe_evidence_html(evidence_refs: list[str]) -> str:
    """Render the inventory-completeness evidence line."""
    if evidence_refs:
        return (
            "<div class='coverage-empty'>Evidence: "
            + ", ".join(_esc(e) for e in evidence_refs)
            + "</div>"
        )
    return "<div class='coverage-empty'>No operator-confirmed evidence</div>"


def _completeness_parts(completeness: str) -> tuple[str, str]:
    """Return (label, css_class) for the inventory completeness status."""
    if completeness == "confirmed_complete":
        return "Confirmed Complete", "coverage-status-green"
    return "Not Applicable (Inferred Partial)", "coverage-status-amber"


def _build_coverage_universe_html(
    universe_data: dict[str, Any],
    completeness: str,
) -> str:
    """Render the coverage universe block, or empty when absent."""
    if not universe_data:
        return ""
    evidence_refs = universe_data.get("evidence_refs", [])
    feasible_targets = universe_data.get("feasible_targets", [])
    excluded_targets = universe_data.get("excluded_targets", [])

    completeness_label, completeness_cls = _completeness_parts(completeness)

    # Bounded canonical target set.
    target_items = _feasible_target_items(feasible_targets)
    excluded_items = _excluded_target_items(excluded_targets)
    evidence_html = _universe_evidence_html(evidence_refs)

    return (
        '<div style="margin-top:1rem">'
        "<h3>Coverage Universe</h3>"
        '<div class="coverage-card">'
        '<div class="coverage-card-header">'
        '<span class="coverage-card-title">Inventory Completeness</span>'
        f'<span class="coverage-status {completeness_cls}">'
        f"{_esc(completeness_label)}</span>"
        "</div>"
        f"{evidence_html}"
        "</div>"
        '<div class="coverage-grid" style="margin-top:0.5rem">'
        f'<div class="coverage-card">'
        '<div class="coverage-card-header">'
        f'<span class="coverage-card-title">'
        f"Feasible Targets ({len(feasible_targets)})</span>"
        '</div><ul class="coverage-list">' + target_items + "</ul></div>"
        f'<div class="coverage-card">'
        '<div class="coverage-card-header">'
        f'<span class="coverage-card-title">'
        f"Excluded Targets ({len(excluded_targets)})</span>"
        '</div><ul class="coverage-list">' + excluded_items + "</ul></div>"
        "</div></div>"
    )


def build_coverage_section(coverage_data: dict[str, Any]) -> str:
    """Build the Coverage Gaps section from loaded coverage-gaps.json data.

    Args:
        coverage_data: Parsed JSON from ``coverage-gaps.json``.

    Returns:
        HTML string for the coverage gaps section.
    """
    gaps = coverage_data.get("coverage_gaps", {})
    uncovered_eps = gaps.get("uncovered_entry_points", [])
    uncovered_zones = gaps.get("uncovered_zones", [])
    uncovered_threats = gaps.get("uncovered_threats", [])
    uncovered_aps = gaps.get("uncovered_attack_patterns", [])
    universe_data = coverage_data.get("coverage_universe", {})
    completeness = universe_data.get("completeness", "not_applicable")
    attributions = gaps.get("gap_attributions", {})
    ep_attributions = attributions.get("entry_points", {})

    total_gaps = (
        len(uncovered_eps)
        + len(uncovered_zones)
        + len(uncovered_threats)
        + len(uncovered_aps)
    )

    # Per-card status and body.
    ep_cls, ep_label = _coverage_status(len(uncovered_eps))
    ep_body = _entry_point_body_html(uncovered_eps, ep_attributions, completeness)

    z_cls, z_label = _coverage_status(len(uncovered_zones))
    z_body = _zone_items_body_html(uncovered_zones)

    t_cls, t_label = _coverage_status(len(uncovered_threats))
    t_body = _plain_items_body_html(
        uncovered_threats,
        _EMPTY_COVERAGE_MESSAGES["uncovered_threats"],
    )

    ap_cls, ap_label = _coverage_status(len(uncovered_aps))
    ap_body = _plain_items_body_html(
        uncovered_aps,
        _EMPTY_COVERAGE_MESSAGES["uncovered_attack_patterns"],
    )

    # Overall status badge
    if total_gaps == 0:
        badge_text = (
            "Full Coverage"
            if completeness == "confirmed_complete"
            else "Known Targets Covered"
        )
    else:
        badge_text = f"{total_gaps} gap{'s' if total_gaps != 1 else ''}"

    summary_html = _build_coverage_summary_html(
        coverage_data.get("coverage_summary", {})
    )
    plan_html = _build_coverage_plan_html(coverage_data.get("coverage_plan", {}))
    universe_html = _build_coverage_universe_html(universe_data, completeness)

    return f"""
    <div id="sec-coverage" class="section">
      <div class="section-header">
        <h2>Coverage Analysis</h2>
        <span class="badge">{badge_text}</span>
      </div>

      <div class="coverage-grid">
        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Entry Points</span>
            <span class="coverage-status {ep_cls}">{ep_label}</span>
          </div>
          {ep_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Active Zones</span>
            <span class="coverage-status {z_cls}">{z_label}</span>
          </div>
          {z_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">In-Scope Threats</span>
            <span class="coverage-status {t_cls}">{t_label}</span>
          </div>
          {t_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Attack Patterns</span>
            <span class="coverage-status {ap_cls}">{ap_label}</span>
          </div>
          {ap_body}
        </div>
      </div>
      {summary_html}
      {universe_html}
      {plan_html}
    </div>
    """
