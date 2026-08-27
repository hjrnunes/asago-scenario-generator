"""Actor Profile Distribution section builder."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc

_DIVERSITY_COLORS: dict[str, str] = {
    "cybercriminal": "#ef4444",  # red
    "nation-state": "#1e40af",  # dark blue
    "malicious-insider": "#f97316",  # orange
    "negligent-insider": "#f59e0b",  # amber/yellow
    "competitor": "#8b5cf6",  # purple
    "hacktivist": "#22c55e",  # green
    "supply-chain-actor": "#14b8a6",  # teal
    "adversarial-user": "#ec4899",  # pink/rose
    "automated-agent": "#6b7280",  # gray
    "unknown": "#4b5563",  # dark gray
}

_GOAL_COLORS: dict[str, str] = {
    "availability": "#ef4444",
    "integrity": "#f59e0b",
    "privacy": "#8b5cf6",
    "abuse": "#0d9488",
}


def _actor_type_counts(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    """Count actor types directly from scenario dicts."""
    model_counts: dict[str, int] = {}
    for s in scenarios:
        actor_profile = s.get("actor_profile")
        if actor_profile and isinstance(actor_profile, dict):
            actor_type = actor_profile.get("actor_type", "unknown")
        else:
            actor_type = "unknown"
        model_counts[actor_type] = model_counts.get(actor_type, 0) + 1
    return model_counts


def _goal_counts(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    """Count parent goal categories across scenarios."""
    goal_counts: dict[str, int] = {}
    for s in scenarios:
        actor_profile = s.get("actor_profile")
        if actor_profile and isinstance(actor_profile, dict):
            gcp = actor_profile.get("goal_category_parent", "")
            if gcp:
                goal_counts[gcp] = goal_counts.get(gcp, 0) + 1
    return goal_counts


def _diversity_warning_html(
    dominant_model: str,
    dominant_fraction: float,
) -> str:
    """Render the low-diversity warning banner when the majority exceeds 80%."""
    if dominant_fraction <= 0.8:
        return ""
    dominant_display = dominant_model.replace("-", " ").replace("_", " ").title()
    pct = int(dominant_fraction * 100)
    return (
        '<div class="warning-banner">'
        '<span class="warning-banner-icon">&#9888;</span>'
        f"<span>Low actor diversity: {pct}% of scenarios use the "
        f"<strong>{_esc(dominant_display)}</strong> actor type. "
        f"Consider varying threat actor types for broader coverage.</span>"
        "</div>"
    )


def _diversity_bars_html(
    counts: dict[str, int],
    total: int,
    colors: dict[str, str],
) -> str:
    """Render sorted horizontal bars for a named-count distribution."""
    bars_html = ""
    for model, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        color = colors.get(model, "#6b7280")
        display_name = model.replace("-", " ").replace("_", " ").title()
        bars_html += f"""
        <div class="diversity-bar-row">
          <span class="diversity-bar-label">{_esc(display_name)}</span>
          <div class="diversity-bar-track">
            <div class="diversity-bar-fill" style="width:{pct:.0f}%;background:{color};">
              {count}
            </div>
          </div>
          <span class="diversity-bar-count">{pct:.0f}%</span>
        </div>"""
    return bars_html


def _goal_bars_html(goal_counts: dict[str, int]) -> str:
    """Render the goal category distribution block, or empty when absent."""
    if not goal_counts:
        return ""
    goal_total = sum(goal_counts.values())
    goal_bars_html = _diversity_bars_html(goal_counts, goal_total, _GOAL_COLORS)
    unique_goals = len(goal_counts)
    return f"""
      <div style="margin-top:20px;">
        <h3 style="font-size:15px;font-weight:600;margin:0 0 10px;">Goal Category Distribution
          <span class="badge" style="margin-left:8px;">{unique_goals} categor{"ies" if unique_goals != 1 else "y"}</span>
        </h3>
        <div class="card">
          <div class="diversity-bar-chart">{goal_bars_html}</div>
        </div>
      </div>"""


def build_attacker_diversity_section(scenarios: list[dict[str, Any]]) -> str:
    """Build the Actor Profile Distribution section from scenario data.

    Computes actor type distribution directly from the loaded scenario dicts
    rather than relying on pre-computed data in ``coverage-gaps.json``.

    Args:
        scenarios: List of parsed scenario envelope dicts (from YAML files).

    Returns:
        HTML string for the actor profile distribution section, or empty string
        if no scenarios are provided.
    """
    if not scenarios:
        return ""

    model_counts = _actor_type_counts(scenarios)
    total = sum(model_counts.values()) if model_counts else 1

    # Compute dominant type and monotone flag (>80% threshold)
    dominant_model = max(model_counts, key=model_counts.get)  # type: ignore[arg-type]
    dominant_fraction = model_counts[dominant_model] / total

    warning_html = _diversity_warning_html(dominant_model, dominant_fraction)
    bars_html = _diversity_bars_html(model_counts, total, _DIVERSITY_COLORS)
    unique_types = len(model_counts)
    goal_section_html = _goal_bars_html(_goal_counts(scenarios))

    return f"""
    <div id="sec-diversity" class="section">
      <div class="section-header">
        <h2>Actor Profile Distribution</h2>
        <span class="badge">{unique_types} type{"s" if unique_types != 1 else ""}</span>
      </div>

      {warning_html}

      <div class="card">
        <div class="diversity-bar-chart">{bars_html}</div>
      </div>

      {goal_section_html}
    </div>
    """
