"""Actor profile and attack-complexity blocks for scenario cards."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.scenario_common import _hex_to_rgb_css
from asago_scenario_generator.report.sections_diversity import _DIVERSITY_COLORS

_CAPABILITY_COLORS: dict[str, str] = {
    "novice": "#22c55e",  # green
    "intermediate": "#3b82f6",  # blue
    "advanced": "#f97316",  # orange
    "expert": "#ef4444",  # red
}


_CAPABILITY_TOOLTIPS: dict[str, str] = {
    "novice": "Limited technical skills, relies on public tools and tutorials",
    "intermediate": "Moderate skills, can adapt existing tools and techniques",
    "advanced": (
        "Deep expertise, can develop custom tools and discover vulnerabilities"
    ),
    "expert": (
        "Elite capabilities, can chain novel zero-days and develop bespoke frameworks"
    ),
}


def _capability_chip(capability_level: str) -> str:
    """Render the capability-level chip, or empty when absent."""
    cap_color = _CAPABILITY_COLORS.get(capability_level, "#6b7280")
    cap_display = capability_level.title() if capability_level else ""
    if not cap_display:
        return ""
    cap_tip = _CAPABILITY_TOOLTIPS.get(capability_level, "")
    cap_tip_attr = f' data-tooltip="{_esc(cap_tip)}"' if cap_tip else ""
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;'
        f"font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(cap_color)},0.15);"
        f'color:{cap_color};"{cap_tip_attr}>{_esc(cap_display)}</span>'
    )


def _goal_category_chip(goal_category_name: str) -> str:
    """Render the goal-category chip, or empty when absent."""
    if not goal_category_name:
        return ""
    display = goal_category_name.replace("-", " ").replace("_", " ").title()
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;'
        f"font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css('#0d9488')},0.15);"
        f'color:#0d9488;">{_esc(display)}</span>'
    )


def _resource_items_html(resources: list[Any]) -> str:
    """Render the resource list items with a none-specified fallback."""
    if resources:
        return "".join(f"<li>{_esc(r)}</li>" for r in resources)
    return "<li>None specified</li>"


def _plain_items_html(items: list[Any]) -> str:
    """Render items as list-item markup (possibly empty)."""
    return "".join(f"<li>{_esc(x)}</li>" for x in items)


def _access_optional_line(
    access: dict[str, Any],
    key: str,
    label: str,
    *,
    code: bool = True,
) -> str:
    """Render an optional access-provenance line, or '' when absent."""
    value = access.get(key)
    if not value:
        return ""
    if code:
        return f"<li>{label}: <code>{_esc(value)}</code></li>"
    return f"<li>{label}: {_esc(value)}</li>"


def _access_provenance_html(access: dict[str, Any] | None) -> str:
    """Build the access provenance sub-block (cmps.6), or '' when absent."""
    access_html = ""
    if access:
        _ingress = access.get("ingress_mode", "")
        _access_cls = access.get("access_class", "")
        _ep_id = access.get("initial_entry_point_id", "")
        list_style = 'style="margin:4px 0 0 16px;padding:0;font-size:13px;color:var(--text-secondary);line-height:1.6;"'
        _access_lines = [
            f"<li>Ingress: <strong>{_esc(_ingress)}</strong></li>",
            f"<li>Access class: <strong>{_esc(_access_cls)}</strong></li>",
            f"<li>Entry point ID: <code>{_esc(_ep_id)}</code></li>",
        ]
        _access_lines.append(
            _access_optional_line(access, "influence_source", "Influence source")
        )
        _access_lines.append(
            _access_optional_line(
                access, "influence_mechanism", "Influence mechanism", code=False
            )
        )
        _access_lines.append(
            _access_optional_line(access, "trust_boundary_id", "Trust boundary ID")
        )
        _access_lines.append(
            _access_optional_line(
                access,
                "material_insider_advantage",
                "Material insider advantage",
                code=False,
            )
        )
        access_html = (
            '<div style="margin-bottom:8px;">'
            '<strong style="color:var(--text-muted);font-size:11px;">ACCESS PROVENANCE:</strong>'
            f"<ul {list_style}>{''.join(_access_lines)}</ul>"
            "</div>"
        )
    return access_html


def _build_actor_profile_block(scenario: dict[str, Any]) -> str:
    """Build a collapsible Actor Profile block for a scenario card.

    Returns an empty string when the scenario has no ``actor_profile``.
    """
    actor_profile = scenario.get("actor_profile")
    if not actor_profile:
        return ""

    actor_type = actor_profile.get("actor_type", "unknown")
    capability_level = actor_profile.get("capability_level", "")
    goal_category_name = actor_profile.get("goal_category_name", "")
    beliefs = actor_profile.get("beliefs", [])
    desires = actor_profile.get("desires", [])
    intentions = actor_profile.get("intentions", [])
    resources = actor_profile.get("resources", [])

    type_color = _DIVERSITY_COLORS.get(actor_type, "#6b7280")
    type_display = actor_type.replace("-", " ").replace("_", " ").title()

    list_style = 'style="margin:4px 0 0 16px;padding:0;font-size:13px;color:var(--text-secondary);line-height:1.6;"'

    # Build access provenance sub-block (cmps.6)
    access_html = _access_provenance_html(actor_profile.get("access"))

    return f"""
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
              <span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(type_color)},0.15);color:{type_color};">{_esc(type_display)}</span>
              {_capability_chip(capability_level)}
              {_goal_category_chip(goal_category_name)}
            </div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6;">
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">BELIEFS:</strong>
                <ul {list_style}>{_plain_items_html(beliefs)}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">DESIRES:</strong>
                <ul {list_style}>{_plain_items_html(desires)}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">INTENTIONS:</strong>
                <ul {list_style}>{_plain_items_html(intentions)}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">RESOURCES:</strong>
                <ul {list_style}>{_resource_items_html(resources)}</ul>
              </div>
              {access_html}
              </div>"""


def _complexity_level_badge(level: str) -> str:
    """Render a colored badge for a required complexity level."""
    color = _CAPABILITY_COLORS.get(level, "#6b7280")
    return (
        '<span style="display:inline-block;padding:3px 10px;border-radius:4px;'
        f"font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(color)},0.15);"
        f'color:{color};">{_esc(level.title() if level else "")}</span>'
    )


def _complexity_summary_lines(
    lower: dict[str, Any], final: dict[str, Any]
) -> list[str]:
    """Build the candidate/final required-level summary lines (cmps.7)."""
    summary_lines = [
        "<li>Candidate lower bound: "
        f"{_complexity_level_badge(lower.get('required_level', ''))}</li>",
    ]
    final_level = final.get("required_level", "")
    if final_level:
        summary_lines.append(
            f"<li>Final required level: {_complexity_level_badge(final_level)}</li>"
        )
    else:
        summary_lines.append(
            "<li>Final required level: "
            '<span style="color:var(--text-muted);font-style:italic;">'
            "not yet assessed</span></li>"
        )
    return summary_lines


def _complexity_reason_items(lower: dict[str, Any], final: dict[str, Any]) -> str:
    """Render the typed reason list items for an assessment."""
    reason_items = ""
    for reason in final.get("reasons") or lower.get("reasons") or []:
        refs = ", ".join(
            f"{_esc(ref.get('kind', ''))}:{_esc(ref.get('ref_id', ''))}"
            for ref in reason.get("evidence", [])
        )
        reason_items += (
            "<li>"
            f"<code>{_esc(reason.get('rule_id', ''))}</code> "
            f"&rarr; <strong>{_esc(reason.get('required_level', ''))}</strong>: "
            f"{_esc(reason.get('detail', ''))}"
            f' <span style="color:var(--text-muted);">[{refs}]</span>'
            "</li>"
        )
    return reason_items


def _complexity_reasons_html(reason_items: str) -> str:
    """Wrap the typed reasons in their block, or return '' when empty."""
    if not reason_items:
        return ""
    return (
        '<div style="margin-bottom:8px;">'
        '<strong style="color:var(--text-muted);font-size:11px;">REASONS:</strong>'
        f'<ul style="margin:4px 0 0 16px;padding:0;font-size:13px;'
        f'color:var(--text-secondary);line-height:1.6;">{reason_items}</ul>'
        "</div>"
    )


def _build_complexity_assessment_block(scenario: dict[str, Any]) -> str:
    """Build the deterministic attack-complexity assessment block (cmps.7).

    Shows the versioned assessment — candidate lower bound, final
    required level, rule version, and typed reasons — distinctly from
    the actor's own capability level.  Returns an empty string when the
    scenario carries no ``attack_complexity_assessment``.
    """
    assessment = scenario.get("attack_complexity_assessment") or {}
    lower = assessment.get("candidate_lower_bound") or {}
    if not lower:
        return ""
    final = assessment.get("final") or {}
    rule_version = _esc(str(assessment.get("rule_version", "")))

    summary_lines = _complexity_summary_lines(lower, final)
    reason_items = _complexity_reason_items(lower, final)
    reasons_html = _complexity_reasons_html(reason_items)

    return (
        '<div style="margin-top:12px;border-top:1px solid var(--border);'
        'padding-top:10px;">'
        '<strong style="color:var(--text-muted);font-size:11px;" '
        'data-tooltip="Deterministic, versioned attack-complexity assessment '
        "(cmps.7). Distinct from the actor's immutable capability level: it "
        "is the capability the attack path requires, derived only from typed "
        'projection and realized-action evidence.">'
        f"ATTACK COMPLEXITY (RULE V{rule_version}):</strong>"
        '<ul style="margin:4px 0 0 16px;padding:0;font-size:13px;'
        'color:var(--text-secondary);line-height:1.9;list-style:none;">'
        f"{''.join(summary_lines)}</ul>"
        f"{reasons_html}"
        "</div>"
    )
