"""Capability Profile section and KC-sub-code helper builders."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.data.loaders import load_kc_threat_mapping
from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    ZONE_NAMES as _ZONE_NAMES_TUPLE,
)
from asago_scenario_generator.report.provenance import (
    ZONE_BG_COLORS,
    ZONE_COLORS,
    _normalize_zone,
)


def _build_kc_descriptions() -> dict[str, str]:
    """Load KC sub-code → description mapping for report tooltips."""
    mapping = load_kc_threat_mapping()
    return {
        sc["kc_subcode"]: sc["description"] for sc in mapping.get("kc_subcodes", [])
    }


def _kc_category(kc: str) -> str:
    """Extract category prefix from a KC sub-code (e.g. 'KC6.2.2' → 'KC6')."""
    parts = kc.split(".")
    return parts[0] if parts else kc


def _corpus_applicability_label(
    corpus_claims: list[dict[str, Any]],
) -> str:
    """Human-readable label for closed-world corpus claim applicability.

    Consumes typed, category-specific :class:`CorpusClaimApplicability`
    records persisted in ``SemanticValidation.corpus_claim_applicability``
    (cmps.9 review correction 2).  Does not infer from completeness strings.
    """
    if not corpus_claims:
        return "Not assessed"
    parts: list[str] = []
    for claim in corpus_claims:
        category = claim.get("category", "unknown")
        status = claim.get("status", "unknown")
        cat_label = category.replace("_", " ")
        parts.append(f"{cat_label} claims {status}")
    return "; ".join(parts)


def _zone_chips_html(raw_zones_active: list[Any]) -> str:
    """Build the compact horizontal active/inactive zone chip strip."""
    zones_active = {_normalize_zone(z) for z in raw_zones_active}
    zone_chips = []
    for z in _ZONE_NAMES_TUPLE:
        active = z in zones_active
        cls = "active" if active else "inactive"
        color = ZONE_COLORS[z]
        bg = ZONE_BG_COLORS[z] if active else ""
        style = f"background:{bg};border-color:{color};color:{color};" if active else ""
        zone_chips.append(
            f'<span class="zone-chip {cls}" style="{style}">'
            f"{_esc(ZONE_DISPLAY_NAMES[z])}</span>"
        )
    return "".join(zone_chips)


def _flag_chips_html(profile: dict[str, Any]) -> str:
    """Build the inline capability flag chips plus the confidence chip."""
    bool_flags = [
        ("Memory", profile.get("has_persistent_memory", False)),
        ("Multi-Agent", profile.get("multi_agent", False)),
        ("HITL", profile.get("hitl", False)),
    ]
    confidence = profile.get("confidence", "unknown")
    flag_chips = []
    for label, val in bool_flags:
        dot_cls = "on" if val else "off"
        flag_chips.append(
            f'<span class="flag-chip">'
            f'<span class="flag-dot {dot_cls}"></span>'
            f'<span class="flag-label">{_esc(label)}</span>'
            f"</span>"
        )
    # Confidence as a text chip
    conf_tip = (
        "Profile inference confidence — how clearly the use-case "
        "description signals these capabilities"
    )
    flag_chips.append(
        f'<span class="flag-chip" data-tooltip="{_esc(conf_tip)}">'
        f'<span class="flag-label">Confidence:</span>'
        f'<span class="flag-value">{_esc(str(confidence).capitalize())}</span>'
        f"</span>"
    )
    return "".join(flag_chips)


def _entry_point_items_html(eps: list[Any]) -> list[str]:
    """Extract name/direction entries from dict or string entry points."""
    _DIR_ARROWS = {"input": "←", "output": "→", "bidirectional": "↔"}
    ep_items = []
    for ep in eps:
        if isinstance(ep, dict):
            name = ep.get("name", str(ep))
            direction = ep.get("direction", "bidirectional")
        else:
            name = str(ep)
            direction = "bidirectional"
        arrow = _DIR_ARROWS.get(direction, "↔")
        ep_items.append(
            f"<li>"
            f'<span class="ep-direction" title="{_esc(direction)}">{arrow}</span>'
            f'<span class="ep-name">{_esc(name)}</span>'
            f"</li>"
        )
    return ep_items


def _ep_row_html(ep_items: list[str]) -> str:
    """Wrap the entry-point list in a profile row, or empty when absent."""
    if not ep_items:
        return ""
    return f"""
        <div class="profile-row">
          <div class="profile-row-label">Entry Points</div>
          <ul class="entry-point-list">{"".join(ep_items)}</ul>
        </div>"""


def _resource_list(
    entries: list[dict[str, Any]], id_field: str, empty_label: str
) -> str:
    """Render an entry-point-style inventory list or an empty label."""
    if not entries:
        return f'<span style="color:var(--text-muted);">{_esc(empty_label)}</span>'
    items = []
    for entry in entries:
        name = entry.get("name", "Unnamed")
        canonical_id = entry.get(id_field, "Unavailable")
        items.append(
            "<li>"
            f'<span class="ep-name">{_esc(name)}</span> '
            f'<code class="tree-meta">{_esc(canonical_id)}</code>'
            "</li>"
        )
    return f'<ul class="entry-point-list">{"".join(items)}</ul>'


def _enum_str(v: Any) -> str:
    """Extract string value from a possible enum object."""
    return str(v.value if hasattr(v, "value") else v)


def _evidence_html(evidence: list[str]) -> str:
    """Render an evidence source list or the no-evidence message."""
    if not evidence:
        return (
            '<span style="color:var(--text-muted);">No evidence sources recorded</span>'
        )
    return (
        '<ul class="entry-point-list">'
        + "".join(f"<li>{_esc(source)}</li>" for source in evidence)
        + "</ul>"
    )


def _kc_subcodes_html(profile: dict[str, Any]) -> str:
    """Build the KC sub-code badge row, or empty when none are declared."""
    kc_subcodes = profile.get("kc_subcodes", [])
    if not kc_subcodes:
        return ""
    kc_descs = _build_kc_descriptions()
    kc_badges = []
    for kc in sorted(kc_subcodes):
        cat = _kc_category(kc)
        desc = _esc(kc_descs.get(kc, ""))
        kc_badges.append(
            f'<span class="kc-badge" data-cat="{cat}" title="{desc}">{_esc(kc)}</span>'
        )
    return f"""
        <div class="profile-row">
          <div class="profile-row-label">System Capabilities (KC Sub-Codes)</div>
          <div class="kc-subcodes-grid">{"".join(kc_badges)}</div>
        </div>"""


def build_capability_profile_section(
    profile: dict[str, Any],
    *,
    corpus_claims: list[dict[str, Any]] | None = None,
) -> str:
    zone_chips = _zone_chips_html(profile.get("zones_active", []))
    flag_chips = _flag_chips_html(profile)
    ep_html = _ep_row_html(_entry_point_items_html(profile.get("entry_points", [])))

    tools_html = _resource_list(
        profile.get("tool_inventory") or [], "tool_id", "No tools inventoried"
    )
    integrations_html = _resource_list(
        profile.get("external_integrations") or [],
        "integration_id",
        "No external integrations inventoried",
    )

    entry_point_completeness = _enum_str(
        profile.get("entry_point_completeness", "unknown")
    )
    entry_point_evidence = profile.get("entry_point_evidence") or []
    tool_inventory_completeness = _enum_str(
        profile.get("tool_inventory_completeness", "unknown")
    )
    tool_inventory_evidence = profile.get("tool_inventory_evidence") or []

    entry_point_evidence_html = _evidence_html(entry_point_evidence)
    tool_inventory_evidence_html = _evidence_html(tool_inventory_evidence)
    kc_html = _kc_subcodes_html(profile)

    return f"""
    <div id="sec-profile" class="section">
      <div class="section-header">
        <h2>Capability Profile</h2>
        <span class="badge">Schneider 5-Zone</span>
      </div>

      <div class="card">
        <div class="profile-row">
          <div class="profile-row-label">Active Zones</div>
          <div class="zone-strip">{zone_chips}</div>
        </div>

        <div class="profile-row">
          <div class="profile-row-label">Capability Flags</div>
          <div class="flags-inline">{flag_chips}</div>
        </div>
        {ep_html}
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory</div>
          {tools_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">External Integrations</div>
          {integrations_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Entry-Point Inventory Completeness</div>
          <span class="flag-value">{_esc(entry_point_completeness.replace("_", " ").title())}</span>
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Entry-Point Inventory Evidence</div>
          {entry_point_evidence_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory Completeness</div>
          <span class="flag-value">{_esc(tool_inventory_completeness.replace("_", " ").title())}</span>
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory Evidence</div>
          {tool_inventory_evidence_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Corpus Claim Applicability</div>
          <span class="flag-value">{_esc(_corpus_applicability_label(corpus_claims or []))}</span>
        </div>
        {kc_html}
      </div>
    </div>
    """
