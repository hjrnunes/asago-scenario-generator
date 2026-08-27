"""Attack-tree node rendering for scenario cards."""

from __future__ import annotations

import logging
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.report.provenance import (
    ZONE_BG_COLORS,
    ZONE_COLORS,
    ZONE_DISPLAY_NAMES,
    _ATLAS_TECHNIQUE_NAMES,
    _normalize_zone,
    _threat_id_tooltip,
)

logger = logging.getLogger(__name__)

_STRUCTURAL_EXPOSURE_TOOLTIPS: dict[str, str] = {
    "single_point_of_failure": "Only one control blocks this attack path",
    "convergence_point": "Multiple attack paths flow through this single control",
    "probabilistic_control": (
        "Relies on an LLM guardrail or classifier — not a binary pass/fail gate"
    ),
    "defense_in_depth_claim": ("Multiple controls back each other up on this path"),
}


_GATE_TOOLTIPS: dict[str, str] = {
    "AND": "All child steps must succeed for this attack to proceed",
    "OR": "Any one child step is sufficient for this attack to proceed",
    "LEAF": "Concrete attack action — no sub-steps",
}


def _gate_parts(gate: str) -> tuple[str, str, str]:
    """Return (css_class, symbol, title_attr) for an attack-tree gate."""
    gate_cls = {"AND": "gate-and", "OR": "gate-or", "LEAF": "gate-leaf"}.get(
        gate, "gate-leaf"
    )
    gate_symbol = {"AND": "&and;", "OR": "&or;", "LEAF": "&bull;"}.get(gate, "&bull;")
    gate_tip = _GATE_TOOLTIPS.get(gate, "")
    gate_title = f' data-tooltip="{_esc(gate_tip)}"' if gate_tip else ""
    return gate_cls, gate_symbol, gate_title


def _zone_style_parts(
    raw_zone: Any,
    action: dict[str, Any],
) -> tuple[str | None, str, str, str]:
    """Return (zone, color, bg, display_label) for a tree node's zone badge."""
    zone = _normalize_zone(raw_zone) if raw_zone is not None else None
    zone_color = ZONE_COLORS.get(zone, "#9ca3af")
    zone_bg = ZONE_BG_COLORS.get(zone, "#374151")
    boundary = action.get("boundary")
    action_kind = action.get("kind")
    zone_display = (
        ZONE_DISPLAY_NAMES.get(zone, zone)
        if zone is not None
        else "External"
        if action_kind == "external_precondition" or boundary == "external"
        else "N/A"
    )
    return zone, zone_color, zone_bg, zone_display


def _validate_capability_profile(
    profile_data: dict[str, Any] | None,
) -> CapabilityProfile | None:
    """Validate profile data for report ID resolution, or None."""
    if not profile_data:
        return None
    try:
        return CapabilityProfile.model_validate(dict(profile_data))
    except ValueError:
        logger.debug("Could not validate capability profile for report ID resolution")
        return None


def _lookup_resource(
    profile: CapabilityProfile,
    resource_id: str,
    resource_kind: str,
) -> Any:
    """Look up a tool/integration/entry-point resource by kind."""
    resolver = {
        "tool": profile.resolve_tool,
        "integration": profile.resolve_integration,
    }.get(resource_kind, profile.resolve_entry_point)
    return resolver(resource_id)


def _resolve_resource_name(
    profile: CapabilityProfile | None,
    resource_id: str | None,
    resource_kind: str,
) -> str | None:
    """Resolve a tool/integration/entry-point ID to its display name."""
    if not resource_id or profile is None:
        return None
    resource = _lookup_resource(profile, resource_id, resource_kind)
    return resource.name if resource else None


def _id_specs_for(
    action_kind: str | None, action: dict[str, Any]
) -> list[tuple[str, str, str]]:
    """Collect (label, id, kind) tuples for the node's resource references."""
    id_specs = []
    if action_kind == "tool_invocation":
        id_specs.append(("Tool", action.get("tool_id"), "tool"))
        if action.get("integration_id"):
            id_specs.append(
                ("Integration", action.get("integration_id"), "integration")
            )
    elif action_kind == "integration_interaction":
        id_specs.append(("Integration", action.get("integration_id"), "integration"))
    elif action_kind == "initial_ingress":
        id_specs.append(("Entry Point", action.get("entry_point_id"), "entry_point"))
    return id_specs


def _action_kind_meta_parts(action_kind: str | None) -> list[str]:
    """Meta span for the action kind (e.g. 'Tool Invocation')."""
    if not action_kind:
        return []
    action_display = action_kind.replace("_", " ").title()
    return [f'<span class="tree-meta">{_esc(action_display)}</span>']


def _resource_meta_parts(
    id_specs: list[tuple[str, str, str]],
    profile: CapabilityProfile | None,
) -> list[str]:
    """Meta spans for resolved resource IDs."""
    meta_parts = []
    for resource_label, resource_id, resource_kind in id_specs:
        resolved = _resolve_resource_name(profile, resource_id, resource_kind)
        display = resolved or "Unresolved"
        meta_parts.append(
            f'<span class="tree-meta">{_esc(resource_label)}: {_esc(display)} '
            f"(<code>{_esc(resource_id or 'Missing ID')}</code>)</span>"
        )
    return meta_parts


def _boundary_meta_parts(action: dict[str, Any]) -> list[str]:
    """Meta span for the action boundary, when declared."""
    boundary = action.get("boundary")
    if not boundary:
        return []
    return [f'<span class="tree-meta">Boundary: {_esc(str(boundary).title())}</span>']


def _impact_meta_parts(action: dict[str, Any], action_kind: str | None) -> list[str]:
    """Meta span for the impact target, when declared."""
    if action_kind == "impact" and action.get("target"):
        return [f'<span class="tree-meta">Target: {_esc(action["target"])}</span>']
    return []


def _evidence_meta_parts(action: dict[str, Any], action_kind: str | None) -> list[str]:
    """Meta span for external-precondition evidence, when declared."""
    if action_kind == "external_precondition" and action.get("access_provenance"):
        return [
            f'<span class="tree-meta">Evidence: {_esc(action["access_provenance"])}</span>'
        ]
    return []


def _threat_meta_parts(threat_id: str | None) -> list[str]:
    """Meta span for the mapped threat ID, when declared."""
    if not threat_id:
        return []
    return [
        f'<span class="tree-meta"{_threat_id_tooltip(threat_id)}>'
        f"{_esc(threat_id)}</span>"
    ]


def _technique_meta_parts(technique_id: str | None) -> list[str]:
    """Meta span for the mapped ATLAS technique ID, when declared."""
    if not technique_id:
        return []
    tech_tip = ""
    if technique_id.startswith("AML.T"):
        name = _ATLAS_TECHNIQUE_NAMES.get(technique_id, "")
        label = f"{technique_id} — {name}" if name else technique_id
        tech_tip = f' data-tooltip="MITRE ATLAS: {_esc(label)}"'
    return [f'<span class="tree-meta"{tech_tip}>{_esc(technique_id)}</span>']


def _control_point_meta_parts(control_point: str | None) -> list[str]:
    """Meta span for the defensive control point, when declared."""
    if not control_point:
        return []
    return [
        f'<span class="tree-meta" style="color:var(--medium);" '
        f'data-tooltip="Defensive control that should block or detect this '
        f'attack step">{_esc(control_point)}</span>'
    ]


def _structural_exposure_meta_parts(structural_exposure: Any) -> list[str]:
    """Meta span for the structural exposure label, when declared."""
    if not structural_exposure:
        return []
    se_str = str(structural_exposure)
    se_display = se_str.replace("_", " ").title()
    se_tip = _STRUCTURAL_EXPOSURE_TOOLTIPS.get(se_str, "Structural exposure")
    return [
        f'<span class="tree-meta" style="color:var(--high);" '
        f'data-tooltip="{_esc(se_tip)}">{_esc(se_display)}</span>'
    ]


def _tree_meta_parts(
    action: dict[str, Any],
    action_kind: str | None,
    id_specs: list[tuple[str, str, str]],
    profile: CapabilityProfile | None,
    threat_id: str | None,
    technique_id: str | None,
    control_point: str | None,
    structural_exposure: Any,
) -> list[str]:
    """Collect all tree-meta spans in the established render order."""
    return (
        _action_kind_meta_parts(action_kind)
        + _resource_meta_parts(id_specs, profile)
        + _boundary_meta_parts(action)
        + _impact_meta_parts(action, action_kind)
        + _evidence_meta_parts(action, action_kind)
        + _threat_meta_parts(threat_id)
        + _technique_meta_parts(technique_id)
        + _control_point_meta_parts(control_point)
        + _structural_exposure_meta_parts(structural_exposure)
    )


def _is_tree_leaf(gate: str, children: list) -> bool:
    """Return whether a node renders as a leaf (no children expansion)."""
    return gate == "LEAF" or not children


def _node_children(children: Any) -> list:
    """Return the child-node list, or an empty list."""
    return children or []


def _build_attack_tree_node(
    node: dict[str, Any] | None,
    profile_data: dict[str, Any] | None = None,
) -> str:
    if node is None:
        return ""

    gate = node.get("gate", "LEAF")
    label = node.get("label", "")
    action = node.get("action") or {}
    action_kind = action.get("kind")
    children = _node_children(node.get("children"))
    threat_id = node.get("threat_id")
    technique_id = node.get("technique_id")
    control_point = node.get("control_point")
    structural_exposure = node.get("structural_exposure")

    gate_cls, gate_symbol, gate_title = _gate_parts(gate)
    zone, zone_color, zone_bg, zone_display = _zone_style_parts(
        node.get("zone"), action
    )

    profile = _validate_capability_profile(profile_data)
    id_specs = _id_specs_for(action_kind, action)
    meta_html = " ".join(
        _tree_meta_parts(
            action,
            action_kind,
            id_specs,
            profile,
            threat_id,
            technique_id,
            control_point,
            structural_exposure,
        )
    )

    if _is_tree_leaf(gate, children):
        return f"""
        <div class="tree-leaf">
          <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
          <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">{_esc(zone_display)}</span>
          <span class="tree-label">{_esc(label)}</span>
          {meta_html}
        </div>"""

    children_html = "".join(_build_attack_tree_node(c, profile_data) for c in children)
    return f"""
    <details open>
      <summary>
        <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
        <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">{_esc(zone_display)}</span>
        <span class="tree-label">{_esc(label)}</span>
        {meta_html}
      </summary>
      {children_html}
    </details>"""
