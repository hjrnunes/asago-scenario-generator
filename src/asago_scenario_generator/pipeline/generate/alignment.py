"""Validator-derived projection alignment table for prompt rendering.

The narrative and attack-tree user prompts identify canonical steps by
semantic ID and present one compact row per selected step.  Every cell is
derived from the projection validation rules (``pipeline.compatibility``)
or from the canonical step itself — there is no hand-authored compatibility
prose that can drift from what strict validation accepts.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
)

_OUTSIDE_ZONE = "outside"
_ACTIVE_ZONE_PHRASE = "active Schneider zone"

# resource_ref kind -> compact label used in the bound-resources cell.
# An output surface produces the observable effect of a step, so it renders
# under the "effect" label.
_RESOURCE_KIND_LABELS: dict[str, str] = {
    "entry_point": "entry_point",
    "tool": "tool",
    "integration": "integration",
    "trust_boundary": "trust_boundary",
    "output_surface": "effect",
    "agent_internal": "agent_internal",
}


def _allowed_tree_kinds(action_kind: str, executor_role: str) -> list[str]:
    """Intersection of the action-kind and executor-role validator mappings."""
    return sorted(
        STEP_TO_LEAF_ACTION_COMPAT.get(action_kind, set())
        & EXECUTOR_ROLE_TO_LEAF_COMPAT.get(executor_role, set())
    )


def bound_resources_from_step(step: dict[str, Any]) -> str:
    """Render the resources bound to one canonical step as compact cells.

    Uses only that step's own resource links; a missing link set renders
    as ``"none"``.
    """
    parts: list[str] = []
    for link in step.get("resource_links", []):
        if not isinstance(link, dict):
            continue
        ref = link.get("resource_ref")
        if not isinstance(ref, dict):
            continue
        label = _RESOURCE_KIND_LABELS.get(ref.get("kind"))
        if label is None:
            continue
        ident = (
            ref.get("entry_point_id")
            or ref.get("tool_id")
            or ref.get("integration_id")
            or ref.get("trust_boundary_id")
        )
        parts.append(f"{label}/{ident}" if ident else label)
    return ", ".join(parts) if parts else "none"


def derive_projection_alignment_row(step: dict[str, Any]) -> dict[str, Any]:
    """Derive the compact alignment row for one selected canonical step.

    The row cells follow the stage-specific boundary validation rules:
    outside-boundary steps use the literal narrative zone ``outside`` and a
    null tree zone; inside/crossing steps use an active Schneider zone.
    """
    boundary = str(step.get("boundary_position", ""))
    if boundary == _OUTSIDE_ZONE:
        narrative_zone = _OUTSIDE_ZONE
        tree_zone = "null"
    else:
        narrative_zone = _ACTIVE_ZONE_PHRASE
        tree_zone = _ACTIVE_ZONE_PHRASE
    return {
        "canonical_id": step["step_id"],
        "action": step.get("action_kind", ""),
        "executor": step.get("executor_role", ""),
        "boundary": boundary,
        "allowed_narrative_zone": narrative_zone,
        "allowed_tree_kinds": _allowed_tree_kinds(
            str(step.get("action_kind", "")), str(step.get("executor_role", ""))
        ),
        "tree_zone": tree_zone,
        "bound_resources": bound_resources_from_step(step),
    }


def derive_projection_alignment_rows(
    selected_steps: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    """Derive one alignment row per selected canonical step, in order."""
    return [derive_projection_alignment_row(step) for step in selected_steps]
