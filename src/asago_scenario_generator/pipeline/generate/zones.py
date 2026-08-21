"""Zone enforcement logic for narratives and attack trees.

Action-aware enforcement (cmps.9):
- External preconditions (zone=None) are never repaired into active AI zones.
- Internal action zone requirements remain profile-active.
- Tool invocation zone must be exactly 'tool_execution'.
- Invalid zones are rejected (violation list), not silently pruned (cmps.9 review correction 4).

Narrative outside-boundary representation (projection transport):
- A narrative step may use the literal zone ``outside`` only when every
  projected step it maps is outside-boundary; ``outside`` represents
  activity outside the assessed AI boundary and is never an active
  Schneider zone.
- Active-zone consumers use :func:`active_narrative_zones` so ``outside``
  traversal is never credited as internal traversal.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from asago_scenario_generator.models.attack_tree import AttackTree, AttackTreeNode
from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep
from asago_scenario_generator.pipeline.tree_utils import collect_tree_zones

logger = logging.getLogger(__name__)

# Literal narrative zone for activity outside the assessed AI boundary.
# Deliberately distinct from the profile's active Schneider zone list.
OUTSIDE_ZONE = "outside"


def projected_boundary_by_id(
    selected_steps: Iterable[dict[str, Any]],
) -> dict[str, str | None]:
    """Index projected-step boundary positions by canonical step ID.

    Malformed transport records (non-dict items, non-string step IDs) are
    ignored so consumers of the resulting map never hit a KeyError from
    transport junk.
    """
    return {
        item["step_id"]: item.get("boundary_position")
        for item in selected_steps
        if isinstance(item, dict) and isinstance(item.get("step_id"), str)
    }


def active_narrative_zones(zone_sequence: Iterable[str]) -> list[str]:
    """Project a narrative zone sequence onto active zones, dropping ``outside``.

    ``outside`` represents activity outside the assessed AI boundary, so it
    is never counted as internal traversal by coverage, priority, faceting,
    or skeleton fallback consumers.
    """
    return [zone for zone in zone_sequence if zone != OUTSIDE_ZONE]


def enforce_narrative_projection_zones(
    narrative: NarrativeLayer,
    zones_active: list[str] | None,
    boundary_by_id: dict[str, str | None] | None,
) -> NarrativeLayer:
    """Validate narrative step zones against projected-step boundary positions.

    Stage-specific narrative boundary rules (projection transport):

    - One narrative step may combine only projected steps with consistent
      boundary positions.
    - A step mapping only outside-boundary projected steps must use the
      literal zone ``outside``.
    - Inside/crossing steps must use an active Schneider zone — never
      ``outside``, never an inactive zone.

    Raises ``ValueError`` with ``projection-zone`` reasons on the first
    violation set — the narrative is never repaired (no step is removed,
    renumbered, or remapped).  Returns the narrative unchanged when every
    step satisfies the rules or when *zones_active*/*boundary_by_id* are
    ``None`` (no validation possible).
    """
    if zones_active is None or boundary_by_id is None:
        return narrative

    active = set(zones_active)
    violations: list[str] = []

    for step in narrative.steps:
        violations.extend(_projection_zone_violations(step, boundary_by_id, active))

    if violations:
        raise ValueError(
            "Narrative has projection-zone violations (no semantic repair): "
            + "; ".join(violations)
        )
    return narrative


def _projection_zone_violations(
    step: NarrativeStep,
    boundary_by_id: dict[str, str | None],
    active: set[str],
) -> list[str]:
    """Stage-specific zone violations for one narrative step's mapping."""
    mapped_ids = [sid for sid in step.projected_step_ids if sid in boundary_by_id]
    if not mapped_ids:
        return []
    boundaries = {boundary_by_id[sid] for sid in mapped_ids}
    if len(boundaries) > 1:
        return [
            f"projection-zone: narrative step {step.step_number} maps "
            f"projected steps with mixed boundary positions "
            f"({sorted(boundaries)})"
        ]
    violation = _narrative_zone_rule_violation(step, next(iter(boundaries)), active)
    return [violation] if violation is not None else []


def _narrative_zone_rule_violation(
    step: NarrativeStep, boundary: str, active: set[str]
) -> str | None:
    """Stage-specific zone rule violation for one step, or None when compliant."""
    if boundary == OUTSIDE_ZONE:
        if step.zone != OUTSIDE_ZONE:
            return (
                f"projection-zone: narrative step {step.step_number} maps "
                f"only outside-boundary projected steps but has zone "
                f"'{step.zone}' (outside step active zone)"
            )
        return None
    if step.zone == OUTSIDE_ZONE:
        return (
            f"projection-zone: narrative step {step.step_number} has "
            f"zone 'outside' but maps {boundary}-boundary projected "
            f"steps ({boundary} step outside)"
        )
    if step.zone not in active:
        return (
            f"projection-zone: narrative step {step.step_number} has "
            f"zone '{step.zone}' which is not an active Schneider "
            f"zone (inactive Schneider zone)"
        )
    return None


def _enforce_zones_narrative(
    narrative: NarrativeLayer,
    zones_active: list[str] | None = None,
) -> NarrativeLayer:
    """Validate zone membership of narrative steps against *zones_active*.

    On candidate-v2 paths (422o.4), zone filtering/renumbering is semantic
    repair and is prohibited.  This function now **validates** zones and
    raises ``ValueError`` when any step has a disallowed zone — it never
    deletes, filters, or renumbers steps.  The caller must retry or reject.

    When *zones_active* is ``None`` the narrative is returned unchanged
    (no validation possible).
    """
    if zones_active is None:
        return narrative

    allowed = set(zones_active)
    violations: list[str] = []

    for step in narrative.steps:
        if step.zone not in allowed:
            violations.append(
                f"disallowed-zone: narrative step {step.step_number} "
                f"has zone '{step.zone}' which is not in "
                f"zones_active={sorted(allowed)}."
            )

    for z in narrative.zone_sequence:
        if z not in allowed:
            violations.append(
                f"disallowed-zone: zone_sequence contains '{z}' "
                f"which is not in zones_active={sorted(allowed)}."
            )

    if violations:
        raise ValueError(
            "Narrative has disallowed zones (422o.4: no semantic repair): "
            + "; ".join(violations)
        )

    return narrative


def _collect_zones_from_tree(node: AttackTreeNode) -> set[str]:
    """Collect all non-None zones referenced in a tree."""
    return collect_tree_zones(node)


def _validate_tree_zones_node(
    node: AttackTreeNode,
    allowed: set[str],
    violations: list[str],
) -> None:
    """Recursively validate that all zoned nodes use allowed zones.

    Nodes with zone=None (external preconditions, external impacts) are
    always valid — they are outside the AI boundary.

    Returns violations for nodes with zones not in *allowed*.  Does NOT
    prune or collapse — the caller retries or rejects the tree.
    """
    if node.zone is not None and node.zone not in allowed:
        violations.append(
            f"disallowed-zone: node '{node.id}' has zone '{node.zone}' "
            f"which is not in zones_active={sorted(allowed)}. "
            f"The tree must be retried or rejected — no silent pruning."
        )

    if node.children:
        for child in node.children:
            _validate_tree_zones_node(child, allowed, violations)


def validate_attack_tree_zones(
    tree: AttackTree,
    zones_active: list[str] | None = None,
) -> list[str]:
    """Validate that all zoned nodes in the attack tree use allowed zones.

    Returns a list of violation descriptions (empty if all zones are valid).
    Nodes with zone=None (external preconditions, external impacts) are
    always valid.

    This is a **validation**, not a transform — it never prunes, collapses,
    or fabricates nodes.  The caller must retry or reject when violations
    exist (cmps.9 review correction 4).
    """
    if zones_active is None:
        return []

    allowed = set(zones_active)
    violations: list[str] = []
    _validate_tree_zones_node(tree.root, allowed, violations)
    return violations


def _enforce_zones_attack_tree(
    tree: AttackTree,
    zones_active: list[str] | None = None,
) -> AttackTree:
    """Validate attack-tree zones against *zones_active*.

    Returns the tree unchanged when all zones are valid or when
    *zones_active* is ``None``.  Raises ``ValueError`` when any node
    has a disallowed zone — the caller must retry or reject.

    This is a **validation gate**, not a pruning transform (cmps.9 review
    correction 4).  It never prunes, collapses, or fabricates nodes.
    """
    if zones_active is None:
        return tree

    violations = validate_attack_tree_zones(tree, zones_active)
    if violations:
        raise ValueError("Attack tree has disallowed zones: " + "; ".join(violations))

    return tree
