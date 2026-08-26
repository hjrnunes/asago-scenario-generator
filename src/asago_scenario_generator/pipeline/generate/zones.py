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


def _mapped_boundary_positions(
    step: NarrativeStep,
    boundary_by_id: dict[str, str | None],
) -> set[str] | None:
    """Boundary positions of a step's mapped projected steps, or None."""
    boundaries: set[str] = set()
    for sid in step.projected_step_ids:
        if sid in boundary_by_id:
            boundaries.add(boundary_by_id[sid])
    return boundaries if boundaries else None


def _mixed_boundary_violation(step: NarrativeStep, boundaries: set[str]) -> str | None:
    """Violation when mapped projected steps mix boundary positions."""
    if len(boundaries) > 1:
        return (
            f"projection-zone: narrative step {step.step_number} maps "
            f"projected steps with mixed boundary positions "
            f"({sorted(boundaries)})"
        )
    return None


def _projection_zone_violations(
    step: NarrativeStep,
    boundary_by_id: dict[str, str | None],
    active: set[str],
) -> list[str]:
    """Stage-specific zone violations for one narrative step's mapping."""
    boundaries = _mapped_boundary_positions(step, boundary_by_id)
    if boundaries is None:
        return []
    mixed = _mixed_boundary_violation(step, boundaries)
    if mixed is not None:
        return [mixed]
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


def _narrative_step_zone_violation(
    step: NarrativeStep, allowed: set[str]
) -> str | None:
    """Violation for a narrative step in a disallowed zone, or None."""
    if step.zone not in allowed:
        return (
            f"disallowed-zone: narrative step {step.step_number} "
            f"has zone '{step.zone}' which is not in "
            f"zones_active={sorted(allowed)}."
        )
    return None


def _narrative_sequence_zone_violations(
    zone_sequence: Iterable[str], allowed: set[str]
) -> list[str]:
    """Violations for disallowed zones in the narrative zone sequence."""
    violations: list[str] = []
    for z in zone_sequence:
        if z not in allowed:
            violations.append(
                f"disallowed-zone: zone_sequence contains '{z}' "
                f"which is not in zones_active={sorted(allowed)}."
            )
    return violations


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
        violation = _narrative_step_zone_violation(step, allowed)
        if violation is not None:
            violations.append(violation)

    violations.extend(
        _narrative_sequence_zone_violations(narrative.zone_sequence, allowed)
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:30:16Z","module_hash":"6ef5ff043e3ca53d1c73548dab6ca84ce07a04c319e3ff9e3a87645dfb4a4653","source_sha256":"a57c64a400ebaddf9b6612763ee084931bd687d3f4318af58ee6da3e97f0e644","functions":[{"id":"func/projected_boundary_by_id","name":"projected_boundary_by_id","line":35,"end_line":48,"hash":"c6653b663baa9ed71cff7b1a752d878f133baadcfee1f8fcc3326a6e2243b70f"},{"id":"func/active_narrative_zones","name":"active_narrative_zones","line":51,"end_line":58,"hash":"cda17cbbdbd7285b2cec371c016e38cecc8cbbe8f91f4a669a04a5b0053e61a9"},{"id":"func/enforce_narrative_projection_zones","name":"enforce_narrative_projection_zones","line":61,"end_line":97,"hash":"b90dd632f3d9a3f45ba5d29faeb8e76246dc627d423b1b6f87817a903208a3ea"},{"id":"func/_mapped_boundary_positions","name":"_mapped_boundary_positions","line":100,"end_line":109,"hash":"a34c55aca2c0f3a22c6b1dd7d6fe14b5ceb1c4bd021f52aa0eb32e30bc4ec3ed"},{"id":"func/_mixed_boundary_violation","name":"_mixed_boundary_violation","line":112,"end_line":120,"hash":"a17d1792db7e04361e3284b62fbdaca11c53baea3336824ed0e85794b1d0ec42"},{"id":"func/_projection_zone_violations","name":"_projection_zone_violations","line":123,"end_line":136,"hash":"002da20494d19bc995951d226f011984adbba933187dd1ca1c5071fe77e2f056"},{"id":"func/_narrative_zone_rule_violation","name":"_narrative_zone_rule_violation","line":139,"end_line":163,"hash":"f417bca2b195c82760fcd09accc1c3c2929caf13e73c1160ef2a9cff13f17231"},{"id":"func/_narrative_step_zone_violation","name":"_narrative_step_zone_violation","line":166,"end_line":176,"hash":"ac1cb0e38ffc0585217eb4f7478be9902b08b792127fc6b8b740810ad075c5f4"},{"id":"func/_narrative_sequence_zone_violations","name":"_narrative_sequence_zone_violations","line":179,"end_line":190,"hash":"8c4b03f87b8b97aa1de4f80c5d273c2a7a287787d23b741ff1bface2d99b6d7b"},{"id":"func/_enforce_zones_narrative","name":"_enforce_zones_narrative","line":193,"end_line":228,"hash":"c2f4f282ccb847ee11f9f61887eb6af792019b06f6a663c35a3ecf961cea116b"},{"id":"func/_collect_zones_from_tree","name":"_collect_zones_from_tree","line":231,"end_line":233,"hash":"ff3be0b851f76bdf2fbd711af55c361e4527127f3aea0b4203b24dc63c332860"},{"id":"func/_validate_tree_zones_node","name":"_validate_tree_zones_node","line":236,"end_line":258,"hash":"0fff59ae24ac3baa492838c44ef568df8753e9568a9d8987a37daaf67adb99b4"},{"id":"func/validate_attack_tree_zones","name":"validate_attack_tree_zones","line":261,"end_line":281,"hash":"8495e44407436070084a71edf2af6a4357410edf97984fd7e25cbf608fb761f2"},{"id":"func/_enforce_zones_attack_tree","name":"_enforce_zones_attack_tree","line":284,"end_line":304,"hash":"b78fe66773c0ff8901a278d73497fd2b3f49f7001be5cc16c3200eaa6f2fb4ab"}]}
# mutate4py-manifest-end
