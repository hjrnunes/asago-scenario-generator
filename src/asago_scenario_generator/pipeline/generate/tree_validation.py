"""Post-generation structure validation for parsed attack trees.

Checks that run after strict parsing: projected-step traceability of
leaves, pinned-ingress path coverage, mandatory-leaf presence, technique
ID/zone compatibility, parsimony and step-node consistency, and tool
execution grounding.
"""

from __future__ import annotations

import logging
from typing import Any

from asago_scenario_generator.data.atlas import TECHNIQUE_ZONE_CONSTRAINTS
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.scenario import NarrativeLayer
from asago_scenario_generator.pipeline.generate.constants import (
    _STEP_NODE_CORRESPONDENCE_FLOOR,
)
from asago_scenario_generator.pipeline.generate.zones import (
    _collect_zones_from_tree,
    projected_boundary_by_id,
)

logger = logging.getLogger(__name__)


def _enumerate_root_to_leaf_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Enumerate all root-to-leaf paths through the attack tree.

    Each path is a list of leaf nodes.  AND gates contribute all children
    to the same path(s); OR gates create one branch per child.
    """
    if node.gate == GateType.LEAF:
        return [[node]]
    if not node.children:
        return []
    if node.gate == GateType.AND:
        # All children must succeed — merge their paths.
        merged: list[list[AttackTreeNode]] = [[]]
        for child in node.children:
            child_paths = _enumerate_root_to_leaf_paths(child)
            if not child_paths:
                continue
            merged = [m + cp for m in merged for cp in child_paths]
        return merged
    # OR gate: each child is a separate branch.
    paths: list[list[AttackTreeNode]] = []
    for child in node.children:
        paths.extend(_enumerate_root_to_leaf_paths(child))
    return paths


def _collect_all_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes from the tree (depth-first)."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_all_leaves(child))
    return leaves


def _validate_tree_against_projection(
    tree: AttackTree,
    projection_context: dict[str, Any] | None,
) -> None:
    """Validate parsed attack tree against the immutable projection context.

    422o.4 blocker #2: On candidate-v2 paths, every non-external_precondition
    security leaf MUST have nonempty projected_step_ids, exactly one complete
    canonical realization per projected ID, and exact realization equality
    to the canonical projection context.  OR nodes are prohibited.

    Raises ``ValueError`` on any violation — no semantic repair.
    """
    if projection_context is None:
        return

    selected_step_ids = set(projection_context.get("selected_step_ids", []))
    boundary_by_id = projected_boundary_by_id(
        projection_context.get("selected_steps", [])
    )

    # Realization records are now derived in post-processing by
    # _fill_tree_realizations() — no need to rebuild them here for
    # equality comparison.  We still validate projected_step_id
    # validity and realization coverage.

    def _check_node(node: AttackTreeNode) -> None:
        # OR nodes are prohibited in v1.
        if node.gate == GateType.OR:
            raise ValueError(
                f"Attack tree node '{node.id}' uses OR gate — OR is "
                f"prohibited in v1 (one concrete execution only)"
            )
        if node.gate == GateType.LEAF:
            action_kind = node.action.kind if node.action else ""
            is_external = action_kind == "external_precondition"
            is_external_impact = (
                action_kind == "impact"
                and getattr(node.action, "boundary", None) == "external"
            )

            if is_external_impact:
                # External impacts happen outside the assessed boundary, so
                # every mapped projected step must itself be outside-boundary.
                # The step ID is preserved (never removed or remapped) and the
                # mapping fails closed as a boundary semantic violation.
                for sid in node.projected_step_ids:
                    if boundary_by_id.get(sid) != "outside":
                        raise ValueError(
                            f"Tree leaf '{node.id}' external impact maps "
                            f"non-outside projected step '{sid}' — boundary "
                            f"semantic violation (fail closed, no repair)"
                        )

            if is_external:
                # Outside-boundary external preconditions are traceable.
                # Internal/crossing external preconditions remain unmapped.
                if not node.projected_step_ids:
                    if node.realizations:
                        raise ValueError(
                            f"External precondition leaf '{node.id}' has "
                            "realizations — external preconditions must have "
                            "empty projected_step_ids and empty realizations"
                        )
                else:
                    for sid in node.projected_step_ids:
                        if sid not in selected_step_ids:
                            raise ValueError(
                                f"External precondition leaf '{node.id}' "
                                f"references unprojected step '{sid}'"
                            )
                        if boundary_by_id.get(sid) != "outside":
                            raise ValueError(
                                f"External precondition leaf '{node.id}' "
                                f"maps non-outside projected step '{sid}' "
                                f"— external preconditions must be unmapped"
                            )
                    real_ids = [
                        realization.projected_step_id
                        for realization in node.realizations
                    ]
                    if len(real_ids) != len(node.projected_step_ids) or set(
                        real_ids
                    ) != set(node.projected_step_ids):
                        raise ValueError(
                            f"External precondition leaf '{node.id}' has "
                            "incomplete canonical realizations for its "
                            "outside-boundary projected steps"
                        )
            else:
                # Every non-external leaf must have nonempty projected IDs.
                if not node.projected_step_ids:
                    raise ValueError(
                        f"Security-bearing leaf '{node.id}' has no "
                        f"projected_step_ids — every non-external_precondition "
                        f"leaf must map to projected steps"
                    )
                # All IDs must be in the selected set.
                for sid in node.projected_step_ids:
                    if sid not in selected_step_ids:
                        raise ValueError(
                            f"Tree leaf '{node.id}' references unprojected "
                            f"step '{sid}' — not in selected_step_ids"
                        )
                # Must have exactly one realization per projected ID.
                if not node.realizations:
                    raise ValueError(
                        f"Security-bearing leaf '{node.id}' has "
                        f"projected_step_ids but no realizations"
                    )
                real_ids = [r.projected_step_id for r in node.realizations]
                if len(set(real_ids)) != len(real_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' has duplicate realization records"
                    )
                if len(real_ids) != len(node.projected_step_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' has {len(real_ids)} realization "
                        f"records but {len(node.projected_step_ids)} "
                        f"projected_step_ids — exactly one per ID required"
                    )
                if set(real_ids) != set(node.projected_step_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' realization IDs {sorted(set(real_ids))} "
                        f"do not match projected_step_ids "
                        f"{sorted(set(node.projected_step_ids))}"
                    )
                # Realization equality check is now a no-op sanity check:
                # post-processing derives realizations from the same
                # projection context, so both sides are computed by
                # derive_step_realization().  We keep the projected_step_id
                # validity and coverage checks above.

        if node.children:
            for child in node.children:
                _check_node(child)

    _check_node(tree.root)


def _validate_pinned_ingress(
    tree: AttackTree,
    pinned_entry_point_id: str | None,
    profile: CapabilityProfile | None = None,
) -> list[str]:
    """Validate that every root-to-leaf path has an initial_ingress leaf.

    When ``pinned_entry_point_id`` is supplied, every initial_ingress action
    in the tree must use that exact entry point ID.  Every final attack path
    must contain at least one initial_ingress leaf.

    When *profile* is supplied, each initial_ingress leaf's zone must match
    the resolved entry point's canonical ``effective_ingress_zone``.  A
    mismatch is a violation — the zone is never silently repaired from a
    label (cmps.9 review correction 3).
    """
    paths = _enumerate_root_to_leaf_paths(tree.root)
    violations: list[str] = []

    for path_idx, path in enumerate(paths, 1):
        ingress_leaves = [
            leaf
            for leaf in path
            if leaf.action is not None and leaf.action.kind == "initial_ingress"
        ]
        if not ingress_leaves:
            violations.append(
                f"missing-initial-ingress: attack path {path_idx} has no "
                f"initial_ingress leaf action. Every root-to-leaf path must "
                f"contain an initial ingress."
            )

    if pinned_entry_point_id is not None:
        all_ingress = [
            leaf
            for leaf in _collect_all_leaves(tree.root)
            if leaf.action is not None and leaf.action.kind == "initial_ingress"
        ]
        for leaf in all_ingress:
            action = leaf.action
            assert action is not None  # guarded by filter above
            if action.entry_point_id != pinned_entry_point_id:
                violations.append(
                    f"pinned-entry-point-mismatch: initial_ingress action uses "
                    f"entry_point_id '{action.entry_point_id}', expected "
                    f"'{pinned_entry_point_id}'."
                )

    # Validate ingress zone against canonical entry-point zone (cmps.9 review 3).
    # Also reject ingress-capable entries whose effective canonical ingress
    # zone is not active in the profile (cmps.9 review correction 5).
    # Use the centralized attacker-accessible ingress predicate so that
    # output-only, system-controlled, missing-zone, and inactive-zone entry
    # points are all rejected through one authority (cmps.9 third review 2).
    if profile is not None:
        active_zones = set(profile.zones_active) if profile.zones_active else set()
        for leaf in _collect_all_leaves(tree.root):
            action = leaf.action
            if action is None or action.kind != "initial_ingress":
                continue
            resolved_ep = profile.resolve_entry_point(action.entry_point_id)
            if resolved_ep is None:
                violations.append(
                    f"unresolved-ingress-zone: initial_ingress leaf '{leaf.id}' "
                    f"references entry_point_id '{action.entry_point_id}' "
                    f"that has no canonical ingress zone."
                )
                continue
            if not is_attacker_accessible_ingress(resolved_ep, active_zones):
                violations.append(
                    f"inaccessible-ingress-entry-point: initial_ingress leaf "
                    f"'{leaf.id}' references entry point "
                    f"'{resolved_ep.name}' (entry_point_id "
                    f"'{action.entry_point_id}') which is not an "
                    f"attacker-accessible ingress route (output-only, "
                    f"system-controlled, or inactive ingress zone)."
                )
                continue
            expected_zone = resolved_ep.effective_ingress_zone
            assert expected_zone is not None  # predicate guarantees this
            if leaf.zone != expected_zone:
                violations.append(
                    f"ingress-zone-mismatch: initial_ingress leaf '{leaf.id}' "
                    f"has zone '{leaf.zone}' but entry point "
                    f"'{action.entry_point_id}' requires zone "
                    f"'{expected_zone}'. The zone must match the canonical "
                    f"entry-point ingress zone, not be inferred from a label."
                )

    return violations


def _strip_non_skeleton_techniques_node(
    node: AttackTreeNode, skeleton_technique_ids: set[str]
) -> int:
    """Recursively strip technique_id from non-skeleton leaf nodes.

    Returns the number of technique_ids stripped.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if (
            node.technique_id is not None
            and node.technique_id not in skeleton_technique_ids
        ):
            logger.debug(
                "Stripping non-skeleton technique_id '%s' from leaf '%s'",
                node.technique_id,
                node.id,
            )
            node.technique_id = None
            stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _strip_non_skeleton_techniques_node(
                child, skeleton_technique_ids
            )
    return stripped


def _strip_non_skeleton_techniques(
    tree: AttackTree, skeleton_technique_ids: set[str]
) -> int:
    """Remove technique_id from leaves that are not in the skeleton.

    The skeleton builder places pinned techniques on mandatory leaves.
    The LLM tree generator often copies those technique IDs onto additional
    leaves it creates, producing decorative/semantically incorrect annotations.
    Only skeleton leaves (those whose technique_id is in the pinned set) should
    retain their technique annotations.

    Args:
        tree: The attack tree to post-process (mutated in place).
        skeleton_technique_ids: Set of pinned technique IDs that are allowed
            to remain on leaves. If empty, ALL leaf technique_ids are stripped.

    Returns:
        The number of technique_ids stripped.
    """
    return _strip_non_skeleton_techniques_node(tree.root, skeleton_technique_ids)


def _validate_technique_zone_node(node: AttackTreeNode) -> int:
    """Recursively strip technique_ids that violate zone constraints.

    Returns the number of technique_ids stripped.

    Action-aware (cmps.9): nodes with zone=None (external preconditions,
    external impacts) are skipped — they are outside the AI boundary.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if node.technique_id is not None and node.zone is not None:
            valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(node.technique_id)
            if valid_zones is not None and node.zone not in valid_zones:
                logger.warning(
                    "Technique-zone mismatch: stripping %s from node %s "
                    "(zone=%s, valid_zones=%s)",
                    node.technique_id,
                    node.id,
                    node.zone,
                    sorted(valid_zones),
                )
                node.technique_id = None
                stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _validate_technique_zone_node(child)
    return stripped


def _validate_technique_zone_compatibility(tree: AttackTree) -> int:
    """Strip technique_ids that violate TECHNIQUE_ZONE_CONSTRAINTS.

    Walks the tree and removes technique_id from any leaf node where
    the technique is not valid in the node's zone per the constraint map.
    Techniques absent from the map are unconstrained and pass.

    Returns the number of technique_ids stripped.
    """
    return _validate_technique_zone_node(tree.root)


def _count_leaves(node: AttackTreeNode) -> int:
    """Count leaf nodes in an attack tree rooted at *node*."""
    if node.gate == GateType.LEAF:
        return 1
    total = 0
    if node.children:
        for child in node.children:
            total += _count_leaves(child)
    return total


def _check_non_actionable_leaves(root: AttackTreeNode, violations: list[str]) -> None:
    """Check 6: flag non-actionable observation leaves.

    Walks the tree collecting LEAF nodes without a technique_id whose
    labels match observation-pattern keywords.  If >=2 such leaves exist,
    appends a violation describing them.
    """
    _OBSERVATION_KEYWORDS = [
        "confirm",
        "observe",
        "verify",
        "monitor",
        "validate",
        "note ",
        "detect ",
        "assess ",
    ]

    def _collect_leaves_recursive(node: AttackTreeNode) -> list[AttackTreeNode]:
        if node.gate == GateType.LEAF:
            return [node]
        leaves: list[AttackTreeNode] = []
        if node.children:
            for child in node.children:
                leaves.extend(_collect_leaves_recursive(child))
        return leaves

    leaves = _collect_leaves_recursive(root)
    matching_ids: list[str] = []
    for leaf in leaves:
        if leaf.technique_id:
            continue
        label_lower = leaf.label.lower()
        if any(kw in label_lower for kw in _OBSERVATION_KEYWORDS):
            matching_ids.append(leaf.id)

    if len(matching_ids) >= 2:
        violations.append(
            f"non-actionable-leaves: {len(matching_ids)} leaf node(s) appear "
            f"to describe observations rather than attacker actions "
            f"({', '.join(matching_ids)}). Remove non-actionable leaves or "
            f"assign a technique_id."
        )


def _check_consistency(
    tree: AttackTree,
    narrative: NarrativeLayer,
    parsimony_budget: int,
    step_node_floor: float = _STEP_NODE_CORRESPONDENCE_FLOOR,
    threat_id: str | None = None,
    tool_names: list[str] | None = None,
    pinned_technique_ids: list[str] | None = None,
) -> list[str]:
    """Run post-generation consistency checks on the attack tree.

    Returns a list of violation descriptions (empty if all checks pass).
    Checks:
      1. Parsimony — leaf count must not exceed budget.
      2. Zone-sequence — every narrative zone must appear in the tree.
      3. Step-node correspondence — ratio must meet the floor.
      4. Missing scenario threat_id — at least one tree node must carry the
         scenario's assigned threat_id.
      5. Tool-execution leaf grounding — every leaf in tool_execution zone
         must reference a tool from the inventory.
      6. Non-actionable leaf padding.
      7. Technique coverage — every pinned technique must appear on at least
         one leaf node.
    """
    violations: list[str] = []

    # Check 1: parsimony
    leaf_count = _count_leaves(tree.root)
    if leaf_count > parsimony_budget:
        violations.append(f"parsimony: {leaf_count} leaves > {parsimony_budget} budget")

    # Check 2: zone-sequence consistency
    narrative_zones = set(narrative.zone_sequence)
    tree_zones = _collect_zones_from_tree(tree.root)
    missing_zones = narrative_zones - tree_zones
    if missing_zones:
        violations.append(
            f"zone-sequence: zones {missing_zones} in narrative but not tree; "
            f"add at least one node in each missing zone: "
            f"{', '.join(sorted(missing_zones))}"
        )

    # Check 3: step-node correspondence
    step_count = len(narrative.steps)
    if leaf_count > 0 and step_count > 0:
        correspondence = min(step_count, leaf_count) / max(step_count, leaf_count)
        if correspondence < step_node_floor:
            violations.append(
                f"step-node: {correspondence:.2f} < {step_node_floor} floor"
            )
    elif step_count == 0:
        # No steps — cannot compute, not a violation
        pass
    elif leaf_count == 0:
        violations.append("step-node: 0 leaves in tree")

    # Check 4: missing scenario threat_id
    if threat_id is not None:
        all_threat_ids = {
            tid
            for tid in (n_tid for n_tid in _collect_threat_ids_from_tree_set(tree.root))
        }
        if threat_id not in all_threat_ids:
            violations.append(
                f"missing-scenario-threat-id: no tree node carries "
                f"threat_id '{threat_id}'; tree has "
                f"{sorted(all_threat_ids) if all_threat_ids else 'none'}. "
                f"At least one node must have threat_id='{threat_id}'"
            )

    # Check 5: tool-execution leaf grounding (typed action check)
    if tool_names is not None:
        _check_tool_execution_leaf_grounding(tree.root, violations)

    # Check 6: non-actionable leaf padding
    _check_non_actionable_leaves(tree.root, violations)

    # Check 7: pinned technique coverage
    if pinned_technique_ids:
        tree_technique_ids = set(tree.collect_technique_ids())
        missing_techniques = set(pinned_technique_ids) - tree_technique_ids
        if missing_techniques:
            violations.append(
                f"missing-pinned-technique: pinned technique(s) "
                f"{sorted(missing_techniques)} not found on any tree leaf; "
                f"tree has {sorted(tree_technique_ids) if tree_technique_ids else 'none'}. "
                f"Assign each missing technique_id to the leaf whose action "
                f"best matches the technique's mechanism."
            )

    return violations


def _collect_threat_ids_from_tree_set(
    node: AttackTreeNode,
) -> set[str]:
    """Collect all non-None threat_id values from tree nodes as a set."""
    ids: set[str] = set()
    if node.threat_id is not None:
        ids.add(node.threat_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_threat_ids_from_tree_set(child))
    return ids


def _check_tool_execution_leaf_grounding(
    node: AttackTreeNode,
    violations: list[str],
) -> None:
    """Check that tool_execution leaf nodes have a resolvable typed action (cmps.9).

    Uses typed action data, not label matching.  Per the authoritative
    ``ACTION_ZONE_RULES`` matrix, both ``tool_invocation`` and
    ``integration_interaction`` are valid in ``tool_execution``:

    - Leaves in ``tool_execution`` zone without a typed action whose kind
      is ``tool_invocation`` or ``integration_interaction``: flag as
      untyped-tool-execution.
    """
    if node.gate == GateType.LEAF:
        if node.zone == "tool_execution":
            action = node.action
            if action is None or action.kind not in (
                "tool_invocation",
                "integration_interaction",
            ):
                violations.append(
                    f"untyped-tool-execution: leaf '{node.id}' in "
                    f"tool_execution zone has no tool_invocation or "
                    f"integration_interaction action. Every tool_execution "
                    f"leaf must carry a resolvable typed action."
                )
    elif node.children:
        for child in node.children:
            _check_tool_execution_leaf_grounding(child, violations)
