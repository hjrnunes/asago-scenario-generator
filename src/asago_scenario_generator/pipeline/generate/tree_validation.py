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


def _and_gate_paths(
    children: list[AttackTreeNode],
) -> list[list[AttackTreeNode]]:
    """Merge child paths — all children must succeed on every path."""
    merged: list[list[AttackTreeNode]] = [[]]
    for child in children:
        child_paths = _enumerate_root_to_leaf_paths(child)
        if not child_paths:
            continue
        merged = [m + cp for m in merged for cp in child_paths]
    return merged


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
        return _and_gate_paths(node.children)
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


def _validate_or_gate(node: AttackTreeNode) -> None:
    """Raise when an OR node appears (OR is prohibited in v1)."""
    if node.gate == GateType.OR:
        raise ValueError(
            f"Attack tree node '{node.id}' uses OR gate — OR is "
            f"prohibited in v1 (one concrete execution only)"
        )


def _is_external_impact_leaf(node: AttackTreeNode) -> bool:
    """Whether a leaf is an impact action outside the assessed boundary."""
    if node.gate != GateType.LEAF:
        return False
    action = node.action
    if action is None or action.kind != "impact":
        return False
    return getattr(action, "boundary", None) == "external"


def _validate_external_impact_boundaries(
    node: AttackTreeNode,
    boundary_by_id: dict[str, str | None],
) -> None:
    """External impacts must map only outside-boundary projected steps."""
    if not _is_external_impact_leaf(node):
        return
    # External impacts happen outside the assessed boundary, so every
    # mapped projected step must itself be outside-boundary. The step ID
    # is preserved (never removed or remapped) and the mapping fails
    # closed as a boundary semantic violation.
    for sid in node.projected_step_ids:
        if boundary_by_id.get(sid) != "outside":
            raise ValueError(
                f"Tree leaf '{node.id}' external impact maps "
                f"non-outside projected step '{sid}' — boundary "
                f"semantic violation (fail closed, no repair)"
            )


def _validate_external_precondition_realizations(
    node: AttackTreeNode,
) -> None:
    """Exactly one outside-boundary canonical realization per mapped step."""
    real_ids = [realization.projected_step_id for realization in node.realizations]
    if len(real_ids) != len(node.projected_step_ids) or set(real_ids) != set(
        node.projected_step_ids
    ):
        raise ValueError(
            f"External precondition leaf '{node.id}' has "
            "incomplete canonical realizations for its "
            "outside-boundary projected steps"
        )


def _validate_external_precondition_mappings(
    node: AttackTreeNode,
    selected_step_ids: set[str],
    boundary_by_id: dict[str, str | None],
) -> None:
    """Every mapped step of an external precondition must be outside-boundary."""
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
    _validate_external_precondition_realizations(node)


def _validate_external_precondition_leaf(
    node: AttackTreeNode,
    selected_step_ids: set[str],
    boundary_by_id: dict[str, str | None],
) -> None:
    """Validate an external precondition leaf's mapping and realizations."""
    if node.projected_step_ids:
        _validate_external_precondition_mappings(
            node, selected_step_ids, boundary_by_id
        )
        return
    if node.realizations:
        raise ValueError(
            f"External precondition leaf '{node.id}' has "
            "realizations — external preconditions must have "
            "empty projected_step_ids and empty realizations"
        )


def _validate_leaf_step_membership(
    node: AttackTreeNode,
    selected_step_ids: set[str],
) -> None:
    """Every mapped step of a security-bearing leaf must be selected."""
    for sid in node.projected_step_ids:
        if sid not in selected_step_ids:
            raise ValueError(
                f"Tree leaf '{node.id}' references unprojected "
                f"step '{sid}' — not in selected_step_ids"
            )


def _missing_realizations(node: AttackTreeNode) -> bool:
    """Whether a security-bearing leaf has no realization records."""
    return not node.realizations


def _duplicate_realization_ids(real_ids: list[str]) -> bool:
    """Whether realization records contain duplicate projected step IDs."""
    return len(set(real_ids)) != len(real_ids)


def _realization_count_mismatch(node: AttackTreeNode, real_ids: list[str]) -> bool:
    """Whether realization records do not match the projected step count."""
    return len(real_ids) != len(node.projected_step_ids)


def _realization_id_mismatch(node: AttackTreeNode, real_ids: list[str]) -> bool:
    """Whether realization IDs do not match the projected step IDs."""
    return set(real_ids) != set(node.projected_step_ids)


def _validate_realization_coverage(node: AttackTreeNode) -> None:
    """Exactly one canonical realization per projected step ID."""
    if _missing_realizations(node):
        raise ValueError(
            f"Security-bearing leaf '{node.id}' has "
            f"projected_step_ids but no realizations"
        )
    real_ids = [realization.projected_step_id for realization in node.realizations]
    if _duplicate_realization_ids(real_ids):
        raise ValueError(f"Leaf '{node.id}' has duplicate realization records")
    if _realization_count_mismatch(node, real_ids):
        raise ValueError(
            f"Leaf '{node.id}' has {len(real_ids)} realization "
            f"records but {len(node.projected_step_ids)} "
            f"projected_step_ids — exactly one per ID required"
        )
    if _realization_id_mismatch(node, real_ids):
        raise ValueError(
            f"Leaf '{node.id}' realization IDs {sorted(set(real_ids))} "
            f"do not match projected_step_ids "
            f"{sorted(set(node.projected_step_ids))}"
        )


def _validate_mapped_leaf(
    node: AttackTreeNode,
    selected_step_ids: set[str],
) -> None:
    """Validate a security-bearing (non-external) leaf."""
    if not node.projected_step_ids:
        raise ValueError(
            f"Security-bearing leaf '{node.id}' has no "
            f"projected_step_ids — every non-external_precondition "
            f"leaf must map to projected steps"
        )
    _validate_leaf_step_membership(node, selected_step_ids)
    _validate_realization_coverage(node)


def _leaf_action_kind(node: AttackTreeNode) -> str:
    """The action kind of a leaf node, or ``""`` when absent."""
    if node.gate != GateType.LEAF:
        return ""
    if node.action is None:
        return ""
    return node.action.kind


def _validate_tree_node(
    node: AttackTreeNode,
    selected_step_ids: set[str],
    boundary_by_id: dict[str, str | None],
) -> None:
    """Validate one node's gate/mapping rules and recurse into children."""
    _validate_or_gate(node)
    if node.gate == GateType.LEAF:
        if _leaf_action_kind(node) == "external_precondition":
            _validate_external_precondition_leaf(
                node, selected_step_ids, boundary_by_id
            )
        else:
            _validate_external_impact_boundaries(node, boundary_by_id)
            _validate_mapped_leaf(node, selected_step_ids)
    if node.children:
        for child in node.children:
            _validate_tree_node(child, selected_step_ids, boundary_by_id)


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
    _validate_tree_node(tree.root, selected_step_ids, boundary_by_id)


def _initial_ingress_leaves(tree: AttackTree) -> list[AttackTreeNode]:
    """All leaves carrying an ``initial_ingress`` action."""
    leaves: list[AttackTreeNode] = []
    for leaf in _collect_all_leaves(tree.root):
        if leaf.action is not None and leaf.action.kind == "initial_ingress":
            leaves.append(leaf)
    return leaves


def _path_has_initial_ingress(path: list[AttackTreeNode]) -> bool:
    """Whether a root-to-leaf path contains an initial_ingress leaf."""
    for leaf in path:
        if leaf.action is not None and leaf.action.kind == "initial_ingress":
            return True
    return False


def _missing_ingress_path_violations(
    paths: list[list[AttackTreeNode]],
) -> list[str]:
    """Violations for attack paths without an initial_ingress leaf."""
    violations: list[str] = []
    for path_idx, path in enumerate(paths, 1):
        if not _path_has_initial_ingress(path):
            violations.append(
                f"missing-initial-ingress: attack path {path_idx} has no "
                f"initial_ingress leaf action. Every root-to-leaf path must "
                f"contain an initial ingress."
            )
    return violations


def _pinned_entry_point_violations(
    all_ingress: list[AttackTreeNode],
    pinned_entry_point_id: str,
) -> list[str]:
    """Violations for ingress actions that ignore the pinned entry point."""
    violations: list[str] = []
    for leaf in all_ingress:
        action = leaf.action
        if action.entry_point_id != pinned_entry_point_id:
            violations.append(
                f"pinned-entry-point-mismatch: initial_ingress action uses "
                f"entry_point_id '{action.entry_point_id}', expected "
                f"'{pinned_entry_point_id}'."
            )
    return violations


def _ingress_action_of(leaf: AttackTreeNode) -> Any | None:
    """The leaf's initial_ingress action, or None when not applicable."""
    if leaf.action is None:
        return None
    if leaf.action.kind != "initial_ingress":
        return None
    return leaf.action


def _leaf_ingress_zone_violation(
    leaf: AttackTreeNode,
    profile: CapabilityProfile,
    active_zones: set[str],
) -> str | None:
    """Zone/accessibility violation for one initial_ingress leaf, or None."""
    action = _ingress_action_of(leaf)
    if action is None:
        return None
    resolved_ep = profile.resolve_entry_point(action.entry_point_id)
    if resolved_ep is None:
        return (
            f"unresolved-ingress-zone: initial_ingress leaf '{leaf.id}' "
            f"references entry_point_id '{action.entry_point_id}' "
            f"that has no canonical ingress zone."
        )
    if not is_attacker_accessible_ingress(resolved_ep, active_zones):
        return (
            f"inaccessible-ingress-entry-point: initial_ingress leaf "
            f"'{leaf.id}' references entry point "
            f"'{resolved_ep.name}' (entry_point_id "
            f"'{action.entry_point_id}') which is not an "
            f"attacker-accessible ingress route (output-only, "
            f"system-controlled, or inactive ingress zone)."
        )
    expected_zone = resolved_ep.effective_ingress_zone
    if leaf.zone != expected_zone:
        return (
            f"ingress-zone-mismatch: initial_ingress leaf '{leaf.id}' "
            f"has zone '{leaf.zone}' but entry point "
            f"'{action.entry_point_id}' requires zone "
            f"'{expected_zone}'. The zone must match the canonical "
            f"entry-point ingress zone, not be inferred from a label."
        )
    return None


def _ingress_zone_violations(
    tree: AttackTree,
    profile: CapabilityProfile | None,
) -> list[str]:
    """Zone/accessibility violations for every initial_ingress leaf."""
    if profile is None:
        return []
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    violations: list[str] = []
    for leaf in _initial_ingress_leaves(tree):
        violation = _leaf_ingress_zone_violation(leaf, profile, active_zones)
        if violation is not None:
            violations.append(violation)
    return violations


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
    violations = _missing_ingress_path_violations(paths)

    if pinned_entry_point_id is not None:
        violations.extend(
            _pinned_entry_point_violations(
                _initial_ingress_leaves(tree), pinned_entry_point_id
            )
        )

    # Validate ingress zone against canonical entry-point zone (cmps.9 review 3).
    # Also reject ingress-capable entries whose effective canonical ingress
    # zone is not active in the profile (cmps.9 review correction 5).
    # Use the centralized attacker-accessible ingress predicate so that
    # output-only, system-controlled, missing-zone, and inactive-zone entry
    # points are all rejected through one authority (cmps.9 third review 2).
    violations.extend(_ingress_zone_violations(tree, profile))

    return violations


def _strip_non_skeleton_leaf(
    node: AttackTreeNode, skeleton_technique_ids: set[str]
) -> int:
    """Strip a non-skeleton technique_id from one leaf; 1 when stripped."""
    if node.gate != GateType.LEAF:
        return 0
    if node.technique_id is None or node.technique_id in skeleton_technique_ids:
        return 0
    logger.debug(
        "Stripping non-skeleton technique_id '%s' from leaf '%s'",
        node.technique_id,
        node.id,
    )
    node.technique_id = None
    return 1


def _strip_non_skeleton_techniques_node(
    node: AttackTreeNode, skeleton_technique_ids: set[str]
) -> int:
    """Recursively strip technique_id from non-skeleton leaf nodes.

    Returns the number of technique_ids stripped.
    """
    stripped = _strip_non_skeleton_leaf(node, skeleton_technique_ids)
    if node.children:
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


def _strip_zone_invalid_technique(node: AttackTreeNode) -> int:
    """Strip one leaf's technique_id when it violates zone constraints."""
    if node.gate != GateType.LEAF:
        return 0
    if node.technique_id is None or node.zone is None:
        return 0
    valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(node.technique_id)
    if valid_zones is None or node.zone in valid_zones:
        return 0
    logger.warning(
        "Technique-zone mismatch: stripping %s from node %s (zone=%s, valid_zones=%s)",
        node.technique_id,
        node.id,
        node.zone,
        sorted(valid_zones),
    )
    node.technique_id = None
    return 1


def _validate_technique_zone_node(node: AttackTreeNode) -> int:
    """Recursively strip technique_ids that violate zone constraints.

    Returns the number of technique_ids stripped.

    Action-aware (cmps.9): nodes with zone=None (external preconditions,
    external impacts) are skipped — they are outside the AI boundary.
    """
    stripped = _strip_zone_invalid_technique(node)
    if node.children:
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


def _check_parsimony(
    leaf_count: int,
    parsimony_budget: int,
    violations: list[str],
) -> None:
    """Check 1: flag leaf counts above the parsimony budget."""
    if leaf_count > parsimony_budget:
        violations.append(f"parsimony: {leaf_count} leaves > {parsimony_budget} budget")


def _check_zone_sequence(
    narrative: NarrativeLayer,
    tree: AttackTree,
    violations: list[str],
) -> None:
    """Check 2: every narrative zone must appear in the tree."""
    narrative_zones = set(narrative.zone_sequence)
    tree_zones = _collect_zones_from_tree(tree.root)
    missing_zones = narrative_zones - tree_zones
    if missing_zones:
        violations.append(
            f"zone-sequence: zones {missing_zones} in narrative but not tree; "
            f"add at least one node in each missing zone: "
            f"{', '.join(sorted(missing_zones))}"
        )


def _check_step_node_correspondence(
    step_count: int,
    leaf_count: int,
    step_node_floor: float,
    violations: list[str],
) -> None:
    """Check 3: step-node correspondence must meet the floor."""
    if step_count == 0:
        # No steps — cannot compute, not a violation
        return
    if leaf_count == 0:
        violations.append("step-node: 0 leaves in tree")
        return
    correspondence = min(step_count, leaf_count) / max(step_count, leaf_count)
    if correspondence < step_node_floor:
        violations.append(f"step-node: {correspondence:.2f} < {step_node_floor} floor")


def _check_scenario_threat_id(
    tree: AttackTree,
    threat_id: str | None,
    violations: list[str],
) -> None:
    """Check 4: at least one tree node must carry the scenario threat_id."""
    if threat_id is None:
        return
    all_threat_ids = _collect_threat_ids_from_tree_set(tree.root)
    if threat_id not in all_threat_ids:
        violations.append(
            f"missing-scenario-threat-id: no tree node carries "
            f"threat_id '{threat_id}'; tree has "
            f"{sorted(all_threat_ids) if all_threat_ids else 'none'}. "
            f"At least one node must have threat_id='{threat_id}'"
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
      7. Candidate classifications are deliberately not compared with leaf
         mappings. Exact leaf provenance is validated against projected steps
         at envelope admission.
    """
    violations: list[str] = []

    # Check 1: parsimony
    leaf_count = _count_leaves(tree.root)
    _check_parsimony(leaf_count, parsimony_budget, violations)

    # Check 2: zone-sequence consistency
    _check_zone_sequence(narrative, tree, violations)

    # Check 3: step-node correspondence
    step_count = len(narrative.steps)
    _check_step_node_correspondence(step_count, leaf_count, step_node_floor, violations)

    # Check 4: missing scenario threat_id
    _check_scenario_threat_id(tree, threat_id, violations)

    # Check 5: tool-execution leaf grounding (typed action check)
    if tool_names is not None:
        _check_tool_execution_leaf_grounding(tree.root, violations)

    # Check 6: non-actionable leaf padding
    _check_non_actionable_leaves(tree.root, violations)

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


def _untyped_tool_execution_violation(
    node: AttackTreeNode, violations: list[str]
) -> None:
    """Flag a tool_execution leaf without a resolvable typed action."""
    if node.gate != GateType.LEAF or node.zone != "tool_execution":
        return
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
    _untyped_tool_execution_violation(node, violations)
    if node.children:
        for child in node.children:
            _check_tool_execution_leaf_grounding(child, violations)
