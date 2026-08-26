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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:28:57Z","module_hash":"0fdcf5c987fc680d334a0d7a49f48688077e1d1cadd40fe855653567518d3bef","source_sha256":"beac2dfdb9c1d0e58e4348b2eec86c092dde286b5da5f111d9e826e35fab395d","functions":[{"id":"func/_and_gate_paths","name":"_and_gate_paths","line":36,"end_line":46,"hash":"9904cf08c1145487f04ce9a025b7356c2561674dc82472297bc76f3094c6566f"},{"id":"func/_enumerate_root_to_leaf_paths","name":"_enumerate_root_to_leaf_paths","line":49,"end_line":65,"hash":"351de946e703b503a3ce409f6c1883bbf2a48f38c97e01c307b1528bedc714ac"},{"id":"func/_collect_all_leaves","name":"_collect_all_leaves","line":68,"end_line":76,"hash":"f9c9487f0e869ddc2f73b86f998f04bb9d7fa5998b2f150bdac38a2ab96ff5ca"},{"id":"func/_validate_or_gate","name":"_validate_or_gate","line":79,"end_line":85,"hash":"d2f8fb9ebe8170362ee6521d34e2637ae89461e3e28b364089201c3ad8fbe84d"},{"id":"func/_is_external_impact_leaf","name":"_is_external_impact_leaf","line":88,"end_line":95,"hash":"69c233d52e185254d095521a0aef2c89a16b2f8aa9e2be10b6fcd8131a2f1ce3"},{"id":"func/_validate_external_impact_boundaries","name":"_validate_external_impact_boundaries","line":98,"end_line":115,"hash":"f6060e201d5d496c21ee209fa84cc1bc0fd48b2aa822a1a99bcb3a9e1f2705f9"},{"id":"func/_validate_external_precondition_realizations","name":"_validate_external_precondition_realizations","line":118,"end_line":130,"hash":"dd85b5fdd12824ceba06fc9b315ccf858cc6fa8aadb8cebac1766b1e78eade45"},{"id":"func/_validate_external_precondition_mappings","name":"_validate_external_precondition_mappings","line":133,"end_line":151,"hash":"927db89cd4fb90504e71c60858110daddd8280593adf9e561c1d1aaae5c05012"},{"id":"func/_validate_external_precondition_leaf","name":"_validate_external_precondition_leaf","line":154,"end_line":170,"hash":"f0b6010caea2baf251c8570b6418ea4b5768c5f574bdbdea2a97b82b4a4c9760"},{"id":"func/_validate_leaf_step_membership","name":"_validate_leaf_step_membership","line":173,"end_line":183,"hash":"58a11fc32508f84359615f01b8963f90b42b9764db22afd1abbccca7b132e29d"},{"id":"func/_missing_realizations","name":"_missing_realizations","line":186,"end_line":188,"hash":"0e0c1c5ebc6ee4b706ed7dcd533b352552c9181e519a764ac506472eb6b386b1"},{"id":"func/_duplicate_realization_ids","name":"_duplicate_realization_ids","line":191,"end_line":193,"hash":"c2dd6ee516f2d728b8adff92a061a541d4be57c03c29f68266a87dd4a431ebb4"},{"id":"func/_realization_count_mismatch","name":"_realization_count_mismatch","line":196,"end_line":198,"hash":"afa7e12baad23c02aa2f065389437d65ab308b2c2931da73b2d6d2199a68dafd"},{"id":"func/_realization_id_mismatch","name":"_realization_id_mismatch","line":201,"end_line":203,"hash":"befb16ba16a1e742df1e3f3319872e2664afd0334c2a732155bc31c35ffe96e3"},{"id":"func/_validate_realization_coverage","name":"_validate_realization_coverage","line":206,"end_line":227,"hash":"14680b4b03b6874e1c8c7a870aba9b7f9d6a13e13cd8a45dd81200f0f21921a7"},{"id":"func/_validate_mapped_leaf","name":"_validate_mapped_leaf","line":230,"end_line":242,"hash":"2fbe8596b68d8f215151564c52c5820935807f09ed3c339816650d158b9369a1"},{"id":"func/_leaf_action_kind","name":"_leaf_action_kind","line":245,"end_line":251,"hash":"c2a35075f48f5a5f6d578f22722698649b8c7b16f3a9390e2dcbda3c9a1093ad"},{"id":"func/_validate_tree_node","name":"_validate_tree_node","line":254,"end_line":271,"hash":"12f0364cfc7bf133be5898eadbddca64c22b7cc5a5922d066781a0f838683b8e"},{"id":"func/_validate_tree_against_projection","name":"_validate_tree_against_projection","line":274,"end_line":299,"hash":"d0ed76da4f7c0c323445ce3aeca7988c93a1d87055ac4322cc50104ebfbab9b0"},{"id":"func/_initial_ingress_leaves","name":"_initial_ingress_leaves","line":302,"end_line":308,"hash":"a79010505f31c0140af56ef6826e2c02893339c62c9ac7d8160a2ff048834b6d"},{"id":"func/_path_has_initial_ingress","name":"_path_has_initial_ingress","line":311,"end_line":316,"hash":"5743a412d184599642f6b75437cfa54fc2391a42df6e53beeea484185805c967"},{"id":"func/_missing_ingress_path_violations","name":"_missing_ingress_path_violations","line":319,"end_line":331,"hash":"91c7a9f355b44c43160e5ac332b8b0bb73ef33e061cd129e38773bc44f2f4d6f"},{"id":"func/_pinned_entry_point_violations","name":"_pinned_entry_point_violations","line":334,"end_line":348,"hash":"3a35491c13398af7c181b864a8109f21afa138c0873a39b500c7d1fe9f9b7965"},{"id":"func/_ingress_action_of","name":"_ingress_action_of","line":351,"end_line":357,"hash":"89758f00c2b8f3038d4ed1fc09dec2a01cdbb25673a6c528a1a2b717a69b9c5c"},{"id":"func/_leaf_ingress_zone_violation","name":"_leaf_ingress_zone_violation","line":360,"end_line":394,"hash":"74105e8bfedc93479ed592c03d83c0f437ab468f44264384f9204950594899bf"},{"id":"func/_ingress_zone_violations","name":"_ingress_zone_violations","line":397,"end_line":410,"hash":"da462ae153646cb6838d84397d733639df2440801dc6810af22af07c84f424e8"},{"id":"func/_validate_pinned_ingress","name":"_validate_pinned_ingress","line":413,"end_line":447,"hash":"04063032ef823205eecc279e37a05d3a00652fb0c0c16696486a50aa5003b2a7"},{"id":"func/_strip_non_skeleton_leaf","name":"_strip_non_skeleton_leaf","line":450,"end_line":464,"hash":"628ad42c3f91084a4bf7289d91ff0ae7efc0298c59c7ca9c893e774e084f3c02"},{"id":"func/_strip_non_skeleton_techniques_node","name":"_strip_non_skeleton_techniques_node","line":467,"end_line":480,"hash":"a77229e6cfe0523aa20aa9c7a08f770385dc52926de23712428c1ebcbb076b08"},{"id":"func/_strip_non_skeleton_techniques","name":"_strip_non_skeleton_techniques","line":483,"end_line":502,"hash":"87aba6087ce02d10ecc32b90f328b643291e77459662da54e30ec6ccc79cccdd"},{"id":"func/_strip_zone_invalid_technique","name":"_strip_zone_invalid_technique","line":505,"end_line":522,"hash":"2508baea7fb668be7519050f68ea4f2b7720e3e49bb268a7a59072bfb5684e1d"},{"id":"func/_validate_technique_zone_node","name":"_validate_technique_zone_node","line":525,"end_line":537,"hash":"fdd32ffa32c20d72ef119e6b97fe01dae03cee91a5354cd14e070386e4421550"},{"id":"func/_validate_technique_zone_compatibility","name":"_validate_technique_zone_compatibility","line":540,"end_line":549,"hash":"5d43bc9d1eb2453b8de7fac05f15b901699f6b816db75da0e4a81dfe83c4dc7a"},{"id":"func/_count_leaves","name":"_count_leaves","line":552,"end_line":560,"hash":"8484966db316e8dd744628708e7b84ed8d7451ba4fa0b6835cfcba6c9d9bdb5c"},{"id":"func/_check_non_actionable_leaves","name":"_check_non_actionable_leaves","line":563,"end_line":605,"hash":"08092cb29ced2248df63494b397c40522593c05bb53536e395fd6cb037a47cd6"},{"id":"func/_check_parsimony","name":"_check_parsimony","line":608,"end_line":615,"hash":"c94ecd7b5e559d773f8da91c784eb34c22aa4dec0115d42dcac29c0b08f17ac1"},{"id":"func/_check_zone_sequence","name":"_check_zone_sequence","line":618,"end_line":632,"hash":"f5868d604449c3262c1752da3f59be2aea6177768459c519f672ccc29309ac04"},{"id":"func/_check_step_node_correspondence","name":"_check_step_node_correspondence","line":635,"end_line":650,"hash":"8c2916ad835129f393f8b716a8e56a679eff39713908780daa08919296b4a699"},{"id":"func/_check_scenario_threat_id","name":"_check_scenario_threat_id","line":653,"end_line":668,"hash":"079b1f77608d2cb1a8c5e18afb9c8d728699f840df81d728d3f70976d949df74"},{"id":"func/_check_consistency","name":"_check_consistency","line":671,"end_line":719,"hash":"818689676ceee4da086f12044604079ca6317b47aa7d525f6717f8d4519c328c"},{"id":"func/_collect_threat_ids_from_tree_set","name":"_collect_threat_ids_from_tree_set","line":722,"end_line":732,"hash":"c982a146d1207b2e46c96839a864b20dd9ffdf2649b160da111d7cff1be86f89"},{"id":"func/_untyped_tool_execution_violation","name":"_untyped_tool_execution_violation","line":735,"end_line":751,"hash":"147976e68884aa2cbb223d38d2ece3575cc94571b076d318482794bd283fd071"},{"id":"func/_check_tool_execution_leaf_grounding","name":"_check_tool_execution_leaf_grounding","line":754,"end_line":771,"hash":"00c620172966903fd41e21f544f7195718b69c09af100796b682186a69638432"}]}
# mutate4py-manifest-end
