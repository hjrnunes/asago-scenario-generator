"""Parsimony budgeting and safe redundant-branch pruning."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    _repair_node,
)
from asago_scenario_generator.pipeline.validation_common import _collect_leaves

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)

# Parsimony pruning — data structures
# ---------------------------------------------------------------------------


@dataclass
class PrunedNode:
    """Record of a single pruned leaf node."""

    node_id: str
    label: str
    parent_gate: str  # "AND" or "OR"
    reason: str  # why it was safe to prune


@dataclass
class ParsimonyResult:
    """Result of parsimony pruning across a batch of scenarios."""

    compliant_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    pruned_scenarios: list[tuple[ScenarioEnvelope, list[PrunedNode]]] = field(
        default_factory=list
    )
    unprunable_scenarios: list[tuple[ScenarioEnvelope, int, int]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Parsimony pruning — helpers
# ---------------------------------------------------------------------------


def _collect_technique_ids(node: AttackTreeNode) -> set[str]:
    """Walk a tree and return the set of unique technique_ids."""
    ids: set[str] = set()
    if node.technique_id:
        ids.add(node.technique_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_technique_ids(child))
    return ids


def _find_parent(root: AttackTreeNode, target_id: str) -> AttackTreeNode | None:
    """Find the parent of the node with the given id."""
    if root.children:
        for child in root.children:
            if child.id == target_id:
                return root
            result = _find_parent(child, target_id)
            if result is not None:
                return result
    return None


def _sibling_labels(parent: AttackTreeNode, node_id: str) -> list[str]:
    """Return labels of siblings (other children of the same parent)."""
    if not parent.children:
        return []
    return [c.label for c in parent.children if c.id != node_id]


def _token_overlap_ratio(label: str, siblings: list[str]) -> float:
    """Compute how much a label's tokens overlap with sibling labels.

    Higher ratio = more redundant = better pruning candidate.
    """
    if not siblings:
        return 0.0
    tokens = set(label.lower().split())
    if not tokens:
        return 0.0
    sibling_tokens: set[str] = set()
    for sib in siblings:
        sibling_tokens.update(sib.lower().split())
    overlap = tokens & sibling_tokens
    return len(overlap) / len(tokens)


def _pruning_priority(
    leaf: AttackTreeNode,
    parent: AttackTreeNode,
    siblings: list[str],
) -> tuple[int, float, int]:
    """Return a sort key for pruning priority.

    Lower values = prune first.
    Priority order:
      1. AND-gate children before OR-gate children (AND=0, OR=1)
      2. Higher token overlap with siblings (negate for ascending sort)
      3. Shorter labels (less semantic content)
    """
    gate_priority = 0 if parent.gate == GateType.AND else 1
    overlap = _token_overlap_ratio(leaf.label, siblings)
    return (gate_priority, -overlap, len(leaf.label))


def _remove_child(parent: AttackTreeNode, child_id: str) -> None:
    """Remove a child node from a parent's children list."""
    if parent.children:
        parent.children = [c for c in parent.children if c.id != child_id]


def _repair_tree_model(root_dict: dict[str, Any]) -> dict[str, Any]:
    """Apply _repair_node to collapse single-child gates after pruning."""
    return _repair_node(root_dict)


# ---------------------------------------------------------------------------
# Parsimony pruning — main function
# ---------------------------------------------------------------------------


def _scenario_leaf_budget(scenario: ScenarioEnvelope) -> int:
    """The parsimony leaf budget for one scenario's tree."""
    from asago_scenario_generator.pipeline.generate.constants import (
        compute_leaf_budget,
    )

    tree = scenario.attack_tree
    technique_ids = _collect_technique_ids(tree.root)
    return compute_leaf_budget(len(technique_ids))


def _leaf_is_prunable_candidate(leaf: AttackTreeNode) -> bool:
    """True when a leaf is unannotated and lacks a typed action."""
    if leaf.technique_id:
        return False
    if leaf.action is not None:
        return False
    return True


def _safe_pruning_parent(
    root: AttackTreeNode, leaf: AttackTreeNode
) -> tuple[AttackTreeNode, list[str]] | None:
    """The parent that may safely lose this leaf, with sibling labels."""
    parent = _find_parent(root, leaf.id)
    if parent is None:
        return None
    if parent.children and len(parent.children) < 2:
        return None
    return parent, _sibling_labels(parent, leaf.id)


def _pruning_candidates(
    leaves: list[AttackTreeNode], root: AttackTreeNode
) -> list[tuple[AttackTreeNode, AttackTreeNode, list[str]]]:
    """Unannotated leaves with a parent that can safely lose one child."""
    candidates: list[tuple[AttackTreeNode, AttackTreeNode, list[str]]] = []
    for leaf in leaves:
        if not _leaf_is_prunable_candidate(leaf):
            continue
        parent_ctx = _safe_pruning_parent(root, leaf)
        if parent_ctx is None:
            continue
        parent, siblings = parent_ctx
        candidates.append((leaf, parent, siblings))
    return candidates


def _pruned_node_record(
    leaf: AttackTreeNode, parent: AttackTreeNode, siblings: list[str]
) -> PrunedNode:
    """Record of one pruned leaf."""
    return PrunedNode(
        node_id=leaf.id,
        label=leaf.label,
        parent_gate=parent.gate.value,
        reason=(
            f"Unannotated leaf under {parent.gate.value} gate; "
            f"token overlap with siblings: "
            f"{_token_overlap_ratio(leaf.label, siblings):.0%}"
        ),
    )


def _collapse_if_single_child(
    parent: AttackTreeNode,
    pruned_root: AttackTreeNode,
    pruned_scenario: ScenarioEnvelope,
) -> AttackTreeNode:
    """Collapse a single-child gate via repair when the parent is left alone."""
    if parent.children and len(parent.children) == 1:
        # Convert to dict, repair, convert back
        root_dict = pruned_root.model_dump()
        repaired_dict = _repair_tree_model(root_dict)
        repaired_root = AttackTreeNode.model_validate(repaired_dict)
        pruned_scenario.attack_tree = AttackTree(
            id=pruned_scenario.attack_tree.id,
            seed_id=pruned_scenario.attack_tree.seed_id,
            goal=pruned_scenario.attack_tree.goal,
            root=repaired_root,
        )
        return repaired_root
    return pruned_root


def _prune_to_budget(
    scenario: ScenarioEnvelope, budget: int
) -> tuple[ScenarioEnvelope, list[PrunedNode]] | None:
    """Deep-copy prune excess leaves; None when no safe candidates remain."""
    # Deep-copy so we don't mutate the original
    pruned_scenario = copy.deepcopy(scenario)
    pruned_root = pruned_scenario.attack_tree.root
    pruned_nodes: list[PrunedNode] = []

    while True:
        current_leaves = _collect_leaves(pruned_root)
        current_leaf_count = len(current_leaves)

        if current_leaf_count <= budget:
            break

        # Find pruning candidates: unannotated leaves
        candidates = _pruning_candidates(current_leaves, pruned_root)
        if not candidates:
            break  # no safe candidates remain

        # Sort by pruning priority
        candidates.sort(key=lambda x: _pruning_priority(x[0], x[1], x[2]))

        # Prune the best candidate
        leaf, parent, siblings = candidates[0]
        _remove_child(parent, leaf.id)
        pruned_nodes.append(_pruned_node_record(leaf, parent, siblings))

        # If parent now has exactly 1 child, collapse it
        pruned_root = _collapse_if_single_child(parent, pruned_root, pruned_scenario)

    return pruned_scenario, pruned_nodes


def _register_pruning_result(
    result: ParsimonyResult,
    scenario: ScenarioEnvelope,
    pruned_scenario: ScenarioEnvelope,
    pruned_nodes: list[PrunedNode],
    budget: int,
    original_leaf_count: int,
) -> None:
    """Re-validate the pruned tree and register the scenario outcome."""
    final_leaves = _collect_leaves(pruned_scenario.attack_tree.root)
    final_leaf_count = len(final_leaves)

    if final_leaf_count <= budget:
        # Validate with Pydantic to ensure structural integrity
        try:
            pruned_scenario.attack_tree = AttackTree.model_validate(
                pruned_scenario.attack_tree.model_dump()
            )
            result.pruned_scenarios.append((pruned_scenario, pruned_nodes))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Pruned tree for %s failed Pydantic validation: %s",
                scenario.scenario_id,
                exc,
            )
            result.unprunable_scenarios.append((scenario, original_leaf_count, budget))
    else:
        result.unprunable_scenarios.append((scenario, final_leaf_count, budget))


def enforce_parsimony(
    scenarios: list[ScenarioEnvelope],
    max_leaf_factor: int = 2,
    max_leaf_offset: int = 2,
) -> ParsimonyResult:
    """Prune excess unannotated leaves from attack trees.

    For each scenario, computes a leaf budget based on the number of
    unique technique_ids in the tree using :func:`compute_leaf_budget`.

    The ``max_leaf_factor`` and ``max_leaf_offset`` parameters are
    deprecated and ignored -- the canonical formula lives in
    ``compute_leaf_budget()``.  They are retained for API compatibility.

    Leaves without a technique_id or typed action are pruning candidates.
    They are removed one at a time (most redundant first) until the leaf
    count is within budget, or no more safe candidates remain. Typed leaves
    are preserved even when that makes the scenario unprunable.

    After pruning, single-child AND/OR gates are collapsed via
    ``_repair_node`` and the resulting tree is re-validated with Pydantic.
    """
    result = ParsimonyResult()

    for scenario in scenarios:
        budget = _scenario_leaf_budget(scenario)

        leaves = _collect_leaves(scenario.attack_tree.root)
        leaf_count = len(leaves)

        if leaf_count <= budget:
            result.compliant_scenarios.append(scenario)
            continue

        pruned = _prune_to_budget(scenario, budget)
        pruned_scenario, pruned_nodes = pruned
        _register_pruning_result(
            result, scenario, pruned_scenario, pruned_nodes, budget, leaf_count
        )

    return result
