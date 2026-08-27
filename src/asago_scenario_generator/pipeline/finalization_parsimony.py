"""Safe parsimony repair for pre-behavior attack trees."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.pipeline.finalization_contracts import GeneratedStage
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
)
from asago_scenario_generator.pipeline.finalization_snapshots import (
    FinalTreeSemanticSnapshot,
)


@dataclass(frozen=True, slots=True)
class RepairRecord:
    before_digest: str
    after_digest: str
    removed_ids: tuple[str, ...]
    preserved_projected_ids: tuple[str, ...]
    accepted: bool
    detail: str


@dataclass(frozen=True, slots=True)
class TreeParsimonyResult:
    tree: AttackTree
    violations: tuple[GateViolation, ...] = ()
    record: RepairRecord | None = None


def _leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    if node.gate is GateType.LEAF:
        return [node]
    return [leaf for child in node.children or () for leaf in _leaves(child)]


def _nodes(node: AttackTreeNode) -> list[AttackTreeNode]:
    return [node, *(item for child in node.children or () for item in _nodes(child))]


def _default_leaf_budget(tree: AttackTree) -> int:
    from asago_scenario_generator.pipeline.generate.constants import (
        compute_leaf_budget,
    )

    technique_budget = compute_leaf_budget(len(set(tree.collect_technique_ids())))
    projected_step_floor = len(
        {step_id for leaf in _leaves(tree.root) for step_id in leaf.projected_step_ids}
    )
    return max(technique_budget, projected_step_floor)


def check_tree_parsimony(tree: AttackTree, *, budget: int | None = None) -> GateResult:
    leaves = _leaves(tree.root)
    if budget is None:
        budget = _default_leaf_budget(tree)
    if len(leaves) <= budget:
        return GateResult(AdmissionEvidenceId.tree_parsimony)
    return GateResult(
        AdmissionEvidenceId.tree_parsimony,
        (
            GateViolation(
                GateCode.parsimony,
                f"{len(leaves)} leaves exceed budget {budget}",
                GeneratedStage.tree,
            ),
        ),
    )


def _leaf_node_prunable(node: AttackTreeNode) -> bool:
    """A leaf is redundant only when it carries no typed action."""
    return node.action is None


def _and_gate_unannotated(node: AttackTreeNode) -> bool:
    """True when the AND gate carries no identity annotations."""
    return (
        node.zone is None
        and node.threat_id is None
        and node.technique_id is None
        and node.tactic is None
    )


def _and_gate_unsupported(node: AttackTreeNode) -> bool:
    """True when the AND gate carries no structural metadata."""
    return (
        node.maestro_layer is None
        and node.control_point is None
        and node.structural_exposure is None
    )


def _and_gate_unrealized(node: AttackTreeNode) -> bool:
    """True when the AND gate carries no realization content."""
    return not node.projected_step_ids and not node.realizations


def _children_all_prunable(node: AttackTreeNode) -> bool:
    """True when every child of the AND gate is itself prunable."""
    return all(_prunable(child) for child in node.children)


def _and_gate_prunable(node: AttackTreeNode) -> bool:
    """True when a structural AND gate is a pure redundant connector."""
    if node.gate is not GateType.AND:
        return False
    if not node.children:
        return False
    if not _and_gate_unannotated(node):
        return False
    if not _and_gate_unsupported(node):
        return False
    if not _and_gate_unrealized(node):
        return False
    return _children_all_prunable(node)


def _prunable(node: AttackTreeNode) -> bool:
    if node.gate is GateType.LEAF:
        # Every valid Phase 3A leaf carries a typed action.  Unmapped does not
        # mean redundant: deleting a typed external precondition weakens the
        # concrete attack and may lower its required complexity.
        return _leaf_node_prunable(node)
    return _and_gate_prunable(node)


def _node_ids(node: AttackTreeNode) -> list[str]:
    return [
        node.id,
        *(node_id for child in node.children or () for node_id in _node_ids(child)),
    ]


def _branch_removable(
    parsed: AttackTreeNode, remaining_children: int, needed: list[int]
) -> bool:
    """True when removing this branch is safe and still required."""
    return bool(needed[0]) and remaining_children > 2 and _prunable(parsed)


def _record_removed_branch(
    parsed: AttackTreeNode, needed: list[int], removed: list[str]
) -> None:
    """Record one removed branch and its leaf-count credit."""
    removed.extend(_node_ids(parsed))
    needed[0] = max(0, needed[0] - len(_leaves(parsed)))


def _prune_dict(node: dict[str, Any], needed: list[int], removed: list[str]) -> None:
    """Remove complete redundant branches without renaming surviving nodes.

    A parent must retain at least two children.  Refusing singleton collapse is
    intentional: collapsing would rename a surviving projected leaf/connector
    and violate the Phase 3A identity-preservation contract.
    """
    children = node.get("children") or []
    kept: list[dict[str, Any]] = []
    removed_branches = 0
    for child in children:
        parsed = AttackTreeNode.model_validate(child)
        remaining_children = len(children) - removed_branches
        if _branch_removable(parsed, remaining_children, needed):
            _record_removed_branch(parsed, needed, removed)
            removed_branches += 1
            continue
        _prune_dict(child, needed, removed)
        kept.append(child)
    if children:
        node["children"] = kept


def _protected_leaf_payloads(tree: AttackTree) -> dict[str, dict[str, Any]]:
    return {
        leaf.id: leaf.model_dump(mode="json")
        for leaf in _leaves(tree.root)
        if not _prunable(leaf)
    }


def _validate_pruned_tree(
    working: dict[str, Any],
    original: FinalTreeSemanticSnapshot,
    needed: list[int],
) -> AttackTree:
    """Validate the pruned dict; fall back to the original tree on failure."""
    try:
        return AttackTree.model_validate(working)
    except ValueError:
        needed[0] = max(1, needed[0])
        return original.tree


def _protected_payloads_match(tree: AttackTree, resulting: AttackTree) -> bool:
    """True when pruning preserved every protected leaf payload."""
    return _protected_leaf_payloads(resulting) == _protected_leaf_payloads(tree)


def _projected_step_ids(tree: AttackTree) -> tuple[str, ...]:
    """Sorted projected step ids across all leaves."""
    return tuple(
        sorted({sid for leaf in _leaves(tree.root) for sid in leaf.projected_step_ids})
    )


def _parsimony_detail(
    removed: list[str], leaves: list[AttackTreeNode], budget: int, accepted: bool
) -> str:
    """Human-readable repair outcome for the record."""
    if not removed and len(leaves) <= budget:
        return "already within budget"
    if accepted:
        return "safe redundant branches removed"
    return "protected leaves prevent meeting budget"


def finalize_tree_parsimony(
    tree: AttackTree, *, budget: int | None = None
) -> TreeParsimonyResult:
    original = FinalTreeSemanticSnapshot.capture(tree)
    working = tree.model_dump(mode="json")
    leaves = _leaves(tree.root)
    if budget is None:
        budget = _default_leaf_budget(tree)
    needed = [max(0, len(leaves) - budget)]
    removed: list[str] = []
    if needed[0]:
        _prune_dict(working["root"], needed, removed)
    resulting = _validate_pruned_tree(working, original, needed)
    if not _protected_payloads_match(tree, resulting):
        resulting = original.tree
        needed[0] = max(1, needed[0])
        removed.clear()
    after = FinalTreeSemanticSnapshot.capture(resulting)
    projected = _projected_step_ids(tree)
    parsimony = check_tree_parsimony(resulting, budget=budget)
    accepted = not parsimony.violations
    record = RepairRecord(
        original.digest,
        after.digest,
        tuple(removed),
        projected,
        accepted,
        _parsimony_detail(removed, leaves, budget, accepted),
    )
    return TreeParsimonyResult(resulting, parsimony.violations, record)
