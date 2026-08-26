"""Pure pre-behavior finalization gates (cmps.5 phase 3A).

This module is intentionally an unwired port.  It snapshots the inputs, applies
the hard semantic gates and the narrowly permitted parsimony repair, and
returns the lifecycle result consumed by :class:`TargetFinalizationMachine`.
It performs no generation, persistence, or runner work.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from asago_scenario_generator.models.attack_pattern_validation import (
    validate_projection_snapshot,
)
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
)
from asago_scenario_generator.models.complexity import capability_level_rank
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.scenario import ActorProfile, NarrativeLayer
from asago_scenario_generator.pipeline.complexity import (
    assess_candidate_complexity,
    assess_final_complexity,
    evaluate_capability_admission,
)
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateFinalizationContext,
    GeneratedArtifacts,
    GeneratedStage,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
)
from asago_scenario_generator.pipeline.generate.actor_access import (
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.constants import compute_leaf_budget
from asago_scenario_generator.pipeline.generate.narrative import (
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
    canonical_json_bytes,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _check_narrative_realizations,
    _check_tree_realizations,
)
from asago_scenario_generator.pipeline.projection_semantics import (
    _check_step_semantic_compatibility,
)
from asago_scenario_generator.pipeline.projection_validation import (
    _check_or_tree_prohibition,
)


class GateCode(str, Enum):
    admission_exception = "admission_exception"
    snapshot_integrity = "snapshot_integrity"
    candidate_identity = "candidate_identity"
    actor_access = "actor_access"
    narrative_access = "narrative_access"
    narrative_realization = "narrative_realization"
    narrative_step_coverage = "narrative_step_coverage"
    narrative_step_bound = "narrative_step_bound"
    tree_realization = "tree_realization"
    canonical_identity = "canonical_identity"
    or_tree = "or_tree"
    empty_realization = "empty_realization"
    no_security_actions = "no_security_actions"
    capability_complexity = "capability_complexity"
    parsimony = "parsimony"
    zone_difference = "zone_difference"
    heuristic_correspondence = "heuristic_correspondence"
    traceability = "traceability"
    structural = "structural"
    semantic = "semantic"
    canonical_compilation_failed = "canonical_compilation_failed"
    phantom = "phantom"
    tree_action_mismatch = "tree_action_mismatch"
    assertion_mismatch = "assertion_mismatch"
    no_realized_security_actions = "no_realized_security_actions"
    scenario_identity = "scenario_identity"
    trusted_context = "trusted_context"


class AdmissionEvidenceId(str, Enum):
    """Closed, durable identifiers for authoritative admission evidence."""

    admission_exception = "admission_exception"
    snapshot_integrity = "snapshot_integrity"
    identity = "identity"
    actor_attack_complexity = "actor_attack_complexity"
    capability_grounding = "capability_grounding"
    tool_integration_grounding = "tool_integration_grounding"
    data_access_grounding = "data_access_grounding"
    catalog_taxonomy_pin_validity = "catalog_taxonomy_pin_validity"
    resource_binding_validity = "resource_binding_validity"
    execution_requirement_drift = "execution_requirement_drift"
    projection_traceability = "projection_traceability"
    structural_validity = "structural_validity"
    identifier_validity = "identifier_validity"
    phantom_validity = "phantom_validity"
    semantic_validity = "semantic_validity"
    behavior_correspondence = "behavior_correspondence"
    narrative_tree_diagnostics = "narrative_tree_diagnostics"
    tree_parsimony = "tree_parsimony"
    or_tree_prohibition = "or_tree_prohibition"


EXCEPTIONAL_ADMISSION_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.admission_exception,
        AdmissionEvidenceId.snapshot_integrity,
    }
)
NORMAL_POSTBEHAVIOR_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = (
    frozenset(AdmissionEvidenceId) - EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
)
CONDITIONALLY_APPLICABLE_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.tool_integration_grounding,
        AdmissionEvidenceId.data_access_grounding,
    }
)


DIAGNOSTIC_BACKED_EVIDENCE_IDS: frozenset[AdmissionEvidenceId] = frozenset(
    {
        AdmissionEvidenceId.tool_integration_grounding,
        AdmissionEvidenceId.data_access_grounding,
        AdmissionEvidenceId.capability_grounding,
        AdmissionEvidenceId.catalog_taxonomy_pin_validity,
        AdmissionEvidenceId.resource_binding_validity,
        AdmissionEvidenceId.execution_requirement_drift,
        AdmissionEvidenceId.identifier_validity,
    }
)


@dataclass(frozen=True, slots=True)
class GateViolation:
    code: GateCode
    detail: str
    owner: GeneratedStage | None

    @property
    def earliest_owner(self) -> GeneratedStage | None:
        return self.owner

    def lifecycle(self) -> LifecycleViolation:
        return LifecycleViolation(
            detail=self.detail,
            owner=self.owner,
            code=self.code.value,
            retryable=self.owner is not None,
        )


@dataclass(frozen=True, slots=True)
class GateResult:
    evidence_id: AdmissionEvidenceId
    violations: tuple[GateViolation, ...] = ()
    diagnostics: tuple[GateViolation, ...] = ()
    outcome: bool | None = None
    applicable: bool = True

    def __post_init__(self) -> None:
        if self.evidence_id in DIAGNOSTIC_BACKED_EVIDENCE_IDS:
            _check_diagnostic_backed(self)
        else:
            _check_ordinary_gate(self)

    @property
    def valid(self) -> bool:
        return not self.violations if self.outcome is None else self.outcome

    @property
    def passed(self) -> bool:
        """Compatibility spelling for callers that describe gates as pass/fail."""
        return self.valid


def _check_diagnostic_backed(gate: GateResult) -> None:
    """Diagnostic-backed categories forbid hard violations and derive outcome."""
    if gate.violations:
        raise ValueError("diagnostic-backed category forbids hard violations")
    if gate.outcome is None or gate.outcome != (not gate.diagnostics):
        raise ValueError("diagnostic-backed category outcome must match diagnostics")


def _check_ordinary_gate(gate: GateResult) -> None:
    """Ordinary gate outcomes are derived from hard violations."""
    if gate.outcome is not None:
        raise ValueError("ordinary gate outcome is derived from hard violations")


M = TypeVar("M", bound=BaseModel)


def _canonical(model: BaseModel) -> bytes:
    return canonical_json_bytes(model)


@dataclass(frozen=True, slots=True)
class _SemanticSnapshot(Generic[M]):
    """Content-addressed model copy; both stored bytes and model are verified."""

    model: M
    canonical_bytes: bytes
    digest: str

    @classmethod
    def capture(cls, model: M):
        fresh = type(model).model_validate(model.model_dump(mode="json"))
        canonical = _canonical(fresh)
        return cls(fresh, canonical, hashlib.sha256(canonical).hexdigest())

    def verify_digest(self) -> None:
        if hashlib.sha256(self.canonical_bytes).hexdigest() != self.digest:
            raise ValueError("snapshot canonical bytes were changed")
        if _canonical(self.model) != self.canonical_bytes:
            raise ValueError("snapshot model drifted after capture")
        # Also prove the held bytes remain independently materializable.
        type(self.model).model_validate_json(self.canonical_bytes)

    def materialize(self) -> M:
        self.verify_digest()
        return type(self.model).model_validate_json(self.canonical_bytes)


class ProjectionSemanticSnapshot(_SemanticSnapshot[ProjectedCandidate]):
    @property
    def candidate(self) -> ProjectedCandidate:
        return self.materialize()

    @property
    def projection(self) -> ProjectedCandidate:
        return self.candidate


class ActorSemanticSnapshot(_SemanticSnapshot[ActorProfile]):
    @property
    def actor(self) -> ActorProfile:
        return self.materialize()


class NarrativeSemanticSnapshot(_SemanticSnapshot[NarrativeLayer]):
    @property
    def narrative(self) -> NarrativeLayer:
        return self.materialize()


class FinalTreeSemanticSnapshot(_SemanticSnapshot[AttackTree]):
    @property
    def tree(self) -> AttackTree:
        return self.materialize()


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


def _block(
    candidate: ProjectedCandidate,
    narrative: NarrativeLayer,
    tree: AttackTree,
    capability_snapshot: Any,
) -> ProjectionEnvelopeBlock:
    # This is the same authoritative derivation used by ordinary envelope
    # assembly.  Passing behavior=None deliberately limits the sidecars to
    # the artifacts that exist before Call 3.
    from asago_scenario_generator.pipeline.generate.assembly import (
        _build_projection_block,
    )

    return _build_projection_block(
        candidate, narrative, tree, None, capability_snapshot
    )


def _selected_step_ids(candidate: ProjectedCandidate) -> set[str]:
    """Selected canonical step ids of a projected candidate."""
    return set(candidate.projection.selected_step_ids)


def _qualify_projection_snapshot(
    candidate: ProjectedCandidate, capability_snapshot: Any
) -> GateResult | None:
    """Qualify the candidate projection against the pinned snapshot."""
    try:
        capability_snapshot.assert_integrity()
        validate_projection_snapshot(
            candidate.projection.model_dump(mode="json"), capability_snapshot
        )
    except (TypeError, ValueError, AttributeError) as exc:
        return GateResult(
            AdmissionEvidenceId.structural_validity,
            (
                GateViolation(
                    GateCode.candidate_identity,
                    f"candidate/projection qualification failed: {exc}",
                    None,
                ),
            ),
        )
    return None


def _conflicting_owner(
    owners: dict[str, str], postcondition: Any, step: Any
) -> str | None:
    """The existing conflicting owner of a postcondition, if any."""
    existing_owner = owners.get(postcondition.postcondition_id)
    if existing_owner is not None and existing_owner != step.step_id:
        return existing_owner
    return None


def _ambiguous_postcondition_violation(
    candidate: ProjectedCandidate,
) -> GateViolation | None:
    """Violation when a postcondition is owned by two different steps."""
    selected_step_ids = _selected_step_ids(candidate)
    postcondition_owners: dict[str, str] = {}
    for step in candidate.projection.source_chain.steps:
        if step.step_id not in selected_step_ids:
            continue
        for postcondition in step.observable_postconditions:
            existing_owner = _conflicting_owner(
                postcondition_owners, postcondition, step
            )
            if existing_owner is not None:
                return GateViolation(
                    GateCode.candidate_identity,
                    f"postcondition '{postcondition.postcondition_id}' has "
                    f"ambiguous owners '{existing_owner}' and "
                    f"'{step.step_id}'",
                    None,
                )
            postcondition_owners[postcondition.postcondition_id] = step.step_id
    return None


def _narrative_duplicate_violation(narrative: NarrativeLayer) -> GateViolation | None:
    """Violation when a narrative step duplicates a projected step."""
    for step in narrative.steps:
        if len(step.projected_step_ids) != len(set(step.projected_step_ids)):
            return GateViolation(
                GateCode.narrative_realization,
                f"narrative step '{step.step_number}' duplicates a projected step",
                GeneratedStage.narrative,
            )
    return None


def _realization_id_order(node: AttackTreeNode) -> tuple[str, ...]:
    """Projected step ids in realization order."""
    return tuple(realization.projected_step_id for realization in node.realizations)


def _tree_realization_violation(tree: AttackTree) -> GateViolation | None:
    """Violation when a tree node duplicates or reorders projected steps."""
    for node in _nodes(tree.root):
        if len(node.projected_step_ids) != len(set(node.projected_step_ids)):
            return GateViolation(
                GateCode.tree_realization,
                f"tree node '{node.id}' duplicates a projected step",
                GeneratedStage.tree,
            )
        if _realization_id_order(node) != tuple(node.projected_step_ids):
            return GateViolation(
                GateCode.tree_realization,
                f"tree node '{node.id}' realization order does not match "
                "projected_step_ids",
                GeneratedStage.tree,
            )
    return None


def _build_prebehavior_block(
    candidate: ProjectedCandidate,
    narrative: NarrativeLayer,
    tree: AttackTree,
    capability_snapshot: Any,
) -> ProjectionEnvelopeBlock | GateResult:
    """Build the pre-behavior projection block, or a qualification failure."""
    try:
        return _block(candidate, narrative, tree, capability_snapshot)
    except (TypeError, ValueError, AttributeError) as exc:
        return GateResult(
            AdmissionEvidenceId.structural_validity,
            (
                GateViolation(
                    GateCode.tree_realization,
                    f"generated realization qualification failed: {exc}",
                    GeneratedStage.tree,
                ),
            ),
        )


def _structural_gate(violation: GateViolation) -> GateResult:
    """Wrap one early structural violation into a gate result."""
    return GateResult(AdmissionEvidenceId.structural_validity, (violation,))


def _structural_prechecks(
    candidate: ProjectedCandidate,
    narrative: NarrativeLayer,
    tree: AttackTree,
    capability_snapshot: Any,
) -> ProjectionEnvelopeBlock | GateResult:
    """Early hard structural gates; the projection block when all pass."""
    gate = _qualify_projection_snapshot(candidate, capability_snapshot)
    if gate is not None:
        return gate
    violation = _ambiguous_postcondition_violation(candidate)
    if violation is not None:
        return _structural_gate(violation)
    violation = _narrative_duplicate_violation(narrative)
    if violation is not None:
        return _structural_gate(violation)
    violation = _tree_realization_violation(tree)
    if violation is not None:
        return _structural_gate(violation)
    return _build_prebehavior_block(candidate, narrative, tree, capability_snapshot)


def _prebehavior_envelope(
    candidate: ProjectedCandidate,
    block: ProjectionEnvelopeBlock,
    actor: ActorProfile,
    narrative: NarrativeLayer,
    tree: AttackTree,
) -> Any:
    """Thin envelope consumed by the realization checkers."""
    return type(
        "PrebehaviorEnvelope",
        (),
        {
            "candidate_id": candidate.candidate_id,
            "projection": block,
            "actor_profile": actor,
            "narrative": narrative,
            "attack_tree": tree,
            "behavior_spec": None,
        },
    )()


def _actor_access_gate_violations(
    actor: ActorProfile, candidate: ProjectedCandidate, profile: Any
) -> list[GateViolation]:
    """Actor access-provenance gates."""
    violations: list[GateViolation] = []
    for item in validate_actor_access_provenance(actor, profile):
        violations.append(
            GateViolation(GateCode.actor_access, item.message, GeneratedStage.actor)
        )
    if (
        actor.access is not None
        and actor.access.initial_entry_point_id
        != candidate.canonical_ingress.entry_point_id
    ):
        violations.append(
            GateViolation(
                GateCode.canonical_identity,
                "actor ingress differs from projected canonical ingress",
                GeneratedStage.actor,
            )
        )
    return violations


def _narrative_access_gate_violations(
    narrative: NarrativeLayer, actor: ActorProfile
) -> list[GateViolation]:
    """Narrative access-realization gates."""
    violations: list[GateViolation] = []
    for item in validate_narrative_access_realization(narrative, actor):
        violations.append(
            GateViolation(
                GateCode.narrative_access, item.message, GeneratedStage.narrative
            )
        )
    return violations


def _narrative_realization_gate_violations(
    narrative: NarrativeLayer, candidate: ProjectedCandidate
) -> list[GateViolation]:
    """Narrative realization-coverage and step-bound gates."""
    violations: list[GateViolation] = []
    narrative_ids = tuple(
        sid for step in narrative.steps for sid in step.projected_step_ids
    )
    if not narrative_ids:
        violations.append(
            GateViolation(
                GateCode.empty_realization,
                "narrative has no projected-step realization",
                GeneratedStage.narrative,
            )
        )
    # Call 1 output-shape gates (completion-length mitigation): the narrative
    # must cover every selected canonical step and stay within
    # selected_step_count + 2 steps, capped at 16.
    selected_step_ids = _selected_step_ids(candidate)
    for code, detail in validate_narrative_step_bounds(narrative, selected_step_ids):
        violations.append(
            GateViolation(GateCode(code), detail, GeneratedStage.narrative)
        )
    return violations


def _ownership_gate_violations(
    candidate: ProjectedCandidate,
    actor: ActorProfile,
    narrative: NarrativeLayer,
    profile: Any,
) -> list[GateViolation]:
    """Actor, narrative-access, and narrative-realization gates."""
    violations: list[GateViolation] = []
    violations.extend(_actor_access_gate_violations(actor, candidate, profile))
    violations.extend(_narrative_access_gate_violations(narrative, actor))
    violations.extend(_narrative_realization_gate_violations(narrative, candidate))
    return violations


def _tree_projected_ids(tree: AttackTree) -> tuple[str, ...]:
    """Projected step ids across all leaves."""
    return tuple(sid for leaf in _leaves(tree.root) for sid in leaf.projected_step_ids)


def _security_bearing_leaves(all_leaves: list[AttackTreeNode]) -> list[AttackTreeNode]:
    """Leaves carrying an action other than an external precondition."""
    return [
        leaf
        for leaf in all_leaves
        if not isinstance(leaf.action, ExternalPreconditionAction)
    ]


def _tree_realization_gate_violations(tree: AttackTree) -> list[GateViolation]:
    """Tree security-action and realization gates."""
    violations: list[GateViolation] = []
    all_leaves = _leaves(tree.root)
    security_leaves = _security_bearing_leaves(all_leaves)
    if not security_leaves:
        violations.append(
            GateViolation(
                GateCode.no_security_actions,
                "tree has no security-bearing action",
                GeneratedStage.tree,
            )
        )
    if not _tree_projected_ids(tree):
        violations.append(
            GateViolation(
                GateCode.empty_realization,
                "tree has no projected-step realization",
                GeneratedStage.tree,
            )
        )
    return violations


def _traceability_violation_code(item: Any, owner: GeneratedStage) -> GateCode:
    """Gate code for one traceability violation item."""
    if item.code is ProjectionTraceabilityViolationCode.or_tree_prohibited:
        return GateCode.or_tree
    if item.code in {
        ProjectionTraceabilityViolationCode.omitted_projected_step,
        ProjectionTraceabilityViolationCode.reordered_projected_step,
        ProjectionTraceabilityViolationCode.duplicated_projected_step,
        ProjectionTraceabilityViolationCode.incomplete_coverage,
        ProjectionTraceabilityViolationCode.unprojected_security_action,
    }:
        if owner is GeneratedStage.narrative:
            return GateCode.narrative_realization
        return GateCode.tree_realization
    return GateCode.canonical_identity


def _traceability_gate_violations(
    envelope: Any, block: ProjectionEnvelopeBlock
) -> list[GateViolation]:
    """Realization-checker violations mapped to narrative/tree gate codes."""
    violations: list[GateViolation] = []
    checks = (
        _check_or_tree_prohibition(envelope, block),
        _check_narrative_realizations(envelope, block),
        _check_tree_realizations(envelope, block),
        _check_step_semantic_compatibility(envelope, block),
    )
    for group in checks:
        for item in group:
            owner = (
                GeneratedStage.narrative
                if "narrative" in item.stage.value
                else GeneratedStage.tree
            )
            code = _traceability_violation_code(item, owner)
            violations.append(GateViolation(code, item.detail, owner))
    return violations


def _realization_gate_violations(
    tree: AttackTree, envelope: Any, block: ProjectionEnvelopeBlock
) -> list[GateViolation]:
    """Tree and traceability realization gates."""
    violations: list[GateViolation] = []
    violations.extend(_tree_realization_gate_violations(tree))
    violations.extend(_traceability_gate_violations(envelope, block))
    return violations


def _narrative_zone_set(narrative: NarrativeLayer) -> set[str]:
    """Zones referenced by narrative steps."""
    return {step.zone for step in narrative.steps}


def _tree_zone_set(tree: AttackTree) -> set[str]:
    """Zones referenced by tree leaves."""
    return {leaf.zone for leaf in _leaves(tree.root) if leaf.zone}


def _diagnostic_gates(
    narrative: NarrativeLayer, tree: AttackTree
) -> list[GateViolation]:
    """Soft diagnostics: zone sets and narrative/tree count correspondence."""
    diagnostics: list[GateViolation] = []
    if _narrative_zone_set(narrative) != _tree_zone_set(tree):
        diagnostics.append(
            GateViolation(
                GateCode.zone_difference,
                "narrative and tree zone sets differ",
                GeneratedStage.tree,
            )
        )
    leaf_count = len(_leaves(tree.root))
    step_count = len(narrative.steps)
    if leaf_count and step_count:
        correspondence = min(step_count, leaf_count) / max(step_count, leaf_count)
        if correspondence < 0.7:
            diagnostics.append(
                GateViolation(
                    GateCode.heuristic_correspondence,
                    f"narrative/tree count correspondence is {correspondence:.2f}",
                    GeneratedStage.tree,
                )
            )
    return diagnostics


def _complexity_gate_violation(
    candidate: ProjectedCandidate,
    tree: AttackTree,
    actor: ActorProfile,
    include_complexity: bool,
) -> GateViolation | None:
    """Capability-complexity admission violation, when requested."""
    if not include_complexity:
        return None
    all_leaves = _leaves(tree.root)
    assessment = assess_final_complexity(
        assess_candidate_complexity(candidate), all_leaves, actor.access
    )
    decision = evaluate_capability_admission(
        actor.capability_level, assessment, phase="final"
    )
    if not decision.admitted:
        routing = decision.violation.routing
        owner = (
            GeneratedStage.actor
            if routing.stage == "call0_actor_generation"
            else GeneratedStage.tree
        )
        return GateViolation(GateCode.capability_complexity, routing.feedback, owner)
    return None


_OWNER_ORDER = {
    None: 0,
    GeneratedStage.actor: 1,
    GeneratedStage.narrative: 2,
    GeneratedStage.tree: 3,
    GeneratedStage.behavior: 4,
}


def _finalize_gate_result(
    violations: list[GateViolation], diagnostics: list[GateViolation]
) -> GateResult:
    """Stable dedup followed by canonical owner order for retry routing."""
    unique = tuple(
        sorted(dict.fromkeys(violations), key=lambda item: _OWNER_ORDER[item.owner])
    )
    return GateResult(
        AdmissionEvidenceId.structural_validity, unique, tuple(diagnostics)
    )


def run_prebehavior_gates(
    candidate: ProjectedCandidate,
    actor: ActorProfile,
    narrative: NarrativeLayer,
    tree: AttackTree,
    capability_snapshot: Any,
    profile: Any | None = None,
    *,
    include_complexity: bool = True,
) -> GateResult:
    """Run hard gates in candidate, actor, narrative, then tree owner order."""
    del profile  # The verified capability snapshot is the sole profile authority.
    block = _structural_prechecks(candidate, narrative, tree, capability_snapshot)
    if isinstance(block, GateResult):
        return block
    envelope = _prebehavior_envelope(candidate, block, actor, narrative, tree)
    profile = capability_snapshot.profile
    violations = _ownership_gate_violations(candidate, actor, narrative, profile)
    violations.extend(_realization_gate_violations(tree, envelope, block))
    diagnostics = _diagnostic_gates(narrative, tree)
    complexity_violation = _complexity_gate_violation(
        candidate, tree, actor, include_complexity
    )
    if complexity_violation is not None:
        violations.append(complexity_violation)
    return _finalize_gate_result(violations, diagnostics)


def _context_guard_failure(
    context: CandidateFinalizationContext,
) -> PrebehaviorFinalizationResult | None:
    """Failure when the context is not a verified candidate context."""
    if not isinstance(context, CandidateFinalizationContext) or not isinstance(
        context.verified_snapshot, ProjectionSemanticSnapshot
    ):
        return PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.candidate_identity,
                    "verified candidate context is required",
                    None,
                ).lifecycle(),
            ),
        )
    return None


def _revalidated_projection(
    context: CandidateFinalizationContext,
) -> ProjectedCandidate | PrebehaviorFinalizationResult:
    """Revalidate the candidate against its authoritative snapshot."""
    try:
        projection = context.verified_snapshot
        projection.verify_digest()
        current = ProjectedCandidate.model_validate(
            context.candidate.model_dump(mode="json")
        )
        if canonical_json_bytes(current) != projection.canonical_bytes:
            raise ValueError(
                "candidate changed after authoritative revalidation snapshot"
            )
    except (TypeError, ValueError, AttributeError) as exc:
        return PrebehaviorFinalizationResult(
            None,
            (GateViolation(GateCode.candidate_identity, str(exc), None).lifecycle(),),
        )
    return projection


def _capture_one_snapshot(
    snapshot_type: type, artifact: Any, owner: GeneratedStage
) -> Any | PrebehaviorFinalizationResult:
    """Capture one semantic snapshot, or a snapshot-integrity failure."""
    try:
        snapshot = snapshot_type.capture(artifact)
        snapshot.verify_digest()
    except (TypeError, ValueError, AttributeError) as exc:
        return PrebehaviorFinalizationResult(
            None,
            (GateViolation(GateCode.snapshot_integrity, str(exc), owner).lifecycle(),),
        )
    return snapshot


def _captured_artifacts(
    artifacts: GeneratedArtifacts,
) -> tuple[Any, Any, Any] | PrebehaviorFinalizationResult:
    """Capture and verify actor, narrative, and tree semantic snapshots."""
    captured: list[Any] = []
    for snapshot_type, artifact, owner in (
        (ActorSemanticSnapshot, artifacts.actor, GeneratedStage.actor),
        (NarrativeSemanticSnapshot, artifacts.narrative, GeneratedStage.narrative),
        (FinalTreeSemanticSnapshot, artifacts.tree, GeneratedStage.tree),
    ):
        snapshot = _capture_one_snapshot(snapshot_type, artifact, owner)
        if isinstance(snapshot, PrebehaviorFinalizationResult):
            return snapshot
        captured.append(snapshot)
    actor, narrative, tree = captured
    return actor, narrative, tree


def _preflight(
    context: CandidateFinalizationContext, artifacts: GeneratedArtifacts
) -> tuple[Any, Any, Any, Any] | PrebehaviorFinalizationResult:
    """Verified (projection, actor, narrative, tree), or a failure result."""
    failure = _context_guard_failure(context)
    if failure is not None:
        return failure
    projection = _revalidated_projection(context)
    if isinstance(projection, PrebehaviorFinalizationResult):
        return projection
    captured = _captured_artifacts(artifacts)
    if isinstance(captured, PrebehaviorFinalizationResult):
        return captured
    actor, narrative, tree = captured
    return projection, actor, narrative, tree


def _gate_failure_result(gates: GateResult) -> PrebehaviorFinalizationResult | None:
    """Lifecycle-violation failure when a gate result has violations."""
    if gates.violations:
        return PrebehaviorFinalizationResult(
            None, tuple(v.lifecycle() for v in gates.violations)
        )
    return None


def _complexity_floor_violation(
    candidate: ProjectedCandidate,
    before_tree: AttackTree,
    after_tree: AttackTree,
    actor: ActorProfile,
) -> PrebehaviorFinalizationResult | None:
    """Violation when parsimony repair lowers required attack complexity."""
    before = assess_final_complexity(
        assess_candidate_complexity(candidate), _leaves(before_tree.root), actor.access
    )
    after = assess_final_complexity(
        assess_candidate_complexity(candidate), _leaves(after_tree.root), actor.access
    )
    if (
        before.final is not None
        and after.final is not None
        and capability_level_rank(after.final.required_level)
        < capability_level_rank(before.final.required_level)
    ):
        return PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.parsimony,
                    "parsimony repair lowered required attack complexity",
                    GeneratedStage.tree,
                ).lifecycle(),
            ),
        )
    return None


def _parsimony_repair(
    tree: AttackTree, candidate: ProjectedCandidate, actor: ActorProfile
) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
    """Apply parsimony repair, then verify the complexity floor holds."""
    repair = finalize_tree_parsimony(tree)
    if repair.violations:
        return None, PrebehaviorFinalizationResult(
            None, tuple(v.lifecycle() for v in repair.violations)
        )
    failure = _complexity_floor_violation(candidate, tree, repair.tree, actor)
    if failure is not None:
        return None, failure
    return repair, None


def _final_tree_snapshot(
    repair: Any,
) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
    """Final repaired-tree snapshot, or a snapshot-integrity failure."""
    try:
        snapshot = FinalTreeSemanticSnapshot.capture(repair.tree)
        snapshot.verify_digest()
    except (TypeError, ValueError, AttributeError) as exc:
        return None, PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.snapshot_integrity, str(exc), GeneratedStage.tree
                ).lifecycle(),
            ),
        )
    return snapshot, None


class PrebehaviorFinalizerPort:
    """Concrete, callable finalization port; deliberately not production-wired."""

    def __init__(self, capability_snapshot: Any, profile: Any | None = None) -> None:
        self.capability_snapshot = capability_snapshot
        self.profile = profile or capability_snapshot.profile

    def _rerun_and_snapshot(
        self,
        projection: ProjectionSemanticSnapshot,
        actor: Any,
        narrative: Any,
        repair: Any,
    ) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
        """Rerun gates on the repaired tree, then capture the final snapshot."""
        failure = _gate_failure_result(
            run_prebehavior_gates(
                projection.candidate,
                actor.actor,
                narrative.narrative,
                repair.tree,
                self.capability_snapshot,
                self.profile,
            )
        )
        if failure is not None:
            return None, failure
        return _final_tree_snapshot(repair)

    def _finalize_verified(
        self,
        projection: ProjectionSemanticSnapshot,
        actor: Any,
        narrative: Any,
        tree: Any,
    ) -> PrebehaviorFinalizationResult:
        """Run the gate, parsimony, and revalidation sequence."""
        try:
            failure = _gate_failure_result(
                run_prebehavior_gates(
                    projection.candidate,
                    actor.actor,
                    narrative.narrative,
                    tree.tree,
                    self.capability_snapshot,
                    self.profile,
                )
            )
            if failure is not None:
                return failure
            repair, failure = _parsimony_repair(
                tree.tree, projection.candidate, actor.actor
            )
            if failure is not None:
                return failure
            snapshot, failure = self._rerun_and_snapshot(
                projection, actor, narrative, repair
            )
            if failure is not None:
                return failure
            return PrebehaviorFinalizationResult(
                snapshot,
                candidate_snapshot=projection,
                actor_snapshot=actor,
                narrative_snapshot=narrative,
                repair_record=repair.record,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            return PrebehaviorFinalizationResult(
                None,
                (
                    GateViolation(
                        GateCode.snapshot_integrity, str(exc), GeneratedStage.tree
                    ).lifecycle(),
                ),
            )

    def __call__(
        self, context: CandidateFinalizationContext, artifacts: GeneratedArtifacts
    ) -> PrebehaviorFinalizationResult:
        preflight = _preflight(context, artifacts)
        if isinstance(preflight, PrebehaviorFinalizationResult):
            return preflight
        projection, actor, narrative, tree = preflight
        return self._finalize_verified(projection, actor, narrative, tree)


def make_prebehavior_finalizer(
    capability_snapshot: Any, profile: Any | None = None
) -> PrebehaviorFinalizerPort:
    """Build the concrete callback without wiring it into the runner."""
    return PrebehaviorFinalizerPort(capability_snapshot, profile)
