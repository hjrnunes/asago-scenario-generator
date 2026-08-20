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

from asago_scenario_generator.models.attack_pattern import validate_projection_snapshot
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
from asago_scenario_generator.pipeline.finalization import (
    CandidateFinalizationContext,
    GeneratedArtifacts,
    GeneratedStage,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
)
from asago_scenario_generator.pipeline.generate.actor import (
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.constants import compute_leaf_budget
from asago_scenario_generator.pipeline.generate.narrative import (
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)
from asago_scenario_generator.pipeline.projection import (
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
            if self.violations:
                raise ValueError("diagnostic-backed category forbids hard violations")
            if self.outcome is None or self.outcome != (not self.diagnostics):
                raise ValueError(
                    "diagnostic-backed category outcome must match diagnostics"
                )
        elif self.outcome is not None:
            raise ValueError("ordinary gate outcome is derived from hard violations")

    @property
    def valid(self) -> bool:
        return not self.violations if self.outcome is None else self.outcome

    @property
    def passed(self) -> bool:
        """Compatibility spelling for callers that describe gates as pass/fail."""
        return self.valid


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


def check_tree_parsimony(tree: AttackTree, *, budget: int | None = None) -> GateResult:
    leaves = _leaves(tree.root)
    if budget is None:
        budget = compute_leaf_budget(len(set(tree.collect_technique_ids())))
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


def _prunable(node: AttackTreeNode) -> bool:
    if node.gate is GateType.LEAF:
        # Every valid Phase 3A leaf carries a typed action.  Unmapped does not
        # mean redundant: deleting a typed external precondition weakens the
        # concrete attack and may lower its required complexity.
        return node.action is None
    return (
        node.gate is GateType.AND
        and bool(node.children)
        and node.zone is None
        and node.threat_id is None
        and node.technique_id is None
        and node.tactic is None
        and node.maestro_layer is None
        and node.control_point is None
        and node.structural_exposure is None
        and not node.projected_step_ids
        and not node.realizations
        and all(_prunable(child) for child in node.children)
    )


def _node_ids(node: AttackTreeNode) -> list[str]:
    return [
        node.id,
        *(node_id for child in node.children or () for node_id in _node_ids(child)),
    ]


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
        descendant_leaves = _leaves(parsed)
        remaining_children = len(children) - removed_branches
        may_remove = remaining_children > 2
        if needed[0] and may_remove and _prunable(parsed):
            removed.extend(_node_ids(parsed))
            needed[0] = max(0, needed[0] - len(descendant_leaves))
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


def finalize_tree_parsimony(
    tree: AttackTree, *, budget: int | None = None
) -> TreeParsimonyResult:
    original = FinalTreeSemanticSnapshot.capture(tree)
    working = tree.model_dump(mode="json")
    leaves = _leaves(tree.root)
    if budget is None:
        budget = compute_leaf_budget(len(set(tree.collect_technique_ids())))
    needed = [max(0, len(leaves) - budget)]
    removed: list[str] = []
    if needed[0]:
        _prune_dict(working["root"], needed, removed)
    try:
        resulting = AttackTree.model_validate(working)
    except ValueError:
        resulting = original.tree
        needed[0] = max(1, needed[0])
    if _protected_leaf_payloads(resulting) != _protected_leaf_payloads(tree):
        resulting = original.tree
        needed[0] = max(1, needed[0])
        removed.clear()
    after = FinalTreeSemanticSnapshot.capture(resulting)
    projected = tuple(
        sorted({sid for leaf in leaves for sid in leaf.projected_step_ids})
    )
    parsimony = check_tree_parsimony(resulting, budget=budget)
    accepted = not parsimony.violations
    record = RepairRecord(
        original.digest,
        after.digest,
        tuple(removed),
        projected,
        accepted,
        (
            "already within budget"
            if not removed and len(leaves) <= budget
            else "safe redundant branches removed"
            if accepted
            else "protected leaves prevent meeting budget"
        ),
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
    selected_step_ids = set(candidate.projection.selected_step_ids)
    postcondition_owners: dict[str, str] = {}
    for step in candidate.projection.source_chain.steps:
        if step.step_id not in selected_step_ids:
            continue
        for postcondition in step.observable_postconditions:
            existing_owner = postcondition_owners.get(postcondition.postcondition_id)
            if existing_owner is not None and existing_owner != step.step_id:
                return GateResult(
                    AdmissionEvidenceId.structural_validity,
                    (
                        GateViolation(
                            GateCode.candidate_identity,
                            f"postcondition '{postcondition.postcondition_id}' has "
                            f"ambiguous owners '{existing_owner}' and "
                            f"'{step.step_id}'",
                            None,
                        ),
                    ),
                )
            postcondition_owners[postcondition.postcondition_id] = step.step_id
    for step in narrative.steps:
        if len(step.projected_step_ids) != len(set(step.projected_step_ids)):
            return GateResult(
                AdmissionEvidenceId.structural_validity,
                (
                    GateViolation(
                        GateCode.narrative_realization,
                        f"narrative step '{step.step_number}' duplicates a projected step",
                        GeneratedStage.narrative,
                    ),
                ),
            )
    for node in _nodes(tree.root):
        if len(node.projected_step_ids) != len(set(node.projected_step_ids)):
            return GateResult(
                AdmissionEvidenceId.structural_validity,
                (
                    GateViolation(
                        GateCode.tree_realization,
                        f"tree node '{node.id}' duplicates a projected step",
                        GeneratedStage.tree,
                    ),
                ),
            )
        realization_ids = tuple(
            realization.projected_step_id for realization in node.realizations
        )
        if realization_ids != tuple(node.projected_step_ids):
            return GateResult(
                AdmissionEvidenceId.structural_validity,
                (
                    GateViolation(
                        GateCode.tree_realization,
                        f"tree node '{node.id}' realization order does not match "
                        "projected_step_ids",
                        GeneratedStage.tree,
                    ),
                ),
            )
    try:
        block = _block(candidate, narrative, tree, capability_snapshot)
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
    profile = capability_snapshot.profile
    envelope = type(
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
    violations: list[GateViolation] = []
    diagnostics: list[GateViolation] = []
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
    for item in validate_narrative_access_realization(narrative, actor):
        violations.append(
            GateViolation(
                GateCode.narrative_access, item.message, GeneratedStage.narrative
            )
        )
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
    for code, detail in validate_narrative_step_bounds(narrative, selected_step_ids):
        violations.append(
            GateViolation(GateCode(code), detail, GeneratedStage.narrative)
        )
    all_leaves = _leaves(tree.root)
    tree_ids = tuple(sid for leaf in all_leaves for sid in leaf.projected_step_ids)
    security_leaves = [
        leaf
        for leaf in all_leaves
        if not isinstance(leaf.action, ExternalPreconditionAction)
    ]
    if not security_leaves:
        violations.append(
            GateViolation(
                GateCode.no_security_actions,
                "tree has no security-bearing action",
                GeneratedStage.tree,
            )
        )
    if not tree_ids:
        violations.append(
            GateViolation(
                GateCode.empty_realization,
                "tree has no projected-step realization",
                GeneratedStage.tree,
            )
        )
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
            if item.code is ProjectionTraceabilityViolationCode.or_tree_prohibited:
                code = GateCode.or_tree
            elif item.code in {
                ProjectionTraceabilityViolationCode.omitted_projected_step,
                ProjectionTraceabilityViolationCode.reordered_projected_step,
                ProjectionTraceabilityViolationCode.duplicated_projected_step,
                ProjectionTraceabilityViolationCode.incomplete_coverage,
                ProjectionTraceabilityViolationCode.unprojected_security_action,
            }:
                code = (
                    GateCode.narrative_realization
                    if owner is GeneratedStage.narrative
                    else GateCode.tree_realization
                )
            else:
                code = GateCode.canonical_identity
            violations.append(GateViolation(code, item.detail, owner))
    narrative_zones = {step.zone for step in narrative.steps}
    tree_zones = {leaf.zone for leaf in _leaves(tree.root) if leaf.zone}
    if narrative_zones != tree_zones:
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
    if include_complexity:
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
            violations.append(
                GateViolation(GateCode.capability_complexity, routing.feedback, owner)
            )
    # Stable dedup followed by canonical candidate → actor → narrative → tree
    # ownership order.  This makes aggregate retry routing explicit.
    owner_order = {
        None: 0,
        GeneratedStage.actor: 1,
        GeneratedStage.narrative: 2,
        GeneratedStage.tree: 3,
        GeneratedStage.behavior: 4,
    }
    unique = tuple(
        sorted(dict.fromkeys(violations), key=lambda item: owner_order[item.owner])
    )
    return GateResult(
        AdmissionEvidenceId.structural_validity, unique, tuple(diagnostics)
    )


class PrebehaviorFinalizerPort:
    """Concrete, callable finalization port; deliberately not production-wired."""

    def __init__(self, capability_snapshot: Any, profile: Any | None = None) -> None:
        self.capability_snapshot = capability_snapshot
        self.profile = profile or capability_snapshot.profile

    def __call__(
        self, context: CandidateFinalizationContext, artifacts: GeneratedArtifacts
    ) -> PrebehaviorFinalizationResult:
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
                (
                    GateViolation(
                        GateCode.candidate_identity, str(exc), None
                    ).lifecycle(),
                ),
            )
        snapshots: list[tuple[Any, Any, GeneratedStage]] = [
            (ActorSemanticSnapshot, artifacts.actor, GeneratedStage.actor),
            (NarrativeSemanticSnapshot, artifacts.narrative, GeneratedStage.narrative),
            (FinalTreeSemanticSnapshot, artifacts.tree, GeneratedStage.tree),
        ]
        captured: list[Any] = []
        for snapshot_type, artifact, owner in snapshots:
            try:
                snapshot = snapshot_type.capture(artifact)
                snapshot.verify_digest()
                captured.append(snapshot)
            except (TypeError, ValueError, AttributeError) as exc:
                return PrebehaviorFinalizationResult(
                    None,
                    (
                        GateViolation(
                            GateCode.snapshot_integrity, str(exc), owner
                        ).lifecycle(),
                    ),
                )
        actor, narrative, tree = captured
        try:
            gates = run_prebehavior_gates(
                projection.candidate,
                actor.actor,
                narrative.narrative,
                tree.tree,
                self.capability_snapshot,
                self.profile,
            )
            if gates.violations:
                return PrebehaviorFinalizationResult(
                    None, tuple(v.lifecycle() for v in gates.violations)
                )
            repair = finalize_tree_parsimony(tree.tree)
            if repair.violations:
                return PrebehaviorFinalizationResult(
                    None, tuple(v.lifecycle() for v in repair.violations)
                )
            before_complexity = assess_final_complexity(
                assess_candidate_complexity(projection.candidate),
                _leaves(tree.tree.root),
                actor.actor.access,
            )
            after_complexity = assess_final_complexity(
                assess_candidate_complexity(projection.candidate),
                _leaves(repair.tree.root),
                actor.actor.access,
            )
            if (
                before_complexity.final is not None
                and after_complexity.final is not None
                and capability_level_rank(after_complexity.final.required_level)
                < capability_level_rank(before_complexity.final.required_level)
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
            # Repair can affect all tree realization gates, so run the full pure set.
            rerun = run_prebehavior_gates(
                projection.candidate,
                actor.actor,
                narrative.narrative,
                repair.tree,
                self.capability_snapshot,
                self.profile,
            )
            if rerun.violations:
                return PrebehaviorFinalizationResult(
                    None, tuple(v.lifecycle() for v in rerun.violations)
                )
            snapshot = FinalTreeSemanticSnapshot.capture(repair.tree)
            snapshot.verify_digest()
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


def make_prebehavior_finalizer(
    capability_snapshot: Any, profile: Any | None = None
) -> PrebehaviorFinalizerPort:
    """Build the concrete callback without wiring it into the runner."""
    return PrebehaviorFinalizerPort(capability_snapshot, profile)
