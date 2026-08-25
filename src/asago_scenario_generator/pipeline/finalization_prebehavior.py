"""Pure candidate, ownership, realization, and complexity gates."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern import validate_projection_snapshot
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.scenario import ActorProfile, NarrativeLayer
from asago_scenario_generator.pipeline.complexity import (
    assess_candidate_complexity,
    evaluate_capability_admission,
)
from asago_scenario_generator.pipeline.finalization import GeneratedStage
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
)
from asago_scenario_generator.pipeline.finalization_parsimony import _leaves, _nodes
from asago_scenario_generator.pipeline.generate.actor import (
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)
from asago_scenario_generator.pipeline.projection import ProjectedCandidate
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


def _final_complexity_assessment(*args: Any, **kwargs: Any) -> Any:
    """Resolve final complexity through the compatibility façade seam."""
    from . import finalization_gates

    return finalization_gates.assess_final_complexity(*args, **kwargs)


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
    assessment = _final_complexity_assessment(
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
