"""Pure candidate, ownership, realization, and complexity gates."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_validation import (
    validate_projection_snapshot,
)
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
from asago_scenario_generator.pipeline.finalization_contracts import GeneratedStage
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
)
from asago_scenario_generator.pipeline.finalization_parsimony import _leaves, _nodes
from asago_scenario_generator.pipeline.generate.actor_access import (
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)
from asago_scenario_generator.pipeline.projection_block import _build_projection_block
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T07:13:00Z","module_hash":"90469a4d4f66e9921c1d72eb1c38f41bccbc6b38daaa977b37c0956fc262c4ad","source_sha256":"7cd1bdaf979483a5be0037b059de81f57bd9d6403bad6ff5bb4e6a1bd1f4dffd","functions":[{"id":"func/_final_complexity_assessment","name":"_final_complexity_assessment","line":53,"end_line":57,"hash":"aa5133861f5c564903448ff1af7db4d9693fd3281372a36d91f180d183b3fb4c"},{"id":"func/_block","name":"_block","line":60,"end_line":71,"hash":"667abc97b3fbfe8c9ebdc2245c2898927affc237288dc6e5e7f202b41ec222ef"},{"id":"func/_selected_step_ids","name":"_selected_step_ids","line":74,"end_line":76,"hash":"e53336f087fd017d7649af500fa2d87d4cadb412117b7a126919605edfc0601e"},{"id":"func/_qualify_projection_snapshot","name":"_qualify_projection_snapshot","line":79,"end_line":99,"hash":"eff067eebe44e405350b014bbfb70ab68dfc9df739eb5a3f3f2b4c3f88f656eb"},{"id":"func/_conflicting_owner","name":"_conflicting_owner","line":102,"end_line":109,"hash":"f01cd0cc63496f52371062ee74dc67285a7a23d42d677e5472557460297d9356"},{"id":"func/_ambiguous_postcondition_violation","name":"_ambiguous_postcondition_violation","line":112,"end_line":134,"hash":"6f61b77b7dad6528e3fb2097457acefc8a02cebfd9bb14555beef1060a778d30"},{"id":"func/_narrative_duplicate_violation","name":"_narrative_duplicate_violation","line":137,"end_line":146,"hash":"14fdfdf622df59e964327775007b1f23ded8fbd8d7162764087f9aa5904b4792"},{"id":"func/_realization_id_order","name":"_realization_id_order","line":149,"end_line":151,"hash":"911aa51d9a9363710aae66ad3b3376fc5c0d75d4fe22d94ad7034228be5cadd4"},{"id":"func/_tree_realization_violation","name":"_tree_realization_violation","line":154,"end_line":170,"hash":"655882e684f51d1c8c70ce5202ba965c1814042e60227acebff80690d6e5895c"},{"id":"func/_build_prebehavior_block","name":"_build_prebehavior_block","line":173,"end_line":192,"hash":"a436e20a62fffe9701de3344996bee33344d5efffa7a0a49b4e1f6cce9393b76"},{"id":"func/_structural_gate","name":"_structural_gate","line":195,"end_line":197,"hash":"d5328316573f0b12d1dd13c5d6234fdc540e6205cda14ea0516e87496bfa3ec6"},{"id":"func/_structural_prechecks","name":"_structural_prechecks","line":200,"end_line":219,"hash":"adce6a6cbadaafc01c41fbb415be9a6e2bdc2d5a0168d5a27aac4ddbe1fb6df4"},{"id":"func/_prebehavior_envelope","name":"_prebehavior_envelope","line":222,"end_line":241,"hash":"16d2ef88ce474c915ce7809d75c47f0a9a1890ffc976ad77e44d6f37f4e3f8c1"},{"id":"func/_actor_access_gate_violations","name":"_actor_access_gate_violations","line":244,"end_line":265,"hash":"2f57666c5ae4b76f592c403cdaa6d8ce022fe1493df451a4e8be5801641b3512"},{"id":"func/_narrative_access_gate_violations","name":"_narrative_access_gate_violations","line":268,"end_line":279,"hash":"77a6b9427fcd7b9481bdf3118d9171fe54ee910424278ff0e584b4b3f419604e"},{"id":"func/_narrative_realization_gate_violations","name":"_narrative_realization_gate_violations","line":282,"end_line":306,"hash":"30f86c67cce4407356622e472937bf2c1aec747d7a15e2d880f6e9e06b799165"},{"id":"func/_ownership_gate_violations","name":"_ownership_gate_violations","line":309,"end_line":320,"hash":"30b0c7f88ae9aa45c0d43ae1e3a599017276c5e4a6873c3f767fea1737417cf6"},{"id":"func/_tree_projected_ids","name":"_tree_projected_ids","line":323,"end_line":325,"hash":"b5eb356fbd06aae61339fb59cbbfe3f420f471faa69aa05ca903d57ab3350625"},{"id":"func/_security_bearing_leaves","name":"_security_bearing_leaves","line":328,"end_line":334,"hash":"8cdc0db7045cc58c73868207d02f9709cb03eb7c31e83ab5bf63a7e71b81333f"},{"id":"func/_tree_realization_gate_violations","name":"_tree_realization_gate_violations","line":337,"end_line":358,"hash":"608f95b5c08186ac7ff43be1d4adc22c29ffd38373ecd644e30de4394c18a376"},{"id":"func/_traceability_violation_code","name":"_traceability_violation_code","line":361,"end_line":375,"hash":"9b2c93d8e9b96bc46def0ea8ea6684874f40da62c41ea82978bc849cbeb63d40"},{"id":"func/_traceability_gate_violations","name":"_traceability_gate_violations","line":378,"end_line":398,"hash":"c230ac1b9a0b39284d1eff8c8d2c3926c559f0bb961e4feb6b5860134ac2f7e2"},{"id":"func/_realization_gate_violations","name":"_realization_gate_violations","line":401,"end_line":408,"hash":"67516685406b0ce337f22b26efd36494bd50df98c185f507bcd7ba71c24d27c0"},{"id":"func/_narrative_zone_set","name":"_narrative_zone_set","line":411,"end_line":413,"hash":"9b9c554e789b6b34eccec0ab53337f1c1393ee3d7a9f541a3ef99504190354b0"},{"id":"func/_tree_zone_set","name":"_tree_zone_set","line":416,"end_line":418,"hash":"ac0dd572984041167cefea054b2f7a78f0a224b88f0ccc5af4de14c5e46e0dd4"},{"id":"func/_diagnostic_gates","name":"_diagnostic_gates","line":421,"end_line":446,"hash":"1a12fa136271a7b06c615b7f563b84ccee6455f73cb8605f36f7906f0b7268f6"},{"id":"func/_complexity_gate_violation","name":"_complexity_gate_violation","line":449,"end_line":473,"hash":"f831734a8196d073c7c42f3c01f720053a0c715600f3215f422161f7bfd82221"},{"id":"func/_finalize_gate_result","name":"_finalize_gate_result","line":485,"end_line":494,"hash":"a9160f2d52dc9bf24afeba1338394c08e3ef6f46631ae279bf13614edead24d6"},{"id":"func/run_prebehavior_gates","name":"run_prebehavior_gates","line":497,"end_line":522,"hash":"dcc08bac7b1dff813827995847d0c4be51f8711ec09e0f8179a280e6cbeb428c"}]}
# mutate4py-manifest-end
