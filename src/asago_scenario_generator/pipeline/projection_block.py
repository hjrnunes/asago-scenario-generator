"""Deterministic projection-envelope construction from generated artifacts.

This leaf owns the authoritative derivation of ``ProjectionEnvelopeBlock``
sidecars from narrative, tree, and behavior fields. Generation assembly and
pre-behavior gates depend inward on it instead of the IO-near
``generate.assembly`` façade.
"""

from __future__ import annotations

from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    AssertionRealizationMapping,
    ProjectionEnvelopeBlock,
)
from asago_scenario_generator.models.scenario import BehaviorSpec, NarrativeLayer
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    compute_derivation_context_digest,
)
from asago_scenario_generator.pipeline.projection_realizations import _iter_leaves


def _build_projection_block(
    candidate: ProjectedCandidate,
    narrative: NarrativeLayer,
    attack_tree: AttackTree | None,
    behavior_spec: BehaviorSpec | str | None,
    capability_snapshot: CapabilityFactSnapshot,
) -> ProjectionEnvelopeBlock:
    """Build a ProjectionEnvelopeBlock from a ProjectedCandidate and actual artifacts.

    Realization mappings are derived deterministically from the actual
    artifact fields (projected_step_ids on narrative steps and tree leaves,
    structured behavior actions/assertions) — never from an independently
    authored sidecar table.
    """
    narrative_realizations = _narrative_realization_mappings(narrative)
    tree_realizations = _tree_realization_mappings(attack_tree)
    behavior_realizations, assertion_realizations = _behavior_realization_mappings(
        behavior_spec
    )

    return ProjectionEnvelopeBlock(
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        projected_mappings=candidate.projected_mappings,
        capability_snapshot=capability_snapshot,
        execution_requirements=candidate.execution_requirements,
        requirement_derivation_version=candidate.requirement_derivation_version,
        execution_requirements_digest=candidate.execution_requirements_digest,
        derivation_context_digest=compute_derivation_context_digest(
            candidate.projection.projection_digest,
            candidate.projection.source_chain.pattern_id,
            candidate.ingress_controllability,
        ),
        narrative_realizations=tuple(narrative_realizations),
        tree_realizations=tuple(tree_realizations),
        behavior_realizations=tuple(behavior_realizations),
        assertion_realizations=tuple(assertion_realizations),
    )


def _narrative_realization_mappings(
    narrative: NarrativeLayer,
) -> list[ArtifactRealizationMapping]:
    """Derive narrative realization mappings from actual narrative.steps."""
    narrative_realizations: list[ArtifactRealizationMapping] = []
    for step in narrative.steps:
        if step.projected_step_ids:
            narrative_realizations.append(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id=str(step.step_number),
                    projected_step_ids=step.projected_step_ids,
                )
            )
    return narrative_realizations


def _tree_realization_mappings(
    attack_tree: AttackTree | None,
) -> list[ArtifactRealizationMapping]:
    """Derive tree realization mappings from actual leaf projected_step_ids."""
    tree_realizations: list[ArtifactRealizationMapping] = []
    if attack_tree is not None:
        for leaf in _iter_leaves(attack_tree.root):
            if leaf.projected_step_ids:
                tree_realizations.append(
                    ArtifactRealizationMapping(
                        artifact_stage=ArtifactStage.attack_tree,
                        element_id=leaf.id,
                        projected_step_ids=leaf.projected_step_ids,
                    )
                )
    return tree_realizations


def _behavior_realization_mappings(
    behavior_spec: BehaviorSpec | str | None,
) -> tuple[list[ArtifactRealizationMapping], list[AssertionRealizationMapping]]:
    """Derive behavior and assertion mappings from a structured BehaviorSpec."""
    behavior_realizations: list[ArtifactRealizationMapping] = []
    assertion_realizations: list[AssertionRealizationMapping] = []
    if isinstance(behavior_spec, BehaviorSpec):
        for action in behavior_spec.actions:
            behavior_realizations.append(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.behavior,
                    element_id=action.action_id,
                    projected_step_ids=action.projected_step_ids,
                )
            )
        for assertion in behavior_spec.assertions:
            assertion_realizations.append(
                AssertionRealizationMapping(
                    element_id=assertion.assertion_id,
                    source_step_ids=assertion.source_step_ids,
                    projected_postcondition_ids=assertion.projected_postcondition_ids,
                )
            )
    return behavior_realizations, assertion_realizations
