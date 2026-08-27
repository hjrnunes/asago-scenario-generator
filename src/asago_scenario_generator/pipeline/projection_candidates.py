"""Candidate construction helpers for authoritative projection."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Callable, Literal

from asago_scenario_generator.models.attack_pattern_chain import CanonicalAttackChain
from asago_scenario_generator.models.attack_pattern_contracts import (
    ConditionEvaluationResult,
    ExecutionRequirement,
)
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_projection_digest,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
    EntryPointResourceReference,
    ResourceBinding,
    StepOmission,
)
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_projection_snapshot,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CandidateComplexityInputs,
    PreconditionEvaluationResult,
    ProjectedCandidate,
    _candidate_v2_id,
    _projected_mappings,
    _selected_steps_for_projection as _selected_steps_from_chain,
    compute_execution_requirements_digest,
)
from asago_scenario_generator.pipeline.projection_relations import (
    _source_influence_relation,
)
from asago_scenario_generator.pipeline.projection_requirements import (
    _derive_execution_requirements,
    _fail_closed_if_no_requirements,
)
from asago_scenario_generator.pipeline.projection_snapshot import (
    CapabilityFactSnapshot,
)


def _bindings_for_combination(
    chain: CanonicalAttackChain,
    resources: tuple[CanonicalResourceReference, ...],
) -> tuple[ResourceBinding, ...]:
    """Pair every chain resource slot with its chosen resource reference."""
    return tuple(
        ResourceBinding(slot_id=slot.slot_id, resource_ref=resource)
        for slot, resource in zip(chain.resource_slots, resources, strict=True)
    )


def _projection_payloads(items: Iterable[Any]) -> list[dict[str, Any]]:
    """Dump projection sub-models to JSON payloads."""
    return [item.model_dump(mode="json") for item in items]


def _projection_data_for_combination(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    condition_results: tuple[ConditionEvaluationResult, ...],
    omissions: tuple[StepOmission, ...],
    bindings: tuple[ResourceBinding, ...],
    catalog_pin: str,
    pattern_pin: str,
    snapshot: CapabilityFactSnapshot,
    source_influence_paths: tuple[Any, ...],
) -> dict[str, Any]:
    """Assemble and digest-address projection data for one combination."""
    projection_data = {
        "schema_version": "1",
        "source_chain": chain.model_dump(mode="json"),
        "selected_step_ids": selected,
        "condition_results": _projection_payloads(condition_results),
        "omissions": _projection_payloads(omissions),
        "bindings": _projection_payloads(bindings),
        "catalog_pin": catalog_pin,
        "pattern_pin": pattern_pin,
        "capability_fact_snapshot_digest": snapshot.snapshot_digest,
        "projection_digest": "0" * 64,
        "source_influence_paths": _projection_payloads(source_influence_paths),
    }
    projection_data["projection_digest"] = compute_projection_digest(projection_data)
    return projection_data


def _ingress_for_combination(
    bindings: tuple[ResourceBinding, ...],
    chain: CanonicalAttackChain,
    snapshot: CapabilityFactSnapshot,
) -> tuple[EntryPointResourceReference, Literal["direct", "indirect"]]:
    """Resolve the binding and controllability of the initial ingress slot."""
    ingress_ref = next(
        item.resource_ref
        for item in bindings
        if item.slot_id == chain.initial_ingress_slot_id
    )
    assert isinstance(ingress_ref, EntryPointResourceReference)
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None
    return ingress_ref, ingress.effective_controllability


def _count_selected_steps(
    selected_steps: list[Any], predicate: Callable[[Any], bool]
) -> int:
    """Count selected steps satisfying a boolean predicate."""
    return sum(predicate(step) for step in selected_steps)


def _candidate_complexity_inputs(
    selected_steps: list[Any],
    bindings: tuple[ResourceBinding, ...],
    requirements: tuple[ExecutionRequirement, ...],
) -> CandidateComplexityInputs:
    """Derive the complexity inputs recorded on each projected candidate."""
    return CandidateComplexityInputs(
        selected_step_count=len(selected_steps),
        attacker_controlled_step_count=_count_selected_steps(
            selected_steps, lambda step: step.attacker_controlled
        ),
        boundary_crossing_step_count=_count_selected_steps(
            selected_steps, lambda step: step.boundary_position == "crossing"
        ),
        selected_conditional_step_count=_count_selected_steps(
            selected_steps, lambda step: step.requirement == "conditional"
        ),
        concrete_binding_count=len(bindings),
        execution_requirement_count=len(requirements),
    )


def _build_candidate_from_combination(
    pattern_id: str,
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    condition_results: tuple[ConditionEvaluationResult, ...],
    omissions: tuple[StepOmission, ...],
    resources: tuple[CanonicalResourceReference, ...],
    catalog_pin: str,
    pattern_pin: str,
    precondition_results: tuple[PreconditionEvaluationResult, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[ProjectedCandidate | None, Any | None]:
    """Build a single ProjectedCandidate from one resource combination.

    Returns ``(candidate, issue)``.  When the combination fails execution
    requirements derivation (a structural rejection, not a budget limit),
    ``candidate`` is None and ``issue`` carries the typed ProjectionIssue.
    """
    bindings = _bindings_for_combination(chain, resources)
    source_influence_paths, relation_issue = _source_influence_relation(
        pattern_id, chain, selected, bindings, snapshot
    )
    if relation_issue is not None:
        return None, relation_issue
    projection_data = _projection_data_for_combination(
        chain,
        selected,
        condition_results,
        omissions,
        bindings,
        catalog_pin,
        pattern_pin,
        snapshot,
        source_influence_paths,
    )
    projection = validate_projection_snapshot(projection_data, snapshot)
    requirements, issue = _derive_execution_requirements(
        pattern_id, chain, projection, snapshot
    )
    requirements, issue = _fail_closed_if_no_requirements(
        pattern_id, requirements, issue
    )
    if issue is not None:
        return None, issue
    requirements_digest = compute_execution_requirements_digest(requirements)
    ingress_ref, ingress_controllability = _ingress_for_combination(
        bindings, chain, snapshot
    )
    selected_steps = _selected_steps_from_chain(chain, selected)
    candidate = ProjectedCandidate(
        candidate_id=_candidate_v2_id(pattern_id, projection),
        pattern_id=pattern_id,
        chain_id=chain.chain_id,
        chain_semantic_revision=chain.semantic_revision,
        chain_semantic_digest=chain.semantic_digest,
        projection=projection,
        canonical_ingress=ingress_ref,
        ingress_controllability=ingress_controllability,
        projected_mappings=_projected_mappings(chain, selected),
        precondition_results=precondition_results,
        execution_requirements=requirements,
        requirement_derivation_version="1",
        execution_requirements_digest=requirements_digest,
        complexity_inputs=_candidate_complexity_inputs(
            selected_steps, bindings, requirements
        ),
    )
    return candidate, None
