"""Deterministic authoritative-chain projection and candidate-v2 expansion.

This module is an explicit migration seam. It does not consume
``ScenarioSeed`` or the legacy attack-pattern catalogue shape. The generation
runner uses its readiness gate before crossing into authoritative projection,
and generation stages consume only :class:`ProjectedCandidate` instances from
this boundary.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    Condition,
    TaxonomyResolver,
)
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
    validate_projection_snapshot,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile

from asago_scenario_generator.pipeline.projection_contracts import (  # noqa: F401
    CandidateComplexityInputs,
    Digest,
    PreconditionEvaluationResult,
    ProjectedCandidate,
    ProjectedMapping,
    ProjectionBatch,
    ProjectionBudget,
    ProjectionIssue,
    ProjectionLimitation,
    ProjectionModel,
    _canonical_json,
    _condition_facts,
    _condition_fact_items,
    _dedupe_sorted_facts,
    _digest,
    _evaluate_preconditions,
    _evaluate_projection_conditions,
    _fact_key,
    _normalize_semantic_order,
    _normalize_unicode,
    _normalized_mapping,
    _normalized_sequence,
    _pattern_pin,
    _resource_contained,
    _resource_id,
    _resource_key,
    _require_unique_requirement_ids,
    _selected_steps_for_projection,
    _verify_candidate_identity,
    _verify_canonical_ingress,
    _verify_chain_identity,
    _verify_complexity_inputs,
    _verify_execution_requirements_digest,
    _verify_precondition_results,
    _verify_precondition_true,
    _verify_projected_mappings,
    _expected_complexity_inputs,
    _expected_precondition_key_map,
    _candidate_v2_id,
    _chain_atlas_mappings,
    _content_pin,
    _entry_point_matches_slot,
    _integration_matches_slot,
    _projected_mappings,
    _resource_id_allowed,
    _restriction_blocks,
    _slot_reference_compatible,
    _step_atlas_mappings,
    _trust_boundary_matches_slot,
    canonical_json_bytes,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)
from asago_scenario_generator.pipeline.projection_snapshot import (  # noqa: F401
    CapabilityFactSnapshot,
    _assert_snapshot_facts_uniquely_sorted,
    _compute_snapshot_digest,
    _snapshot_resource_payload,
    _sorted_by,
    _sorted_canonical,
    capture_capability_snapshot,
)


class ProjectionReadinessReport(ProjectionModel):
    """Preflight result for architecture and qualification evidence."""

    ready: bool
    required_resource_categories: tuple[str, ...] = ()
    missing_resource_categories: tuple[str, ...] = ()
    required_facts: tuple[str, ...] = ()
    missing_facts: tuple[str, ...] = ()
    pattern_ids: tuple[str, ...] = ()


class ProjectionReadinessError(ValueError):
    """Raised before projection when reviewed architecture evidence is absent."""

    def __init__(self, report: ProjectionReadinessReport) -> None:
        self.report = report
        details: list[str] = []
        if report.missing_resource_categories:
            details.append(
                "missing resource categories "
                + ", ".join(report.missing_resource_categories)
                + "; supply a reviewed architecture with '--profile'"
            )
        if report.missing_facts:
            details.append(
                "missing qualification facts "
                + ", ".join(report.missing_facts)
                + "; supply authoritative readings with '--qualification-facts'"
            )
        super().__init__(
            "Projection readiness failed before projection: "
            + "; ".join(details)
            + ". No architecture enrichment workflow was launched."
        )


_RESOURCE_CATEGORY_BY_KIND = {
    "entry_point": "entry_points",
    "tool": "tool_inventory",
    "integration": "external_integrations",
    "trust_boundary": "trust_boundaries",
    "output_surface": "output_surfaces",
    "agent_internal": "agent_internal",
}


def _required_resource_categories(
    patterns: Sequence[AttackPattern],
) -> tuple[str, ...]:
    required_kinds = {
        slot.kind
        for pattern in patterns
        for slot in pattern.canonical_chain.resource_slots
    }
    return tuple(sorted(_RESOURCE_CATEGORY_BY_KIND[kind] for kind in required_kinds))


def _available_resource_categories(
    profile: CapabilityProfile,
) -> dict[str, bool]:
    return {
        "entry_points": bool(profile.entry_points),
        "tool_inventory": bool(profile.tool_inventory),
        "external_integrations": bool(profile.external_integrations),
        "trust_boundaries": bool(profile.trust_boundaries),
        "output_surfaces": any(
            item.direction in ("output", "bidirectional")
            for item in profile.entry_points
        ),
        "agent_internal": "reasoning" in profile.zones_active,
    }


def _pattern_conditions(pattern: AttackPattern) -> Iterable[Condition]:
    for step in pattern.canonical_chain.steps:
        if step.condition is not None:
            yield step.condition
        yield from (precondition.condition for precondition in step.preconditions)


def _readiness_fact_references(
    patterns: Sequence[AttackPattern],
) -> dict[str, AuthoritativeFactReference]:
    fact_refs: dict[str, AuthoritativeFactReference] = {}
    for pattern in patterns:
        for condition in _pattern_conditions(pattern):
            for reference in _condition_facts(condition):
                fact_refs[_fact_key(reference)] = reference
    return fact_refs


def required_fact_references(
    patterns: Sequence[AttackPattern],
) -> tuple[AuthoritativeFactReference, ...]:
    """Return the complete canonical fact inventory used by readiness."""
    references = _readiness_fact_references(patterns)
    return tuple(references[key] for key in sorted(references))


def _required_fact_ids(
    fact_refs: dict[str, AuthoritativeFactReference],
) -> tuple[str, ...]:
    return tuple(sorted(reference.fact_id for reference in fact_refs.values()))


def _missing_fact_ids(
    fact_refs: dict[str, AuthoritativeFactReference],
    snapshot: CapabilityFactSnapshot,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            reference.fact_id
            for reference in fact_refs.values()
            if (
                (evidence := snapshot.fact(reference)) is None
                or evidence.status == "unknown"
            )
        )
    )


def check_projection_readiness(
    patterns: Sequence[AttackPattern],
    snapshot: CapabilityFactSnapshot,
) -> ProjectionReadinessReport:
    """Check selected patterns against the immutable profile/fact snapshot."""
    required_categories = _required_resource_categories(patterns)
    available_by_category = _available_resource_categories(snapshot.profile)
    missing_categories = tuple(
        category
        for category in required_categories
        if not available_by_category[category]
    )
    fact_refs = _readiness_fact_references(patterns)
    required_facts = _required_fact_ids(fact_refs)
    missing_facts = _missing_fact_ids(fact_refs, snapshot)
    return ProjectionReadinessReport(
        ready=not missing_categories and not missing_facts,
        required_resource_categories=required_categories,
        missing_resource_categories=missing_categories,
        required_facts=required_facts,
        missing_facts=missing_facts,
        pattern_ids=tuple(sorted(pattern.id for pattern in patterns)),
    )


def ensure_projection_readiness(
    patterns: Sequence[AttackPattern],
    snapshot: CapabilityFactSnapshot,
) -> ProjectionReadinessReport:
    """Raise actionable guidance instead of converting missing evidence to zero candidates."""
    report = check_projection_readiness(patterns, snapshot)
    if not report.ready:
        raise ProjectionReadinessError(report)
    return report


from asago_scenario_generator.pipeline.projection_resources import (  # noqa: E402, F401
    _assignment_conflicts,
    _cartesian_fill,
    _combination_baseline,
    _combination_key,
    _combination_satisfies_distinctness,
    _constrained_components,
    _constrained_indexes,
    _count_compatible_combinations,
    _count_component_assignments,
    _distinctness_edges,
    _entry_point_reference_allowed,
    _entry_point_references,
    _integration_references,
    _iter_compatible_combinations,
    _iter_coverage_first_combinations,
    _max_option_length,
    _offset_variants,
    _output_surface_references,
    _references_for_kind,
    _references_for_slot,
    _tool_references,
    _trust_boundary_references,
    _unconstrained_product,
    _variant_combinations,
    _agent_internal_references,
)


from asago_scenario_generator.pipeline.projection_allocation import (  # noqa: E402, F401
    _PatternProjectionState,
)
from asago_scenario_generator.pipeline.projection_requirements import (  # noqa: E402, F401
    _derive_execution_requirements,
    _derive_execution_requirements_core,
    _fail_closed_if_no_requirements,
    _ingress_controllability_for_link,
    _link_role_requirement,
    _linked_postcondition_ids,
    _observation_requirements,
    _require_unique_requirement_ids_or_issue,
    _requirement_id,
    _resolve_ingress_controllability,
    _security_outcome_requirements,
    _selected_ingress_links,
    _source_identity_kind_for_link,
)

from asago_scenario_generator.pipeline.projection_relations import (  # noqa: E402, F401
    _boundary_zones_or_none,
    _resource_id_or_none,
    _source_binding_kind_detail,
    _source_boundary_detail,
    _source_entry_point_detail,
    _source_identity_kind_detail,
    _source_influence_expected_kind,
    _source_influence_links,
    _source_ingress_relation_guard,
    _source_relation_boundary,
    _source_relation_issue,
    _source_relation_issue_detail,
    _source_relation_refs,
    _source_relation_resolution,
    _source_influence_relation,
    _validate_source_influence_paths,
)


def validate_projected_candidate(
    candidate_dict: dict[str, Any],
    snapshot: CapabilityFactSnapshot,
    authoritative_record: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    *,
    expected_catalog_pin: Digest,
) -> ProjectedCandidate:
    """Qualify serialized candidate integrity against trusted authoritative inputs."""
    snapshot.assert_integrity()
    candidate = ProjectedCandidate.model_validate(candidate_dict)
    authoritative = validate_attack_pattern(authoritative_record, taxonomy_resolver)
    authoritative = AttackPattern.model_validate(
        _normalize_semantic_order(authoritative.model_dump(mode="json"))
    )
    _validate_chain_identity(candidate, authoritative)
    _validate_pattern_pins(candidate, authoritative, expected_catalog_pin)
    _validate_prerequisite_zones(
        authoritative.prerequisite_capabilities, snapshot.profile
    )
    _validate_prerequisite_kc(authoritative.prerequisite_capabilities, snapshot.profile)
    _validate_snapshot_digest_pin(candidate, snapshot)
    validate_projection_snapshot(candidate.projection.model_dump(mode="json"), snapshot)
    _validate_source_influence_paths(candidate, snapshot)
    _validate_precondition_evidence(candidate, snapshot)
    _validate_ingress_controllability(candidate, snapshot)
    _validate_bindings_against_snapshot(candidate, snapshot)
    _validate_derived_requirements(candidate, snapshot)
    return candidate


def _validate_chain_identity(
    candidate: ProjectedCandidate, authoritative: AttackPattern
) -> None:
    """Require the candidate chain and pattern id to match the authority."""
    if candidate.projection.source_chain != authoritative.canonical_chain:
        raise ValueError("candidate source chain does not match authoritative pattern")
    if candidate.pattern_id != authoritative.id:
        raise ValueError("candidate pattern id does not match authoritative pattern")


def _validate_pattern_pins(
    candidate: ProjectedCandidate,
    authoritative: AttackPattern,
    expected_catalog_pin: Digest,
) -> None:
    """Require the candidate pins to match the authority and trusted catalog."""
    if candidate.projection.pattern_pin != _pattern_pin(authoritative):
        raise ValueError("candidate pattern pin does not match authoritative pattern")
    if candidate.projection.catalog_pin != expected_catalog_pin:
        raise ValueError("candidate catalog pin does not match trusted catalog")


def _validate_prerequisite_zones(
    prerequisites: Any, profile: CapabilityProfile
) -> None:
    """Require the authoritative pattern zones to be active in the snapshot."""
    if not set(prerequisites.min_zones).issubset(profile.zones_active):
        raise ValueError("authoritative pattern zones are incompatible with snapshot")


def _kc_requires_compatible(kc_requires: Any, profile_kc: set[str]) -> bool:
    """True when the pattern's KC requirements are satisfied by the profile."""
    if not kc_requires:
        return True
    if not set(kc_requires.all).issubset(profile_kc):
        return False
    if kc_requires.any and not set(kc_requires.any).intersection(profile_kc):
        return False
    return True


def _validate_prerequisite_kc(prerequisites: Any, profile: CapabilityProfile) -> None:
    """Require the authoritative pattern KC requirements to be satisfiable."""
    profile_kc = set(profile.kc_subcodes)
    if not _kc_requires_compatible(prerequisites.kc_requires, profile_kc):
        raise ValueError("authoritative pattern KC requirements are incompatible")


def _validate_snapshot_digest_pin(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's snapshot digest pin to match the resolver."""
    if candidate.projection.capability_fact_snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("candidate capability snapshot digest pin does not match")


def _validate_precondition_evidence(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require precondition evidence to match the resolver reading."""
    for result in candidate.precondition_results:
        for evidence in result.evidence:
            if snapshot.fact(evidence.fact) != evidence:
                raise ValueError(
                    "precondition fact evidence does not match resolver reading"
                )


def _validate_ingress_controllability(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's ingress controllability to match the snapshot."""
    ingress = snapshot.profile.resolve_entry_point(
        candidate.canonical_ingress.entry_point_id
    )
    if ingress is None or ingress.effective_controllability != (
        candidate.ingress_controllability
    ):
        raise ValueError("candidate ingress controllability does not match snapshot")


def _validate_bindings_against_snapshot(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require every binding to be compatible with the snapshot resources."""
    binding_by_slot = {
        binding.slot_id: binding.resource_ref
        for binding in candidate.projection.bindings
    }
    chain = candidate.projection.source_chain
    for slot in chain.resource_slots:
        allowed = _references_for_slot(
            slot,
            snapshot,
            initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
        )
        if binding_by_slot[slot.slot_id] not in allowed:
            raise ValueError("candidate binding is incompatible with snapshot resource")


def _validate_derived_requirements(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's requirements to match the authoritative derivation."""
    requirements, issue = _derive_execution_requirements(
        candidate.pattern_id,
        candidate.projection.source_chain,
        candidate.projection,
        snapshot,
    )
    requirements, issue = _fail_closed_if_no_requirements(
        candidate.pattern_id, requirements, issue
    )
    if issue is not None or requirements != candidate.execution_requirements:
        raise ValueError("candidate execution requirements do not match derivation")


from asago_scenario_generator.pipeline.projection_candidates import (  # noqa: E402, F401
    _bindings_for_combination,
    _build_candidate_from_combination,
    _candidate_complexity_inputs,
    _ingress_for_combination,
    _projection_data_for_combination,
    _selected_steps_from_chain,
)


def project_authoritative_candidates(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
    *,
    budget: ProjectionBudget | None = None,
    coverage_target_ids: set[str] | None = None,
) -> ProjectionBatch:
    """Qualify, project, bind, and identify authoritative candidate-v2 records.

    Structurally parsed ``AttackPattern`` objects and legacy catalogue records are
    deliberately not accepted: every raw record crosses the merged qualification
    boundary in this call.

    When ``coverage_target_ids`` is provided, the global budget allocation is
    coverage-aware: one feasible candidate per coverage target is reserved
    before binding variants and secondary expansion.  This ensures every
    ingress target receives at least one projected candidate before the
    budget is exhausted.  If ``budget.max_candidates`` is below the number of
    feasible coverage targets, reservation is best-effort and the caller
    should emit a ``selection_limitation`` for uncovered targets.
    """
    _authoritative_records_type_check(records)
    budget = _resolve_projection_budget(budget)
    snapshot.assert_integrity()
    qualified = _qualify_authoritative_records(records, taxonomy_resolver)
    catalog_pin = _catalog_content_pin(qualified)
    candidate_groups: list[_PatternProjectionState] = []
    issues: list[ProjectionIssue] = []
    for pattern, pattern_pin in qualified:
        _project_authoritative_pattern(
            pattern, pattern_pin, snapshot, catalog_pin, candidate_groups, issues
        )
    allocator = _AuthoritativeCandidateAllocator(
        budget, candidate_groups, issues, coverage_target_ids
    )
    allocator.reserve_coverage_targets()
    allocator.emit_reserved_targets()
    allocator.emit_pending()
    allocator.fill_round_robin()
    allocator.probe_truncation()
    return ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=_sorted_emitted_candidates(allocator.by_identity),
        infeasibilities=_sorted_infeasibilities(issues),
        limitations=_sorted_limitations(allocator.build_limitations()),
        unreserved_coverage_targets=allocator.unreserved_targets(),
        infeasible_coverage_targets=allocator.infeasible_coverage_targets(),
    )


# Authoritative projection, qualification, and allocation machinery lives
# in the sibling module pipeline.projection_authoritative; re-export it
# here so every existing import path keeps working.
from asago_scenario_generator.pipeline.projection_authoritative import (  # noqa: E402
    _resolve_projection_budget as _resolve_projection_budget,
    _catalog_content_pin as _catalog_content_pin,
    _sorted_emitted_candidates as _sorted_emitted_candidates,
    _infeasibility_key as _infeasibility_key,
    _sorted_infeasibilities as _sorted_infeasibilities,
    _limitation_key as _limitation_key,
    _sorted_limitations as _sorted_limitations,
    _authoritative_records_type_check as _authoritative_records_type_check,
    _qualify_authoritative_pattern as _qualify_authoritative_pattern,
    _resolve_qualified_patterns as _resolve_qualified_patterns,
    _qualify_authoritative_records as _qualify_authoritative_records,
    _profile_compatibility_gaps as _profile_compatibility_gaps,
    _incompatible_profile_issue as _incompatible_profile_issue,
    _profile_gate_failure_issue as _profile_gate_failure_issue,
    _results_contain_unknown as _results_contain_unknown,
    _results_contain_false as _results_contain_false,
    _unresolved_condition_issue as _unresolved_condition_issue,
    _unresolved_precondition_issue as _unresolved_precondition_issue,
    _false_precondition_issue as _false_precondition_issue,
    _inapplicable_projection_issue as _inapplicable_projection_issue,
    _select_conditionally_required_steps as _select_conditionally_required_steps,
    _projection_is_applicable as _projection_is_applicable,
    _omitted_conditional_steps as _omitted_conditional_steps,
    _precondition_results_or_none as _precondition_results_or_none,
    _profile_and_condition_gate as _profile_and_condition_gate,
    _qualified_condition_state as _qualified_condition_state,
    _ingress_slot_index as _ingress_slot_index,
    _gather_slot_options as _gather_slot_options,
    _source_influence_relation_links as _source_influence_relation_links,
    _relation_slot_ids as _relation_slot_ids,
    _source_influence_relation_state as _source_influence_relation_state,
    _check_simple_missing_slot as _check_simple_missing_slot,
    _slot_by_id as _slot_by_id,
    _source_influence_target_id as _source_influence_target_id,
    _source_influence_failure_issue as _source_influence_failure_issue,
    _record_missing_slot_issues as _record_missing_slot_issues,
    _direct_ingress_options as _direct_ingress_options,
    _has_source_influence_activation as _has_source_influence_activation,
    _has_direct_ingress_activation as _has_direct_ingress_activation,
    _no_activation_violation as _no_activation_violation,
    _resolve_ingress_activation as _resolve_ingress_activation,
    _zero_bindings_issue as _zero_bindings_issue,
    _assemble_pattern_state as _assemble_pattern_state,
    _project_authoritative_pattern as _project_authoritative_pattern,
    _target_ingress_reference as _target_ingress_reference,
    _dedupe_projection_issues as _dedupe_projection_issues,
    _AuthoritativeCandidateAllocator as _AuthoritativeCandidateAllocator,
    compute_authoritative_catalog_pin as compute_authoritative_catalog_pin,
)
