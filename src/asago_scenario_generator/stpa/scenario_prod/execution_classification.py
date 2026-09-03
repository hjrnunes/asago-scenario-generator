"""Deterministic classification of one STPA semantic execution contract."""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.stpa.models.execution_classification import (
    AmbiguousExecutionMatch,
    BindingCompleteness,
    EnvironmentBasis,
    ExecutionClassification,
    ExecutionClassificationDiagnostic,
    ExecutionClaimScope,
    ExecutionContractDisposition,
    ExecutionDiagnosticCode,
    ExecutionProfileFit,
    ExecutionResourcePurpose,
    ExecutionTargetProfile,
    InventoryCompleteness,
    ProfileAuthority,
    ProfileBasis,
    ResolvedExecutionBinding,
    SemanticExecutionContract,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import UnsafeOutcome


def classify_scenario_execution(
    contract: SemanticExecutionContract,
    unsafe_outcome: UnsafeOutcome | None,
    profile: ExecutionTargetProfile | None,
) -> ExecutionClassification:
    """Classify one contract without constructing a provider or runtime client.

    The returned dimensions are deliberately independent: semantic
    completeness describes the contract, while environment basis describes
    the evidence supplied for realizing it.  Matching is exact and stable;
    no resource is selected from prose or by fuzzy name matching.
    """
    if not isinstance(contract, SemanticExecutionContract):
        raise TypeError("contract must be a SemanticExecutionContract")
    if contract.disposition is ExecutionContractDisposition.analytical_only:
        return _classify_analytical_contract(contract)
    return _classify_executable_contract(contract, unsafe_outcome, profile)


def _classify_executable_contract(
    contract: SemanticExecutionContract,
    unsafe_outcome: UnsafeOutcome | None,
    profile: ExecutionTargetProfile | None,
) -> ExecutionClassification:
    """Classify an executable route after the analytical branch is removed."""
    if unsafe_outcome is None:
        return _classify_missing_outcome()
    if not isinstance(unsafe_outcome, UnsafeOutcome):
        raise TypeError("unsafe_outcome must be an UnsafeOutcome")
    if not _outcome_matches_contract(contract, unsafe_outcome):
        return _classify_outcome_mismatch()
    return _classify_validated_executable(contract, profile)


def _classify_validated_executable(
    contract: SemanticExecutionContract,
    profile: ExecutionTargetProfile | None,
) -> ExecutionClassification:
    """Classify a route after its unsafe-outcome identity is validated."""

    requirements = contract.resource_requirements
    if not requirements:
        return _classify_resource_free_contract()

    if profile is None:
        return _classify_without_profile(contract, requirements)

    return _classify_profile_bound_contract(contract, profile)


def _classify_profile_bound_contract(
    contract: SemanticExecutionContract,
    profile: ExecutionTargetProfile,
) -> ExecutionClassification:
    """Classify resource requirements against an intact, compatible profile."""

    try:
        profile.assert_integrity()
    except ValueError:
        return _classify_invalid_profile(profile)

    expected_basis = _expected_profile_basis(contract)
    if expected_basis is not None and profile.basis is not expected_basis:
        return _classify_basis_mismatch(profile)

    return _classify_against_profile(contract, profile)


def _classify_analytical_contract(
    contract: SemanticExecutionContract,
) -> ExecutionClassification:
    """Classify an explicit analytical-only contract without execution claims."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        diagnostics=tuple(
            _diagnostic(ExecutionDiagnosticCode.execution_route_missing, gap.detail)
            for gap in contract.gaps
        ),
    )


def _classify_missing_outcome() -> ExecutionClassification:
    """Classify a route that has no semantic unsafe-outcome oracle."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        diagnostics=(
            _diagnostic(
                ExecutionDiagnosticCode.oracle_missing,
                "semantic unsafe outcome is required for execution",
            ),
        ),
    )


def _classify_outcome_mismatch() -> ExecutionClassification:
    """Classify a route whose action does not match its unsafe outcome."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        diagnostics=(
            _diagnostic(
                ExecutionDiagnosticCode.execution_route_missing,
                "unsafe outcome does not match the selected execution action",
            ),
        ),
    )


def _classify_resource_free_contract() -> ExecutionClassification:
    """Classify a model-only route that needs no environment resources."""
    return _classification(
        BindingCompleteness.concrete,
        EnvironmentBasis.target_agnostic,
        ExecutionProfileFit.not_required,
        ExecutionClaimScope.model_behavior_only,
    )


def _classify_without_profile(
    contract: SemanticExecutionContract,
    requirements: Sequence,
) -> ExecutionClassification:
    """Retain resource roles as unresolved when no profile was supplied."""
    code = (
        ExecutionDiagnosticCode.simulation_contract_missing
        if contract.requested_environment_basis is not None
        and contract.requested_environment_basis.value == "simulation_profile"
        else ExecutionDiagnosticCode.target_profile_not_supplied
    )
    return _classification(
        BindingCompleteness.parameterized,
        EnvironmentBasis.none,
        ExecutionProfileFit.needs_binding,
        ExecutionClaimScope.no_execution_claim,
        unresolved=requirements,
        diagnostics=tuple(
            _diagnostic(code, "no selected environment profile was supplied", item)
            for item in requirements
        ),
    )


def _classify_invalid_profile(
    profile: ExecutionTargetProfile,
) -> ExecutionClassification:
    """Classify a profile whose recorded digest does not match its content."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        profile_digest=profile.semantic_digest,
        diagnostics=(
            _diagnostic(
                ExecutionDiagnosticCode.target_profile_digest_mismatch,
                "selected environment profile digest is not intact",
            ),
        ),
    )


def _classify_basis_mismatch(
    profile: ExecutionTargetProfile,
) -> ExecutionClassification:
    """Classify a profile that uses a different basis than the contract requests."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        profile_digest=profile.semantic_digest,
        diagnostics=(
            _diagnostic(
                ExecutionDiagnosticCode.execution_route_missing,
                "selected profile basis does not match requested environment basis",
            ),
        ),
    )


def _outcome_matches_contract(
    contract: SemanticExecutionContract,
    outcome: UnsafeOutcome,
) -> bool:
    """Require the contract to preserve the unsafe action identity."""
    if _action_is_model_observed(contract):
        return True
    return _target_action_matches_outcome(contract, outcome)


def _action_is_model_observed(contract: SemanticExecutionContract) -> bool:
    """Return whether the route observes model or agent output directly."""
    return contract.action_kind is not None and contract.action_kind.value in {
        "model_output",
        "agent_message",
    }


def _target_action_matches_outcome(
    contract: SemanticExecutionContract,
    outcome: UnsafeOutcome,
) -> bool:
    """Match the selected external action requirement to the unsafe outcome."""
    return any(
        requirement.purpose is ExecutionResourcePurpose.target_action
        and requirement.owner_ref == outcome.control_action_id
        and requirement.operation == outcome.control_action_id
        for requirement in contract.resource_requirements
    )


def _expected_profile_basis(contract: SemanticExecutionContract) -> ProfileBasis | None:
    requested = (
        contract.requested_environment_basis.value
        if contract.requested_environment_basis is not None
        else None
    )
    if requested == "target_profile":
        return ProfileBasis.target
    if requested == "simulation_profile":
        return ProfileBasis.simulation
    return None


def _classify_against_profile(
    contract: SemanticExecutionContract,
    profile: ExecutionTargetProfile,
) -> ExecutionClassification:
    results = _collect_profile_matches(contract, profile)
    return _classification_from_profile_matches(profile, *results)


def _collect_profile_matches(
    contract: SemanticExecutionContract,
    profile: ExecutionTargetProfile,
) -> tuple[list, list, list, list, list, list]:
    """Collect exact profile matches and diagnostic buckets per requirement."""
    resolved: list[ResolvedExecutionBinding] = []
    unresolved: list = []
    unsupported: list = []
    invalid: list = []
    ambiguous: list[AmbiguousExecutionMatch] = []
    diagnostics: list[ExecutionClassificationDiagnostic] = []
    for requirement in contract.resource_requirements:
        _collect_requirement_match(
            requirement,
            profile,
            resolved,
            unresolved,
            unsupported,
            invalid,
            ambiguous,
            diagnostics,
        )
    return resolved, unresolved, unsupported, invalid, ambiguous, diagnostics


def _collect_requirement_match(
    requirement,
    profile: ExecutionTargetProfile,
    resolved: list,
    unresolved: list,
    unsupported: list,
    invalid: list,
    ambiguous: list,
    diagnostics: list,
) -> None:
    """Classify one requirement against one profile without selecting by prose."""
    matches = _matching_resources(requirement, profile.resources)
    if requirement.exact_resource_id is not None:
        _classify_exact_requirement(
            requirement,
            matches,
            profile,
            resolved,
            unresolved,
            unsupported,
            invalid,
            diagnostics,
        )
        return
    if len(matches) > 1:
        _record_ambiguous_match(requirement, matches, ambiguous, diagnostics)
        return
    if len(matches) == 1 and _role_match_is_authoritative(matches[0][0], profile):
        _record_resolved_match(requirement, matches[0], resolved)
        return
    _classify_unresolved_role(
        requirement,
        matches,
        profile,
        unresolved,
        unsupported,
        diagnostics,
    )


def _record_ambiguous_match(
    requirement,
    matches,
    ambiguous: list,
    diagnostics: list,
) -> None:
    """Retain all role candidates when a profile cannot establish uniqueness."""
    candidate_ids = tuple(item[0].resource_id for item in matches)
    ambiguous.append(
        AmbiguousExecutionMatch(
            requirement_id=requirement.requirement_id,
            candidate_resource_ids=candidate_ids,
        )
    )
    diagnostics.append(
        _diagnostic(
            ExecutionDiagnosticCode.target_resource_ambiguous,
            "role requirement matched more than one exact resource",
            requirement,
            candidate_ids=candidate_ids,
        )
    )


def _record_resolved_match(requirement, match, resolved: list) -> None:
    """Append one authoritative role/resource/operation identity."""
    resource, operation = match
    resolved.append(
        ResolvedExecutionBinding(
            requirement_id=requirement.requirement_id,
            resource_id=resource.resource_id,
            operation_id=operation.operation_id,
        )
    )


def _classification_from_profile_matches(
    profile: ExecutionTargetProfile,
    resolved: list,
    unresolved: list,
    unsupported: list,
    invalid: list,
    ambiguous: list,
    diagnostics: list,
) -> ExecutionClassification:
    """Turn profile match buckets into the independent classification axes."""

    if invalid:
        return _classification_for_invalid_matches(profile, resolved, diagnostics)
    if not unresolved and not unsupported and not ambiguous:
        return _classification_for_complete_matches(profile, resolved, diagnostics)
    return _classification_for_incomplete_matches(
        profile,
        resolved,
        unresolved,
        unsupported,
        ambiguous,
        diagnostics,
    )


def _classification_for_invalid_matches(
    profile: ExecutionTargetProfile,
    resolved: list,
    diagnostics: list,
) -> ExecutionClassification:
    """Return the closed invalid result for an incompatible exact reference."""
    return _classification(
        BindingCompleteness.analytical_only,
        EnvironmentBasis.none,
        ExecutionProfileFit.invalid,
        ExecutionClaimScope.no_execution_claim,
        resolved=resolved,
        diagnostics=diagnostics,
        profile_digest=profile.semantic_digest,
    )


def _classification_for_complete_matches(
    profile: ExecutionTargetProfile,
    resolved: list,
    diagnostics: list,
) -> ExecutionClassification:
    """Return the concrete claim corresponding to the profile basis."""
    if profile.basis is ProfileBasis.simulation:
        return _classification(
            BindingCompleteness.concrete,
            EnvironmentBasis.simulation_profile,
            ExecutionProfileFit.matched,
            ExecutionClaimScope.agent_behavior_with_simulated_tools,
            resolved=resolved,
            profile_digest=profile.semantic_digest,
            diagnostics=diagnostics,
        )
    return _classification(
        BindingCompleteness.concrete,
        EnvironmentBasis.target_profile,
        ExecutionProfileFit.matched,
        ExecutionClaimScope.target_specific_intent,
        resolved=resolved,
        profile_digest=profile.semantic_digest,
        diagnostics=diagnostics,
    )


def _classification_for_incomplete_matches(
    profile: ExecutionTargetProfile,
    resolved: list,
    unresolved: list,
    unsupported: list,
    ambiguous: list,
    diagnostics: list,
) -> ExecutionClassification:
    """Return a parameterized result while retaining every match diagnostic."""
    fit = ExecutionProfileFit.needs_binding
    if ambiguous:
        fit = ExecutionProfileFit.ambiguous
    elif unsupported:
        fit = ExecutionProfileFit.unsupported
    return _classification(
        BindingCompleteness.parameterized,
        _environment_basis(profile),
        fit,
        ExecutionClaimScope.no_execution_claim,
        resolved=resolved,
        unresolved_ids=unresolved,
        ambiguous=ambiguous,
        unsupported_ids=unsupported,
        profile_digest=profile.semantic_digest,
        diagnostics=diagnostics,
    )


def _matching_resources(requirement, resources):
    """Return exact resource/operation matches in canonical resource order."""
    matches = []
    for resource in resources:
        if not _resource_matches(requirement, resource):
            continue
        matches.extend(
            (resource, operation)
            for operation in _matching_operations(requirement, resource)
        )
    return tuple(
        sorted(matches, key=lambda item: (item[0].resource_id, item[1].operation_id))
    )


def _matching_operations(requirement, resource):
    """Return operations with the exact semantic name and observable properties."""
    required_properties = set(requirement.required_properties)
    return tuple(
        operation
        for operation in resource.operations
        if operation.semantic_operation == requirement.operation
        and required_properties.issubset(operation.observable_properties)
    )


def _resource_matches(requirement, resource) -> bool:
    """Match role, kind, owner and required surfaces exactly."""
    return (
        resource.resource_kind in requirement.acceptable_resource_kinds
        and requirement.role_id in resource.role_ids
        and requirement.owner_ref in resource.structural_refs
        and set(requirement.required_surfaces).issubset(resource.surfaces)
        and (
            requirement.required_attacker_influence is None
            or resource.attacker_influence is requirement.required_attacker_influence
        )
    )


def _role_match_is_authoritative(resource, profile) -> bool:
    """Require reviewed facts and a complete inventory for role searches."""
    return (
        resource.authority is ProfileAuthority.reviewed
        and profile.inventory_completeness is InventoryCompleteness.reviewed_complete
        and (
            profile.authority is ProfileAuthority.reviewed
            or profile.basis is ProfileBasis.simulation
        )
    )


def _classify_exact_requirement(
    requirement,
    matches,
    profile,
    resolved,
    unresolved,
    unsupported,
    invalid,
    diagnostics,
) -> None:
    """Resolve or reject a producer-selected exact resource reference."""
    candidates = [
        item for item in matches if item[0].resource_id == requirement.exact_resource_id
    ]
    if not candidates:
        invalid.append(requirement.requirement_id)
        diagnostics.append(
            _diagnostic(
                ExecutionDiagnosticCode.explicit_target_ref_dangling,
                "explicit resource reference is absent or incompatible with its operation",
                requirement,
            )
        )
        return
    resource, operation = candidates[0]
    if not _exact_resource_is_authoritative(resource, profile):
        unresolved.append(requirement.requirement_id)
        diagnostics.append(
            _diagnostic(
                ExecutionDiagnosticCode.profile_inferred_only,
                "explicit resource is not backed by reviewed evidence",
                requirement,
            )
        )
        return
    resolved.append(
        ResolvedExecutionBinding(
            requirement_id=requirement.requirement_id,
            resource_id=resource.resource_id,
            operation_id=operation.operation_id,
        )
    )


def _exact_resource_is_authoritative(resource, profile) -> bool:
    """Allow reviewed resources in complete targets or explicit simulations."""
    return resource.authority is ProfileAuthority.reviewed and (
        profile.authority is ProfileAuthority.reviewed
        or profile.basis is ProfileBasis.simulation
    )


def _classify_unresolved_role(
    requirement,
    matches,
    profile,
    unresolved,
    unsupported,
    diagnostics,
) -> None:
    """Retain zero/one weak matches without claiming target execution."""
    unresolved.append(requirement.requirement_id)
    if profile.authority is not ProfileAuthority.reviewed:
        diagnostics.append(
            _diagnostic(
                ExecutionDiagnosticCode.profile_inferred_only,
                "profile facts are inferred and cannot establish a target claim",
                requirement,
            )
        )
    elif profile.inventory_completeness is not InventoryCompleteness.reviewed_complete:
        diagnostics.append(
            _diagnostic(
                ExecutionDiagnosticCode.profile_inventory_unknown,
                "role search requires a reviewed-complete inventory",
                requirement,
                candidate_ids=tuple(item[0].resource_id for item in matches),
            )
        )
    else:
        unsupported.append(requirement.requirement_id)
        unresolved.pop()
        diagnostics.append(
            _diagnostic(
                ExecutionDiagnosticCode.operation_unsupported,
                "reviewed-complete profile has no compatible resource operation",
                requirement,
            )
        )


def _environment_basis(profile: ExecutionTargetProfile) -> EnvironmentBasis:
    """Convert target-profile basis to the wire classification value."""
    return (
        EnvironmentBasis.simulation_profile
        if profile.basis is ProfileBasis.simulation
        else EnvironmentBasis.target_profile
    )


def _diagnostic(
    code: ExecutionDiagnosticCode,
    detail: str,
    requirement=None,
    *,
    candidate_ids: Sequence[str] = (),
) -> ExecutionClassificationDiagnostic:
    """Build one stable diagnostic record."""
    return ExecutionClassificationDiagnostic(
        code=code,
        detail=detail,
        requirement_id=(
            requirement.requirement_id if requirement is not None else None
        ),
        candidate_resource_ids=tuple(candidate_ids),
    )


def _classification(
    completeness: BindingCompleteness,
    environment: EnvironmentBasis,
    fit: ExecutionProfileFit,
    claim: ExecutionClaimScope,
    *,
    resolved=(),
    unresolved=(),
    unresolved_ids=None,
    ambiguous=(),
    unsupported=(),
    unsupported_ids=None,
    diagnostics=(),
    profile_digest=None,
) -> ExecutionClassification:
    """Construct a canonical classification from local match results."""
    unresolved_values = (
        tuple(unresolved_ids)
        if unresolved_ids is not None
        else tuple(item.requirement_id for item in unresolved)
    )
    unsupported_values = (
        tuple(unsupported_ids)
        if unsupported_ids is not None
        else tuple(item.requirement_id for item in unsupported)
    )
    return ExecutionClassification(
        binding_completeness=completeness,
        environment_basis=environment,
        profile_fit=fit,
        claim_scope=claim,
        resolved_bindings=tuple(resolved),
        unresolved_requirement_ids=unresolved_values,
        ambiguous_matches=tuple(ambiguous),
        unsupported_requirement_ids=unsupported_values,
        diagnostics=tuple(diagnostics),
        target_profile_digest=profile_digest,
    )


__all__ = ["classify_scenario_execution"]
