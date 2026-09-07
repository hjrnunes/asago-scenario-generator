"""Acceptance-first tests for deterministic STPA execution classification."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    BindingCompleteness,
    EnvironmentBasis,
    ExecutionActionKind,
    ExecutionClaimScope,
    ExecutionContractDisposition,
    ExecutionDeliveryClass,
    ExecutionProfileFit,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionSurface,
    ExecutionSemanticGapCode,
    ExecutionTargetProfile,
    DiscoveryProvenance,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    RequestedEnvironmentBasis,
    SemanticAuthority,
    SourceProtocol,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SemanticExecutionGap,
    SimulationBehavior,
    TargetProfileOperation,
    TargetProfileResource,
    _freeze_json,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    AdversarialStimulusRequirement,
    UnsafeOutcome,
    _validate_stimulus_delivery,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionPresenceCondition,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    classify_scenario_execution,
    resolve_contract_environment_request,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _validate_assembled_environment_basis,
)


def _outcome() -> UnsafeOutcome:
    return UnsafeOutcome(
        outcome_id="OUTCOME-1",
        control_action_id="CA-1-1",
        uca_type=UCAType.not_provided,
        condition=ActionPresenceCondition(
            control_action_id="CA-1-1", expected="not_provided"
        ),
        semantic_proposition=None,
        semantic_binding_required=False,
    )


def _direct_contract() -> SemanticExecutionContract:
    return SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.model_output,
    )


def _tool_contract(
    *,
    exact_resource_id: str | None = None,
    requested_basis: RequestedEnvironmentBasis
    | None = RequestedEnvironmentBasis.target_profile,
) -> SemanticExecutionContract:
    return SemanticExecutionContract(
        requested_environment_basis=requested_basis,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.indirect_content,
            factor_id="CF-1",
            source_role="attacker_influenced_content",
            carrier_requirement_id="REQ-1",
        ),
        action_kind=ExecutionActionKind.model_output,
        resource_requirements=(
            {
                "requirement_id": "REQ-1",
                "purpose": ExecutionResourcePurpose.stimulus_carrier,
                "factor_id": "CF-1",
                "owner_ref": "PM-1-1",
                "acceptable_resource_kinds": (ExecutionResourceKind.tool,),
                "role_id": "attacker_influenced_content_source",
                "operation": "retrieve-1",
                "required_properties": ("content_reaches_model_context",),
                "required_surfaces": ("tool_result",),
                "required_attacker_influence": "indirect",
                "exact_resource_id": exact_resource_id,
                "late_bindable": exact_resource_id is None,
                "evidence_refs": ("CF-1",),
            },
        ),
    )


def _target_profile(
    *,
    inventory_completeness: InventoryCompleteness = InventoryCompleteness.observed_complete,
    resources: tuple[TargetProfileResource, ...] | None = None,
    basis: ProfileBasis = ProfileBasis.target,
) -> ExecutionTargetProfile:
    resources = resources or (
        TargetProfileResource(
            resource_id="mcp:target-1:retrieve-1",
            resource_kind=ExecutionResourceKind.tool,
            target_id="target-1",
            tool_name="retrieve-1",
            description="Retrieve content for the model context.",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            output_schema="opaque",
            role_ids=("attacker_influenced_content_source",),
            structural_refs=("PM-1-1",),
            attacker_influence="indirect",
            surfaces=("tool_call", "tool_result"),
            operations=(
                TargetProfileOperation(
                    operation_id="retrieve-1",
                    semantic_operation="retrieve-1",
                    observable_properties=("content_reaches_model_context",),
                ),
            ),
            evidence_refs=("inventory:tool:retrieve-1",),
        ),
    )
    tool = McpToolObservation(
        name="retrieve-1",
        source_observation_sha256=(
            "3458984c2818544369783de6780da78f10f3c60be6e2c07dcd2dc6c585108a3a"
        ),
        description="Retrieve content for the model context.",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        output_schema="opaque",
    )
    inventory = McpInventoryObservation(
        target_id="target-1",
        authorization_scope_id="scope-1",
        tools=(tool,),
    )
    return ExecutionTargetProfile(
        target_id="target-1",
        authorization_scope_id="scope-1",
        basis=basis,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.reviewed,
        inventory_completeness=inventory_completeness,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="fixture-scanner",
            interpreter_id="fixture-interpreter",
            verifier_id="fixture-verifier",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=(
            {
                "resource_id": "mcp:target-1:retrieve-1",
                "tool_name": "retrieve-1",
                "disposition": "supported",
                "evidence_refs": ("inventory:tool:retrieve-1:description",),
                "rationale": "fixture interpretation",
            },
        ),
    )


def _profile_update(
    profile: ExecutionTargetProfile, **updates
) -> ExecutionTargetProfile:
    payload = profile.model_dump(mode="json", exclude={"semantic_digest"})
    if updates.get("basis") in {"simulation", ProfileBasis.simulation}:
        target_id = updates.pop("target_id", profile.target_id)
        updates.pop("environment_id", None)
        payload.update(
            {
                "target_id": target_id,
                "basis": "simulation",
                "source_protocol": "simulation",
                "inventory_authority": None,
                "inventory_completeness": "unknown",
                "source_inventory_digest": None,
                "discovery_provenance": None,
                "inventory": None,
                "interpretations": (),
            }
        )
    payload.update(updates)
    return ExecutionTargetProfile.model_validate(payload)


def _simulation_resource(
    resource_id: str = "sim:retrieve-1",
) -> TargetProfileResource:
    return TargetProfileResource(
        resource_id=resource_id,
        resource_kind=ExecutionResourceKind.tool,
        description="Simulate content retrieval.",
        input_schema={"type": "object", "properties": {}},
        role_ids=("attacker_influenced_content_source",),
        structural_refs=("PM-1-1",),
        attacker_influence="indirect",
        surfaces=("tool_result",),
        operations=(
            TargetProfileOperation(
                operation_id="retrieve-1",
                semantic_operation="retrieve-1",
                observable_properties=("content_reaches_model_context",),
            ),
        ),
        evidence_refs=(f"simulation:{resource_id}",),
        simulation_behavior=SimulationBehavior(
            inputs={"content": "fixture"},
            outputs={"content_reaches_model_context": True},
            emitted_events=("content_retrieved",),
            observation_points=("model_context",),
        ),
    )


def _simulation_profile(
    resources: tuple[TargetProfileResource, ...] | None = None,
    *,
    semantic_authority: SemanticAuthority = SemanticAuthority.reviewed,
) -> ExecutionTargetProfile:
    return ExecutionTargetProfile(
        target_id="sim-1",
        authorization_scope_id="fixture-scope",
        basis=ProfileBasis.simulation,
        inventory_authority=None,
        semantic_authority=semantic_authority,
        inventory_completeness=InventoryCompleteness.unknown,
        source_protocol=SourceProtocol.simulation,
        resources=resources or (_simulation_resource(),),
    )


def test_direct_prompt_is_concrete_target_agnostic() -> None:
    result = classify_scenario_execution(_direct_contract(), _outcome(), None)

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.environment_basis is EnvironmentBasis.target_agnostic
    assert result.profile_fit is ExecutionProfileFit.not_required
    assert result.claim_scope is ExecutionClaimScope.model_behavior_only
    assert result.diagnostics == ()


def test_resource_free_route_retains_supplied_target_profile_lineage() -> None:
    profile = _target_profile()

    result = classify_scenario_execution(_direct_contract(), _outcome(), profile)

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.environment_basis is EnvironmentBasis.target_agnostic
    assert result.profile_fit is ExecutionProfileFit.not_required
    assert result.claim_scope is ExecutionClaimScope.model_behavior_only
    assert result.target_profile_digest == profile.semantic_digest
    assert result.inventory_authority is None
    assert result.semantic_authority is None


@pytest.mark.parametrize(
    ("has_resources", "requested", "expected"),
    (
        (False, None, RequestedEnvironmentBasis.target_agnostic),
        (
            False,
            RequestedEnvironmentBasis.target_agnostic,
            RequestedEnvironmentBasis.target_agnostic,
        ),
        (
            False,
            RequestedEnvironmentBasis.target_profile,
            RequestedEnvironmentBasis.target_agnostic,
        ),
        (
            False,
            RequestedEnvironmentBasis.simulation_profile,
            RequestedEnvironmentBasis.target_agnostic,
        ),
        (True, None, None),
        (
            True,
            RequestedEnvironmentBasis.target_profile,
            RequestedEnvironmentBasis.target_profile,
        ),
        (
            True,
            RequestedEnvironmentBasis.simulation_profile,
            RequestedEnvironmentBasis.simulation_profile,
        ),
    ),
)
def test_resolve_contract_environment_request_is_resource_sensitive(
    has_resources: bool,
    requested: RequestedEnvironmentBasis | None,
    expected: RequestedEnvironmentBasis | None,
) -> None:
    requirements = _tool_contract().resource_requirements if has_resources else ()

    assert resolve_contract_environment_request(requirements, requested) is expected


def test_resource_bearing_contract_can_retain_unspecified_basis() -> None:
    contract = _tool_contract(requested_basis=None)

    assert contract.requested_environment_basis is None


def test_unspecified_resource_basis_has_distinct_diagnostic() -> None:
    result = classify_scenario_execution(
        _tool_contract(requested_basis=None), _outcome(), None
    )

    assert result.diagnostics[0].code.value == "environment_profile_not_supplied"


def test_parameterized_role_without_profile_is_retained() -> None:
    result = classify_scenario_execution(_tool_contract(), _outcome(), None)

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.environment_basis is EnvironmentBasis.none
    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.unresolved_requirement_ids == ("REQ-1",)
    assert result.diagnostics[0].code.value == "target_profile_not_supplied"


def test_target_profile_does_not_resolve_a_role_without_target_realization() -> None:
    result = classify_scenario_execution(
        _tool_contract(), _outcome(), _target_profile()
    )

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.environment_basis is EnvironmentBasis.target_profile
    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.claim_scope is ExecutionClaimScope.no_execution_claim
    assert result.resolved_bindings == ()
    assert result.diagnostics[0].code.value == "profile_inferred_only"


def test_partial_inventory_does_not_claim_unique_role_match() -> None:
    result = classify_scenario_execution(
        _tool_contract(),
        _outcome(),
        _target_profile(inventory_completeness=InventoryCompleteness.observed_partial),
    )

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.unresolved_requirement_ids == ("REQ-1",)
    assert any(
        item.code.value == "profile_inferred_only" for item in result.diagnostics
    )


def test_two_matches_are_ambiguous_and_no_resource_is_selected() -> None:
    first = _simulation_resource()
    second = _simulation_resource("sim:retrieve-2")
    result = classify_scenario_execution(
        _tool_contract(requested_basis=RequestedEnvironmentBasis.simulation_profile),
        _outcome(),
        _simulation_profile((first, second)),
    )

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.profile_fit is ExecutionProfileFit.ambiguous
    assert result.resolved_bindings == ()
    assert result.ambiguous_matches[0].candidate_resource_ids == (
        "sim:retrieve-1",
        "sim:retrieve-2",
    )


def test_exact_resource_can_resolve_in_partial_inventory() -> None:
    result = classify_scenario_execution(
        _tool_contract(exact_resource_id="mcp:target-1:retrieve-1"),
        _outcome(),
        _target_profile(inventory_completeness=InventoryCompleteness.observed_partial),
    )

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.claim_scope is ExecutionClaimScope.target_specific_intent


def test_exact_target_action_does_not_require_attacker_influence_metadata() -> None:
    profile = _target_profile()
    resource = profile.resources[0].model_copy(
        update={"attacker_influence": AttackerInfluence.unknown}
    )
    contract = SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_profile,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.tool_call,
        resource_requirements=(
            {
                "requirement_id": "REQ-target-action",
                "purpose": ExecutionResourcePurpose.target_action,
                "owner_ref": "CA-1-1",
                "acceptable_resource_kinds": (ExecutionResourceKind.tool,),
                "role_id": "target_control_action",
                "operation": "retrieve-1",
                "required_surfaces": ("tool_call",),
                "required_attacker_influence": None,
                "exact_resource_id": resource.resource_id,
                "late_bindable": False,
                "evidence_refs": ("CA-1-1",),
            },
        ),
    )
    result = classify_scenario_execution(
        contract,
        _outcome(),
        _target_profile(resources=(resource,)),
    )

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.resolved_bindings[0].resource_id == resource.resource_id


def test_incompatible_exact_resource_is_invalid_without_fallback() -> None:
    result = classify_scenario_execution(
        _tool_contract(exact_resource_id="mcp:target-1:missing"),
        _outcome(),
        _target_profile(),
    )

    assert result.binding_completeness is BindingCompleteness.analytical_only
    assert result.profile_fit is ExecutionProfileFit.invalid
    assert result.resolved_bindings == ()
    assert result.unsupported_requirement_ids == ()
    assert result.diagnostics[0].code.value == "explicit_target_ref_dangling"


def test_missing_outcome_is_analytical_only() -> None:
    profile = _target_profile()
    result = classify_scenario_execution(_direct_contract(), None, profile)

    assert result.binding_completeness is BindingCompleteness.analytical_only
    assert result.claim_scope is ExecutionClaimScope.no_execution_claim
    assert result.diagnostics[0].code.value == "oracle_missing"
    assert result.target_profile_digest == profile.semantic_digest
    assert result.inventory_authority is None
    assert result.semantic_authority is None


def test_target_profile_digest_is_content_addressed() -> None:
    profile = _target_profile()
    assert profile.semantic_digest == profile.compute_semantic_digest()
    with pytest.raises(ValueError, match="semantic_digest"):
        ExecutionTargetProfile.model_validate(
            profile.model_dump(mode="json") | {"semantic_digest": "0" * 64}
        )


def test_profile_resource_requires_unique_semantic_operations() -> None:
    base = _target_profile().resources[0]
    duplicate = base.operations[0].model_copy(update={"operation_id": "retrieve-2"})
    payload = base.model_dump(mode="python")
    payload["operations"] = (base.operations[0], duplicate)
    with pytest.raises(ValueError, match="exactly one operation"):
        TargetProfileResource(**payload)


def test_simulation_profile_is_concrete_with_simulated_claim() -> None:
    profile = _simulation_profile()

    result = classify_scenario_execution(
        _tool_contract(requested_basis=RequestedEnvironmentBasis.simulation_profile),
        _outcome(),
        profile,
    )

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.environment_basis is EnvironmentBasis.simulation_profile
    assert result.claim_scope is ExecutionClaimScope.agent_behavior_with_simulated_tools


def test_complete_inferred_simulation_profile_can_be_concrete() -> None:
    profile = _simulation_profile(semantic_authority=SemanticAuthority.inferred)

    result = classify_scenario_execution(
        _tool_contract(requested_basis=RequestedEnvironmentBasis.simulation_profile),
        _outcome(),
        profile,
    )

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.environment_basis is EnvironmentBasis.simulation_profile
    assert result.profile_fit is ExecutionProfileFit.matched


def test_exact_resource_can_resolve_in_complete_inferred_simulation_profile() -> None:
    profile = _simulation_profile(semantic_authority=SemanticAuthority.inferred)

    result = classify_scenario_execution(
        _tool_contract(
            exact_resource_id="sim:retrieve-1",
            requested_basis=RequestedEnvironmentBasis.simulation_profile,
        ),
        _outcome(),
        profile,
    )

    assert result.binding_completeness is BindingCompleteness.concrete
    assert result.environment_basis is EnvironmentBasis.simulation_profile
    assert result.profile_fit is ExecutionProfileFit.matched
    assert result.claim_scope is ExecutionClaimScope.agent_behavior_with_simulated_tools


def test_simulation_profile_requires_behavior_for_every_resource() -> None:
    resource = _simulation_resource().model_copy(update={"simulation_behavior": None})
    with pytest.raises(ValueError, match="simulation_behavior"):
        _simulation_profile((resource,))


def test_target_profile_rejects_simulation_behavior() -> None:
    resource = (
        _target_profile()
        .resources[0]
        .model_copy(
            update={
                "simulation_behavior": SimulationBehavior(
                    inputs={"content": "fixture"},
                    outputs={"content_reaches_model_context": True},
                    observation_points=("model_context",),
                )
            }
        )
    )
    with pytest.raises(ValueError, match="MCP resources"):
        _profile_update(_target_profile(resources=(resource,)))


def test_runtime_observer_and_clock_kinds_are_not_semantic_resources() -> None:
    with pytest.raises(ValueError, match="acceptable_resource_kinds"):
        SemanticExecutionContract(
            requested_environment_basis=RequestedEnvironmentBasis.target_profile,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.indirect_content,
                factor_id="CF-1",
                source_role="attacker_influenced_content",
                carrier_requirement_id="REQ-1",
            ),
            action_kind=ExecutionActionKind.model_output,
            resource_requirements=(
                {
                    "requirement_id": "REQ-1",
                    "purpose": ExecutionResourcePurpose.stimulus_carrier,
                    "factor_id": "CF-1",
                    "owner_ref": "PM-1-1",
                    "acceptable_resource_kinds": ("observer",),
                    "role_id": "attacker_influenced_content_source",
                    "operation": "retrieve_content",
                    "required_surfaces": ("tool_result",),
                    "required_attacker_influence": "indirect",
                    "late_bindable": True,
                    "evidence_refs": ("CF-1",),
                },
            ),
        )


@pytest.mark.parametrize(
    "completeness",
    [InventoryCompleteness.unknown, InventoryCompleteness.observed_partial],
)
def test_zero_role_matches_remain_unresolved_in_noncomplete_inventory(
    completeness,
) -> None:
    resource = _target_profile().resources[0].model_copy(update={"role_ids": ()})
    result = classify_scenario_execution(
        _tool_contract(),
        _outcome(),
        _target_profile(inventory_completeness=completeness, resources=(resource,)),
    )

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.unresolved_requirement_ids == ("REQ-1",)
    assert result.unsupported_requirement_ids == ()


def test_zero_role_match_stays_unresolved_without_target_realization() -> None:
    resource = _target_profile().resources[0].model_copy(update={"role_ids": ()})
    result = classify_scenario_execution(
        _tool_contract(), _outcome(), _target_profile(resources=(resource,))
    )

    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.unresolved_requirement_ids == ("REQ-1",)
    assert result.unsupported_requirement_ids == ()


def test_inferred_profile_cannot_establish_target_claim() -> None:
    profile = _profile_update(_target_profile(), semantic_authority="inferred")

    result = classify_scenario_execution(_tool_contract(), _outcome(), profile)

    assert result.binding_completeness is BindingCompleteness.parameterized
    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.diagnostics[0].code.value == "profile_inferred_only"


def test_requested_target_basis_rejects_simulation_profile() -> None:
    profile = _simulation_profile()

    result = classify_scenario_execution(_tool_contract(), _outcome(), profile)

    assert result.binding_completeness is BindingCompleteness.analytical_only
    assert result.environment_basis is EnvironmentBasis.none
    assert result.profile_fit is ExecutionProfileFit.invalid
    assert result.diagnostics[0].code.value == "execution_route_missing"


def test_analytical_contract_is_explicit_and_has_no_route() -> None:
    contract = SemanticExecutionContract(
        disposition=ExecutionContractDisposition.analytical_only,
        gaps=(
            SemanticExecutionGap(
                code=ExecutionSemanticGapCode.operation_missing,
                detail="No operation was established.",
                evidence_refs=("CF-1",),
            ),
        ),
    )

    profile = _target_profile()
    result = classify_scenario_execution(contract, _outcome(), profile)

    assert contract.delivery is None
    assert contract.action_kind is None
    assert contract.requested_environment_basis is None
    assert result.binding_completeness is BindingCompleteness.analytical_only
    assert result.diagnostics[0].code.value == "execution_route_missing"
    assert result.target_profile_digest == profile.semantic_digest


def test_profile_and_contract_ordering_is_canonical() -> None:
    contract = _tool_contract()
    profile = _target_profile()
    reordered_profile = _profile_update(
        profile, resources=tuple(reversed(profile.resources))
    )
    reordered_contract = SemanticExecutionContract.model_validate(
        contract.model_dump(mode="json", exclude={"semantic_digest"})
        | {"resource_requirements": tuple(reversed(contract.resource_requirements))}
    )

    assert reordered_profile.semantic_digest == profile.semantic_digest
    assert reordered_contract.semantic_digest == contract.semantic_digest
    assert classify_scenario_execution(
        contract, _outcome(), profile
    ) == classify_scenario_execution(reordered_contract, _outcome(), reordered_profile)


def test_interface_json_freezing_covers_nested_and_rejected_values() -> None:
    assert _freeze_json({"nested": [1, {"enabled": True}], "empty": None}) == {
        "nested": [1, {"enabled": True}],
        "empty": None,
    }
    assert _freeze_json("scalar") == "scalar"
    with pytest.raises(TypeError, match="mapping keys"):
        _freeze_json({1: "not-json"})
    with pytest.raises(TypeError, match="only JSON values"):
        _freeze_json(object())
    with pytest.raises(ValueError, match="NaN"):
        _freeze_json(float("nan"))


def test_stimulus_delivery_rejects_missing_and_mismatched_routes() -> None:
    delivery = SemanticExecutionDelivery(
        delivery_class=ExecutionDeliveryClass.indirect_content,
        factor_id="CF-1",
        source_role="attacker_influenced_content",
        carrier_requirement_id="REQ-1",
    )
    item = AdversarialStimulusRequirement(
        stimulus_id="STIM-1",
        intent="deliver content",
        desired_effect="reach context",
        delivery_class=ExecutionDeliveryClass.indirect_content,
        factor_id="CF-1",
        source_role="attacker_influenced_content",
        carrier_requirement_id="REQ-1",
    )
    _validate_stimulus_delivery(item, delivery)
    with pytest.raises(ValueError, match="execution delivery"):
        _validate_stimulus_delivery(item, None)
    with pytest.raises(ValueError, match="match"):
        _validate_stimulus_delivery(
            item.model_copy(update={"source_role": "other_source"}), delivery
        )


def test_assembled_environment_basis_checks_only_complete_routes() -> None:
    direct = _direct_contract()
    analytical = SemanticExecutionContract(
        disposition=ExecutionContractDisposition.analytical_only,
        gaps=(
            SemanticExecutionGap(
                code=ExecutionSemanticGapCode.operation_missing,
                detail="No operation was established.",
                evidence_refs=("CF-1",),
            ),
        ),
    )
    _validate_assembled_environment_basis(direct, None)
    _validate_assembled_environment_basis(
        analytical, RequestedEnvironmentBasis.target_profile
    )
    _validate_assembled_environment_basis(
        direct, RequestedEnvironmentBasis.target_agnostic
    )
    _validate_assembled_environment_basis(
        _tool_contract(), RequestedEnvironmentBasis.target_profile
    )
    with pytest.raises(ValueError, match="does not match"):
        _validate_assembled_environment_basis(
            _tool_contract(), RequestedEnvironmentBasis.simulation_profile
        )


def test_reviewed_resource_requires_evidence() -> None:
    resource = _target_profile().resources[0]
    payload = resource.model_dump(mode="python")
    payload["evidence_refs"] = ()
    with pytest.raises(ValueError, match="evidence_refs"):
        TargetProfileResource(**payload)


def test_profile_surface_constraints_are_required_for_matching() -> None:
    contract = _tool_contract()
    requirement = contract.resource_requirements[0].model_copy(
        update={"required_surfaces": (ExecutionSurface.user_input,)}
    )
    contract = SemanticExecutionContract.model_validate(
        contract.model_dump(mode="python", exclude={"semantic_digest"})
        | {"resource_requirements": (requirement,)}
    )
    result = classify_scenario_execution(
        contract,
        _outcome(),
        _target_profile(),
    )

    assert result.profile_fit is ExecutionProfileFit.needs_binding
    assert result.unresolved_requirement_ids == ("REQ-1",)


def test_resource_requirement_requires_one_semantic_surface() -> None:
    payload = _tool_contract().resource_requirements[0].model_dump(mode="python")
    payload.pop("required_surfaces")

    with pytest.raises(ValueError, match="required_surfaces"):
        SemanticExecutionContract(
            requested_environment_basis=RequestedEnvironmentBasis.target_profile,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.indirect_content,
                factor_id="CF-1",
                source_role="attacker_influenced_content",
                carrier_requirement_id="REQ-1",
            ),
            action_kind=ExecutionActionKind.model_output,
            resource_requirements=(payload,),
        )
