"""Tests for STPA execution contracts, target profiles, and environment bases."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionContractDisposition,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionSemanticGapCode,
    ExecutionTargetProfile,
    ProfileBasis,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SemanticExecutionGap,
    SimulationBehavior,
    TargetProfileResource,
    _freeze_json,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    resolve_contract_environment_request,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.assemble import (
    _validate_assembled_environment_basis,
)
from tests.stpa.helpers import make_direct_execution_contract
from tests.helpers.execution_classification import _target_profile
from tests.helpers.execution_classification import (
    _simulation_profile,
    _simulation_resource,
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


def test_assembled_environment_basis_checks_only_complete_routes() -> None:
    direct = make_direct_execution_contract()
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


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"basis": "target"}, "require basis=simulation"),
        ({"inventory_authority": "observed"}, "cannot claim observed inventory"),
        ({"source_inventory_digest": "0" * 64}, "source_inventory_digest"),
        (
            {
                "discovery_provenance": {
                    "scanner_id": "s",
                    "interpreter_id": "i",
                    "verifier_id": "v",
                }
            },
            "discovery_provenance",
        ),
        (
            {
                "inventory": {
                    "target_id": "sim-1",
                    "authorization_scope_id": "fixture-scope",
                    "tools": (),
                }
            },
            "cannot carry an MCP inventory",
        ),
        ({"inventory_completeness": "observed_complete"}, "unknown inventory"),
        (
            {
                "interpretations": (
                    {
                        "resource_id": "sim:retrieve-1",
                        "tool_name": "retrieve-1",
                        "disposition": "supported",
                        "evidence_refs": ("simulation:sim:retrieve-1",),
                        "rationale": "fixture interpretation",
                    },
                )
            },
            "cannot carry MCP interpretations",
        ),
    ),
)
def test_simulation_profile_rejects_observed_mcp_claims(
    updates: dict, message: str
) -> None:
    payload = _simulation_profile().model_dump(mode="json", exclude={"semantic_digest"})
    payload.update(updates)
    with pytest.raises(ValueError, match=message):
        ExecutionTargetProfile.model_validate(payload)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"resource_kind": "integration"}, "only valid for tool resources"),
        ({"target_id": None}, "require target_id"),
        ({"surfaces": ("tool_call",)}, "tool_call and tool_result surfaces"),
        ({"tool_name": "retrieve-2"}, "operation_id must equal tool_name"),
        (
            {
                "operations": (
                    {"operation_id": "retrieve-1", "semantic_operation": "x"},
                )
            },
            "semantic_operation must equal",
        ),
        (
            {
                "operations": (
                    {
                        "operation_id": "retrieve-1",
                        "semantic_operation": "retrieve-1",
                        "argument_names": ("query",),
                    },
                )
            },
            "argument_names must match input schema",
        ),
        (
            {
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                "argument_names": ("other",),
            },
            "argument_names must match input_schema properties",
        ),
    ),
)
def test_mcp_profile_resource_rejects_inexact_tool_identity(
    updates: dict, message: str
) -> None:
    payload = _target_profile().resources[0].model_dump(mode="json")
    payload.update(updates)
    with pytest.raises(ValueError, match=message):
        TargetProfileResource.model_validate(payload)


def test_profile_resource_derives_argument_names_from_schema() -> None:
    payload = _simulation_resource().model_dump(mode="json")
    payload["input_schema"] = {
        "type": "object",
        "properties": {"b": {"type": "string"}, "a": {"type": "string"}},
    }
    resource = TargetProfileResource.model_validate(payload)
    assert resource.argument_names == ("a", "b")
    payload["input_schema"] = {"type": "object"}
    payload["argument_names"] = ("z", "y")
    assert TargetProfileResource.model_validate(payload).argument_names == ("y", "z")
