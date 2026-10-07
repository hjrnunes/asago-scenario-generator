"""Acceptance handlers for the execution environment-basis correction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import (
    _feature_state,
    World,
)

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    ExecutionActionKind,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionSurface,
    ExecutionTargetProfile,
    DiscoveryProvenance,
    InventoryAuthority,
    InventoryCompleteness,
    McpToolObservation,
    ProfileBasis,
    RequestedEnvironmentBasis,
    McpInventoryObservation,
    SemanticAuthority,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SimulationBehavior,
    SourceProtocol,
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetProfileOperation,
    TargetProfileResource,
    TargetSemanticInterpretation,
    TargetStateEffect,
    ExecutionResourceRequirement,
    InterpreterVerifierAgreement,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    resolve_contract_environment_request,
)
from registry import StepTable

step = StepTable()


FEATURE_ID = "stpa_execution_environment_basis"

_ROOT = Path(PROJECT_ROOT)
_PROMPTS = (
    _ROOT / "src" / "asago_scenario_generator" / "stpa" / "system_model" / "prompts"
)


def _state(world: World) -> dict[str, Any]:
    return _feature_state(world, "execution_basis_state")


def _requested(value: str) -> RequestedEnvironmentBasis | None:
    """Translate the feature's explicit omission marker to ``None``."""
    if value == "omitted":
        return None
    return RequestedEnvironmentBasis(value)


def _requirement(purpose: ExecutionResourcePurpose) -> ExecutionResourceRequirement:
    """Build one exact semantic requirement for the requested resource role."""
    common = {
        "factor_id": "CF-1",
        "late_bindable": True,
        "evidence_refs": ("CF-1",),
    }
    if purpose is ExecutionResourcePurpose.agent_channel:
        return ExecutionResourceRequirement(
            requirement_id="REQ-agent-channel",
            purpose=purpose,
            owner_ref="RESP-1",
            acceptable_resource_kinds=(ExecutionResourceKind.agent_channel,),
            role_id="agent_message",
            operation="deliver_agent_message",
            required_surfaces=(ExecutionSurface.agent_message,),
            required_properties=("agent_message_observable",),
            required_attacker_influence=AttackerInfluence.direct,
            **common,
        )
    if purpose is ExecutionResourcePurpose.stimulus_carrier:
        return ExecutionResourceRequirement(
            requirement_id="REQ-carrier",
            purpose=purpose,
            owner_ref="PM-1-1",
            acceptable_resource_kinds=(
                ExecutionResourceKind.integration,
                ExecutionResourceKind.tool,
            ),
            role_id="attacker_influenced_content_source",
            operation="retrieve_content",
            required_surfaces=(ExecutionSurface.tool_result,),
            required_properties=("content_reaches_model_context",),
            required_attacker_influence=AttackerInfluence.indirect,
            **common,
        )
    if purpose is ExecutionResourcePurpose.state_resource:
        return ExecutionResourceRequirement(
            requirement_id="REQ-state",
            purpose=purpose,
            owner_ref="PM-1-1",
            acceptable_resource_kinds=(ExecutionResourceKind.state_store,),
            role_id="unsafe_state",
            operation="read_unsafe_state",
            required_surfaces=(ExecutionSurface.state_observation,),
            required_properties=("unsafe_state_observable",),
            required_attacker_influence=AttackerInfluence.none,
            **common,
        )
    return ExecutionResourceRequirement(
        requirement_id="REQ-target-action",
        purpose=purpose,
        owner_ref="CA-1-1",
        acceptable_resource_kinds=(
            ExecutionResourceKind.integration,
            ExecutionResourceKind.tool,
        ),
        role_id="target_control_action",
        operation="CA-1-1",
        required_surfaces=(ExecutionSurface.tool_call,),
        required_attacker_influence=AttackerInfluence.none,
        **common,
    )


def _contract(
    kind: str,
    requested: RequestedEnvironmentBasis | None = None,
) -> SemanticExecutionContract:
    """Build one valid contract with the named semantic resource role."""
    if kind == "agent_message":
        action = ExecutionActionKind.agent_message
        delivery = ExecutionDeliveryClass.conversation_context
        purpose = ExecutionResourcePurpose.agent_channel
        source_role = "conversation_context"
    elif kind == "indirect_content":
        action = ExecutionActionKind.model_output
        delivery = ExecutionDeliveryClass.indirect_content
        purpose = ExecutionResourcePurpose.stimulus_carrier
        source_role = "attacker_influenced_content"
    else:
        action = ExecutionActionKind(kind)
        delivery = ExecutionDeliveryClass.direct_prompt
        purpose = ExecutionResourcePurpose.target_action
        source_role = "direct_user_input"
    requirement = _requirement(purpose)
    return SemanticExecutionContract(
        requested_environment_basis=requested,
        delivery=SemanticExecutionDelivery(
            delivery_class=delivery,
            factor_id="CF-1",
            source_role=source_role,
            carrier_requirement_id=(
                requirement.requirement_id
                if purpose is ExecutionResourcePurpose.stimulus_carrier
                else None
            ),
        ),
        action_kind=action,
        resource_requirements=(requirement,),
    )


def _profile(profile_basis: str) -> ExecutionTargetProfile:
    """Build a reviewed target or explicit simulation profile for one route."""
    basis = (
        ProfileBasis.simulation
        if profile_basis == "simulation"
        else ProfileBasis.target
    )
    if basis is ProfileBasis.simulation:
        resource = TargetProfileResource(
            resource_id="agent-channel-1",
            resource_kind=ExecutionResourceKind.agent_channel,
            role_ids=("agent_message",),
            structural_refs=("RESP-1",),
            attacker_influence=AttackerInfluence.direct,
            surfaces=(ExecutionSurface.agent_message,),
            operations=(
                TargetProfileOperation(
                    operation_id="deliver-1",
                    semantic_operation="deliver_agent_message",
                    observable_properties=("agent_message_observable",),
                ),
            ),
            evidence_refs=("review:agent-channel",),
            simulation_behavior=SimulationBehavior(
                inputs={"message": "fixture"},
                outputs={"agent_message_observable": True},
                observation_points=("agent_channel",),
            ),
        )
        return ExecutionTargetProfile(
            target_id="simulation-target",
            authorization_scope_id="simulation-scope",
            basis=basis,
            source_protocol=SourceProtocol.simulation,
            semantic_authority=SemanticAuthority.reviewed,
            inventory_completeness=InventoryCompleteness.unknown,
            resources=(resource,),
        )

    target_id = "target"
    tool_name = "deliver_agent_message"
    resource_id = f"mcp:{target_id}:{tool_name}"
    input_schema = {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
    }
    output_schema = {
        "type": "object",
        "properties": {"agent_message_observable": {"type": "boolean"}},
    }
    tool = McpToolObservation(
        name=tool_name,
        source_observation_sha256=(
            "15585938bfaaeaea7044265646d4bda1b81d6eb342a4c3d16272071d59999376"
        ),
        title="Agent message",
        description="Deliver one message to the agent channel.",
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=None,
    )
    inventory = McpInventoryObservation(
        target_id=target_id,
        authorization_scope_id="target-scope",
        tools=(tool,),
    )
    resource = TargetProfileResource(
        resource_id=resource_id,
        resource_kind=ExecutionResourceKind.tool,
        target_id=target_id,
        tool_name=tool_name,
        title=tool.title,
        description=tool.description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=None,
        argument_names=tool.argument_names,
        surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
        role_ids=("agent_message",),
        structural_refs=("RESP-1",),
        attacker_influence=AttackerInfluence.direct,
        operations=(
            TargetProfileOperation(
                operation_id=tool_name,
                semantic_operation=tool_name,
                argument_names=tool.argument_names,
                observable_properties=("agent_message_observable",),
            ),
        ),
        evidence_refs=("inventory:tool:deliver_agent_message",),
    )
    interpretation = TargetSemanticInterpretation(
        resource_id=resource_id,
        tool_name=tool_name,
        disposition=TargetInterpretationDisposition.supported,
        likely_effect=TargetOperationEffect.execute,
        likely_state_effect=TargetStateEffect.none,
        semantic_roles=("agent_message",),
        evidence_refs=("inventory:tool:deliver_agent_message",),
        rationale="The exact tool description exposes the agent-message route.",
        interpreter_verifier_agreement=InterpreterVerifierAgreement.agree,
    )
    return ExecutionTargetProfile(
        target_id=target_id,
        authorization_scope_id="target-scope",
        basis=basis,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.reviewed,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="acceptance-scanner",
            interpreter_id="acceptance-interpreter",
            verifier_id="acceptance-verifier",
        ),
        inventory=inventory,
        resources=(resource,),
        interpretations=(interpretation,),
    )


@step(r"^the execution environment-basis acceptance context is available$")
def _h_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Initialize feature state."""
    del text, examples
    _state(world).clear()
    return True, ""


@step(r'^a "[^"]+" domain requirement set$')
def _h_requirements(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture the pure resolver input shape."""
    del examples
    match = re.search(r'^a "([^"]+)" domain requirement set$', text)
    if match is None:
        return False, f"Could not parse requirement set: {text}"
    state = _state(world)
    state["requirements"] = (
        ()
        if match.group(1) == "none"
        else (_requirement(ExecutionResourcePurpose.agent_channel),)
    )
    return True, ""


@step(r'^the contract environment request resolves a "[^"]+" request$')
def _h_resolve(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Resolve one environment request through the producer seam."""
    del examples
    match = re.search(
        r'^the contract environment request resolves a "([^"]+)" request$', text
    )
    if match is None:
        return False, f"Could not parse requested basis: {text}"

    state = _state(world)
    try:
        state["resolved"] = resolve_contract_environment_request(
            state.get("requirements", ()), _requested(match.group(1))
        )
        state["resolve_error"] = None
    except (TypeError, ValueError) as exc:
        state["resolved"] = None
        state["resolve_error"] = exc
    return True, ""


@step(r'^the resolved contract environment request is "[^"]+"$')
def _h_resolved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the pure resolver result."""
    del examples
    match = re.search(r'^the resolved contract environment request is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse expected basis: {text}"
    state = _state(world)
    if state.get("resolve_error") is not None:
        return False, f"resolver failed: {state['resolve_error']}"
    actual = state.get("resolved")
    actual_value = actual.value if actual is not None else "omitted"
    expected = match.group(1)
    return actual_value == expected, f"expected {expected}, got {actual_value}"


@step(r"^resolving the contract environment request is rejected$")
def _h_resolve_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert an invalid target-agnostic/resource combination is rejected."""
    del text, examples
    error = _state(world).get("resolve_error")
    return error is not None, "resource-bearing target_agnostic request was accepted"


@step(
    r"^a resource-bearing agent-message contract with an omitted environment request$"
)
def _h_agent_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Create an omitted resource-bearing contract."""
    del text, examples
    _state(world)["contract"] = _contract("agent_message")
    return True, ""


@step(r"^the Stage 2 action-semantics prompts and critic prompt are inspected$")
def _h_prompts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Read the Stage 2 action and critic prompts for deterministic checks."""
    del text, examples
    paths = (
        _PROMPTS / "stage2_call2b_system.j2",
        _PROMPTS / "stage2_call2b_user.j2",
        _PROMPTS / "critic_system.j2",
    )
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        return False, f"prompt files are missing: {missing}"
    _state(world)["prompt_text"] = "\n".join(
        path.read_text(encoding="utf-8") for path in paths
    )
    return True, ""


@step(r"^Stage 2 defines all five action kinds by typed meaning$")
def _h_action_definitions(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check all five typed action meanings are stated in the prompt."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    required = {
        "model_output": ("returned by the tested model", "tested model or agent"),
        "tool_call": ("structured invocation",),
        "state_change": ("session or persistent state",),
        "agent_message": ("internal message",),
        "environment_action": ("external side effect",),
    }
    missing = [
        name
        for name, alternatives in required.items()
        if name not in corpus or not any(item in corpus for item in alternatives)
    ]
    return not missing, f"typed action definitions are missing: {missing}"


@step(r"^Stage 2 gives domain-neutral examples for all five action kinds$")
def _h_action_examples(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the five domain-neutral action-kind contrasts."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    alternatives = (
        ("advice to a user", "returning advice"),
        ("loan-renewal invocation", "structured loan-renewal"),
        ("session record", "updating a session"),
        ("risk flag", "sending a risk"),
        ("physical alarm", "activating a physical"),
    )
    missing = [
        items[0] for items in alternatives if not any(item in corpus for item in items)
    ]
    return not missing, f"domain-neutral examples are missing: {missing}"


@step(r"^the critic prompt names a typed action-effect conflict as an explicit gap$")
def _h_critic_gap(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the critic asks for an explicit typed effect conflict gap."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    required = ("typed", "effect", "conflict", "gap")
    missing = [item for item in required if item not in corpus]
    return not missing, f"critic prompt lacks typed conflict guidance: {missing}"


@step(r'^a control action whose description says "[^"]+"$')
def _h_typed_action(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Build the intentionally prose-conflicting typed control action."""
    del text, examples
    action = ControlAction(
        ca_id="CA-1-1",
        description="Return advice to a user",
        target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
        effect_kind=ControlActionEffectKind.environment_action,
        temporality=ControlActionTemporality.instantaneous,
    )
    _state(world)["typed_action"] = action
    return True, ""


@step(r'^whose typed effect kind is "[^"]+"$')
def _h_typed_effect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the feature's declared typed effect before validation."""
    del examples
    match = re.search(r'^whose typed effect kind is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse typed effect: {text}"
    action = _state(world).get("typed_action")
    actual = action.effect_kind.value if action and action.effect_kind else None
    expected = match.group(1)
    return actual == expected, f"expected typed effect {expected}, got {actual}"


@step(r"^the control action semantics are validated$")
def _h_typed_action_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Re-validate the action and ensure prose did not rewrite its effect."""
    del text, examples
    action = _state(world).get("typed_action")
    if action is None:
        return False, "typed action is unavailable"
    validated = ControlAction.model_validate(action.model_dump(mode="python"))
    _state(world)["typed_action"] = validated
    return True, ""


@step(r'^its typed effect kind remains "[^"]+"$')
def _h_typed_action_remains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the explicit typed effect remains authoritative."""
    del examples
    match = re.search(r'^its typed effect kind remains "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse effect expectation: {text}"
    action = _state(world).get("typed_action")
    actual = action.effect_kind.value if action and action.effect_kind else None
    expected = match.group(1)
    return actual == expected, f"expected {expected}, got {actual}"


@step(r"^the unresolved contract is serialized as canonical JSON$")
def _h_serialize_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Serialize the unresolved contract through ordinary JSON."""
    del text, examples
    contract = _state(world).get("contract")
    if contract is None:
        return False, "no unresolved contract is available"
    _state(world)["wire"] = json.loads(contract.model_dump_json())
    return True, ""


@step(r"^standard JSON tooling parses a null requested environment basis$")
def _h_wire_null(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the portable wire form carries a JSON null request."""
    del text, examples
    wire = _state(world).get("wire")
    return (
        wire is not None and wire.get("requested_environment_basis") is None,
        "wire contract did not contain a null requested_environment_basis",
    )


@step(r'^the portable contract retains the "[^"]+" requirement$')
def _h_wire_agent_channel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the portable wire form retains semantic agent-channel identity."""
    del examples
    match = re.search(
        r'^the portable contract retains the "([^"]+)" requirement$', text
    )
    if match is None:
        return False, f"Could not parse requirement expectation: {text}"
    wire = _state(world).get("wire") or {}
    actual = [item.get("purpose") for item in wire.get("resource_requirements", ())]
    expected = match.group(1)
    return expected in actual, f"expected {expected} in {actual}"


register = step.register


__all__ = ["FEATURE_ID", "register"]
