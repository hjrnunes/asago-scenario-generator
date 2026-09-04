"""Acceptance handlers for the execution environment-basis correction."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import (
    World,
    _make_sp3_cs,
    _make_sp3_loss_analysis,
    _make_sp3_threat,
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
    InventoryCompleteness,
    ProfileAuthority,
    ProfileBasis,
    RequestedEnvironmentBasis,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SimulationBehavior,
    TargetProfileOperation,
    TargetProfileResource,
    ExecutionResourceRequirement,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    UnsafeOutcome,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionPresenceCondition,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    classify_scenario_execution,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlStructure,
)
from tests.stpa.sp1_helpers import MockLLMClient


FEATURE_ID = "stpa_execution_environment_basis"

_ROOT = Path(PROJECT_ROOT)
_PROMPTS = (
    _ROOT / "src" / "asago_scenario_generator" / "stpa" / "system_model" / "prompts"
)


def _state(world: World) -> dict[str, Any]:
    """Return the per-scenario state for this feature."""
    state = getattr(world, "execution_basis_state", None)
    if state is None:
        state = {}
        world.execution_basis_state = state
    return state


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


def _outcome() -> UnsafeOutcome:
    """Build the minimal unsafe outcome accepted by the classifier."""
    return UnsafeOutcome(
        outcome_id="OUTCOME-1",
        control_action_id="CA-1-1",
        uca_type=UCAType.not_provided,
        condition=ActionPresenceCondition(
            control_action_id="CA-1-1", expected="not_provided"
        ),
        semantic_binding_required=False,
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


def _resource_free_contract() -> SemanticExecutionContract:
    """Build the resource-free model-output contract."""
    return SemanticExecutionContract(
        requested_environment_basis=None,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.direct_prompt,
            factor_id="CF-1",
            source_role="direct_user_input",
        ),
        action_kind=ExecutionActionKind.model_output,
    )


def _profile(profile_basis: str) -> ExecutionTargetProfile:
    """Build a reviewed profile that exactly matches an agent-channel role."""
    basis = (
        ProfileBasis.simulation
        if profile_basis == "simulation"
        else ProfileBasis.target
    )
    behavior = (
        SimulationBehavior(
            inputs={"message": "fixture"},
            outputs={"agent_message_observable": True},
            observation_points=("agent_channel",),
        )
        if basis is ProfileBasis.simulation
        else None
    )
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
        simulation_behavior=behavior,
    )
    return ExecutionTargetProfile(
        profile_id=f"{profile_basis}-profile",
        environment_id=f"{profile_basis}-environment",
        basis=basis,
        authority=ProfileAuthority.reviewed,
        inventory_completeness=InventoryCompleteness.reviewed_complete,
        evidence_refs=("review:environment",),
        resources=(resource,),
    )


def _stage5_payload(delivery: str, action: str) -> dict[str, Any]:
    """Build a closed provider response for one Stage 5 route."""
    stimulus = {
        "direct_prompt": "user_message",
        "conversation_context": "conversation",
        "indirect_content": "retrieved_content",
    }[delivery]
    return {
        "stimulus": {
            "category": stimulus,
            "description": "The supplied stimulus exercises the selected factor.",
        },
        "defender_vulnerabilities": [
            {
                "belief_handle": "belief_1",
                "vulnerability": "The selected belief can be stale.",
            },
            {
                "belief_handle": "belief_2",
                "vulnerability": "The selected schema belief can be stale.",
            },
        ],
        "attacker_bdi": {
            "beliefs": ["The controller can act on stale state."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the selected structural condition.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected structural condition can remain stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_presence",
                "control_action_id": "CA-1-1",
                "expected": "not_provided",
            },
            "hazard_refs": [],
            "constraint_refs": [],
        },
        "execution_route": {
            "disposition": "executable_route",
            "delivery_class": delivery,
            "selected_factor_handle": "cause_1",
            "action_kind": action,
            "reason": "The supplied structural evidence supports this route.",
        },
    }


def _stage5_context(action: str):
    """Build a context whose typed action semantics match the provider route."""
    structure_payload = _make_sp3_cs(include_resp2=True).model_dump(mode="json")
    control_action = structure_payload["responsibilities"][0]["control_actions"][0]
    control_action["temporality"] = "instantaneous"
    if action == "agent_message":
        control_action["target"] = {"type": "responsibility", "id": "RESP-2"}
        control_action["effect_kind"] = "agent_message"
    else:
        control_action["effect_kind"] = action
    structure = ControlStructure.model_validate(structure_payload)
    return build_scenario_generation_context(
        _make_sp3_threat(),
        structure,
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )


def _h_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Initialize feature state."""
    del text, examples
    _state(world).clear()
    return True, ""


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


def _h_resolve(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Resolve one environment request through the producer seam."""
    del examples
    match = re.search(
        r'^the contract environment request resolves a "([^"]+)" request$', text
    )
    if match is None:
        return False, f"Could not parse requested basis: {text}"
    from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
        resolve_contract_environment_request,
    )

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


def _h_resolve_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert an invalid target-agnostic/resource combination is rejected."""
    del text, examples
    error = _state(world).get("resolve_error")
    return error is not None, "resource-bearing target_agnostic request was accepted"


def _h_agent_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Create an omitted resource-bearing contract."""
    del text, examples
    _state(world)["contract"] = _contract("agent_message")
    return True, ""


def _h_contract_validate_classify(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Validate and classify the unresolved contract without a profile."""
    del text, examples
    state = _state(world)
    contract = state.get("contract")
    try:
        state["classification"] = classify_scenario_execution(
            contract, _outcome(), None
        )
        state["contract_error"] = None
    except (TypeError, ValueError) as exc:
        state["contract_error"] = exc
    return True, ""


def _h_contract_basis_null(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the contract preserves the omitted basis as null."""
    del text, examples
    state = _state(world)
    contract = state.get("contract")
    if contract is None:
        return False, "no contract was constructed"
    return (
        contract.requested_environment_basis is None,
        "resource-bearing contract did not retain a null request",
    )


def _h_axes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the four independent classification dimensions."""
    del examples
    match = re.search(r'^the classification axes are "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse axes: {text}"
    state = _state(world)
    result = state.get("classification")
    if result is None:
        return False, f"classification unavailable: {state.get('contract_error')}"
    actual = "/".join(
        (
            result.binding_completeness.value,
            result.environment_basis.value,
            result.profile_fit.value,
            result.claim_scope.value,
        )
    )
    expected = match.group(1)
    return actual == expected, f"expected {expected}, got {actual}"


def _h_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the first deterministic classification diagnostic code."""
    del examples
    match = re.search(r'^the classification diagnostic is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse diagnostic: {text}"
    result = _state(world).get("classification")
    if result is None:
        return False, "classification unavailable"
    actual = result.diagnostics[0].code.value if result.diagnostics else None
    expected = match.group(1)
    return actual == expected, f"expected {expected}, got {actual}"


def _h_stage5_route(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture an offline route for corrected contextual Stage 5."""
    del examples
    match = re.search(
        r'^an offline Stage 5 "([^"]+)" route with action "([^"]+)"$', text
    )
    if match is None:
        return False, f"Could not parse Stage 5 route: {text}"
    delivery, action = match.groups()
    state = _state(world)
    state["stage5_context"] = _stage5_context(action)
    state["stage5_action"] = action
    state["stage5_delivery"] = delivery
    state["stage5_payload"] = _stage5_payload(delivery, action)
    return True, ""


def _h_stage5_materialize(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run Stage 5 with an explicitly omitted basis."""
    del text, examples
    state = _state(world)
    client = MockLLMClient()
    payload = state["stage5_payload"]
    client.set_response_queue([payload, payload])
    state["stage5_result"], state["stage5_error"] = generate_bdi_for_context(
        client,
        state["stage5_context"],
        Path(tempfile.mkdtemp(prefix="asago-basis-stage5-")),
        requested_environment_basis=None,
    )
    return True, ""


def _h_stage5_basis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert Stage 5's materialized contract basis."""
    del examples
    match = re.search(r'^the Stage 5 execution contract basis is "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse Stage 5 basis: {text}"
    result = _state(world).get("stage5_result")
    if result is None or result.execution_contract is None:
        return False, f"Stage 5 failed: {_state(world).get('stage5_error')}"
    actual = result.execution_contract.requested_environment_basis
    actual_value = actual.value if actual is not None else "omitted"
    expected = match.group(1)
    return actual_value == expected, f"expected {expected}, got {actual_value}"


def _h_stage5_requirements(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert Stage 5's domain-resource purposes."""
    del examples
    match = re.search(r'^the Stage 5 contract has domain requirements "([^"]+)"$', text)
    if match is None:
        return False, f"Could not parse Stage 5 requirements: {text}"
    result = _state(world).get("stage5_result")
    if result is None or result.execution_contract is None:
        return False, "Stage 5 did not produce a contract"
    actual = ",".join(
        item.purpose.value for item in result.execution_contract.resource_requirements
    )
    expected = "" if match.group(1) == "none" else match.group(1)
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_executable_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture one direct or domain-resource contract for classification."""
    del examples
    match = re.search(
        r'^an executable "([^"]+)" contract with one domain requirement$', text
    )
    if match is None:
        return False, f"Could not parse contract kind: {text}"
    _state(world)["contract"] = _contract(match.group(1))
    return True, ""


def _h_explicit_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture a contract with an explicit target or simulation request."""
    del examples
    match = re.search(
        r'^an executable agent-message contract requesting "([^"]+)"$', text
    )
    if match is None:
        return False, f"Could not parse explicit basis: {text}"
    _state(world)["contract"] = _contract("agent_message", _requested(match.group(1)))
    return True, ""


def _h_classify_no_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Classify the current contract without a selected profile."""
    return _h_contract_validate_classify(world, text, examples)


def _h_profile_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture an omitted agent-message contract for profile binding."""
    del text, examples
    _state(world)["contract"] = _contract("agent_message")
    return True, ""


def _h_profile_classify(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Classify against an exact reviewed target or simulation profile."""
    del examples
    match = re.search(
        r'^the contract is classified with a reviewed "([^"]+)" profile$', text
    )
    if match is None:
        return False, f"Could not parse profile kind: {text}"
    state = _state(world)
    state["profile"] = _profile(match.group(1))
    state["classification"] = classify_scenario_execution(
        state["contract"], _outcome(), state["profile"]
    )
    return True, ""


def _h_profile_digest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the selected profile's content address is retained."""
    del text, examples
    state = _state(world)
    result = state.get("classification")
    profile = state.get("profile")
    if result is None or profile is None:
        return False, "profile classification is unavailable"
    return (
        result.target_profile_digest == profile.semantic_digest,
        "classification did not pin the selected profile digest",
    )


def _h_resource_free(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Capture a resource-free model-output contract."""
    del text, examples
    _state(world)["contract"] = _resource_free_contract()
    return True, ""


def _target_profile_without_resources() -> ExecutionTargetProfile:
    """Build a profile that must not affect a resource-free classification."""
    return ExecutionTargetProfile(
        profile_id="global-target",
        environment_id="global-target",
        basis=ProfileBasis.target,
        authority=ProfileAuthority.reviewed,
        inventory_completeness=InventoryCompleteness.reviewed_complete,
        evidence_refs=("review:global",),
        resources=(),
    )


def _h_resource_free_classify(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Classify a resource-free contract with an irrelevant global profile."""
    del text, examples
    state = _state(world)
    state["profile"] = _target_profile_without_resources()
    state["classification"] = classify_scenario_execution(
        state["contract"], _outcome(), state["profile"]
    )
    return True, ""


def _h_no_profile_digest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert a resource-free result does not pin an irrelevant profile."""
    del text, examples
    result = _state(world).get("classification")
    if result is None:
        return False, "classification is unavailable"
    return (
        result.target_profile_digest is None,
        "resource-free classification pinned a profile digest",
    )


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


def _h_action_examples(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the five domain-neutral action-kind contrasts."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    alternatives = (
        ("advice to a user", "returning advice"),
        ("refund invocation", "structured refund"),
        ("session record", "updating a session"),
        ("risk flag", "sending a risk"),
        ("physical alarm", "activating a physical"),
    )
    missing = [
        items[0] for items in alternatives if not any(item in corpus for item in items)
    ]
    return not missing, f"domain-neutral examples are missing: {missing}"


def _h_critic_gap(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the critic asks for an explicit typed effect conflict gap."""
    del text, examples
    corpus = _state(world).get("prompt_text", "").lower()
    required = ("typed", "effect", "conflict", "gap")
    missing = [item for item in required if item not in corpus]
    return not missing, f"critic prompt lacks typed conflict guidance: {missing}"


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


def _h_serialize_contract(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Serialize the unresolved contract through ordinary JSON."""
    del text, examples
    contract = _state(world).get("contract")
    if contract is None:
        return False, "no unresolved contract is available"
    _state(world)["wire"] = json.loads(contract.model_dump_json())
    return True, ""


def _h_wire_null(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert the portable wire form carries a JSON null request."""
    del text, examples
    wire = _state(world).get("wire")
    return (
        wire is not None and wire.get("requested_environment_basis") is None,
        "wire contract did not contain a null requested_environment_basis",
    )


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


def register(api: object) -> None:
    """Register execution environment-basis acceptance steps."""
    api.register(
        r"^the execution environment-basis acceptance context is available$",
        _h_available,
    )
    api.register(r'^a "[^"]+" domain requirement set$', _h_requirements)
    api.register(
        r'^the contract environment request resolves a "[^"]+" request$',
        _h_resolve,
    )
    api.register(
        r'^the resolved contract environment request is "[^"]+"$',
        _h_resolved,
    )
    api.register(
        r"^resolving the contract environment request is rejected$",
        _h_resolve_rejected,
    )
    api.register(
        r"^a resource-bearing agent-message contract with an omitted environment request$",
        _h_agent_contract,
    )
    api.register(
        r"^the unresolved contract is validated and classified without a profile$",
        _h_contract_validate_classify,
    )
    api.register(
        r"^the contract requested environment basis is null$", _h_contract_basis_null
    )
    api.register(r'^the classification axes are "[^"]+"$', _h_axes)
    api.register(r'^the classification diagnostic is "[^"]+"$', _h_diagnostic)
    api.register(
        r'^an offline Stage 5 "[^"]+" route with action "[^"]+"$',
        _h_stage5_route,
    )
    api.register(
        r"^Stage 5 materializes the route with an omitted basis$",
        _h_stage5_materialize,
    )
    api.register(r'^the Stage 5 execution contract basis is "[^"]+"$', _h_stage5_basis)
    api.register(
        r'^the Stage 5 contract has domain requirements "[^"]+"$',
        _h_stage5_requirements,
    )
    api.register(
        r'^an executable "[^"]+" contract with one domain requirement$',
        _h_executable_contract,
    )
    api.register(
        r"^the contract is classified without a profile$",
        _h_classify_no_profile,
    )
    api.register(
        r'^an executable agent-message contract requesting "[^"]+"$',
        _h_explicit_contract,
    )
    api.register(
        r"^an executable agent-message contract with an omitted environment request$",
        _h_profile_contract,
    )
    api.register(
        r'^the contract is classified with a reviewed "[^"]+" profile$',
        _h_profile_classify,
    )
    api.register(
        r"^the selected profile digest is pinned in the classification$",
        _h_profile_digest,
    )
    api.register(r"^a resource-free model-output contract$", _h_resource_free)
    api.register(
        r"^the contract is classified with a reviewed target profile$",
        _h_resource_free_classify,
    )
    api.register(
        r"^no selected profile digest is pinned in the classification$",
        _h_no_profile_digest,
    )
    api.register(
        r"^the Stage 2 action-semantics prompts and critic prompt are inspected$",
        _h_prompts,
    )
    api.register(
        r"^Stage 2 defines all five action kinds by typed meaning$",
        _h_action_definitions,
    )
    api.register(
        r"^Stage 2 gives domain-neutral examples for all five action kinds$",
        _h_action_examples,
    )
    api.register(
        r"^the critic prompt names a typed action-effect conflict as an explicit gap$",
        _h_critic_gap,
    )
    api.register(
        r'^a control action whose description says "[^"]+"$',
        _h_typed_action,
    )
    api.register(
        r'^whose typed effect kind is "[^"]+"$',
        _h_typed_effect,
    )
    api.register(
        r"^the control action semantics are validated$",
        _h_typed_action_validated,
    )
    api.register(
        r'^its typed effect kind remains "[^"]+"$',
        _h_typed_action_remains,
    )
    api.register(
        r"^the unresolved contract is serialized as canonical JSON$",
        _h_serialize_contract,
    )
    api.register(
        r"^standard JSON tooling parses a null requested environment basis$",
        _h_wire_null,
    )
    api.register(
        r'^the portable contract retains the "[^"]+" requirement$',
        _h_wire_agent_channel,
    )


__all__ = ["FEATURE_ID", "register"]
