"""Execution-route validation and execution-contract compilation."""

from __future__ import annotations

from collections.abc import Sequence
from pydantic import (
    BaseModel,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    StateValueCondition,
    normalize_semantic_proposition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    ExecutionActionKind,
    ExecutionContractDisposition,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SemanticExecutionGap,
    ExecutionResourceRequirement,
    ExecutionSurface,
    RequestedEnvironmentBasis,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    resolve_contract_environment_request,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from .wire import (
    AnalyticalOnlyRouteSelection,
    StimulusCategory,
    UnsafeOutcomeDeclaration,
    _CausalSourceChoice,
    _ContextExecutableRouteDraft,
    _ContextStimulusDraft,
    _ContextUnsafeOutcomeDraft,
)
from .sources import (
    _DELIVERY_FACTOR_KINDS,
    _causal_source_choices,
    _context_expected_action_kind,
    _stimulus_delivery,
    _typed_control_action_target_kind,
)


_RESPONSIBILITY_TARGET_KIND = "responsibility"


def _validate_stimulus_route(
    route: AnalyticalOnlyRouteSelection | _ContextExecutableRouteDraft,
    stimulus: _ContextStimulusDraft,
) -> ExecutionDeliveryClass | None:
    """Require supported typed stimuli to use their one matching delivery."""
    if isinstance(route, AnalyticalOnlyRouteSelection):
        # An already non-executable finding may have several valid gaps. Do
        # not reject it merely because it records the missing operation before
        # the unsupported delivery; neither conclusion authorizes execution.
        return None
    expected_delivery = _stimulus_delivery(stimulus.category)
    if expected_delivery is None:
        raise ValueError(
            f"stimulus category {stimulus.category.value} has no supported delivery; "
            "use an analytical_only route with delivery_path_missing"
        )
    return ExecutionDeliveryClass(expected_delivery)


def _validate_execution_route(
    route: AnalyticalOnlyRouteSelection | _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
    *,
    stimulus: _ContextStimulusDraft | None = None,
    target_operation: TargetOperationObservation | None = None,
) -> None:
    """Validate provider route choices against one exact request context."""
    declared_handles = _declared_causal_handles(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        _validate_context_route_binding(route, factor_drafts)
        _validate_analytical_route_gaps(route, declared_handles)
        return
    selected_factor_handle, delivery_class = _resolve_route_binding(
        route,
        factor_drafts,
        stimulus,
    )
    _validate_selected_factor_handle(selected_factor_handle, declared_handles)
    _validate_action_kind_against_control_action(
        route,
        context,
        target_operation=target_operation,
    )
    _validate_delivery_factor_fidelity(
        selected_factor_handle,
        delivery_class,
        context,
    )
    _validate_indirect_access_evidence(
        selected_factor_handle, delivery_class, factor_drafts
    )
    _validate_model_output_outcome(route, unsafe_outcome)


def _validate_indirect_access_evidence(
    selected_handle: str,
    delivery_class: str,
    factor_drafts: Sequence[BaseModel],
) -> None:
    """A control-loop failure alone does not establish an indirect ingress."""
    if delivery_class != ExecutionDeliveryClass.indirect_content:
        return
    factor = next(row for row in factor_drafts if row.source_handle == selected_handle)
    if factor.evidence_status == CausalEvidenceStatus.structural_failure:
        raise ValueError(
            "indirect stimulus requires reachable_capability evidence or an explicit "
            "bounded_assumption about the carrier/access path; structural_failure "
            "does not establish attacker control over a tool or retrieval result. "
            "If the authored stimulus is a user request and tool returns are "
            "unchanged background, describe that input instead."
        )


def _context_route_binding_handles(
    factor_drafts: Sequence[BaseModel],
) -> tuple[str, ...]:
    """Return factor handles carrying the one provider route binding."""
    return tuple(
        factor.source_handle
        for factor in factor_drafts
        if getattr(factor, "selected_for_route", False)
    )


def _validate_context_route_binding(
    route: AnalyticalOnlyRouteSelection | _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
) -> str | None:
    """Validate the factor-owned binding cardinality for the context wire."""
    selected = _context_route_binding_handles(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        if selected:
            raise ValueError(
                "analytical_only route must not select a causal factor; "
                "set selected_for_route=false on every factor"
            )
        return None
    if len(selected) != 1:
        raise ValueError(
            "executable route must bind exactly one declared causal factor with "
            "selected_for_route=true"
        )
    return selected[0]


def _resolve_route_binding(
    route: _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
    stimulus: _ContextStimulusDraft | None,
) -> tuple[str, ExecutionDeliveryClass]:
    """Resolve the context factor-owned binding and its stimulus delivery."""
    if stimulus is None:
        raise ValueError("context executable route requires a stimulus")
    delivery_class = _validate_stimulus_route(route, stimulus)
    selected_factor_handle = _validate_context_route_binding(route, factor_drafts)
    if delivery_class is None or selected_factor_handle is None:
        raise ValueError("executable context route is missing its binding")
    return selected_factor_handle, delivery_class


def _validate_delivery_factor_fidelity(
    selected_factor_handle: str,
    delivery_class: ExecutionDeliveryClass,
    context: ScenarioGenerationContext,
) -> None:
    """Require the chosen stimulus route to exercise its selected factor."""
    if not isinstance(selected_factor_handle, str):
        raise TypeError("selected factor handle must be a string")
    if not isinstance(delivery_class, ExecutionDeliveryClass):
        raise TypeError("delivery class must be an ExecutionDeliveryClass")
    kinds = {choice.handle: choice.kind for choice in _causal_source_choices(context)}
    selected_kind = kinds.get(selected_factor_handle)
    if selected_kind in _DELIVERY_FACTOR_KINDS[delivery_class]:
        return
    allowed = ", ".join(
        item.value
        for item in sorted(
            _DELIVERY_FACTOR_KINDS[delivery_class], key=lambda item: item.value
        )
    )
    actual = selected_kind.value if selected_kind is not None else "unknown"
    raise ValueError(
        f"{delivery_class.value} cannot exercise selected factor kind "
        f"{actual}; choose one of [{allowed}] or an analytical route"
    )


def _validate_model_output_outcome(
    route: _ContextExecutableRouteDraft,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Keep model-output judgments semantic instead of deployment-string bound."""
    condition = unsafe_outcome.condition
    if route.action_kind is not ExecutionActionKind.model_output:
        return
    proposition = getattr(unsafe_outcome, "semantic_proposition", None)
    normalize_semantic_proposition(proposition, required=True)
    if getattr(condition, "type", None) != "action_value":
        return
    if not (
        getattr(condition, "property", None) == "semantic_proposition"
        and getattr(condition, "operator", None) == "equals"
        and type(getattr(condition, "expected", None)) is bool
        and getattr(condition, "expected", None) is True
    ):
        raise ValueError(
            "model_output action_value must use the fixed semantic proposition "
            "condition (property=semantic_proposition, operator=equals, expected=true)"
        )


def _declared_causal_handles(factor_drafts: Sequence[BaseModel]) -> set[str]:
    """Return the unique request-local handles declared by provider factors."""
    handles = {item.source_handle for item in factor_drafts}
    if len(handles) != len(factor_drafts):
        raise ValueError("causal factor source handles must be unique")
    return handles


def _validate_analytical_route_gaps(
    route: AnalyticalOnlyRouteSelection,
    declared_handles: set[str],
) -> None:
    """Require analytical gap evidence to refer to declared local factors."""
    for gap in route.gaps:
        if not set(gap.evidence_handles) <= declared_handles:
            raise ValueError(
                "analytical gap evidence handles must name declared causal factors"
            )


def _validate_selected_factor_handle(
    selected_factor_handle: str,
    declared_handles: set[str],
) -> None:
    """Require an executable route to select one declared local factor."""
    if selected_factor_handle not in declared_handles:
        raise ValueError(
            "execution route selected_factor_handle must name a declared causal factor"
        )


def _validate_action_kind_against_control_action(
    route: _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
    *,
    target_operation: TargetOperationObservation | None = None,
) -> None:
    """Validate the provider's action choice against typed action semantics.

    The route schema performs cross-field checks (for example, whether a
    target-action role accompanies ``tool_call``).  That is not enough: an
    action can be internally coherent while observing the wrong effect.  When
    the selected control action carries a typed effect, or the target
    operation attests a tool call, that kind is authoritative.  An action
    without either is not checked.
    """
    expected = _context_expected_action_kind(context, target_operation)
    if expected is None:
        return
    if route.action_kind is not expected:
        raise ValueError(
            "execution route action_kind does not match the selected control "
            f"action's typed effect/target ({expected.value})"
        )


def _required_execution_role_handles(
    route: _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
    *,
    delivery_class: ExecutionDeliveryClass | None = None,
) -> set[str]:
    """Return the role handles required by the chosen action and outcome."""
    roles: set[str] = set()
    if delivery_class is None:
        raise ValueError("context executable route requires its derived delivery class")
    if delivery_class is ExecutionDeliveryClass.indirect_content:
        roles.add("role_stimulus_carrier")
    # Conversation context is a standard runtime surface, not a domain
    # resource.  It therefore contributes no semantic resource requirement.

    if route.action_kind in {
        ExecutionActionKind.tool_call,
        ExecutionActionKind.state_change,
        ExecutionActionKind.environment_action,
    }:
        roles.add("role_target_action")
    if route.action_kind is ExecutionActionKind.agent_message:
        roles.add("role_agent_channel")
    if isinstance(unsafe_outcome.condition, StateValueCondition):
        roles.add("role_state")
    return roles


def _factor_ids_by_handle(factor_drafts: Sequence[BaseModel]) -> dict[str, str]:
    """Assign canonical CF identities in provider declaration order."""
    return {
        item.source_handle: f"CF-{index}"
        for index, item in enumerate(factor_drafts, start=1)
    }


def _materialize_execution_contract(
    route: AnalyticalOnlyRouteSelection | _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
    choices: dict[str, _CausalSourceChoice],
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
    *,
    stimulus: _ContextStimulusDraft | None = None,
    target_operation: TargetOperationObservation | None = None,
) -> SemanticExecutionContract:
    """Resolve provider-local route handles into the semantic contract."""
    factor_ids = _factor_ids_by_handle(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        gaps = tuple(
            SemanticExecutionGap(
                code=gap.code,
                detail=gap.detail,
                evidence_refs=tuple(factor_ids[item] for item in gap.evidence_handles),
            )
            for gap in route.gaps
        )
        return SemanticExecutionContract(
            disposition=ExecutionContractDisposition.analytical_only,
            gaps=gaps,
        )

    _validate_execution_route(
        route,
        factor_drafts,
        context,
        unsafe_outcome,
        stimulus=stimulus,
        target_operation=target_operation,
    )
    selected_factor_handle, delivery_class = _resolve_route_binding(
        route,
        factor_drafts,
        stimulus,
    )
    selected_factor_id = factor_ids[selected_factor_handle]
    selected_source_id = choices[selected_factor_handle].source_id
    requirements = _materialize_execution_requirements(
        route,
        selected_factor_id,
        selected_source_id,
        unsafe_outcome,
        context,
        stimulus=stimulus,
        target_operation=target_operation,
    )
    basis = resolve_contract_environment_request(
        requirements, requested_environment_basis
    )
    return SemanticExecutionContract(
        requested_environment_basis=basis,
        delivery=SemanticExecutionDelivery(
            delivery_class=delivery_class,
            factor_id=selected_factor_id,
            source_role=_source_role_for_delivery(delivery_class),
            carrier_requirement_id=(
                "REQ-carrier"
                if delivery_class is ExecutionDeliveryClass.indirect_content
                else None
            ),
        ),
        action_kind=route.action_kind,
        resource_requirements=requirements,
    )


def _source_role_for_delivery(delivery_class: ExecutionDeliveryClass) -> str:
    """Return the canonical semantic source role for a delivery class."""
    return {
        ExecutionDeliveryClass.direct_prompt: "direct_user_input",
        ExecutionDeliveryClass.indirect_content: "attacker_influenced_content",
        ExecutionDeliveryClass.conversation_context: "conversation_context",
    }[delivery_class]


def _materialize_execution_requirements(
    route: _ContextExecutableRouteDraft,
    selected_factor_id: str,
    selected_source_id: str,
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
    *,
    stimulus: _ContextStimulusDraft | None = None,
    target_operation: TargetOperationObservation | None = None,
) -> tuple[ExecutionResourceRequirement, ...]:
    """Build semantic requirements from typed route/action/outcome values."""
    requirements: list[ExecutionResourceRequirement] = []
    handles, carrier_influence = _execution_requirement_inputs(
        route, context, unsafe_outcome, stimulus
    )
    if "role_stimulus_carrier" in handles:
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-carrier",
                purpose=ExecutionResourcePurpose.stimulus_carrier,
                factor_id=selected_factor_id,
                owner_ref=selected_source_id,
                acceptable_resource_kinds=(
                    ExecutionResourceKind.integration,
                    ExecutionResourceKind.tool,
                ),
                role_id="attacker_influenced_content_source",
                operation="retrieve_content",
                required_surfaces=(ExecutionSurface.tool_result,),
                required_properties=("content_reaches_model_context",),
                required_attacker_influence=carrier_influence,
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    if "role_target_action" in handles:
        action_id = context.target_control_path.control_action.action_id
        operation = (
            target_operation.operation_id if target_operation is not None else action_id
        )
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-target-action",
                purpose=ExecutionResourcePurpose.target_action,
                owner_ref=action_id,
                acceptable_resource_kinds=(
                    ExecutionResourceKind.integration,
                    ExecutionResourceKind.tool,
                ),
                role_id="target_control_action",
                operation=operation,
                required_surfaces=(ExecutionSurface.tool_call,),
                required_properties=(),
                # This requirement identifies the exact target action being
                # executed. Attacker influence constrains stimulus carriers,
                # not the action endpoint selected by target realization.
                required_attacker_influence=None,
                exact_resource_id=(
                    target_operation.resource_id
                    if target_operation is not None
                    else None
                ),
                late_bindable=target_operation is None,
                evidence_refs=(action_id,),
            )
        )
    if "role_state" in handles:
        subject_ref = getattr(unsafe_outcome.condition, "subject_ref", None)
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-state",
                purpose=ExecutionResourcePurpose.state_resource,
                owner_ref=subject_ref
                or context.target_control_path.control_action.action_id,
                acceptable_resource_kinds=(ExecutionResourceKind.state_store,),
                role_id="unsafe_state",
                operation="read_unsafe_state",
                required_surfaces=(ExecutionSurface.state_observation,),
                required_properties=("unsafe_state_observable",),
                required_attacker_influence="none",
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    if "role_agent_channel" in handles:
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-agent-channel",
                purpose=ExecutionResourcePurpose.agent_channel,
                owner_ref=_agent_channel_owner_ref(context),
                acceptable_resource_kinds=(ExecutionResourceKind.agent_channel,),
                role_id="agent_message",
                operation="deliver_agent_message",
                required_surfaces=(ExecutionSurface.agent_message,),
                required_properties=("agent_message_observable",),
                required_attacker_influence="direct",
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    return tuple(requirements)


def _execution_requirement_inputs(
    route: _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
    unsafe_outcome: UnsafeOutcomeDeclaration,
    stimulus: _ContextStimulusDraft | None,
) -> tuple[set[str], AttackerInfluence]:
    """Derive role handles and carrier influence from typed provider fields."""
    return (
        _required_execution_role_handles(
            route,
            context,
            unsafe_outcome,
            delivery_class=(
                _stimulus_delivery_class(stimulus) if stimulus is not None else None
            ),
        ),
        _stimulus_attacker_influence(stimulus),
    )


def _stimulus_delivery_class(
    stimulus: _ContextStimulusDraft | None,
) -> ExecutionDeliveryClass:
    """Resolve the one supported delivery primitive for a typed stimulus."""
    if stimulus is None:
        raise ValueError("context executable route requires a stimulus")
    expected_delivery = _stimulus_delivery(stimulus.category)
    if expected_delivery is None:
        raise ValueError(
            f"stimulus category {stimulus.category.value} has no supported delivery"
        )
    return ExecutionDeliveryClass(expected_delivery)


def _stimulus_attacker_influence(
    stimulus: _ContextStimulusDraft | None,
) -> AttackerInfluence:
    """Derive carrier influence from the typed stimulus category only."""
    if stimulus is None:
        return AttackerInfluence.unknown
    if stimulus.category in {
        StimulusCategory.retrieved_content,
        StimulusCategory.tool_content,
    }:
        return AttackerInfluence.indirect
    return AttackerInfluence.unknown


def _agent_channel_owner_ref(context: ScenarioGenerationContext) -> str:
    """Resolve the exact responsibility target for an agent-message action."""
    action = context.target_control_path.control_action
    if _typed_control_action_target_kind(action) == _RESPONSIBILITY_TARGET_KIND:
        return action.target_id
    return context.target_control_path.controller.element_id
