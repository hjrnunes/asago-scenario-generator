"""Canonical per-step semantics shared by projected generation stages.

The provider authors presentation and organization.  This module owns the
typed action, zone, exact step mapping, ingress identity, and narrative
compatibility region for every selected projected step.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackerAction,
    ExternalPreconditionAction,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    LeafAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
)


class ProjectionInfeasible(ValueError):
    """Canonical semantics cannot be derived without invention."""

    stage_failure_code = "projection_infeasible"
    stage_failure_retryable = False


@dataclass(frozen=True, slots=True)
class CanonicalProjectedStepSemantics:
    """Compiler-owned semantics for one selected projected step."""

    projected_step_id: str
    order: int
    action: LeafAction
    zone: str
    technique_id: str | None
    realization: ProjectedStepRealization
    initial_ingress: bool
    narrative_region: str
    label: str


@dataclass(frozen=True, slots=True)
class CanonicalProjectionSemantics:
    """Complete ordered semantic inventory for one projected candidate."""

    steps: tuple[CanonicalProjectedStepSemantics, ...]

    def for_step(self, projected_step_id: str) -> CanonicalProjectedStepSemantics:
        """Resolve one canonical step or fail with projection ownership."""

        for step in self.steps:
            if step.projected_step_id == projected_step_id:
                return step
        raise ProjectionInfeasible(
            f"selected projected step '{projected_step_id}' is absent"
        )


def compatible_leaf_action_kinds_for_step(
    step: dict[str, Any], projection_context: dict[str, Any] | None = None
) -> set[str]:
    """Return validator-compatible leaf kinds narrowed by canonical ownership.

    The raw action/executor intersection deliberately includes every shape the
    catalog can represent. A concrete projected step has stronger semantics:
    only an explicit ingress owner may use ``initial_ingress``, and an outside
    step may only be an external precondition or impact. Compilation and
    prompt alignment consume this same narrowing rule.
    """

    compatible = STEP_TO_LEAF_ACTION_COMPAT.get(
        str(step.get("action_kind", "")), set()
    ) & (EXECUTOR_ROLE_TO_LEAF_COMPAT.get(str(step.get("executor_role", "")), set()))
    owns_ingress = _owns_initial_ingress(step, projection_context or {})
    if owns_ingress:
        compatible &= {"initial_ingress"}
    else:
        compatible -= {"initial_ingress"}
    if step.get("boundary_position") == "outside":
        compatible &= {"external_precondition", "impact"}
    return compatible


def _ingress_link_matches(link: dict[str, Any], initial_slot: str | None) -> bool:
    """Return True when an ingress role link targets the initial slot."""
    slot_id = link.get("slot_id")
    return initial_slot is None or slot_id is None or slot_id == initial_slot


def _source_influence_link_matches(
    link: dict[str, Any], initial_slot: str | None
) -> bool:
    """Return True when a source-influence link targets the initial slot."""
    target_slot = link.get("target_ingress_slot_id")
    return initial_slot is None or target_slot == initial_slot


def _link_owns_initial_ingress(link: object, initial_slot: str | None) -> bool:
    """Return True when one resource link owns the initial ingress slot."""
    if not isinstance(link, dict):
        return False
    if link.get("role") == "ingress":
        return _ingress_link_matches(link, initial_slot)
    if link.get("role") == "source_influence":
        return _source_influence_link_matches(link, initial_slot)
    return False


def _owns_initial_ingress(
    step: dict[str, Any], projection_context: dict[str, Any]
) -> bool:
    initial_slot = projection_context.get("initial_ingress_slot_id")
    return any(
        _link_owns_initial_ingress(link, initial_slot)
        for link in step.get("resource_links", ())
    )


def _resource_refs(step: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        reference
        for link in step.get("resource_links", ())
        if isinstance(link, dict)
        and isinstance((reference := link.get("resource_ref")), dict)
    ]


def _matching_reference_values(
    references: list[dict[str, Any]], kind: str, key: str
) -> list[str]:
    """Collect the bound values of one resource kind from step references."""
    return [
        str(reference[key])
        for reference in references
        if reference.get("kind") == kind and reference.get(key)
    ]


def _resource_id(references: list[dict[str, Any]], kind: str, key: str) -> str | None:
    values = _matching_reference_values(references, kind, key)
    if len(set(values)) > 1:
        raise ProjectionInfeasible(
            f"projected step has more than one {kind} binding: {sorted(set(values))}"
        )
    return values[0] if values else None


def _derive_ingress_action(
    step: dict[str, Any],
    projection_context: dict[str, Any],
    compatible: set[str],
    entry_point_id: str | None,
) -> InitialIngressAction:
    """Compile the canonical initial-ingress action for an ingress-owning step."""
    if "initial_ingress" not in compatible:
        raise ProjectionInfeasible(
            f"ingress-owning step '{step.get('step_id')}' is incompatible "
            "with initial_ingress"
        )
    canonical_ingress = projection_context.get("canonical_ingress", {})
    if not entry_point_id and isinstance(canonical_ingress, dict):
        entry_point_id = canonical_ingress.get("entry_point_id")
    if not entry_point_id:
        raise ProjectionInfeasible(
            f"ingress-owning step '{step.get('step_id')}' has no canonical entry point"
        )
    return InitialIngressAction(entry_point_id=str(entry_point_id))


def _derive_impact_action(step: dict[str, Any], boundary: str) -> ImpactAction:
    """Compile the canonical impact action from observable postconditions."""
    descriptions = [
        str(postcondition.get("description"))
        for postcondition in step.get("observable_postconditions", ())
        if isinstance(postcondition, dict) and postcondition.get("description")
    ]
    target = descriptions[0] if descriptions else "Projected security impact"
    return ImpactAction(
        boundary="external" if boundary == "outside" else "internal",
        target=target[:200],
    )


def _derive_boundary_action(
    step: dict[str, Any],
    compatible: set[str],
    boundary: str,
) -> ExternalPreconditionAction | None:
    """Compile the outside-step precondition when the kind is compatible."""
    if boundary == "outside" and "external_precondition" in compatible:
        return ExternalPreconditionAction()
    return None


def _derive_impact_action_for_step(
    step: dict[str, Any],
    compatible: set[str],
    boundary: str,
    action_kind: str,
) -> ImpactAction | None:
    """Compile the canonical impact action when the step declares impact."""
    if action_kind == "impact" and "impact" in compatible:
        return _derive_impact_action(step, boundary)
    return None


def _derive_tool_invocation_action(
    tool_id: str | None,
    integration_id: str | None,
    compatible: set[str],
) -> ToolInvocationAction | None:
    """Compile the tool invocation when a tool binding is compatible."""
    if tool_id is not None and "tool_invocation" in compatible:
        return ToolInvocationAction(tool_id=tool_id, integration_id=integration_id)
    return None


def _derive_integration_action(
    integration_id: str | None,
    compatible: set[str],
) -> IntegrationInteractionAction | None:
    """Compile the integration interaction when its binding is compatible."""
    if integration_id is not None and "integration_interaction" in compatible:
        return IntegrationInteractionAction(integration_id=integration_id)
    return None


def _derive_generic_action(step: dict[str, Any], compatible: set[str]) -> LeafAction:
    """Compile the generic actor/ai-system action or fail projection ownership."""
    if "attacker_action" in compatible:
        return AttackerAction()
    if "ai_system_action" in compatible:
        return AiSystemAction()
    raise ProjectionInfeasible(
        f"no canonical tree action can be derived for step '{step.get('step_id')}' "
        f"from compatible kinds {sorted(compatible)} and its resource bindings"
    )


def _derive_action(
    step: dict[str, Any], projection_context: dict[str, Any]
) -> LeafAction:
    compatible = compatible_leaf_action_kinds_for_step(step, projection_context)
    references = _resource_refs(step)
    boundary = str(step.get("boundary_position", ""))
    action_kind = str(step.get("action_kind", ""))
    entry_point_id = _resource_id(references, "entry_point", "entry_point_id")
    tool_id = _resource_id(references, "tool", "tool_id")
    integration_id = _resource_id(references, "integration", "integration_id")

    if _owns_initial_ingress(step, projection_context):
        return _derive_ingress_action(
            step, projection_context, compatible, entry_point_id
        )

    candidates = (
        _derive_boundary_action(step, compatible, boundary),
        _derive_impact_action_for_step(step, compatible, boundary, action_kind),
        _derive_tool_invocation_action(tool_id, integration_id, compatible),
        _derive_integration_action(integration_id, compatible),
    )
    for candidate in candidates:
        if candidate is not None:
            return candidate
    return _derive_generic_action(step, compatible)


def _zone_or_fail(
    action: InitialIngressAction,
    ingress_zone: object,
    active: tuple[str, ...],
) -> str:
    """Return the canonical ingress zone or fail projection ownership."""
    if not isinstance(ingress_zone, str):
        raise ProjectionInfeasible(
            f"initial ingress '{action.entry_point_id}' has no canonical zone"
        )
    if ingress_zone not in active:
        raise ProjectionInfeasible(
            f"initial ingress '{action.entry_point_id}' uses inactive canonical "
            f"zone '{ingress_zone}'"
        )
    return ingress_zone


def _derive_ingress_zone(
    action: InitialIngressAction, profile: CapabilityProfile, active: tuple[str, ...]
) -> str:
    """Derive the canonical zone of an initial-ingress action."""
    entry_point = profile.resolve_entry_point(action.entry_point_id)
    ingress_zone = (
        entry_point.effective_ingress_zone if entry_point is not None else None
    )
    return _zone_or_fail(action, ingress_zone, active)


def _tool_execution_binding(step: dict[str, Any]) -> bool:
    """Return True when a step invokes a tool or integration binding."""
    resource_kinds = {reference.get("kind") for reference in _resource_refs(step)}
    return str(step.get("action_kind", "")) == "invoke" and bool(
        resource_kinds.intersection({"tool", "integration"})
    )


def _preferred_active_zone(
    kind: str, tool_execution: bool, active: tuple[str, ...]
) -> str | None:
    """Return the first active zone matching the step's kind conditions."""
    for zone, condition in (
        ("tool_execution", tool_execution),
        ("memory", kind == "persist"),
    ):
        if condition and zone in active:
            return zone
    if "reasoning" in active:
        return "reasoning"
    return None


def _fallback_active_zone(active: tuple[str, ...]) -> str:
    """Return the first active zone or fail projection ownership."""
    if active:
        return active[0]
    raise ProjectionInfeasible(
        "profile has no active zone for an inside projected step"
    )


def _derive_inside_zone(step: dict[str, Any], active: tuple[str, ...]) -> str:
    """Derive the resource-kind zone of an inside projected step."""
    zone = _preferred_active_zone(
        str(step.get("action_kind", "")),
        _tool_execution_binding(step),
        active,
    )
    return zone or _fallback_active_zone(active)


def _derive_zone(
    step: dict[str, Any], action: LeafAction, profile: CapabilityProfile
) -> str:
    boundary = str(step.get("boundary_position", ""))
    if boundary == "outside":
        return "outside"

    active = tuple(profile.zones_active or ())
    if action.kind == "initial_ingress":
        assert isinstance(action, InitialIngressAction)
        return _derive_ingress_zone(action, profile, active)
    return _derive_inside_zone(step, active)


def _normalized_technique_ids(raw: object) -> tuple[str, ...]:
    """Normalize a technique binding to a tuple of identifier strings."""
    iterable = (raw,) if isinstance(raw, str) else raw
    return tuple(str(item) for item in iterable)


def _derive_technique_id(step: dict[str, Any]) -> str | None:
    technique_ids = _normalized_technique_ids(step.get("technique_ids", ()))
    if len(technique_ids) > 1:
        raise ProjectionInfeasible(
            f"projected step '{step.get('step_id')}' has ambiguous technique "
            f"bindings {list(technique_ids)}"
        )
    return technique_ids[0] if technique_ids else None


def _canonical_label(step: dict[str, Any], action: LeafAction) -> str:
    descriptions = [
        str(postcondition.get("description"))
        for postcondition in step.get("observable_postconditions", ())
        if isinstance(postcondition, dict) and postcondition.get("description")
    ]
    if descriptions:
        return descriptions[0][:120]
    return f"{action.kind.replace('_', ' ')} projected step"[:120]


def _selected_step_ids(projection_context: dict[str, Any]) -> tuple[str, ...]:
    """Return the ordered selected step IDs or fail projection ownership."""
    selected_ids = tuple(
        str(item) for item in projection_context.get("selected_step_ids", ())
    )
    if not selected_ids:
        raise ProjectionInfeasible("projection contains no selected steps")
    if len(set(selected_ids)) != len(selected_ids):
        raise ProjectionInfeasible("projection contains duplicate selected step IDs")
    return selected_ids


def _provisional_step_semantics(
    step_id: str,
    step: dict[str, Any],
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
) -> tuple[LeafAction, str, str | None, ProjectedStepRealization]:
    """Derive one step's action, zone, technique, and realization semantics."""
    realization_data = step.get("realization")
    if not isinstance(realization_data, dict):
        raise ProjectionInfeasible(
            f"projected step '{step_id}' has no canonical realization"
        )
    realization = ProjectedStepRealization.model_validate(realization_data)
    if realization.projected_step_id != step_id:
        raise ProjectionInfeasible(
            f"projected step '{step_id}' realization identifies "
            f"'{realization.projected_step_id}'"
        )
    action = _derive_action(step, projection_context)
    zone = _derive_zone(step, action, profile)
    technique_id = _derive_technique_id(step)
    return action, zone, technique_id, realization


def _require_initial_ingress(
    provisional: list[
        tuple[dict[str, Any], LeafAction, str, str | None, ProjectedStepRealization]
    ],
) -> None:
    """Fail projection ownership when no provisional step is an initial ingress."""
    if not any(action.kind == "initial_ingress" for _, action, _, _, _ in provisional):
        raise ProjectionInfeasible("canonical steps contain no initial ingress")


def _canonical_step_entries(
    provisional: list[
        tuple[dict[str, Any], LeafAction, str, str | None, ProjectedStepRealization]
    ],
) -> list[CanonicalProjectedStepSemantics]:
    """Attach ordered identity, narrative regions, and labels to semantics."""
    steps: list[CanonicalProjectedStepSemantics] = []
    region_index = -1
    previous_region_key: tuple[str, str] | None = None
    for index, (step, action, zone, technique_id, realization) in enumerate(
        provisional, start=1
    ):
        region_key = (zone, realization.boundary_position)
        if region_key != previous_region_key:
            region_index += 1
            previous_region_key = region_key
        steps.append(
            CanonicalProjectedStepSemantics(
                projected_step_id=str(step["step_id"]),
                order=int(step.get("order", index)),
                action=action,
                zone=zone,
                technique_id=technique_id,
                realization=realization,
                initial_ingress=action.kind == "initial_ingress",
                narrative_region=f"r{region_index}",
                label=_canonical_label(step, action),
            )
        )
    return steps


def _steps_by_id(projection_context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index the projection's selected steps by their step id."""
    return {
        str(step["step_id"]): step
        for step in projection_context.get("selected_steps", ())
        if isinstance(step, dict) and step.get("step_id")
    }


def derive_canonical_projection_semantics(
    projection_context: dict[str, Any], profile: CapabilityProfile
) -> CanonicalProjectionSemantics:
    """Derive the complete immutable semantic inventory for generation."""

    step_by_id = _steps_by_id(projection_context)
    selected_ids = _selected_step_ids(projection_context)

    provisional: list[
        tuple[dict[str, Any], LeafAction, str, str | None, ProjectedStepRealization]
    ] = []
    for step_id in selected_ids:
        step = step_by_id.get(step_id)
        if step is None:
            raise ProjectionInfeasible(f"selected projected step '{step_id}' is absent")
        action, zone, technique_id, realization = _provisional_step_semantics(
            step_id, step, projection_context, profile
        )
        provisional.append((step, action, zone, technique_id, realization))

    _require_initial_ingress(provisional)
    return CanonicalProjectionSemantics(
        steps=tuple(_canonical_step_entries(provisional))
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T01:22:18Z","module_hash":"6ed09723412f9a27bcc28c268519b69667e011a51972ea53f5d52a50ae2f2c46","source_sha256":"fee694e6e468577888ef9cac8847d5eaaf52c058a40afa58e88a370dab815875","functions":[{"id":"func/CanonicalProjectionSemantics.for_step","name":"for_step","line":59,"end_line":67,"hash":"e8e8c00ca8323d8df7853500c29c5e7ac11a7905defc6a568ffd8506bf1ebefb"},{"id":"func/compatible_leaf_action_kinds_for_step","name":"compatible_leaf_action_kinds_for_step","line":70,"end_line":92,"hash":"5b6e2f2025f9ee2de4fb4c641800f42c88703df4cab3581333c104fddb10c1f9"},{"id":"func/_ingress_link_matches","name":"_ingress_link_matches","line":95,"end_line":98,"hash":"edc910521bb0b261715a67921f63e0e6ec30782c9b84aa426066a9155a0768b1"},{"id":"func/_source_influence_link_matches","name":"_source_influence_link_matches","line":101,"end_line":106,"hash":"2a7c48f45520687296b68b8aa5b01ff4ad4490edc77dda337483805c6e5d7e3e"},{"id":"func/_link_owns_initial_ingress","name":"_link_owns_initial_ingress","line":109,"end_line":117,"hash":"e3ac81be48d0060e722b7833997b2dac4b253acd63f16c4dd625900773fced68"},{"id":"func/_owns_initial_ingress","name":"_owns_initial_ingress","line":120,"end_line":127,"hash":"5849cc42bd5eea8bf4835f487f9f46007bfac0d960e28dadf6aed10c79b08ea9"},{"id":"func/_resource_refs","name":"_resource_refs","line":130,"end_line":136,"hash":"741423b4eb6180e0cc96d8ef26de4ee8e83776fd94baf0d85b566206087c08dc"},{"id":"func/_matching_reference_values","name":"_matching_reference_values","line":139,"end_line":147,"hash":"f8df7da1835d563ac14463f967c658d38f8306c8db585b4c7f564bd031280585"},{"id":"func/_resource_id","name":"_resource_id","line":150,"end_line":156,"hash":"fc208015f3072f31962e4efff0fbd1bcffd7e98d0bdeb2ae235c4a5675f3ccc8"},{"id":"func/_derive_ingress_action","name":"_derive_ingress_action","line":159,"end_line":178,"hash":"f86d0ed3d83d7a163398c9bf9a8f3f6e4c543454d629e82fd4f159888bd68e82"},{"id":"func/_derive_impact_action","name":"_derive_impact_action","line":181,"end_line":192,"hash":"b2239b876009814a2302752f9fb611962968e529a35a36bd098594950a4085b7"},{"id":"func/_derive_boundary_action","name":"_derive_boundary_action","line":195,"end_line":203,"hash":"db490c061db9c0e3008831a5a92311517474a0e68495b022cb567332f7ee5653"},{"id":"func/_derive_impact_action_for_step","name":"_derive_impact_action_for_step","line":206,"end_line":215,"hash":"90216b254ff621047e4f28b84c9fddfb5a619f57e5d0aaaa74af13fd9d6d5fef"},{"id":"func/_derive_tool_invocation_action","name":"_derive_tool_invocation_action","line":218,"end_line":226,"hash":"00fcb42dd366b9bd5707e3154bd45e429f15c00f5b0ff42e55595ca16c9a16bf"},{"id":"func/_derive_integration_action","name":"_derive_integration_action","line":229,"end_line":236,"hash":"b88802a35879a7e005bf9fca10d93a7461b0cd7959b9b9e72236dd9d92072d37"},{"id":"func/_derive_generic_action","name":"_derive_generic_action","line":239,"end_line":248,"hash":"0335ec8eee04827f41875976ffafb16b9d326aeb5496a1e1e8c63fc1dd19e59c"},{"id":"func/_derive_action","name":"_derive_action","line":251,"end_line":276,"hash":"03b7f3895272cde6d69c66178f40141223b6c8890174a02aceafd68740e6bfc1"},{"id":"func/_zone_or_fail","name":"_zone_or_fail","line":279,"end_line":294,"hash":"30673434c84d836898dbafff9ce30a48433abc706bc61d618da37c8078877baa"},{"id":"func/_derive_ingress_zone","name":"_derive_ingress_zone","line":297,"end_line":305,"hash":"ca419dafdc65d79eaa561d25cc135eed2b0d126ae200fd8cf1f31b834e7f9317"},{"id":"func/_tool_execution_binding","name":"_tool_execution_binding","line":308,"end_line":313,"hash":"76b1a25e209a85d24c87175acc444f72384d71f8eb21e5c4b9d2818ca2d0f076"},{"id":"func/_preferred_active_zone","name":"_preferred_active_zone","line":316,"end_line":328,"hash":"35d86ee76fa9e7b97cbc8044c7afd9dcf413b08afe445942631ed73522863dab"},{"id":"func/_fallback_active_zone","name":"_fallback_active_zone","line":331,"end_line":337,"hash":"404c0fd67fda75f9b24fbd1dc6a405b5508b70b814390a9e4cf3132823f10998"},{"id":"func/_derive_inside_zone","name":"_derive_inside_zone","line":340,"end_line":347,"hash":"a712cdaf93cc84fcfe960fb2ee167b86cf68f651b4856d16d3cbaabb9e9676d9"},{"id":"func/_derive_zone","name":"_derive_zone","line":350,"end_line":361,"hash":"a00ff44a08deda8c6c8a34aaeed6357ca9f80facd29cc71750d84f474b7bed1e"},{"id":"func/_normalized_technique_ids","name":"_normalized_technique_ids","line":364,"end_line":367,"hash":"7afe69ebe92efd753b63c7c30c028e80f1e7ec89d16b3f69af624d86eaa34f75"},{"id":"func/_derive_technique_id","name":"_derive_technique_id","line":370,"end_line":377,"hash":"c3d37199d09bf52cb42784b6babb33339906cec5c602266c6a026c5b6b70403b"},{"id":"func/_canonical_label","name":"_canonical_label","line":380,"end_line":388,"hash":"cf2d20db98145f37033eb001d8239f01f4838dfb828530982cc82cd0205dc10e"},{"id":"func/_selected_step_ids","name":"_selected_step_ids","line":391,"end_line":400,"hash":"b30aca47b6271f2f4b9a8eb1b75e2f1739c6072cb667c4015325a3c11e69a36b"},{"id":"func/_provisional_step_semantics","name":"_provisional_step_semantics","line":403,"end_line":424,"hash":"4a4143e400f8da564aa2a3c36b4ebf0b0ff272ed1ad12aebdd66118700ffdd77"},{"id":"func/_require_initial_ingress","name":"_require_initial_ingress","line":427,"end_line":434,"hash":"c6a9b2cfcba2c837f12f101e8d4c1f89baf27de93164f09a41e2341d0ea105d5"},{"id":"func/_canonical_step_entries","name":"_canonical_step_entries","line":437,"end_line":466,"hash":"5e467b84b1b354ec5440a5484bc72433571d13ee399e221a5ad6a1cc857a45ac"},{"id":"func/_steps_by_id","name":"_steps_by_id","line":469,"end_line":475,"hash":"53bcc974b29972e61dda59524167af77231bc8da8127d0fa57bbb556b32a3007"},{"id":"func/derive_canonical_projection_semantics","name":"derive_canonical_projection_semantics","line":478,"end_line":501,"hash":"b69fc6f50760288f540a840a275c281d3fcc0f6b62e4c383dededa1aa530cdd8"}]}
# mutate4py-manifest-end
