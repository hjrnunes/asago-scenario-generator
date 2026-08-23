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


def _owns_initial_ingress(
    step: dict[str, Any], projection_context: dict[str, Any]
) -> bool:
    initial_slot = projection_context.get("initial_ingress_slot_id")
    for link in step.get("resource_links", ()):
        if not isinstance(link, dict):
            continue
        role = link.get("role")
        if role == "ingress":
            slot_id = link.get("slot_id")
            if initial_slot is None or slot_id is None or slot_id == initial_slot:
                return True
        if role == "source_influence":
            target_slot = link.get("target_ingress_slot_id")
            if initial_slot is None or target_slot == initial_slot:
                return True
    return False


def _resource_refs(step: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        reference
        for link in step.get("resource_links", ())
        if isinstance(link, dict)
        and isinstance((reference := link.get("resource_ref")), dict)
    ]


def _resource_id(references: list[dict[str, Any]], kind: str, key: str) -> str | None:
    values = [
        str(reference[key])
        for reference in references
        if reference.get("kind") == kind and reference.get(key)
    ]
    if len(set(values)) > 1:
        raise ProjectionInfeasible(
            f"projected step has more than one {kind} binding: {sorted(set(values))}"
        )
    return values[0] if values else None


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
                f"ingress-owning step '{step.get('step_id')}' has no canonical "
                "entry point"
            )
        return InitialIngressAction(entry_point_id=str(entry_point_id))

    if boundary == "outside" and "external_precondition" in compatible:
        return ExternalPreconditionAction()
    if action_kind == "impact" and "impact" in compatible:
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
    if tool_id is not None and "tool_invocation" in compatible:
        return ToolInvocationAction(tool_id=tool_id, integration_id=integration_id)
    if integration_id is not None and "integration_interaction" in compatible:
        return IntegrationInteractionAction(integration_id=integration_id)
    if "attacker_action" in compatible:
        return AttackerAction()
    if "ai_system_action" in compatible:
        return AiSystemAction()
    raise ProjectionInfeasible(
        f"no canonical tree action can be derived for step '{step.get('step_id')}' "
        f"from compatible kinds {sorted(compatible)} and its resource bindings"
    )


def _derive_zone(
    step: dict[str, Any], action: LeafAction, profile: CapabilityProfile
) -> str:
    boundary = str(step.get("boundary_position", ""))
    if boundary == "outside":
        return "outside"

    active = tuple(profile.zones_active or ())
    if action.kind == "initial_ingress":
        assert isinstance(action, InitialIngressAction)
        entry_point = profile.resolve_entry_point(action.entry_point_id)
        ingress_zone = (
            entry_point.effective_ingress_zone if entry_point is not None else None
        )
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

    resource_kinds = {reference.get("kind") for reference in _resource_refs(step)}
    action_kind = str(step.get("action_kind", ""))
    if (
        action_kind == "invoke"
        and resource_kinds.intersection({"tool", "integration"})
        and "tool_execution" in active
    ):
        return "tool_execution"
    if action_kind == "persist" and "memory" in active:
        return "memory"
    if "reasoning" in active:
        return "reasoning"
    if active:
        return active[0]
    raise ProjectionInfeasible(
        "profile has no active zone for an inside projected step"
    )


def _derive_technique_id(step: dict[str, Any]) -> str | None:
    raw = step.get("technique_ids", ())
    if isinstance(raw, str):
        raw = (raw,)
    technique_ids = tuple(str(item) for item in raw)
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


def derive_canonical_projection_semantics(
    projection_context: dict[str, Any], profile: CapabilityProfile
) -> CanonicalProjectionSemantics:
    """Derive the complete immutable semantic inventory for generation."""

    step_by_id = {
        str(step["step_id"]): step
        for step in projection_context.get("selected_steps", ())
        if isinstance(step, dict) and step.get("step_id")
    }
    selected_ids = tuple(
        str(item) for item in projection_context.get("selected_step_ids", ())
    )
    if not selected_ids:
        raise ProjectionInfeasible("projection contains no selected steps")
    if len(set(selected_ids)) != len(selected_ids):
        raise ProjectionInfeasible("projection contains duplicate selected step IDs")

    provisional: list[
        tuple[dict[str, Any], LeafAction, str, str | None, ProjectedStepRealization]
    ] = []
    for index, step_id in enumerate(selected_ids, start=1):
        step = step_by_id.get(step_id)
        if step is None:
            raise ProjectionInfeasible(f"selected projected step '{step_id}' is absent")
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
        provisional.append((step, action, zone, technique_id, realization))

    if not any(action.kind == "initial_ingress" for _, action, _, _, _ in provisional):
        raise ProjectionInfeasible("canonical steps contain no initial ingress")

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
    return CanonicalProjectionSemantics(steps=tuple(steps))
