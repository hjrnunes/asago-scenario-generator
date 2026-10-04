"""Pure projection of SP1/SP2 authority into one SP3 scenario context."""

from __future__ import annotations

from collections.abc import Sequence


from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlStructure,
    CoordinationLink,
    coordination_process_model_owner,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    DescribedElement,
    ReachableCapability,
    ScenarioCatalogContext,
    ScenarioConstraint,
    ScenarioCoordinationPath,
    ScenarioControlPath,
    ScenarioGenerationContext,
    ScenarioHazard,
    ScenarioICAContext,
    ScenarioIdentity,
    ScenarioLoss,
    ScenarioObligationConsideration,
    ScenarioSourcePin,
    semantic_digest,
)


_UCA_DEFINITIONS = {
    UCAType.not_provided: "The required control action is absent when it is needed.",
    UCAType.incorrect: (
        "The action is provided, but its value, content, destination, or effect is unsafe."
    ),
    UCAType.wrong_timing: (
        "The action is provided too early, too late, or in an unsafe order."
    ),
    UCAType.wrong_duration: (
        "A continuous action stops too soon, continues too long, or has an unsafe duration."
    ),
}


def execution_implementation_kind(
    control_action: "DescribedControlAction",
    target_operation: TargetOperationObservation | None = None,
) -> ControlActionEffectKind | None:
    """Return the execution implementation kind for one selected action.

    A target-realization row is an additive implementation attestation.  Its
    exact observed operation therefore supplies the Stage 5 implementation
    kind (an MCP/tool invocation) without changing the systemic action's
    conceptual target or effect stored in :class:`ScenarioControlPath`.
    Without that attestation, preserve the baseline action effect exactly.
    The explicit type check prevents a caller from turning arbitrary context
    into an execution claim.
    """
    if target_operation is not None:
        if not isinstance(target_operation, TargetOperationObservation):
            raise TypeError("target_operation must be a TargetOperationObservation")
        return ControlActionEffectKind.tool_call
    return control_action.effect_kind


def build_scenario_generation_context(
    threat: StructuralThreat,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    *,
    scenario_id: str,
    obligation_considerations: Sequence[ScenarioObligationConsideration] = (),
    reachable_capabilities: Sequence[ReachableCapability] = (),
) -> ScenarioGenerationContext:
    """Build one exact, fail-closed context for an accepted structural threat."""
    controller_id, action_id, uca_type = _parse_selected_slot(threat)
    control_path = _build_control_path(control_structure, controller_id, action_id)
    hazards, losses = _selected_hazards_and_losses(threat, loss_analysis)
    constraints = _selected_constraints(threat, loss_analysis, hazards)
    if threat.ica_id is None:
        raise ValueError("selected structural threat has no exact ICA identity")

    capability_records = tuple(reachable_capabilities)
    context_values = {
        "source_pins": _source_pins(
            threat, control_path, hazards, losses, constraints, capability_records
        ),
        "scenario_identity": ScenarioIdentity(
            scenario_id=scenario_id,
            ica_slot_id=threat.ica_slot_id,
            ica_id=threat.ica_id,
        ),
        "ica": ScenarioICAContext(
            ica_id=threat.ica_id,
            slot_id=threat.ica_slot_id,
            uca_type=uca_type,
            uca_type_definition=_UCA_DEFINITIONS[uca_type],
            exact_ica_text=threat.ica_text,
            unsafe_action=threat.ica_text,
            hazardous_context=threat.hazardous_context,
            loss_consequence=threat.loss_scenario,
        ),
        "target_control_path": control_path,
        "losses": losses,
        "hazards": hazards,
        "constraints": constraints,
        "obligation_considerations": tuple(obligation_considerations),
        "reachable_capabilities": capability_records,
        "catalog_context": tuple(
            ScenarioCatalogContext(
                catalog=item.catalog,
                entry_id=item.id,
                name=item.name,
                confidence=item.confidence,
            )
            for item in threat.catalog_mappings
        ),
    }
    return ScenarioGenerationContext.create(**context_values)


def _parse_selected_slot(threat: StructuralThreat) -> tuple[str, str, UCAType]:
    parts = threat.ica_slot_id.split(":")
    if len(parts) not in {3, 4} or any(not part for part in parts):
        raise ValueError(f"Invalid ICA slot ID format: {threat.ica_slot_id}")
    try:
        uca_type = UCAType(parts[2])
    except ValueError as exc:
        raise ValueError(f"Invalid ICA type in slot: {threat.ica_slot_id}") from exc
    return parts[0], parts[1], uca_type


def _build_control_path(
    control_structure: ControlStructure,
    controller_id: str,
    action_id: str,
) -> ScenarioControlPath:
    """Build a responsibility or coordination-link control-path view."""
    if controller_id.startswith("CL-"):
        return _coordination_control_path(control_structure, controller_id, action_id)

    responsibility = _responsibility(control_structure, controller_id)
    action = _control_action(responsibility, action_id)
    controlled_process = _controlled_process_or_none(control_structure, action.target)
    return ScenarioControlPath(
        controller=DescribedElement(
            element_id=responsibility.resp_id,
            description=responsibility.description,
        ),
        responsibility=DescribedElement(
            element_id=responsibility.resp_id,
            description=responsibility.description,
        ),
        control_action=_describe_control_action(
            action,
            target_id=(
                controlled_process.cp_id
                if controlled_process is not None
                else action.target.id
                if action.target is not None
                else "unspecified"
            ),
        ),
        controlled_process=(
            DescribedElement(
                element_id=controlled_process.cp_id,
                description=controlled_process.description,
            )
            if controlled_process is not None
            else None
        ),
        process_model_parts=tuple(
            DescribedElement(element_id=item.pm_id, description=item.description)
            for item in responsibility.process_model_parts
        ),
        feedback=tuple(
            DescribedElement(
                element_id=item.fb_id,
                description=item.description,
                source_kind=(
                    item.source_kind.value if item.source_kind is not None else None
                ),
            )
            for item in responsibility.feedback_channels
        ),
    )


def _coordination_control_path(
    control_structure: ControlStructure,
    link_id: str,
    mechanism_id: str,
) -> ScenarioControlPath:
    """Resolve one exact CL/CM slot without relabelling it as RESP/CA."""
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"selected coordination link {link_id!r} is not exact or is dangling"
        )
    link: CoordinationLink = links[0]
    if link.coordination_mechanism.cm_id != mechanism_id:
        raise ValueError(
            f"selected coordination mechanism {mechanism_id!r} does not match "
            f"coordination link {link_id!r}"
        )

    source = _responsibility(control_structure, link.source)
    target = _responsibility(control_structure, link.target)
    try:
        pm_owner = coordination_process_model_owner(control_structure, link)
    except ValueError as exc:
        # Preserve the context seam's stable diagnostic while delegating the
        # endpoint-owner rule to the shared typed control-structure authority.
        raise ValueError(
            f"coordination link {link_id!r} shared PM {link.shared_pm!r} "
            "is not owned by exactly one endpoint responsibility"
        ) from exc

    endpoint_responsibilities = (source, target)
    process_models = _described_process_models(endpoint_responsibilities)
    feedback = _described_feedback(endpoint_responsibilities)
    controlled_processes = _described_controlled_processes(
        control_structure, endpoint_responsibilities
    )
    coordination_path = ScenarioCoordinationPath(
        link_id=link.link_id,
        description=link.description,
        source=DescribedElement(
            element_id=source.resp_id, description=source.description
        ),
        target=DescribedElement(
            element_id=target.resp_id, description=target.description
        ),
        shared_process_model=DescribedElement(
            element_id=link.shared_pm,
            description=next(
                item.description
                for owner in (pm_owner,)
                for item in owner.process_model_parts
                if item.pm_id == link.shared_pm
            ),
        ),
        coordination_mechanism=DescribedElement(
            element_id=link.coordination_mechanism.cm_id,
            description=link.coordination_mechanism.description,
        ),
        controlled_processes=controlled_processes,
    )
    return ScenarioControlPath(
        controller=DescribedElement(
            element_id=link.link_id, description=link.description
        ),
        responsibility=None,
        coordination_path=coordination_path,
        control_action=DescribedControlAction(
            action_id=link.coordination_mechanism.cm_id,
            description=link.coordination_mechanism.description,
            target_id=link.shared_pm,
            target_kind="coordination_path",
            effect_kind=ControlActionEffectKind.agent_message,
        ),
        controlled_process=coordination_path.controlled_process,
        process_model_parts=process_models,
        feedback=feedback,
        related_control_actions=_described_control_actions(endpoint_responsibilities),
    )


def _described_process_models(responsibilities) -> tuple[DescribedElement, ...]:
    """Describe endpoint process-model parts in stable responsibility order."""
    return _described_elements(responsibilities, "process_model_parts", "pm_id")


def _described_feedback(responsibilities) -> tuple[DescribedElement, ...]:
    """Describe endpoint feedback channels in stable responsibility order."""
    return _described_elements(responsibilities, "feedback_channels", "fb_id")


def _described_elements(
    responsibilities,
    collection_name: str,
    identity_name: str,
) -> tuple[DescribedElement, ...]:
    """Describe one responsibility-owned element family without duplicates."""
    seen: set[str] = set()
    result: list[DescribedElement] = []
    for responsibility in responsibilities:
        for item in getattr(responsibility, collection_name):
            identity = getattr(item, identity_name)
            if identity not in seen:
                result.append(
                    DescribedElement(element_id=identity, description=item.description)
                )
                seen.add(identity)
    return tuple(result)


def _described_control_actions(responsibilities) -> tuple[DescribedControlAction, ...]:
    """Describe endpoint actions that may contribute causal evidence."""
    seen: set[str] = set()
    result: list[DescribedControlAction] = []
    for responsibility in responsibilities:
        for action in responsibility.control_actions:
            if action.ca_id in seen:
                continue
            target_id = action.target.id if action.target is not None else "unspecified"
            result.append(_describe_control_action(action, target_id=target_id))
            seen.add(action.ca_id)
    return tuple(result)


def _describe_control_action(
    action: object, *, target_id: str
) -> DescribedControlAction:
    """Copy authoritative action semantics without interpreting prose."""
    target = getattr(action, "target", None)
    target_kind = getattr(target, "type", None) or "unspecified"
    return DescribedControlAction(
        action_id=getattr(action, "ca_id"),
        description=getattr(action, "description"),
        target_id=target_id,
        target_kind=target_kind,
        effect_kind=getattr(action, "effect_kind", None),
    )


def _described_controlled_processes(
    control_structure: ControlStructure,
    responsibilities,
) -> tuple[DescribedElement, ...]:
    """Collect exact endpoint controlled-process targets without guessing one."""
    processes_by_id = {
        item.cp_id: item for item in control_structure.controlled_processes
    }
    process_ids: list[str] = []
    for responsibility in responsibilities:
        for action in responsibility.control_actions:
            target = action.target
            if target is not None and target.id in processes_by_id:
                if target.id not in process_ids:
                    process_ids.append(target.id)
    return tuple(
        DescribedElement(
            element_id=process_id, description=processes_by_id[process_id].description
        )
        for process_id in process_ids
    )


def _responsibility(control_structure: ControlStructure, controller_id: str):
    matches = [
        item
        for item in control_structure.responsibilities
        if item.resp_id == controller_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"selected controller {controller_id!r} is not an exact responsibility"
        )
    return matches[0]


def _control_action(responsibility, action_id: str):
    matches = [
        item for item in responsibility.control_actions if item.ca_id == action_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"selected action {action_id!r} is not owned by the controller"
        )
    return matches[0]


def _controlled_process(control_structure: ControlStructure, target):
    if target is None or target.type.value != "controlled_process":
        raise ValueError(
            "selected control action has no exact controlled-process target"
        )
    matches = [
        item
        for item in control_structure.controlled_processes
        if item.cp_id == target.id
    ]
    if len(matches) != 1:
        raise ValueError("selected control action target is dangling or ambiguous")
    return matches[0]


def _controlled_process_or_none(control_structure: ControlStructure, target):
    """Resolve a process target while preserving responsibility targets."""
    if target is not None and target.type.value == "responsibility":
        return None
    return _controlled_process(control_structure, target)


def _selected_hazards(threat, loss_analysis):
    selected_hazard_ids = tuple(dict.fromkeys(threat.related_hazards))
    if not selected_hazard_ids:
        raise ValueError("selected ICA has no exact related hazard")
    hazards_by_id = {item.hazard_id: item for item in loss_analysis.hazards}
    try:
        return tuple(hazards_by_id[item] for item in selected_hazard_ids)
    except KeyError as exc:
        raise ValueError(
            f"selected ICA references unknown hazard {exc.args[0]!r}"
        ) from exc


def _reachable_losses(selected, loss_analysis):
    loss_ids = tuple(
        dict.fromkeys(ref for item in selected for ref in item.related_losses)
    )
    losses_by_id = {
        item.loss_id: item
        for item in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    }
    if not loss_ids or any(item not in losses_by_id for item in loss_ids):
        raise ValueError("selected hazard does not reach an exact loss")
    return loss_ids, losses_by_id


def _selected_hazards_and_losses(threat, loss_analysis):
    selected = _selected_hazards(threat, loss_analysis)
    loss_ids, losses_by_id = _reachable_losses(selected, loss_analysis)
    return (
        tuple(
            ScenarioHazard(
                hazard_id=item.hazard_id,
                description=item.description,
                related_loss_ids=tuple(item.related_losses),
            )
            for item in selected
        ),
        tuple(
            ScenarioLoss(
                loss_id=losses_by_id[item].loss_id,
                description=losses_by_id[item].description,
            )
            for item in loss_ids
        ),
    )


def _selected_constraints(threat, loss_analysis, hazards):
    selected_constraint_ids = tuple(dict.fromkeys(threat.related_constraints))
    if not selected_constraint_ids:
        raise ValueError("selected ICA has no exact governing constraint")
    constraints_by_id = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    try:
        selected = tuple(constraints_by_id[item] for item in selected_constraint_ids)
    except KeyError as exc:
        raise ValueError(
            f"selected ICA references unknown constraint {exc.args[0]!r}"
        ) from exc
    hazard_ids = {item.hazard_id for item in hazards}
    for item in selected:
        if not set(item.related_hazards) & hazard_ids:
            raise ValueError(
                f"selected constraint {item.constraint_id!r} does not govern a selected hazard"
            )
    return tuple(
        ScenarioConstraint(
            constraint_id=item.constraint_id,
            description=item.description,
            related_hazard_ids=tuple(item.related_hazards),
        )
        for item in selected
    )


def _source_pins(threat, control_path, hazards, losses, constraints, capabilities):
    records = (
        ("structural_threat", threat.model_dump(mode="json")),
        ("control_path", control_path.model_dump(mode="json")),
        (
            "loss_relationships",
            {
                "hazards": [item.model_dump(mode="json") for item in hazards],
                "losses": [item.model_dump(mode="json") for item in losses],
                "constraints": [item.model_dump(mode="json") for item in constraints],
            },
        ),
        (
            "capabilities",
            [item.model_dump(mode="json") for item in capabilities],
        ),
    )
    return tuple(
        ScenarioSourcePin(
            source_kind=kind,
            semantic_digest=semantic_digest(
                value,
                frame=f"asago-scenario-generator:scenario-context-source:{kind}:v1",
            ),
        )
        for kind, value in records
    )
