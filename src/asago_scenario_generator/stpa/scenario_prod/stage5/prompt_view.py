"""Stage 5 prompt rendering and its YAML views."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
import yaml
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    ScenarioObligationConsideration,
    ScenarioGenerationContext,
)
from ..condition_family import ConditionFamily, family_prompt_view
from ..condition_check import (
    build_condition_universe,
    condition_fact_listing,
)
from ..target_observations import TargetObservationSnapshot
from .wire import (
    _CausalSourceChoice,
)
from .sources import (
    _UNTRUSTED_SOURCE_KINDS,
    _action_duration_eligible,
    _causal_source_choices,
    _compatible_mechanisms,
    _context_expected_action_kind,
    _normalize_typed_value,
    _typed_control_action_effect,
    _typed_control_action_target_kind,
)


def build_context_bdi_prompts(
    scenario_context: ScenarioGenerationContext,
    loader: TemplateLoader,
    *,
    target_operation: TargetOperationObservation | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    observation_contract: ObservationContract | None = None,
    condition_family: ConditionFamily | None = None,
) -> tuple[str, str]:
    """Render Stage 5 from only the immutable context and output contract.

    The prompt requests scenario semantics and causal evidence only and
    carries no stimulus, delivery or executable-condition demands. A
    ``condition_family`` hint renders only where the condition is requested.
    """
    scenario_context_yaml = yaml.dump(
        _stage5_prompt_context(scenario_context),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    source_choices = _causal_source_choices(scenario_context)
    if not source_choices:
        raise ValueError("selected scenario context has no valid causal-factor sources")
    source_choices_yaml = _context_source_choices_yaml(source_choices)
    temporal_reference_choices_yaml = _temporal_reference_choices_yaml(
        scenario_context, source_choices
    )
    expected_action_kind = _context_expected_action_kind(
        scenario_context,
        target_operation,
    )
    target_operation_yaml = _target_operation_prompt_yaml(target_operation)
    observed_operations_yaml = _observed_operations_prompt_yaml(
        execution_target_profile
    )
    target_observations_yaml = _target_observations_prompt_yaml(target_observations)
    has_target_operation = target_operation is not None
    has_observed_operations = execution_target_profile is not None
    has_target_observations = target_observations is not None
    # The response schema carries the condition key only with an observation
    # contract, so the prompt describes it under the same gate.
    condition_universe = build_condition_universe(
        execution_target_profile=execution_target_profile,
        target_operation=target_operation,
        target_observations=target_observations,
    )
    has_condition_references = (
        observation_contract is not None and condition_universe.grounded
    )
    condition_fact_paths = (
        condition_fact_listing(condition_universe.fact_values)
        if has_condition_references
        else ""
    )
    (
        observation_contract_yaml,
        available_observation_kinds,
        unsupported_observation_claims,
    ) = _observation_contract_prompt_values(observation_contract)
    return (
        loader.render_prompt(
            "stage5_context_system.j2",
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            expected_action_kind=(
                expected_action_kind.value if expected_action_kind is not None else None
            ),
            has_target_operation=has_target_operation,
            has_observed_operations=has_observed_operations,
            observed_operations_yaml=observed_operations_yaml,
            has_target_observations=has_target_observations,
            observation_contract_yaml=observation_contract_yaml,
            has_observation_contract=observation_contract is not None,
            available_observation_kinds=available_observation_kinds,
            unsupported_observation_claims=unsupported_observation_claims,
            has_condition_references=has_condition_references,
        ),
        loader.render_prompt(
            "stage5_context_user.j2",
            scenario_context_yaml=scenario_context_yaml,
            causal_source_choices_yaml=source_choices_yaml,
            temporal_reference_choices_yaml=temporal_reference_choices_yaml,
            target_operation_yaml=target_operation_yaml,
            observed_operations_yaml=observed_operations_yaml,
            target_observations_yaml=target_observations_yaml,
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            selected_uca_type=scenario_context.ica.uca_type.value,
            expected_action_kind=(
                expected_action_kind.value if expected_action_kind is not None else None
            ),
            has_target_operation=has_target_operation,
            has_observed_operations=has_observed_operations,
            has_target_observations=has_target_observations,
            observation_contract_yaml=observation_contract_yaml,
            has_observation_contract=observation_contract is not None,
            available_observation_kinds=available_observation_kinds,
            unsupported_observation_claims=unsupported_observation_claims,
            has_condition_references=has_condition_references,
            condition_fact_paths=condition_fact_paths,
            condition_family=(
                family_prompt_view(condition_family)
                if has_condition_references
                else None
            ),
        ),
    )


def _observation_contract_prompt_values(
    observation_contract: ObservationContract | None,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if observation_contract is None:
        return "No observation contract was supplied.", (), ()
    contract_yaml = yaml.dump(
        observation_contract.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    available_kinds = tuple(
        item.kind for item in observation_contract.capture if item.available
    )
    return contract_yaml, available_kinds, observation_contract.unsupported_claims


def _target_operation_prompt_yaml(
    target_operation: TargetOperationObservation | None,
) -> str:
    """Render only exact target facts selected by the realization lens."""
    if target_operation is None:
        return "No exact target operation was established for this control action."
    return _yaml_dump(
        {
            "resource_id": target_operation.resource_id,
            "operation_id": target_operation.operation_id,
            "description": target_operation.description,
            "input_schema": _plain_prompt_json(
                target_operation.model_dump(mode="json")["input_schema"]
            ),
            "argument_names": list(target_operation.argument_names),
            "likely_effect": target_operation.effect,
            "likely_state_effect": target_operation.state_effect,
        }
    )


def _observed_operations_prompt_yaml(
    execution_target_profile: ExecutionTargetProfile | None,
) -> str:
    """Render every exact operation from the supplied target profile."""

    if execution_target_profile is None:
        return "No bound execution target profile was supplied."

    interpretations = {
        item.resource_id: item for item in execution_target_profile.interpretations
    }
    rendered = [
        _observed_operation_item(
            resource, operation, interpretations.get(resource.resource_id)
        )
        for resource in execution_target_profile.resources
        for operation in resource.operations
    ]
    if not rendered:
        return "The supplied target profile contains no operations."
    return _yaml_dump(rendered)


def _observed_operation_item(resource, operation, interpretation) -> dict[str, object]:
    item: dict[str, object] = {
        "operation_name": operation.operation_id,
        "resource_id": resource.resource_id,
        "argument_names": list(operation.argument_names or resource.argument_names),
        "input_schema": _plain_prompt_json(resource.input_schema),
    }
    if resource.description is not None:
        item["description"] = resource.description
    if resource.output_schema is not None:
        item["output_schema"] = _plain_prompt_json(resource.output_schema)
    if resource.annotations is not None:
        item["annotations"] = _plain_prompt_json(resource.annotations)
    if resource.surfaces:
        item["surfaces"] = [surface.value for surface in resource.surfaces]
    if interpretation is not None:
        item.update(
            {
                "likely_effect": interpretation.likely_effect.value,
                "likely_state_effect": interpretation.likely_state_effect.value,
                "interpretation_disposition": interpretation.disposition.value,
                "interpreter_verifier_agreement": (
                    interpretation.interpreter_verifier_agreement.value
                ),
            }
        )
    return item


def _target_observations_prompt_yaml(
    target_observations: TargetObservationSnapshot | None,
) -> str:
    """Render quoted target observations without profile/capture metadata."""
    if target_observations is None:
        return "No target observations were supplied."
    records = list(target_observations.prompt_records())
    rendered = _yaml_dump(records)
    if target_observations.read_status != "observed":
        rendered += (
            "\nExplicit evidence gap: no successful target read observation was "
            "supplied; absence is not evidence that a condition is false.\n"
        )
    return rendered


def _yaml_dump(value: object) -> str:
    """Dump one prompt view with the stable Stage 5 YAML options."""
    return yaml.dump(
        value,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _plain_prompt_json(value: object) -> object:
    """Convert frozen profile JSON into ordinary YAML-safe JSON values."""
    return json.loads(json.dumps(value))


def _context_source_choices_yaml(
    source_choices: Sequence[_CausalSourceChoice],
) -> str:
    """Render local causal handles and their selection guidance."""
    rendered_choices: list[dict[str, object]] = []
    for choice in source_choices:
        rendered_choice: dict[str, object] = {
            "source_handle": choice.handle,
            "source_type": _source_type_explanation(choice.kind),
            "description": choice.description,
            "select_when": _source_selection_guidance(choice.kind),
        }
        if choice.source_kind is not None:
            rendered_choice["feedback_source_kind"] = choice.source_kind
            rendered_choice["untrusted"] = choice.source_kind in _UNTRUSTED_SOURCE_KINDS
        rendered_choice["compatible_mechanisms"] = _compatible_mechanisms(choice)
        rendered_choices.append(rendered_choice)
    return _yaml_dump(rendered_choices)


def _stage5_prompt_context(
    context: ScenarioGenerationContext,
) -> Mapping[str, object]:
    """Project authority into only the facts Stage 5 can interpret or copy."""
    return {
        "unsafe_control_action": {
            "category": context.ica.uca_type.value,
            "category_meaning": context.ica.uca_type_definition,
            "statement": context.ica.exact_ica_text,
            "hazardous_context": context.ica.hazardous_context,
            "loss_consequence": context.ica.loss_consequence,
        },
        "selected_control_path": _stage5_control_path(context),
        "unsafe_results": _stage5_unsafe_results(context),
        "taxonomy_considerations": _stage5_taxonomy_considerations(context),
        "reachable_capabilities": _stage5_reachable_capabilities(context),
    }


def _stage5_control_path(context: ScenarioGenerationContext) -> Mapping[str, object]:
    """Describe the selected owner, action, and controlled processes."""
    path = context.target_control_path
    action_view: dict[str, object] = {
        "reference": path.control_action.action_id,
        "description": path.control_action.description,
    }
    action_semantics = _control_action_semantics(path.control_action)
    if action_semantics:
        action_view.update(action_semantics)
    return {
        "owner_description": _stage5_owner_description(context),
        "target_action": action_view,
        "controlled_processes": _stage5_controlled_processes(context),
    }


def _control_action_semantics(action: DescribedControlAction) -> dict[str, str]:
    """Expose the selected action's typed target, effect, and temporal facts.

    Only typed values are read; an action is never classified from its
    description.
    """
    semantics: dict[str, str] = {}
    target_kind = _typed_control_action_target_kind(action)
    effect_kind = _typed_control_action_effect(action)
    if target_kind is not None:
        semantics["target_kind"] = target_kind
    if effect_kind is not None:
        semantics["effect_kind"] = effect_kind
    temporality = _normalize_typed_value(getattr(action, "temporality", None))
    semantics["temporality"] = temporality or "unknown"
    semantics["duration_eligibility"] = (
        "eligible" if _action_duration_eligible(action) else "not_established"
    )
    return semantics


def _stage5_owner_description(context: ScenarioGenerationContext) -> str:
    """Return the one validated responsibility or coordination owner."""
    path = context.target_control_path
    if path.responsibility is not None:
        return path.responsibility.description
    if path.coordination_path is not None:
        return path.coordination_path.description
    raise ValueError("selected control path has no owner")


def _stage5_controlled_processes(context: ScenarioGenerationContext) -> list[str]:
    """Return plain controlled-process descriptions for either path shape."""
    path = context.target_control_path
    if path.coordination_path is not None:
        return [
            item.description for item in path.coordination_path.controlled_processes
        ]
    if path.controlled_process is not None:
        return [path.controlled_process.description]
    return []


def _stage5_unsafe_results(context: ScenarioGenerationContext) -> Mapping[str, object]:
    """Expose consequence descriptions; lineage IDs remain compiler-owned."""
    return {
        "losses": [item.description for item in context.losses],
        "hazards": [item.description for item in context.hazards],
        "constraints": [item.description for item in context.constraints],
    }


def _stage5_taxonomy_considerations(
    context: ScenarioGenerationContext,
) -> list[Mapping[str, object]]:
    """Keep taxonomy meaning while removing its bookkeeping identities."""
    return [
        _stage5_taxonomy_consideration(item)
        for item in context.obligation_considerations
    ]


def _stage5_taxonomy_consideration(
    item: ScenarioObligationConsideration,
) -> Mapping[str, object]:
    """Name the pattern, or for a governance risk the risk, and keep the rest."""
    name = (
        {"risk_name": item.risk_name}
        if item.kind == "governance"
        else {"pattern_name": item.attack_pattern_name}
    )
    return {
        **name,
        "concern": item.concise_concern,
        "review_outcome": item.disposition,
        "review_reason": item.rationale,
    }


def _stage5_reachable_capabilities(
    context: ScenarioGenerationContext,
) -> list[Mapping[str, object]]:
    """Expose capability references only because provider output may copy them."""
    return [
        {
            "capability_ref": item.capability_id,
            "description": item.description,
            "evidence": item.evidence,
            "access_refs": list(item.access_path),
        }
        for item in context.reachable_capabilities
    ]


def _temporal_reference_choices_yaml(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
) -> str:
    """Explain local temporal handles without exposing hidden identities."""
    references = [
        {
            "reference_handle": "target_action",
            "meaning": "the selected unsafe control action",
            "allowed_for": (
                "factor reference_handle and until_step_handle; not outcome ordering"
            ),
        }
    ]
    references.extend(
        {
            "reference_handle": choice.handle,
            "meaning": (
                f"the selected {_source_type_explanation(choice.kind)} source "
                f"({choice.description})"
            ),
            "allowed_for": (
                "factor reference_handle and until_step_handle, or outcome ordering"
            ),
        }
        for choice in choices
    )
    return yaml.dump(
        {
            "choices": references,
            "outcome_ordering_reference_handles": [choice.handle for choice in choices],
            "resolution": (
                "Outcome ordering must use a distinct declared causal-factor handle; "
                "target_action is the final action step and is never a valid outcome "
                "ordering reference (never `target_action` itself). Deterministic "
                "compilation resolves valid handles "
                "to exact structural or projected step references; do not emit "
                "structural IDs here."
            ),
        },
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _source_type_explanation(kind: CausalFactorKind) -> str:
    """Describe a source category without exposing its structural identity."""
    return {
        CausalFactorKind.process_model_flaw: "a process-model belief or state",
        CausalFactorKind.feedback_delay: "a feedback update or timing condition",
        CausalFactorKind.sensor_anomaly: "a feedback observation anomaly",
        CausalFactorKind.actuator_anomaly: "a control-action execution condition",
    }[kind]


def _source_selection_guidance(kind: CausalFactorKind) -> str:
    """Explain when a structurally valid causal category is meaningful."""
    return {
        CausalFactorKind.process_model_flaw: (
            "Select only for an incorrect, missing, or stale controller belief/state."
        ),
        CausalFactorKind.feedback_delay: (
            "Select only when timing, lateness, staleness, or missing feedback is "
            "part of the causal explanation."
        ),
        CausalFactorKind.sensor_anomaly: (
            "The feedback itself misreports a known fact through an explained "
            "corruption mechanism; interpretation of an accurate result belongs "
            "to the process-model belief instead."
        ),
        CausalFactorKind.actuator_anomaly: (
            "Select only for failure or distortion while executing the selected "
            "control action."
        ),
    }[kind]
