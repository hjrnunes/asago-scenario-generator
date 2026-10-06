"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for the causal story + attacker BDI,
and deterministic assembly of the ScenarioSpec.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Callable

import yaml
from pydantic import (
    BaseModel,
)

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    parse_llm_result,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod.outcome_grounding import (
    OutcomeGroundingResolution,
    resolve_outcome_grounding,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactor,
    CausalFactorKind,
    CausalMechanism,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticCondition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    SemanticExecutionContract,
    ExecutionTargetProfile,
    RequestedEnvironmentBasis,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationAssessment,
    ObservationContract,
    ObservationCriterion,
    assess_observation_criteria,
    default_observation_contract,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    ScenarioGenerationContext,
    validate_factor_evidence,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
    AttackerBDI,
    DefenderBDI,
    ScenarioSpec,
    ThreatSource,
)

from asago_scenario_generator.stpa.discriminating_condition import (
    ConditionCheck,
    DiscriminatingCondition,
)

from .._constants import PROMPTS_DIR
from ..condition_family import ConditionFamily, family_prompt_view
from ..condition_check import (
    ConditionUniverse,
    build_condition_universe,
    check_discriminating_condition,
    condition_fact_listing,
    condition_failure_message,
)
from ..content_surface import ContentSurfaceFacts
from ..target_observations import TargetObservationSnapshot
from ..tool_call_binding import bind_tool_call_condition
from .wire import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    StimulusCategory,
    UnsafeOutcomeDeclaration,
    _CausalSourceChoice,
    _ContextAdversarialDraft,
    _ContextFunctionalAdversaryDraft,
    _ContextStimulusDraft,
    _ContextTemporalConditionWire,
)
from .sources import (
    _UNTRUSTED_SOURCE_KINDS,
    _action_duration_eligible,
    _causal_source_choices,
    _compatible_delivery_classes,
    _compatible_mechanisms,
    _context_expected_action_kind,
    _normalize_typed_value,
    _stimulus_delivery,
    _typed_control_action_effect,
    _typed_control_action_target_kind,
)
from .conditions import (
    _materialize_provider_condition,
    _normalize_legacy_temporal_fields,
    _resolve_state_value_subject,
    _resolve_temporal_condition,
)
from .records import (
    _write_outcome_grounding_record,
    _write_stage5_normalization_record,
)
from .schema import (
    _context_bdi_provider_payload_type,
    _context_provider_schema_kwargs,
    _scenario_semantics_payload_type,
)
from .route import (
    _materialize_execution_contract,
)
from .validate import (
    FUNCTIONAL_TEST_GAIN,
    _ADVERSARY_REACH_BY_STIMULUS,
    _NormalDraftCheck,
    _normalize_provider_semantic_proposition,
    _validate_context_provider_payload,
    _validate_intention_factor_handles,
    _validate_normal_provider_payload,
    _validate_unsafe_outcome_for_target,
)
from .feedback import (
    _context_validation_retry_feedback,
    _normal_validation_retry_feedback,
)


_LENGTH_RETRY_MAX_COMPLETION_TOKENS = 2048
_LENGTH_RETRY_PROMPT = (
    "\n\nThe prior response was truncated. Return only a concise "
    "schema-matching response with no explanation."
)
_LENGTH_RETRY_EXHAUSTED_PREFIX = (
    "BDI generation retry exhausted after LengthFinishReasonError:"
)
_UNSELECTED_PROCESS_MODEL_MARKER = "Not selected as a causal factor in this scenario."


def generate_scenario_id(index: int = 0) -> str:
    """Generate a deterministic scenario ID.

    Args:
        index: Zero-based scenario index.

    Returns:
        A scenario ID in the format ``SCN-NNN`` (zero-padded).
    """
    return f"SCN-{index + 1:03d}"


def parse_ica_slot_id(slot_id: str) -> dict[str, str]:
    """Parse an ICA slot ID into its components.

    Supports two identity shapes:
    - ``RESP-X:CA-Y:TYPE-Z`` (responsibility slot)
    - ``CL-X:CM-Y:TYPE-Z`` (coordination link slot)
    - either shape with a fourth explicit action-temporality component

    Args:
        slot_id: The ICA slot ID string.

    Returns:
        A dict with keys ``controller``, ``control_action``, and ``ica_type``.
    """
    parts = slot_id.split(":")
    if len(parts) not in {3, 4} or any(not part for part in parts):
        raise ValueError(f"Invalid ICA slot ID format: {slot_id}")
    return {
        "controller": parts[0],
        "control_action": parts[1],
        "ica_type": parts[2],
    }


def generate_bdi_for_context(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_5",
    step: str = "bdi_generation",
    temperature: float = DEFAULT_TEMPERATURE,
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
    target_operation: TargetOperationObservation | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    execution_design: bool = True,
    observation_contract: ObservationContract | None = None,
    condition_family: ConditionFamily | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Execute corrected Stage 5 with one caller-selected environment basis.

    ``execution_design=True`` (the historical default, used by execution
    projection and bundle publication callers) requests the strict execution
    wire: stimulus, execution route and executable unsafe-outcome conditions
    with their full artifact-feasibility validation.  The normal product run
    passes ``execution_design=False``: the response requests scenario
    semantics and causal evidence only, and no artifact-feasibility gate runs.
    ``condition_family`` is an optional code-derived hint rendered with the
    discriminating-condition instructions; it never enters the context.
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)
    choices = _causal_source_choices(scenario_context)
    if not choices:
        return (
            None,
            "No valid causal-factor sources exist in the selected control path.",
        )
    _require_intact_environment_inputs(
        target_operation,
        execution_target_profile,
        target_observations,
        observation_contract,
    )
    if not execution_design:
        return _generate_bdi_semantics_only(
            llm_client,
            scenario_context,
            run_dir,
            loader=loader,
            stage=stage,
            step=step,
            temperature=temperature,
            target_operation=target_operation,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            content_surface=content_surface,
            observation_contract=observation_contract,
            condition_family=condition_family,
        )
    system_prompt, user_prompt = build_context_bdi_prompts(
        scenario_context,
        loader,
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
    )
    expected_action_kind = _context_expected_action_kind(
        scenario_context,
        target_operation,
    )
    response_format = _context_bdi_provider_payload_type(
        len(choices),
        expected_action_kind,
        **_context_provider_schema_kwargs(
            scenario_context,
            choices,
            target_operation=target_operation,
        ),
    )
    validation_retry_feedback = _context_validation_retry_feedback(
        scenario_context, choices
    )
    draft, error, _ = _call_bdi_with_bounded_length_retry(
        llm_client,
        system_prompt,
        user_prompt,
        run_dir,
        response_format=response_format,
        stage=stage,
        step=step,
        slot_id=scenario_context.scenario_identity.ica_slot_id,
        scenario_id=scenario_context.scenario_identity.scenario_id,
        temperature=temperature,
        validation_retry_feedback=validation_retry_feedback,
        result_validator=lambda value: _validate_context_provider_payload(
            value,
            scenario_context,
            target_operation,
            execution_target_profile,
            content_surface,
        ),
    )
    result, error, grounding = _finish_context_bdi(
        draft,
        error,
        choices,
        scenario_context,
        requested_environment_basis,
        target_operation,
        target_observations,
        observation_contract,
    )
    if result is not None and draft is not None and grounding is not None:
        _write_outcome_grounding_record(
            draft,
            result,
            scenario_context,
            run_dir,
            target_observations=target_observations,
            grounding=grounding,
        )
    return result, error


def _require_intact_environment_inputs(
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    observation_contract: ObservationContract | None,
) -> None:
    """Reject mistyped environment inputs and verify each supplied one's pin."""
    if target_operation is not None and not isinstance(
        target_operation, TargetOperationObservation
    ):
        raise TypeError("target_operation must be a TargetOperationObservation")
    if execution_target_profile is not None and not isinstance(
        execution_target_profile, ExecutionTargetProfile
    ):
        raise TypeError("execution_target_profile must be an ExecutionTargetProfile")
    if execution_target_profile is not None:
        execution_target_profile.assert_integrity()
    if target_observations is not None and not isinstance(
        target_observations, TargetObservationSnapshot
    ):
        raise TypeError("target_observations must be a TargetObservationSnapshot")
    if target_observations is not None:
        target_observations.assert_integrity()
    if observation_contract is not None:
        observation_contract.verify_digest()


def _generate_bdi_semantics_only(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    run_dir: Path,
    *,
    loader: TemplateLoader,
    stage: str,
    step: str,
    temperature: float,
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    content_surface: ContentSurfaceFacts | None,
    observation_contract: ObservationContract | None,
    condition_family: ConditionFamily | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Run the normal Stage 5 wire: scenario semantics and evidence only.

    The supplied target facts (``target_operation`` and
    ``target_observations``) are semantic grounding, not execution design:
    the normal prompt renders them so the semantic proposition can name the
    documented operation and the observed record values it acts on.
    """
    choices = _causal_source_choices(scenario_context)
    condition_universe = build_condition_universe(
        execution_target_profile=execution_target_profile,
        target_operation=target_operation,
        target_observations=target_observations,
    )
    system_prompt, user_prompt = build_context_bdi_prompts(
        scenario_context,
        loader,
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        execution_design=False,
        observation_contract=observation_contract,
        condition_family=condition_family,
    )
    response_format = _scenario_semantics_payload_type(
        len(choices),
        duration_eligible=_action_duration_eligible(
            scenario_context.target_control_path.control_action
        ),
        observation_criteria_required=observation_contract is not None,
        condition_references_supplied=condition_universe.grounded,
    )
    checks: list[_NormalDraftCheck] = []

    def validate(value: BaseModel, *, condition_required: bool = True) -> BaseModel:
        check = _validate_normal_provider_payload(
            value,
            scenario_context,
            content_surface,
            observation_contract,
            target_operation=target_operation,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            condition_required=condition_required,
        )
        checks.append(check)
        return check.draft

    draft, error, final_llm_result = _call_bdi_with_bounded_length_retry(
        llm_client,
        system_prompt,
        user_prompt,
        run_dir,
        response_format=response_format,
        stage=stage,
        step=step,
        slot_id=scenario_context.scenario_identity.ica_slot_id,
        scenario_id=scenario_context.scenario_identity.scenario_id,
        temperature=temperature,
        validation_retry_feedback=_normal_validation_retry_feedback(
            scenario_context,
            choices,
            target_observations=target_observations,
        ),
        result_validator=validate,
    )
    condition_omitted_reason: str | None = None
    if (
        error is not None
        and observation_contract is not None
        and condition_universe.grounded
    ):
        # The condition must never be the reason a scenario is lost: after
        # the one correction, a draft that passes without its condition is
        # published without one.
        recovered = _draft_without_condition(
            final_llm_result,
            response_format,
            lambda value: validate(value, condition_required=False),
        )
        if recovered is not None:
            condition_omitted_reason = _condition_omitted_reason(error)
            draft, error = recovered, None
    result, error = _finish_normal_context_bdi(
        draft,
        error,
        choices,
        scenario_context,
        observation_contract,
        condition_universe=condition_universe,
        condition_omitted_reason=condition_omitted_reason,
    )
    if result is not None:
        published = next(check for check in checks if check.draft is draft)
        _write_stage5_normalization_record(
            published.normalizations, scenario_context, run_dir
        )
    return result, error


def _finish_context_bdi(
    draft: BaseModel | None,
    error: str | None,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
    target_operation: TargetOperationObservation | None,
    target_observations: TargetObservationSnapshot | None,
    observation_contract: ObservationContract | None = None,
) -> tuple[
    BDIGenerationResult | None,
    str | None,
    OutcomeGroundingResolution | None,
]:
    """Compile one parsed provider draft or preserve its closed failure."""
    if error is not None or draft is None:
        return None, error, None
    try:
        result, grounding = _materialize_context_bdi(
            draft,
            choices,
            context,
            requested_environment_basis,
            target_operation,
            target_observations,
            observation_contract,
        )
        return (
            result,
            None,
            grounding,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}", None


def _finish_normal_context_bdi(
    draft: BaseModel | None,
    error: str | None,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    observation_contract: ObservationContract | None = None,
    *,
    condition_universe: ConditionUniverse | None = None,
    condition_omitted_reason: str | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Compile one normal-path draft without any execution materialization."""
    if error is not None or draft is None:
        return None, error
    try:
        return (
            _materialize_normal_context_bdi(
                draft,
                choices,
                context,
                observation_contract,
                condition_universe=condition_universe,
                condition_omitted_reason=condition_omitted_reason,
            ),
            None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _call_bdi_with_bounded_length_retry(
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    *,
    response_format: type[BaseModel],
    stage: str,
    step: str,
    temperature: float,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    result_validator: Callable[[BaseModel], BaseModel | None] | None = None,
    validation_retry_feedback: str | None = None,
) -> tuple[BaseModel | None, str | None, object]:
    """Call the closed Stage 5 contract with its one length-only retry.

    Returns the draft, the error, and the provider result of the last attempt
    (``None`` when no response arrived).
    """
    retry_feedback = validation_retry_feedback or (
        " Return only a closed JSON object with every required field. "
        "Include causal_factors, explicit temporal_condition (including "
        "null), unsafe_outcome with its typed condition, and one "
        "execution_route. Do not return semantic_binding_required; "
        "deterministic code derives it."
    )
    policy = CorrectionPolicy(
        validation_retries=1, feedback=retry_feedback, include_schema=False
    )

    def call(prompt: str, max_completion_tokens: int | None):
        return call_with_policy(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=prompt,
            response_format=response_format,
            run_dir=run_dir,
            stage=stage,
            step=step,
            policy=policy,
            slot_id=slot_id,
            scenario_id=scenario_id,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
            result_validator=result_validator,
            result_parser=lambda value: _parse_context_bdi_result(
                value, response_format
            ),
        )

    first = call(user_prompt, None)
    if not _is_length_finish_reason_error(first.error):
        return first.value, first.error, first.result
    retry = call(
        user_prompt + _LENGTH_RETRY_PROMPT, _LENGTH_RETRY_MAX_COMPLETION_TOKENS
    )
    if retry.error is None:
        return retry.value, None, retry.result
    return None, f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry.error}", retry.result


def _parse_context_bdi_result(result, response_format: type[BaseModel]) -> BaseModel:
    """Parse the contextual provider payload without compiler-owned fields.

    Historical temporal field spellings remain a narrow parse convenience.
    Route/factor migration is deliberately not performed: the context wire
    contract must expose one explicit factor binding and no independent route
    factor or delivery selector.
    """
    content = result.content
    if isinstance(content, BaseModel):
        payload = content.model_dump(mode="json")
    elif isinstance(content, Mapping):
        payload = dict(content)
    elif isinstance(content, str):
        payload = json.loads(_decode_provider_json_text(content))
    else:
        return parse_llm_result(result, response_format)
    if isinstance(payload, Mapping):
        payload = dict(payload)
        _normalize_legacy_temporal_fields(payload)
    return response_format.model_validate(payload)


def _decode_provider_json_text(value: str) -> str:
    """Remove only an exact JSON Markdown fence before provider parsing."""
    stripped = value.strip()
    lines = stripped.splitlines()
    if (
        len(lines) >= 3
        and lines[0].strip().lower() in {"```json", "```"}
        and lines[-1].strip() == "```"
    ):
        return "\n".join(lines[1:-1])
    return stripped


_CONDITION_DISCARDED_ANALYTICAL = (
    "The scenario is analytical-only, so the returned discriminating "
    "condition was discarded."
)
_CONDITION_DISCARDED_UNGROUNDED = (
    "No target operations or observations were supplied, so the returned "
    "discriminating condition was discarded."
)


def _discriminating_condition_result(
    condition: DiscriminatingCondition | None,
    universe: ConditionUniverse | None,
    assessment: ObservationAssessment | None = None,
) -> tuple[DiscriminatingCondition | None, ConditionCheck | None, str | None]:
    """Return the accepted condition, its code-owned check, and any omission."""

    if condition is None or universe is None:
        return None, None, None
    if assessment is not None and assessment.disposition == "analytical_only":
        return None, None, _CONDITION_DISCARDED_ANALYTICAL
    if not universe.grounded:
        return None, None, _CONDITION_DISCARDED_UNGROUNDED
    outcome = check_discriminating_condition(condition, universe)
    if outcome.failures:
        raise ValueError(condition_failure_message(outcome))
    return outcome.condition, outcome.check, None


def _condition_omitted_reason(error: str) -> str:
    """Return the code-owned publication note for a condition that failed.

    The exact failure text stays in the Stage 5 call log; the note names only
    its stable code so published prose carries no raw validator output.
    """

    if "discriminating_condition_missing" in error:
        code = "discriminating_condition_missing"
    elif "discriminating_condition_check_failed" in error:
        code = "discriminating_condition_check_failed"
    else:
        code = "discriminating_condition_invalid"
    return (
        f"The discriminating condition failed validation after one correction "
        f"({code}); the scenario is published without a condition."
    )


def _draft_without_condition(
    llm_result: object,
    response_format: type[BaseModel],
    validate: Callable[[BaseModel], BaseModel],
) -> BaseModel | None:
    """Re-parse the final response with its condition removed, if that passes.

    Returns ``None`` when the response is unavailable or still fails without
    the condition, so only condition-attributable failures are recovered.
    """

    content = getattr(llm_result, "content", None)
    try:
        if isinstance(content, BaseModel):
            payload = content.model_dump(mode="json")
        elif isinstance(content, Mapping):
            payload = json.loads(json.dumps(content))
        elif isinstance(content, str):
            payload = json.loads(_decode_provider_json_text(content))
        else:
            return None
    except (TypeError, ValueError):
        return None
    outcome = payload.get("unsafe_outcome") if isinstance(payload, dict) else None
    if not isinstance(outcome, dict):
        return None
    outcome["discriminating_condition"] = None
    try:
        return validate(
            _parse_context_bdi_result(SimpleNamespace(content=payload), response_format)
        )
    except (TypeError, ValueError):
        return None


def _materialize_adversary(
    draft: BaseModel, stimulus: _ContextStimulusDraft | None
) -> Adversary:
    """Derive the compiler-owned adversary fields (Phase 3 deviations 7-8).

    ``reaches_target_via`` is a function of the stimulus category; an
    analytical-only delivery (`file_upload`, `traffic_load`, `unknown`) has
    none of the three primitives, so the persisted reach is null. A
    ``kind: none`` record ignores the provider's gain text and carries the
    fixed functional-test marker. The normal wire carries no stimulus, so
    the reach stays null unless the adversary kind itself asserts content
    reach; the producer makes no delivery claim the handoff could publish.
    """
    if stimulus is not None:
        reach = _ADVERSARY_REACH_BY_STIMULUS.get(stimulus.category)
    elif draft.kind is AdversaryKind.third_party_via_content:
        reach = AdversaryReach.retrieved_content
    else:
        reach = None
    if draft.kind is AdversaryKind.none:
        gain = FUNCTIONAL_TEST_GAIN
    else:
        gain = getattr(draft, "gain", None)
        if gain is None:
            raise ValueError("adversarial response omitted its required gain")
    return Adversary(kind=draft.kind, gain=gain, reaches_target_via=reach)


def _is_length_finish_reason_error(error: str | None) -> bool:
    """Return whether a safe-call error came from completion length exhaustion."""
    if error is None:
        return False
    error_type, _, _message = error.partition(":")
    return error_type == "LengthFinishReasonError"


def is_bdi_length_retry_exhausted(error: str | None) -> bool:
    """Return whether both bounded structured-output length attempts failed."""
    return bool(error and error.startswith(_LENGTH_RETRY_EXHAUSTED_PREFIX))


def build_context_bdi_prompts(
    scenario_context: ScenarioGenerationContext,
    loader: TemplateLoader,
    *,
    target_operation: TargetOperationObservation | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    execution_design: bool = True,
    observation_contract: ObservationContract | None = None,
    condition_family: ConditionFamily | None = None,
) -> tuple[str, str]:
    """Render Stage 5 from only the immutable context and output contract.

    ``execution_design=False`` renders the normal product wire: the prompt
    requests scenario semantics and causal evidence only and carries no
    stimulus, delivery or executable-condition demands. A
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
    source_choices_yaml = _context_source_choices_yaml(
        source_choices,
        execution_design=execution_design,
    )
    stimulus_choices_yaml = _stimulus_choices_yaml() if execution_design else ""
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
            execution_design=execution_design,
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
            stimulus_choices_yaml=stimulus_choices_yaml,
            temporal_reference_choices_yaml=temporal_reference_choices_yaml,
            target_operation_yaml=target_operation_yaml,
            observed_operations_yaml=observed_operations_yaml,
            target_observations_yaml=target_observations_yaml,
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            selected_uca_type=scenario_context.ica.uca_type.value,
            expected_action_kind=(
                expected_action_kind.value if expected_action_kind is not None else None
            ),
            execution_design=execution_design,
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
    *,
    execution_design: bool = True,
) -> str:
    """Render local causal handles and their typed delivery compatibility.

    ``execution_design=False`` omits the delivery/factor compatibility view:
    those columns are execution design and the normal wire carries no route
    to satisfy.
    """
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
        if execution_design:
            compatible_delivery_classes = _compatible_delivery_classes(choice.kind)
            compatible_stimulus_categories = _compatible_stimulus_categories(
                choice.kind
            )
            rendered_choice["compatible_delivery_classes"] = [
                item.value for item in compatible_delivery_classes
            ]
            rendered_choice["compatible_stimulus_categories"] = list(
                compatible_stimulus_categories
            )
            if not compatible_stimulus_categories:
                rendered_choice["route_instruction"] = (
                    "analytical_only; this factor cannot select an executable route"
                )
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
        {
            "pattern_name": item.attack_pattern_name,
            "concern": item.concise_concern,
            "review_outcome": item.disposition,
            "review_reason": item.rationale,
        }
        for item in context.obligation_considerations
    ]


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


_STIMULUS_CATEGORY_DESCRIPTIONS = {
    StimulusCategory.user_message: (
        "one attacker-authored user message, including requests that cause normal "
        "tool use; unchanged tool returns remain background evidence"
    ),
    StimulusCategory.conversation: (
        "earlier conversation turns that establish context before the target action"
    ),
    StimulusCategory.conversation_context: (
        "earlier conversation turns (compatibility spelling for conversation)"
    ),
    StimulusCategory.retrieved_content: (
        "content the attacker authors or alters in a retrieved source; requires "
        "a separately supported carrier/access hypothesis, not just an observed read"
    ),
    StimulusCategory.tool_content: (
        "content the attacker authors or alters in a tool result; requires a "
        "separately supported carrier/access hypothesis, not normal tool use"
    ),
    StimulusCategory.file_upload: (
        "a file-upload event or attachment, which has no supported Stage 5 delivery primitive"
    ),
    StimulusCategory.traffic_load: (
        "a high-volume or rate-based traffic/load event, which has no supported primitive"
    ),
    StimulusCategory.unknown: "an unspecified or unsupported stimulus delivery",
}


def _stimulus_choices_yaml() -> str:
    """Render the closed provider-only stimulus vocabulary."""
    return yaml.dump(
        [
            {
                "category": category.value,
                "description": description,
                "supported_delivery": _stimulus_delivery(category),
            }
            for category, description in _STIMULUS_CATEGORY_DESCRIPTIONS.items()
        ],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _compatible_stimulus_categories(
    kind: CausalFactorKind,
) -> tuple[str, ...]:
    """Project the fixed delivery/factor table onto stimulus categories."""
    compatible_deliveries = {
        delivery.value for delivery in _compatible_delivery_classes(kind)
    }
    return tuple(
        category.value
        for category in _STIMULUS_CATEGORY_DESCRIPTIONS
        if _stimulus_delivery(category) in compatible_deliveries
    )


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


def _materialize_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
    target_operation: TargetOperationObservation | None,
    target_observations: TargetObservationSnapshot | None,
    observation_contract: ObservationContract | None = None,
) -> tuple[BDIGenerationResult, OutcomeGroundingResolution]:
    """Resolve provider-local handles to exact context-owned structural IDs."""
    choices_by_handle = {choice.handle: choice for choice in choices}
    attacker_bdi = _materialize_context_attacker_bdi(draft, choices_by_handle)
    factors = _materialize_context_factors(draft, choices, choices_by_handle, context)
    unsafe_outcome, grounding = _materialize_context_unsafe_outcome(
        draft,
        context,
        target_operation=target_operation,
        target_observations=target_observations,
    )
    execution_contract = _materialize_execution_contract(
        draft.execution_route,
        draft.causal_factors,
        choices_by_handle,
        unsafe_outcome,
        context,
        requested_environment_basis,
        stimulus=draft.stimulus,
        target_operation=target_operation,
    )
    criteria = [
        ObservationCriterion.model_validate(item.model_dump(mode="json"))
        for item in getattr(draft.unsafe_outcome, "observation_criteria", ())
    ]
    observation_assessment = (
        assess_observation_criteria(criteria, observation_contract)
        if observation_contract is not None and criteria
        else None
    )
    adversary_draft = getattr(draft, "adversary", None)
    adversary = (
        _materialize_adversary(adversary_draft, draft.stimulus)
        if isinstance(
            adversary_draft,
            (_ContextAdversarialDraft, _ContextFunctionalAdversaryDraft),
        )
        else None
    )
    return (
        BDIGenerationResult(
            defender_vulnerabilities=_materialize_context_vulnerabilities(
                factors,
                context,
            ),
            attacker_bdi=attacker_bdi,
            causal_factors=factors,
            unsafe_outcome=unsafe_outcome,
            execution_contract=execution_contract,
            adversary=adversary,
            observation_criteria=criteria,
            observation_assessment=observation_assessment,
            observation_contract_id=(
                observation_contract.contract_id
                if observation_contract is not None and criteria
                else None
            ),
            observation_contract_digest=(
                observation_contract.content_digest
                if observation_contract is not None and criteria
                else None
            ),
            safe_observable_outcome=draft.unsafe_outcome.safe_observable_outcome,
        ),
        grounding,
    )


def _materialize_normal_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    observation_contract: ObservationContract | None = None,
    *,
    condition_universe: ConditionUniverse | None = None,
    condition_omitted_reason: str | None = None,
) -> BDIGenerationResult:
    """Compile a normal-path draft: semantics and evidence, no execution wire.

    The result carries no execution contract and no executable unsafe-outcome
    condition; nothing is generated and later stripped.  Lineage stays
    compiler-owned: the exact hazard/constraint IDs derive from the immutable
    context.
    """
    choices_by_handle = {choice.handle: choice for choice in choices}
    attacker_bdi = _materialize_context_attacker_bdi(draft, choices_by_handle)
    factors = _materialize_context_factors(draft, choices, choices_by_handle, context)
    outcome = draft.unsafe_outcome
    _normalize_provider_semantic_proposition(outcome, context)
    adversary = _materialize_adversary(draft.adversary, None)
    criteria, contract, assessment = _normal_observation_assessment(
        outcome, observation_contract
    )
    condition, condition_check, discarded_reason = _discriminating_condition_result(
        getattr(outcome, "discriminating_condition", None),
        condition_universe,
        assessment,
    )
    omitted_reason = condition_omitted_reason or discarded_reason
    binding = bind_tool_call_condition(
        condition,
        condition_universe.fact_values if condition_universe is not None else {},
        condition_omitted_reason=omitted_reason,
    )
    return BDIGenerationResult(
        defender_vulnerabilities=_materialize_context_vulnerabilities(
            factors,
            context,
        ),
        attacker_bdi=attacker_bdi,
        causal_factors=factors,
        unsafe_outcome=UnsafeOutcomeDeclaration(
            condition=None,
            semantic_proposition=outcome.semantic_proposition,
            hazard_refs=tuple(item.hazard_id for item in context.hazards),
            constraint_refs=tuple(item.constraint_id for item in context.constraints),
        ),
        adversary=adversary,
        observation_criteria=criteria,
        observation_assessment=assessment,
        observation_contract_id=contract.contract_id if contract is not None else None,
        observation_contract_digest=(
            contract.content_digest if contract is not None else None
        ),
        safe_observable_outcome=outcome.safe_observable_outcome,
        discriminating_condition=condition,
        condition_check=condition_check,
        condition_omitted_reason=omitted_reason,
        tool_call_condition_status=binding.status,
        tool_call_condition=binding.condition,
    )


def _normal_observation_assessment(
    outcome: BaseModel, observation_contract: ObservationContract | None
) -> tuple[
    list[ObservationCriterion],
    ObservationContract | None,
    ObservationAssessment | None,
]:
    criteria = [
        ObservationCriterion.model_validate(item.model_dump(mode="json"))
        for item in outcome.observation_criteria
    ]
    contract = observation_contract or (
        default_observation_contract() if criteria else None
    )
    assessment = (
        assess_observation_criteria(criteria, contract)
        if contract is not None
        else None
    )
    return criteria, contract, assessment


def _materialize_context_attacker_bdi(
    draft: BaseModel,
    choices_by_handle: Mapping[str, _CausalSourceChoice],
) -> AttackerBDI:
    """Compile provider attacker prose and local intention handles."""
    attacker_draft = draft.attacker_bdi
    _validate_intention_factor_handles(attacker_draft, draft.causal_factors)
    return AttackerBDI(
        beliefs=list(attacker_draft.beliefs),
        desires=list(attacker_draft.desires),
        intentions=[
            _materialize_intention(item, choices_by_handle)
            for item in attacker_draft.intentions
        ],
    )


def _materialize_context_factors(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    choices_by_handle: Mapping[str, _CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> list[CausalFactorDeclaration]:
    """Compile causal factors and close their temporal references."""
    factor_order = {
        factor.source_handle: index
        for index, factor in enumerate(draft.causal_factors, start=1)
    }
    return [
        _materialize_causal_factor(
            item,
            choices_by_handle,
            temporal_condition=_resolve_temporal_condition(
                item.temporal_condition,
                item.source_handle,
                choices,
                context,
                factor_order=factor_order,
                binding_scope=f"factor-{factor_order[item.source_handle]}",
            ),
        )
        for item in draft.causal_factors
    ]


def _materialize_context_unsafe_outcome(
    draft: BaseModel,
    context: ScenarioGenerationContext,
    *,
    target_operation: TargetOperationObservation | None = None,
    target_observations: TargetObservationSnapshot | None = None,
) -> tuple[UnsafeOutcomeDeclaration, OutcomeGroundingResolution]:
    """Compile the provider semantic outcome and derive binding state."""
    condition = draft.unsafe_outcome.condition
    condition = _resolve_state_value_subject(condition, _causal_source_choices(context))
    if isinstance(condition, _ContextTemporalConditionWire):
        condition = _resolve_temporal_condition(
            condition,
            "target_action",
            _causal_source_choices(context),
            context,
            factor_order={
                factor.source_handle: index
                for index, factor in enumerate(draft.causal_factors, start=1)
            },
            binding_scope="outcome",
        )
    _normalize_provider_semantic_proposition(draft.unsafe_outcome, context)
    expected_action_kind = _context_expected_action_kind(context, target_operation)
    if expected_action_kind is None:
        # Legacy contexts may not classify the control action, while their
        # executable provider route still carries the explicit action kind.
        expected_action_kind = getattr(draft.execution_route, "action_kind", None)
    proposed_condition = _materialize_provider_condition(condition)
    grounding = resolve_outcome_grounding(
        proposed_condition,
        draft.unsafe_outcome.comparison_evidence,
        _comparison_sources(context, target_observations),
        model_output=expected_action_kind is ExecutionActionKind.model_output,
        proposition=draft.unsafe_outcome.semantic_proposition,
        target_observations=target_observations,
    )
    return (
        UnsafeOutcomeDeclaration(
            condition=grounding.condition,
            semantic_proposition=draft.unsafe_outcome.semantic_proposition,
            hazard_refs=tuple(item.hazard_id for item in context.hazards),
            constraint_refs=tuple(item.constraint_id for item in context.constraints),
        ),
        grounding,
    )


def _comparison_sources(
    context: ScenarioGenerationContext,
    target_observations: TargetObservationSnapshot | None = None,
) -> dict[str, str]:
    """Only supplied rule/action text is value evidence; tool schemas are not policy."""
    sources = {item.constraint_id: item.description for item in context.constraints}
    action = context.target_control_path.control_action
    sources[action.action_id] = action.description
    if target_observations is not None:
        sources.update(target_observations.source_texts())
    return sources


def _materialize_context_vulnerabilities(
    factors: Sequence[CausalFactorDeclaration],
    context: ScenarioGenerationContext,
) -> dict[str, str]:
    """Derive public PM annotations from one causal story.

    Contextual providers explain a process-model flaw only through the exact
    causal-factor source and evidence.  Every supplied PM still appears in
    the legacy public map; a PM without a selected factor receives a
    scenario-scoped marker rather than an assertion that its evidence is
    absent.
    """
    vulnerabilities = {
        belief.element_id: _UNSELECTED_PROCESS_MODEL_MARKER
        for belief in context.target_control_path.process_model_parts
    }
    for factor in factors:
        if factor.kind is CausalFactorKind.process_model_flaw:
            if factor.source_id in vulnerabilities:
                vulnerabilities[factor.source_id] = factor.evidence
    return vulnerabilities


def _materialize_intention(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
) -> str:
    """Attach exact structural identities to one model-authored intention."""
    source_ids = tuple(
        dict.fromkeys(choices[handle].source_id for handle in draft.source_handles)
    )
    return f"{draft.description.strip()} [structural sources: {', '.join(source_ids)}]"


def _materialize_causal_factor(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
    *,
    temporal_condition: SemanticCondition | None = None,
) -> CausalFactorDeclaration:
    """Compile one local causal-source handle into the closed domain record."""
    choice = choices[draft.source_handle]
    evidence_status = draft.evidence_status
    bounded_assumption = getattr(draft, "bounded_assumption", None)
    capability_refs = tuple(getattr(draft, "capability_refs", ()))
    access_refs = tuple(getattr(draft, "access_refs", ()))
    if (
        bounded_assumption is not None
        and evidence_status is CausalEvidenceStatus.structural_failure
        and not capability_refs
        and not access_refs
    ):
        evidence_status = CausalEvidenceStatus.bounded_assumption
    return CausalFactorDeclaration(
        kind=choice.kind,
        source_id=choice.source_id,
        evidence=draft.evidence,
        mechanism=getattr(draft, "mechanism", CausalMechanism.none),
        temporal_condition=(
            temporal_condition
            if temporal_condition is not None
            else getattr(draft, "temporal_condition", None)
        ),
        evidence_status=evidence_status,
        capability_refs=capability_refs,
        access_refs=access_refs,
        bounded_assumption=bounded_assumption,
    )


def assemble_scenario_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    scenario_index: int = 0,
    *,
    scenario_context: ScenarioGenerationContext | None = None,
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
) -> ScenarioSpec:
    """Assemble a ScenarioSpec from the defender BDI and LLM result.

    Merges vulnerability annotations into the defender BDI and combines
    with the attacker BDI. The defender BDI IDs are NOT trusted from the
    LLM — the original deterministic values are used, and vulnerabilities
    are extracted by matching to the original pm_id values.

    Declared causal factors are selected in declared order with their
    evidence descriptions and optional timing; every factor reference is
    validated against the control structure (a ``ValueError`` names the
    invalid causal-factor reference) so unbacked structural presence
    never invents a factor.

    Args:
        defender_bdi: Pre-populated defender BDI (will be mutated in place).
        llm_result: The LLM generation result.
        threat: The structural threat.
        control_structure: The full control structure.
        scenario_index: Zero-based index for scenario ID generation.

    Returns:
        A :class:`ScenarioSpec`.
    """
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    _validate_optional_assembly_context(scenario_context, threat, scenario_index)
    _merge_defender_vulnerabilities(defender_bdi, llm_result)
    causal_factors = _materialize_causal_factors(llm_result)
    _validate_assembled_factors(causal_factors, control_structure, scenario_context)
    # The normal semantics-only wire materializes no contract and no
    # executable condition, so the contract validator does not apply to it.
    # An executable condition marks a historical execution-designed
    # assembly, which must retain its exact contract; a hybrid result (no
    # condition but a supplied contract) keeps the delivery/basis checks.
    if _carries_execution_design(llm_result) or (
        llm_result.execution_contract is not None
    ):
        _validate_assembled_execution_contract(
            llm_result.execution_contract,
            causal_factors,
            scenario_context,
            requested_environment_basis,
        )
    unsafe_condition = _validated_unsafe_condition(
        llm_result, UCAType(slot_parts["ica_type"]), slot_parts["control_action"]
    )
    if scenario_context is not None:
        # Context is the only authoritative source for selected consequence
        # lineage.  The contextual provider wire carries descriptions only;
        # deterministic assembly derives the exact IDs here.
        hazard_refs = [item.hazard_id for item in scenario_context.hazards]
        constraint_refs = [item.constraint_id for item in scenario_context.constraints]
    else:
        hazard_refs, constraint_refs = _unsafe_outcome_refs(llm_result, threat)

    return ScenarioSpec(
        scenario_id=generate_scenario_id(scenario_index),
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller=slot_parts["controller"],
        target_control_action=slot_parts["control_action"],
        ica_type=UCAType(slot_parts["ica_type"]),
        defender_bdi=defender_bdi,
        attacker_bdi=llm_result.attacker_bdi,
        catalog_context=threat.catalog_mappings,
        loss_scenario=threat.loss_scenario,
        causal_factors=causal_factors,
        unsafe_outcome_condition=unsafe_condition,
        unsafe_outcome_semantic_proposition=(
            llm_result.unsafe_outcome.semantic_proposition
            if llm_result.unsafe_outcome is not None
            else None
        ),
        unsafe_outcome_hazard_refs=hazard_refs,
        unsafe_outcome_constraint_refs=constraint_refs,
        scenario_context=scenario_context,
        execution_contract=llm_result.execution_contract,
        adversary=llm_result.adversary,
        observation_criteria=llm_result.observation_criteria,
        observation_assessment=llm_result.observation_assessment,
        observation_contract_id=llm_result.observation_contract_id,
        observation_contract_digest=llm_result.observation_contract_digest,
        safe_observable_outcome=llm_result.safe_observable_outcome,
        discriminating_condition=llm_result.discriminating_condition,
        condition_check=llm_result.condition_check,
        condition_omitted_reason=llm_result.condition_omitted_reason,
        tool_call_condition_status=llm_result.tool_call_condition_status,
        tool_call_condition=llm_result.tool_call_condition,
    )


def _carries_execution_design(llm_result: BDIGenerationResult) -> bool:
    """Return True when the result materialized an executable outcome condition.

    The normal semantics-only wire materializes ``condition=None`` and no
    execution contract.  An executable condition marks a historical
    execution-designed assembly, which must retain its exact contract.
    """
    return (
        llm_result.unsafe_outcome is not None
        and llm_result.unsafe_outcome.condition is not None
    )


def _validate_assembled_execution_contract(
    contract: SemanticExecutionContract | None,
    causal_factors: Sequence[CausalFactor],
    context: ScenarioGenerationContext | None,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> None:
    """Require execution-designed contextual assembly to retain its contract.

    The normal product wire requests no execution design, so its
    semantics-only assembly (no contract, no executable condition) never
    reaches this validator.  An execution-designed contextual assembly
    without a contract is a historical-path bug and fails closed; a supplied
    contract (historical execution callers) still must retain an exact
    delivery/factor binding and the caller's basis.
    """
    if context is None:
        return
    if contract is None:
        raise ValueError("corrected Stage 5 output must include execution_contract")
    _validate_assembled_delivery_factor(contract, causal_factors)
    _validate_assembled_environment_basis(contract, requested_environment_basis)


def _validate_assembled_delivery_factor(
    contract: SemanticExecutionContract,
    causal_factors: Sequence[CausalFactor],
) -> None:
    """Require a contextual delivery to bind to one assembled factor."""
    if contract.delivery is None:
        return
    factor_ids = {
        f"CF-{index}" for index, _factor in enumerate(causal_factors, start=1)
    }
    if contract.delivery.factor_id not in factor_ids:
        raise ValueError(
            "execution contract delivery factor_id must resolve to a declared factor"
        )


def _validate_assembled_environment_basis(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> None:
    """Require the assembled contract to retain the caller's selected basis."""
    if not _assembly_basis_check_applies(contract, requested_environment_basis):
        return
    if not _assembly_basis_matches(contract, requested_environment_basis):
        raise ValueError(
            "execution contract requested_environment_basis does not match "
            "the caller-selected environment basis"
        )


def _assembly_basis_check_applies(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> bool:
    """Return whether assembly supplied enough context to compare the basis."""
    return requested_environment_basis is not None and contract.delivery is not None


def _assembly_basis_matches(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis,
) -> bool:
    """Compare the assembled contract basis with the caller's selected basis."""
    expected_basis = (
        RequestedEnvironmentBasis.target_agnostic
        if not contract.resource_requirements
        else requested_environment_basis
    )
    return contract.requested_environment_basis is expected_basis


def _validate_context_matches_threat(
    context: ScenarioGenerationContext,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Reject an attempt to assemble provider output under different authority."""
    if _context_threat_identity(context) != _threat_identity(threat, scenario_index):
        raise ValueError("scenario context does not match selected structural threat")


def _context_threat_identity(
    context: ScenarioGenerationContext,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the context identity fields used for threat pinning."""
    identity = context.scenario_identity
    return (
        identity.scenario_id,
        identity.ica_id,
        identity.ica_slot_id,
        context.ica.exact_ica_text,
        context.ica.hazardous_context,
        context.ica.loss_consequence,
    )


def _threat_identity(
    threat: StructuralThreat,
    scenario_index: int,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the threat identity in the context comparison order."""
    return (
        generate_scenario_id(scenario_index),
        threat.ica_id,
        threat.ica_slot_id,
        threat.ica_text,
        threat.hazardous_context,
        threat.loss_scenario,
    )


def _validate_optional_assembly_context(
    context: ScenarioGenerationContext | None,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Validate a supplied scenario context before compiling provider output."""
    if context is not None:
        _validate_context_matches_threat(context, threat, scenario_index)


def _merge_defender_vulnerabilities(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
) -> None:
    """Attach provider vulnerability prose to deterministic belief IDs."""
    for belief in defender_bdi.beliefs:
        belief.vulnerability = llm_result.defender_vulnerabilities.get(belief.pm_id, "")


def _materialize_causal_factors(
    llm_result: BDIGenerationResult,
) -> list[CausalFactor]:
    """Compile the declared Stage 5 factor records without inference."""
    return [
        CausalFactor(
            kind=declaration.kind,
            source_id=declaration.source_id,
            description=declaration.evidence,
            declared_timing=declaration.timing,
            evidence_status=declaration.evidence_status,
            capability_refs=declaration.capability_refs,
            access_refs=declaration.access_refs,
            bounded_assumption=declaration.bounded_assumption,
            temporal_condition=declaration.temporal_condition,
            mechanism=declaration.mechanism,
        )
        for declaration in llm_result.causal_factors
    ]


def _validate_assembled_factors(
    causal_factors: list[CausalFactor],
    control_structure: ControlStructure,
    context: ScenarioGenerationContext | None,
) -> None:
    """Validate factor references against structure and optional context."""
    validate_factor_sources(control_structure, causal_factors)
    if context is None:
        return
    validate_factor_evidence(context, causal_factors)
    _validate_context_factor_sources(context, causal_factors)


def _validated_unsafe_condition(
    llm_result: BDIGenerationResult,
    uca_type: UCAType,
    control_action_id: str,
) -> SemanticCondition | None:
    """Validate and return the provider's typed unsafe condition when present.

    The normal product wire materializes no executable condition, so an
    absent condition is the expected normal shape; a supplied condition keeps
    its exact UCA-family validation for historical callers.
    """
    outcome = llm_result.unsafe_outcome
    if outcome is None or outcome.condition is None:
        return None
    _validate_unsafe_outcome_for_target(outcome, uca_type, control_action_id)
    return outcome.condition


def _unsafe_outcome_refs(
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
) -> tuple[list[str], list[str]]:
    """Use validated provider refs or the threat's authoritative fallback refs."""
    outcome = llm_result.unsafe_outcome
    if outcome is None:
        return list(threat.related_hazards), list(threat.related_constraints)
    return list(outcome.hazard_refs), list(outcome.constraint_refs)


def _validate_context_factor_sources(
    context: ScenarioGenerationContext,
    causal_factors: list[CausalFactor],
) -> None:
    """Keep every declared cause inside the selected control-path slice."""
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        path.control_action.action_id,
        *(item.action_id for item in path.related_control_actions),
    }
    for factor in causal_factors:
        if factor.source_id not in allowed:
            raise ValueError(
                f"Causal factor source {factor.source_id!r} is outside the "
                "selected scenario control path."
            )
