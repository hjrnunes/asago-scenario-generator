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
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticCondition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    SemanticExecutionContract,
    ExecutionTargetProfile,
    RequestedEnvironmentBasis,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
    validate_factor_evidence,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    DefenderBDI,
    ScenarioSpec,
    ThreatSource,
)


from .._constants import PROMPTS_DIR
from ..condition_family import ConditionFamily
from ..condition_check import (
    ConditionUniverse,
    build_condition_universe,
)
from ..content_surface import ContentSurfaceFacts
from ..target_observations import TargetObservationSnapshot
from .wire import (
    BDIGenerationResult,
    _CausalSourceChoice,
)
from .sources import (
    _action_duration_eligible,
    _causal_source_choices,
    _context_expected_action_kind,
)
from .conditions import (
    _normalize_legacy_temporal_fields,
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
from .validate import (
    _NormalDraftCheck,
    _validate_context_provider_payload,
    _validate_normal_provider_payload,
    _validate_unsafe_outcome_for_target,
)
from .feedback import (
    _context_validation_retry_feedback,
    _normal_validation_retry_feedback,
)
from .prompt_view import (
    build_context_bdi_prompts,
)
from .compile import (
    _materialize_context_bdi,
    _materialize_normal_context_bdi,
)


_LENGTH_RETRY_MAX_COMPLETION_TOKENS = 2048
_LENGTH_RETRY_PROMPT = (
    "\n\nThe prior response was truncated. Return only a concise "
    "schema-matching response with no explanation."
)
_LENGTH_RETRY_EXHAUSTED_PREFIX = (
    "BDI generation retry exhausted after LengthFinishReasonError:"
)


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


def _is_length_finish_reason_error(error: str | None) -> bool:
    """Return whether a safe-call error came from completion length exhaustion."""
    if error is None:
        return False
    error_type, _, _message = error.partition(":")
    return error_type == "LengthFinishReasonError"


def is_bdi_length_retry_exhausted(error: str | None) -> bool:
    """Return whether both bounded structured-output length attempts failed."""
    return bool(error and error.startswith(_LENGTH_RETRY_EXHAUSTED_PREFIX))


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
