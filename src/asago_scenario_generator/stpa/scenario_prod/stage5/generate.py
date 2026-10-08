"""Stage 5 provider call for both paths: plan, call, and publish.

``generate_bdi_for_context`` renders the semantics-only request, makes the
one provider call with its bounded length retry, and compiles and records
the reply.
"""

from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace
from pathlib import Path
from collections.abc import Mapping
from typing import Callable

from pydantic import (
    BaseModel,
)

from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    parse_llm_result,
    strip_json_fence,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)


from .._constants import PROMPTS_DIR
from ..condition_family import ConditionFamily
from ..condition_check import (
    ConditionCheckOutcome,
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
)
from .condition_routing import route_without_condition
from .records import (
    _write_stage5_normalization_record,
)
from .schema import (
    _scenario_semantics_payload_type,
)
from .validate import (
    _NormalDraftCheck,
    _validate_normal_provider_payload,
)
from .feedback import (
    _normal_validation_retry_feedback,
)
from .issues import CONDITION_FAILURE_CODES, IssueCode, ValidationIssue, issues_of
from .prompt_view import (
    build_context_bdi_prompts,
)
from .compile import (
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


def generate_bdi_for_context(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_5",
    step: str = "bdi_generation",
    temperature: float = DEFAULT_TEMPERATURE,
    target_operation: TargetOperationObservation | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    observation_contract: ObservationContract | None = None,
    condition_family: ConditionFamily | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Generate one Stage 5 scenario-semantics result.

    The response requests scenario semantics and causal evidence only: the
    scenario handoff carries no stimulus, route, or executable condition, so
    no artifact-feasibility gate runs. ``condition_family`` is an optional
    code-derived hint rendered with the discriminating-condition
    instructions; it never enters the context.
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
    return _generate_semantics(
        llm_client,
        scenario_context,
        choices,
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


def _generate_semantics(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    choices: tuple[_CausalSourceChoice, ...],
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
    condition_family: ConditionFamily | None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Request, validate, and compile scenario semantics and evidence only.

    The supplied target facts (``target_operation`` and
    ``target_observations``) are semantic grounding, not execution design:
    the prompt renders them so the semantic proposition can name the
    documented operation and the observed record values it acts on.
    """
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
        observation_contract=observation_contract,
        condition_family=condition_family,
        condition_universe=condition_universe,
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
            condition_universe=condition_universe,
        )
        checks.append(check)
        return check.draft

    def validate_without_condition(
        value: BaseModel, contract: ObservationContract, failure_code: str
    ) -> BaseModel:
        """Validate a draft without its condition and route it off a command attempt.

        A routed draft is validated again as a whole; when that fails the
        unrouted draft publishes, so the routing never loses a scenario.
        """
        draft = validate(value, condition_required=False)
        first = checks[-1]
        routed = route_without_condition(draft, contract, failure_code)
        if routed is None:
            return draft
        try:
            final = validate(routed.draft, condition_required=False)
        except (TypeError, ValueError):
            return draft
        checks[-1] = replace(
            checks[-1],
            normalizations=(
                *first.normalizations,
                *routed.normalizations,
                *checks[-1].normalizations,
            ),
            route=routed.route,
        )
        return final

    def finish(
        draft: BaseModel | None,
        error: str | None,
        final_llm_result: object,
        issues: tuple[ValidationIssue, ...],
    ) -> tuple[BDIGenerationResult | None, str | None]:
        condition_omitted_reason: str | None = None
        if (
            error is not None
            and observation_contract is not None
            and condition_universe.grounded
        ):
            # The condition must never be the reason a scenario is lost: after
            # the one correction, a draft that passes without its condition is
            # published without one.
            failure_code = _condition_failure_code(issues)
            recovered = _draft_without_condition(
                final_llm_result,
                response_format,
                lambda value: validate_without_condition(
                    value, observation_contract, failure_code
                ),
            )
            if recovered is not None:
                route = next(
                    check.route for check in checks if check.draft is recovered
                )
                condition_omitted_reason = _condition_omitted_reason(issues, route)
                draft, error = recovered, None
        published = next((check for check in checks if check.draft is draft), None)
        result, error = _finish_normal_context_bdi(
            draft,
            error,
            choices,
            scenario_context,
            observation_contract,
            condition_universe=condition_universe,
            condition_omitted_reason=condition_omitted_reason,
            condition_outcome=(
                published.condition_outcome if published is not None else None
            ),
        )
        if result is not None:
            _write_stage5_normalization_record(
                published.normalizations, scenario_context, run_dir
            )
        return result, error

    draft, error, final_llm_result, issues = _call_bdi_with_bounded_length_retry(
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
    return finish(draft, error, final_llm_result, issues)


def _finish_normal_context_bdi(
    draft: BaseModel | None,
    error: str | None,
    choices: tuple[_CausalSourceChoice, ...],
    context: ScenarioGenerationContext,
    observation_contract: ObservationContract | None = None,
    *,
    condition_universe: ConditionUniverse | None = None,
    condition_omitted_reason: str | None = None,
    condition_outcome: ConditionCheckOutcome | None = None,
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
                condition_outcome=condition_outcome,
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
    validation_retry_feedback: Callable[[Exception], str],
    slot_id: str | None = None,
    scenario_id: str | None = None,
    result_validator: Callable[[BaseModel], BaseModel | None] | None = None,
) -> tuple[BaseModel | None, str | None, object, tuple[ValidationIssue, ...]]:
    """Call the closed Stage 5 contract with its one length-only retry.

    Returns the draft, the error, the provider result of the last attempt
    (``None`` when no response arrived), and the issues the last attempt's
    failure carried.
    """
    policy = CorrectionPolicy(
        validation_retries=1,
        feedback=validation_retry_feedback,
        include_schema=False,
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
            response_parser=lambda value, _cleanup: _parse_context_bdi_result(
                value, response_format
            ),
        )

    first = call(user_prompt, None)
    if not _is_length_finish_reason_error(first.error):
        return first.value, first.error, first.result, issues_of(first.failure)
    retry = call(
        user_prompt + _LENGTH_RETRY_PROMPT, _LENGTH_RETRY_MAX_COMPLETION_TOKENS
    )
    if retry.error is None:
        return retry.value, None, retry.result, ()
    return (
        None,
        f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry.error}",
        retry.result,
        issues_of(retry.failure),
    )


def _parse_context_bdi_result(result, response_format: type[BaseModel]) -> BaseModel:
    """Parse the contextual provider payload without compiler-owned fields.

    Route/factor migration is deliberately not performed: the context wire
    contract exposes no route, factor-route binding or delivery selector.
    """
    content = result.content
    if isinstance(content, BaseModel):
        payload = content.model_dump(mode="json")
    elif isinstance(content, Mapping):
        payload = dict(content)
    elif isinstance(content, str):
        payload = json.loads(strip_json_fence(content))
    else:
        return parse_llm_result(result, response_format)
    return response_format.model_validate(payload)


def _condition_failure_code(issues: tuple[ValidationIssue, ...]) -> str:
    """Return the stable code of the condition failure the final attempt raised."""

    raised = {issue.code for issue in issues}
    if IssueCode.discriminating_condition_missing in raised:
        return IssueCode.discriminating_condition_missing.value
    return next(
        (item.value for item in CONDITION_FAILURE_CODES if item in raised),
        "discriminating_condition_invalid",
    )


_ROUTE_NOTES = {
    None: "the scenario is published without a condition.",
    "reply": (
        "the scenario is published without a condition and its claim moved "
        "from command_attempt to reply."
    ),
    "analytical_only": (
        "the response declares no reply criterion the contract supports, so "
        "the command_attempt claim cannot run without its condition and the "
        "scenario is published as analytical_only."
    ),
}


def _condition_omitted_reason(
    issues: tuple[ValidationIssue, ...], route: str | None = None
) -> str:
    """Return the code-owned publication note for a condition that failed.

    The exact failure text stays in the Stage 5 call log; the note names only
    the stable code of the issue the final attempt raised, so published prose
    carries no raw validator output. A routed scenario names where it went.
    """

    return (
        f"The discriminating condition failed validation after one correction "
        f"({_condition_failure_code(issues)}); {_ROUTE_NOTES[route]}"
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
            payload = json.loads(strip_json_fence(content))
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
