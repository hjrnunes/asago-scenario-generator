"""Typed, single-attempt generation stages used by production finalization.

Each ``generate_*_stage`` function owns exactly one Call 0--3 invocation;
validation, retry routing, admission, and persistence remain explicit ports.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Generic, Literal, TypeVar, cast

from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    BehaviorSpec,
    CallName,
    NarrativeLayer,
    ScenarioEnvelope,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ADVERSARIAL_ONLY_THREATS,
)
from asago_scenario_generator.pipeline.generate.actor import (
    ActorDraftV2,
    ActorSemanticDraftError,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    NarrativeDraftV2,
    NarrativeSemanticDraftError,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl as CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
    StageCallEvidence,
    stage_attempt_failure,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.pipeline.semantic_generation import (
    DraftViolation,
    StageAttemptEvidence,
    StageGenerationEvidence,
    _digest,
)


_SEMANTIC_STAGE_COMPLETION_CAPS: dict[CallName, int] = {
    CallName.actor_profile: 4096,
    CallName.narrative: 8192,
    CallName.attack_tree: 8192,
    CallName.behavior_spec: 4096,
}


def _bounded_completion_cap(client: LLMClient, operation_cap: int) -> int:
    """Apply the lower of the semantic operation and operator transport caps."""
    transport_cap = getattr(client, "max_completion_tokens", None)
    if isinstance(transport_cap, int) and transport_cap > 0:
        return min(operation_cap, transport_cap)
    return operation_cap


@dataclass(frozen=True, slots=True, kw_only=True)
class GenerationRequest:
    """Immutable input contract shared by all four generation stages."""

    seed: ScenarioSeed
    profile: CapabilityProfile
    client: LLMClient
    use_case: str
    pinned_entry_point_id: str
    projected_candidate: ProjectedCandidate
    capability_snapshot: CapabilityFactSnapshot
    preferred_entry_point: str | None = None
    excluded_entry_points: tuple[str, ...] = ()
    excluded_patterns: tuple[str, ...] = ()
    excluded_structural_patterns: tuple[str, ...] = ()
    preferred_actor_type: str | None = None
    excluded_actor_types: tuple[str, ...] = ()
    preferred_capability_level: str | None = None
    attack_goal: dict[str, Any] | None = None
    pinned_entry_point: str | None = None
    pinned_technique_ids: tuple[str, ...] = ()
    pinned_technique_names: tuple[str, ...] = ()
    prior_titles: tuple[str, ...] = ()
    run_id: str = ""
    candidate_id: str = ""
    attempt: int = 1
    presentation_fallback: Literal["allow", "forbid"] = "allow"


@dataclass(frozen=True, slots=True)
class PreparedGeneration:
    """Validated identity and immutable projection context for Calls 0--3."""

    request: GenerationRequest
    candidate_id: str
    scenario_id: str
    projection_context: dict[str, Any]


def _split_retry(retry: RetryDirective | None) -> tuple[str | None, str | None]:
    """Split one retry directive into its two mutually exclusive channels.

    Returns ``(semantic_feedback, completion_length_feedback)``: a
    completion-length retry routes its feedback only through the length
    channel, every other retry only through the semantic channel, and a
    first attempt carries no feedback at all.
    """
    if retry is None:
        return None, None
    if retry.reason == StageAttemptFailure.COMPLETION_LENGTH_CODE:
        return None, retry.feedback
    return retry.feedback, None


def _optional_list(values: Any) -> list[Any] | None:
    """Convert a possibly-empty sequence to ``None``, the call contract marker."""
    return list(values) or None


class _AttemptRecordingClient:
    """Transparent client proxy retaining truthful one-attempt evidence."""

    def __init__(
        self,
        client: LLMClient,
        *,
        attempt_index: int = 0,
        retry_class: Literal["length", "semantic"] | None = None,
    ) -> None:
        self._client = client
        self.attempt_index = attempt_index
        self.retry_class = retry_class
        self.invoked = False
        self.system_prompt: str | None = None
        self.user_prompt: str | None = None
        self.result: LLMResult | None = None
        self.request_controls: dict[str, Any] = {}
        self._unstructured_response = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Any = None,
        **kwargs: Any,
    ) -> LLMResult:
        self.invoked = True
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        self._unstructured_response = response_format is None
        max_tokens = kwargs.get("max_completion_tokens")
        if max_tokens is None:
            max_tokens = getattr(self._client, "max_completion_tokens", None)
        request_temperature = kwargs.get("temperature")
        if request_temperature is None:
            request_temperature = getattr(self._client, "temperature", None)
        if not isinstance(max_tokens, int):
            max_tokens = None
        if not isinstance(request_temperature, (int, float)):
            request_temperature = None
        transport_token_cap = getattr(self._client, "max_completion_tokens", None)
        if not isinstance(transport_token_cap, int):
            transport_token_cap = None
        self.request_controls = {
            "response_schema": (
                (
                    "compact-v1"
                    if response_format.__name__.startswith("Compact")
                    else "standard"
                )
                if response_format is not None
                else None
            ),
            "max_completion_tokens": max_tokens,
            "transport_token_cap": transport_token_cap,
            "temperature": request_temperature,
        }
        result = self._client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            **kwargs,
        )
        if result.request_controls:
            self.request_controls = {
                **self.request_controls,
                **result.request_controls,
            }
            result.request_controls = self.request_controls
        else:
            result.request_controls = self.request_controls
        self.result = result
        return self.result

    def failure(
        self,
        call_name: CallName,
        exception: BaseException,
        *,
        code: str | None = None,
        retryable: bool | None = None,
        semantic_evidence: StageGenerationEvidence | None = None,
    ) -> StageAttemptFailure:
        return stage_attempt_failure(
            call_name,
            exception,
            phase=(
                "post_response"
                if self.result is not None
                else "invocation"
                if self.invoked
                else "before_invocation"
            ),
            invoked=self.invoked,
            system_prompt=self.system_prompt,
            user_prompt=self.user_prompt,
            result=self.result,
            raw_response=(
                self.result.content
                if self.result is not None
                and self._unstructured_response
                and isinstance(self.result.content, str)
                else None
            ),
            request_controls=self.request_controls,
            code=code,
            retryable=retryable,
            semantic_evidence=semantic_evidence,
        )


def _attempt_recorder(
    client: LLMClient, retry: RetryDirective | None
) -> _AttemptRecordingClient:
    retry_class = None
    if retry is not None:
        retry_class = (
            "length"
            if retry.reason == StageAttemptFailure.COMPLETION_LENGTH_CODE
            else "semantic"
        )
    return _AttemptRecordingClient(
        client,
        attempt_index=retry.attempt_index if retry is not None else 0,
        retry_class=retry_class,
    )


ArtifactT = TypeVar("ArtifactT")


@dataclass(frozen=True, slots=True)
class _StageResult(Generic[ArtifactT]):
    artifact: ArtifactT
    evidence: StageCallEvidence


@dataclass(frozen=True, slots=True)
class ActorStageResult(_StageResult[ActorProfile]):
    diversity_limitation: str | None = None


@dataclass(frozen=True, slots=True)
class NarrativeStageResult(_StageResult[NarrativeLayer]):
    pass


@dataclass(frozen=True, slots=True)
class TreeStageResult(_StageResult[AttackTree]):
    pass


@dataclass(frozen=True, slots=True)
class BehaviorStageResult(_StageResult[BehaviorSpec]):
    pass


def _evidence(
    call_name: CallName,
    result: LLMResult,
    semantic_evidence: StageGenerationEvidence | None = None,
) -> StageCallEvidence:
    # Late package lookup preserves the established unittest patch surface.
    import asago_scenario_generator.pipeline.generate as generate

    return StageCallEvidence(
        call_name,
        result,
        generate._call_metadata(call_name, result),
        semantic_evidence,
    )


def _semantic_request_digest(
    call_name: CallName, recorder: _AttemptRecordingClient
) -> str:
    return _digest(
        {
            "stage": call_name.value,
            "system_prompt": recorder.system_prompt,
            "user_prompt": recorder.user_prompt,
            "effective_controls": recorder.request_controls,
        }
    )


def _actor_handle_map(draft: Any, actor: ActorProfile | None) -> dict[str, str]:
    if actor is None:
        return {}
    resolved = {
        draft.actor_type_handle: actor.actor_type,
        draft.capability_level_handle: actor.capability_level,
    }
    resolved.update(zip(draft.resource_handles, actor.resources, strict=True))
    return resolved


def _narrative_handle_map(projection_context: dict[str, Any]) -> dict[str, str]:
    return {
        f"s{index}": str(projected_step_id)
        for index, projected_step_id in enumerate(
            projection_context.get("selected_step_ids", ())
        )
    }


def _semantic_attempt_evidence(
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
    result_kind: Literal[
        "accepted",
        "invalid_draft",
        "length_failure",
        "protocol_failure",
        "compiler_failure",
    ],
    violations: tuple[DraftViolation, ...] = (),
    failure_detail: str | None = None,
    warnings: tuple[str, ...] = (),
    finish_reason: str | None = None,
    response_digest: str | None = None,
) -> StageGenerationEvidence:
    result = recorder.result
    if response_digest is None and result is not None:
        response_digest = _digest(result.content)
    accepted = (
        response_digest if result_kind in {"accepted", "compiler_failure"} else None
    )
    lifecycle_stage = {
        CallName.actor_profile: "actor",
        CallName.narrative: "narrative",
        CallName.attack_tree: "tree",
        CallName.behavior_spec: "behavior",
    }[call_name]
    return StageGenerationEvidence(
        stage=lifecycle_stage,
        compiler_name=compiler_name,
        handle_map=handle_map,
        attempts=(
            StageAttemptEvidence(
                attempt_index=recorder.attempt_index,
                request_digest=_semantic_request_digest(call_name, recorder),
                response_digest=response_digest,
                finish_reason=finish_reason or ("stop" if result is not None else None),
                result=result_kind,
                effective_controls=recorder.request_controls,
                validation_violations=violations,
                retry_class=recorder.retry_class,
                failure_detail=failure_detail,
            ),
        ),
        accepted_draft_digest=accepted,
        warnings=warnings,
    )


def _draft_violations(exception: Any) -> tuple[DraftViolation, ...]:
    return tuple(
        DraftViolation(item.code, item.detail)
        for item in getattr(exception, "violations", ())
    )


def _terminalize_length_retry(
    failure: StageAttemptFailure, retry: RetryDirective | None
) -> StageAttemptFailure:
    """Give the second, caller-authorized length attempt its terminal code."""
    if (
        failure.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        and retry is not None
        and retry.reason == StageAttemptFailure.COMPLETION_LENGTH_CODE
    ):
        failure.code = StageAttemptFailure.SEMANTIC_DRAFT_LENGTH_CODE
        failure.retryable = False
    return failure


def _attach_failure_evidence(
    failure: StageAttemptFailure,
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
) -> StageAttemptFailure:
    """Attach bounded semantic evidence to one already-classified attempt."""
    if failure.semantic_evidence is not None:
        return failure
    result_kind = {
        StageAttemptFailure.COMPLETION_LENGTH_CODE: "length_failure",
        StageAttemptFailure.SEMANTIC_DRAFT_LENGTH_CODE: "length_failure",
        StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE: "protocol_failure",
        StageAttemptFailure.SEMANTIC_DRAFT_INVALID_CODE: "invalid_draft",
        StageAttemptFailure.CANONICAL_COMPILATION_CODE: "compiler_failure",
    }.get(failure.code)
    if result_kind is None:
        return failure
    failure.semantic_evidence = _semantic_attempt_evidence(
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        result_kind=cast(Any, result_kind),
        violations=(DraftViolation(failure.code, failure.detail),),
        failure_detail=f"{failure.exception_type}: {failure.detail}",
        finish_reason=failure.finish_reason,
        response_digest=failure.partial_sha256,
    )
    return failure


def _tree_handle_map(
    prepared: PreparedGeneration, narrative: NarrativeLayer
) -> dict[str, str]:
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        derive_canonical_leaf_specs,
    )

    specs = derive_canonical_leaf_specs(
        prepared.projection_context, narrative, prepared.request.profile
    )
    return {spec.leaf_handle: spec.projected_step_ids[0] for spec in specs}


def _behavior_handle_map(
    prepared: PreparedGeneration, tree: AttackTree
) -> dict[str, str]:
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        derive_behavior_handles,
    )

    context = derive_behavior_handles(
        tree, prepared.request.profile, prepared.projection_context
    )
    return {
        **{item.handle: item.action.action_id for item in context.action_handles},
        **{item.handle: item.assertion_id for item in context.assertion_handles},
    }


def prepare_generation(request: GenerationRequest) -> PreparedGeneration:
    """Validate identity inputs and build the shared projection context."""
    from asago_scenario_generator.pipeline.generate.assembly import (
        _build_projection_context,
        _validate_candidate_id,
        _validate_run_id,
        compute_scenario_id,
    )

    candidate_id = request.candidate_id or request.projected_candidate.candidate_id
    if candidate_id != request.projected_candidate.candidate_id:
        raise ValueError(
            f"candidate_id '{candidate_id}' does not match projected candidate "
            f"identity '{request.projected_candidate.candidate_id}'"
        )
    _validate_run_id(request.run_id)
    _validate_candidate_id(candidate_id)
    if request.attempt < 1:
        raise ValueError(f"attempt must be >= 1, got {request.attempt}")

    excluded = list(request.excluded_actor_types)
    if (
        request.seed.threat_id in _ADVERSARIAL_ONLY_THREATS
        and "negligent-insider" not in excluded
    ):
        excluded.append("negligent-insider")
    normalized = replace(request, excluded_actor_types=tuple(excluded))
    return PreparedGeneration(
        request=normalized,
        candidate_id=candidate_id,
        scenario_id=compute_scenario_id(request.run_id, candidate_id, request.attempt),
        projection_context=_build_projection_context(request.projected_candidate),
    )


def generate_actor_stage(
    prepared: PreparedGeneration,
    retry: RetryDirective | None = None,
) -> ActorStageResult:
    """Perform exactly one actor-profile LLM call."""
    import asago_scenario_generator.pipeline.generate as generate

    request = prepared.request
    recorder = _attempt_recorder(request.client, retry)
    semantic_feedback, length_feedback = _split_retry(retry)
    compact_schema = (
        retry.provider_retry_value("response_schema") is not None if retry else False
    )
    max_completion_tokens = _bounded_completion_cap(
        request.client, _SEMANTIC_STAGE_COMPLETION_CAPS[CallName.actor_profile]
    )
    try:
        actor, result, limitation = generate._call_actor_profile(
            request.seed,
            request.profile,
            recorder,
            request.use_case,
            preferred_actor_type=request.preferred_actor_type,
            excluded_actor_types=_optional_list(request.excluded_actor_types),
            preferred_capability_level=request.preferred_capability_level,
            attack_goal=request.attack_goal,
            pinned_technique_ids=_optional_list(request.pinned_technique_ids),
            forced_actor_type=retry.forced_actor_type if retry else None,
            pinned_entry_point=request.pinned_entry_point,
            pinned_entry_point_id=request.pinned_entry_point_id,
            access_feedback=semantic_feedback,
            completion_length_feedback=length_feedback,
            compact_response_schema=compact_schema,
            max_completion_tokens=max_completion_tokens,
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        semantic_evidence = None
        if isinstance(exc, ActorSemanticDraftError):
            code = StageAttemptFailure.SEMANTIC_DRAFT_INVALID_CODE
            retryable = True
            semantic_evidence = _semantic_attempt_evidence(
                call_name=CallName.actor_profile,
                compiler_name="compile_actor_draft:v2",
                recorder=recorder,
                handle_map={},
                result_kind="invalid_draft",
                violations=_draft_violations(exc),
                failure_detail=str(exc),
            )
        elif recorder.result is not None and isinstance(
            recorder.result.content, ActorDraftV2
        ):
            code = StageAttemptFailure.CANONICAL_COMPILATION_CODE
            retryable = False
            semantic_evidence = _semantic_attempt_evidence(
                call_name=CallName.actor_profile,
                compiler_name="compile_actor_draft:v2",
                recorder=recorder,
                handle_map={},
                result_kind="compiler_failure",
                failure_detail=f"{type(exc).__name__}: {exc}",
            )
        else:
            code = None
            retryable = None
            if recorder.invoked:
                from pydantic import ValidationError

                if isinstance(exc, ValidationError):
                    code = StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE
                    retryable = True
                    semantic_evidence = _semantic_attempt_evidence(
                        call_name=CallName.actor_profile,
                        compiler_name="compile_actor_draft:v2",
                        recorder=recorder,
                        handle_map={},
                        result_kind="protocol_failure",
                        violations=(DraftViolation("provider_protocol", str(exc)),),
                        failure_detail=f"{type(exc).__name__}: {exc}",
                    )
        failure = _terminalize_length_retry(
            recorder.failure(
                CallName.actor_profile,
                exc,
                code=code,
                retryable=retryable,
                semantic_evidence=semantic_evidence,
            ),
            retry,
        )
        raise _attach_failure_evidence(
            failure,
            call_name=CallName.actor_profile,
            compiler_name="compile_actor_draft:v2",
            recorder=recorder,
            handle_map={},
        ) from exc
    semantic_evidence = None
    if isinstance(result.content, ActorDraftV2):
        semantic_evidence = _semantic_attempt_evidence(
            call_name=CallName.actor_profile,
            compiler_name="compile_actor_draft:v2",
            recorder=recorder,
            handle_map=_actor_handle_map(result.content, actor),
            result_kind="accepted",
        )
    return ActorStageResult(
        artifact=actor,
        evidence=_evidence(CallName.actor_profile, result, semantic_evidence),
        diversity_limitation=limitation,
    )


def generate_narrative_stage(
    prepared: PreparedGeneration,
    actor: ActorProfile,
    retry: RetryDirective | None = None,
) -> NarrativeStageResult:
    """Perform exactly one narrative LLM call."""
    import asago_scenario_generator.pipeline.generate as generate

    request = prepared.request
    titles = (
        retry.prior_titles
        if retry and retry.prior_titles is not None
        else request.prior_titles
    )
    recorder = _attempt_recorder(request.client, retry)
    semantic_feedback, length_feedback = _split_retry(retry)
    retry_max_tokens = (
        retry.provider_retry_value("max_completion_tokens") if retry else None
    )
    operation_cap = (
        int(retry_max_tokens)
        if isinstance(retry_max_tokens, int)
        else _SEMANTIC_STAGE_COMPLETION_CAPS[CallName.narrative]
    )
    max_completion_tokens = _bounded_completion_cap(request.client, operation_cap)
    try:
        narrative, result = generate._call_narrative(
            request.seed,
            request.profile,
            recorder,
            request.use_case,
            actor_profile=actor,
            preferred_entry_point=request.preferred_entry_point,
            excluded_entry_points=_optional_list(request.excluded_entry_points),
            excluded_patterns=_optional_list(request.excluded_patterns),
            excluded_structural_patterns=_optional_list(
                request.excluded_structural_patterns
            ),
            pinned_entry_point=request.pinned_entry_point,
            pinned_technique_ids=_optional_list(request.pinned_technique_ids),
            prior_titles=_optional_list(titles),
            pinned_entry_point_id=request.pinned_entry_point_id,
            realization_feedback=semantic_feedback,
            completion_length_feedback=length_feedback,
            max_completion_tokens=max_completion_tokens,
            projection_context=prepared.projection_context,
            presentation_fallback_allowed=request.presentation_fallback == "allow",
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        semantic_evidence = None
        handle_map = _narrative_handle_map(prepared.projection_context)
        if isinstance(exc, NarrativeSemanticDraftError):
            code = StageAttemptFailure.SEMANTIC_DRAFT_INVALID_CODE
            retryable = True
            semantic_evidence = _semantic_attempt_evidence(
                call_name=CallName.narrative,
                compiler_name="compile_narrative_draft:v2",
                recorder=recorder,
                handle_map=handle_map,
                result_kind="invalid_draft",
                violations=_draft_violations(exc),
                failure_detail=str(exc),
            )
        elif recorder.result is not None and isinstance(
            recorder.result.content, NarrativeDraftV2
        ):
            code = StageAttemptFailure.CANONICAL_COMPILATION_CODE
            retryable = False
            semantic_evidence = _semantic_attempt_evidence(
                call_name=CallName.narrative,
                compiler_name="compile_narrative_draft:v2",
                recorder=recorder,
                handle_map=handle_map,
                result_kind="compiler_failure",
                failure_detail=f"{type(exc).__name__}: {exc}",
            )
        else:
            code = None
            retryable = None
            if recorder.invoked:
                from pydantic import ValidationError

                if isinstance(exc, ValidationError):
                    code = StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE
                    retryable = True
                    semantic_evidence = _semantic_attempt_evidence(
                        call_name=CallName.narrative,
                        compiler_name="compile_narrative_draft:v2",
                        recorder=recorder,
                        handle_map=handle_map,
                        result_kind="protocol_failure",
                        violations=(DraftViolation("provider_protocol", str(exc)),),
                        failure_detail=f"{type(exc).__name__}: {exc}",
                    )
        failure = _terminalize_length_retry(
            recorder.failure(
                CallName.narrative,
                exc,
                code=code,
                retryable=retryable,
                semantic_evidence=semantic_evidence,
            ),
            retry,
        )
        raise _attach_failure_evidence(
            failure,
            call_name=CallName.narrative,
            compiler_name="compile_narrative_draft:v2",
            recorder=recorder,
            handle_map=handle_map,
        ) from exc
    semantic_evidence = None
    if isinstance(result.content, NarrativeDraftV2):
        warnings = (
            ("presentation_fallback: narrative title was synthesized",)
            if result.content.title is None
            else ()
        )
        semantic_evidence = _semantic_attempt_evidence(
            call_name=CallName.narrative,
            compiler_name="compile_narrative_draft:v2",
            recorder=recorder,
            handle_map=_narrative_handle_map(prepared.projection_context),
            result_kind="accepted",
            warnings=warnings,
        )
    return NarrativeStageResult(
        artifact=narrative,
        evidence=_evidence(CallName.narrative, result, semantic_evidence),
    )


def generate_tree_stage(
    prepared: PreparedGeneration,
    actor: ActorProfile,
    narrative: NarrativeLayer,
    retry: RetryDirective | None = None,
) -> TreeStageResult:
    """Perform exactly one attack-tree LLM call (no hidden parse retry)."""
    import asago_scenario_generator.pipeline.generate as generate

    request = prepared.request
    recorder = _attempt_recorder(request.client, retry)
    semantic_feedback, length_feedback = _split_retry(retry)
    retry_temperature = retry.provider_retry_value("temperature") if retry else None
    max_completion_tokens = _bounded_completion_cap(
        request.client, _SEMANTIC_STAGE_COMPLETION_CAPS[CallName.attack_tree]
    )
    try:
        tree, result = generate._call_attack_tree_once(
            request.seed,
            narrative,
            recorder,
            request.use_case,
            profile=request.profile,
            actor_profile=actor,
            pinned_technique_ids=_optional_list(request.pinned_technique_ids),
            pinned_technique_names=_optional_list(request.pinned_technique_names),
            consistency_feedback=semantic_feedback,
            completion_length_feedback=length_feedback,
            temperature=retry_temperature,
            max_completion_tokens=max_completion_tokens,
            pinned_entry_point_id=request.pinned_entry_point_id,
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure as exc:
        from asago_scenario_generator.pipeline.generate.tree_semantics import (
            AttackTreeDraftV2,
            AttackTreeDraftV3,
        )

        handles = (
            _tree_handle_map(prepared, narrative)
            if recorder.result is not None
            and isinstance(
                recorder.result.content, (AttackTreeDraftV2, AttackTreeDraftV3)
            )
            else {}
        )
        raise _terminalize_length_retry(
            _attach_failure_evidence(
                exc,
                call_name=CallName.attack_tree,
                compiler_name="compile_attack_tree_draft:v2",
                recorder=recorder,
                handle_map=handles,
            ),
            retry,
        )
    except Exception as exc:
        failure = recorder.failure(CallName.attack_tree, exc)
        raise _terminalize_length_retry(failure, retry) from exc
    semantic_evidence = None
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        AttackTreeDraftV2,
        AttackTreeDraftV3,
    )

    if isinstance(result.content, (AttackTreeDraftV2, AttackTreeDraftV3)):
        semantic_evidence = _semantic_attempt_evidence(
            call_name=CallName.attack_tree,
            compiler_name="compile_attack_tree_draft:v2",
            recorder=recorder,
            handle_map=_tree_handle_map(prepared, narrative),
            result_kind="accepted",
        )
    return TreeStageResult(
        artifact=tree,
        evidence=_evidence(CallName.attack_tree, result, semantic_evidence),
    )


def generate_behavior_stage(
    prepared: PreparedGeneration,
    narrative: NarrativeLayer,
    tree: AttackTree,
    retry: RetryDirective | None = None,
) -> BehaviorStageResult:
    """Perform exactly one structured behavior-spec LLM call.

    Both feedback channels are caller-owned. This function routes one supplied
    directive into one provider call and never performs an internal retry.
    """
    import asago_scenario_generator.pipeline.generate as generate

    request = prepared.request
    recorder = _attempt_recorder(request.client, retry)
    semantic_feedback, length_feedback = _split_retry(retry)
    compact_schema = (
        retry.provider_retry_value("response_schema") is not None if retry else False
    )
    max_completion_tokens = _bounded_completion_cap(
        request.client, _SEMANTIC_STAGE_COMPLETION_CAPS[CallName.behavior_spec]
    )
    try:
        behavior, result = generate._call_behavior_spec(
            request.seed,
            narrative,
            tree,
            request.profile,
            recorder,
            request.use_case,
            prepared.scenario_id,
            pinned_technique_ids=_optional_list(request.pinned_technique_ids),
            semantic_feedback=semantic_feedback,
            completion_length_feedback=length_feedback,
            compact_response_schema=compact_schema,
            max_completion_tokens=max_completion_tokens,
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure as exc:
        failure = _terminalize_length_retry(exc, retry)
        raise _attach_failure_evidence(
            failure,
            call_name=CallName.behavior_spec,
            compiler_name="compile_behavior_draft:v2",
            recorder=recorder,
            handle_map={},
        )
    except Exception as exc:
        from asago_scenario_generator.pipeline.generate.behavior_semantics import (
            BehaviorDraftV2,
        )

        failure = recorder.failure(CallName.behavior_spec, exc)
        handles = (
            _behavior_handle_map(prepared, tree)
            if recorder.result is not None
            and isinstance(recorder.result.content, BehaviorDraftV2)
            else {}
        )
        failure = _attach_failure_evidence(
            failure,
            call_name=CallName.behavior_spec,
            compiler_name="compile_behavior_draft:v2",
            recorder=recorder,
            handle_map=handles,
        )
        raise _terminalize_length_retry(failure, retry) from exc
    semantic_evidence = None
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        BehaviorDraftV2,
    )

    if isinstance(result.content, BehaviorDraftV2):
        semantic_evidence = _semantic_attempt_evidence(
            call_name=CallName.behavior_spec,
            compiler_name="compile_behavior_draft:v2",
            recorder=recorder,
            handle_map=_behavior_handle_map(prepared, tree),
            result_kind="accepted",
        )
    return BehaviorStageResult(
        artifact=behavior,
        evidence=_evidence(CallName.behavior_spec, result, semantic_evidence),
    )


def assemble_final_envelope(
    prepared: PreparedGeneration,
    actor: ActorProfile,
    narrative: NarrativeLayer,
    tree: AttackTree,
    behavior: BehaviorSpec,
    evidence: tuple[StageCallEvidence, ...],
    *,
    notes: tuple[str, ...] = (),
) -> ScenarioEnvelope:
    """Assemble and traceability-check a final envelope without persistence."""
    import asago_scenario_generator.pipeline.generate as generate
    from asago_scenario_generator.pipeline.generate.assembly import (
        ProjectionTraceabilityError,
        SourceInfluenceProvenanceError,
    )
    from asago_scenario_generator.pipeline.projection_validation import (
        validate_projection_traceability,
    )

    request = prepared.request
    envelope = generate._assemble_envelope(
        seed=request.seed,
        profile=request.profile,
        narrative=narrative,
        attack_tree=tree,
        behavior_spec=behavior,
        call_metadata_list=[item.metadata for item in evidence],
        model_name=request.client.model,
        use_case=request.use_case,
        notes=list(notes),
        actor_profile=actor,
        pinned_technique_ids=_optional_list(request.pinned_technique_ids),
        pinned_entry_point=request.pinned_entry_point,
        pinned_entry_point_id=request.pinned_entry_point_id,
        run_id=request.run_id,
        candidate_id=prepared.candidate_id,
        attempt=request.attempt,
        projected_candidate=request.projected_candidate,
        capability_snapshot=request.capability_snapshot,
    )
    result = validate_projection_traceability(envelope)
    if not result.valid:
        raise ProjectionTraceabilityError(
            result=result,
            scenario_id=envelope.scenario_id,
            seed_id=request.seed.seed_id,
        )
    # Source-influence provenance qualification (Wave 2 slice 5, fail-closed).
    # Assembly always attaches the provenance block, and the gate rejects
    # any envelope whose qualification fails.
    from asago_scenario_generator.pipeline.source_influence import (
        validate_source_influence_provenance,
    )

    provenance_result = validate_source_influence_provenance(envelope)
    if not provenance_result.valid:
        raise SourceInfluenceProvenanceError(
            result=provenance_result,
            scenario_id=envelope.scenario_id,
            seed_id=request.seed.seed_id,
        )
    return envelope
