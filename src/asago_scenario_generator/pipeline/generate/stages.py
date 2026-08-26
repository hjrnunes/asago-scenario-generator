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
from asago_scenario_generator.pipeline.generate.actor_semantics import (
    ActorDraftV2,
    ActorDraftV3,
    ActorSemanticDraftError,
)
from asago_scenario_generator.pipeline.generate.narrative_semantics import (
    NarrativeDraftV2,
    NarrativeDraftV3,
    NarrativeSemanticDraftError,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl as CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
    StageCallEvidence,
    stage_attempt_failure,
)
from asago_scenario_generator.pipeline.projection_contracts import (
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


def _resolved_int_control(
    requested: Any, client: LLMClient, attribute: str
) -> int | None:
    """Resolve one optional integer control against the client default."""
    value = requested if requested is not None else getattr(client, attribute, None)
    return value if isinstance(value, int) else None


def _resolved_temperature(requested: Any, client: LLMClient) -> float | None:
    """Resolve the optional temperature control against the client default."""
    value = requested if requested is not None else getattr(client, "temperature", None)
    return value if isinstance(value, (int, float)) else None


def _response_schema_label(response_format: Any) -> str | None:
    """Provider-facing response-schema label, or None for unstructured calls."""
    if response_format is None:
        return None
    return (
        "compact-v1" if response_format.__name__.startswith("Compact") else "standard"
    )


def _merged_controls(base: dict[str, Any], result: LLMResult) -> dict[str, Any]:
    """Merge provider-returned controls, mirroring them onto the result."""
    if result.request_controls:
        merged = {**base, **result.request_controls}
        result.request_controls = merged
        return merged
    result.request_controls = base
    return base


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
        max_tokens = _resolved_int_control(
            kwargs.get("max_completion_tokens"),
            self._client,
            "max_completion_tokens",
        )
        request_temperature = _resolved_temperature(
            kwargs.get("temperature"), self._client
        )
        transport_token_cap = _resolved_int_control(
            None, self._client, "max_completion_tokens"
        )
        self.request_controls = {
            "response_schema": _response_schema_label(response_format),
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
        self.request_controls = _merged_controls(self.request_controls, result)
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
    if isinstance(draft, ActorDraftV3):
        resolved = {
            draft.actor_choice_handle: f"{actor.actor_type}:{actor.capability_level}"
        }
    else:
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


def _retry_prior_titles(
    request: GenerationRequest, retry: RetryDirective | None
) -> tuple[str, ...]:
    """Retry-owned prior titles when supplied, else the request inventory."""
    if retry is not None and retry.prior_titles is not None:
        return retry.prior_titles
    return request.prior_titles


def _operation_token_cap(retry: RetryDirective | None, default: int) -> int:
    """Retry-authorized completion cap when supplied, else the stage cap."""
    retry_max_tokens = (
        retry.provider_retry_value("max_completion_tokens") if retry else None
    )
    if isinstance(retry_max_tokens, int):
        return int(retry_max_tokens)
    return default


def _compact_schema_requested(retry: RetryDirective | None) -> bool:
    """True when the retry directive authorizes the compact response schema."""
    if retry is None:
        return False
    return retry.provider_retry_value("response_schema") is not None


def _invalid_draft_evidence(
    exc: Exception,
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
    semantic_error_type: type[Exception],
) -> StageGenerationEvidence | None:
    """Semantic-evidence record for a semantic draft error, or None."""
    if not isinstance(exc, semantic_error_type):
        return None
    return _semantic_attempt_evidence(
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        result_kind="invalid_draft",
        violations=_draft_violations(exc),
        failure_detail=str(exc),
    )


def _compiler_failure_evidence(
    exc: Exception,
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
    draft_types: tuple[type, ...],
) -> StageGenerationEvidence | None:
    """Semantic-evidence record for a canonical-compilation failure, or None."""
    if recorder.result is None or not isinstance(recorder.result.content, draft_types):
        return None
    return _semantic_attempt_evidence(
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        result_kind="compiler_failure",
        failure_detail=f"{type(exc).__name__}: {exc}",
    )


def _protocol_failure_evidence(
    exc: Exception,
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
) -> StageGenerationEvidence | None:
    """Semantic-evidence record for a provider-protocol violation, or None."""
    if not recorder.invoked:
        return None
    from pydantic import ValidationError

    if not isinstance(exc, ValidationError):
        return None
    return _semantic_attempt_evidence(
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        result_kind="protocol_failure",
        violations=(DraftViolation("provider_protocol", str(exc)),),
        failure_detail=f"{type(exc).__name__}: {exc}",
    )


def _classify_stage_exception(
    exc: Exception,
    *,
    call_name: CallName,
    compiler_name: str,
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
    semantic_error_type: type[Exception],
    draft_types: tuple[type, ...],
) -> tuple[str | None, bool | None, StageGenerationEvidence | None]:
    """Map one stage exception to (code, retryable, semantic evidence)."""
    evidence = _invalid_draft_evidence(
        exc,
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        semantic_error_type=semantic_error_type,
    )
    if evidence is not None:
        return StageAttemptFailure.SEMANTIC_DRAFT_INVALID_CODE, True, evidence
    evidence = _compiler_failure_evidence(
        exc,
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
        draft_types=draft_types,
    )
    if evidence is not None:
        return StageAttemptFailure.CANONICAL_COMPILATION_CODE, False, evidence
    evidence = _protocol_failure_evidence(
        exc,
        call_name=call_name,
        compiler_name=compiler_name,
        recorder=recorder,
        handle_map=handle_map,
    )
    if evidence is not None:
        return StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE, True, evidence
    return None, None, None


def _actor_accepted_evidence(
    recorder: _AttemptRecordingClient,
    actor: ActorProfile,
    draft: Any,
) -> StageGenerationEvidence | None:
    """Accepted-draft evidence for an actor response, or None."""
    if not isinstance(draft, (ActorDraftV2, ActorDraftV3)):
        return None
    return _semantic_attempt_evidence(
        call_name=CallName.actor_profile,
        compiler_name="compile_actor_draft:v3",
        recorder=recorder,
        handle_map=_actor_handle_map(draft, actor),
        result_kind="accepted",
    )


def _narrative_accepted_evidence(
    recorder: _AttemptRecordingClient,
    handle_map: dict[str, str],
    draft: Any,
) -> StageGenerationEvidence | None:
    """Accepted-draft evidence for a narrative response, or None."""
    if not isinstance(draft, (NarrativeDraftV2, NarrativeDraftV3)):
        return None
    warnings = (
        ("presentation_fallback: narrative title was synthesized",)
        if draft.title is None
        else ()
    )
    return _semantic_attempt_evidence(
        call_name=CallName.narrative,
        compiler_name="compile_narrative_draft:v3",
        recorder=recorder,
        handle_map=handle_map,
        result_kind="accepted",
        warnings=warnings,
    )


def _tree_handles_for_result(
    prepared: PreparedGeneration,
    narrative: NarrativeLayer,
    recorder: _AttemptRecordingClient,
) -> dict[str, str]:
    """Tree handle map when the recorder holds a compiled draft, else empty."""
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        AttackTreeDraftV2,
        AttackTreeDraftV3,
    )

    if recorder.result is not None and isinstance(
        recorder.result.content, (AttackTreeDraftV2, AttackTreeDraftV3)
    ):
        return _tree_handle_map(prepared, narrative)
    return {}


def _tree_accepted_evidence(
    prepared: PreparedGeneration,
    narrative: NarrativeLayer,
    recorder: _AttemptRecordingClient,
    result: LLMResult,
) -> StageGenerationEvidence | None:
    """Accepted-draft evidence for a tree response, or None."""
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        AttackTreeDraftV2,
        AttackTreeDraftV3,
    )

    if not isinstance(result.content, (AttackTreeDraftV2, AttackTreeDraftV3)):
        return None
    return _semantic_attempt_evidence(
        call_name=CallName.attack_tree,
        compiler_name="compile_attack_tree_draft:v2",
        recorder=recorder,
        handle_map=_tree_handle_map(prepared, narrative),
        result_kind="accepted",
    )


def _behavior_handles_for_result(
    prepared: PreparedGeneration,
    tree: AttackTree,
    recorder: _AttemptRecordingClient,
) -> dict[str, str]:
    """Behavior handle map when the recorder holds a compiled draft, else empty."""
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        BehaviorDraftV2,
    )

    if recorder.result is not None and isinstance(
        recorder.result.content, BehaviorDraftV2
    ):
        return _behavior_handle_map(prepared, tree)
    return {}


def _behavior_accepted_evidence(
    prepared: PreparedGeneration,
    tree: AttackTree,
    recorder: _AttemptRecordingClient,
    result: LLMResult,
) -> StageGenerationEvidence | None:
    """Accepted-draft evidence for a behavior response, or None."""
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        BehaviorDraftV2,
    )

    if not isinstance(result.content, BehaviorDraftV2):
        return None
    return _semantic_attempt_evidence(
        call_name=CallName.behavior_spec,
        compiler_name="compile_behavior_draft:v2",
        recorder=recorder,
        handle_map=_behavior_handle_map(prepared, tree),
        result_kind="accepted",
    )


def _resolved_candidate_id(request: GenerationRequest) -> str:
    """The request candidate id validated against the projected identity."""
    candidate_id = request.candidate_id or request.projected_candidate.candidate_id
    if candidate_id != request.projected_candidate.candidate_id:
        raise ValueError(
            f"candidate_id '{candidate_id}' does not match projected candidate "
            f"identity '{request.projected_candidate.candidate_id}'"
        )
    return candidate_id


def _normalize_excluded_actor_types(
    request: GenerationRequest,
) -> GenerationRequest:
    """Append the mandatory adversarial-only actor exclusion when applicable."""
    excluded = list(request.excluded_actor_types)
    if (
        request.seed.threat_id in _ADVERSARIAL_ONLY_THREATS
        and "negligent-insider" not in excluded
    ):
        excluded.append("negligent-insider")
    return replace(request, excluded_actor_types=tuple(excluded))


def prepare_generation(request: GenerationRequest) -> PreparedGeneration:
    """Validate identity inputs and build the shared projection context."""
    from asago_scenario_generator.pipeline.generate.assembly import (
        _build_projection_context,
        _validate_candidate_id,
        _validate_run_id,
        compute_scenario_id,
    )
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        validate_tree_projection_realizability,
    )

    candidate_id = _resolved_candidate_id(request)
    _validate_run_id(request.run_id)
    _validate_candidate_id(candidate_id)
    if request.attempt < 1:
        raise ValueError(f"attempt must be >= 1, got {request.attempt}")

    normalized = _normalize_excluded_actor_types(request)
    projection_context = _build_projection_context(request.projected_candidate)
    validate_tree_projection_realizability(projection_context, request.profile)
    return PreparedGeneration(
        request=normalized,
        candidate_id=candidate_id,
        scenario_id=compute_scenario_id(request.run_id, candidate_id, request.attempt),
        projection_context=projection_context,
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
    compact_schema = _compact_schema_requested(retry)
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
        code, retryable, semantic_evidence = _classify_stage_exception(
            exc,
            call_name=CallName.actor_profile,
            compiler_name="compile_actor_draft:v3",
            recorder=recorder,
            handle_map={},
            semantic_error_type=ActorSemanticDraftError,
            draft_types=(ActorDraftV2, ActorDraftV3),
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
            compiler_name="compile_actor_draft:v3",
            recorder=recorder,
            handle_map={},
        ) from exc
    semantic_evidence = _actor_accepted_evidence(recorder, actor, result.content)
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
    titles = _retry_prior_titles(request, retry)
    recorder = _attempt_recorder(request.client, retry)
    semantic_feedback, length_feedback = _split_retry(retry)
    operation_cap = _operation_token_cap(
        retry, _SEMANTIC_STAGE_COMPLETION_CAPS[CallName.narrative]
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
        handle_map = _narrative_handle_map(prepared.projection_context)
        code, retryable, semantic_evidence = _classify_stage_exception(
            exc,
            call_name=CallName.narrative,
            compiler_name="compile_narrative_draft:v3",
            recorder=recorder,
            handle_map=handle_map,
            semantic_error_type=NarrativeSemanticDraftError,
            draft_types=(NarrativeDraftV2, NarrativeDraftV3),
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
            compiler_name="compile_narrative_draft:v3",
            recorder=recorder,
            handle_map=handle_map,
        ) from exc
    semantic_evidence = _narrative_accepted_evidence(
        recorder,
        _narrative_handle_map(prepared.projection_context),
        result.content,
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
        handles = _tree_handles_for_result(prepared, narrative, recorder)
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
    semantic_evidence = _tree_accepted_evidence(prepared, narrative, recorder, result)
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
    compact_schema = _compact_schema_requested(retry)
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
        failure = recorder.failure(CallName.behavior_spec, exc)
        handles = _behavior_handles_for_result(prepared, tree, recorder)
        failure = _attach_failure_evidence(
            failure,
            call_name=CallName.behavior_spec,
            compiler_name="compile_behavior_draft:v2",
            recorder=recorder,
            handle_map=handles,
        )
        raise _terminalize_length_retry(failure, retry) from exc
    semantic_evidence = _behavior_accepted_evidence(prepared, tree, recorder, result)
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:27:21Z","module_hash":"7816f21c118568caa1def3d3d13bb4fab1c4dc4dffe448ce7e836ef2bbc2b806","source_sha256":"0ef555ff95b4af1947bb5fdef75edc2383b780d5bf9c056d4ce40f21680923e9","functions":[{"id":"func/_bounded_completion_cap","name":"_bounded_completion_cap","line":63,"end_line":68,"hash":"296d61c333f6a68bba46e4beb3430e6b0b7c2ebfbee96df257a492b32f811fe7"},{"id":"func/_split_retry","name":"_split_retry","line":110,"end_line":122,"hash":"503e9d5cedb0913d5443b6c2807138ce0bdefc8d015ed63674126699ae4cda29"},{"id":"func/_optional_list","name":"_optional_list","line":125,"end_line":127,"hash":"89b18d84606da6772a69ee1b8f603e73fb92fa3aa267cb6f9db3b0684eba2286"},{"id":"func/_resolved_int_control","name":"_resolved_int_control","line":130,"end_line":135,"hash":"306c436d6884a99bc2809af022210554054f315a8a864d790e659c9c5821c33e"},{"id":"func/_resolved_temperature","name":"_resolved_temperature","line":138,"end_line":141,"hash":"a221f63b589ef9e5b5ee324757da9179115874e5be59a0a978513fd4e3ae98da"},{"id":"func/_response_schema_label","name":"_response_schema_label","line":144,"end_line":150,"hash":"24d3c68b963421153ed00f9584ff1b4c90022bf4f6088675be2138da0b240dd1"},{"id":"func/_merged_controls","name":"_merged_controls","line":153,"end_line":160,"hash":"22a17aac8ddfb7ac8e3b6944e9a553a0ca51812f3b07dcb7c8f6d5c43a3e7267"},{"id":"func/_AttemptRecordingClient.__init__","name":"__init__","line":166,"end_line":181,"hash":"14282e19d31911a03561685334d95ba32143b49782180d6086c42c75846dc84b"},{"id":"func/_AttemptRecordingClient.__getattr__","name":"__getattr__","line":183,"end_line":184,"hash":"f0bf728eabed9535fe2e2e3e8d8c8e9c489f6487b17d10f2e2f59282a0f64030"},{"id":"func/_AttemptRecordingClient.complete","name":"complete","line":186,"end_line":222,"hash":"58fbf2befd71adbcf07c4a276c574e79dd7bbdf4eec0979e84df526277ac241c"},{"id":"func/_AttemptRecordingClient.failure","name":"failure","line":224,"end_line":258,"hash":"83a6467c9adf6dd13bbe28eb14d8c9a544502fb789b2e2508a6ff42d74a986c5"},{"id":"func/_attempt_recorder","name":"_attempt_recorder","line":261,"end_line":275,"hash":"e60ff23891a2012426e0194202551a234de04ad265706b5570ff1f78a7f1343a"},{"id":"func/_evidence","name":"_evidence","line":307,"end_line":320,"hash":"749732c6c6b42ac6fab1f0f43def6e5540665fa6da05f4dfb0abdb7e44808462"},{"id":"func/_semantic_request_digest","name":"_semantic_request_digest","line":323,"end_line":333,"hash":"ab811f0524c96f5a150bf752eaeede7b8b62878df55e676bb9b7af40b3138dc3"},{"id":"func/_actor_handle_map","name":"_actor_handle_map","line":336,"end_line":349,"hash":"e8350deae092c67ebcb73bd59bdd9ed59687196129fd41f1bb6769324aa5bf20"},{"id":"func/_narrative_handle_map","name":"_narrative_handle_map","line":352,"end_line":358,"hash":"e67b172fda21e17c38817915fb2676fa64792abbad6fa6529d0744985e5dd6e1"},{"id":"func/_semantic_attempt_evidence","name":"_semantic_attempt_evidence","line":361,"end_line":411,"hash":"06e0298b5e151ddd54f3af2de1f606ee9d1d59841344bd06a815101d0c6bae50"},{"id":"func/_draft_violations","name":"_draft_violations","line":414,"end_line":418,"hash":"8774e4dfb55f59feee760e0e1ca83815d322af2a608545a91721ebb398776a8a"},{"id":"func/_terminalize_length_retry","name":"_terminalize_length_retry","line":421,"end_line":432,"hash":"10e53e842b33e3c82b66c6440e4b43d2b4768ca887152b883f8cf8bc02ccb3d0"},{"id":"func/_attach_failure_evidence","name":"_attach_failure_evidence","line":435,"end_line":466,"hash":"e0676278ce486c420c7f0716a1a1cb793c62e123625d5356bdaba1d3aca6d032"},{"id":"func/_tree_handle_map","name":"_tree_handle_map","line":469,"end_line":479,"hash":"15226b7a18581a0491d65b093d61d131b26a2338d566e5b6c782c9699261f79a"},{"id":"func/_behavior_handle_map","name":"_behavior_handle_map","line":482,"end_line":495,"hash":"1e7ca1103c4a5bf4dee12e740d6f8a3c3bf94f585d8bb09f12b5b759332d2ebf"},{"id":"func/_retry_prior_titles","name":"_retry_prior_titles","line":498,"end_line":504,"hash":"9990f68a103ff40593f8211c303672fe4a19a25467f76a9c983c891684d88f95"},{"id":"func/_operation_token_cap","name":"_operation_token_cap","line":507,"end_line":514,"hash":"19e8bfbd11e7f4458b9ce59c053af3821437af952604e8652efa08023bd75fdc"},{"id":"func/_compact_schema_requested","name":"_compact_schema_requested","line":517,"end_line":521,"hash":"c98076a015e869888e85099796eb0745aca5a8186e07c4e4a8be5993a8bd09bc"},{"id":"func/_invalid_draft_evidence","name":"_invalid_draft_evidence","line":524,"end_line":544,"hash":"bf738a787c949e44444ab7a48e33ae660b97ab5a2d834d361c46da69de878946"},{"id":"func/_compiler_failure_evidence","name":"_compiler_failure_evidence","line":547,"end_line":566,"hash":"245d417a674b79669d365042bfbbb908c012c3476a7d8e4c941a1399712ea24d"},{"id":"func/_protocol_failure_evidence","name":"_protocol_failure_evidence","line":569,"end_line":592,"hash":"243f5282a08154fbfc867bc24afa36050ddc98128f4c992c40bd0e2d16733c50"},{"id":"func/_classify_stage_exception","name":"_classify_stage_exception","line":595,"end_line":635,"hash":"70319068cd9883b67c8c4f0fcbbe2b17857c13241e5b2e1726339194e6ebc687"},{"id":"func/_actor_accepted_evidence","name":"_actor_accepted_evidence","line":638,"end_line":652,"hash":"faed91888550d1047d7d4811409f0cef77d4dee81eae046d4ccc3817f2947e23"},{"id":"func/_narrative_accepted_evidence","name":"_narrative_accepted_evidence","line":655,"end_line":675,"hash":"9a12d6820cbf1ede52c96f49d5aead47044cfce8ef45c590b31dccb98e45fa44"},{"id":"func/_tree_handles_for_result","name":"_tree_handles_for_result","line":678,"end_line":693,"hash":"575a3cf670bc8d727f7462bd0ec9a74ca36c11ae0ed62c87b497dde4e47b141b"},{"id":"func/_tree_accepted_evidence","name":"_tree_accepted_evidence","line":696,"end_line":716,"hash":"5fb0ec22eb2e74dc33511888716e7125227f3151e64f63bb71cf3260bdd39fd1"},{"id":"func/_behavior_handles_for_result","name":"_behavior_handles_for_result","line":719,"end_line":733,"hash":"31a1ccf21442de0c1797ba3605ed3bf64bad6b3aeb5ef5b9826c6bb011694341"},{"id":"func/_behavior_accepted_evidence","name":"_behavior_accepted_evidence","line":736,"end_line":755,"hash":"b3637a4297b5500ed9de966c918a5d18f3c730feb1dc10f9b4136c7f1653aacb"},{"id":"func/_resolved_candidate_id","name":"_resolved_candidate_id","line":758,"end_line":766,"hash":"bbfd92f260950832a28c84712d7b8f0e4c65c08c65e1ca13e1cd1e3b8c4927f3"},{"id":"func/_normalize_excluded_actor_types","name":"_normalize_excluded_actor_types","line":769,"end_line":779,"hash":"7f9095ef20df56e60302580319a7ce0005cade343f6c6abb3a89601a7ea2e8d4"},{"id":"func/prepare_generation","name":"prepare_generation","line":782,"end_line":808,"hash":"83e5b4f6b4bb9ff2eaba351a0169b0f2a70d3fd378354429d4c964b2b28aba5b"},{"id":"func/generate_actor_stage","name":"generate_actor_stage","line":811,"end_line":879,"hash":"b69dd1553a6c4106eaddd95771ee9c523c7006acced9d8db924c399cd80432b8"},{"id":"func/generate_narrative_stage","name":"generate_narrative_stage","line":882,"end_line":959,"hash":"de6b6d43bb492e063349d4ad6de88cbab72b2351461b9d9bc35922ef1a22bfe5"},{"id":"func/generate_tree_stage","name":"generate_tree_stage","line":962,"end_line":1014,"hash":"196b3d2b723e37240d51590cfa8c6d3c95fc44e69b8234c603ad611734ccfb91"},{"id":"func/generate_behavior_stage","name":"generate_behavior_stage","line":1017,"end_line":1077,"hash":"4f817e4ccaf971a13ba1f37a15b7a52acf73e26b11ba479ddeaaf9ad65444889"},{"id":"func/assemble_final_envelope","name":"assemble_final_envelope","line":1080,"end_line":1142,"hash":"20b7ab8d5f308289503aeca01724c154071dccd797e6d1f9068a794521b68f32"}]}
# mutate4py-manifest-end
