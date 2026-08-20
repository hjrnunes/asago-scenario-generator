"""Typed, single-attempt generation stages for the cmps.5 lifecycle seam.

The production runner is intentionally not wired to these primitives yet.
Each ``generate_*_stage`` function owns exactly one Call 0--3 invocation;
validation, retry routing, admission, and persistence remain explicit ports.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Generic, Literal, TypeVar

from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    BehaviorSpec,
    CallMetadata,
    CallName,
    NarrativeLayer,
    ScenarioEnvelope,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ADVERSARIAL_ONLY_THREATS,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed


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


@dataclass(frozen=True, slots=True)
class PreparedGeneration:
    """Validated identity and immutable projection context for Calls 0--3."""

    request: GenerationRequest
    candidate_id: str
    scenario_id: str
    projection_context: dict[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class RetryDirective:
    """Caller-owned feedback for one explicit stage re-invocation.

    ``reason`` distinguishes the completion-length channel from semantic
    feedback.  A length retry appends ``feedback`` verbatim to the end of
    the original user prompt; semantic retries route through the existing
    per-stage feedback channels.
    """

    feedback: str | None = None
    reason: str | None = None
    forced_actor_type: str | None = None
    prior_titles: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class StageCallEvidence:
    """The exact LLM result and derived metadata for one stage invocation."""

    call_name: CallName
    result: LLMResult
    metadata: CallMetadata


class StageAttemptFailure(Exception):
    """Truthful evidence for a failed single stage attempt.

    ``phase`` discriminates failures before the client was called, failures
    raised by the client invocation, and failures after an ``LLMResult`` was
    obtained.  Missing result/raw response fields are intentionally ``None``.

    Completion-length failures carry ``code == "completion_length"`` plus the
    typed finish reason and usage extracted by the shared adapter; all other
    failures keep the generic ``stage_attempt_failed`` code.  Callers route on
    ``code``, never on exception text.
    """

    DEFAULT_CODE = "stage_attempt_failed"
    COMPLETION_LENGTH_CODE = "completion_length"

    def __init__(
        self,
        *,
        call_name: CallName,
        exception: BaseException,
        phase: Literal["before_invocation", "invocation", "post_response"],
        invoked: bool,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        result: LLMResult | None = None,
        raw_response: Any | None = None,
        code: str = "stage_attempt_failed",
        finish_reason: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> None:
        super().__init__(str(exception))
        self.call_name = call_name
        self.exception_type = type(exception).__name__
        self.detail = str(exception)
        self.phase = phase
        self.invoked = invoked
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        self.result = result
        self.raw_response = raw_response
        self.code = code
        self.finish_reason = finish_reason
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


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


def stage_attempt_failure(
    call_name: CallName,
    exception: BaseException,
    *,
    phase: Literal["before_invocation", "invocation", "post_response"],
    invoked: bool,
    system_prompt: str | None = None,
    user_prompt: str | None = None,
    result: LLMResult | None = None,
    raw_response: Any | None = None,
) -> StageAttemptFailure:
    """Build a typed StageAttemptFailure, normalizing length exhaustion.

    Completion-length failures are recognized structurally from the shared
    adapter's typed error — never from exception text — and carry the code
    ``completion_length`` plus finish reason and usage fields.
    """
    from asago_scenario_generator.llm.client import CompletionLengthError

    if isinstance(exception, CompletionLengthError):
        return StageAttemptFailure(
            call_name=call_name,
            exception=exception,
            phase=phase,
            invoked=invoked,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            result=result,
            raw_response=raw_response,
            code=StageAttemptFailure.COMPLETION_LENGTH_CODE,
            finish_reason=exception.finish_reason,
            prompt_tokens=exception.prompt_tokens,
            completion_tokens=exception.completion_tokens,
        )
    return StageAttemptFailure(
        call_name=call_name,
        exception=exception,
        phase=phase,
        invoked=invoked,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        result=result,
        raw_response=raw_response,
    )


class _AttemptRecordingClient:
    """Transparent client proxy retaining truthful one-attempt evidence."""

    def __init__(self, client: LLMClient) -> None:
        self._client = client
        self.invoked = False
        self.system_prompt: str | None = None
        self.user_prompt: str | None = None
        self.result: LLMResult | None = None
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
        self.result = self._client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            **kwargs,
        )
        return self.result

    def failure(
        self, call_name: CallName, exception: BaseException
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


def _evidence(call_name: CallName, result: LLMResult) -> StageCallEvidence:
    # Late package lookup preserves the established unittest patch surface.
    import asago_scenario_generator.pipeline.generate as generate

    return StageCallEvidence(
        call_name, result, generate._call_metadata(call_name, result)
    )


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
    recorder = _AttemptRecordingClient(request.client)
    semantic_feedback, length_feedback = _split_retry(retry)
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
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        raise recorder.failure(CallName.actor_profile, exc) from exc
    return ActorStageResult(
        artifact=actor,
        evidence=_evidence(CallName.actor_profile, result),
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
    recorder = _AttemptRecordingClient(request.client)
    semantic_feedback, length_feedback = _split_retry(retry)
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
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        raise recorder.failure(CallName.narrative, exc) from exc
    return NarrativeStageResult(
        artifact=narrative, evidence=_evidence(CallName.narrative, result)
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
    recorder = _AttemptRecordingClient(request.client)
    semantic_feedback, length_feedback = _split_retry(retry)
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
            pinned_entry_point_id=request.pinned_entry_point_id,
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        raise recorder.failure(CallName.attack_tree, exc) from exc
    return TreeStageResult(
        artifact=tree, evidence=_evidence(CallName.attack_tree, result)
    )


def generate_behavior_stage(
    prepared: PreparedGeneration,
    narrative: NarrativeLayer,
    tree: AttackTree,
    retry: RetryDirective | None = None,
) -> BehaviorStageResult:
    """Perform exactly one structured behavior-spec LLM call.

    Only the completion-length retry channel is supported; semantic
    feedback for Call 3 is still out of contract (phases 3--6).
    """
    import asago_scenario_generator.pipeline.generate as generate

    request = prepared.request
    recorder = _AttemptRecordingClient(request.client)
    _, length_feedback = _split_retry(retry)
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
            completion_length_feedback=length_feedback,
            projection_context=prepared.projection_context,
        )
    except StageAttemptFailure:
        raise
    except Exception as exc:
        raise recorder.failure(CallName.behavior_spec, exc) from exc
    return BehaviorStageResult(
        artifact=behavior, evidence=_evidence(CallName.behavior_spec, result)
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
