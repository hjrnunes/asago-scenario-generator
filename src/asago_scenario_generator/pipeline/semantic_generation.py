"""Bounded semantic generation behind one stage-level interface.

Provider drafts use request-local handles.  The application resolves those
handles to canonical identities only after the provider-authored semantics
have passed validation.
"""

from __future__ import annotations

import re
import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Generic, Literal, Mapping, Protocol, Sequence, TypeVar

from pydantic import BaseModel

_HANDLE_PREFIX = re.compile(r"^[a-z]+$")


@dataclass(frozen=True, slots=True)
class HandleChoice:
    """One canonical choice exposed to a provider under a short handle."""

    canonical_id: str
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class HandleBinding:
    """A request-local handle bound to one canonical choice."""

    handle: str
    canonical_id: str
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class RequestHandleMap:
    """Immutable request-local handle inventory."""

    bindings: tuple[HandleBinding, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for binding in self.bindings:
            if binding.handle in seen:
                raise ValueError(f"duplicate request-local handle: {binding.handle}")
            seen.add(binding.handle)

    @classmethod
    def allocate(cls, groups: Mapping[str, Sequence[HandleChoice]]) -> RequestHandleMap:
        bindings: list[HandleBinding] = []
        for prefix in sorted(groups):
            if not _HANDLE_PREFIX.fullmatch(prefix):
                raise ValueError("handle prefixes must contain lowercase letters only")
            bindings.extend(
                HandleBinding(
                    handle=f"{prefix}{index}",
                    canonical_id=choice.canonical_id,
                    display_name=choice.display_name,
                )
                for index, choice in enumerate(groups[prefix])
            )
        return cls(tuple(bindings))

    @property
    def handles(self) -> tuple[str, ...]:
        return tuple(binding.handle for binding in self.bindings)

    def resolve(self, handle: str) -> HandleBinding:
        try:
            return next(
                binding for binding in self.bindings if binding.handle == handle
            )
        except StopIteration:
            raise KeyError(f"unknown request-local handle: {handle}") from None

    def as_dict(self) -> Mapping[str, str]:
        return MappingProxyType(
            {binding.handle: binding.canonical_id for binding in self.bindings}
        )


@dataclass(frozen=True, slots=True)
class DraftViolation:
    """One provider-correctable semantic draft violation."""

    code: str
    detail: str
    handles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DraftValidation:
    """Result returned by a stage's pure semantic validator."""

    violations: tuple[DraftViolation, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.violations


ContextT = TypeVar("ContextT")
DraftT = TypeVar("DraftT")
ArtifactT = TypeVar("ArtifactT")


@dataclass(frozen=True, slots=True, kw_only=True)
class SemanticAttemptRequest(Generic[ContextT]):
    """One bounded request crossing the semantic adapter seam."""

    stage: str
    attempt_index: int
    context: ContextT
    handles: RequestHandleMap
    effective_controls: Mapping[str, Any]
    feedback: tuple[DraftViolation, ...] = ()
    compact_presentation: bool = False
    request_digest: str


@dataclass(frozen=True, slots=True)
class SemanticAdapterDraft(Generic[DraftT]):
    """A provider draft returned with its typed finish reason."""

    draft: DraftT
    finish_reason: str = "stop"


class SemanticAdapterFailureKind(str, Enum):
    """Failures normalized by an adapter before lifecycle policy sees them."""

    length = "length"
    protocol = "protocol"


@dataclass(frozen=True, slots=True, kw_only=True)
class SemanticAdapterFailure:
    """Typed provider failure with optional bounded response evidence."""

    kind: SemanticAdapterFailureKind
    detail: str
    finish_reason: str | None = None
    response_digest: str | None = None


@dataclass(frozen=True, slots=True)
class SemanticProviderCall:
    """One stage-built provider call; prompt and schema construction stay injected."""

    system_prompt: str
    user_prompt: str
    response_format: Any = None
    completion_kwargs: Mapping[str, Any] = field(default_factory=dict)


class OpenAICompatibleSemanticAdapter(Generic[ContextT, DraftT]):
    """One-call production adapter for the project OpenAI-compatible client."""

    def __init__(
        self,
        *,
        complete: Callable[..., Any],
        build_call: Callable[[SemanticAttemptRequest[ContextT]], SemanticProviderCall],
        decode_draft: Callable[[Any], DraftT],
    ) -> None:
        self._complete = complete
        self._build_call = build_call
        self._decode_draft = decode_draft

    def generate(
        self, request: SemanticAttemptRequest[ContextT]
    ) -> SemanticAdapterDraft[DraftT] | SemanticAdapterFailure:
        from asago_scenario_generator.llm.client import CompletionLengthError

        try:
            call = self._build_call(request)
            result = self._complete(
                system_prompt=call.system_prompt,
                user_prompt=call.user_prompt,
                response_format=call.response_format,
                **dict(call.completion_kwargs),
            )
            content = result.content
            draft = self._decode_draft(content)
        except CompletionLengthError as exc:
            return SemanticAdapterFailure(
                kind=SemanticAdapterFailureKind.length,
                detail=str(exc),
                finish_reason=exc.finish_reason,
                response_digest=exc.partial_sha256,
            )
        except Exception as exc:
            return SemanticAdapterFailure(
                kind=SemanticAdapterFailureKind.protocol,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return SemanticAdapterDraft(draft)


class SemanticGenerationAdapter(Protocol[ContextT, DraftT]):
    """Adapter interface for one semantic provider attempt."""

    def generate(
        self, request: SemanticAttemptRequest[ContextT]
    ) -> SemanticAdapterDraft[DraftT] | SemanticAdapterFailure: ...


class ScriptedSemanticAdapter(Generic[ContextT, DraftT]):
    """Deterministic test adapter; never a production semantic fallback."""

    def __init__(
        self,
        script: Sequence[SemanticAdapterDraft[DraftT] | SemanticAdapterFailure],
    ) -> None:
        self._script = tuple(script)
        self._attempts: list[SemanticAttemptRequest[ContextT]] = []

    @property
    def attempts(self) -> tuple[SemanticAttemptRequest[ContextT], ...]:
        return tuple(self._attempts)

    def generate(
        self, request: SemanticAttemptRequest[ContextT]
    ) -> SemanticAdapterDraft[DraftT] | SemanticAdapterFailure:
        self._attempts.append(request)
        try:
            return self._script[len(self._attempts) - 1]
        except IndexError:
            raise RuntimeError("scripted semantic adapter exhausted") from None


@dataclass(frozen=True, slots=True)
class StageAttemptEvidence:
    """Durable, bounded evidence for one provider attempt."""

    attempt_index: int
    request_digest: str
    response_digest: str | None
    finish_reason: str | None
    result: Literal[
        "accepted",
        "invalid_draft",
        "length_failure",
        "protocol_failure",
        "compiler_failure",
    ]
    effective_controls: Mapping[str, Any]
    validation_violations: tuple[DraftViolation, ...] = ()
    retry_class: Literal["length", "semantic"] | None = None
    failure_detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the stable JSON-safe persistence representation."""
        return {
            "attempt_index": self.attempt_index,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "finish_reason": self.finish_reason,
            "result": self.result,
            "effective_controls": _plain_value(self.effective_controls),
            "validation_violations": [
                {
                    "code": violation.code,
                    "detail": violation.detail,
                    "handles": list(violation.handles),
                }
                for violation in self.validation_violations
            ],
            "retry_class": self.retry_class,
            "failure_detail": self.failure_detail,
        }


@dataclass(frozen=True, slots=True)
class StageGenerationEvidence:
    """Evidence resolving accepted semantics to canonical identities."""

    stage: str
    compiler_name: str
    handle_map: Mapping[str, str]
    attempts: tuple[StageAttemptEvidence, ...]
    accepted_draft_digest: str | None
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Return the stable JSON-safe persistence representation."""
        return {
            "stage": self.stage,
            "compiler_name": self.compiler_name,
            "handle_map": dict(self.handle_map),
            "attempts": [attempt.as_dict() for attempt in self.attempts],
            "accepted_draft_digest": self.accepted_draft_digest,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class StageGenerationSuccess(Generic[DraftT, ArtifactT]):
    """A provider-authored draft compiled into one canonical artifact."""

    artifact: ArtifactT
    accepted_draft: DraftT
    evidence: StageGenerationEvidence
    warnings: tuple[str, ...] = ()


class StageFailureCode(str, Enum):
    """Terminal classifications emitted by semantic stage generation."""

    semantic_draft_length_failed = "semantic_draft_length_failed"
    semantic_draft_protocol_failed = "semantic_draft_protocol_failed"
    semantic_draft_invalid = "semantic_draft_invalid"
    canonical_compilation_failed = "canonical_compilation_failed"


@dataclass(frozen=True, slots=True)
class StageGenerationFailure:
    """One typed failed attempt for the caller-owned lifecycle to route."""

    code: StageFailureCode
    detail: str
    evidence: StageGenerationEvidence


@dataclass(frozen=True, slots=True, kw_only=True)
class SemanticRetryDirective:
    """Caller-owned controls for one explicit retry attempt."""

    retry_class: Literal["length", "semantic"]
    feedback: tuple[DraftViolation, ...] = ()
    compact_presentation: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class StageGenerationRequest(Generic[ContextT, DraftT, ArtifactT]):
    """Complete input for exactly one semantic generation attempt."""

    stage: str
    context: ContextT
    handles: RequestHandleMap
    request_payload: Mapping[str, Any]
    effective_controls: Mapping[str, Any]
    compiler_name: str
    validate_draft: Callable[[ContextT, DraftT], DraftValidation]
    compile_draft: Callable[[ContextT, DraftT], ArtifactT]
    attempt_index: int = 0
    retry: SemanticRetryDirective | None = None


def _plain_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_value(item) for item in value]
    if isinstance(value, BaseModel):
        return _plain_value(value.model_dump(mode="json"))
    if is_dataclass(value) and not isinstance(value, type):
        return _plain_value(asdict(value))
    raise TypeError(
        f"cannot create generation evidence digest for {type(value).__name__}"
    )


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _plain_value(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def generate_stage(
    request: StageGenerationRequest[ContextT, DraftT, ArtifactT],
    adapter: SemanticGenerationAdapter[ContextT, DraftT],
) -> StageGenerationSuccess[DraftT, ArtifactT] | StageGenerationFailure:
    """Generate, validate, and compile exactly one provider-authored draft."""
    retry = request.retry
    feedback = retry.feedback if retry else ()
    compact = retry.compact_presentation if retry else False
    retry_class = retry.retry_class if retry else None
    request_digest = _digest(
        {
            "stage": request.stage,
            "payload": request.request_payload,
            "handles": request.handles.as_dict(),
            "effective_controls": request.effective_controls,
            "attempt_index": request.attempt_index,
            "feedback": feedback,
            "compact_presentation": compact,
            "retry_class": retry_class,
        }
    )
    attempt = SemanticAttemptRequest(
        stage=request.stage,
        attempt_index=request.attempt_index,
        context=request.context,
        handles=request.handles,
        effective_controls=MappingProxyType(dict(request.effective_controls)),
        feedback=feedback,
        compact_presentation=compact,
        request_digest=request_digest,
    )
    response = adapter.generate(attempt)
    if isinstance(response, SemanticAdapterFailure):
        result = (
            "length_failure"
            if response.kind is SemanticAdapterFailureKind.length
            else "protocol_failure"
        )
        code = (
            StageFailureCode.semantic_draft_length_failed
            if response.kind is SemanticAdapterFailureKind.length
            else StageFailureCode.semantic_draft_protocol_failed
        )
        violations = (
            (DraftViolation("provider_protocol", response.detail),)
            if response.kind is SemanticAdapterFailureKind.protocol
            else ()
        )
        evidence = StageAttemptEvidence(
            attempt_index=request.attempt_index,
            request_digest=request_digest,
            response_digest=response.response_digest,
            finish_reason=response.finish_reason,
            result=result,
            effective_controls=attempt.effective_controls,
            validation_violations=violations,
            retry_class=retry_class,
            failure_detail=response.detail,
        )
        return StageGenerationFailure(
            code=code,
            detail=response.detail,
            evidence=_stage_evidence(request, evidence),
        )

    response_digest = _digest(response.draft)
    validation = request.validate_draft(request.context, response.draft)
    if not validation.valid:
        evidence = StageAttemptEvidence(
            attempt_index=request.attempt_index,
            request_digest=request_digest,
            response_digest=response_digest,
            finish_reason=response.finish_reason,
            result="invalid_draft",
            effective_controls=attempt.effective_controls,
            validation_violations=validation.violations,
            retry_class=retry_class,
        )
        return StageGenerationFailure(
            code=StageFailureCode.semantic_draft_invalid,
            detail="semantic draft is invalid",
            evidence=_stage_evidence(request, evidence),
        )

    try:
        artifact = request.compile_draft(request.context, response.draft)
    except Exception as exc:  # compiler defects are typed, never retried
        detail = f"{type(exc).__name__}: {exc}"
        evidence = StageAttemptEvidence(
            attempt_index=request.attempt_index,
            request_digest=request_digest,
            response_digest=response_digest,
            finish_reason=response.finish_reason,
            result="compiler_failure",
            effective_controls=attempt.effective_controls,
            retry_class=retry_class,
            failure_detail=detail,
        )
        return StageGenerationFailure(
            code=StageFailureCode.canonical_compilation_failed,
            detail=detail,
            evidence=_stage_evidence(request, evidence, response_digest),
        )
    evidence = StageAttemptEvidence(
        attempt_index=request.attempt_index,
        request_digest=request_digest,
        response_digest=response_digest,
        finish_reason=response.finish_reason,
        result="accepted",
        effective_controls=attempt.effective_controls,
        retry_class=retry_class,
    )
    return StageGenerationSuccess(
        artifact=artifact,
        accepted_draft=response.draft,
        evidence=_stage_evidence(request, evidence, response_digest),
    )


def _stage_evidence(
    request: StageGenerationRequest[Any, Any, Any],
    attempt: StageAttemptEvidence,
    accepted_draft_digest: str | None = None,
) -> StageGenerationEvidence:
    return StageGenerationEvidence(
        stage=request.stage,
        compiler_name=request.compiler_name,
        handle_map=request.handles.as_dict(),
        attempts=(attempt,),
        accepted_draft_digest=accepted_draft_digest,
    )
