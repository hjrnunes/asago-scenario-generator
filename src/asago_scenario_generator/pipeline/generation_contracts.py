"""Stable contracts shared by generation, lifecycle, and persistence adapters.

The stage implementations are one consumer of these contracts, not their
owner.  Keeping retry directives and attempt evidence here prevents lifecycle
policy and durable persistence from importing the stage-call adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from asago_scenario_generator.llm.client import (
    CompletionLengthError,
    LLMResult,
)
from asago_scenario_generator.models.scenario import CallMetadata, CallName

if TYPE_CHECKING:
    from asago_scenario_generator.pipeline.semantic_generation import (
        StageGenerationEvidence,
    )

__all__ = [
    "CausalRetryControl",
    "RetryDirective",
    "StageAttemptFailure",
    "StageCallEvidence",
    "stage_attempt_failure",
]


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
    causal_control: CausalRetryControl | None = None
    attempt_index: int = 1

    def provider_retry_value(self, field: str) -> str | int | float | None:
        """Return the approved retry value when its control targets ``field``."""
        control = self.causal_control
        if control is None or control.field != field:
            return None
        return control.retry_value


@dataclass(frozen=True, slots=True)
class CausalRetryControl:
    """One approved provider-facing causal change for a bounded retry."""

    control_id: str
    field: str
    initial_value: str | int | float
    retry_value: str | int | float


@dataclass(frozen=True, slots=True)
class StageCallEvidence:
    """The exact LLM result and derived metadata for one stage invocation."""

    call_name: CallName
    result: LLMResult
    metadata: CallMetadata
    semantic_evidence: StageGenerationEvidence | None = None


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
    SEMANTIC_DRAFT_LENGTH_CODE = "semantic_draft_length_failed"
    SEMANTIC_DRAFT_PROTOCOL_CODE = "semantic_draft_protocol_failed"
    SEMANTIC_DRAFT_INVALID_CODE = "semantic_draft_invalid"
    PROJECTION_INFEASIBLE_CODE = "projection_infeasible"
    CANONICAL_COMPILATION_CODE = "canonical_compilation_failed"

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
        total_tokens: int | None = None,
        usage_details: dict[str, Any] | None = None,
        response_id: str | None = None,
        model: str | None = None,
        partial_character_count: int | None = None,
        partial_sha256: str | None = None,
        partial_preview_prefix: str | None = None,
        partial_preview_suffix: str | None = None,
        elapsed_ms: int | None = None,
        request_controls: dict[str, Any] | None = None,
        retryable: bool = True,
        semantic_evidence: StageGenerationEvidence | None = None,
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
        self.total_tokens = total_tokens
        self.usage_details = usage_details
        self.response_id = response_id
        self.model = model
        self.partial_character_count = partial_character_count
        self.partial_sha256 = partial_sha256
        self.partial_preview_prefix = partial_preview_prefix
        self.partial_preview_suffix = partial_preview_suffix
        self.elapsed_ms = elapsed_ms
        self.request_controls = request_controls or {}
        self.retryable = retryable
        self.semantic_evidence = semantic_evidence


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
    request_controls: dict[str, Any] | None = None,
    code: str | None = None,
    retryable: bool | None = None,
    semantic_evidence: StageGenerationEvidence | None = None,
) -> StageAttemptFailure:
    """Build a typed StageAttemptFailure, normalizing length exhaustion.

    Completion-length failures are recognized structurally from the shared
    adapter's typed error, never from exception text, and carry the code
    ``completion_length`` plus finish reason and usage fields.
    """
    if isinstance(exception, CompletionLengthError):
        return _completion_length_failure(
            call_name,
            exception,
            phase=phase,
            invoked=invoked,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            result=result,
            raw_response=raw_response,
            request_controls=request_controls,
            semantic_evidence=semantic_evidence,
        )
    code, retryable = _resolved_failure_code(exception, code, retryable, invoked)
    return StageAttemptFailure(
        call_name=call_name,
        exception=exception,
        phase=phase,
        invoked=invoked,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        result=result,
        raw_response=raw_response,
        code=code or StageAttemptFailure.DEFAULT_CODE,
        request_controls=request_controls,
        retryable=True if retryable is None else bool(retryable),
        semantic_evidence=semantic_evidence,
    )


def _completion_length_failure(
    call_name: CallName,
    exception: CompletionLengthError,
    *,
    phase: Literal["before_invocation", "invocation", "post_response"],
    invoked: bool,
    system_prompt: str | None = None,
    user_prompt: str | None = None,
    result: LLMResult | None = None,
    raw_response: Any | None = None,
    request_controls: dict[str, Any] | None = None,
    semantic_evidence: StageGenerationEvidence | None = None,
) -> StageAttemptFailure:
    """Build the typed failure for an adapter completion-length exhaustion."""
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
        total_tokens=exception.total_tokens,
        usage_details=exception.usage_details,
        response_id=exception.response_id,
        model=exception.model,
        partial_character_count=exception.partial_character_count,
        partial_sha256=exception.partial_sha256,
        partial_preview_prefix=exception.partial_preview_prefix,
        partial_preview_suffix=exception.partial_preview_suffix,
        elapsed_ms=exception.elapsed_ms,
        request_controls=request_controls,
        retryable=True,
        semantic_evidence=semantic_evidence,
    )


def _resolved_failure_code(
    exception: BaseException,
    code: str | None,
    retryable: bool | None,
    invoked: bool,
) -> tuple[str | None, bool | None]:
    """Resolve the failure code and retryability from the exception itself."""
    code = code or getattr(exception, "stage_failure_code", None)
    if retryable is None:
        retryable = getattr(exception, "stage_failure_retryable", None)
    if code is None:
        from pydantic import ValidationError

        if invoked and isinstance(exception, ValidationError):
            code = StageAttemptFailure.SEMANTIC_DRAFT_PROTOCOL_CODE
            retryable = True
    return code, retryable
