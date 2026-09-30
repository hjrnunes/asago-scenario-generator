"""Profile-backed structured interpreter for the target-discovery seam.

This module is the only provider-aware part of the standalone scanner.  It
resolves a named model profile, delegates both structured calls to the shared
``safe_llm_call`` boundary, and exposes deterministic call evidence back to
the pure discovery composition seam.  The temporary safe-call log is
discarded after each request; the scanner persists the sanitized, replayable
records returned by :meth:`drain_call_records`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StrictStr, create_model

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_bytes,
)
from asago_scenario_generator.request_schema import (
    string_enum,
    string_items_enum,
    uses_guided_decoding,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.models.execution_classification import (
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetStateEffect,
)
from asago_scenario_generator.stpa.pipeline.llm_config import (
    resolve_llm_client_from_profile,
)

from .contracts import (
    TargetInterpretationDraft,
    TargetInterpretationRequest,
    TargetInterpretationResponse,
    TargetInterpretationVerification,
    TargetToolPromptView,
)
from .prompts import (
    build_interpretation_prompt,
    build_verifier_prompt,
    prompt_hash,
)


class _ProviderInterpretationDraft(ClosedCanonicalModel):
    """Required model-facing fields for one request-local tool."""

    tool_handle: StrictStr = Field(pattern=r"^TOOL-[0-9]+$")
    disposition: TargetInterpretationDisposition
    likely_effect: TargetOperationEffect
    likely_state_effect: TargetStateEffect
    semantic_roles: tuple[StrictStr, ...]
    observer_tool_handles: tuple[StrictStr, ...]
    evidence_refs: tuple[StrictStr, ...] = Field(min_length=1)
    rationale: StrictStr = Field(min_length=1)


SEMANTIC_ROLE_VOCABULARY: tuple[str, ...] = (
    "text_search",
    "identifier_lookup",
    "state_observation",
    "state_change",
    "command_execution",
)
"""Closed role labels a guided decoder may emit.

Only ``text_search`` is standardized and matched by downstream code.  The
other labels name the contrasts the interpreter prompt draws.  They exist
because a guided decoder that means to write any role label must pick one
of the enum values; with ``text_search`` as the only value, every intended
role becomes a false ``text_search`` claim.
"""


def _request_row_model(
    tools: Sequence[TargetToolPromptView],
) -> type[_ProviderInterpretationDraft]:
    """Close the row schema to the request's handles and the role vocabulary.

    The enums change the transport schema only, so guided decoding cannot
    invent a role label or handle.  Evidence references stay open: one
    batch-wide enum would let a row cite another tool's fields, and
    discovery already rejects references outside the row's own tool.
    Local validation is the static row's.
    """
    handles = [tool.handle for tool in tools]
    return create_model(
        "_ProviderInterpretationDraft",
        __base__=_ProviderInterpretationDraft,
        tool_handle=(
            StrictStr,
            Field(pattern=r"^TOOL-[0-9]+$", json_schema_extra=string_enum(handles)),
        ),
        semantic_roles=(
            tuple[StrictStr, ...],
            Field(
                json_schema_extra=string_items_enum(
                    SEMANTIC_ROLE_VOCABULARY, max_items=1
                )
            ),
        ),
        observer_tool_handles=(
            tuple[StrictStr, ...],
            Field(json_schema_extra=string_items_enum(handles)),
        ),
    )


def _provider_response_model(
    tool_count: int,
    *,
    tools: Sequence[TargetToolPromptView] = (),
) -> type[BaseModel]:
    """Build a strict response schema with one row per supplied tool."""
    row = _request_row_model(tools) if tools else _ProviderInterpretationDraft
    interpretations_type = Annotated[
        tuple[row, ...],  # type: ignore[valid-type]
        Field(min_length=tool_count, max_length=tool_count),
    ]
    return create_model(
        "TargetInterpretationProviderResponse",
        __base__=ClosedCanonicalModel,
        interpretations=(interpretations_type, ...),
    )


class _ProviderVerificationVerdict(ClosedCanonicalModel):
    """Required model-facing fields for one verifier verdict."""

    tool_handle: StrictStr = Field(pattern=r"^TOOL-[0-9]+$")
    reason: StrictStr = Field(min_length=1)
    agreement: Literal["agree", "disagree"]


def _provider_verification_model(
    tool_count: int,
    *,
    tools: Sequence[TargetToolPromptView] = (),
) -> type[BaseModel]:
    """Build a strict verifier schema with one verdict per supplied tool."""
    verdict: type[_ProviderVerificationVerdict] = _ProviderVerificationVerdict
    if tools:
        verdict = create_model(
            "_ProviderVerificationVerdict",
            __base__=_ProviderVerificationVerdict,
            tool_handle=(
                StrictStr,
                Field(
                    pattern=r"^TOOL-[0-9]+$",
                    json_schema_extra=string_enum(tool.handle for tool in tools),
                ),
            ),
        )
    verdicts_type = Annotated[
        tuple[verdict, ...],  # type: ignore[valid-type]
        Field(min_length=tool_count, max_length=tool_count),
    ]
    return create_model(
        "TargetInterpretationProviderVerification",
        __base__=ClosedCanonicalModel,
        verdicts=(verdicts_type, ...),
    )


class TargetDiscoveryLlmError(RuntimeError):
    """Safe provider-boundary error with no endpoint or response leakage."""

    def __init__(self, kind: str, error: BaseException) -> None:
        self.kind = kind
        self.error_type = _stable_error_type(error)
        self.http_status = _stable_http_status(error)
        status = f", status={self.http_status}" if self.http_status is not None else ""
        super().__init__(f"{kind} call failed ({self.error_type}{status})")


class TargetDiscoveryLlmInterpreter:
    """Issue one interpretation and one independent verifier call per batch."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        model_profile: str | None = None,
        temperature: float | None = None,
        max_completion_tokens: int | None = None,
    ) -> None:
        self._llm_client = llm_client
        self.model_profile = model_profile
        self.model_name = str(getattr(llm_client, "model", "unknown-model"))
        self._temperature = (
            temperature
            if temperature is not None
            else float(getattr(llm_client, "temperature", 0.4))
        )
        self._max_completion_tokens = (
            max_completion_tokens
            if max_completion_tokens is not None
            else getattr(llm_client, "max_completion_tokens", None)
        )
        self._call_records: list[dict[str, Any]] = []

    @classmethod
    def from_profile(
        cls,
        profiles_file: str | Path,
        profile_name: str,
        **kwargs: Any,
    ) -> "TargetDiscoveryLlmInterpreter":
        """Resolve one existing named model profile into an interpreter."""
        llm_client, resolved_profile = resolve_llm_client_from_profile(
            str(profiles_file), profile_name
        )
        return cls(
            llm_client,
            model_profile=resolved_profile,
            **kwargs,
        )

    def interpret(
        self, request: TargetInterpretationRequest
    ) -> TargetInterpretationResponse:
        """Interpret one bounded request through a strict structured call."""
        system_prompt, user_prompt = build_interpretation_prompt(request)
        parsed = self._structured_call(
            kind="interpretation",
            request=request,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_provider_response_model(
                len(request.tools), tools=self._guided_tools(request)
            ),
        )
        if parsed is None:
            raise TypeError("safe interpreter response was not typed")
        try:
            interpretations = tuple(
                TargetInterpretationDraft.model_validate(item.model_dump(mode="json"))
                for item in parsed.interpretations
            )
            expected = tuple(tool.handle for tool in request.tools)
            actual = tuple(item.tool_handle for item in interpretations)
            if len(set(actual)) != len(actual) or set(actual) != set(expected):
                raise ValueError(
                    "interpretation response must cover every request-local tool "
                    "handle exactly once"
                )
        except (AttributeError, TypeError, ValueError) as exc:
            raise TargetDiscoveryLlmError("interpretation", exc) from exc
        return TargetInterpretationResponse(interpretations=interpretations)

    def verify(
        self,
        request: TargetInterpretationRequest,
        response: TargetInterpretationResponse,
    ) -> TargetInterpretationVerification:
        """Independently verify each record of one validated interpretation."""
        system_prompt, user_prompt = build_verifier_prompt(request, response)
        parsed = self._structured_call(
            kind="verification",
            request=request,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_provider_verification_model(
                len(request.tools), tools=self._guided_tools(request)
            ),
            response_for_record=response,
        )
        if parsed is None:
            raise TypeError("safe verifier response was not typed")
        try:
            verification = TargetInterpretationVerification.model_validate(
                parsed.model_dump(mode="json")
            )
            expected = {tool.handle for tool in request.tools}
            actual = {item.tool_handle for item in verification.verdicts}
            if actual != expected:
                raise ValueError(
                    "verification response must cover every request-local tool "
                    "handle exactly once"
                )
        except (AttributeError, TypeError, ValueError) as exc:
            raise TargetDiscoveryLlmError("verification", exc) from exc
        return verification

    def _guided_tools(
        self, request: TargetInterpretationRequest
    ) -> tuple[TargetToolPromptView, ...]:
        """The tools that close the request schema, only under guided decoding."""
        if uses_guided_decoding(self._llm_client):
            return request.tools
        return ()

    def drain_call_records(self) -> tuple[Mapping[str, Any], ...]:
        """Return and clear exact sanitized records for the current scan."""
        records = tuple(self._call_records)
        self._call_records.clear()
        return records

    def _structured_call(
        self,
        *,
        kind: str,
        request: TargetInterpretationRequest,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel],
        response_for_record: BaseModel | None = None,
    ) -> BaseModel | None:
        """Run one safe structured call and retain replayable call evidence."""
        result: LLMResult | None = None
        parsed: BaseModel | None = None
        error: BaseException | None = None
        try:
            # ``safe_llm_call`` writes its standard lifecycle log to this
            # disposable directory.  The scanner-owned record below is the
            # durable accounting surface, so no provider log path leaks into
            # the profile or manifest.
            with TemporaryDirectory(prefix="asago-target-discovery-") as directory:
                parsed, result, error_message = safe_llm_call(
                    llm_client=self._llm_client,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=response_format,
                    run_dir=Path(directory),
                    stage="target_discovery",
                    step=kind,
                    temperature=self._temperature,
                    max_completion_tokens=self._max_completion_tokens,
                    allow_unvalidated=False,
                    prompt_template_hashes={
                        "target_discovery_prompt": prompt_hash(
                            system_prompt, user_prompt
                        )
                    },
                )
            if error_message is not None:
                error = _SafeCallFailure(error_message)
        except BaseException as exc:  # noqa: BLE001 - provider boundary
            error = exc
        self._call_records.append(
            self._call_record(
                kind=kind,
                request=request,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                parsed=parsed,
                result=result,
                error=error,
                response_for_record=response_for_record,
            )
        )
        if error is not None or parsed is None:
            raise TargetDiscoveryLlmError(kind, error or RuntimeError("empty response"))
        return parsed

    def _call_record(
        self,
        *,
        kind: str,
        request: TargetInterpretationRequest,
        system_prompt: str,
        user_prompt: str,
        parsed: BaseModel | None,
        result: LLMResult | None,
        error: BaseException | None,
        response_for_record: BaseModel | None,
    ) -> dict[str, Any]:
        """Build one deterministic record without runtime configuration."""
        actual_system, actual_user = _record_prompts(result, system_prompt, user_prompt)
        response_content = _record_response_content(parsed, result)
        record = _base_call_record(
            kind=kind,
            batch_id=request.batch_id,
            model=self.model_name,
            model_profile=self.model_profile,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            actual_system=actual_system,
            actual_user=actual_user,
            parsed=parsed,
            response_content=response_content,
            result=result,
            error=error,
        )
        _record_error(record, error)
        _record_verification_digest(record, response_for_record)
        return record


class _SafeCallFailure(RuntimeError):
    """Internal marker retaining safe provider class/status metadata."""

    def __init__(self, message: str) -> None:
        # ``safe_llm_call`` returns a display string rather than the original
        # exception.  Keep only a stable class prefix and labelled HTTP status;
        # never retain the provider body, endpoint, or other message detail.
        self.error_type = _error_type_from_message(message) or "safe_llm_call"
        self.http_status = _http_status_from_message(message)
        super().__init__("safe_llm_call failed")


def _record_prompts(
    result: LLMResult | None,
    system_prompt: str,
    user_prompt: str,
) -> tuple[str, str]:
    """Use provider-rendered prompts when available, otherwise requested text."""
    return (
        _result_prompt(result, "system_prompt") or system_prompt,
        _result_prompt(result, "user_prompt") or user_prompt,
    )


def _record_response_content(
    parsed: BaseModel | None,
    result: LLMResult | None,
) -> Any:
    """Choose validated structured content before raw provider content."""
    return _json_value(
        parsed if parsed is not None else getattr(result, "content", None)
    )


def _base_call_record(
    *,
    kind: str,
    batch_id: str,
    model: str,
    model_profile: str | None,
    system_prompt: str,
    user_prompt: str,
    actual_system: str,
    actual_user: str,
    parsed: BaseModel | None,
    response_content: Any,
    result: LLMResult | None,
    error: BaseException | None,
) -> dict[str, Any]:
    """Construct the common secret-free call evidence fields."""
    return {
        "kind": kind,
        "stage": "target_discovery",
        "step": kind,
        "batch_id": batch_id,
        "model": model,
        "model_profile": model_profile,
        "prompt_hash": prompt_hash(system_prompt, user_prompt),
        "rendered_prompt_hash": prompt_hash(actual_system, actual_user),
        "system_prompt_text": actual_system,
        "user_prompt_text": actual_user,
        "validated_response": _json_value(parsed),
        "response_content": (
            _canonical_text(response_content) if response_content is not None else None
        ),
        "prompt_tokens": int(getattr(result, "prompt_tokens", 0) or 0),
        "completion_tokens": int(getattr(result, "completion_tokens", 0) or 0),
        "usage_details": dict(getattr(result, "usage_details", {}) or {}),
        "request_controls": dict(getattr(result, "request_controls", {}) or {}),
        # A failed helper call may have dispatched a request without returning
        # an ``LLMResult``.  ``None`` means unmeasured; zero is reserved for a
        # result that explicitly reports a zero duration.
        "duration_ms": _result_duration(result),
        "success": error is None and parsed is not None,
        "provider_response_received": result is not None,
        "semantic_validation_passed": parsed is not None and error is None,
    }


def _record_error(record: dict[str, Any], error: BaseException | None) -> None:
    """Attach stable error metadata without provider message details."""
    if error is None:
        return
    record["error_type"] = _stable_error_type(error)
    http_status = _stable_http_status(error)
    if http_status is not None:
        record["http_status"] = http_status


_ERROR_TYPE_PREFIX = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*:")
_HTTP_STATUS_LABEL = re.compile(
    r"\b(?:error\s+code|http(?:[_\s-]?status)|status(?:[_\s-]?code)?)"
    r"\s*[:=]?\s*(\d{3})\b",
    re.IGNORECASE,
)


def _error_type_from_message(message: str) -> str | None:
    """Extract only a stable exception-class prefix from helper text."""
    match = _ERROR_TYPE_PREFIX.match(message)
    return match.group(1) if match is not None else None


def _coerce_http_status(value: Any) -> int | None:
    """Return a conventional HTTP status while rejecting arbitrary values."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 100 <= value <= 599:
        return int(value)
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        if 100 <= parsed <= 599:
            return parsed
    return None


def _http_status_from_message(message: str) -> int | None:
    """Extract a labelled HTTP status without retaining the source message."""
    match = _HTTP_STATUS_LABEL.search(message)
    return _coerce_http_status(match.group(1)) if match is not None else None


def _exception_http_status(error: BaseException) -> int | None:
    """Read a status from common exception/response attributes only."""
    for attribute in ("http_status", "status_code"):
        status = _coerce_http_status(getattr(error, attribute, None))
        if status is not None:
            return status
    response = getattr(error, "response", None)
    return _coerce_http_status(getattr(response, "status_code", None))


def _stable_error_type(error: BaseException) -> str:
    """Return an explicit or parsed error class, never a provider message."""
    explicit = getattr(error, "error_type", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    parsed = _error_type_from_message(str(error))
    return parsed or type(error).__name__


def _stable_http_status(error: BaseException) -> int | None:
    """Return status metadata from a safe marker or exception attributes."""
    explicit = _coerce_http_status(getattr(error, "http_status", None))
    if explicit is not None:
        return explicit
    status = _exception_http_status(error)
    if status is not None:
        return status
    return _http_status_from_message(str(error))


def _result_duration(result: LLMResult | None) -> int | None:
    """Return measured duration, leaving absent provider results unknown."""
    if result is None:
        return None
    value = getattr(result, "duration_ms", None)
    return int(value) if value is not None else None


def _record_verification_digest(
    record: dict[str, Any], response: BaseModel | None
) -> None:
    """Pin the interpretation supplied to the independent verifier."""
    if response is not None:
        record["verified_interpretation_digest"] = _digest_model(response)


def _result_prompt(result: LLMResult | None, field: str) -> str:
    """Read one prompt field from a result while accepting test doubles."""
    value = getattr(result, field, "") if result is not None else ""
    return value if isinstance(value, str) else ""


def _json_value(value: Any) -> Any:
    """Convert model/provider values into JSON-safe values without repr text."""
    if value is None:
        return None
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_text(value: Any) -> str:
    """Render one response value deterministically for JSONL accounting."""
    if isinstance(value, str):
        return value
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest_model(value: BaseModel) -> str:
    """Digest a typed model for verifier-side audit context."""
    return hashlib.sha256(
        canonical_json_bytes(value.model_dump(mode="json"))
    ).hexdigest()


__all__ = ["TargetDiscoveryLlmError", "TargetDiscoveryLlmInterpreter"]
