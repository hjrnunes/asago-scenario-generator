"""Profile-backed structured interpreter for the target-discovery seam.

This module is the only provider-aware part of the standalone scanner.  It
resolves a named model profile, delegates both structured calls to the shared
``call_with_policy`` boundary, and exposes deterministic call evidence back to
the pure discovery composition seam.  The shared call log in the
discovery output directory records each request; :meth:`drain_call_records`
returns those entries, with provider error text withheld, for the scanner to
publish.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StrictStr, create_model

from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.request_schema import (
    string_enum,
    string_items_enum,
    uses_guided_decoding,
)
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE,
    LLMClient,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
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
from .persistence import CALLS_FILENAME
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
        self.error_type = type(error).__name__
        self.http_status = _failure_http_status(error)
        status = f", status={self.http_status}" if self.http_status is not None else ""
        super().__init__(f"{kind} call failed ({self.error_type}{status})")


class TargetDiscoveryLlmInterpreter:
    """Issue one interpretation and one independent verifier call per batch."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        run_dir: Path,
        model_profile: str | None = None,
        temperature: float | None = None,
        max_completion_tokens: int | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._run_dir = Path(run_dir)
        self.model_profile = model_profile
        self.model_name = str(getattr(llm_client, "model", "unknown-model"))
        self._temperature = (
            temperature
            if temperature is not None
            else float(getattr(llm_client, "temperature", DEFAULT_TEMPERATURE))
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
        *,
        run_dir: Path,
        **kwargs: Any,
    ) -> "TargetDiscoveryLlmInterpreter":
        """Resolve one existing named model profile into an interpreter."""
        llm_client, resolved_profile = resolve_llm_client_from_profile(
            str(profiles_file), profile_name
        )
        return cls(
            llm_client,
            run_dir=run_dir,
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
        )
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
    ) -> BaseModel:
        """Run one safe structured call and collect what the shared log recorded."""
        calls_path = self._run_dir / CALLS_FILENAME
        offset = calls_path.stat().st_size if calls_path.exists() else 0
        parsed: BaseModel | None = None
        error: BaseException | None = None
        try:
            outcome = call_with_policy(
                llm_client=self._llm_client,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format=response_format,
                run_dir=self._run_dir,
                stage="target_discovery",
                step=kind,
                policy=CorrectionPolicy(),
                temperature=self._temperature,
                max_completion_tokens=self._max_completion_tokens,
                allow_unvalidated=False,
                prompt_template_hashes={
                    "target_discovery_prompt": prompt_hash(system_prompt, user_prompt)
                },
            )
            parsed = outcome.value
            if outcome.error is not None:
                error = outcome.failure or RuntimeError("safe_llm_call failed")
        except BaseException as exc:  # noqa: BLE001 - provider boundary
            error = exc
        failure = None
        if error is not None or parsed is None:
            failure = TargetDiscoveryLlmError(kind, error or RuntimeError("empty"))
        self._call_records.extend(
            _entries_logged_since(calls_path, offset, request.batch_id, failure)
        )
        if failure is not None:
            raise failure
        return parsed


def _entries_logged_since(
    calls_path: Path,
    offset: int,
    batch_id: str,
    failure: TargetDiscoveryLlmError | None,
) -> list[dict[str, Any]]:
    """Read the entries one call appended to the shared call log.

    The shared log keeps the provider's error text, which can carry a response
    body, so a failed call's entries keep only the failure class and status.
    """
    if not calls_path.exists():
        return []
    with calls_path.open("rb") as handle:
        handle.seek(offset)
        lines = handle.read().decode("utf-8").splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    for entry in entries:
        entry["batch_id"] = batch_id
        if failure is not None and "error" in entry:
            entry["error"] = str(failure)
    return entries


def _coerce_http_status(value: Any) -> int | None:
    """Return a conventional integer HTTP status while rejecting other values."""
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return None


def _failure_http_status(error: BaseException) -> int | None:
    """Read the status an SDK error carries on itself or on its response."""
    status = _coerce_http_status(getattr(error, "status_code", None))
    if status is not None:
        return status
    response = getattr(error, "response", None)
    return _coerce_http_status(getattr(response, "status_code", None))


__all__ = ["TargetDiscoveryLlmError", "TargetDiscoveryLlmInterpreter"]
