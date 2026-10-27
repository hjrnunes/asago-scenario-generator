"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.provider_record import (
    CallIdentity,
    call_identity,
    provider_requests_of,
)
from asago_scenario_generator.stpa.infra.transport_retry import (
    count_transport_retries,
)
from asago_scenario_generator.stpa.infra.call_log import (
    CallLog,
    _content_pin,
    _safe_error,
    append_call_log,
    call_log_of,
    make_call_log_entry,
)
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE,
    LLMClient,
    LLMResult,
    _plain_value,
    _response_content,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptAudit,
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    audit_prompt_contract,
    enforce_prompt_audit,
)
from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.request_schema import (
    flat_restore_drops,
    restore_flat_reply_for,
    restores_flat_replies,
)

_T = TypeVar("_T", bound=BaseModel)


class MissingCompletionBudget(ValueError):
    """A configured client declares no ``max_completion_tokens`` and the call sets none."""


def _preflight_configured_prompt(
    llm_client: LLMClient,
    *,
    system_prompt: str,
    user_prompt: str,
    stage: str,
    max_completion_tokens: int | None,
) -> PromptAudit | None:
    """Reject an oversized rendered prompt before a configured provider call."""
    context_window = getattr(llm_client, "context_window", None)
    if context_window is None:
        # Lightweight deterministic test adapters predate model profiles. Real
        # named profiles carry this value through LLMClient and are audited.
        return None
    completion = max_completion_tokens or getattr(
        llm_client, "max_completion_tokens", None
    )
    if completion is None:
        raise MissingCompletionBudget(
            "configured model must declare max_completion_tokens"
        )
    audit = audit_prompt_contract(
        stage=stage,
        prompt_view={},
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        budget=PromptBudget(
            context_window=context_window,
            maximum_completion_tokens=completion,
            safety_margin=getattr(llm_client, "safety_margin", None),
        ),
        raise_on_error=False,
    )
    return audit


def _prompt_audit_fields(audit: PromptAudit | None) -> dict[str, Any]:
    """Serialize one pre-dispatch audit into the durable provider call record."""
    if audit is None:
        return {}
    detail = {
        "rendered_prompt_digest": audit.rendered_prompt_digest,
        "input_tokens": audit.input_tokens,
        "input_tokens_estimated": audit.input_tokens_estimated,
        "context_window": audit.context_window,
        "maximum_completion_tokens": audit.maximum_completion_tokens,
        "safety_margin": audit.safety_margin,
        "usable_input_tokens": audit.usable_input_tokens,
        "provider_call_allowed": audit.ok,
        "errors": list(audit.errors),
    }
    return {
        "rendered_prompt_digest": audit.rendered_prompt_digest,
        "preflight_input_tokens": audit.input_tokens,
        "prompt_preflight": detail,
    }


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _safe_error_detail(error: BaseException) -> str:
    """Keep typed error context while excluding connection material."""
    return _safe_error(str(error))


def _transformation(
    name: str,
    input_value: Any,
    output_value: Any,
    *,
    detail: str | None = None,
) -> dict[str, Any]:
    """Build one ordered, content-pinned cleanup record."""
    item: dict[str, Any] = {
        "name": name,
        "input_pin": _content_pin(
            input_value, "stpa-cleanup-input-v1", jsonable=False, stringify=True
        ),
        "output_pin": _content_pin(
            output_value, "stpa-cleanup-output-v1", jsonable=False, stringify=True
        ),
    }
    if detail:
        item["detail"] = detail
    return item


def _decode_json_text_with_evidence(
    value: str,
) -> tuple[Any, list[dict[str, Any]]]:
    """Decode JSON while retaining each applied cleanup transformation."""
    transformations: list[dict[str, Any]] = []
    current = value
    try:
        decoded = json.loads(current.strip())
    except json.JSONDecodeError as initial_error:
        current, fenced = _remove_markdown_fence(current)
        if fenced is not None:
            transformations.append(
                _transformation(
                    "markdown_fence_removal",
                    value,
                    fenced,
                    detail="removed one exact outer Markdown fence",
                )
            )
        try:
            decoded = json.loads(current.strip())
        except json.JSONDecodeError:
            repaired = _TRAILING_COMMA.sub(r"\1", current)
            if repaired == current:
                raise initial_error
            transformations.append(
                _transformation(
                    "trailing_comma_repair",
                    current,
                    repaired,
                    detail="removed commas immediately before object/array closure",
                )
            )
            current = repaired
            decoded = json.loads(current.strip())
    transformations.append(
        _transformation(
            "plain_json_decode",
            current,
            decoded,
            detail="decoded the cleaned JSON text",
        )
    )
    return decoded, transformations


def _fenced_json_body(value: str) -> str | None:
    """Return the body inside one exact outer JSON Markdown fence, else None."""
    lines = value.strip().splitlines()
    if (
        len(lines) >= 3
        and lines[0].strip().lower() in {"```json", "```"}
        and lines[-1].strip() == "```"
    ):
        return "\n".join(lines[1:-1])
    return None


def strip_json_fence(text: str) -> str:
    """Return the body inside one exact outer JSON fence, else the stripped text."""
    body = _fenced_json_body(text)
    return text.strip() if body is None else body


def _remove_markdown_fence(value: str) -> tuple[str, str | None]:
    """Remove one exact outer JSON Markdown fence when present."""
    body = _fenced_json_body(value)
    if body is None:
        return value, None
    return body, body


class StageError(Exception):
    """Exception carrying stage and step context for a failed LLM call.

    Attributes:
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
        message: Human-readable error description.
    """

    def __init__(self, *, stage: str, step: str, message: str) -> None:
        self.stage = stage
        self.step = step
        self.message = message
        super().__init__(f"{stage}/{step}: {message}")


def _stringify_response_content(content: Any) -> str:
    """Convert LLM response content to a string for logging.

    Handles Pydantic models, dicts, and raw strings.
    """
    if content is None:
        return ""
    if isinstance(content, BaseModel):
        return json.dumps(raw_model_data(content))
    if isinstance(content, dict):
        return json.dumps(content)
    return str(content)


def _has_provider_choices(response: Any) -> bool:
    """Return whether an attached object exposes a usable choice list."""
    choices = getattr(response, "choices", None)
    if not choices:
        return False
    try:
        choices[0]
    except (IndexError, KeyError, TypeError):
        return False
    return True


def _attached_provider_response(error: BaseException) -> Any | None:
    """Recover a completion attached to an SDK parse/validation exception.

    OpenAI-compatible SDKs commonly attach the already received completion to
    ``completion`` when structured parsing fails.  A few adapters use
    ``response`` or ``raw_response``.  Only objects with a non-empty
    ``choices`` collection are treated as provider responses; exception text
    and transport bodies are never copied into the durable response field.
    """
    for attribute in ("completion", "response", "raw_response"):
        attached = getattr(error, attribute, None)
        if _has_provider_choices(attached):
            return attached
    return None


def _provider_response_usage(response: Any) -> tuple[int | None, int | None]:
    """Extract usage counters from an attached provider completion."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return None, None
    return (
        (
            int(usage.prompt_tokens)
            if getattr(usage, "prompt_tokens", None) is not None
            else None
        ),
        (
            int(usage.completion_tokens)
            if getattr(usage, "completion_tokens", None) is not None
            else None
        ),
    )


def _provider_response_usage_details(response: Any) -> dict[str, Any]:
    """Preserve nested usage details from an attached provider response."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    value = _plain_value(usage)
    return value if isinstance(value, dict) else {}


def parse_llm_result(
    result: LLMResult,
    model_class: type[_T],
    *,
    cleanup_transformations: list[dict[str, Any]] | None = None,
) -> _T:
    """Parse and validate an LLM result into the specified Pydantic model.

    Handles three content types the LLM client may return:
    - An already-parsed model instance (returned as-is).
    - A plain dict (validated via ``model_validate``).
    - A JSON string (parsed then validated).

    Args:
        result: The LLM result wrapper.
        model_class: The target Pydantic model class.

    Returns:
        A validated instance of *model_class*.

    Raises:
        ValidationError: If the content cannot be parsed into *model_class*.
    """
    content = result.content
    if isinstance(content, model_class):
        return content
    if isinstance(content, dict):
        return model_class.model_validate(restore_flat_reply_for(model_class, content))
    if isinstance(content, str):
        decoded, transformations = _decode_json_text_with_evidence(content)
        if cleanup_transformations is not None:
            cleanup_transformations.extend(transformations)
        return model_class.model_validate(restore_flat_reply_for(model_class, decoded))
    raise TypeError(
        f"Unexpected LLM result content type: {type(content).__name__}, "
        f"expected {model_class.__name__}, dict, or str."
    )


def decode_content(
    result: LLMResult,
    *,
    cleanup_transformations: list[dict[str, Any]] | None = None,
) -> Any:
    """Decode the JSON-shaped content of an LLM result without validation."""
    content = result.content
    if isinstance(content, BaseModel):
        return raw_model_data(content)
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        decoded, transformations = _decode_json_text_with_evidence(content)
        if cleanup_transformations is not None:
            cleanup_transformations.extend(transformations)
        return decoded
    raise TypeError(
        f"Unexpected LLM result content type: {type(content).__name__}, "
        "expected a Pydantic model, dict, or JSON string."
    )


def _build_completion_kwargs(
    *,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    temperature: float,
    max_completion_tokens: int | None,
) -> dict[str, Any]:
    """Build the common keyword arguments for a structured completion."""
    completion_kwargs: dict[str, Any] = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "response_format": response_format,
        "temperature": temperature,
    }
    if max_completion_tokens is not None:
        completion_kwargs["max_completion_tokens"] = max_completion_tokens
    return completion_kwargs


def _result_usage(
    result: LLMResult | None,
) -> tuple[int | None, int | None, int]:
    """Return prompt tokens, completion tokens, and duration for a result."""
    if result is None:
        return None, None, 0
    return result.prompt_tokens, result.completion_tokens, result.duration_ms


@dataclass
class _SafeCallState:
    """Mutable state retained while one bounded structured call is attempted."""

    result: LLMResult | None = None
    prompt_audit: PromptAudit | None = None
    raw_result_validation_failed: bool = False
    result_validation_failed: bool = False
    response_parser_failed: bool = False
    draft_parsed: bool = False
    semantic_validation_passed: bool = False
    cleanup_transformations: list[dict[str, Any]] = field(default_factory=list)
    flat_restore_drops: tuple[dict[str, str], ...] = ()
    cleaned_response: Any | None = None
    attempt_number: int = 1
    dispatched: bool = False
    transport_retries: int = 0
    retry_of: str | None = None
    logged_attempt_id: str | None = None
    provider_requests: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _FailureEvidence:
    """Safe provider evidence copied into one failed call record."""

    prompt_tokens: int | None
    completion_tokens: int | None
    duration_ms: int
    response_content: str | None
    provider_response_received: bool
    usage_details: dict[str, Any]


def _failure_class(
    error: BaseException,
    *,
    provider_response_received: bool,
    state: _SafeCallState,
) -> str:
    """Classify configuration, transport, malformed, and answered semantic failures."""
    if isinstance(error, MissingCompletionBudget):
        return "configuration_failure"
    if not provider_response_received:
        return "provider_failure"
    if state.result_validation_failed:
        return "answered_semantic_failure"
    if isinstance(error, json.JSONDecodeError):
        return "answered_malformed"
    if any(
        (
            state.raw_result_validation_failed,
            isinstance(error, (ValidationError, TypeError)),
            state.response_parser_failed,
        )
    ):
        return "answered_schema_failure"
    return "answered_failure"


def _failure_evidence(
    result: LLMResult | None,
    error: BaseException,
) -> _FailureEvidence:
    """Extract usage/content while excluding exception bodies from evidence."""
    attached = None if result is not None else _attached_provider_response(error)
    if result is not None:
        prompt_tokens, completion_tokens, duration_ms = _result_usage(result)
        response_content = _stringify_response_content(result.content)
        usage_details = dict(result.usage_details)
    else:
        prompt_tokens, completion_tokens = _provider_response_usage(attached)
        duration_ms = 0
        usage_details = _provider_response_usage_details(attached)
        response_content = (
            _stringify_response_content(_response_content(attached))
            if attached is not None
            else None
        )
    return _FailureEvidence(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        duration_ms=duration_ms,
        response_content=response_content,
        provider_response_received=result is not None or attached is not None,
        usage_details=usage_details,
    )


def _raw_response_for_failure(
    result: LLMResult | None,
    evidence: _FailureEvidence,
) -> Any | None:
    """Return exact raw content only when the adapter exposed it."""
    if result is None:
        return evidence.response_content
    if result.raw_response is not None:
        return result.raw_response
    if isinstance(result.content, str):
        return result.content
    return None


def _call_client(
    llm_client: LLMClient,
    completion_kwargs: dict[str, Any],
    state: _SafeCallState,
) -> LLMResult:
    """Call a client, counting the transport retries the client makes.

    The provider records the call sent are kept for its call-log entry.
    """
    with count_transport_retries() as retries:
        try:
            return llm_client.complete(**completion_kwargs)
        finally:
            state.transport_retries += retries.count
            state.provider_requests = provider_requests_of(llm_client)


def _request_controls(
    result: LLMResult | None, state: _SafeCallState
) -> dict[str, Any]:
    """Retain nonsecret controls and the transport retry count."""
    controls = dict(result.request_controls) if result is not None else {}
    if state.transport_retries:
        controls["transport_retries"] = state.transport_retries
    return controls


def _validate_raw_result(
    result: LLMResult,
    validator: Callable[[Any], None] | None,
    state: _SafeCallState,
) -> None:
    """Run pre-parse validation while retaining its failure classification."""
    if validator is None:
        return
    try:
        validator(
            decode_content(
                result,
                cleanup_transformations=state.cleanup_transformations,
            )
        )
    except Exception:
        state.raw_result_validation_failed = True
        raise


def _parse_and_validate_result(
    result: LLMResult,
    response_format: type[_T],
    response_parser: Callable[[LLMResult, list[dict[str, Any]]], _T] | None,
    result_validator: Callable[[_T], _T | None] | None,
    state: _SafeCallState,
) -> _T:
    """Parse one result and run optional stage-local semantic validation."""
    state.flat_restore_drops = _flat_restore_drops(result, response_format)
    try:
        model = _parse_structured_result(
            result,
            response_format,
            response_parser=response_parser,
            cleanup_transformations=state.cleanup_transformations,
        )
        state.draft_parsed = True
    except Exception:
        state.response_parser_failed = response_parser is not None
        raise
    if result_validator is None:
        return model
    try:
        checked = result_validator(model)
    except Exception:
        state.result_validation_failed = True
        raise
    return model if checked is None else checked


def _perform_safe_call(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    run_dir: Path,
    stage: str,
    step: str,
    temperature: float,
    max_completion_tokens: int | None,
    raw_result_validator: Callable[[Any], None] | None,
    result_validator: Callable[[_T], _T | None] | None,
    response_parser: Callable[[LLMResult, list[dict[str, Any]]], _T] | None,
    slot_id: str | None,
    scenario_id: str | None,
    prompt_template_hashes: Mapping[str, str] | None,
    state: _SafeCallState,
    attempt_number: int,
) -> _T:
    """Execute one complete structured attempt and log a successful result."""
    state.prompt_audit = _preflight_configured_prompt(
        llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        stage=stage,
        max_completion_tokens=max_completion_tokens,
    )
    enforce_prompt_audit(state.prompt_audit)
    completion_kwargs = _build_completion_kwargs(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        temperature=temperature,
        max_completion_tokens=max_completion_tokens,
    )
    state.attempt_number = attempt_number
    state.dispatched = True
    state.result = _call_client(llm_client, completion_kwargs, state=state)
    _validate_raw_result(state.result, raw_result_validator, state)
    model = _parse_and_validate_result(
        state.result,
        response_format,
        response_parser,
        result_validator,
        state,
    )
    state.cleaned_response = model
    state.semantic_validation_passed = True
    state.logged_attempt_id = log_llm_call(
        state.result,
        llm_client.model,
        run_dir,
        stage,
        step,
        slot_id=slot_id,
        scenario_id=scenario_id,
        prompt_audit=state.prompt_audit,
        prompt_template_hashes=prompt_template_hashes,
        attempt_number=state.attempt_number,
        cleanup_transformations=tuple(state.cleanup_transformations),
        flat_restore_drops=state.flat_restore_drops,
        cleaned_response=model,
        request_controls=_request_controls(state.result, state),
        call_log=call_log_of(llm_client),
        retry_of=state.retry_of,
        provider_requests=state.provider_requests,
    )
    return model


def _log_structured_failure(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    stage: str,
    step: str,
    attempt_user_prompt: str,
    system_prompt: str,
    error: BaseException,
    state: _SafeCallState,
    slot_id: str | None,
    scenario_id: str | None,
    prompt_template_hashes: Mapping[str, str] | None,
    attempt_number: int,
) -> str:
    """Log one structured failure and return its stable display message."""
    error_msg = f"{type(error).__name__}: {_safe_error_detail(error)}"
    evidence = _failure_evidence(state.result, error)
    state.logged_attempt_id = log_llm_call_failure(
        llm_client.model,
        run_dir,
        stage,
        step,
        error_msg,
        system_prompt=system_prompt,
        user_prompt=attempt_user_prompt,
        prompt_tokens=evidence.prompt_tokens,
        completion_tokens=evidence.completion_tokens,
        usage_details=evidence.usage_details,
        duration_ms=evidence.duration_ms,
        prompt_audit=state.prompt_audit,
        provider_response_received=evidence.provider_response_received,
        draft_parsed=state.draft_parsed,
        semantic_validation_passed=state.semantic_validation_passed,
        compiled=state.semantic_validation_passed,
        response_content=evidence.response_content,
        raw_response=_raw_response_for_failure(state.result, evidence),
        cleaned_response=state.cleaned_response,
        cleanup_transformations=tuple(state.cleanup_transformations),
        flat_restore_drops=state.flat_restore_drops,
        attempt_number=state.attempt_number,
        request_controls=_request_controls(state.result, state),
        failure_class=_failure_class(
            error,
            provider_response_received=evidence.provider_response_received,
            state=state,
        ),
        call_log=call_log_of(llm_client),
        provider_requests=state.provider_requests,
        slot_id=slot_id,
        scenario_id=scenario_id,
        terminal_error_codes=(
            _terminal_error_code(
                error,
                provider_response_received=evidence.provider_response_received,
            ),
        ),
        prompt_template_hashes=prompt_template_hashes,
        retry_of=state.retry_of,
    )
    return error_msg


def _retry_kind(
    error: BaseException,
    state: _SafeCallState,
    json_retries_remaining: int,
    validation_retries_remaining: int,
    *,
    correct_undecodable: bool = False,
) -> str | None:
    """Select the existing bounded retry policy without changing precedence."""
    if isinstance(error, json.JSONDecodeError) and json_retries_remaining:
        return "json"
    if (
        _validation_retry_requested(
            error, state, correct_undecodable=correct_undecodable
        )
        and validation_retries_remaining
    ):
        return "validation"
    return None


def _validation_retry_requested(
    error: BaseException,
    state: _SafeCallState,
    *,
    correct_undecodable: bool = False,
) -> bool:
    """Report whether a failure belongs to the validation retry set.

    An undecodable body joins the set only when the policy opts in and the
    provider answered, so the correction has a reply to carry.
    """
    if isinstance(error, json.JSONDecodeError):
        return correct_undecodable and state.result is not None
    return bool(
        isinstance(error, ValidationError)
        or state.raw_result_validation_failed
        or state.result_validation_failed
        or state.response_parser_failed
    )


@dataclass(frozen=True)
class CorrectionPolicy:
    """Which failed responses earn another request, and what it carries.

    An undecodable body earns up to ``json_retries`` repeats of the same
    prompt.  A schema, parser, or validator failure earns up to
    ``validation_retries`` correction requests: the original prompt plus
    ``feedback``, the prior response when ``include_response``, the exact
    error, and the response schema when ``include_schema``.  ``feedback`` is
    text, or a function from the failure to the text.  ``error_note`` is a
    function from the failure to a note placed right after the exact error;
    an empty note adds nothing.  Every other failure ends the call.

    With ``correct_undecodable``, an undecodable body that no ``json_retries``
    repeat covers also earns a validation correction.  That correction shows
    the prior response without its trailing whitespace, so a reply that ended
    in a whitespace run never reaches the prompt.  Pass a ``feedback``
    function to word it for the decode error.
    """

    json_retries: int = 0
    validation_retries: int = 0
    feedback: str | Callable[[Exception], str] | None = None
    include_schema: bool = True
    include_response: bool = False
    error_note: Callable[[Exception], str] | None = None
    correct_undecodable: bool = False

    def __post_init__(self) -> None:
        if self.json_retries < 0 or self.validation_retries < 0:
            raise ValueError("retry counts must be non-negative")


@dataclass(frozen=True)
class CallOutcome(Generic[_T]):
    """The published model or the last error, and the requests dispatched.

    ``failure`` is the exception behind ``error``, for a caller that reads
    typed detail from it.  ``attempt_number`` is the number of the last
    attempt, so a follow-up request in the same step can continue it.
    ``attempt_id`` is the call-log id of the last attempt, which a follow-up
    request names as its ``retry_of``; it is ``None`` when nothing was logged.
    """

    value: _T | None
    result: LLMResult | None
    error: str | None
    calls: int
    failure: BaseException | None = None
    attempt_number: int = 1
    attempt_id: str | None = None


@dataclass
class RequestTally:
    """The requests dispatched inside one :func:`count_requests` scope."""

    requests: int = 0


_TALLIES: ContextVar[tuple[RequestTally, ...]] = ContextVar(
    "request_tallies", default=()
)


@contextmanager
def count_requests(tally: RequestTally | None = None) -> Iterator[RequestTally]:
    """Tally every request :func:`call_with_policy` dispatches inside the block.

    The tally stays readable after the block ends, also when the block raised.
    Scopes nest: an outer tally includes the requests of its inner scopes.
    Pass *tally* to keep adding to one tally across several scopes.
    """
    tally = RequestTally() if tally is None else tally
    token = _TALLIES.set((*_TALLIES.get(), tally))
    try:
        yield tally
    finally:
        _TALLIES.reset(token)


def _dispatched(calls: int) -> int:
    """Add *calls* dispatched requests to every active tally."""
    for tally in _TALLIES.get():
        tally.requests += calls
    return calls


_EXACT_FEEDBACK_MAX_CHARS = 4000


class ExactFeedbackError(ValueError):
    """A result-validator failure whose itemized text is the correction.

    The correction prompt keeps its line breaks and uses a larger bound
    than for other errors, so every listed failure reaches the model.
    ``max_chars`` is that bound; a subclass whose list must reach the model
    whole at any length sets it to ``None``.
    """

    max_chars: int | None = _EXACT_FEEDBACK_MAX_CHARS


def correction_prompt(
    *,
    original_prompt: str,
    feedback: str | None,
    error: Exception,
    response_format: type[BaseModel],
    include_schema: bool,
    prior_result: LLMResult | None = None,
    include_prior_response: bool = False,
    error_note: str = "",
) -> str:
    """Build a bounded correction prompt with field-specific validation errors."""
    suffix = feedback or ""
    if include_prior_response and prior_result is not None:
        prior_response = _stringify_response_content(prior_result.content)
        if isinstance(error, json.JSONDecodeError):
            # A whitespace runaway would add its whole run to the prompt.
            prior_response = prior_response.rstrip()
        suffix += (
            "\n\nPrior structured response to correct in place:\n"
            f"```json\n{prior_response}\n```"
        )
    suffix += (
        "\n\nExact validation error from the prior response:\n"
        f"{compact_validation_error(error)}"
    )
    if error_note:
        suffix += f"\n\n{error_note}"
    if include_schema:
        schema = json.dumps(
            response_format.model_json_schema(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        suffix += (
            "\n\nExpected response schema (return one JSON object matching it):\n"
            f"```json\n{schema}\n```"
        )
    else:
        suffix += (
            "\n\nReturn one JSON object matching the response schema already supplied."
        )
    return original_prompt + suffix


def compact_validation_error(error: Exception) -> str:
    """Describe failed fields without echoing prior input or verbose URLs."""
    if isinstance(error, ValidationError):
        return "ValidationError:\n" + "\n".join(_validation_error_lines(error))
    if isinstance(error, json.JSONDecodeError):
        return (
            f"JSONDecodeError at line {error.lineno}, column {error.colno}: {error.msg}"
        )
    if isinstance(error, ExactFeedbackError):
        message = "\n".join(" ".join(line.split()) for line in str(error).splitlines())
        if error.max_chars is not None:
            message = _truncated(message, error.max_chars)
        return f"ValueError: {message}"
    message = " ".join(str(error).split())
    return f"{type(error).__name__}: {_truncated(message, 800)}"


def _validation_error_lines(error: ValidationError) -> list[str]:
    """Describe at most eight failed fields, without input values or URLs."""
    items = error.errors(include_url=False, include_context=False)
    return [
        f"- {'.'.join(str(part) for part in item['loc']) or 'response'}: "
        f"{_model_facing_message(item)} ({item['type']})"
        for item in items[:8]
    ]


def _model_facing_message(item: Mapping[str, Any]) -> str:
    """Return the error message with no private wire class name in it.

    Pydantic words a ``model_type`` failure as "... or instance of <Class>",
    and the class is an internal wire model the response never mentions.
    A type failure on a null says so, since the message alone reads the
    same for any wrong value.
    """
    message = (
        "Input should be an object"
        if item["type"] == "model_type"
        else str(item["msg"])
    )
    if item.get("input", _NO_INPUT) is None and _is_type_failure(item["type"]):
        return f"{message}, not null"
    return message


_NO_INPUT = object()


def _is_type_failure(error_type: str) -> bool:
    """Whether a Pydantic error type rejects the kind of value given."""
    return error_type.endswith("_type") or error_type in ("literal_error", "enum")


def _truncated(message: str, limit: int) -> str:
    """Shorten *message* to *limit* characters, ending in an ellipsis when cut."""
    if len(message) > limit:
        return message[: limit - 3] + "..."
    return message


def _parse_structured_result(
    result: LLMResult,
    response_format: type[_T],
    response_parser: (Callable[[LLMResult, list[dict[str, Any]]], _T] | None) = None,
    cleanup_transformations: list[dict[str, Any]] | None = None,
) -> _T:
    """Parse a structured result with the stage parser or the response model."""
    if response_parser is not None:
        return response_parser(
            _restored_result(result, response_format),
            cleanup_transformations if cleanup_transformations is not None else [],
        )
    return parse_llm_result(
        result,
        response_format,
        cleanup_transformations=cleanup_transformations,
    )


def _flat_restore_drops(
    result: LLMResult, response_format: type[BaseModel]
) -> tuple[dict[str, str], ...]:
    """Return the drops the flat-reply restore makes for ``result``.

    The restore runs at several parse sites, each on the same decoded reply,
    so one pass over that reply lists what any of them drops.  A reply that
    does not decode has no drop.
    """
    if not restores_flat_replies(response_format):
        return ()
    content = result.content
    if not isinstance(content, (dict, str)):
        content = result.raw_response
    if isinstance(content, str):
        try:
            content = _decode_json_text_with_evidence(content)[0]
        except ValueError:
            return ()
    return tuple(flat_restore_drops(response_format, content))


def _restored_result(result: LLMResult, response_format: type[_T]) -> LLMResult:
    """Return ``result`` with a flat reply restored for a stage parser.

    The parser still decodes the content itself, so restored text stays text.
    The result the caller keeps (and logs) is not changed.
    """
    if not restores_flat_replies(response_format):
        return result
    content = result.content
    if isinstance(content, str):
        try:
            decoded = json.loads(strip_json_fence(content))
        except json.JSONDecodeError:
            return result
        restored = restore_flat_reply_for(response_format, decoded)
        text = json.dumps(restored, ensure_ascii=False)
        return result if restored == decoded else _with_content(result, text)
    if isinstance(content, dict):
        restored = restore_flat_reply_for(response_format, content)
        return result if restored == content else _with_content(result, restored)
    return result


def _with_content(result: LLMResult, content: Any) -> LLMResult:
    return result.model_copy(update={"content": content})


def log_llm_call(
    result: LLMResult,
    model: str,
    run_dir: Path,
    stage: str,
    step: str,
    *,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    prompt_audit: PromptAudit | None = None,
    prompt_template_hashes: Mapping[str, str] | None = None,
    attempt_number: int = 1,
    cleanup_transformations: tuple[Mapping[str, Any], ...] = (),
    flat_restore_drops: tuple[Mapping[str, str], ...] = (),
    cleaned_response: Any | None = None,
    request_controls: Mapping[str, Any] | None = None,
    call_log: CallLog | None = None,
    retry_of: str | None = None,
    provider_requests: Sequence[Mapping[str, Any]] = (),
) -> str:
    """Append a call-log entry for a single LLM call and return its attempt id.

    Args:
        result: The LLM result wrapper (provides prompts and token counts).
        model: The model name used for the call.
        run_dir: Directory where ``calls.jsonl`` is appended.
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
        provider_requests: The ``provider-calls.jsonl`` records the call
            wrote.  With any, the entry names them instead of holding the
            prompt and response text; with none it keeps the text.
    """
    _success = True
    _response_content = _stringify_response_content(result.content)
    raw_response = (
        result.raw_response
        if result.raw_response is not None
        else result.content
        if isinstance(result.content, str)
        else None
    )
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        usage_details=result.usage_details,
        duration_ms=result.duration_ms,
        success=_success,
        slot_id=slot_id,
        scenario_id=scenario_id,
        response_content=_response_content,
        raw_response=raw_response,
        cleaned_response=(
            result.content if cleaned_response is None else cleaned_response
        ),
        cleanup_transformations=cleanup_transformations,
        flat_restore_drops=flat_restore_drops,
        attempt_number=attempt_number,
        request_controls=(
            dict(result.request_controls)
            if request_controls is None
            else dict(request_controls)
        ),
        provider_response_received=True,
        draft_parsed=True,
        semantic_validation_passed=True,
        compiled=False,
        published=False,
        prompt_template_hashes=prompt_template_hashes,
        retry_of=retry_of,
        provider_requests=provider_requests,
        response_parsed=isinstance(result.content, BaseModel),
    )
    entry.update(_prompt_audit_fields(prompt_audit))
    append_call_log([entry], run_dir, call_log)
    return str(entry["attempt_id"])


def log_llm_call_failure(
    model: str,
    run_dir: Path,
    stage: str,
    step: str,
    error: str,
    *,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    usage_details: Mapping[str, Any] | None = None,
    duration_ms: int = 0,
    prompt_audit: PromptAudit | None = None,
    provider_response_received: bool = False,
    draft_parsed: bool = False,
    semantic_validation_passed: bool = False,
    compiled: bool = False,
    response_content: str | None = None,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    terminal_error_codes: tuple[str, ...] = ("provider_call_failure",),
    prompt_template_hashes: Mapping[str, str] | None = None,
    raw_response: Any | None = None,
    cleaned_response: Any | None = None,
    cleanup_transformations: tuple[Mapping[str, Any], ...] = (),
    flat_restore_drops: tuple[Mapping[str, str], ...] = (),
    attempt_number: int = 1,
    request_controls: Mapping[str, Any] | None = None,
    failure_class: str | None = None,
    call_log: CallLog | None = None,
    retry_of: str | None = None,
    provider_requests: Sequence[Mapping[str, Any]] = (),
) -> str:
    """Append a call-log entry for a failed LLM call and return its attempt id.

    Args:
        model: The model name used for the call.
        run_dir: Directory where ``calls.jsonl`` is appended.
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
        error: Error message describing the failure.
        system_prompt: System prompt text (hashed in the entry).
        user_prompt: User prompt text (hashed in the entry).
        prompt_tokens: Prompt tokens consumed (0 if call failed before completion).
        completion_tokens: Completion tokens generated (0 if call failed before completion).
        duration_ms: Wall-clock duration in milliseconds (0 if not measured).
        provider_requests: As for :func:`log_llm_call`; none when the call
            failed before dispatch.
    """
    _success = False
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        usage_details=usage_details,
        duration_ms=duration_ms,
        success=_success,
        error=error,
        slot_id=slot_id,
        scenario_id=scenario_id,
        response_content=response_content,
        raw_response=raw_response,
        cleaned_response=cleaned_response,
        cleanup_transformations=cleanup_transformations,
        flat_restore_drops=flat_restore_drops,
        attempt_number=attempt_number,
        request_controls=request_controls,
        failure_class=failure_class,
        provider_response_received=provider_response_received,
        draft_parsed=draft_parsed,
        semantic_validation_passed=semantic_validation_passed,
        compiled=compiled,
        terminal_error_codes=terminal_error_codes,
        prompt_template_hashes=prompt_template_hashes,
        retry_of=retry_of,
        provider_requests=provider_requests,
    )
    entry.update(_prompt_audit_fields(prompt_audit))
    append_call_log([entry], run_dir, call_log)
    return str(entry["attempt_id"])


def call_with_policy(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    run_dir: Path,
    stage: str,
    step: str,
    policy: CorrectionPolicy,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    max_completion_tokens: int | None = None,
    raw_result_validator: Callable[[Any], None] | None = None,
    result_validator: Callable[[_T], _T | None] | None = None,
    response_parser: (Callable[[LLMResult, list[dict[str, Any]]], _T] | None) = None,
    prompt_template_hashes: Mapping[str, str] | None = None,
    first_attempt_number: int = 1,
    retry_of: str | None = None,
) -> CallOutcome[_T]:
    """Request a structured response, correcting it as ``policy`` allows.

    Each attempt is logged independently.  The outcome carries the published
    model or the last attempt's error, and the number of requests actually
    dispatched (a prompt blocked by preflight dispatches none).

    Args:
        llm_client: LLM client for making the completion call.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        response_format: Target Pydantic model class for validation.
        run_dir: Directory for call logging.
        stage: Pipeline stage identifier.
        step: Sub-step within the stage.
        policy: Which failures earn another request, and what it carries.
        slot_id: Exact ICA slot identity for durable call evidence, when applicable.
        scenario_id: Exact scenario identity for durable call evidence, when applicable.
        temperature: LLM temperature.
        max_completion_tokens: Optional cap on completion tokens. When
            provided, forwarded to ``llm_client.complete``.
        raw_result_validator: Optional validation to run on the decoded
            response before parsing.
        result_validator: Optional additional validation to run on the parsed
            model before the call is logged as successful. A
            validator that returns a model publishes that model, which is
            logged and returned, in place of the parsed one.
        response_parser: Optional stage-local parser for semantic responses.
            It receives the raw ``LLMResult`` and the mutable
            cleanup-transformation list of the durable call record, and must
            return a validated response model. Use it when a stage needs
            stricter wire validation than the shared compatibility decoder
            provides; a parser that applies a response correction appends it
            to the list so the record keeps it apart from model output.
        first_attempt_number: Number of the first attempt in the call log; a
            follow-up request in the same step continues the numbering.
        retry_of: Call-log ``attempt_id`` of the failed attempt the first
            attempt repeats, recorded as its ``retry_of``; later attempts
            name the attempt before them.
    """
    json_retries_remaining = policy.json_retries
    validation_retries_remaining = policy.validation_retries
    attempt_user_prompt = user_prompt
    attempt_number = first_attempt_number
    calls = 0
    while True:
        state = _SafeCallState(retry_of=retry_of)
        try:
            with call_identity(
                CallIdentity(
                    stage=stage,
                    step=step,
                    slot_id=slot_id,
                    scenario_id=scenario_id,
                    attempt_number=attempt_number,
                )
            ):
                model = _perform_safe_call(
                    llm_client=llm_client,
                    system_prompt=system_prompt,
                    user_prompt=attempt_user_prompt,
                    response_format=response_format,
                    run_dir=run_dir,
                    stage=stage,
                    step=step,
                    temperature=temperature,
                    max_completion_tokens=max_completion_tokens,
                    raw_result_validator=raw_result_validator,
                    result_validator=result_validator,
                    response_parser=response_parser,
                    slot_id=slot_id,
                    scenario_id=scenario_id,
                    prompt_template_hashes=prompt_template_hashes,
                    state=state,
                    attempt_number=attempt_number,
                )
            return CallOutcome(
                model,
                state.result,
                None,
                _dispatched(calls + 1 + state.transport_retries),
                attempt_number=attempt_number,
                attempt_id=state.logged_attempt_id,
            )
        except Exception as exc:
            calls += state.dispatched + state.transport_retries
            error_msg = _log_structured_failure(
                llm_client=llm_client,
                run_dir=run_dir,
                stage=stage,
                step=step,
                attempt_user_prompt=attempt_user_prompt,
                system_prompt=system_prompt,
                error=exc,
                state=state,
                slot_id=slot_id,
                scenario_id=scenario_id,
                prompt_template_hashes=prompt_template_hashes,
                attempt_number=attempt_number,
            )
            retry_kind = _retry_kind(
                exc,
                state,
                json_retries_remaining,
                validation_retries_remaining,
                correct_undecodable=policy.correct_undecodable,
            )
            if retry_kind == "json":
                json_retries_remaining -= 1
                attempt_number += 1
                retry_of = state.logged_attempt_id
                continue
            if retry_kind == "validation":
                validation_retries_remaining -= 1
                attempt_number += 1
                retry_of = state.logged_attempt_id
                attempt_user_prompt = correction_prompt(
                    original_prompt=user_prompt,
                    feedback=(
                        policy.feedback(exc)
                        if callable(policy.feedback)
                        else policy.feedback
                    ),
                    error=exc,
                    response_format=response_format,
                    include_schema=policy.include_schema,
                    prior_result=state.result,
                    include_prior_response=policy.include_response,
                    error_note=policy.error_note(exc) if policy.error_note else "",
                )
                continue
            return CallOutcome(
                None,
                state.result,
                error_msg,
                _dispatched(calls),
                exc,
                attempt_number=attempt_number,
                attempt_id=state.logged_attempt_id,
            )


def _terminal_error_code(
    error: BaseException,
    *,
    provider_response_received: bool = False,
) -> str:
    """Map provider-stage failures to stable lifecycle diagnostics.

    A provider that answered but whose answer failed stage-local semantic
    validation is not a call failure: the record already shows
    ``provider_response_received``, so the code names the semantic failure
    instead.
    """
    if isinstance(error, PromptBudgetExceeded):
        return "prompt_budget_exceeded"
    if isinstance(error, (ValidationError, json.JSONDecodeError)):
        return "provider_contract_failure"
    if isinstance(error, PromptContractError):
        return "provider_contract_failure"
    if provider_response_received:
        return "provider_semantic_validation_failure"
    return "provider_call_failure"


def is_provider_contract_failure(error: BaseException | None) -> bool:
    """Tell whether the call log records *error* as ``provider_contract_failure``."""
    return error is not None and (
        _terminal_error_code(error) == "provider_contract_failure"
    )
