"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptAudit,
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    audit_prompt_contract,
)
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa._model_data import raw_model_data

_T = TypeVar("_T", bound=BaseModel)


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
        raise ValueError("configured model must declare max_completion_tokens")
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


def _enforce_prompt_audit(audit: PromptAudit | None) -> None:
    """Fail before dispatch while allowing callers to retain the audit."""
    if audit is None or audit.ok:
        return
    if (
        audit.usable_input_tokens is not None
        and audit.input_tokens > audit.usable_input_tokens
    ):
        raise PromptBudgetExceeded(
            input_tokens=audit.input_tokens,
            usable_input_tokens=audit.usable_input_tokens,
            context_window=audit.context_window or 0,
            maximum_completion_tokens=audit.maximum_completion_tokens or 0,
            safety_margin=audit.safety_margin or 0,
        )
    raise PromptContractError(*audit.errors)


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
        "provider_call_allowed": audit.provider_call_allowed,
        "errors": list(audit.errors),
    }
    return {
        "rendered_prompt_digest": audit.rendered_prompt_digest,
        "preflight_input_tokens": audit.input_tokens,
        "prompt_preflight": detail,
    }


def _decode_json_text(value: str) -> Any:
    """Decode JSON, tolerating only an exact Markdown JSON fence wrapper."""
    stripped = value.strip()
    lines = stripped.splitlines()
    if (
        len(lines) >= 3
        and lines[0].strip().lower() in {"```json", "```"}
        and lines[-1].strip() == "```"
    ):
        stripped = "\n".join(lines[1:-1])
    return json.loads(stripped)


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


def _provider_response_content(response: Any) -> Any:
    """Extract message content from an attached provider completion."""
    choices = getattr(response, "choices", None)
    if not choices:
        return None
    try:
        choice = choices[0]
    except (IndexError, KeyError, TypeError):
        return None
    message = getattr(choice, "message", None)
    return getattr(message, "content", None)


def _provider_response_usage(response: Any) -> tuple[int, int]:
    """Extract usage counters from an attached provider completion."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0, 0
    return (
        int(getattr(usage, "prompt_tokens", 0) or 0),
        int(getattr(usage, "completion_tokens", 0) or 0),
    )


def parse_llm_result(result: LLMResult, model_class: type[_T]) -> _T:
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
        return model_class.model_validate(content)
    if isinstance(content, str):
        return model_class.model_validate(_decode_json_text(content))
    raise TypeError(
        f"Unexpected LLM result content type: {type(content).__name__}, "
        f"expected {model_class.__name__}, dict, or str."
    )


def _decode_llm_content(result: LLMResult) -> Any:
    """Decode the JSON-shaped content of an LLM result without validation."""
    content = result.content
    if isinstance(content, BaseModel):
        return raw_model_data(content)
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        return _decode_json_text(content)
    raise TypeError(
        f"Unexpected LLM result content type: {type(content).__name__}, "
        "expected a Pydantic model, dict, or JSON string."
    )


def parse_llm_result_unvalidated(result: LLMResult, model_class: type[_T]) -> _T:
    """Decode an LLM result into nested models without field validation.

    This narrow escape hatch is used by SP1 control-structure parsing so
    malformed IDs can be repaired from structural position before the final
    ``ControlStructure`` validation.  It still requires a decodable
    JSON-shaped response; missing fields and other schema errors are left for
    the post-normalization model validation to report.
    """
    content = _decode_llm_content(result)
    if isinstance(content, model_class):
        return content
    if not isinstance(content, dict):
        raise TypeError(
            f"Expected a mapping for {model_class.__name__}, "
            f"got {type(content).__name__}."
        )
    return construct_model_unvalidated(content, model_class)


def _build_completion_kwargs(
    *,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    temperature: float,
    max_completion_tokens: int | None,
    allow_unvalidated: bool,
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
    if allow_unvalidated:
        completion_kwargs["allow_unvalidated"] = True
    return completion_kwargs


def _is_unsupported_unvalidated_error(
    error: TypeError,
    allow_unvalidated: bool,
) -> bool:
    """Check whether a client rejected the optional compatibility argument."""
    if not allow_unvalidated:
        return False
    message = str(error)
    return "unexpected keyword argument" in message and "allow_unvalidated" in message


def _result_usage(
    result: LLMResult | None,
) -> tuple[int, int, int]:
    """Return prompt tokens, completion tokens, and duration for a result."""
    if result is None:
        return 0, 0, 0
    return result.prompt_tokens, result.completion_tokens, result.duration_ms


@dataclass
class _SafeCallState:
    """Mutable state retained while one bounded structured call is attempted."""

    result: LLMResult | None = None
    prompt_audit: PromptAudit | None = None
    raw_result_validation_failed: bool = False
    result_validation_failed: bool = False
    result_parser_failed: bool = False
    draft_parsed: bool = False
    semantic_validation_passed: bool = False


@dataclass(frozen=True)
class _FailureEvidence:
    """Safe provider evidence copied into one failed call record."""

    prompt_tokens: int
    completion_tokens: int
    duration_ms: int
    response_content: str | None
    provider_response_received: bool


def _failure_evidence(
    result: LLMResult | None,
    error: BaseException,
) -> _FailureEvidence:
    """Extract usage/content while excluding exception bodies from evidence."""
    attached = None if result is not None else _attached_provider_response(error)
    if result is not None:
        prompt_tokens, completion_tokens, duration_ms = _result_usage(result)
        response_content = _stringify_response_content(result.content)
    else:
        prompt_tokens, completion_tokens = _provider_response_usage(attached)
        duration_ms = 0
        response_content = (
            _stringify_response_content(_provider_response_content(attached))
            if attached is not None
            else None
        )
    return _FailureEvidence(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        duration_ms=duration_ms,
        response_content=response_content,
        provider_response_received=result is not None or attached is not None,
    )


def _safe_llm_call_client(
    llm_client: LLMClient,
    completion_kwargs: dict[str, Any],
    allow_unvalidated: bool,
) -> LLMResult:
    """Call a client, retrying once without unsupported compatibility kwargs."""
    try:
        return llm_client.complete(**completion_kwargs)
    except TypeError as exc:
        if not _is_unsupported_unvalidated_error(exc, allow_unvalidated):
            raise
        completion_kwargs.pop("allow_unvalidated", None)
        return llm_client.complete(**completion_kwargs)


def _validate_raw_result(
    result: LLMResult,
    validator: Callable[[Any], None] | None,
    state: _SafeCallState,
) -> None:
    """Run pre-parse validation while retaining its failure classification."""
    if validator is None:
        return
    try:
        validator(_decode_llm_content(result))
    except Exception:
        state.raw_result_validation_failed = True
        raise


def _parse_and_validate_result(
    result: LLMResult,
    response_format: type[_T],
    allow_unvalidated: bool,
    result_parser: Callable[[LLMResult], _T] | None,
    result_validator: Callable[[_T], None] | None,
    state: _SafeCallState,
) -> _T:
    """Parse one result and run optional stage-local semantic validation."""
    try:
        model = _parse_structured_result(
            result,
            response_format,
            allow_unvalidated,
            result_parser=result_parser,
        )
        state.draft_parsed = True
    except Exception:
        state.result_parser_failed = result_parser is not None
        raise
    if result_validator is None:
        return model
    try:
        result_validator(model)
    except Exception:
        state.result_validation_failed = True
        raise
    return model


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
    allow_unvalidated: bool,
    raw_result_validator: Callable[[Any], None] | None,
    result_validator: Callable[[_T], None] | None,
    result_parser: Callable[[LLMResult], _T] | None,
    slot_id: str | None,
    scenario_id: str | None,
    prompt_template_hashes: Mapping[str, str] | None,
    state: _SafeCallState,
) -> _T:
    """Execute one complete structured attempt and log a successful result."""
    state.prompt_audit = _preflight_configured_prompt(
        llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        stage=stage,
        max_completion_tokens=max_completion_tokens,
    )
    _enforce_prompt_audit(state.prompt_audit)
    completion_kwargs = _build_completion_kwargs(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        temperature=temperature,
        max_completion_tokens=max_completion_tokens,
        allow_unvalidated=allow_unvalidated,
    )
    state.result = _safe_llm_call_client(
        llm_client, completion_kwargs, allow_unvalidated=allow_unvalidated
    )
    _validate_raw_result(state.result, raw_result_validator, state)
    model = _parse_and_validate_result(
        state.result,
        response_format,
        allow_unvalidated,
        result_parser,
        result_validator,
        state,
    )
    state.semantic_validation_passed = True
    log_llm_call(
        state.result,
        llm_client.model,
        run_dir,
        stage,
        step,
        slot_id=slot_id,
        scenario_id=scenario_id,
        prompt_audit=state.prompt_audit,
        prompt_template_hashes=prompt_template_hashes,
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
) -> str:
    """Log one structured failure and return its stable display message."""
    error_msg = f"{type(error).__name__}: {error}"
    evidence = _failure_evidence(state.result, error)
    log_llm_call_failure(
        llm_client.model,
        run_dir,
        stage,
        step,
        error_msg,
        system_prompt=system_prompt,
        user_prompt=attempt_user_prompt,
        prompt_tokens=evidence.prompt_tokens,
        completion_tokens=evidence.completion_tokens,
        duration_ms=evidence.duration_ms,
        prompt_audit=state.prompt_audit,
        provider_response_received=evidence.provider_response_received,
        draft_parsed=state.draft_parsed,
        semantic_validation_passed=state.semantic_validation_passed,
        compiled=state.semantic_validation_passed,
        response_content=evidence.response_content,
        slot_id=slot_id,
        scenario_id=scenario_id,
        terminal_error_codes=(
            _terminal_error_code(
                error,
                provider_response_received=evidence.provider_response_received,
            ),
        ),
        prompt_template_hashes=prompt_template_hashes,
    )
    return error_msg


def _retry_kind(
    error: BaseException,
    state: _SafeCallState,
    json_retries_remaining: int,
    validation_retries_remaining: int,
) -> str | None:
    """Select the existing bounded retry policy without changing precedence."""
    if isinstance(error, json.JSONDecodeError) and json_retries_remaining:
        return "json"
    if _validation_retry_requested(error, state) and validation_retries_remaining:
        return "validation"
    return None


def _validation_retry_requested(
    error: BaseException,
    state: _SafeCallState,
) -> bool:
    """Report whether a failure belongs to the existing validation retry set."""
    if isinstance(error, json.JSONDecodeError):
        return False
    return bool(
        isinstance(error, ValidationError)
        or state.raw_result_validation_failed
        or state.result_validation_failed
        or state.result_parser_failed
    )


def _validate_retry_counts(
    json_decode_retries: int,
    validation_retries: int,
) -> None:
    """Reject negative retry budgets before beginning a call."""
    if json_decode_retries < 0 or validation_retries < 0:
        raise ValueError("retry counts must be non-negative")


def _raw_completion_kwargs(
    *,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_completion_tokens: int | None,
) -> dict[str, Any]:
    """Build the raw text completion request shape."""
    completion_kwargs: dict[str, Any] = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "response_format": None,
        "temperature": temperature,
    }
    if max_completion_tokens is not None:
        completion_kwargs["max_completion_tokens"] = max_completion_tokens
    return completion_kwargs


def _raw_text(result: LLMResult) -> str:
    """Coerce a raw completion to text while preserving empty responses."""
    content = result.content
    if content is None:
        return ""
    return content if isinstance(content, str) else str(content)


def _log_raw_failure(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    stage: str,
    step: str,
    system_prompt: str,
    user_prompt: str,
    error: BaseException,
    state: _SafeCallState,
    slot_id: str | None,
    scenario_id: str | None,
) -> str:
    """Log one raw-text failure while retaining provider response evidence."""
    error_msg = f"{type(error).__name__}: {error}"
    evidence = _failure_evidence(state.result, error)
    log_llm_call_failure(
        llm_client.model,
        run_dir,
        stage,
        step,
        error_msg,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        prompt_tokens=evidence.prompt_tokens,
        completion_tokens=evidence.completion_tokens,
        duration_ms=evidence.duration_ms,
        prompt_audit=state.prompt_audit,
        provider_response_received=evidence.provider_response_received,
        response_content=evidence.response_content,
        slot_id=slot_id,
        scenario_id=scenario_id,
    )
    return error_msg


def _validation_retry_prompt(
    *,
    original_prompt: str,
    feedback: str | None,
    error: Exception,
    response_format: type[BaseModel],
    include_schema: bool,
    prior_result: LLMResult | None = None,
    include_prior_response: bool = False,
) -> str:
    """Build a bounded correction prompt with field-specific validation errors."""
    suffix = feedback or ""
    if include_prior_response and prior_result is not None:
        prior_response = _stringify_response_content(prior_result.content)
        suffix += (
            "\n\nPrior structured response to correct in place:\n"
            f"```json\n{prior_response}\n```"
        )
    suffix += (
        "\n\nExact validation error from the prior response:\n"
        f"{_compact_validation_error(error)}"
    )
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


def _compact_validation_error(error: Exception) -> str:
    """Describe failed fields without echoing prior input or verbose URLs."""
    if isinstance(error, ValidationError):
        lines: list[str] = []
        for item in error.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[:8]:
            location = ".".join(str(part) for part in item["loc"]) or "response"
            lines.append(f"- {location}: {item['msg']} ({item['type']})")
        return "ValidationError:\n" + "\n".join(lines)
    if isinstance(error, json.JSONDecodeError):
        return (
            f"JSONDecodeError at line {error.lineno}, column {error.colno}: {error.msg}"
        )
    message = " ".join(str(error).split())
    if len(message) > 800:
        message = message[:797] + "..."
    return f"{type(error).__name__}: {message}"


def _parse_structured_result(
    result: LLMResult,
    response_format: type[_T],
    allow_unvalidated: bool,
    result_parser: Callable[[LLMResult], _T] | None = None,
) -> _T:
    """Validate a structured result, with a tolerant fallback when requested."""
    if result_parser is not None:
        return result_parser(result)
    try:
        return parse_llm_result(result, response_format)
    except ValidationError:
        if not allow_unvalidated:
            raise
        return parse_llm_result_unvalidated(result, response_format)


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
) -> None:
    """Append a call-log entry for a single LLM call.

    Args:
        result: The LLM result wrapper (provides prompts and token counts).
        model: The model name used for the call.
        run_dir: Directory where ``calls.jsonl`` is appended.
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
    """
    _success = True
    _response_content = _stringify_response_content(result.content)
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
        success=_success,
        slot_id=slot_id,
        scenario_id=scenario_id,
        response_content=_response_content,
        provider_response_received=True,
        draft_parsed=True,
        semantic_validation_passed=True,
        compiled=False,
        published=False,
        prompt_template_hashes=prompt_template_hashes,
    )
    entry.update(_prompt_audit_fields(prompt_audit))
    append_call_log([entry], run_dir)


def log_llm_call_failure(
    model: str,
    run_dir: Path,
    stage: str,
    step: str,
    error: str,
    *,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
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
) -> None:
    """Append a call-log entry for a failed LLM call.

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
        duration_ms=duration_ms,
        success=_success,
        error=error,
        slot_id=slot_id,
        scenario_id=scenario_id,
        response_content=response_content,
        provider_response_received=provider_response_received,
        draft_parsed=draft_parsed,
        semantic_validation_passed=semantic_validation_passed,
        compiled=compiled,
        terminal_error_codes=terminal_error_codes,
        prompt_template_hashes=prompt_template_hashes,
    )
    entry.update(_prompt_audit_fields(prompt_audit))
    append_call_log([entry], run_dir)


def safe_llm_call(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    run_dir: Path,
    stage: str,
    step: str,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    temperature: float = 0.4,
    max_completion_tokens: int | None = None,
    allow_unvalidated: bool = False,
    raw_result_validator: Callable[[Any], None] | None = None,
    result_validator: Callable[[_T], None] | None = None,
    json_decode_retries: int = 0,
    validation_retries: int = 0,
    validation_retry_feedback: str | None = None,
    validation_retry_include_schema: bool = True,
    validation_retry_include_response: bool = False,
    result_parser: Callable[[LLMResult], _T] | None = None,
    prompt_template_hashes: Mapping[str, str] | None = None,
) -> tuple[_T | None, LLMResult | None, str | None]:
    """Wrap complete() + parse_llm_result() in a try/except.

    On success, logs the call and returns ``(model, result, None)``.
    On failure, logs the failure and returns ``(None, result_or_none, error_msg)``.
    When requested, bounded additional attempts are made only for explicitly
    selected JSON-decoding or Pydantic-validation failures. Each attempt is
    logged independently.

    Args:
        llm_client: LLM client for making the completion call.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        response_format: Target Pydantic model class for validation.
        run_dir: Directory for call logging.
        stage: Pipeline stage identifier.
        step: Sub-step within the stage.
        slot_id: Exact ICA slot identity for durable call evidence, when applicable.
        scenario_id: Exact scenario identity for durable call evidence, when applicable.
        temperature: LLM temperature.
        max_completion_tokens: Optional cap on completion tokens. When
            provided, forwarded to ``llm_client.complete``.
        allow_unvalidated: When true, decode a JSON-shaped response into
            nested models without field validators if normal validation
            fails.  Callers must validate the resulting structure after
            deterministic normalization.
        raw_result_validator: Optional validation to run on the decoded
            response before Pydantic parsing. This is useful when tolerant
            decoding would otherwise discard unknown fields.
        result_validator: Optional additional validation to run on the parsed
            model before the call is logged as successful. This also applies
            to models built through the tolerant unvalidated path.
        json_decode_retries: Number of extra attempts to make after a
            ``json.JSONDecodeError``. Defaults to zero.
        validation_retries: Number of extra attempts to make after Pydantic
            validation or the explicit ``result_validator`` fails. Defaults
            to zero; stages must opt in.
        validation_retry_feedback: Optional text appended to the original user
            prompt on a validation retry.
        validation_retry_include_schema: Whether to repeat the complete JSON
            schema in a retry prompt. Stages using transport-level structured
            output may disable this to keep correction prompts compact.
        validation_retry_include_response: Whether to show the failed structured
            response to a validation retry so it can be corrected in place.
        result_parser: Optional stage-local parser for semantic responses. The
            parser receives the raw ``LLMResult`` and must return a validated
            response model. It is useful when a stage needs stricter wire
            validation than the shared compatibility decoder provides.

    Returns:
        A tuple of (validated_model_or_None, llm_result_or_None, error_or_None).
    """
    _validate_retry_counts(json_decode_retries, validation_retries)

    json_retries_remaining = json_decode_retries
    validation_retries_remaining = validation_retries
    attempt_user_prompt = user_prompt
    while True:
        state = _SafeCallState()
        try:
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
                allow_unvalidated=allow_unvalidated,
                raw_result_validator=raw_result_validator,
                result_validator=result_validator,
                result_parser=result_parser,
                slot_id=slot_id,
                scenario_id=scenario_id,
                prompt_template_hashes=prompt_template_hashes,
                state=state,
            )
            return model, state.result, None
        except Exception as exc:
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
            )
            retry_kind = _retry_kind(
                exc,
                state,
                json_retries_remaining,
                validation_retries_remaining,
            )
            if retry_kind == "json":
                json_retries_remaining -= 1
                continue
            if retry_kind == "validation":
                validation_retries_remaining -= 1
                attempt_user_prompt = _validation_retry_prompt(
                    original_prompt=user_prompt,
                    feedback=validation_retry_feedback,
                    error=exc,
                    response_format=response_format,
                    include_schema=validation_retry_include_schema,
                    prior_result=state.result,
                    include_prior_response=validation_retry_include_response,
                )
                continue
            return None, state.result, error_msg


def _terminal_error_code(
    error: BaseException,
    *,
    provider_response_received: bool = False,
) -> str:
    """Map provider-stage failures to stable lifecycle diagnostics.

    A provider that answered but whose answer failed stage-local semantic
    validation is not a call failure: the record already shows
    ``provider_response_received``, so the code names the semantic failure
    instead (fourth checkpoint 4 finding 6).
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


def safe_llm_call_raw(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    stage: str,
    step: str,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    temperature: float = 0.4,
    max_completion_tokens: int | None = None,
    raw_result_validator: Callable[[Any], None] | None = None,
) -> tuple[str | None, LLMResult | None, str | None]:
    """Wrap complete() for raw text responses (no structured response_format).

    Like :func:`safe_llm_call` but for calls that return raw text instead
    of a structured Pydantic model. The LLM client is called with
    ``response_format=None``.

    On success, logs the call and returns ``(text, result, None)``.
    On failure, logs the failure and returns ``(None, result_or_none, error_msg)``.

    Args:
        llm_client: LLM client for making the completion call.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        run_dir: Directory for call logging.
        stage: Pipeline stage identifier.
        step: Sub-step within the stage.
        temperature: LLM temperature.
        max_completion_tokens: Optional cap on completion tokens.
        raw_result_validator: Optional validation to run after the provider
            response is received but before a successful call is logged.  A
            failure retains the raw response and usage in the failure record.
        slot_id: Exact ICA slot identity for durable call evidence, when applicable.
        scenario_id: Exact scenario identity for durable call evidence, when applicable.

    Returns:
        A tuple of (raw_text_or_None, llm_result_or_None, error_or_None).
    """
    state = _SafeCallState()
    try:
        state.prompt_audit = _preflight_configured_prompt(
            llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage=stage,
            max_completion_tokens=max_completion_tokens,
        )
        _enforce_prompt_audit(state.prompt_audit)
        state.result = llm_client.complete(
            **_raw_completion_kwargs(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_completion_tokens=max_completion_tokens,
            )
        )
        content = _raw_text(state.result)
        if raw_result_validator is not None:
            raw_result_validator(content)
        log_llm_call(
            state.result,
            llm_client.model,
            run_dir,
            stage,
            step,
            slot_id=slot_id,
            scenario_id=scenario_id,
            prompt_audit=state.prompt_audit,
        )
        return content, state.result, None
    except Exception as exc:
        error_msg = _log_raw_failure(
            llm_client=llm_client,
            run_dir=run_dir,
            stage=stage,
            step=step,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            error=exc,
            state=state,
            slot_id=slot_id,
            scenario_id=scenario_id,
        )
        return None, state.result, error_msg
