"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa._model_data import raw_model_data

_T = TypeVar("_T", bound=BaseModel)


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
        return model_class.model_validate(json.loads(content))
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
        return json.loads(content)
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


def _parse_structured_result(
    result: LLMResult,
    response_format: type[_T],
    allow_unvalidated: bool,
) -> _T:
    """Validate a structured result, with a tolerant fallback when requested."""
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
        response_content=_response_content,
    )
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
    )
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
    temperature: float = 0.4,
    max_completion_tokens: int | None = None,
    allow_unvalidated: bool = False,
    raw_result_validator: Callable[[Any], None] | None = None,
    result_validator: Callable[[_T], None] | None = None,
    json_decode_retries: int = 0,
    validation_retries: int = 0,
    validation_retry_feedback: str | None = None,
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

    Returns:
        A tuple of (validated_model_or_None, llm_result_or_None, error_or_None).
    """
    if json_decode_retries < 0 or validation_retries < 0:
        raise ValueError("retry counts must be non-negative")

    json_retries_remaining = json_decode_retries
    validation_retries_remaining = validation_retries
    attempt_user_prompt = user_prompt
    while True:
        result: LLMResult | None = None
        raw_result_validation_failed = False
        result_validation_failed = False
        try:
            completion_kwargs = _build_completion_kwargs(
                system_prompt=system_prompt,
                user_prompt=attempt_user_prompt,
                response_format=response_format,
                temperature=temperature,
                max_completion_tokens=max_completion_tokens,
                allow_unvalidated=allow_unvalidated,
            )
            try:
                result = llm_client.complete(**completion_kwargs)
            except TypeError as exc:
                if not _is_unsupported_unvalidated_error(exc, allow_unvalidated):
                    raise
                completion_kwargs.pop("allow_unvalidated", None)
                result = llm_client.complete(**completion_kwargs)
            if raw_result_validator is not None:
                decoded_content = _decode_llm_content(result)
                try:
                    raw_result_validator(decoded_content)
                except Exception:
                    raw_result_validation_failed = True
                    raise
            model = _parse_structured_result(
                result,
                response_format,
                allow_unvalidated,
            )
            if result_validator is not None:
                try:
                    result_validator(model)
                except Exception:
                    result_validation_failed = True
                    raise
            log_llm_call(result, llm_client.model, run_dir, stage, step)
            return model, result, None
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            _prompt_tokens, _completion_tokens, _duration_ms = _result_usage(result)
            log_llm_call_failure(
                llm_client.model,
                run_dir,
                stage,
                step,
                error_msg,
                system_prompt=system_prompt,
                user_prompt=attempt_user_prompt,
                prompt_tokens=_prompt_tokens,
                completion_tokens=_completion_tokens,
                duration_ms=_duration_ms,
            )
            if isinstance(exc, json.JSONDecodeError) and json_retries_remaining:
                json_retries_remaining -= 1
                continue
            if (
                isinstance(exc, ValidationError)
                or raw_result_validation_failed
                or result_validation_failed
            ) and validation_retries_remaining:
                validation_retries_remaining -= 1
                if validation_retry_feedback:
                    attempt_user_prompt = user_prompt + validation_retry_feedback
                continue
            return None, result, error_msg


def safe_llm_call_raw(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    stage: str,
    step: str,
    temperature: float = 0.4,
    max_completion_tokens: int | None = None,
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

    Returns:
        A tuple of (raw_text_or_None, llm_result_or_None, error_or_None).
    """
    result: LLMResult | None = None
    try:
        completion_kwargs: dict[str, Any] = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "response_format": None,
            "temperature": temperature,
        }
        if max_completion_tokens is not None:
            completion_kwargs["max_completion_tokens"] = max_completion_tokens
        result = llm_client.complete(**completion_kwargs)
        content = result.content
        if content is None:
            content = ""
        if not isinstance(content, str):
            content = str(content)
        log_llm_call(result, llm_client.model, run_dir, stage, step)
        return content, result, None
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        _prompt_tokens, _completion_tokens, _duration_ms = _result_usage(result)
        log_llm_call_failure(
            llm_client.model,
            run_dir,
            stage,
            step,
            error_msg,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            prompt_tokens=_prompt_tokens,
            completion_tokens=_completion_tokens,
            duration_ms=_duration_ms,
        )
        return None, result, error_msg
