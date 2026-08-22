"""OpenAI-compatible LLM client for asago-scenario-generator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Mapping
from typing import Any

from openai import LengthFinishReasonError, OpenAI
from pydantic import BaseModel, Field


class CompletionLengthError(RuntimeError):
    """Project-owned typed evidence for a completion-length exhaustion.

    Normalizes the two provider shapes — the structured OpenAI SDK
    ``LengthFinishReasonError`` and unstructured choices whose
    ``finish_reason == "length"`` — into one typed value carrying usage
    and finish reason as fields.  Callers classify on these fields, never
    by parsing exception text.
    """

    finish_reason: str = "length"
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    usage_details: dict[str, Any]
    response_id: str | None
    model: str | None
    partial_character_count: int
    partial_sha256: str | None
    partial_preview_prefix: str | None
    partial_preview_suffix: str | None
    elapsed_ms: int | None

    def __init__(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        finish_reason: str = "length",
        message: str | None = None,
        total_tokens: int | None = None,
        usage_details: Mapping[str, Any] | None = None,
        response_id: str | None = None,
        model: str | None = None,
        partial_character_count: int = 0,
        partial_sha256: str | None = None,
        partial_preview_prefix: str | None = None,
        partial_preview_suffix: str | None = None,
        elapsed_ms: int | None = None,
    ) -> None:
        super().__init__(
            message or "completion length limit reached; response finished early"
        )
        self.finish_reason = finish_reason
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = (
            total_tokens
            if total_tokens is not None
            else prompt_tokens + completion_tokens
        )
        self.usage_details = dict(usage_details or {})
        self.response_id = response_id
        self.model = model
        self.partial_character_count = partial_character_count
        self.partial_sha256 = partial_sha256
        self.partial_preview_prefix = partial_preview_prefix
        self.partial_preview_suffix = partial_preview_suffix
        self.elapsed_ms = elapsed_ms

    @classmethod
    def from_usage(
        cls,
        usage: Any,
        *,
        finish_reason: str = "length",
        response: Any | None = None,
        partial_content: Any | None = None,
    ) -> CompletionLengthError:
        """Build typed length-exhaustion evidence from a provider usage record.

        ``usage`` may be ``None`` or carry no token fields; missing counts
        degrade to zero without parsing exception text.
        """
        prompt_tokens, completion_tokens = _usage_counts(usage)
        usage_details = _usage_details(usage)
        total_tokens = usage_details.get("total_tokens")
        if not isinstance(total_tokens, int):
            total_tokens = prompt_tokens + completion_tokens
        diagnostics = _partial_diagnostics(partial_content)
        return cls(
            finish_reason=finish_reason,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            usage_details=usage_details,
            response_id=_response_field(response, "id"),
            model=_response_field(response, "model"),
            **diagnostics,
        )


def _usage_counts(usage: Any) -> tuple[int, int]:
    """Extract ``(prompt_tokens, completion_tokens)``, tolerating None usage."""
    if usage is None:
        return 0, 0
    return (
        int(getattr(usage, "prompt_tokens", 0) or 0),
        int(getattr(usage, "completion_tokens", 0) or 0),
    )


def _plain_value(value: Any) -> Any:
    """Convert SDK/Pydantic telemetry objects into JSON-compatible values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_value(item) for item in value]
    if hasattr(value, "__dict__"):
        return {
            str(key): _plain_value(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return str(value)


def _usage_details(usage: Any) -> dict[str, Any]:
    """Preserve all provider usage and nested token-detail fields."""
    plain = _plain_value(usage)
    return plain if isinstance(plain, dict) else {}


def _response_field(response: Any | None, name: str) -> str | None:
    value = getattr(response, name, None) if response is not None else None
    return value if isinstance(value, str) else None


_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(?:secret|password|passwd|token|api[_-]?key|authorization)"
    r"\s*[:=]\s*[^\s,;]+"
)
_PREVIEW_LIMIT = 128


def _redacted_preview(content: str, *, suffix: bool) -> str:
    redacted = _SENSITIVE_VALUE.sub("[REDACTED]", content)
    if len(redacted) <= _PREVIEW_LIMIT:
        return redacted
    return redacted[-_PREVIEW_LIMIT:] if suffix else redacted[:_PREVIEW_LIMIT]


def _partial_diagnostics(content: Any | None) -> dict[str, Any]:
    """Return bounded, redacted evidence without retaining the full response."""
    if content is None:
        return {
            "partial_character_count": 0,
            "partial_sha256": None,
            "partial_preview_prefix": None,
            "partial_preview_suffix": None,
        }
    if not isinstance(content, str):
        content = json.dumps(_plain_value(content), ensure_ascii=False, sort_keys=True)
    return {
        "partial_character_count": len(content),
        "partial_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "partial_preview_prefix": _redacted_preview(content, suffix=False),
        "partial_preview_suffix": _redacted_preview(content, suffix=True),
    }


def _response_schema_label(response_format: type[BaseModel] | None) -> str | None:
    if response_format is None:
        return None
    return (
        "compact-v1" if response_format.__name__.startswith("Compact") else "standard"
    )


def _recover_complete_structured_partial(
    content: Any,
    response_format: type[BaseModel] | None,
) -> BaseModel | None:
    """Recover one schema-valid JSON value followed only by whitespace.

    Some OpenAI-compatible deployments keep emitting whitespace after a
    complete structured value until the token limit. The SDK reports that as a
    length failure even though the semantic payload is complete. Recovery is
    deliberately narrower than JSON repair: incomplete values, additional
    values, non-whitespace suffixes, and schema-invalid values all fail closed.
    """
    if not isinstance(content, str) or response_format is None:
        return None
    try:
        if not issubclass(response_format, BaseModel):
            return None
    except TypeError:
        return None
    stripped = content.lstrip()
    try:
        value, end = json.JSONDecoder().raw_decode(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if stripped[end:].strip():
        return None
    try:
        return response_format.model_validate(value)
    except (TypeError, ValueError):
        return None


class LLMResult(BaseModel):
    """Wrapper carrying the LLM response plus usage telemetry."""

    content: Any = Field(description="Parsed model instance or raw text string.")
    prompt_tokens: int = Field(description="Prompt tokens consumed.")
    completion_tokens: int = Field(description="Completion tokens generated.")
    duration_ms: int = Field(description="Wall-clock duration in milliseconds.")
    system_prompt: str = Field(default="", description="System prompt sent to the LLM.")
    user_prompt: str = Field(default="", description="User prompt sent to the LLM.")
    request_controls: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-facing controls used for this request.",
    )


class LLMClient:
    """Thin wrapper around the OpenAI SDK for structured and unstructured completions."""

    DEFAULT_TEMPERATURE: float = 0.4

    _OPENROUTER_DEFAULT_HEADERS: dict[str, str] = {
        "HTTP-Referer": "https://github.com/asago-ai/asago-scenario-generator",
        "X-Title": "asago-scenario-generator",
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        extra_headers: dict[str, str] | None = None,
        top_p: float | None = None,
        top_k: int | None = None,
        use_guided_decoding: bool = False,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL")
            or None
        )
        self.api_key = api_key or os.environ.get(
            "ASAGO_SCENARIO_GENERATOR_API_KEY", "unused"
        )
        self.model = model or os.environ.get(
            "ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-3n-e4b-it"
        )
        env_val = os.environ.get("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS")
        self.max_completion_tokens = max_completion_tokens or (
            int(env_val) if env_val else None
        )
        env_temp = os.environ.get("ASAGO_SCENARIO_GENERATOR_TEMPERATURE")
        if temperature is not None:
            self.temperature = temperature
        elif env_temp is not None:
            self.temperature = float(env_temp)
        else:
            self.temperature = self.DEFAULT_TEMPERATURE
        self.top_p = top_p
        self.top_k = top_k
        self.use_guided_decoding = use_guided_decoding
        self.timeout = timeout

        # --- extra headers resolution ---
        self.extra_headers = self._resolve_extra_headers(extra_headers)

        if not self.base_url:
            raise ValueError(
                "No LLM endpoint configured."
                " Set ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL or pass --base-url."
            )
        openai_kwargs: dict[str, Any] = dict(
            base_url=self.base_url,
            api_key=self.api_key,
            default_headers=self.extra_headers or None,
        )
        if timeout is not None:
            openai_kwargs["timeout"] = timeout
        self._client = OpenAI(**openai_kwargs)

    def _resolve_extra_headers(
        self, explicit: dict[str, str] | None
    ) -> dict[str, str] | None:
        """Merge explicit headers, env-var headers, and OpenRouter defaults."""
        # 1. Start with env-var headers (if any).
        env_raw = os.environ.get("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS")
        env_headers: dict[str, str] = json.loads(env_raw) if env_raw else {}

        # 2. Explicit constructor arg wins over env var.
        merged: dict[str, str] = {**env_headers, **(explicit or {})}

        # 3. Auto-inject OpenRouter defaults for missing keys.
        if self.base_url and "openrouter.ai" in self.base_url:
            for key, default in self._OPENROUTER_DEFAULT_HEADERS.items():
                merged.setdefault(key, default)

        return merged if merged else None

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        transport_token_cap = getattr(self, "max_completion_tokens", None)
        effective_max = max_completion_tokens or transport_token_cap
        effective_temp = temperature if temperature is not None else self.temperature
        top_p = getattr(self, "top_p", None)
        top_k = getattr(self, "top_k", None)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        extra_kwargs: dict[str, Any] = {"temperature": effective_temp}
        if effective_max is not None:
            extra_kwargs["max_completion_tokens"] = effective_max
        if top_p is not None:
            extra_kwargs["top_p"] = top_p
        if top_k is not None:
            extra_kwargs["extra_body"] = {"top_k": top_k}

        t0 = time.perf_counter_ns()
        try:
            response, content, recovered_whitespace = self._complete(
                messages, response_format, extra_kwargs
            )
        except CompletionLengthError as exc:
            exc.elapsed_ms = max(0, (time.perf_counter_ns() - t0) // 1_000_000)
            raise
        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        prompt_tokens, completion_tokens = _usage_counts(response.usage)

        return LLMResult(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            duration_ms=duration_ms,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            request_controls={
                "response_schema": (_response_schema_label(response_format)),
                "max_completion_tokens": effective_max,
                "transport_token_cap": transport_token_cap,
                "temperature": effective_temp,
                "top_p": top_p,
                "top_k": top_k,
                "structured_whitespace_recovered": recovered_whitespace,
            },
        )

    def _complete(
        self,
        messages: list[dict[str, Any]],
        response_format: type[BaseModel] | None,
        extra_kwargs: dict[str, Any],
    ) -> tuple[Any, Any, bool]:
        """Run one request, returning response, content, and recovery evidence.

        Normalizes both provider length shapes — the structured SDK
        ``LengthFinishReasonError`` and an unstructured choice whose
        ``finish_reason == "length"`` — into one typed
        ``CompletionLengthError`` carrying usage evidence.
        """
        try:
            if response_format is not None:
                response = self._client.beta.chat.completions.parse(
                    model=self.model,
                    messages=messages,
                    response_format=response_format,
                    **extra_kwargs,
                )
                content = response.choices[0].message.parsed
            else:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    **extra_kwargs,
                )
                content = response.choices[0].message.content
        except LengthFinishReasonError as exc:
            completion = exc.completion
            partial_content = _choice_content(completion)
            recovered = _recover_complete_structured_partial(
                partial_content, response_format
            )
            if recovered is not None:
                return completion, recovered, True
            raise CompletionLengthError.from_usage(
                completion.usage,
                response=completion,
                partial_content=partial_content,
            ) from exc

        finish_reason = getattr(response.choices[0], "finish_reason", None)
        if response_format is None and str(finish_reason) == "length":
            # Unstructured length exhaustion: a completed response whose
            # choice ended for length is still a length failure.
            raise CompletionLengthError.from_usage(
                response.usage,
                response=response,
                partial_content=_choice_content(response),
            )
        return response, content, False


def _choice_content(response: Any) -> Any | None:
    """Read provider partial content for diagnostics only."""
    try:
        return response.choices[0].message.content
    except (AttributeError, IndexError, KeyError, TypeError):
        return None
