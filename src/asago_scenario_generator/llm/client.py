"""OpenAI-compatible LLM client for asago-scenario-generator."""

from __future__ import annotations

import json
import os
import time
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

    def __init__(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        finish_reason: str = "length",
        message: str | None = None,
    ) -> None:
        super().__init__(
            message or "completion length limit reached; response finished early"
        )
        self.finish_reason = finish_reason
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens

    @classmethod
    def from_usage(
        cls,
        usage: Any,
        *,
        finish_reason: str = "length",
    ) -> CompletionLengthError:
        """Build typed length-exhaustion evidence from a provider usage record.

        ``usage`` may be ``None`` or carry no token fields; missing counts
        degrade to zero without parsing exception text.
        """
        prompt_tokens, completion_tokens = _usage_counts(usage)
        return cls(
            finish_reason=finish_reason,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


def _usage_counts(usage: Any) -> tuple[int, int]:
    """Extract ``(prompt_tokens, completion_tokens)``, tolerating None usage."""
    if usage is None:
        return 0, 0
    return usage.prompt_tokens, usage.completion_tokens


class LLMResult(BaseModel):
    """Wrapper carrying the LLM response plus usage telemetry."""

    content: Any = Field(description="Parsed model instance or raw text string.")
    prompt_tokens: int = Field(description="Prompt tokens consumed.")
    completion_tokens: int = Field(description="Completion tokens generated.")
    duration_ms: int = Field(description="Wall-clock duration in milliseconds.")
    system_prompt: str = Field(default="", description="System prompt sent to the LLM.")
    user_prompt: str = Field(default="", description="User prompt sent to the LLM.")


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

        # --- extra headers resolution ---
        self.extra_headers = self._resolve_extra_headers(extra_headers)

        if not self.base_url:
            raise ValueError(
                "No LLM endpoint configured."
                " Set ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL or pass --base-url."
            )
        self._client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            default_headers=self.extra_headers or None,
        )

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
        effective_max = max_completion_tokens or self.max_completion_tokens
        effective_temp = temperature if temperature is not None else self.temperature

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        extra_kwargs: dict[str, Any] = {"temperature": effective_temp}
        if effective_max is not None:
            extra_kwargs["max_completion_tokens"] = effective_max

        t0 = time.perf_counter_ns()
        response, content = self._complete(messages, response_format, extra_kwargs)
        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        prompt_tokens, completion_tokens = _usage_counts(response.usage)

        return LLMResult(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            duration_ms=duration_ms,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    def _complete(
        self,
        messages: list[dict[str, Any]],
        response_format: type[BaseModel] | None,
        extra_kwargs: dict[str, Any],
    ) -> tuple[Any, Any]:
        """Run exactly one provider request, returning ``(response, content)``.

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
            raise CompletionLengthError.from_usage(exc.completion.usage) from exc

        finish_reason = getattr(response.choices[0], "finish_reason", None)
        if response_format is None and str(finish_reason) == "length":
            # Unstructured length exhaustion: a completed response whose
            # choice ended for length is still a length failure.
            raise CompletionLengthError.from_usage(response.usage)
        return response, content
