"""OpenAI-compatible LLM client — clean copy for the STPA pipeline.

This is a clean copy of the LLM client from ``asago_scenario_generator.llm.client``
with zero coupling to the existing pipeline. Same OpenAI-compatible
interface.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from openai import OpenAI
from pydantic import BaseModel, Field

DEFAULT_TEMPERATURE: float = 0.4

_OPENROUTER_DEFAULT_HEADERS: dict[str, str] = {
    "HTTP-Referer": "https://github.com/asago-ai/asago-scenario-generator",
    "X-Title": "asago-scenario-generator",
}


def _resolve_temperature(
    explicit: float | None,
    env_var: str | None,
) -> float:
    """Resolve the effective temperature from explicit arg or env var."""
    if explicit is not None:
        return explicit
    if env_var is not None:
        return float(env_var)
    return DEFAULT_TEMPERATURE


def _resolve_max_tokens(
    explicit: int | None,
    env_var: str | None,
) -> int | None:
    """Resolve the effective max_completion_tokens from explicit arg or env var."""
    if explicit is not None:
        return explicit
    return int(env_var) if env_var else None


def _resolve_base_url(explicit: str | None) -> str | None:
    """Resolve base_url from explicit arg or environment."""
    return explicit or os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL") or None


def _resolve_api_key(explicit: str | None) -> str:
    """Resolve API key from explicit arg or environment."""
    return explicit or os.environ.get("ASAGO_SCENARIO_GENERATOR_API_KEY", "unused")


def _resolve_model(explicit: str | None) -> str:
    """Resolve model name from explicit arg or environment."""
    return explicit or os.environ.get(
        "ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-3n-e4b-it"
    )


def _resolve_extra_headers(
    base_url: str | None,
    explicit: dict[str, str] | None,
    env_raw: str | None,
) -> dict[str, str] | None:
    """Merge explicit headers, env-var headers, and OpenRouter defaults."""
    env_headers: dict[str, str] = json.loads(env_raw) if env_raw else {}
    merged: dict[str, str] = {**env_headers, **(explicit or {})}
    _inject_openrouter_headers(merged, base_url)
    return merged if merged else None


def _inject_openrouter_headers(merged: dict[str, str], base_url: str | None) -> None:
    """Inject OpenRouter default headers if the base URL points to OpenRouter."""
    if base_url and "openrouter.ai" in base_url:
        for key, default in _OPENROUTER_DEFAULT_HEADERS.items():
            merged.setdefault(key, default)


def _prompt_messages(system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
    """Build the standard system + user message pair for one completion."""
    return [
        dict(role=role, content=content)
        for role, content in (
            ("system", system_prompt),
            ("user", user_prompt),
        )
    ]


def _guided_json_enabled(
    use_guided_decoding: bool,
    allow_unvalidated: bool,
    response_format: type[BaseModel] | None,
) -> bool:
    """Whether vLLM guided_json applies for this request."""
    return use_guided_decoding and allow_unvalidated and response_format is not None


def _apply_legacy_json_fallback(
    extra_kwargs: dict[str, Any],
    allow_unvalidated: bool,
    response_format: type[BaseModel] | None,
    use_guided_json: bool,
) -> None:
    """Fall back to legacy json_object mode for models without guided decoding."""
    if allow_unvalidated and response_format is not None and not use_guided_json:
        extra_kwargs["response_format"] = {"type": "json_object"}


def _token_usage(response: Any) -> Any:
    """Normalize a response's usage record to a token-count object."""
    return (
        response.usage or type("U", (), {"prompt_tokens": 0, "completion_tokens": 0})()
    )


def _top_k_extra_body(top_k: int | None) -> dict[str, Any]:
    """The extra_body entries for the top_k control."""
    if top_k is None:
        return {}
    return {"top_k": top_k}


def _guided_json_extra_body(
    use_guided_json: bool,
    response_format: type[BaseModel] | None,
) -> dict[str, Any]:
    """The extra_body entries for vLLM strict JSON schema enforcement."""
    if use_guided_json and response_format is not None:
        return {"guided_json": response_format.model_json_schema()}
    return {}


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

    DEFAULT_TEMPERATURE: float = DEFAULT_TEMPERATURE

    _OPENROUTER_DEFAULT_HEADERS: dict[str, str] = _OPENROUTER_DEFAULT_HEADERS

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
    ) -> None:
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.model = _resolve_model(model)
        self.max_completion_tokens = _resolve_max_tokens(
            max_completion_tokens,
            os.environ.get("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS"),
        )
        self.temperature = _resolve_temperature(
            temperature, os.environ.get("ASAGO_SCENARIO_GENERATOR_TEMPERATURE")
        )
        self.extra_headers = _resolve_extra_headers(
            self.base_url,
            extra_headers,
            os.environ.get("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS"),
        )
        self.top_p = top_p
        self.top_k = top_k
        self.use_guided_decoding = use_guided_decoding

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

    def _build_extra_kwargs(
        self,
        effective_max: int | None,
        effective_temp: float,
        response_format: type[BaseModel] | None = None,
        use_guided_json: bool = False,
    ) -> dict[str, Any]:
        """Build the extra kwargs dict for the OpenAI completion call.

        ``top_k`` is not a standard OpenAI API parameter and raises
        ``TypeError`` on non-OpenAI providers (e.g. OpenRouter). It is
        routed through ``extra_body`` instead of as a top-level kwarg.

        ``guided_json`` enables vLLM's strict JSON schema enforcement via
        guided decoding, masking invalid tokens during generation.
        """
        kwargs: dict[str, Any] = {"temperature": effective_temp}
        if effective_max is not None:
            kwargs["max_completion_tokens"] = effective_max
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p

        extra_body = {
            **_top_k_extra_body(self.top_k),
            **_guided_json_extra_body(use_guided_json, response_format),
        }
        if extra_body:
            kwargs["extra_body"] = extra_body

        return kwargs

    def _request_completion(
        self,
        messages: list[dict[str, str]],
        response_format: type[BaseModel] | None,
        extra_kwargs: dict[str, Any],
        allow_unvalidated: bool,
    ) -> tuple[Any, Any]:
        """Request a completion and return its response plus extracted content."""
        if response_format is not None and not allow_unvalidated:
            response = self._client.beta.chat.completions.parse(
                model=self.model,
                messages=messages,
                response_format=response_format,
                **extra_kwargs,
            )
            return response, response.choices[0].message.parsed

        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            **extra_kwargs,
        )
        return response, response.choices[0].message.content

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        allow_unvalidated: bool = False,
    ) -> LLMResult:
        effective_max = max_completion_tokens or self.max_completion_tokens
        effective_temp = temperature if temperature is not None else self.temperature

        # Use vLLM guided_json for strict schema enforcement when enabled via profile
        # This enables guided decoding which masks invalid tokens during generation
        # Only enabled when use_guided_decoding=True in model profile
        use_guided_json = _guided_json_enabled(
            self.use_guided_decoding, allow_unvalidated, response_format
        )
        extra_kwargs = self._build_extra_kwargs(
            effective_max, effective_temp, response_format, use_guided_json
        )
        _apply_legacy_json_fallback(
            extra_kwargs, allow_unvalidated, response_format, use_guided_json
        )

        t0 = time.perf_counter_ns()
        response, content = self._request_completion(
            _prompt_messages(system_prompt, user_prompt),
            response_format,
            extra_kwargs,
            allow_unvalidated,
        )

        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        usage = _token_usage(response)

        return LLMResult(
            content=content,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            duration_ms=duration_ms,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T14:01:03Z","module_hash":"ff1a057fc1fbd6eacf792c97b4ac5e6deb73a2c85268d27ccd2389e6caa5f165","functions":[{"id":"func/_resolve_temperature","name":"_resolve_temperature","line":26,"end_line":35,"hash":"998ed6ac410ac249f9323306689e281049387bb4cdb7b40473aa70e8a12d5218"},{"id":"func/_resolve_max_tokens","name":"_resolve_max_tokens","line":38,"end_line":45,"hash":"cb0fddfec270db0947c9e4c4641ca1ab14a3a0840697f7b1d186b3f95bd4492c"},{"id":"func/_resolve_base_url","name":"_resolve_base_url","line":48,"end_line":50,"hash":"f49d568278a6d26ac457df37e5df8d5ec67f8e3fbf717ab6139b0868093eff26"},{"id":"func/_resolve_api_key","name":"_resolve_api_key","line":53,"end_line":55,"hash":"9d252c6a2c4627645193dc1d414b204a9fb0ae3ca6fbec47157ea6929db89a2e"},{"id":"func/_resolve_model","name":"_resolve_model","line":58,"end_line":62,"hash":"702c4a307f67d7519b9926c7cd7bcff24dd960c8d96239b4793cf9d1e670e506"},{"id":"func/_resolve_extra_headers","name":"_resolve_extra_headers","line":65,"end_line":74,"hash":"e60982eb84b4e3e6c180960e7bedb1b8fb5c8f4cf6c98d0632e8c673e10d0708"},{"id":"func/_inject_openrouter_headers","name":"_inject_openrouter_headers","line":77,"end_line":83,"hash":"7a170937e63ad4d1e269ef89e011e3003b8a7c8d66fe519abff1ab75995ac6eb"},{"id":"func/LLMClient.__init__","name":"__init__","line":104,"end_line":142,"hash":"801cd57c4cdaeac3e1a0b63df68ccb744ca229266b7865dff3116beae87477b7"},{"id":"func/LLMClient._build_extra_kwargs","name":"_build_extra_kwargs","line":144,"end_line":162,"hash":"ea5ddcda6171abbf66b936205c9c2322a781ab72c39257c7aac6771fc868f880"},{"id":"func/LLMClient.complete","name":"complete","line":164,"end_line":213,"hash":"efd8693b01257982cf4a81fb5410cdaebd45fafe79e17d74ef2503ec43845b77"}]}
# mutate4py-manifest-end
