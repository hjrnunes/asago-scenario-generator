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

from asago_scenario_generator.model_profiles import DEFAULT_REQUEST_TIMEOUT_SECONDS

DEFAULT_TEMPERATURE: float = 0.4

_ENV_MAX_COMPLETION_TOKENS = "ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS"
_ENV_TEMPERATURE = "ASAGO_SCENARIO_GENERATOR_TEMPERATURE"
_ENV_TOP_P = "ASAGO_SCENARIO_GENERATOR_TOP_P"
_ENV_TOP_K = "ASAGO_SCENARIO_GENERATOR_TOP_K"
_ENV_USE_GUIDED_DECODING = "ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING"
_ENV_TIMEOUT = "ASAGO_SCENARIO_GENERATOR_TIMEOUT"

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
        return _validated_float(explicit, "temperature", minimum=0.0)
    if env_var is not None:
        return _validated_float(env_var, _ENV_TEMPERATURE, minimum=0.0)
    return DEFAULT_TEMPERATURE


def _resolve_max_tokens(
    explicit: int | None,
    env_var: str | None,
) -> int | None:
    """Resolve the effective max_completion_tokens from explicit arg or env var."""
    if explicit is not None:
        return _validated_int(explicit, "max_completion_tokens", minimum=1)
    if not env_var:
        return None
    return _validated_int(env_var, _ENV_MAX_COMPLETION_TOKENS, minimum=1)


def _resolve_timeout(explicit: float | None, env_var: str | None) -> float:
    """Resolve a positive request deadline from explicit, env, or default."""
    if explicit is not None:
        return _validated_float(explicit, "timeout", minimum=0.000001)
    if env_var is not None:
        return _validated_float(env_var, _ENV_TIMEOUT, minimum=0.000001)
    return DEFAULT_REQUEST_TIMEOUT_SECONDS


def _validated_float(
    value: float | str,
    name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Parse and range-check a floating-point sampling setting."""
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {parsed}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{name} must be at most {maximum}, got {parsed}")
    return parsed


def _validated_int(value: int | str, name: str, *, minimum: int) -> int:
    """Parse and range-check an integer sampling setting."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {parsed}")
    return parsed


def _resolve_optional_float(
    explicit: float | None,
    env_name: str,
    *,
    minimum: float,
    maximum: float | None = None,
) -> float | None:
    """Resolve an optional float using explicit → environment precedence."""
    if explicit is not None:
        return _validated_float(
            explicit,
            env_name.removeprefix("ASAGO_SCENARIO_GENERATOR_").lower(),
            minimum=minimum,
            maximum=maximum,
        )
    raw = os.environ.get(env_name)
    if raw is None:
        return None
    return _validated_float(raw, env_name, minimum=minimum, maximum=maximum)


def _resolve_optional_int(
    explicit: int | None,
    env_name: str,
    *,
    minimum: int,
) -> int | None:
    """Resolve an optional integer using explicit → environment precedence."""
    if explicit is not None:
        return _validated_int(
            explicit,
            env_name.removeprefix("ASAGO_SCENARIO_GENERATOR_").lower(),
            minimum=minimum,
        )
    raw = os.environ.get(env_name)
    if raw is None:
        return None
    return _validated_int(raw, env_name, minimum=minimum)


def _resolve_bool(explicit: bool | None, env_name: str, default: bool) -> bool:
    """Resolve a boolean using explicit → environment → default precedence."""
    if explicit is not None:
        return explicit
    raw = os.environ.get(env_name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{env_name} must be a boolean (true/false), got {raw!r}")


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
        use_guided_decoding: bool | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.model = _resolve_model(model)
        self.max_completion_tokens = _resolve_max_tokens(
            max_completion_tokens,
            os.environ.get(_ENV_MAX_COMPLETION_TOKENS),
        )
        self.temperature = _resolve_temperature(
            temperature, os.environ.get(_ENV_TEMPERATURE)
        )
        self.extra_headers = _resolve_extra_headers(
            self.base_url,
            extra_headers,
            os.environ.get("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS"),
        )
        self.top_p = _resolve_optional_float(
            top_p,
            _ENV_TOP_P,
            minimum=0.0,
            maximum=1.0,
        )
        self.top_k = _resolve_optional_int(top_k, _ENV_TOP_K, minimum=1)
        self.use_guided_decoding = _resolve_bool(
            use_guided_decoding,
            _ENV_USE_GUIDED_DECODING,
            False,
        )
        self.timeout = _resolve_timeout(timeout, os.environ.get(_ENV_TIMEOUT))

        if not self.base_url:
            raise ValueError(
                "No LLM endpoint configured."
                " Set ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL or pass --base-url."
            )
        self._client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            default_headers=self.extra_headers or None,
            timeout=self.timeout,
            max_retries=0,
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


def effective_model_config(
    client: LLMClient,
    *,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Return effective non-secret settings suitable for run manifests."""
    return {
        "model": client.model,
        "base_url": client.base_url,
        "max_completion_tokens": getattr(client, "max_completion_tokens", None),
        "temperature": effective_temperature(client, temperature),
        "top_p": getattr(client, "top_p", None),
        "top_k": getattr(client, "top_k", None),
        "use_guided_decoding": getattr(client, "use_guided_decoding", False),
        "timeout": getattr(client, "timeout", DEFAULT_REQUEST_TIMEOUT_SECONDS),
    }


def effective_temperature(
    client: LLMClient,
    explicit: float | None = None,
) -> float:
    """Resolve a stage override, client value, or the shared legacy default."""
    configured = getattr(client, "temperature", DEFAULT_TEMPERATURE)
    return _validated_float(
        configured if explicit is None else explicit,
        "temperature",
        minimum=0.0,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:50:54Z","module_hash":"1f7549ba302813e41030398beb4aa5afb1986dfed1fc94954d6720b2590bec06","source_sha256":"5e150c3e801603ab5ebf88b606641355b41ea8f227bb591d2d9b4b60cfb1e650","functions":[{"id":"func/_resolve_temperature","name":"_resolve_temperature","line":26,"end_line":35,"hash":"998ed6ac410ac249f9323306689e281049387bb4cdb7b40473aa70e8a12d5218"},{"id":"func/_resolve_max_tokens","name":"_resolve_max_tokens","line":38,"end_line":45,"hash":"cb0fddfec270db0947c9e4c4641ca1ab14a3a0840697f7b1d186b3f95bd4492c"},{"id":"func/_resolve_base_url","name":"_resolve_base_url","line":48,"end_line":50,"hash":"53db5a7a428e00f2e581cea2352b7b5914a09d5b3e3bc5b2d2816aa1f721d676"},{"id":"func/_resolve_api_key","name":"_resolve_api_key","line":53,"end_line":55,"hash":"c525af29e91b8375a85bae92778913503d11c5212731ae1db03b3ed690d15ca8"},{"id":"func/_resolve_model","name":"_resolve_model","line":58,"end_line":62,"hash":"d58dc2c9c0924bf03d603f0f4f782681efeb2a60bd49d1b634ba72de81349c8a"},{"id":"func/_resolve_extra_headers","name":"_resolve_extra_headers","line":65,"end_line":74,"hash":"e60982eb84b4e3e6c180960e7bedb1b8fb5c8f4cf6c98d0632e8c673e10d0708"},{"id":"func/_inject_openrouter_headers","name":"_inject_openrouter_headers","line":77,"end_line":81,"hash":"7a170937e63ad4d1e269ef89e011e3003b8a7c8d66fe519abff1ab75995ac6eb"},{"id":"func/_prompt_messages","name":"_prompt_messages","line":84,"end_line":92,"hash":"9ac842ffb512c78810c8a8c8208e6105388ec49a774379bf57709ad4bacb5a6a"},{"id":"func/_guided_json_enabled","name":"_guided_json_enabled","line":95,"end_line":101,"hash":"8742086e914c9b404a0da24044183ff77994ca62a04e1255e61cb9b0b4f0214f"},{"id":"func/_apply_legacy_json_fallback","name":"_apply_legacy_json_fallback","line":104,"end_line":112,"hash":"33f647c4ce69a1215a641bd22623bb14f86c3c51d1e4aea01565de078fc1a61d"},{"id":"func/_token_usage","name":"_token_usage","line":115,"end_line":119,"hash":"de804c595314ac1e2eb65ac77febc5ba127ad956340e8491a9c40fb81721ef14"},{"id":"func/_top_k_extra_body","name":"_top_k_extra_body","line":122,"end_line":126,"hash":"949f97e8feb35c14d87c8955a805f35af73f4ec6847431ede80bacf6036547ea"},{"id":"func/_guided_json_extra_body","name":"_guided_json_extra_body","line":129,"end_line":136,"hash":"f7fa30329a6bf126580f8152e04b5ebe9f88d189b373e70df55fa6a32483be03"},{"id":"func/LLMClient.__init__","name":"__init__","line":157,"end_line":197,"hash":"7eb8608426c6f50c8eb46a7e2454fe6d86a5f3406c70bd38c67d74889b8b0b37"},{"id":"func/LLMClient._build_extra_kwargs","name":"_build_extra_kwargs","line":199,"end_line":228,"hash":"57d971ed36b2b3f074af08d2049cdc01f4f5bde6a499a3d533c32c73eaaba756"},{"id":"func/LLMClient._request_completion","name":"_request_completion","line":230,"end_line":252,"hash":"bdb906ab26f8b5f78d33d50604fd273d3e44c9f79a12fb9c0bcf8645b5af6ae2"},{"id":"func/LLMClient.complete","name":"complete","line":254,"end_line":297,"hash":"d29b335dabe84c3128aaf23f82d1ab5db7f5fd5f246440c35a34e579e0e761cf"}]}
# mutate4py-manifest-end
