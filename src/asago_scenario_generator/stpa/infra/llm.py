"""OpenAI-compatible LLM client for the STPA pipeline.

The client has no coupling to ``asago_scenario_generator.pipeline``.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from typing import Any

from openai import LengthFinishReasonError, OpenAI, RateLimitError
from pydantic import BaseModel, Field

from asago_scenario_generator.model_profiles import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    reasoning_completion_cap,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    ProviderCallSession,
)
from asago_scenario_generator.stpa.infra.transport_retry import retry_once
from asago_scenario_generator.request_schema import portable_request_schema

DEFAULT_TEMPERATURE: float = 0.4

_ENV_MAX_COMPLETION_TOKENS = "ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS"
_ENV_CONTEXT_WINDOW = "ASAGO_SCENARIO_GENERATOR_CONTEXT_WINDOW"
_ENV_SAFETY_MARGIN = "ASAGO_SCENARIO_GENERATOR_PROMPT_SAFETY_MARGIN"
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


def _json_object_compatibility(
    base_url: str | None, response_format: type[BaseModel] | None
) -> bool:
    """Use portable JSON-object requests for OpenRouter structured output."""
    return bool(
        response_format is not None and base_url and "openrouter.ai" in base_url
    )


def _openrouter_schema_prompt(
    user_prompt: str,
    base_url: str | None,
    response_format: type[BaseModel] | None,
) -> str:
    """Carry the exact Pydantic schema when OpenRouter uses JSON-object mode."""
    if not _json_object_compatibility(base_url, response_format):
        return user_prompt
    if response_format is None or not issubclass(response_format, BaseModel):
        return user_prompt
    schema = json.dumps(
        response_format.model_json_schema(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        f"{user_prompt}\n\nReturn exactly one JSON object matching this JSON Schema. "
        f"Use the property names exactly as written:\n{schema}"
    )


def _apply_legacy_json_fallback(
    extra_kwargs: dict[str, Any],
    allow_unvalidated: bool,
    response_format: type[BaseModel] | None,
    use_guided_json: bool,
    *,
    json_schema_strict: bool = True,
    openrouter_compatibility: bool = False,
) -> None:
    """Select JSON Schema or portable JSON-object structured output.

    OpenRouter keeps its JSON-object compatibility request. Guided decoding
    keeps the strict JSON Schema request. Other tolerant structured calls can
    opt into the original, non-strict Pydantic schema.
    """
    if not allow_unvalidated or response_format is None:
        return
    extra_kwargs["response_format"] = (
        _json_schema_response_format(
            response_format,
            json_schema_strict=json_schema_strict if not use_guided_json else True,
        )
        if (
            _is_pydantic_model_type(response_format)
            and (
                use_guided_json
                or (not openrouter_compatibility and not json_schema_strict)
            )
        )
        else {"type": "json_object"}
    )


def _token_usage(response: Any) -> Any:
    """Normalize a response's usage record to a token-count object."""
    usage = getattr(response, "usage", None)
    return usage or type("U", (), {"prompt_tokens": None, "completion_tokens": None})()


def _plain_value(value: Any) -> Any:
    """Convert provider usage objects into JSON-compatible values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [_plain_value(item) for item in value]
    items = _plain_items(value)
    if items is None:
        return str(value)
    return {str(key): _plain_value(item) for key, item in items}


def _plain_items(value: Any) -> Any:
    """Return the key-value pairs of a mapping or public object attributes."""
    if isinstance(value, Mapping):
        return value.items()
    if hasattr(value, "__dict__"):
        return [(k, v) for k, v in vars(value).items() if not k.startswith("_")]
    return None


def _usage_details(response: Any) -> dict[str, Any]:
    """Preserve provider usage details, including reasoning token counts."""
    usage = getattr(response, "usage", None)
    plain = _plain_value(usage)
    return plain if isinstance(plain, dict) else {}


def _is_pydantic_model_type(value: Any) -> bool:
    """Return whether *value* is a concrete Pydantic response model type."""
    return isinstance(value, type) and issubclass(value, BaseModel)


def _response_choice(response: Any) -> Any | None:
    """Return the first completion choice when an SDK response has one."""
    choices = getattr(response, "choices", None)
    if not choices:
        return None
    try:
        return choices[0]
    except (IndexError, KeyError, TypeError):
        return None


def _response_content(response: Any) -> Any:
    """Extract only provider message content from a completion response."""
    choice = _response_choice(response)
    message = getattr(choice, "message", None) if choice is not None else None
    return getattr(message, "content", None)


def _response_finish_reason(response: Any) -> str | None:
    """Read a provider finish reason without depending on SDK model classes."""
    choice = _response_choice(response)
    reason = getattr(choice, "finish_reason", None) if choice is not None else None
    return reason if isinstance(reason, str) else None


def _raise_if_length_without_content(response: Any) -> None:
    """Fail a length stop that returned no final content.

    Reasoning models can spend the whole completion cap on hidden reasoning.
    A truncated but non-empty answer keeps its historical handling.
    """
    if _response_finish_reason(response) == "length" and not _response_content(
        response
    ):
        raise LengthFinishReasonError(completion=response)


def _locally_parse_response_content(
    content: Any,
    response_format: type[BaseModel],
) -> Any:
    """Parse strict structured content after raw response capture.

    Returning the original content on a local validation error is deliberate:
    ``call_with_policy`` owns contract diagnostics and can log the malformed
    response together with its usage.  Successful strict calls still expose
    the parsed model to direct callers, matching the historical API.
    """
    if isinstance(content, response_format):
        return content
    try:
        if isinstance(content, dict):
            return response_format.model_validate(content)
        if isinstance(content, str):
            return response_format.model_validate(json.loads(content))
    except Exception:  # noqa: BLE001 - retain raw content for safe parsing
        return content
    return content


def _parse_strict_response_content(
    content: Any,
    response_format: type[BaseModel] | None,
    request_unvalidated: bool,
) -> Any:
    """Apply local strict validation only after raw provider evidence exists."""
    if (
        response_format is None
        or request_unvalidated
        or not _is_pydantic_model_type(response_format)
    ):
        return content
    return _locally_parse_response_content(content, response_format)


def _top_k_extra_body(top_k: int | None) -> dict[str, Any]:
    """The extra_body entries for the top_k control."""
    if top_k is None:
        return {}
    return {"top_k": top_k}


def _thinking_extra_body(enable_thinking: bool | None) -> dict[str, Any]:
    """Map the profile switch to the vLLM chat-template request body."""
    if enable_thinking is not None:
        return {"chat_template_kwargs": {"enable_thinking": enable_thinking}}
    return {}


def _json_schema_response_format(
    response_format: type[BaseModel],
    *,
    json_schema_strict: bool = True,
) -> dict[str, Any]:
    """Build the OpenAI-compatible JSON Schema request shape."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": response_format.__name__,
            "strict": json_schema_strict,
            "schema": portable_request_schema(response_format.model_json_schema()),
        },
    }


class LLMResult(BaseModel):
    """Wrapper carrying the LLM response plus usage telemetry."""

    content: Any = Field(description="Parsed model instance or raw text string.")
    prompt_tokens: int | None = Field(
        default=None, description="Prompt tokens consumed, when reported."
    )
    completion_tokens: int | None = Field(
        default=None, description="Completion tokens generated, when reported."
    )
    usage_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider usage details, including reasoning token counts.",
    )
    duration_ms: int = Field(description="Wall-clock duration in milliseconds.")
    system_prompt: str = Field(default="", description="System prompt sent to the LLM.")
    user_prompt: str = Field(default="", description="User prompt sent to the LLM.")
    raw_response: Any | None = Field(
        default=None,
        description="Exact provider message content before local parsing.",
    )
    request_controls: dict[str, Any] = Field(
        default_factory=dict,
        description="Nonsecret provider controls used for this request.",
    )


class LLMClient:
    """Thin wrapper around the OpenAI SDK for structured and unstructured completions."""

    DEFAULT_TEMPERATURE: float = DEFAULT_TEMPERATURE

    _OPENROUTER_DEFAULT_HEADERS: dict[str, str] = _OPENROUTER_DEFAULT_HEADERS

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        context_window: int | None = None,
        safety_margin: int | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        extra_headers: dict[str, str] | None = None,
        top_p: float | None = None,
        top_k: int | None = None,
        enable_thinking: bool | None = None,
        use_guided_decoding: bool | None = None,
        timeout: float | None = None,
        seed: int | None = None,
        reasoning_effort: str | None = None,
        service_tier: str | None = None,
        service_tier_fallback: str | None = None,
        sampling_controls: bool | None = None,
        strict_json_schema: bool | None = None,
        json_schema_strict: bool | None = None,
        session: ProviderCallSession | None = None,
    ) -> None:
        self.session = session
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.model = _resolve_model(model)
        self.context_window = _resolve_optional_int(
            context_window, _ENV_CONTEXT_WINDOW, minimum=1
        )
        self.safety_margin = _resolve_optional_int(
            safety_margin, _ENV_SAFETY_MARGIN, minimum=0
        )
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
        self.seed = (
            _validated_int(seed, "seed", minimum=0) if seed is not None else None
        )
        self.enable_thinking = enable_thinking
        self.use_guided_decoding = _resolve_bool(
            use_guided_decoding,
            _ENV_USE_GUIDED_DECODING,
            False,
        )
        self.timeout = _resolve_timeout(timeout, os.environ.get(_ENV_TIMEOUT))
        self.reasoning_effort = reasoning_effort
        self.service_tier = service_tier
        self.service_tier_fallback = service_tier_fallback
        self.sampling_controls = (
            True if sampling_controls is None else sampling_controls
        )
        if strict_json_schema:
            raise ValueError(
                "strict_json_schema: true is not supported; set "
                "strict_json_schema: false or remove the key from the profile"
            )
        self.strict_json_schema = False
        self.json_schema_strict = (
            True if json_schema_strict is None else json_schema_strict
        )

        if not self.base_url and not (session is not None and session.replay_only):
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

        Structured-output enforcement is emitted separately as the standard
        top-level ``response_format`` request field.
        """
        kwargs: dict[str, Any] = {}
        if self.sampling_controls:
            kwargs["temperature"] = effective_temp
            if self.top_p is not None:
                kwargs["top_p"] = self.top_p
            if self.seed is not None:
                kwargs["seed"] = self.seed
        if effective_max is not None:
            kwargs["max_completion_tokens"] = effective_max
        if self.reasoning_effort is not None:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if self.service_tier is not None:
            kwargs["service_tier"] = self.service_tier

        extra_body = (
            {
                **_top_k_extra_body(self.top_k),
                **_thinking_extra_body(self.enable_thinking),
            }
            if self.sampling_controls
            else {}
        )
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
            if not _is_pydantic_model_type(response_format):
                raise TypeError(
                    "a strict structured completion needs a Pydantic model class "
                    f"as response_format, got {response_format!r}"
                )
            # Validate only after the raw content and usage have been captured.
            extra_kwargs = {
                **extra_kwargs,
                "response_format": _json_schema_response_format(
                    response_format,
                    json_schema_strict=self.json_schema_strict,
                ),
            }

        response = self._send(
            "chat.completions.create",
            model=self.model,
            messages=messages,
            **extra_kwargs,
        )
        _raise_if_length_without_content(response)
        return response, _response_content(response)

    def _send(self, api: str, **request: Any) -> Any:
        """Send one SDK request, through this client's record/replay session if any."""

        def send() -> Any:
            endpoint = self._client
            for part in api.split("."):
                endpoint = getattr(endpoint, part)
            return endpoint(**request)

        if self.session is None:
            return retry_once(send)
        return self.session.exchange_with_retry(api=api, request=request, send=send)

    @staticmethod
    def _is_429_rate_limit(error: BaseException) -> bool:
        """Return whether an OpenAI rate-limit error carries HTTP 429."""
        if not isinstance(error, RateLimitError):
            return False
        status = getattr(error, "status_code", None)
        if status is None:
            status = getattr(getattr(error, "response", None), "status_code", None)
        return status == 429

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        allow_unvalidated: bool = False,
    ) -> LLMResult:
        if self.session is None:
            return self._complete(
                system_prompt,
                user_prompt,
                response_format,
                max_completion_tokens,
                temperature,
                allow_unvalidated,
            )
        with self.session.scope():
            return self._complete(
                system_prompt,
                user_prompt,
                response_format,
                max_completion_tokens,
                temperature,
                allow_unvalidated,
            )

    def _complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None,
        max_completion_tokens: int | None,
        temperature: float | None,
        allow_unvalidated: bool,
    ) -> LLMResult:
        effective_max = reasoning_completion_cap(
            max_completion_tokens or self.max_completion_tokens,
            profile_cap=self.max_completion_tokens,
            reasoning_effort=self.reasoning_effort,
        )
        effective_temp = temperature if temperature is not None else self.temperature

        request_unvalidated = allow_unvalidated or _json_object_compatibility(
            self.base_url, response_format
        )
        effective_user_prompt = _openrouter_schema_prompt(
            user_prompt, self.base_url, response_format
        )

        # Use vLLM guided_json for strict schema enforcement when enabled via profile
        # This enables guided decoding which masks invalid tokens during generation
        # Only enabled when use_guided_decoding=True in model profile
        use_guided_json = _guided_json_enabled(
            self.use_guided_decoding, request_unvalidated, response_format
        )
        extra_kwargs = self._build_extra_kwargs(
            effective_max, effective_temp, response_format, use_guided_json
        )
        _apply_legacy_json_fallback(
            extra_kwargs,
            request_unvalidated,
            response_format,
            use_guided_json,
            json_schema_strict=self.json_schema_strict,
            openrouter_compatibility=_json_object_compatibility(
                self.base_url, response_format
            ),
        )

        t0 = time.perf_counter_ns()
        messages = _prompt_messages(system_prompt, effective_user_prompt)
        service_tier_fallback_used = False
        try:
            response, content = self._request_completion(
                messages,
                response_format,
                extra_kwargs,
                request_unvalidated,
            )
        except RateLimitError as error:
            if (
                self.service_tier is None
                or self.service_tier_fallback is None
                or not self._is_429_rate_limit(error)
            ):
                raise
            retry_kwargs = {
                **extra_kwargs,
                "service_tier": self.service_tier_fallback,
            }
            response, content = self._request_completion(
                messages,
                response_format,
                retry_kwargs,
                request_unvalidated,
            )
            service_tier_fallback_used = True

        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        usage = _token_usage(response)
        content = _parse_strict_response_content(
            content, response_format, request_unvalidated
        )

        return LLMResult(
            content=content,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            usage_details=_usage_details(response),
            duration_ms=duration_ms,
            system_prompt=system_prompt,
            user_prompt=effective_user_prompt,
            raw_response=_response_content(response),
            request_controls=self._request_controls(
                effective_temp,
                effective_max,
                response_format,
                service_tier_fallback_used=service_tier_fallback_used,
            ),
        )

    def _request_controls(
        self,
        effective_temp: float | None,
        effective_max: int | None,
        response_format: type[BaseModel] | None,
        *,
        service_tier_fallback_used: bool,
    ) -> dict[str, Any]:
        """Record the controls one completion request actually used."""
        sampled = self.sampling_controls
        return {
            "temperature": effective_temp if sampled else None,
            "max_completion_tokens": effective_max,
            "top_p": self.top_p if sampled else None,
            "top_k": self.top_k if sampled else None,
            "seed": self.seed if sampled else None,
            "enable_thinking": self.enable_thinking if sampled else None,
            "reasoning_effort": self.reasoning_effort,
            "service_tier": (
                self.service_tier_fallback
                if service_tier_fallback_used
                else self.service_tier
            ),
            "service_tier_fallback_used": service_tier_fallback_used,
            "service_tier_original": (
                self.service_tier if service_tier_fallback_used else None
            ),
            "service_tier_fallback": self.service_tier_fallback,
            "sampling_controls": self.sampling_controls,
            "strict_json_schema": self.strict_json_schema,
            "json_schema_strict": self.json_schema_strict,
            "response_schema": (
                response_format.__name__ if response_format is not None else None
            ),
        }


def effective_model_config(
    client: LLMClient,
    *,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Return effective non-secret settings suitable for run manifests."""
    return {
        "model": client.model,
        "endpoint_configured": bool(client.base_url),
        "context_window": getattr(client, "context_window", None),
        "safety_margin": getattr(client, "safety_margin", None),
        "max_completion_tokens": getattr(client, "max_completion_tokens", None),
        "temperature": effective_temperature(client, temperature),
        "top_p": getattr(client, "top_p", None),
        "top_k": getattr(client, "top_k", None),
        "seed": getattr(client, "seed", None),
        "enable_thinking": getattr(client, "enable_thinking", None),
        "use_guided_decoding": getattr(client, "use_guided_decoding", False),
        "reasoning_effort": getattr(client, "reasoning_effort", None),
        "service_tier": getattr(client, "service_tier", None),
        "service_tier_fallback": getattr(client, "service_tier_fallback", None),
        "sampling_controls": getattr(client, "sampling_controls", True),
        "strict_json_schema": getattr(client, "strict_json_schema", False),
        "json_schema_strict": getattr(client, "json_schema_strict", True),
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
