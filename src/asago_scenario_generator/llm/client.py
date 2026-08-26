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

from asago_scenario_generator.llm.messages import prompt_messages as _prompt_messages

_DEFAULT_TEMPERATURE = 0.4


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


def _is_plain_scalar(value: Any) -> bool:
    """Whether *value* is already a JSON-compatible scalar."""
    if value is None:
        return True
    return isinstance(value, (str, int, float, bool))


def _plain_mapping(value: Mapping) -> dict[str, Any]:
    return {str(key): _plain_value(item) for key, item in value.items()}


def _plain_sequence(value: Any) -> list[Any]:
    return [_plain_value(item) for item in value]


def _plain_object(value: Any) -> Any:
    """Convert an arbitrary object via its ``__dict__``, skipping privates."""
    if not hasattr(value, "__dict__"):
        return str(value)
    return {
        str(key): _plain_value(item)
        for key, item in vars(value).items()
        if not key.startswith("_")
    }


def _plain_value(value: Any) -> Any:
    """Convert SDK/Pydantic telemetry objects into JSON-compatible values."""
    if _is_plain_scalar(value):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return _plain_mapping(value)
    if isinstance(value, (list, tuple)):
        return _plain_sequence(value)
    return _plain_object(value)


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


def _is_pydantic_model_schema(response_format: type[BaseModel]) -> bool:
    """Whether the response format is a Pydantic model class usable as a schema."""
    try:
        return issubclass(response_format, BaseModel)
    except TypeError:
        return False


def _decoded_json_value(stripped: str) -> tuple[Any, int] | None:
    """Decode one leading JSON value, or None when the text is not a JSON value."""
    try:
        value, end = json.JSONDecoder().raw_decode(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return value, end


def _validated_recovered(
    value: Any, response_format: type[BaseModel]
) -> BaseModel | None:
    """Validate a decoded value against the schema, or None when invalid."""
    try:
        return response_format.model_validate(value)
    except (TypeError, ValueError):
        return None


def _recoverable_input(content: Any, response_format: type[BaseModel] | None) -> bool:
    """Whether the input can be a recoverable structured partial."""
    if not isinstance(content, str) or response_format is None:
        return False
    return _is_pydantic_model_schema(response_format)


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
    if not _recoverable_input(content, response_format):
        return None
    stripped = content.lstrip()
    decoded = _decoded_json_value(stripped)
    if decoded is None:
        return None
    value, end = decoded
    if stripped[end:].strip():
        return None
    return _validated_recovered(value, response_format)


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


def _resolve_base_url_arg(explicit: str | None) -> str | None:
    """Resolve base_url from the explicit argument or environment."""
    return explicit or os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL") or None


def _resolve_api_key_arg(explicit: str | None) -> str:
    """Resolve the API key from the explicit argument or environment."""
    return explicit or os.environ.get("ASAGO_SCENARIO_GENERATOR_API_KEY", "unused")


def _resolve_model_arg(explicit: str | None) -> str:
    """Resolve the model name from the explicit argument or environment."""
    return explicit or os.environ.get(
        "ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-3n-e4b-it"
    )


def _resolve_max_tokens_arg(explicit: int | None) -> int | None:
    """Resolve max completion tokens, falling back to the environment."""
    env_val = os.environ.get("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS")
    return explicit or (int(env_val) if env_val else None)


def _resolve_temperature_arg(explicit: float | None) -> float:
    """Resolve the temperature from the explicit argument, env, or default."""
    if explicit is not None:
        return explicit
    env_temp = os.environ.get("ASAGO_SCENARIO_GENERATOR_TEMPERATURE")
    if env_temp is not None:
        return float(env_temp)
    return _DEFAULT_TEMPERATURE


def _require_base_url(base_url: str | None) -> None:
    """Fail fast when no endpoint is configured."""
    if not base_url:
        raise ValueError(
            "No LLM endpoint configured."
            " Set ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL or pass --base-url."
        )


def _openai_client(
    base_url: str,
    api_key: str,
    extra_headers: dict[str, str] | None,
    timeout: float | None,
) -> OpenAI:
    """Build the OpenAI SDK client with optional timeout."""
    openai_kwargs: dict[str, Any] = dict(
        base_url=base_url,
        api_key=api_key,
        default_headers=extra_headers or None,
    )
    if timeout is not None:
        openai_kwargs["timeout"] = timeout
    return OpenAI(**openai_kwargs)


def _json_env_headers(env_name: str) -> dict[str, str]:
    """Parse a JSON-encoded headers environment variable, defaulting to empty."""
    env_raw = os.environ.get(env_name)
    return json.loads(env_raw) if env_raw else {}


def _inject_openrouter_defaults(
    merged: dict[str, str],
    base_url: str | None,
    defaults: Mapping[str, str],
) -> None:
    """Fill missing keys with OpenRouter defaults when the URL is OpenRouter."""
    if base_url and "openrouter.ai" in base_url:
        for key, default in defaults.items():
            merged.setdefault(key, default)


def _effective_temperature(explicit: float | None, fallback: float) -> float:
    """The effective temperature: explicit value, else the client default."""
    return explicit if explicit is not None else fallback


def _completion_extra_kwargs(
    effective_max: int | None,
    effective_temp: float,
    top_p: float | None,
    top_k: int | None,
) -> dict[str, Any]:
    """Build the provider-facing kwargs for one completion request."""
    extra_kwargs: dict[str, Any] = {"temperature": effective_temp}
    if effective_max is not None:
        extra_kwargs["max_completion_tokens"] = effective_max
    if top_p is not None:
        extra_kwargs["top_p"] = top_p
    if top_k is not None:
        extra_kwargs["extra_body"] = {"top_k": top_k}
    return extra_kwargs


def _request_completion(
    client: OpenAI,
    model: str,
    messages: list[dict[str, Any]],
    response_format: type[BaseModel] | None,
    extra_kwargs: dict[str, Any],
) -> tuple[Any, Any]:
    """Run one provider request, returning ``(response, content)``."""
    if response_format is not None:
        response = client.beta.chat.completions.parse(
            model=model,
            messages=messages,
            response_format=response_format,
            **extra_kwargs,
        )
        content = response.choices[0].message.parsed
    else:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            **extra_kwargs,
        )
        content = response.choices[0].message.content
    return response, content


def _recover_length_failure(
    exc: LengthFinishReasonError,
    response_format: type[BaseModel] | None,
) -> tuple[Any, Any, bool]:
    """Normalize a structured SDK length failure into recovery or a typed error."""
    completion = exc.completion
    partial_content = _choice_content(completion)
    recovered = _recover_complete_structured_partial(partial_content, response_format)
    if recovered is not None:
        return completion, recovered, True
    raise CompletionLengthError.from_usage(
        completion.usage,
        response=completion,
        partial_content=partial_content,
    ) from exc


def _raise_if_unstructured_length(
    response: Any, response_format: type[BaseModel] | None
) -> None:
    """Raise a typed length error when an unstructured choice finished early."""
    finish_reason = getattr(response.choices[0], "finish_reason", None)
    if response_format is None and str(finish_reason) == "length":
        raise CompletionLengthError.from_usage(
            response.usage,
            response=response,
            partial_content=_choice_content(response),
        )


def _request_controls(
    response_format: type[BaseModel] | None,
    effective_max: int | None,
    transport_token_cap: int | None,
    effective_temp: float,
    top_p: float | None,
    top_k: int | None,
    recovered_whitespace: bool,
) -> dict[str, Any]:
    """The request_controls telemetry dict for one completion result."""
    return {
        "response_schema": _response_schema_label(response_format),
        "max_completion_tokens": effective_max,
        "transport_token_cap": transport_token_cap,
        "temperature": effective_temp,
        "top_p": top_p,
        "top_k": top_k,
        "structured_whitespace_recovered": recovered_whitespace,
    }


class LLMClient:
    """Thin wrapper around the OpenAI SDK for structured and unstructured completions."""

    DEFAULT_TEMPERATURE: float = _DEFAULT_TEMPERATURE

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
        self.base_url = _resolve_base_url_arg(base_url)
        self.api_key = _resolve_api_key_arg(api_key)
        self.model = _resolve_model_arg(model)
        self.max_completion_tokens = _resolve_max_tokens_arg(max_completion_tokens)
        self.temperature = _resolve_temperature_arg(temperature)
        self.top_p = top_p
        self.top_k = top_k
        self.use_guided_decoding = use_guided_decoding
        self.timeout = timeout

        # --- extra headers resolution ---
        self.extra_headers = self._resolve_extra_headers(extra_headers)

        _require_base_url(self.base_url)
        self._client = _openai_client(
            self.base_url, self.api_key, self.extra_headers, timeout
        )

    def _resolve_extra_headers(
        self, explicit: dict[str, str] | None
    ) -> dict[str, str] | None:
        """Merge explicit headers, env-var headers, and OpenRouter defaults."""
        env_headers = _json_env_headers("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS")
        merged: dict[str, str] = {**env_headers, **(explicit or {})}
        _inject_openrouter_defaults(
            merged, self.base_url, self._OPENROUTER_DEFAULT_HEADERS
        )
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
        effective_temp = _effective_temperature(temperature, self.temperature)
        top_p = getattr(self, "top_p", None)
        top_k = getattr(self, "top_k", None)

        messages = _prompt_messages(system_prompt, user_prompt)
        extra_kwargs = _completion_extra_kwargs(
            effective_max, effective_temp, top_p, top_k
        )

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
            request_controls=_request_controls(
                response_format,
                effective_max,
                transport_token_cap,
                effective_temp,
                top_p,
                top_k,
                recovered_whitespace,
            ),
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
            response, content = _request_completion(
                self._client, self.model, messages, response_format, extra_kwargs
            )
        except LengthFinishReasonError as exc:
            return _recover_length_failure(exc, response_format)
        _raise_if_unstructured_length(response, response_format)
        return response, content, False


def _choice_content(response: Any) -> Any | None:
    """Read provider partial content for diagnostics only."""
    try:
        return response.choices[0].message.content
    except (AttributeError, IndexError, KeyError, TypeError):
        return None


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T13:08:38Z","module_hash":"6d3475c9fe5ddad87857bb219373cbb012f204c939b68ea8f7f48dd54214cc93","source_sha256":"d5727a6f4e580a0636c3bd6446093cc718b7d45c78c1f1e706ebf689b8b91253","functions":[{"id":"func/CompletionLengthError.__init__","name":"__init__","line":44,"end_line":79,"hash":"3ac858f40023ff2bd7630985c35f3f814471f38439860a27c958518d5ef82baf"},{"id":"func/CompletionLengthError.from_usage","name":"from_usage","line":82,"end_line":110,"hash":"48fa0e8b52818aeea7eea5e81f9ad8a6525a8bbc62b8305a5a70ec46f1e35929"},{"id":"func/_usage_counts","name":"_usage_counts","line":113,"end_line":120,"hash":"b27e72f0ae89883296db113fb79b463db2b61890c08679def7c646334ea5f294"},{"id":"func/_is_plain_scalar","name":"_is_plain_scalar","line":123,"end_line":127,"hash":"add6579baf955c6ce676afbf0ebcc4e1baf63ab985646a6fb9e1c9a6385e7db1"},{"id":"func/_plain_mapping","name":"_plain_mapping","line":130,"end_line":131,"hash":"a1d80f02688230e814ddb196a704fcd4baa55a79ae55a751f1115e7beab8f469"},{"id":"func/_plain_sequence","name":"_plain_sequence","line":134,"end_line":135,"hash":"59b8d5c789b98d3038b1305fce85b5cbccf567a48a8a8a2b8ca1a11c2f6525ed"},{"id":"func/_plain_object","name":"_plain_object","line":138,"end_line":146,"hash":"22d76c9683374bf2e4e3083878e4e906e6d877ce9a0d984af89d007642f419bd"},{"id":"func/_plain_value","name":"_plain_value","line":149,"end_line":159,"hash":"924e68fae1bb4e5f7feecf676264c86ffd64cb98dd6c65a657753a982d4e7b06"},{"id":"func/_usage_details","name":"_usage_details","line":162,"end_line":165,"hash":"56ca3ced7e032ae66388550e5d31c7821e8549415f6bfb03132d2fd69c8322b3"},{"id":"func/_response_field","name":"_response_field","line":168,"end_line":170,"hash":"42aecfddb396013b33d6b5fd26c1cc43cd4779b2effbf7cd9d79613d1614a342"},{"id":"func/_redacted_preview","name":"_redacted_preview","line":180,"end_line":184,"hash":"9ee3c49d3adeee1310a901749b2719209cfcbaf60fc2a435dbfdcd7cbf2c30da"},{"id":"func/_partial_diagnostics","name":"_partial_diagnostics","line":187,"end_line":203,"hash":"f8c29615ac46271a1397f6648a7cc154277ce653c48187584e2fd6351d0b3c86"},{"id":"func/_response_schema_label","name":"_response_schema_label","line":206,"end_line":211,"hash":"282faa93f9b7a71302c23b7c6461db7eee4d0b8d18150b4901d70c64efd0acb2"},{"id":"func/_is_pydantic_model_schema","name":"_is_pydantic_model_schema","line":214,"end_line":219,"hash":"c8c38e24f4c804a2483bf922faa37a855b1035d1f2ae92ccae1088b210edbd43"},{"id":"func/_decoded_json_value","name":"_decoded_json_value","line":222,"end_line":228,"hash":"b78beb20a56555782848e350a5df110bc0871e7b4bd602b72bc7cdd8d4df3207"},{"id":"func/_validated_recovered","name":"_validated_recovered","line":231,"end_line":238,"hash":"bd3d8d83fe7338f36423364696d5181a988bcb2d936963064699e7ff8d5bd3b2"},{"id":"func/_recoverable_input","name":"_recoverable_input","line":241,"end_line":245,"hash":"3e182a24c6c3d2570b3ccaba1315cc0468d636db4d83711d756462f46631f85d"},{"id":"func/_recover_complete_structured_partial","name":"_recover_complete_structured_partial","line":248,"end_line":269,"hash":"a6fa8bc2aed9bdae6ee668f3fb24ef68a0a2c96168bf677e8c8c72ba931c5c2b"},{"id":"func/_resolve_base_url_arg","name":"_resolve_base_url_arg","line":287,"end_line":289,"hash":"3a5aeaf105a4202fc810a514f83e587aab4d614f9b7816facb93db580119177a"},{"id":"func/_resolve_api_key_arg","name":"_resolve_api_key_arg","line":292,"end_line":294,"hash":"1084416fdc4402219b2fce461dcb038543211c9e8a534aa3585aded8ba48b5f6"},{"id":"func/_resolve_model_arg","name":"_resolve_model_arg","line":297,"end_line":301,"hash":"8ba0f97069a12c0b4d0a5addc544b22635f7854e255e02618c16386a0b54c67d"},{"id":"func/_resolve_max_tokens_arg","name":"_resolve_max_tokens_arg","line":304,"end_line":307,"hash":"0e89de287e0c0b39a4eff60583116f32d7c1b15867b06313eb3a5f0f7e647a66"},{"id":"func/_resolve_temperature_arg","name":"_resolve_temperature_arg","line":310,"end_line":317,"hash":"1857385c2f22af9eea80a5a3ba9ec7d299fedf21f8033d68404b2867e7c69d8b"},{"id":"func/_require_base_url","name":"_require_base_url","line":320,"end_line":326,"hash":"c3b7e05e3df908ca9b7566cd88647dd55a36f3a376bcc81adf634930ab357b05"},{"id":"func/_openai_client","name":"_openai_client","line":329,"end_line":343,"hash":"9e0ac96bf2dc594997987189b72deb74c0077ed2c4018d6b1e774e8cdec95242"},{"id":"func/_json_env_headers","name":"_json_env_headers","line":346,"end_line":349,"hash":"11520ff178a3d16433c8ce795f328070a4da5a4a909ba8814b814819f27efeba"},{"id":"func/_inject_openrouter_defaults","name":"_inject_openrouter_defaults","line":352,"end_line":360,"hash":"2fcade68887f11e2fb8bb9406112145b7a54b8c141ee3be3e6094918fc1973d1"},{"id":"func/_effective_temperature","name":"_effective_temperature","line":363,"end_line":365,"hash":"6465900fd94a6a99afefdb4ab9f67da774e72574b30dc822fbd89eb4d1a718fb"},{"id":"func/_completion_extra_kwargs","name":"_completion_extra_kwargs","line":368,"end_line":382,"hash":"aba7e68f8e7facceeb484d0ee18819ff01ac982f14e5148bf1af95c44a11dd92"},{"id":"func/_request_completion","name":"_request_completion","line":385,"end_line":408,"hash":"3706c50af3f3670e7c95fdebf020ac0779232a8a98cc6109eac3ee145de3c24f"},{"id":"func/_recover_length_failure","name":"_recover_length_failure","line":411,"end_line":425,"hash":"301938b5c0285008640a6daf8496b67252c031adfcbb30205dc3043431a553bf"},{"id":"func/_raise_if_unstructured_length","name":"_raise_if_unstructured_length","line":428,"end_line":438,"hash":"ca3a089b3bdc50d4d8972c5f4d6664c746df06f4eed42478d762a76754cbc340"},{"id":"func/_request_controls","name":"_request_controls","line":441,"end_line":459,"hash":"a414edf1c2dae2fee7135e4f89bc9695e0fc6a427f69dc41d878ec3dd6acf12b"},{"id":"func/LLMClient.__init__","name":"__init__","line":472,"end_line":501,"hash":"9b39b08d133932949bf9cff61b6754d1893ba1ee14cc37f20e383d7c498a9b46"},{"id":"func/LLMClient._resolve_extra_headers","name":"_resolve_extra_headers","line":503,"end_line":512,"hash":"e731d0c50565e645c403af2f031829aa8be06706c3bb29438d721d0dce0209e3"},{"id":"func/LLMClient.complete","name":"complete","line":514,"end_line":560,"hash":"43e80e5d8c4f27a545407d6c17a9c6080f4aa869f20a7ef5fec8a732fa8484e4"},{"id":"func/LLMClient._complete","name":"_complete","line":562,"end_line":582,"hash":"a79661e3026e784fbc6d2e875cb2ca6a8f0b61bd189389c353d40ad1a20d8a63"},{"id":"func/_choice_content","name":"_choice_content","line":585,"end_line":590,"hash":"60552e553283c84c69c734116cf1de15b62e0c92ce4bea7ebcb5919d8e99ffaa"}]}
# mutate4py-manifest-end
