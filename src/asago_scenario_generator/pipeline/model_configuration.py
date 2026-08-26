"""Resolve one truthful, secret-safe model configuration for generation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from asago_scenario_generator.model_profiles import load_profile

DEFAULT_PROFILES_FILE = Path("config/model-profiles.yaml")
DEFAULT_MODEL = "gemma-3n-e4b-it"
DEFAULT_TEMPERATURE = 0.4


class ConfigSource(str, Enum):
    """Where one effective control obtained its value."""

    cli = "cli"
    profile = "profile"
    environment = "environment"
    application_default = "application_default"


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectiveModelConfig:
    """Private connection inputs plus public effective generation controls."""

    model: str
    base_url: str | None
    api_key: str
    temperature: float
    max_completion_tokens: int | None
    timeout: float | None
    top_p: float | None
    top_k: int | None
    use_guided_decoding: bool
    extra_headers: Mapping[str, str] | None
    profile_name: str | None
    profiles_file: Path | None
    sources: Mapping[str, ConfigSource]

    def client_kwargs(self) -> dict[str, Any]:
        """Return constructor inputs, including secrets, for ``LLMClient`` only."""
        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
            "max_completion_tokens": self.max_completion_tokens,
            "temperature": self.temperature,
            "extra_headers": dict(self.extra_headers or {}),
            "top_p": self.top_p,
            "top_k": self.top_k,
            "use_guided_decoding": self.use_guided_decoding,
            "timeout": self.timeout,
        }

    def public_controls(self) -> dict[str, Any]:
        """Return manifest-safe controls and their non-secret sources."""
        public_fields = (
            "model",
            "base_url",
            "temperature",
            "max_completion_tokens",
            "timeout",
            "top_p",
            "top_k",
            "use_guided_decoding",
            "headers",
        )
        return {
            "profile_name": self.profile_name,
            "profiles_file": (
                str(self.profiles_file.resolve()) if self.profiles_file else None
            ),
            "model": self.model,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            "timeout": self.timeout,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "use_guided_decoding": self.use_guided_decoding,
            "header_names": sorted((self.extra_headers or {}).keys()),
            "sources": {
                field: self.sources[field].value
                for field in public_fields
                if field in self.sources
            },
        }


def _profile_value(profile: Mapping[str, Any], profile_field: str) -> Any:
    """Return a profile field value, or None when the key is absent."""
    if profile_field in profile:
        return profile[profile_field]
    return None


def _has_env_value(environ: Mapping[str, str], env_field: str) -> bool:
    """Whether the environment has a non-empty value for *env_field*."""
    if env_field not in environ:
        return False
    return environ[env_field] != ""


def _choose(
    explicit: Any,
    profile: Mapping[str, Any],
    profile_field: str,
    environ: Mapping[str, str],
    env_field: str,
    default: Any,
) -> tuple[Any, ConfigSource]:
    if explicit is not None:
        return explicit, ConfigSource.cli
    profile_value = _profile_value(profile, profile_field)
    if profile_value is not None:
        return profile_value, ConfigSource.profile
    if _has_env_value(environ, env_field):
        return environ[env_field], ConfigSource.environment
    return default, ConfigSource.application_default


def _coerce_positive(value: Any, field: str, parser: Callable[[Any], Any]) -> Any:
    """Parse *value* with *parser* and require it to be strictly positive."""
    if value is None:
        return None
    parsed = parser(value)
    if parsed <= 0:
        raise ValueError(f"{field} must be positive")
    return parsed


def _optional_int(value: Any, field: str) -> int | None:
    return _coerce_positive(value, field, int)


def _optional_float(value: Any, field: str) -> float | None:
    return _coerce_positive(value, field, float)


def _bool_string_value(value: Any) -> bool | None:
    """Return the boolean meaning of a string literal, or None when it is not one."""
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    parsed = _bool_string_value(value)
    if parsed is not None:
        return parsed
    raise ValueError(f"{field} must be a boolean")


def _is_string_string_mapping(value: Any) -> bool:
    """Whether *value* is a mapping whose keys and values are all strings."""
    if not isinstance(value, Mapping):
        return False
    return all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    )


def _headers(value: Any) -> Mapping[str, str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = json.loads(value)
    if not _is_string_string_mapping(value):
        raise ValueError("headers must be a string-to-string mapping")
    return MappingProxyType(dict(value))


def _resolution_specs(
    base_url: str | None,
    api_key: str | None,
    model: str | None,
    max_completion_tokens: int | None,
    temperature: float | None,
    timeout: float | None,
    top_p: float | None,
    top_k: int | None,
    use_guided_decoding: bool | None,
    extra_headers: Mapping[str, str] | None,
) -> dict[str, tuple[Any, str, Any]]:
    """The per-field (explicit, env-var, default) resolution table."""
    return {
        "base_url": (base_url, "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None),
        "api_key": (api_key, "ASAGO_SCENARIO_GENERATOR_API_KEY", "unused"),
        "model": (model, "ASAGO_SCENARIO_GENERATOR_MODEL_NAME", DEFAULT_MODEL),
        "max_completion_tokens": (
            max_completion_tokens,
            "ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS",
            None,
        ),
        "temperature": (
            temperature,
            "ASAGO_SCENARIO_GENERATOR_TEMPERATURE",
            DEFAULT_TEMPERATURE,
        ),
        "timeout": (timeout, "ASAGO_SCENARIO_GENERATOR_TIMEOUT", None),
        "top_p": (top_p, "ASAGO_SCENARIO_GENERATOR_TOP_P", None),
        "top_k": (top_k, "ASAGO_SCENARIO_GENERATOR_TOP_K", None),
        "use_guided_decoding": (
            use_guided_decoding,
            "ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING",
            False,
        ),
        "headers": (
            extra_headers,
            "ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS",
            None,
        ),
    }


def _resolve_values(
    specs: dict[str, tuple[Any, str, Any]],
    profile: Mapping[str, Any],
    environment: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, ConfigSource]]:
    """Resolve every spec field through the CLI → profile → env → default chain."""
    values: dict[str, Any] = {}
    sources: dict[str, ConfigSource] = {}
    for field, (explicit, env_field, default) in specs.items():
        values[field], sources[field] = _choose(
            explicit, profile, field, environment, env_field, default
        )
    return values, sources


def _optional_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_float_value(value: Any) -> float | None:
    return float(value) if value is not None else None


def _config_from_values(
    values: dict[str, Any],
    sources: dict[str, ConfigSource],
    model_profile: str | None,
    profile_path: Path,
) -> EffectiveModelConfig:
    """Build the effective config from resolved values with type coercion."""
    return EffectiveModelConfig(
        model=str(values["model"]),
        base_url=_optional_str(values["base_url"]),
        api_key=str(values["api_key"]),
        max_completion_tokens=_optional_int(
            values["max_completion_tokens"], "max_completion_tokens"
        ),
        temperature=float(values["temperature"]),
        timeout=_optional_float(values["timeout"], "timeout"),
        top_p=_optional_float_value(values["top_p"]),
        top_k=_optional_int(values["top_k"], "top_k"),
        use_guided_decoding=_bool(values["use_guided_decoding"], "use_guided_decoding"),
        extra_headers=_headers(values["headers"]),
        profile_name=model_profile,
        profiles_file=profile_path if model_profile else None,
        sources=MappingProxyType(sources),
    )


def resolve_effective_model_config(
    *,
    model_profile: str | None = None,
    profiles_file: Path | str = DEFAULT_PROFILES_FILE,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    max_completion_tokens: int | None = None,
    temperature: float | None = None,
    timeout: float | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    use_guided_decoding: bool | None = None,
    extra_headers: Mapping[str, str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> EffectiveModelConfig:
    """Resolve CLI overrides, then a named profile, environment, and defaults."""
    environment = os.environ if environ is None else environ
    profile_path = Path(profiles_file)
    profile = load_profile(profile_path, model_profile) if model_profile else {}
    specs = _resolution_specs(
        base_url,
        api_key,
        model,
        max_completion_tokens,
        temperature,
        timeout,
        top_p,
        top_k,
        use_guided_decoding,
        extra_headers,
    )
    values, sources = _resolve_values(specs, profile, environment)
    return _config_from_values(values, sources, model_profile, profile_path)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:34:06Z","module_hash":"c4476600c944779fc342c874688f76807603f5d7147f86a91b4de303886fd98f","source_sha256":"24c99e150753844f8b4987f5850771469a50b5a7e8336919a521b3edba524459","functions":[{"id":"func/EffectiveModelConfig.client_kwargs","name":"client_kwargs","line":48,"end_line":61,"hash":"fc61f5b0f9ad261af77811f603c403f62ba7014d95f2f69a9579897693adabd7"},{"id":"func/EffectiveModelConfig.public_controls","name":"public_controls","line":63,"end_line":95,"hash":"9629673517cc0f06691184aee27a6182f39b416375063620c19a58e4d0602279"},{"id":"func/_profile_value","name":"_profile_value","line":98,"end_line":102,"hash":"6c7d37dc0e13de9b3c3c9228ccb688801d4f9ab23f43fc8aefccb8c4e6fe036b"},{"id":"func/_has_env_value","name":"_has_env_value","line":105,"end_line":109,"hash":"643293fa8d3c898b73c6f2fce57c6aa4eb02b795b69a8a81c2e76767eaf4ba14"},{"id":"func/_choose","name":"_choose","line":112,"end_line":127,"hash":"f35f7cf24ec70ccb158de7619773eef8935daa334f5276d198e4d2d22369d9f3"},{"id":"func/_coerce_positive","name":"_coerce_positive","line":130,"end_line":137,"hash":"a20a928291e1cc86bbb0779d28122ba17fa1f40b0ec9ee3f5261544ed0c71b4b"},{"id":"func/_optional_int","name":"_optional_int","line":140,"end_line":141,"hash":"a57537c844eb0b760a90e64d7759e68a22d1925a8ad7327ee1c12d1aa86d0dad"},{"id":"func/_optional_float","name":"_optional_float","line":144,"end_line":145,"hash":"59d394bb15e2d3e9e642a2341122042c5550cb063c4fdf7db324711636e79bb6"},{"id":"func/_bool_string_value","name":"_bool_string_value","line":148,"end_line":157,"hash":"a6d9e19d78f6f0644fb45db956d3526f3d747bb6580e03aa8a0d2066ae562129"},{"id":"func/_bool","name":"_bool","line":160,"end_line":166,"hash":"f372d9c9068b0e1592c84e5618c8b8712f089485e8374a553da6a70a71676e17"},{"id":"func/_is_string_string_mapping","name":"_is_string_string_mapping","line":169,"end_line":175,"hash":"9793c65cd2428fa2a915b06d1648a5cc4700b6e46da6600436aacc14ac84a1aa"},{"id":"func/_headers","name":"_headers","line":178,"end_line":185,"hash":"73601d3476fa7fae68da80fbf2a790360073c02507f35ad85266ebe9caa96643"},{"id":"func/_resolution_specs","name":"_resolution_specs","line":188,"end_line":228,"hash":"f81bbe96b44ad72f4450a53db266f95292e7fa68f559f3bf75d5ed9aa15046f7"},{"id":"func/_resolve_values","name":"_resolve_values","line":231,"end_line":243,"hash":"9ea4e1a0388af88af2e3bfddfde8986465548dc89ef11c0f785d25ca664cca4f"},{"id":"func/_optional_str","name":"_optional_str","line":246,"end_line":247,"hash":"3ce5eb1554d4bc55c291dbea895d740babf633c75bbb91c59c96c0307174aece"},{"id":"func/_optional_float_value","name":"_optional_float_value","line":250,"end_line":251,"hash":"223b6d02a4ff8d299834cec17a3a7873c8c4a1a01b6b2bf1a976248c5d2d804b"},{"id":"func/_config_from_values","name":"_config_from_values","line":254,"end_line":277,"hash":"e16e021e7801c976f44ea0752a0f00645a58f957a23a3207b39fbefeb88fdb20"},{"id":"func/resolve_effective_model_config","name":"resolve_effective_model_config","line":280,"end_line":313,"hash":"904527456358c2460e55d48608088a6e559701fc8bfa9b1bdf6ca7856c0b06d8"}]}
# mutate4py-manifest-end
