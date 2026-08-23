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

from asago_scenario_generator.stpa.infra.model_profiles import load_profile

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
    if profile_field in profile and profile[profile_field] is not None:
        return profile[profile_field], ConfigSource.profile
    if env_field in environ and environ[env_field] != "":
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


def _bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "yes"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "no"}:
        return False
    raise ValueError(f"{field} must be a boolean")


def _headers(value: Any) -> Mapping[str, str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError("headers must be a string-to-string mapping")
    return MappingProxyType(dict(value))


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
    specs = {
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
    values: dict[str, Any] = {}
    sources: dict[str, ConfigSource] = {}
    for field, (explicit, env_field, default) in specs.items():
        values[field], sources[field] = _choose(
            explicit, profile, field, environment, env_field, default
        )

    return EffectiveModelConfig(
        model=str(values["model"]),
        base_url=str(values["base_url"]) if values["base_url"] is not None else None,
        api_key=str(values["api_key"]),
        max_completion_tokens=_optional_int(
            values["max_completion_tokens"], "max_completion_tokens"
        ),
        temperature=float(values["temperature"]),
        timeout=_optional_float(values["timeout"], "timeout"),
        top_p=(float(values["top_p"]) if values["top_p"] is not None else None),
        top_k=_optional_int(values["top_k"], "top_k"),
        use_guided_decoding=_bool(values["use_guided_decoding"], "use_guided_decoding"),
        extra_headers=_headers(values["headers"]),
        profile_name=model_profile,
        profiles_file=profile_path if model_profile else None,
        sources=MappingProxyType(sources),
    )
