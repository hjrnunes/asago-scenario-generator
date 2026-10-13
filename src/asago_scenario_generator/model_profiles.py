"""Shared named-profile loader for generation and STPA model configuration.

Both workflows resolve connection and generation parameters from the same
YAML shape. The loader stays off either workflow façade so generation does
not import STPA infrastructure and STPA does not import the generation
pipeline.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 300.0

REQUIRED_FIELDS: tuple[str, ...] = ("base_url", "model", "api_key")
OPTIONAL_FIELDS: tuple[str, ...] = (
    "context_window",
    "safety_margin",
    "max_completion_tokens",
    "temperature",
    "top_p",
    "top_k",
    "repetition_penalty",
    "seed",
    "headers",
    "enable_thinking",
    "use_guided_decoding",
    "timeout",
    "reasoning_effort",
    "service_tier",
    "service_tier_fallback",
    "sampling_controls",
    "strict_json_schema",
    "json_schema_strict",
)
_ALLOWED_FIELDS: frozenset[str] = frozenset((*REQUIRED_FIELDS, *OPTIONAL_FIELDS))


class ProfileFieldError(ValueError):
    """A profile field is unknown, missing or invalid; ``field`` names it.

    The message never holds the offending value, which can be a credential.
    """

    def __init__(self, message: str, *, field: str) -> None:
        super().__init__(message)
        self.field = field


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_false(value: Any) -> bool:
    return value is False


def _is_headers(value: Any) -> bool:
    return isinstance(value, dict) and all(
        _is_text(name) and isinstance(item, str) for name, item in value.items()
    )


def _integer(minimum: int) -> Callable[[Any], bool]:
    def check(value: Any) -> bool:
        return (
            isinstance(value, int) and not isinstance(value, bool) and value >= minimum
        )

    return check


def _number(
    *, minimum: float = 0.0, maximum: float | None = None, exclusive: bool = False
) -> Callable[[Any], bool]:
    def check(value: Any) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if not math.isfinite(value):
            return False
        if value < minimum or (exclusive and value == minimum):
            return False
        return maximum is None or value <= maximum

    return check


# One validity rule per field, as in the model-profile contract's field table.
_FIELD_RULES: dict[str, Callable[[Any], bool]] = {
    "base_url": _is_text,
    "model": _is_text,
    "api_key": _is_text,
    "context_window": _integer(1),
    "safety_margin": _integer(0),
    "max_completion_tokens": _integer(1),
    "temperature": _number(),
    "top_p": _number(maximum=1.0),
    "top_k": _integer(1),
    "repetition_penalty": _number(exclusive=True),
    "seed": _integer(0),
    "headers": _is_headers,
    "enable_thinking": _is_bool,
    "use_guided_decoding": _is_bool,
    "timeout": _number(exclusive=True),
    "reasoning_effort": _is_text,
    "service_tier": _is_text,
    "service_tier_fallback": _is_text,
    "sampling_controls": _is_bool,
    "strict_json_schema": _is_false,
    "json_schema_strict": _is_bool,
}


def reasoning_completion_cap(
    requested: int | None,
    *,
    profile_cap: int | None,
    reasoning_effort: str | None,
) -> int | None:
    """Return the completion cap to send for one request.

    Call sites size their caps for visible output. Reasoning models count hidden
    reasoning tokens against the same cap, so a profile that sets
    ``reasoning_effort`` raises every smaller call-site cap to its own
    ``max_completion_tokens``. Other profiles keep the call-site cap.
    """
    if reasoning_effort is None or profile_cap is None:
        return requested
    if requested is None:
        return profile_cap
    return max(requested, profile_cap)


def _check_profile_fields(profile: dict[str, Any], profile_name: str) -> None:
    unknown = sorted(str(key) for key in profile if key not in _ALLOWED_FIELDS)
    if unknown:
        raise ProfileFieldError(
            f"Profile '{profile_name}' has unknown field(s): {', '.join(unknown)}",
            field=unknown[0],
        )
    for field in REQUIRED_FIELDS:
        if profile.get(field) in (None, ""):
            raise ProfileFieldError(
                f"Profile '{profile_name}' is missing required field '{field}'",
                field=field,
            )
    for field, rule in _FIELD_RULES.items():
        value = profile.get(field)
        if value is not None and not rule(value):
            raise ProfileFieldError(
                f"Profile '{profile_name}' has invalid field '{field}'", field=field
            )


def load_profile(profiles_path: Path | str, profile_name: str) -> dict[str, Any]:
    """Load a named profile from a YAML profiles file.

    Args:
        profiles_path: Path to the YAML file containing model profiles.
        profile_name: Name of the profile to load (top-level key).

    Returns:
        A dict with keys ``base_url``, ``model``, ``api_key`` and any
        optional fields present (``context_window``, ``safety_margin``,
        ``max_completion_tokens``, ``temperature``, ``top_p``, ``top_k``,
        ``repetition_penalty``, ``seed``, ``headers``, ``enable_thinking``, ``use_guided_decoding``,
        ``timeout``, ``reasoning_effort``, ``service_tier``,
        ``service_tier_fallback``, ``sampling_controls``,
        ``strict_json_schema``, and ``json_schema_strict``).

    Raises:
        FileNotFoundError: If the profiles file does not exist.
        KeyError: If *profile_name* is not found in the file.
        ProfileFieldError: A ``ValueError`` whose ``field`` names a field
            outside the allow-list, a missing or empty required field, or a
            value that breaks the field's rule in the ``model-profile``
            contract. The message never holds the value.
        ValueError: If the entry is not a mapping.
    """
    path = Path(profiles_path)
    if not path.exists():
        raise FileNotFoundError(f"Model profiles file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or profile_name not in raw:
        raise KeyError(f"Profile '{profile_name}' not found in {path}")
    profile = raw[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Profile '{profile_name}' in {path} is not a mapping")
    _check_profile_fields(profile, profile_name)
    return {
        field: profile[field]
        for field in (*REQUIRED_FIELDS, *OPTIONAL_FIELDS)
        if profile.get(field) is not None
    }
