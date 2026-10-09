"""Shared named-profile loader for generation and STPA model configuration.

Both workflows resolve connection and generation parameters from the same
YAML shape. The loader stays off either workflow façade so generation does
not import STPA infrastructure and STPA does not import the generation
pipeline.
"""

from __future__ import annotations

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


def load_profile(profiles_path: Path | str, profile_name: str) -> dict[str, Any]:
    """Load a named profile from a YAML profiles file.

    Args:
        profiles_path: Path to the YAML file containing model profiles.
        profile_name: Name of the profile to load (top-level key).

    Returns:
        A dict with keys ``base_url``, ``model``, ``api_key`` and any
        optional fields present (``context_window``, ``safety_margin``,
        ``max_completion_tokens``, ``temperature``, ``top_p``, ``top_k``,
        ``seed``, ``headers``, ``enable_thinking``, ``use_guided_decoding``,
        ``timeout``, ``reasoning_effort``, ``service_tier``,
        ``service_tier_fallback``, ``sampling_controls``,
        ``strict_json_schema``, and ``json_schema_strict``).

    Raises:
        FileNotFoundError: If the profiles file does not exist.
        KeyError: If *profile_name* is not found in the file.
        ValueError: If the profile has a field outside the allow-list (the
            message names the field, never its value), or if a required field
            is missing or empty.
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
    unknown = sorted(str(key) for key in profile if key not in _ALLOWED_FIELDS)
    if unknown:
        raise ValueError(
            f"Profile '{profile_name}' has unknown field(s): {', '.join(unknown)}"
        )
    for field in REQUIRED_FIELDS:
        if profile.get(field) in (None, ""):
            raise ValueError(
                f"Profile '{profile_name}' is missing required field '{field}'"
            )
    return {
        field: profile[field]
        for field in (*REQUIRED_FIELDS, *OPTIONAL_FIELDS)
        if profile.get(field) is not None
    }
