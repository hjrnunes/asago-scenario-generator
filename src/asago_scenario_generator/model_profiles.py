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
)


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


def _load_raw_profiles(path: Path) -> dict[str, Any]:
    """Load and return the raw YAML profiles mapping.

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Model profiles file not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _resolve_profile_dict(raw: Any, profile_name: str, path: Path) -> dict[str, Any]:
    """Return the profile dict for *profile_name* from the raw YAML.

    Raises:
        KeyError: If *profile_name* is not found.
        ValueError: If the profile entry is not a mapping.
    """
    if not isinstance(raw, dict) or profile_name not in raw:
        raise KeyError(f"Profile '{profile_name}' not found in {path}")
    profile = raw[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Profile '{profile_name}' in {path} is not a mapping")
    return profile


def _extract_required_fields(
    profile: dict[str, Any], profile_name: str, path: Path
) -> dict[str, Any]:
    """Validate and return the required fields from *profile*.

    Raises:
        ValueError: If a required field is missing or empty.
    """
    result: dict[str, Any] = {}
    for field in REQUIRED_FIELDS:
        value = profile.get(field)
        if value is None or (isinstance(value, str) and value == ""):
            raise ValueError(
                f"Profile '{profile_name}' is missing required field '{field}'"
            )
        result[field] = value
    return result


def _extract_optional_fields(profile: dict[str, Any]) -> dict[str, Any]:
    """Return optional fields that are present and non-None."""
    return {
        field: profile[field]
        for field in OPTIONAL_FIELDS
        if field in profile and profile[field] is not None
    }


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
        ``service_tier_fallback``, ``sampling_controls``, and
        ``strict_json_schema``).

    Raises:
        FileNotFoundError: If the profiles file does not exist.
        KeyError: If *profile_name* is not found in the file.
        ValueError: If a required field is missing or empty.
    """
    path = Path(profiles_path)
    raw = _load_raw_profiles(path)
    profile = _resolve_profile_dict(raw, profile_name, path)
    return _extract_required_fields(
        profile, profile_name, path
    ) | _extract_optional_fields(profile)
