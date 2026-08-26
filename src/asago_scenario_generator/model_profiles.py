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

REQUIRED_FIELDS: tuple[str, ...] = ("base_url", "model", "api_key")
OPTIONAL_FIELDS: tuple[str, ...] = (
    "max_completion_tokens",
    "temperature",
    "top_p",
    "top_k",
    "headers",
    "use_guided_decoding",
    "timeout",
)


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
        optional fields present (``max_completion_tokens``, ``temperature``,
        ``top_p``, ``top_k``, ``headers``, ``use_guided_decoding``).

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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T10:05:22Z","module_hash":"77c68b4638c64dc17302a7f89728f749bc3fc5c5ce77f7356479976c17453bea","source_sha256":"04f9b75fef7cf61b721a9d204eb6bcd1f9ca6e7a824048ffb74d0c605644c76e","functions":[{"id":"func/_load_raw_profiles","name":"_load_raw_profiles","line":28,"end_line":36,"hash":"ff714750fe0041b0b6da7ec349da7bcc14766d59655e4536d289e1c0d6fc4cf4"},{"id":"func/_resolve_profile_dict","name":"_resolve_profile_dict","line":39,"end_line":51,"hash":"7f8ef73c2f1b0a7c086027ef8d87c8269586c4b66cba2e02d3da9b1c4c1d4a17"},{"id":"func/_extract_required_fields","name":"_extract_required_fields","line":54,"end_line":70,"hash":"3e51e29750c3c8be2322681e723f58543c9864284fcc95c18939d14f783c4145"},{"id":"func/_extract_optional_fields","name":"_extract_optional_fields","line":73,"end_line":79,"hash":"31c602779e4937352a8689dd491214f609f749c699e6b2383fb53e3a1d897478"},{"id":"func/load_profile","name":"load_profile","line":82,"end_line":104,"hash":"f6fbbe78df01f13564ee12bc4cfd420fdb64a00f4e7fb24bca4f5e850dea2469"}]}
# mutate4py-manifest-end
