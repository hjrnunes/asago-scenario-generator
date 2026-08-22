"""Model profile loader for the STPA pipeline.

Loads named LLM connection and generation parameters from a YAML file,
replacing the need to edit environment variables to switch models.
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
# {"version":1,"tested_at":"2026-08-09T09:14:52Z","module_hash":"48c96c3023633fc3db6f4f3e4dc706f00937cb5f080264e152b2e6c6cff83fce","functions":[{"id":"func/_load_raw_profiles","name":"_load_raw_profiles","line":24,"end_line":32,"hash":"ff714750fe0041b0b6da7ec349da7bcc14766d59655e4536d289e1c0d6fc4cf4"},{"id":"func/_resolve_profile_dict","name":"_resolve_profile_dict","line":35,"end_line":51,"hash":"7f8ef73c2f1b0a7c086027ef8d87c8269586c4b66cba2e02d3da9b1c4c1d4a17"},{"id":"func/_extract_required_fields","name":"_extract_required_fields","line":54,"end_line":70,"hash":"3e51e29750c3c8be2322681e723f58543c9864284fcc95c18939d14f783c4145"},{"id":"func/_extract_optional_fields","name":"_extract_optional_fields","line":73,"end_line":79,"hash":"31c602779e4937352a8689dd491214f609f749c699e6b2383fb53e3a1d897478"},{"id":"func/load_profile","name":"load_profile","line":82,"end_line":105,"hash":"7456fd596395071d3ba836e477b68cc17573daa2fb96ac625b7c36f6be69f3dd"}]}
# mutate4py-manifest-end
