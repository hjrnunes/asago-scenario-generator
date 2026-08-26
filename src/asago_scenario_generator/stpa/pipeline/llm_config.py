"""Shared LLM client resolution for the STPA pipeline.

Extracted from ``scripts/run_sp1.py`` to avoid duplicating the LLM
client creation logic across runner scripts and the ``stpa-run`` CLI
command.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.model_profiles import load_profile

logger = logging.getLogger(__name__)

DEFAULT_PROFILES_FILE = "config/model-profiles.yaml"


def resolve_llm_client_from_profile(
    profiles_file: str, profile_name: str
) -> tuple[LLMClient, str]:
    """Create an LLMClient from a named model profile.

    Returns the client and the profile name (for manifest recording).
    """
    profile = load_profile(profiles_file, profile_name)
    logger.info(
        "Loaded profile '%s' from %s: model=%s, base_url=%s",
        profile_name,
        profiles_file,
        profile.get("model"),
        profile.get("base_url"),
    )
    client = LLMClient(
        base_url=profile.get("base_url"),
        api_key=profile.get("api_key"),
        model=profile.get("model"),
        max_completion_tokens=profile.get("max_completion_tokens"),
        temperature=profile.get("temperature"),
        top_p=profile.get("top_p"),
        top_k=profile.get("top_k"),
        extra_headers=profile.get("headers"),
        use_guided_decoding=profile.get("use_guided_decoding", False),
    )
    return client, profile_name


def resolve_llm_client_from_env() -> LLMClient:
    """Create an LLMClient from Asago environment variables."""
    base_url = os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL")
    model = os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-4-26b-a4b-it")
    api_key = os.environ.get("ASAGO_SCENARIO_GENERATOR_API_KEY", "unused")
    logger.info("Creating LLMClient from env: base_url=%s, model=%s", base_url, model)
    return LLMClient(base_url=base_url, model=model, api_key=api_key)


def resolve_llm_client(
    profile_name: str | None,
    sp_profile_name: str | None,
    profiles_file: str,
) -> tuple[LLMClient, str | None]:
    """Resolve an LLM client per stage with a three-level fallback.

    Resolution order:
      1. *sp_profile_name* (per-stage override) — if provided.
      2. *profile_name* (default --profile) — if provided.
      3. Environment variables.

    Returns a ``(LLMClient, profile_name_or_None)`` tuple where the
    second element is the name of the profile used (or ``None`` when
    falling back to environment variables).
    """
    effective = sp_profile_name or profile_name
    if effective is not None:
        return resolve_llm_client_from_profile(profiles_file, effective)
    return resolve_llm_client_from_env(), None


# ---------------------------------------------------------------------------
# Use-case reading
# ---------------------------------------------------------------------------


def _looks_like_path_reference(content: str) -> bool:
    """Check whether stripped content looks like a file-path reference.

    Returns True when the content is short (< 200 chars), has no
    newlines, and ends with ``.txt`` or ``.md`` — a heuristic for
    detecting a use-case file that contains a path to the real
    use-case file instead of actual content.
    """
    if "\n" in content or "\r" in content:
        return False
    reference = content.strip()
    return (
        len(reference) < 200
        and reference.endswith((".txt", ".md"))
    )


def _resolve_reference_path(reference: str, source_file: Path) -> Path:
    """Resolve a path reference found inside a use-case file.

    Searches the source file's parent directory first, then the
    current working directory (for relative paths). Absolute paths
    are used as-is.

    Raises:
        FileNotFoundError: When no candidate file exists.
    """
    reference_path = Path(reference)
    if reference_path.is_absolute():
        candidates = [reference_path]
    else:
        candidates = [
            source_file.parent / reference_path,
            Path.cwd() / reference_path,
        ]
    resolved = next((c for c in candidates if c.exists()), None)
    if resolved is None:
        raise FileNotFoundError(
            f"Use-case file {source_file} references unresolved path {reference!r}"
        )
    return resolved


def read_use_case(path: str) -> str:
    """Read use-case text from file, stripping @ prefix if present.

    If the file content itself looks like a path reference (short, no
    newlines, ends with ``.txt`` or ``.md``), resolves and reads the
    referenced file instead.
    """
    if path.startswith("@"):
        path = path[1:]
    use_case_path = Path(path)
    if not use_case_path.exists():
        raise FileNotFoundError(f"Use-case file not found: {path}")
    logger.info("Reading use-case from %s", path)
    content = use_case_path.read_text(encoding="utf-8")
    if _looks_like_path_reference(content):
        reference = content.strip()
        resolved_path = _resolve_reference_path(reference, use_case_path)
        content = resolved_path.read_text(encoding="utf-8")
    logger.info("Loaded use-case text: %s", content[:100])
    return content


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:26:00Z","module_hash":"4be2fe5edad8155a547da53ae30c3f09c9a789001853002182054924a0252115","functions":[{"id":"func/resolve_llm_client_from_profile","name":"resolve_llm_client_from_profile","line":22,"end_line":47,"hash":"934d2bfb618888994141f4c02699037a0f48ab8792ca33ba736dd5b3c21a8a98"},{"id":"func/resolve_llm_client_from_env","name":"resolve_llm_client_from_env","line":50,"end_line":60,"hash":"8df7a0ca3da15ab5e856da48e30d0bc9a99a5dd8fb75734afb5d91f6a54331b4"},{"id":"func/resolve_llm_client","name":"resolve_llm_client","line":63,"end_line":82,"hash":"e093d239a4207901f7c50a08408c177b94885d287a39d70dac702a8c57a0e5a5"},{"id":"func/_looks_like_path_reference","name":"_looks_like_path_reference","line":90,"end_line":104,"hash":"18819db98b3b27efef57f81adea6af6045fee56cd6f6c3dc813e0d13fdaf26e7"},{"id":"func/_resolve_reference_path","name":"_resolve_reference_path","line":107,"end_line":131,"hash":"c97159a13dfa2dfbc0865d6e04b1ec067ab8353245c240636423908dc4709ea5"},{"id":"func/read_use_case","name":"read_use_case","line":134,"end_line":153,"hash":"819d118043e1e716dc3eeac6f278a22beff63e7351a7f3306a9b3f8565450280"}]}
# mutate4py-manifest-end
