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
        use_guided_decoding=profile.get("use_guided_decoding"),
        timeout=profile.get("timeout"),
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
    return len(reference) < 200 and reference.endswith((".txt", ".md"))


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
    referenced file instead.  Surrounding whitespace is tolerated because
    editors commonly terminate one-line path-reference files with a newline.
    """
    if path.startswith("@"):
        path = path[1:]
    use_case_path = Path(path)
    if not use_case_path.exists():
        raise FileNotFoundError(f"Use-case file not found: {path}")
    logger.info("Reading use-case from %s", path)
    content = use_case_path.read_text(encoding="utf-8")
    reference = content.strip()
    if _looks_like_path_reference(content) or _looks_like_path_reference(reference):
        resolved_path = _resolve_reference_path(reference, use_case_path)
        content = resolved_path.read_text(encoding="utf-8")
    logger.info("Loaded use-case text: %s", content[:100])
    return content
