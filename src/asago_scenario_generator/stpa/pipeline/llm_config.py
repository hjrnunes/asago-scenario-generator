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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:54:04Z","module_hash":"4a91adce7c3defd0e9bf3b0b0635de62f8b29ae29d52155bd663115beda70185","source_sha256":"6685cf28594f1369c1c9707cbcb6fa08dfce363a07050f23db0565255e5af290","functions":[{"id":"func/resolve_llm_client_from_profile","name":"resolve_llm_client_from_profile","line":22,"end_line":48,"hash":"4d68f484021d45d4199ae2753db1d4e9b568bf0063993b83b3725e8a3227608c"},{"id":"func/resolve_llm_client_from_env","name":"resolve_llm_client_from_env","line":51,"end_line":57,"hash":"4ddb057803d1d47fffcb670c4a1df0acca1378f4ff15f76a03d1636389d566d0"},{"id":"func/resolve_llm_client","name":"resolve_llm_client","line":60,"end_line":79,"hash":"e093d239a4207901f7c50a08408c177b94885d287a39d70dac702a8c57a0e5a5"},{"id":"func/_looks_like_path_reference","name":"_looks_like_path_reference","line":87,"end_line":101,"hash":"808f1528133b21d0da120fef55fc6d26c6f52a7664bfd2c26ab9a276459ac803"},{"id":"func/_resolve_reference_path","name":"_resolve_reference_path","line":104,"end_line":127,"hash":"c97159a13dfa2dfbc0865d6e04b1ec067ab8353245c240636423908dc4709ea5"},{"id":"func/read_use_case","name":"read_use_case","line":130,"end_line":150,"hash":"da046cbdcf826d474d71bb64f1a273d3139fec1328fb76985f02e2c30bead1bc"}]}
# mutate4py-manifest-end
