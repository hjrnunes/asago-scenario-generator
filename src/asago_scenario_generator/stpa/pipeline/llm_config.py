"""Shared LLM client resolution for the STPA pipeline."""

from __future__ import annotations

import logging
import os

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.model_profiles import load_profile
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession

logger = logging.getLogger(__name__)


def resolve_llm_client_from_profile(
    profiles_file: str,
    profile_name: str,
    session: ProviderCallSession | None = None,
) -> tuple[LLMClient, str]:
    """Create an LLMClient from a named model profile.

    The client records and replays through *session* when one is given.
    Returns the client and the profile name (for manifest recording).
    """
    profile = load_profile(profiles_file, profile_name)
    logger.info(
        "Loaded profile '%s' from %s: model=%s, endpoint_configured=%s",
        profile_name,
        profiles_file,
        profile.get("model"),
        bool(profile.get("base_url")),
    )
    client = LLMClient(
        base_url=profile.get("base_url"),
        api_key=profile.get("api_key"),
        model=profile.get("model"),
        context_window=profile.get("context_window"),
        safety_margin=profile.get("safety_margin"),
        max_completion_tokens=profile.get("max_completion_tokens"),
        temperature=profile.get("temperature"),
        top_p=profile.get("top_p"),
        top_k=profile.get("top_k"),
        seed=profile.get("seed"),
        enable_thinking=profile.get("enable_thinking"),
        extra_headers=profile.get("headers"),
        use_guided_decoding=profile.get("use_guided_decoding"),
        timeout=profile.get("timeout"),
        reasoning_effort=profile.get("reasoning_effort"),
        service_tier=profile.get("service_tier"),
        service_tier_fallback=profile.get("service_tier_fallback"),
        sampling_controls=profile.get("sampling_controls"),
        strict_json_schema=profile.get("strict_json_schema"),
        json_schema_strict=profile.get("json_schema_strict"),
        session=session,
    )
    return client, profile_name


def resolve_llm_client_from_env(
    session: ProviderCallSession | None = None,
) -> LLMClient:
    """Create an LLMClient from Asago environment variables."""
    base_url = os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL")
    model = os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-4-26b-a4b-it")
    api_key = os.environ.get("ASAGO_SCENARIO_GENERATOR_API_KEY", "unused")
    logger.info(
        "Creating LLMClient from env: model=%s, endpoint_configured=%s",
        model,
        bool(base_url),
    )
    return LLMClient(base_url=base_url, model=model, api_key=api_key, session=session)


def resolve_llm_client(
    profile_name: str | None,
    profiles_file: str,
    session: ProviderCallSession | None = None,
) -> tuple[LLMClient, str | None]:
    """Resolve an LLM client from *profile_name*, else from the environment.

    Returns a ``(LLMClient, profile_name_or_None)`` tuple where the
    second element is the name of the profile used (or ``None`` when
    falling back to environment variables).
    """
    if profile_name is not None:
        return resolve_llm_client_from_profile(profiles_file, profile_name, session)
    return resolve_llm_client_from_env(session), None


# ---------------------------------------------------------------------------
# Use-case reading
# ---------------------------------------------------------------------------
