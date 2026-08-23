"""Call 0: Actor Profile generation logic."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.llm.client import (
    LengthFinishReasonError as LengthFinishReasonError,
    LLMClient,
    LLMResult,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import ACTOR_TYPES, ActorProfile
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _max_capability_level,  # noqa: F401
    compute_compatible_actor_types,  # noqa: F401
    compute_minimum_capability_level,  # noqa: F401
)
from asago_scenario_generator.pipeline.generate.actor_context import (
    build_call0_context,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ADVERSARIAL_INTENTION_KEYWORDS,
    _CAPABILITY_FLOORS,
    _CAPABILITY_ORDER,
)
from asago_scenario_generator.pipeline.generate.ontology import (
    _lookup_entry_point_controllability,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

# The provider draft protocol and the typed access-provenance policy live in
# sibling leaf modules (`actor_semantics`, `actor_access`); every name they
# own is re-exported here so the historical ``generate.actor`` import
# surface stays intact.
from asago_scenario_generator.pipeline.generate.actor_semantics import (  # noqa: F401
    ActorDraftContext,
    ActorDraftV2,
    ActorDraftV3,
    ActorDraftViolation,
    ActorSemanticDraftError,
    _actor_choice_inventory,
    _actor_draft_inventories,
    _actor_draft_prompt,
    _capability_floor_violation,
    _capability_level_inventory,
    _compatible_actor_types_for_projection,
    _compile_projected_actor_draft,
    _derive_canonical_actor_access,
    _literal_from_handles,
    _resolve_actor_handles,
    _selected_step_resource_names,
    _validate_distinct_resource_handles,
    compile_actor_draft,
    create_actor_draft_model,
    create_actor_draft_v3_model,
)
from asago_scenario_generator.pipeline.generate.actor_access import (  # noqa: F401
    ActorAccessViolation,
    Call0Response,
    CompactCall0Response,
    _Call0Item,
    _CALL0_ENUM_MAX_LENGTH,
    _CALL0_EVIDENCE_MAX_LENGTH,
    _CALL0_ITEM_MAX_LENGTH,
    _CALL0_LIST_MAX_ITEMS,
    build_actor_access_provenance,
    validate_actor_access_provenance,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normalization and validation helpers
# ---------------------------------------------------------------------------


def _normalize_actor_type(raw: str) -> str:
    """Normalize LLM-generated actor_type to a valid ActorType value.

    Handles cases where the LLM adds parenthetical qualifiers, e.g.
    "Nation-State (Information Warfare Unit)" -> "nation-state".
    """
    cleaned = raw.strip().lower().split("(")[0].strip()
    for valid in ACTOR_TYPES:
        if cleaned == valid or cleaned.replace(" ", "-") == valid:
            return valid
    # Substring match as last resort
    for valid in ACTOR_TYPES:
        if valid in cleaned or cleaned in valid:
            return valid
    logger.warning(
        "Unrecognized actor_type '%s', defaulting to 'adversarial-user'", raw
    )
    return "adversarial-user"


def _normalize_capability_level(raw: str) -> str:
    """Normalize LLM-generated capability_level to a valid value."""
    cleaned = raw.strip().lower().split("(")[0].strip()
    valid_levels = ("novice", "intermediate", "advanced", "expert")
    for level in valid_levels:
        if level in cleaned:
            return level
    logger.warning(
        "Unrecognized capability_level '%s', defaulting to 'intermediate'", raw
    )
    return "intermediate"


def _enforce_capability_floor(actor_type: str, capability_level: str) -> str:
    """Bump capability_level up to the actor-type floor if it is too low.

    Returns the (possibly upgraded) capability level.
    """
    floor = _CAPABILITY_FLOORS.get(actor_type)
    if floor is None:
        return capability_level
    floor_idx = _CAPABILITY_ORDER.index(floor)
    current_idx = (
        _CAPABILITY_ORDER.index(capability_level)
        if capability_level in _CAPABILITY_ORDER
        else 1  # default to intermediate if unknown
    )
    if current_idx < floor_idx:
        logger.warning(
            "Capability floor violation: %s actor had '%s', bumped to '%s'",
            actor_type,
            capability_level,
            floor,
        )
        return floor
    return capability_level


def _validate_actor_type(actor_profile: ActorProfile) -> ActorProfile:
    """Validate that a negligent-insider's BDI profile is non-adversarial.

    If the actor_type is ``negligent-insider`` but the intentions list contains
    adversarial keywords (e.g. "exploit", "jailbreak"), the actor is
    reassigned to ``adversarial-user`` and a warning is logged.  This is a
    defence-in-depth check behind the prompt reinforcement in
    ``call0_system.j2``.

    Returns the (possibly corrected) actor profile.
    """
    if actor_profile.actor_type != "negligent-insider":
        return actor_profile

    matched: list[str] = []
    for intention in actor_profile.intentions:
        intention_lower = intention.lower()
        for keyword in _ADVERSARIAL_INTENTION_KEYWORDS:
            if re.search(r"\b" + re.escape(keyword) + r"\b", intention_lower):
                matched.append(keyword)

    if matched:
        unique_matches = sorted(set(matched))
        logger.warning(
            "BDI validation: negligent-insider intentions contain adversarial "
            "keywords %s — reassigning to adversarial-user",
            unique_matches,
        )
        actor_profile = actor_profile.model_copy(
            update={"actor_type": "adversarial-user"},
        )
    return actor_profile


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def _complete_actor_profile(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    *,
    compact_response_schema: bool = False,
    response_format: type[BaseModel] | None = None,
    max_completion_tokens: int | None = None,
) -> LLMResult:
    """Complete Call 0 exactly once with the operator-configured limit.

    Length exhaustion is normalized by the shared adapter into typed
    ``CompletionLengthError`` evidence; this helper never retries.
    Retry ownership belongs to the finalization lifecycle.
    """
    effective_max = (
        max_completion_tokens
        if max_completion_tokens is not None
        else client.max_completion_tokens
    )
    return client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format
        or (CompactCall0Response if compact_response_schema else Call0Response),
        max_completion_tokens=effective_max,
    )


def _bump_capability_level(
    capability_level: str,
    required_floor: str | None,
    *,
    seed_id: str,
    floor_label: str,
) -> str:
    """Raise a capability level to a required floor when it sits below it."""
    if not required_floor or required_floor not in _CAPABILITY_ORDER:
        return capability_level
    floor_idx = _CAPABILITY_ORDER.index(required_floor)
    current_idx = (
        _CAPABILITY_ORDER.index(capability_level)
        if capability_level in _CAPABILITY_ORDER
        else 1
    )
    if current_idx < floor_idx:
        logger.warning(
            "%s: seed %s requires '%s', actor had '%s' — bumped",
            floor_label,
            seed_id,
            required_floor,
            capability_level,
        )
        return required_floor
    return capability_level


def _compile_legacy_actor_profile(
    seed: ScenarioSeed,
    ctx: Mapping[str, Any],
    resp: Call0Response,
) -> ActorProfile:
    """Normalize the historical Call0Response into a canonical actor profile."""
    actor_type = _normalize_actor_type(resp.actor_type)
    capability_level = _normalize_capability_level(resp.capability_level)
    capability_level = _enforce_capability_floor(actor_type, capability_level)
    # Enforce computed capability-level minimum floor (estu constraint)
    capability_level = _bump_capability_level(
        capability_level,
        ctx.get("minimum_capability_level"),
        seed_id=seed.seed_id,
        floor_label="Capability-level floor (estu)",
    )
    # Enforce seed-level min_complexity constraint
    capability_level = _bump_capability_level(
        capability_level,
        seed.min_complexity,
        seed_id=seed.seed_id,
        floor_label="Seed min_complexity floor",
    )
    return ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=resp.beliefs,
        desires=resp.desires,
        intentions=resp.intentions,
        resources=resp.resources,
    )


def _semantic_draft_request_parts(
    ctx: Mapping[str, Any],
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
    *,
    compact_response_schema: bool,
) -> tuple[
    dict[str, str],
    dict[str, str],
    dict[str, tuple[str, str]],
    dict[str, str],
    type[BaseModel],
    str,
]:
    """Build the V3 handle inventories, response model, and prompt suffix."""
    actor_types, capability_levels, resources = _actor_draft_inventories(
        ctx, projection_context, profile
    )
    actor_choices = _actor_choice_inventory(actor_types, capability_levels)
    response_model = create_actor_draft_v3_model(
        actor_choice_handles=tuple(actor_choices),
        resource_handles=tuple(resources),
        compact=compact_response_schema,
    )
    draft_suffix = _actor_draft_prompt(actor_choices, resources)
    return (
        actor_types,
        capability_levels,
        actor_choices,
        resources,
        response_model,
        draft_suffix,
    )


def _attach_legacy_access_provenance(
    actor_profile: ActorProfile,
    resp: Call0Response,
    profile: CapabilityProfile,
    *,
    pinned_entry_point_id: str | None,
    pinned_entry_point: str | None,
    projection_context: dict[str, Any] | None,
) -> ActorProfile:
    """Attach typed access provenance to a legacy Call0 actor profile."""
    if not pinned_entry_point_id:
        return actor_profile
    ep_controllability = _lookup_entry_point_controllability(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )
    actor_profile.access = build_actor_access_provenance(
        entry_point_id=pinned_entry_point_id,
        ep_controllability=ep_controllability,
        actor_type=actor_profile.actor_type,
        resp=resp,
        profile=profile,
        projection_context=projection_context,
    )
    return actor_profile


def _call_actor_profile(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    preferred_actor_type: str | None = None,
    excluded_actor_types: list[str] | None = None,
    preferred_capability_level: str | None = None,
    attack_goal: dict[str, Any] | None = None,
    pinned_technique_ids: list[str] | None = None,
    forced_actor_type: str | None = None,
    pinned_entry_point: str | None = None,
    pinned_entry_point_id: str | None = None,
    access_feedback: str | None = None,
    completion_length_feedback: str | None = None,
    compact_response_schema: bool = False,
    max_completion_tokens: int | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[ActorProfile, LLMResult, str | None]:
    """Generate a threat actor profile for a scenario seed (Call 0).

    Delegates context building to :func:`build_call0_context`, then renders
    templates, calls the LLM, and parses the response.

    ``completion_length_feedback`` (the finalization-owned length-retry
    suffix) is appended verbatim to the end of the rendered user prompt,
    after every semantic section.

    Returns:
        Tuple of (ActorProfile, LLMResult, diversity_limitation).
    """
    ctx = build_call0_context(
        seed=seed,
        profile=profile,
        use_case=use_case,
        preferred_actor_type=preferred_actor_type,
        excluded_actor_types=excluded_actor_types,
        preferred_capability_level=preferred_capability_level,
        attack_goal=attack_goal,
        pinned_technique_ids=pinned_technique_ids,
        forced_actor_type=forced_actor_type,
        pinned_entry_point=pinned_entry_point,
        pinned_entry_point_id=pinned_entry_point_id,
        access_feedback=access_feedback,
        projection_context=projection_context,
    )

    semantic_draft_v2 = projection_context is not None
    system_prompt = render_prompt(
        "call0_system.j2",
        zones_active=profile.zones_active,
        tool_inventory=ctx["tool_inventory"],
        semantic_draft_v2=semantic_draft_v2,
    )
    user_prompt = render_prompt(
        "call0_user.j2", **ctx, semantic_draft_v2=semantic_draft_v2
    )
    actor_types: dict[str, str] = {}
    capability_levels: dict[str, str] = {}
    actor_choices: dict[str, tuple[str, str]] = {}
    resources: dict[str, str] = {}
    response_model: type[BaseModel] | None = None
    if semantic_draft_v2:
        (
            actor_types,
            capability_levels,
            actor_choices,
            resources,
            response_model,
            draft_suffix,
        ) = _semantic_draft_request_parts(
            ctx,
            projection_context,
            profile,
            compact_response_schema=compact_response_schema,
        )
        user_prompt += draft_suffix
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = _complete_actor_profile(
        client,
        system_prompt,
        user_prompt,
        compact_response_schema=compact_response_schema,
        response_format=response_model,
        max_completion_tokens=max_completion_tokens,
    )

    resp = result.content
    if isinstance(resp, (ActorDraftV2, ActorDraftV3)):
        return (
            _compile_projected_actor_draft(
                resp=resp,
                actor_types=actor_types,
                capability_levels=capability_levels,
                resources=resources,
                actor_choices=actor_choices,
                minimum_capability_level=ctx["minimum_capability_level"],
                projection_context=projection_context,
            ),
            result,
            ctx.get("diversity_limitation"),
        )

    # Scripted fixtures using the historical response remain supported while
    # live projected requests advertise and parse only ActorDraftV3.
    actor_profile = _compile_legacy_actor_profile(seed, ctx, resp)

    # Build typed access provenance from canonical EP identity (cmps.6)
    actor_profile = _attach_legacy_access_provenance(
        actor_profile,
        resp,
        profile,
        pinned_entry_point_id=pinned_entry_point_id,
        pinned_entry_point=pinned_entry_point,
        projection_context=projection_context,
    )

    return actor_profile, result, ctx.get("diversity_limitation")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-21T12:04:02Z","module_hash":"6f394168dc1d5cdedbab851be26db81a56d4a01c0d842974c69ba842904810a9","source_sha256":"f9cb699bc56b29697555d2d8604cd47b47a4d564ea5144a6bda94b63f419e4fc","functions":[{"id":"func/_normalize_actor_type","name":"_normalize_actor_type","line":112,"end_line":129,"hash":"b14a12241134138150c3a650d05ea0c25e6d6f174234ad165964d5672753684d"},{"id":"func/_normalize_capability_level","name":"_normalize_capability_level","line":132,"end_line":142,"hash":"a9c1580791267cf62ecc36250e99295564baf4b3ce757ae961cd748a69b2fa7e"},{"id":"func/_enforce_capability_floor","name":"_enforce_capability_floor","line":145,"end_line":167,"hash":"aab9a89c8d440c382d9bd5d3bedd8ba1888349f2850606a2b0a3b5775f24149b"},{"id":"func/_validate_actor_type","name":"_validate_actor_type","line":170,"end_line":201,"hash":"c95cc34d0eda29274412d741a9f8aa01a477baf6df5bab2b52d6c7a4f48a23c2"},{"id":"func/build_actor_access_provenance","name":"build_actor_access_provenance","line":217,"end_line":272,"hash":"02ca2d66c246ac8997b0811d3574988d4bafc9e76f6c240f1286ecfdec0d95dc"},{"id":"func/_canonical_checks","name":"_canonical_checks","line":275,"end_line":484,"hash":"d2b36eff3a1be48d8dc66cf0f61f69277fb93102a1fd6ca075144e915365847e"},{"id":"func/validate_actor_access_provenance","name":"validate_actor_access_provenance","line":487,"end_line":612,"hash":"c1a7a8e202aa760b400b0946a93a5d99808ff6fae33042d55d2a99790b5bfde8"},{"id":"func/_complete_actor_profile","name":"_complete_actor_profile","line":620,"end_line":634,"hash":"299c1231324c1a3eeed4ba30713c3e16467c61a7b362a0b179ce590cb212c6ce"},{"id":"func/_call_actor_profile","name":"_call_actor_profile","line":637,"end_line":754,"hash":"f9ba3ac1cef0e9c8020df5551ac781249ae3b04b52f6b6e81fc0bfce02cfffc6"}]}
# mutate4py-manifest-end
