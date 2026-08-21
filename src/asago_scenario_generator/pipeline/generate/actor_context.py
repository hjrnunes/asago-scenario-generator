"""Call 0 actor-profile prompt context construction."""

from __future__ import annotations

import logging
from typing import Any

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
)
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _ep_controllability_to_ingress_mode,
    compute_compatible_actor_types,
    compute_minimum_capability_level,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _CAPABILITY_ORDER,
    _INSIDER_ACTOR_TYPES,
)
from asago_scenario_generator.pipeline.generate.goals import (
    _build_attack_goal_context_block,
)
from asago_scenario_generator.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
    build_kc_definitions_block,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

logger = logging.getLogger(__name__)


def _technique_ids_for_seed(
    seed: ScenarioSeed,
    pinned_technique_ids: list[str] | None,
) -> list[str]:
    """Return the technique IDs that constrain this Call 0."""
    return pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids


def _apply_capability_preference_floor(
    preferred_capability_level: str | None,
    minimum_capability_level: str,
    seed_id: str,
) -> str | None:
    """Raise a preferred capability hint when the computed floor requires it."""
    if not preferred_capability_level or minimum_capability_level == "novice":
        return preferred_capability_level

    preferred_index = (
        _CAPABILITY_ORDER.index(preferred_capability_level)
        if preferred_capability_level in _CAPABILITY_ORDER
        else 1
    )
    floor_index = _CAPABILITY_ORDER.index(minimum_capability_level)
    if preferred_index >= floor_index:
        return preferred_capability_level

    logger.debug(
        "Capability floor override: preferred '%s' < minimum '%s' "
        "for seed %s — bumping preferred",
        preferred_capability_level,
        minimum_capability_level,
        seed_id,
    )
    return minimum_capability_level


def _resolve_preferred_actor_type(
    preferred_actor_type: str | None,
    compatible_actor_types: set[str],
    excluded_actor_types: list[str] | None,
    seed_id: str,
) -> str | None:
    """Keep a preferred actor type inside the computed compatibility set."""
    if not preferred_actor_type:
        return preferred_actor_type
    if preferred_actor_type in compatible_actor_types:
        return preferred_actor_type
    return _fallback_preferred_actor_type(
        preferred_actor_type,
        compatible_actor_types,
        excluded_actor_types,
        seed_id,
    )


def _fallback_preferred_actor_type(
    preferred_actor_type: str,
    compatible_actor_types: set[str],
    excluded_actor_types: list[str] | None,
    seed_id: str,
) -> str:
    """Choose a compatible fallback when a preferred actor type is invalid."""
    excluded_set = set(excluded_actor_types) if excluded_actor_types else set()
    fallback_candidates = compatible_actor_types - excluded_set
    replacement = min(fallback_candidates or compatible_actor_types)
    logger.debug(
        "Actor type constraint override: preferred '%s' not compatible "
        "for seed %s — falling back to '%s'",
        preferred_actor_type,
        seed_id,
        replacement,
    )
    return replacement


def _build_diversity_section(
    *,
    forced_actor_type: str | None,
    compatible_actor_types: set[str],
    preferred_actor_type: str | None,
    excluded_actor_types: list[str] | None,
    preferred_capability_level: str | None,
    seed_id: str,
) -> tuple[str | None, str, str | None]:
    """Build actor diversity guidance and resolve forced actor constraints."""
    diversity_limitation: str | None = None
    if forced_actor_type:
        forced_actor_type, diversity_limitation = _resolve_forced_actor_type(
            forced_actor_type,
            compatible_actor_types,
            seed_id,
        )
        return (
            forced_actor_type,
            _format_forced_actor_section(forced_actor_type),
            diversity_limitation,
        )

    if not (preferred_actor_type or excluded_actor_types or preferred_capability_level):
        return forced_actor_type, "", diversity_limitation

    return (
        forced_actor_type,
        _format_diversity_guidance(
            preferred_actor_type,
            excluded_actor_types,
            preferred_capability_level,
        ),
        diversity_limitation,
    )


def _resolve_forced_actor_type(
    forced_actor_type: str,
    compatible_actor_types: set[str],
    seed_id: str,
) -> tuple[str, str | None]:
    """Resolve an incompatible forced actor type to a feasible fallback."""
    if forced_actor_type in compatible_actor_types:
        return forced_actor_type, None

    logger.warning(
        "Forced actor_type '%s' not in compatible set %s for seed %s "
        "— replacing with feasible fallback (cmps.6)",
        forced_actor_type,
        sorted(compatible_actor_types),
        seed_id,
    )
    return min(compatible_actor_types), forced_actor_type


def _format_forced_actor_section(forced_actor_type: str) -> str:
    """Render the hard actor-type constraint section."""
    return (
        "\n## Actor Type Constraint\n"
        f"- You MUST use actor_type: {forced_actor_type}. "
        "This is a hard constraint, not a suggestion. "
        "Generate beliefs, desires, intentions, and resources that are "
        f"appropriate and realistic for a {forced_actor_type} actor.\n"
    )


def _format_diversity_guidance(
    preferred_actor_type: str | None,
    excluded_actor_types: list[str] | None,
    preferred_capability_level: str | None,
) -> str:
    """Render soft actor and capability guidance."""
    diversity_lines = ["\n## Actor Type Guidance"]
    if preferred_actor_type:
        diversity_lines.append(
            f"- Preferred actor type: {preferred_actor_type} "
            "(use this unless it would be unrealistic for the threat)"
        )
    if excluded_actor_types:
        diversity_lines.append(
            f"- Avoid these overused actor types: {excluded_actor_types}"
        )
    if preferred_capability_level:
        diversity_lines.append(
            f"- Preferred capability level: {preferred_capability_level} "
            "(use this unless it would be unrealistic for the threat)"
        )
    return "\n".join(diversity_lines) + "\n"


def _build_technique_guidance(
    technique_context: str,
    pinned_technique_ids: list[str] | None,
) -> str:
    """Build hard or advisory technique framing for the Call 0 prompt."""
    if pinned_technique_ids:
        return (
            "You MUST use these ATLAS technique(s) to inform the actor's intentions "
            "and resource selection — the actor should have plausible knowledge "
            "and tools for these techniques. This is a hard constraint.\n"
        )
    if technique_context:
        return (
            "Use these techniques to inform the actor's intentions and resource "
            "selection — the actor should have plausible knowledge and tools for "
            "these techniques.\n"
        )
    return ""


def _build_indirect_access_section(
    profile: CapabilityProfile,
    pinned_entry_point_id: str,
) -> str:
    """Build structured evidence guidance for an indirect ingress surface."""
    upstream_context = _format_upstream_context(profile, pinned_entry_point_id)
    boundaries_context = _format_boundary_context(profile)
    return (
        "\n## Access Provenance Constraint (MANDATORY)\n"
        "The pinned entry point is an **indirect** ingress surface — "
        "the actor influences an upstream data source rather than "
        "typing input directly. You MUST provide structured evidence:\n"
        "- `access_class`: one of `public`, `authenticated`, "
        "`privileged`, `supply_chain` — the actor's relationship to "
        "the system\n"
        "- `influence_source`: the name of the upstream entry point "
        "(data source or channel) the actor influences\n"
        "- `influence_mechanism`: how the actor exerts influence "
        "(e.g. 'document poisoning', 'supply-chain staging')\n"
        "- `trust_boundary_id`: the name of a TrustBoundary "
        "declared in the capability profile\n"
        f"{upstream_context}"
        f"{boundaries_context}"
    )


def _format_upstream_context(
    profile: CapabilityProfile,
    pinned_entry_point_id: str,
) -> str:
    """Render valid upstream entry points for indirect access guidance."""
    upstream_lines = [
        (
            f"  - {entry_point.name} "
            f"(direction={entry_point.direction}, "
            f"controllability={entry_point.effective_controllability}, "
            f"zone={entry_point.effective_ingress_zone})"
        )
        for entry_point in _eligible_upstream_entry_points(
            profile,
            pinned_entry_point_id,
        )
    ]
    if not upstream_lines:
        return ""
    return (
        "\nValid influence_source entry-point names "
        "(the upstream data source the actor influences):\n"
        + "\n".join(upstream_lines)
        + "\n"
    )


def _eligible_upstream_entry_points(
    profile: CapabilityProfile,
    pinned_entry_point_id: str,
) -> list[EntryPoint]:
    """Return non-output, non-system entry points other than the pinned one."""
    if profile.resolve_entry_point(pinned_entry_point_id) is None:
        return []
    return [
        entry_point
        for entry_point in profile.entry_points
        if _is_eligible_upstream_entry_point(entry_point, pinned_entry_point_id)
    ]


def _is_eligible_upstream_entry_point(
    entry_point: EntryPoint,
    pinned_entry_point_id: str,
) -> bool:
    """Check whether an entry point can provide indirect influence."""
    return (
        entry_point.entry_point_id != pinned_entry_point_id
        and entry_point.direction != "output"
        and entry_point.effective_controllability != "system"
    )


def _format_boundary_context(profile: CapabilityProfile) -> str:
    """Render valid trust boundaries for indirect access guidance."""
    boundary_lines = [
        f"  - {boundary.name} ({boundary.from_zone}→{boundary.to_zone})"
        for boundary in profile.trust_boundaries or []
    ]
    if not boundary_lines:
        return ""
    return (
        "\nValid trust_boundary_id values (choose one that "
        "connects the influence source zone to the pinned "
        "entry point zone):\n" + "\n".join(boundary_lines) + "\n"
    )


def _build_direct_access_section(is_insider: bool) -> str:
    """Build structured evidence guidance for a direct ingress surface."""
    if is_insider:
        return (
            "\n## Access Provenance Constraint (MANDATORY)\n"
            "The pinned entry point is a **direct** ingress surface "
            "and the actor is an insider. You MUST provide:\n"
            "- `access_class`: one of `public`, `authenticated`, "
            "`privileged` — the actor's relationship to the system\n"
            "- `material_insider_advantage`: a structured material "
            "advantage beyond public access that justifies why an "
            "insider uses this surface (e.g. 'knowledge of internal "
            "rate-limit bypass', 'access to pre-production config "
            "overrides affecting input validation')\n"
        )
    return (
        "\n## Access Provenance Constraint\n"
        "The pinned entry point is a **direct** ingress surface. "
        "The actor interacts through the normal user interface.\n"
        "- `access_class`: one of `public`, `authenticated`, "
        "`privileged` — the actor's relationship to the system\n"
    )


def _build_access_provenance_section(
    *,
    profile: CapabilityProfile,
    pinned_entry_point_id: str | None,
    pinned_entry_point_controllability: str | None,
    forced_actor_type: str | None,
    preferred_actor_type: str | None,
) -> str:
    """Build access provenance guidance for the pinned entry point."""
    if not pinned_entry_point_id:
        return ""

    ingress_mode = _ep_controllability_to_ingress_mode(
        pinned_entry_point_controllability
    )
    if ingress_mode == "indirect":
        return _build_indirect_access_section(profile, pinned_entry_point_id)
    if ingress_mode != "direct":
        return ""

    is_insider = (
        forced_actor_type in _INSIDER_ACTOR_TYPES
        if forced_actor_type
        else preferred_actor_type in _INSIDER_ACTOR_TYPES
        if preferred_actor_type
        else False
    )
    return _build_direct_access_section(is_insider)


def build_call0_context(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
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
    projection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 0 (Actor Profile).

    Pure data-preparation function that constructs all template variables
    needed by ``call0_system.j2`` and ``call0_user.j2``.  No LLM calls.

    Args:
        seed: The scenario seed providing threat context.
        profile: The system's capability profile.
        use_case: Free-text description of the system under assessment.
        preferred_actor_type: Suggested actor type for diversity (hint, not enforced).
        excluded_actor_types: Actor types to avoid (already overused in this batch).
        preferred_capability_level: Suggested capability level for diversity
            (hint, not enforced).
        attack_goal: Selected attack goal sub-goal dict from the taxonomy.
        pinned_technique_ids: Hard-constrained ATLAS technique IDs from the
            candidate filter.
        forced_actor_type: Hard-constrained actor type override.
        pinned_entry_point: Hard-constrained entry point from the candidate
            filter.

    Returns:
        Dict mapping template variable names to their values.  Keys
        include both system-prompt variables (``minimum_capability_level``,
        ``compatible_actor_types``) and user-prompt variables
        (``technique_context``, ``diversity_section``, etc.).
    """
    # Compute capability-level minimum floor (estu constraint)
    _tech_ids_for_floor = _technique_ids_for_seed(seed, pinned_technique_ids)
    # Look up EP controllability early so it's available for floor computation
    _ep_controllability_for_floor = _lookup_entry_point_controllability(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )
    minimum_capability_level = compute_minimum_capability_level(
        _tech_ids_for_floor,
        _ep_controllability_for_floor,
        seed.threat_id,
    )

    # Override preferred_capability_level if it falls below the computed floor
    preferred_capability_level = _apply_capability_preference_floor(
        preferred_capability_level,
        minimum_capability_level,
        seed.seed_id,
    )

    # Compute actor-type compatible set (ok0p constraint)
    _goal_id = attack_goal["id"] if attack_goal else None
    compatible_actor_types = compute_compatible_actor_types(
        _tech_ids_for_floor,
        _ep_controllability_for_floor,
        seed.threat_id,
        entry_point_name=pinned_entry_point,
        goal_id=_goal_id,
    )

    # Override preferred_actor_type if not in compatible set
    preferred_actor_type = _resolve_preferred_actor_type(
        preferred_actor_type,
        compatible_actor_types,
        excluded_actor_types,
        seed.seed_id,
    )

    # Build actor type diversity guidance
    forced_actor_type, diversity_section, _diversity_limitation = (
        _build_diversity_section(
            forced_actor_type=forced_actor_type,
            compatible_actor_types=compatible_actor_types,
            preferred_actor_type=preferred_actor_type,
            excluded_actor_types=excluded_actor_types,
            preferred_capability_level=preferred_capability_level,
            seed_id=seed.seed_id,
        )
    )

    # Build shared ATLAS technique context — pin to specific techniques if set
    tech_ids_for_context = _technique_ids_for_seed(seed, pinned_technique_ids)
    technique_context = _build_technique_context_block(tech_ids_for_context)
    technique_framing_0 = _build_technique_guidance(
        technique_context,
        pinned_technique_ids,
    )

    # Build attack goal context block
    goal_section = ""
    if attack_goal is not None:
        goal_section = _build_attack_goal_context_block(attack_goal)

    # Compute technique count for BDI parsimony (intention budget)
    pinned_technique_count = len(pinned_technique_ids) if pinned_technique_ids else 1

    # Look up entry point direction and controllability from the capability profile
    pinned_entry_point_direction = _lookup_entry_point_direction(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )
    pinned_entry_point_controllability = _lookup_entry_point_controllability(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )

    # Build KC/KCX definition block for the prompt
    kc_definitions = build_kc_definitions_block(profile.kc_subcodes)

    # Build focused ontology context block for this seed
    ontology_context = _build_ontology_context(
        entry_point_name=pinned_entry_point or "",
        entry_point_direction=pinned_entry_point_direction,
        zones=profile.zones_active,
        technique_ids=list(tech_ids_for_context) if tech_ids_for_context else [],
        entry_point_controllability=pinned_entry_point_controllability,
    )

    # Build access provenance section for the prompt (cmps.6)
    access_provenance_section = _build_access_provenance_section(
        profile=profile,
        pinned_entry_point_id=pinned_entry_point_id,
        pinned_entry_point_controllability=pinned_entry_point_controllability,
        forced_actor_type=forced_actor_type,
        preferred_actor_type=preferred_actor_type,
    )

    # Humanize projection context for the template (Phase 3)
    from asago_scenario_generator.pipeline.generate.names import (
        humanize_projection_context,
    )

    humanized_projection = (
        humanize_projection_context(projection_context, profile)
        if projection_context is not None
        else projection_context
    )

    return {
        # System prompt variables
        "minimum_capability_level": minimum_capability_level,
        "compatible_actor_types": sorted(compatible_actor_types),
        # User prompt variables
        "use_case": use_case,
        "seed": seed,
        "profile": profile,
        "technique_context": technique_context,
        "technique_framing_0": technique_framing_0,
        "goal_section": goal_section,
        "diversity_section": diversity_section,
        "diversity_limitation": _diversity_limitation,
        "access_provenance_section": access_provenance_section,
        "access_feedback": access_feedback or "",
        "pinned_entry_point": pinned_entry_point,
        "pinned_entry_point_direction": pinned_entry_point_direction,
        "pinned_entry_point_id": pinned_entry_point_id,
        "pinned_technique_count": pinned_technique_count,
        "kc_definitions": kc_definitions,
        "ontology_context": ontology_context,
        "tool_inventory": profile.tool_inventory or [],
        "projection_context": humanized_projection,
    }


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-21T15:12:17Z","module_hash":"f40b1526e1129a72e0d3ee0a58a470fa8b46615b619cb37e9a11588cea201a4c","source_sha256":"65a186f2d44f5a1335437031925e7882f51e787cef67625512a1dab0d79d9ce3","functions":[{"id":"func/_technique_ids_for_seed","name":"_technique_ids_for_seed","line":36,"end_line":41,"hash":"c0d92c84a7666ed545679f7f90dce8f6af4b505c1313ba54a1159d7db26ec3a5"},{"id":"func/_apply_capability_preference_floor","name":"_apply_capability_preference_floor","line":44,"end_line":69,"hash":"e6048d730338f709adb88a06fe5e6b5b67536f6d3311885c3686c506231475a6"},{"id":"func/_resolve_preferred_actor_type","name":"_resolve_preferred_actor_type","line":72,"end_line":88,"hash":"0e67c149a12603fcacc98e49116d8b17f841edec6c9b5db42ce39ef8180fb782"},{"id":"func/_fallback_preferred_actor_type","name":"_fallback_preferred_actor_type","line":91,"end_line":108,"hash":"0f70f3eaf8b704cb35aef3ea0d0e4c87e94a56c2131f9e420b80d9b6ac0d9545"},{"id":"func/_build_diversity_section","name":"_build_diversity_section","line":111,"end_line":145,"hash":"4ca744d991ba69c80cb0150ecc47763dbdf74c244dc664ac4c7de2f28078b01b"},{"id":"func/_resolve_forced_actor_type","name":"_resolve_forced_actor_type","line":148,"end_line":164,"hash":"3f4c5cd28baf02db3fa78dda0cf6bff539aef9bd60f10843c6d05bc03e740f18"},{"id":"func/_format_forced_actor_section","name":"_format_forced_actor_section","line":167,"end_line":175,"hash":"334288a199488d2361e42a6e6fc320511a1ba2a2937259b9c4d68a360ab59deb"},{"id":"func/_format_diversity_guidance","name":"_format_diversity_guidance","line":178,"end_line":199,"hash":"79b532b320899f9542ea5b202ae2493591d45850ac77be47ea70d29543004847"},{"id":"func/_build_technique_guidance","name":"_build_technique_guidance","line":202,"end_line":219,"hash":"a524f36febddf47beb332d6427c54844d6733742f6a7121d9221b4e35e99625a"},{"id":"func/_build_indirect_access_section","name":"_build_indirect_access_section","line":222,"end_line":245,"hash":"2cd4b2a2861e1b46e7aceca4856d4a86821f689c48754a1c16d646137fa73efa"},{"id":"func/_format_upstream_context","name":"_format_upstream_context","line":248,"end_line":272,"hash":"0ea6a3dec10fe56990b8b9701255a57c49c580bbf34e973d9406f2a07195a619"},{"id":"func/_eligible_upstream_entry_points","name":"_eligible_upstream_entry_points","line":275,"end_line":286,"hash":"34a1f2a1327026179831e5cd0b2a8caefe3beeeead7aeac599826f97c52b13b6"},{"id":"func/_is_eligible_upstream_entry_point","name":"_is_eligible_upstream_entry_point","line":289,"end_line":298,"hash":"fd81d1b77f771a997c6c73e297bbbb0d4e249cefdfb678cef3ac4fc0147d0b87"},{"id":"func/_format_boundary_context","name":"_format_boundary_context","line":301,"end_line":313,"hash":"f6a9a6ad26e195d97ca7dcac72171773a293e0a07e3f23fc68f21eabb6bb0187"},{"id":"func/_build_direct_access_section","name":"_build_direct_access_section","line":316,"end_line":337,"hash":"816e3cb8a515f0e657aa83221dac6907a6093a8e5ceee2f3bbbdc26eb332f36e"},{"id":"func/_build_access_provenance_section","name":"_build_access_provenance_section","line":340,"end_line":367,"hash":"a5f958ed44c5070f5d7217b41f97efbb4afdc5ebfc261c4abb8b878be5fcdffa"},{"id":"func/build_call0_context","name":"build_call0_context","line":370,"end_line":545,"hash":"629f1fe54def5cd1ecec0fdde33086ba71bad606412252411e298f3bcd4ac524"}]}
# mutate4py-manifest-end
