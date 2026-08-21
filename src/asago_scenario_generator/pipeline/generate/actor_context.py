"""Call 0 actor-profile prompt context construction."""

from __future__ import annotations

import logging
from typing import Any

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.generate.actor import (
    _CAPABILITY_ORDER,
    _INSIDER_ACTOR_TYPES,
    _ep_controllability_to_ingress_mode,
    compute_compatible_actor_types,
    compute_minimum_capability_level,
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
    _tech_ids_for_floor = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
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
    if preferred_capability_level and minimum_capability_level != "novice":
        pref_idx = (
            _CAPABILITY_ORDER.index(preferred_capability_level)
            if preferred_capability_level in _CAPABILITY_ORDER
            else 1
        )
        floor_idx = _CAPABILITY_ORDER.index(minimum_capability_level)
        if pref_idx < floor_idx:
            logger.debug(
                "Capability floor override: preferred '%s' < minimum '%s' "
                "for seed %s — bumping preferred",
                preferred_capability_level,
                minimum_capability_level,
                seed.seed_id,
            )
            preferred_capability_level = minimum_capability_level

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
    if preferred_actor_type and preferred_actor_type not in compatible_actor_types:
        # Pick next best from compatible set (not excluded)
        excluded_set = set(excluded_actor_types) if excluded_actor_types else set()
        fallback_candidates = compatible_actor_types - excluded_set
        if fallback_candidates:
            preferred_actor_type = min(fallback_candidates)
            logger.debug(
                "Actor type constraint override: preferred '%s' not compatible "
                "for seed %s — falling back to '%s'",
                preferred_actor_type,
                seed.seed_id,
                preferred_actor_type,
            )
        else:
            # All compatible types are excluded; pick any compatible type
            preferred_actor_type = min(compatible_actor_types)

    # Build actor type diversity guidance
    diversity_section = ""
    _diversity_limitation: str | None = None
    if forced_actor_type:
        # Hard constraint — override any preferred/excluded hints.
        # cmps.6: incompatible forced types must be replaced before prompt
        # rendering with a feasible actor; diversity must never force an
        # incompatible actor.  Record the limitation so callers know.
        if forced_actor_type not in compatible_actor_types:
            _diversity_limitation = forced_actor_type
            logger.warning(
                "Forced actor_type '%s' not in compatible set %s for seed %s "
                "— replacing with feasible fallback (cmps.6)",
                forced_actor_type,
                sorted(compatible_actor_types),
                seed.seed_id,
            )
            forced_actor_type = min(compatible_actor_types)
        diversity_section = (
            "\n## Actor Type Constraint\n"
            f"- You MUST use actor_type: {forced_actor_type}. "
            "This is a hard constraint, not a suggestion. "
            "Generate beliefs, desires, intentions, and resources that are "
            f"appropriate and realistic for a {forced_actor_type} actor.\n"
        )
    elif preferred_actor_type or excluded_actor_types or preferred_capability_level:
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
        diversity_section = "\n".join(diversity_lines) + "\n"

    # Build shared ATLAS technique context — pin to specific techniques if set
    tech_ids_for_context = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context = _build_technique_context_block(tech_ids_for_context)
    if pinned_technique_ids:
        technique_framing_0 = (
            "You MUST use these ATLAS technique(s) to inform the actor's intentions "
            "and resource selection — the actor should have plausible knowledge "
            "and tools for these techniques. This is a hard constraint.\n"
        )
    else:
        technique_framing_0 = (
            "Use these techniques to inform the actor's intentions and resource "
            "selection — the actor should have plausible knowledge and tools for "
            "these techniques.\n"
            if technique_context
            else ""
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
    access_provenance_section = ""
    if pinned_entry_point_id:
        ingress_mode = _ep_controllability_to_ingress_mode(
            pinned_entry_point_controllability
        )
        if ingress_mode == "indirect":
            # Build explicit lists of valid trust-boundary names and upstream
            # entry-point names so the LLM can choose a valid source→boundary→
            # ingress path using human-readable names (cmps.6, Phase 3).
            _boundaries_ctx = ""
            if profile.trust_boundaries:
                _boundary_lines = []
                for tb in profile.trust_boundaries:
                    _boundary_lines.append(
                        f"  - {tb.name} ({tb.from_zone}→{tb.to_zone})"
                    )
                _boundaries_ctx = (
                    "\nValid trust_boundary_id values (choose one that "
                    "connects the influence source zone to the pinned "
                    "entry point zone):\n" + "\n".join(_boundary_lines) + "\n"
                )

            _upstream_eps_ctx = ""
            _pinned_ep = profile.resolve_entry_point(pinned_entry_point_id)
            if _pinned_ep is not None:
                _upstream_eps = [
                    ep
                    for ep in profile.entry_points
                    if ep.entry_point_id != pinned_entry_point_id
                    and ep.direction != "output"
                    and ep.effective_controllability != "system"
                ]
                if _upstream_eps:
                    _up_lines = []
                    for ep in _upstream_eps:
                        _up_lines.append(
                            f"  - {ep.name} "
                            f"(direction={ep.direction}, "
                            f"controllability={ep.effective_controllability}, "
                            f"zone={ep.effective_ingress_zone})"
                        )
                    _upstream_eps_ctx = (
                        "\nValid influence_source entry-point names "
                        "(the upstream data source the actor influences):\n"
                        + "\n".join(_up_lines)
                        + "\n"
                    )

            access_provenance_section = (
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
                f"{_upstream_eps_ctx}"
                f"{_boundaries_ctx}"
            )
        elif ingress_mode == "direct":
            # Check if the actor type might be an insider
            _is_insider = (
                forced_actor_type in _INSIDER_ACTOR_TYPES
                if forced_actor_type
                else (
                    preferred_actor_type in _INSIDER_ACTOR_TYPES
                    if preferred_actor_type
                    else False
                )
            )
            if _is_insider:
                access_provenance_section = (
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
            else:
                access_provenance_section = (
                    "\n## Access Provenance Constraint\n"
                    "The pinned entry point is a **direct** ingress surface. "
                    "The actor interacts through the normal user interface.\n"
                    "- `access_class`: one of `public`, `authenticated`, "
                    "`privileged` — the actor's relationship to the system\n"
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
