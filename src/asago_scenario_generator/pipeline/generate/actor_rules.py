"""Pure actor-selection rules for Call 0 generation.

This module owns deterministic policy used to constrain actor profiles.  It
deliberately has no prompt, LLM, or orchestration dependencies so prompt
context construction and actor generation can depend on it without forming a
cycle.
"""

from __future__ import annotations

from asago_scenario_generator.data.atlas import TECHNIQUE_PROPERTIES
from asago_scenario_generator.pipeline.generate.constants import (
    _ACTOR_GOAL_INCOMPATIBLE,
    _ADVERSARIAL_ONLY_THREATS,
    _CAPABILITY_ORDER,
    ALL_ACTOR_TYPES,
    CHAIN_TECHNIQUE_PAIRS,
)


def _max_capability_level(a: str, b: str) -> str:
    """Return the higher of two capability levels."""
    idx_a = _CAPABILITY_ORDER.index(a) if a in _CAPABILITY_ORDER else 0
    idx_b = _CAPABILITY_ORDER.index(b) if b in _CAPABILITY_ORDER else 0
    return _CAPABILITY_ORDER[max(idx_a, idx_b)]


def compute_minimum_capability_level(
    atlas_technique_ids: list[str] | tuple[str, ...] | None,
    ep_controllability: str | None,
    threat_id: str | None,
) -> str:
    """Compute the minimum capability level floor for a scenario seed.

    Applies four rules and returns the highest triggered floor:

    R1 -- Supply chain / training technique: advanced
    R2 -- Multi-technique escalation (2+ techniques, unless chain pair): intermediate
    R3 -- System EP access floor: intermediate
    R4 -- Indirect EP + adversarial-only threat (except T2): intermediate

    Returns:
        The highest minimum capability level across all triggered rules.
        Defaults to "novice" if no rules fire.
    """
    floor = "novice"
    tech_ids = list(atlas_technique_ids) if atlas_technique_ids else []

    # R1 -- Supply chain / training technique
    for tid in tech_ids:
        props = TECHNIQUE_PROPERTIES.get(tid)
        if props and props.get("target_layer") in ("supply_chain", "training"):
            floor = _max_capability_level(floor, "advanced")
            break  # already at advanced, no need to check more

    # R2 -- Multi-technique escalation
    if len(tech_ids) >= 2:
        # Check if the pair is a chain pair (only applies to exactly 2 techniques)
        is_chain = False
        if len(tech_ids) == 2:
            pair = (tech_ids[0], tech_ids[1])
            pair_rev = (tech_ids[1], tech_ids[0])
            is_chain = (
                pair in CHAIN_TECHNIQUE_PAIRS or pair_rev in CHAIN_TECHNIQUE_PAIRS
            )
        if not is_chain:
            floor = _max_capability_level(floor, "intermediate")

    # R3 -- System EP access floor
    if ep_controllability == "system":
        floor = _max_capability_level(floor, "intermediate")

    # R4 -- Indirect EP + adversarial-only threat (except T2)
    if (
        ep_controllability == "indirect"
        and threat_id in _ADVERSARIAL_ONLY_THREATS
        and threat_id != "T2"
    ):
        floor = _max_capability_level(floor, "intermediate")

    return floor


def _ep_controllability_to_ingress_mode(ep_controllability: str | None) -> str | None:
    """Map effective entry-point controllability to an ingress mode.

    Returns ``"direct"``, ``"indirect"``, or ``None`` for system or unknown
    controllability.  System entry points are not eligible ingress.
    """
    if ep_controllability in ("direct", "indirect"):
        return ep_controllability
    return None


def compute_compatible_actor_types(
    atlas_technique_ids: list[str] | tuple[str, ...] | None,
    ep_controllability: str | None,
    threat_id: str | None,
    entry_point_name: str | None = None,
    goal_id: str | None = None,
) -> set[str]:
    """Compute structurally compatible actor types for a seed.

    Applies threat, technique, target-layer, and actor-goal constraints while
    preserving a non-empty fallback set.
    """
    # These parameters remain part of the stable helper contract.  Typed
    # provenance, rather than the display name or controllability hint,
    # determines indirect eligibility.

    compatible = set(ALL_ACTOR_TYPES)
    tech_ids = list(atlas_technique_ids) if atlas_technique_ids else []

    # R1 -- Adversarial-only threat exclusion
    if threat_id in _ADVERSARIAL_ONLY_THREATS:
        compatible.discard("negligent-insider")

    # R2 -- no blanket indirect actor allowlist.  Actor eligibility for
    # indirect ingress is determined by typed evidence validated post-hoc.

    # R3 -- Technique requires direct access
    for tid in tech_ids:
        props = TECHNIQUE_PROPERTIES.get(tid)
        if props and props.get("requires_direct_access"):
            compatible.discard("negligent-insider")
            compatible.discard("supply-chain-actor")
            break

    # R4 -- Supply chain target layer
    for tid in tech_ids:
        props = TECHNIQUE_PROPERTIES.get(tid)
        if props and props.get("target_layer") == "supply_chain":
            compatible &= {
                "supply-chain-actor",
                "nation-state",
                "malicious-insider",
                "automated-agent",
            }
            break

    # R5 -- Actor-goal consistency
    if goal_id and goal_id in _ACTOR_GOAL_INCOMPATIBLE:
        incompatible = _ACTOR_GOAL_INCOMPATIBLE[goal_id]
        pruned = compatible - incompatible
        # Safety: never empty the set — skip R5 if it would.
        if pruned:
            compatible = pruned

    return compatible
