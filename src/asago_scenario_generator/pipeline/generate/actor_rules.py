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


def _has_target_layer(
    technique_ids: list[str],
    target_layers: tuple[str, ...],
) -> bool:
    """Return whether any technique targets one of the supplied layers."""
    return any(
        (props := TECHNIQUE_PROPERTIES.get(technique_id))
        and props.get("target_layer") in target_layers
        for technique_id in technique_ids
    )


def _has_non_chain_technique_escalation(technique_ids: list[str]) -> bool:
    """Return whether multiple techniques require escalation."""
    if len(technique_ids) < 2:
        return False
    if len(technique_ids) != 2:
        return True
    pair = (technique_ids[0], technique_ids[1])
    return pair not in CHAIN_TECHNIQUE_PAIRS and pair[::-1] not in CHAIN_TECHNIQUE_PAIRS


def _has_intermediate_access_floor(
    ep_controllability: str | None,
    threat_id: str | None,
) -> bool:
    """Return whether entry-point access requires intermediate capability."""
    return ep_controllability == "system" or (
        ep_controllability == "indirect"
        and threat_id in _ADVERSARIAL_ONLY_THREATS
        and threat_id != "T2"
    )


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
    tech_ids = list(atlas_technique_ids) if atlas_technique_ids else []
    floors = [
        "advanced"
        if _has_target_layer(tech_ids, ("supply_chain", "training"))
        else "novice",
        "intermediate" if _has_non_chain_technique_escalation(tech_ids) else "novice",
        "intermediate"
        if _has_intermediate_access_floor(ep_controllability, threat_id)
        else "novice",
    ]
    return max(floors, key=_CAPABILITY_ORDER.index)


def _ep_controllability_to_ingress_mode(ep_controllability: str | None) -> str | None:
    """Map effective entry-point controllability to an ingress mode.

    Returns ``"direct"``, ``"indirect"``, or ``None`` for system or unknown
    controllability.  System entry points are not eligible ingress.
    """
    if ep_controllability in ("direct", "indirect"):
        return ep_controllability
    return None


def _discard_direct_access_incompatible(
    compatible: set[str],
    technique_ids: list[str],
) -> set[str]:
    """Remove actor types that cannot use a direct-access technique."""
    for technique_id in technique_ids:
        props = TECHNIQUE_PROPERTIES.get(technique_id)
        if props and props.get("requires_direct_access"):
            return compatible - {"negligent-insider", "supply-chain-actor"}
    return compatible


def _apply_actor_goal_constraint(
    compatible: set[str],
    goal_id: str | None,
) -> set[str]:
    """Remove actor types incompatible with a selected goal, if possible."""
    if not goal_id or goal_id not in _ACTOR_GOAL_INCOMPATIBLE:
        return compatible
    incompatible = _ACTOR_GOAL_INCOMPATIBLE[goal_id]
    pruned = compatible - incompatible
    return pruned if pruned else compatible


def _apply_supply_chain_actor_constraint(
    compatible: set[str],
    technique_ids: list[str],
) -> set[str]:
    """Restrict actor types when a technique targets the supply chain."""
    if not _has_target_layer(technique_ids, ("supply_chain",)):
        return compatible
    return compatible & {
        "supply-chain-actor",
        "nation-state",
        "malicious-insider",
        "automated-agent",
    }


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
    compatible = _discard_direct_access_incompatible(compatible, tech_ids)

    # R4 -- Supply chain target layer
    compatible = _apply_supply_chain_actor_constraint(compatible, tech_ids)

    # R5 -- Actor-goal consistency
    return _apply_actor_goal_constraint(compatible, goal_id)
