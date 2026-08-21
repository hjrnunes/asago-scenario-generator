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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-21T15:12:15Z","module_hash":"92b823e6705f5f84033068463135f52b92db2db1d92fbac12cb513f8485fb3b6","source_sha256":"46fa53ad90095f43e1304095585d84bbef98b20f64e5e29a075cd4230f6fac4f","functions":[{"id":"func/_max_capability_level","name":"_max_capability_level","line":21,"end_line":25,"hash":"b3a7bb649c6ce56e166de08514249fe8954f957c8032beee3de983d026e8174a"},{"id":"func/_has_target_layer","name":"_has_target_layer","line":28,"end_line":37,"hash":"4f5f9ea2c00d23f5817c071eaa29eb9c340f0f4d26a8d53e663451f79cb27c34"},{"id":"func/_has_non_chain_technique_escalation","name":"_has_non_chain_technique_escalation","line":40,"end_line":47,"hash":"ca8bfd01cca9f3830a7a9b11a7c307a6638dfd7914d21635b7f74066b569f352"},{"id":"func/_has_intermediate_access_floor","name":"_has_intermediate_access_floor","line":50,"end_line":59,"hash":"8adbc229f0106876c61416196de6a1e8fa8fca1d02743c16e766dbe6b42e87ed"},{"id":"func/compute_minimum_capability_level","name":"compute_minimum_capability_level","line":62,"end_line":90,"hash":"5f2d8903db21deb811bfcc63bf52415875157519571390b3ee7b70aae52239d3"},{"id":"func/_ep_controllability_to_ingress_mode","name":"_ep_controllability_to_ingress_mode","line":93,"end_line":101,"hash":"fe2b2cafdae13b2f52ecf270a0a56066bb3f7c30dfb87bde0255b9270b7af078"},{"id":"func/_discard_direct_access_incompatible","name":"_discard_direct_access_incompatible","line":104,"end_line":113,"hash":"d7032cc9a5db6c6d868cd4ebb226d00558c741940ab5d460d6cea90aa63a2c39"},{"id":"func/_apply_actor_goal_constraint","name":"_apply_actor_goal_constraint","line":116,"end_line":125,"hash":"d7ac6ed8fce347085e513641827693e4acc713a50a387fe237d5eadf1b364443"},{"id":"func/_apply_supply_chain_actor_constraint","name":"_apply_supply_chain_actor_constraint","line":128,"end_line":140,"hash":"359ffc51054e4e6d7d800604197cbed22f34fbfdcd86caa1294e2d1d8774de63"},{"id":"func/compute_compatible_actor_types","name":"compute_compatible_actor_types","line":143,"end_line":176,"hash":"f0bceef6ee352d1c996c89e652099eb7df190c312e2e10ec2792e6eacff10a19"}]}
# mutate4py-manifest-end
