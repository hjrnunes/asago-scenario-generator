"""Threat gating: the attack patterns in scope for a capability profile."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.data.loaders import (
    build_threat_to_patterns_index,
    load_agentic_threats,
    load_attack_patterns,
    load_kc_threat_mapping,
)
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models.capability_profile import CapabilityProfile

_THREATS_PATH = (
    DATA_ROOT
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


def in_scope_attack_pattern_ids(profile: CapabilityProfile) -> list[str]:
    """Return the pattern IDs of the threats a profile's KC sub-codes enable.

    A threat is in scope when one of the profile's KC sub-codes maps to it in
    kc-threat-mapping.yaml, or when the profile has HITL controls and the
    mapping lists the threat as HITL-enabled. Threats follow the order of the
    threats file and patterns follow the catalog order within a threat; the
    taxonomy inputs digest depends on both. A pattern whose ``kc_requires``
    gate the profile does not meet is dropped.
    """
    kc_mapping = load_kc_threat_mapping()
    enabled = {
        tid
        for kc in profile.kc_subcodes
        for tid in kc_mapping["kc_to_threats"].get(kc, [])
    }
    if profile.hitl:
        enabled.update(kc_mapping["hitl"]["threat_ids"])

    patterns = load_attack_patterns()
    by_threat = build_threat_to_patterns_index(patterns)
    profile_kcs = set(profile.kc_subcodes)
    return [
        pattern_id
        for threat_id in load_agentic_threats(_THREATS_PATH)
        if threat_id in enabled
        for pattern_id in by_threat.get(threat_id, [])
        if _kc_requires_met(patterns[pattern_id], profile_kcs)
    ]


def _kc_requires_met(pattern: dict[str, Any], profile_kcs: set[str]) -> bool:
    """Evaluate a pattern's ``kc_requires`` gate: ``{any: [...], all: [...]}``.

    Any-listed sub-codes need a single overlap; all-listed sub-codes must all
    be present. A pattern without the gate, or with an absent list, passes.
    """
    kc_req = (pattern.get("prerequisite_capabilities") or {}).get("kc_requires")
    if kc_req is None:
        return True
    any_kcs = kc_req.get("any")
    if any_kcs and not profile_kcs.intersection(any_kcs):
        return False
    all_kcs = kc_req.get("all")
    return not all_kcs or set(all_kcs).issubset(profile_kcs)
