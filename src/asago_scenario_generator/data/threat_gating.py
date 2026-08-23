"""Threat gating logic for asago-scenario-generator.

Determines which OWASP Agentic Threats are in scope for a given
capability profile, based on the profile's KC (Key Component) sub-codes
mapped to threats via data/taxonomies/mappings/kc-threat-mapping.yaml.

A threat is in scope if the profile has at least one KC sub-code that
maps to that threat.  HITL (T10) is cross-cutting — enabled when
profile.hitl is True.

Attack-pattern filtering evaluates ``prerequisite_capabilities`` defined
in each AP-* attack pattern to apply additional checks within gated threats
(e.g. kc_requires, shared writable memory, vector store).  Each
attack pattern carries a ``threat_id`` field linking it to an OWASP threat,
so patterns are grouped by threat and filtered per-threat against the
capability profile.
"""

from __future__ import annotations

import logging
from pathlib import Path
from pydantic import BaseModel, Field

from asago_scenario_generator.data.loaders import (
    build_threat_to_patterns_index,
    load_agentic_threats,
    load_attack_patterns,
    load_kc_threat_mapping,
)
from asago_scenario_generator.models import CapabilityProfile, MemoryScope, MemoryType

logger = logging.getLogger(__name__)

# Default path to OWASP Agentic Threats data
_DEFAULT_THREATS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class ThreatScopeEntry(BaseModel):
    """A threat that is in scope for the assessed system."""

    threat_id: str = Field(description="Threat ID (e.g. 'T2')")
    threat_name: str = Field(description="Human-readable threat name")
    attack_pattern_ids: list[str] = Field(
        default_factory=list,
        description="Attack pattern IDs applicable to this system (e.g. ['AP-T2-01', 'AP-T2-03'])",
    )
    gating_reason: str = Field(
        description="Why this threat is in scope (e.g. 'always in scope', 'has_persistent_memory is true')",
    )


class OutOfScopeEntry(BaseModel):
    """A group of threats that are out of scope, with the reason."""

    threat_ids: list[str] = Field(description="Threat IDs that are out of scope")
    reason: str = Field(description="Why these threats are out of scope")


class ThreatScope(BaseModel):
    """The complete threat scope determination for a capability profile."""

    in_scope: list[ThreatScopeEntry] = Field(default_factory=list)
    out_of_scope: list[OutOfScopeEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# KC-based threat gating
# ---------------------------------------------------------------------------

_ALL_THREAT_IDS = [f"T{i}" for i in range(1, 18)]


def _compute_kc_enabled_threats(
    profile: CapabilityProfile,
    kc_mapping: dict,
) -> dict[str, str]:
    """Return {threat_id: gating_reason} for all threats enabled by the profile's KC sub-codes."""
    kc_to_threats = kc_mapping["kc_to_threats"]
    enabled: dict[str, set[str]] = {}

    for kc in profile.kc_subcodes:
        for tid in kc_to_threats.get(kc, []):
            enabled.setdefault(tid, set()).add(kc)

    if profile.hitl:
        for tid in kc_mapping["hitl"]["threat_ids"]:
            enabled.setdefault(tid, set()).add("hitl")

    return {
        tid: f"enabled by KC sub-codes: {sorted(kcs)}" for tid, kcs in enabled.items()
    }


# ---------------------------------------------------------------------------
# Attack-pattern filtering helpers
# ---------------------------------------------------------------------------


def _has_shared_writable_memory(profile: CapabilityProfile) -> bool:
    """Check if the profile has shared memory that the agent can write to.

    Like ``_has_vector_store``, falls back to ``has_persistent_memory``
    when ``memory_mechanisms`` is ``None`` (Stage 1 data only) to avoid
    premature filtering.
    """
    if profile.memory_mechanisms is None:
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        return False
    return any(
        m.scope == MemoryScope.shared and m.writable_by_agent
        for m in profile.memory_mechanisms
    )


def _has_vector_store(profile: CapabilityProfile) -> bool:
    """Check if the profile includes a vector_store memory mechanism.

    When ``memory_mechanisms`` is populated (Stage 2 data), this performs
    an exact check for a ``vector_store`` entry.  When it is ``None``
    (Stage 1 data only, where the LLM prompt explicitly forbids
    populating Stage 2 fields), the function falls back to
    ``has_persistent_memory`` as a conservative proxy: if the system has
    persistent memory at all, a vector store is plausible and we should
    not silently filter out the attack pattern.  This avoids the premature-
    gating bug where ``memory_mechanisms`` was always ``None`` after
    Stage 1, causing ``_has_vector_store()`` to always return ``False``
    and silently dropping attack patterns like AP-T2-05.
    """
    if profile.memory_mechanisms is None:
        # Stage 1 only — no detailed memory data yet.
        # Fall back to the broad has_persistent_memory flag so we don't
        # prematurely filter attack patterns that require a vector store.
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        # Explicitly empty list (Stage 2 said "no memory mechanisms")
        return False
    return any(m.type == MemoryType.vector_store for m in profile.memory_mechanisms)


def _evaluate_prerequisite_capabilities(
    prereqs: dict,
    profile: CapabilityProfile,
) -> bool:
    """Evaluate a pattern's prerequisite_capabilities against a profile.

    Each field in prereqs is a gate; ALL must pass for the attack pattern
    to be included.  Unknown fields are silently ignored (forward-compat).

    Zone-based checks (min_zones, requires_tool_execution) were removed in
    Phase 3 — kc_requires is strictly more precise and subsumes them.
    Boolean prerequisite flags (requires_persistent_memory, requires_multi_agent,
    etc.) were replaced by KCX sub-codes in kc_requires during Phase 4.

    Returns:
        True if all prerequisites are satisfied, False otherwise.
    """
    # kc_requires: {any: [...], all: [...]}
    kc_req = prereqs.get("kc_requires")
    if kc_req is not None:
        profile_kcs = set(profile.kc_subcodes)
        any_kcs = kc_req.get("any")
        if any_kcs and not profile_kcs.intersection(any_kcs):
            return False
        all_kcs = kc_req.get("all")
        if all_kcs and not set(all_kcs).issubset(profile_kcs):
            return False

    return True


def _filter_attack_patterns(
    patterns: list[dict],
    profile: CapabilityProfile,
) -> list[str]:
    """Filter attack patterns by prerequisite_capabilities against a profile.

    For each pattern that defines ``prerequisite_capabilities``, evaluates
    those capabilities against the profile.  Patterns whose prerequisites
    are not met are excluded from the returned list.  Patterns without
    prerequisites are always included.

    Args:
        patterns: List of attack pattern dicts (each must have an ``id`` key).
        profile: The capability profile to evaluate against.

    Returns:
        List of surviving pattern IDs (e.g. ``['AP-T7-01', 'AP-T7-03']``).
    """
    surviving: list[str] = []

    for pattern in patterns:
        pid = pattern.get("id", "unknown")
        prereqs = pattern.get("prerequisite_capabilities")
        if prereqs is None:
            surviving.append(pid)
            continue

        if _evaluate_prerequisite_capabilities(prereqs, profile):
            surviving.append(pid)
            logger.info(
                "Gating PASSED %s: prerequisite_capabilities satisfied",
                pid,
            )
        else:
            logger.warning(
                "Gating FILTERED %s: prerequisite_capabilities not met",
                pid,
            )

    return surviving


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


def determine_threat_scope(
    profile: CapabilityProfile,
    threats_path: str | Path | None = None,
    kc_mapping_path: str | Path | None = None,
    attack_patterns_path: str | Path | None = None,
) -> ThreatScope:
    """Determine which threats are in scope for a given capability profile.

    Uses KC sub-codes from the profile mapped to threats via
    kc-threat-mapping.yaml. A threat is in scope if any of the profile's
    KC sub-codes maps to it. HITL (T10) is cross-cutting.

    Args:
        profile: The capability profile to evaluate.
        threats_path: Path to the agentic threats YAML. Defaults to the
            bundled data file.
        kc_mapping_path: Path to the KC sub-code -> threat mapping YAML.
            Defaults to the bundled kc-threat-mapping.yaml.
        attack_patterns_path: Path to a single attack-patterns YAML.
            Defaults to the bundled attack-pattern catalog.

    Returns:
        ThreatScope with in_scope and out_of_scope entries.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)

    # Load KC→T mapping
    kc_mapping = load_kc_threat_mapping(kc_mapping_path)
    enabled = _compute_kc_enabled_threats(profile, kc_mapping)

    # Load attack patterns and group by threat_id for data-driven gating
    patterns = load_attack_patterns(attack_patterns_path)
    threat_to_patterns = build_threat_to_patterns_index(patterns)
    logger.info(
        "Loaded %d attack patterns across %d threats for data-driven gating",
        len(patterns),
        len(threat_to_patterns),
    )

    in_scope: list[ThreatScopeEntry] = []
    out_of_scope_ids: list[str] = []

    for tid in _ALL_THREAT_IDS:
        if tid not in threats:
            continue

        threat = threats[tid]
        reason = enabled.get(tid)

        if reason is None:
            out_of_scope_ids.append(tid)
            continue

        pattern_ids = threat_to_patterns.get(tid, [])
        all_patterns = [patterns[pid] for pid in pattern_ids if pid in patterns]
        filtered_ids = _filter_attack_patterns(all_patterns, profile)
        dropped = set(pattern_ids) - set(filtered_ids)
        logger.info(
            "Threat %s (%s) IN SCOPE: %s — %d/%d attack patterns kept%s",
            tid,
            threat["name"],
            reason,
            len(filtered_ids),
            len(pattern_ids),
            f" (dropped: {sorted(dropped)})" if dropped else "",
        )
        in_scope.append(
            ThreatScopeEntry(
                threat_id=tid,
                threat_name=threat["name"],
                attack_pattern_ids=filtered_ids,
                gating_reason=reason,
            )
        )

    out_of_scope: list[OutOfScopeEntry] = []
    if out_of_scope_ids:
        logger.warning(
            "Threats %s OUT OF SCOPE: no KC sub-codes in profile map to these threats",
            out_of_scope_ids,
        )
        out_of_scope.append(
            OutOfScopeEntry(
                threat_ids=out_of_scope_ids,
                reason="no KC sub-codes in profile map to these threats",
            )
        )

    return ThreatScope(in_scope=in_scope, out_of_scope=out_of_scope)
