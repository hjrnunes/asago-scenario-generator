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

from asago_scenario_generator.data.loaders import (
    build_threat_to_patterns_index,
    load_agentic_threats,
    load_attack_patterns,
    load_kc_threat_mapping,
)
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models import CapabilityProfile
from asago_scenario_generator.models.threat_scope import (
    OutOfScopeEntry,
    ThreatScope,
    ThreatScopeEntry,
)

logger = logging.getLogger(__name__)

# Default path to OWASP Agentic Threats data
_DEFAULT_THREATS_PATH = (
    DATA_ROOT
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


# ---------------------------------------------------------------------------
# KC-based threat gating
# ---------------------------------------------------------------------------


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


def _kc_requires_met(kc_req: dict, profile_kcs: set[str]) -> bool:
    """Evaluate a pattern's kc_requires gate: {any: [...], all: [...]}.

    Any-listed sub-codes need a single overlap; all-listed sub-codes must
    all be present.  Absent lists are not gates.
    """
    any_kcs = kc_req.get("any")
    if any_kcs and not profile_kcs.intersection(any_kcs):
        return False
    all_kcs = kc_req.get("all")
    if all_kcs and not set(all_kcs).issubset(profile_kcs):
        return False
    return True


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
    kc_req = prereqs.get("kc_requires")
    if kc_req is None:
        return True
    return _kc_requires_met(kc_req, set(profile.kc_subcodes))


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
# Per-threat evaluation
# ---------------------------------------------------------------------------


def _evaluate_threats(
    threats: dict,
    enabled: dict[str, str],
    threat_to_patterns: dict[str, list[str]],
    patterns: dict[str, dict],
    profile: CapabilityProfile,
) -> tuple[list[ThreatScopeEntry], list[str]]:
    """Evaluate every threat ID loaded from the threats taxonomy against the profile.

    The threat inventory is the loaded data itself, so taxonomy growth
    (e.g. a new T18) is evaluated automatically.  Iteration follows the
    file's declaration order and stays deterministic.

    Returns the in-scope entries and the IDs skipped because no KC
    sub-code enabled them.
    """
    in_scope: list[ThreatScopeEntry] = []
    out_of_scope_ids: list[str] = []

    for tid, threat in threats.items():
        entry = _build_in_scope_entry(
            tid, threat, enabled, threat_to_patterns, patterns, profile
        )
        if entry is None:
            out_of_scope_ids.append(tid)
            continue
        in_scope.append(entry)

    return in_scope, out_of_scope_ids


def _build_in_scope_entry(
    tid: str,
    threat: dict,
    enabled: dict[str, str],
    threat_to_patterns: dict[str, list[str]],
    patterns: dict[str, dict],
    profile: CapabilityProfile,
) -> ThreatScopeEntry | None:
    """Build the in-scope entry for one threat, or None when not enabled."""
    reason = enabled.get(tid)
    if reason is None:
        return None

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
    return ThreatScopeEntry(
        threat_id=tid,
        threat_name=threat["name"],
        attack_pattern_ids=filtered_ids,
        gating_reason=reason,
    )


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

    in_scope, out_of_scope_ids = _evaluate_threats(
        threats, enabled, threat_to_patterns, patterns, profile
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
