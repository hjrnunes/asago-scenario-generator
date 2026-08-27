"""Deterministic candidate rule filtering implementations."""

from __future__ import annotations

import logging
from collections.abc import Callable

from asago_scenario_generator.data.atlas import (
    ATLAS_TECHNIQUE_NAMES,
    TECHNIQUE_PROPERTIES,
    THREAT_PREREQUISITES,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    classify_entry_point,
)
from asago_scenario_generator.pipeline.candidate_expansion import canonicalize_and_dedup
from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    CandidateTriple,
    RemovalDecision,
    RejectionRecord,
    StageRecord,
    compute_candidate_id,
)

logger = logging.getLogger("asago_scenario_generator.pipeline.candidates")

# ---------------------------------------------------------------------------
# Rule-based candidate pre-filter
# ---------------------------------------------------------------------------
#
# Deterministic rules that reject structurally impossible candidates
# BEFORE the LLM filter.  Each rule takes a technique ID, entry point
# name, entry point type, and capability profile; returns (reject,
# rationale).  Rules REJECT ONLY -- they never accept.  All non-rejected
# candidates pass to the LLM filter.
#
# The old DIRECT_ONLY_TECHNIQUES / apply_technique_entry_point_filter
# post-filter is absorbed here as _rule_direct_vs_indirect.
#
# Entry point controllability classification (classify_entry_point) and
# keyword constants are imported from asago_scenario_generator.models.capability_profile.


def is_indirect_entry_point(
    entry_point_name: str,
    direction: str,
    controllability: str | None = None,
) -> bool:
    """Return True if the entry point is an indirect channel.

    Convenience wrapper around :func:`classify_entry_point` for backward
    compatibility.
    """
    return (
        classify_entry_point(entry_point_name, direction, controllability) == "indirect"
    )


# Legacy constant preserved for backward compatibility in tests.
# The rule engine now uses TECHNIQUE_PROPERTIES instead.
DIRECT_ONLY_TECHNIQUES: frozenset[str] = frozenset(
    {
        tid
        for tid, props in TECHNIQUE_PROPERTIES.items()
        if props.get("requires_direct_access")
    }
)


def _get_technique_name(technique_id: str) -> str:
    """Look up human-readable name for a technique ID."""
    return ATLAS_TECHNIQUE_NAMES.get(technique_id, technique_id)


# --- Rule functions ---
#
# Each rule takes (technique_id, entry_point_name, ep_type, profile) and
# returns (reject: bool, rationale: str | None).  Rationale is a
# fixed-format template string when reject=True, None otherwise.


def _rule_supply_chain_mismatch(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0048/T0010 supply chain attacks are incompatible with runtime entry points."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("target_layer") != "supply_chain":
        return False, None
    if ep_type in ("direct", "indirect"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"supply chain attacks target the model development pipeline, "
            f"not runtime inputs."
        )
    return False, None


def _rule_entry_point_not_interactive(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """System-controlled entry points are not attacker-accessible."""
    if ep_type != "system":
        return False, None
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if "system" in props.get("incompatible_entry_types", set()):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"system-controlled entry points are not attacker-accessible."
        )
    return False, None


def _rule_wrong_zone_direction(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Output-direction entry points cannot serve as attack ingress."""
    if ep_type != "system":
        return False, None
    # Check if the entry point name suggests output-only semantics.
    name_lower = entry_point_name.lower()
    output_signals = ("output", "response", "reply", "outbound", "emit")
    if not any(sig in name_lower for sig in output_signals):
        return False, None
    return True, (
        f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
        f"is incompatible with entry point type {ep_type} -- "
        f"output-direction entry points cannot be attack ingress channels."
    )


def _rule_technique_incompatible(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique's incompatible_entry_types includes this entry point type."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    incompatible = props.get("incompatible_entry_types", set())
    if ep_type in incompatible:
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique cannot target this entry point type."
        )
    return False, None


def _rule_direct_vs_indirect(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0051.000 requires direct access; T0051.001 requires indirect."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("requires_direct_access") and ep_type == "indirect":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique requires direct attacker access to the prompt interface."
        )
    # T0051.001 and similar indirect-only techniques: reject on direct EPs.
    if technique_id == "AML.T0051.001" and ep_type == "direct":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"indirect prompt injection requires a non-user-facing data channel."
        )
    return False, None


def _rule_preparatory_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0043/T0044/T0016/T0021 are pre-attack prep, not entry-point-exploitable."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("is_preparatory"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"preparatory techniques are pre-attack steps that do not "
            f"directly exploit runtime entry points."
        )
    return False, None


# Layer mismatch table: (target_layer, incompatible ep_types, reason).
_LAYER_MISMATCH_REASONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "tool_schema",
        ("direct",),
        "tool schema injection targets tool metadata trust boundaries, "
        "not direct user chat interfaces.",
    ),
    (
        "training",
        ("direct", "indirect"),
        "training pipeline attacks target the model development process, "
        "not runtime inputs.",
    ),
    (
        "embedding",
        ("direct",),
        "embedding manipulation targets vector stores, not direct user input channels.",
    ),
)


def _layer_rejection(target_layer: str, ep_type: str) -> str | None:
    """The incompatibility reason for a layer/ep-type pair, if any."""
    for layer, incompatible_ep_types, reason in _LAYER_MISMATCH_REASONS:
        if target_layer == layer and ep_type in incompatible_ep_types:
            return reason
    return None


def _rule_technique_targets_wrong_layer(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique targets an infrastructure layer incompatible with the entry point."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    target_layer = props.get("target_layer")
    if target_layer is None:
        return False, None
    reason = _layer_rejection(target_layer, ep_type)
    if reason is None:
        return False, None
    return True, (
        f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
        f"is incompatible with entry point type {ep_type} -- {reason}"
    )


# Ordered list of all per-technique rules.  Evaluated top-to-bottom; first rejection wins.
_ALL_RULES = [
    _rule_supply_chain_mismatch,
    _rule_entry_point_not_interactive,
    _rule_wrong_zone_direction,
    _rule_technique_incompatible,
    _rule_direct_vs_indirect,
    _rule_preparatory_technique,
    _rule_technique_targets_wrong_layer,
]


# --- Threat-level prerequisite rules ---
#
# These check whether a candidate's OWASP threat (threat_id) has zone or
# capability prerequisites that the profile does not satisfy.  Unlike
# per-technique rules, these operate at the candidate level and reject
# the entire candidate regardless of technique.


def _rule_seed_profile_compatibility(
    seed_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject seeds that are structurally infeasible for the given profile.

    AP-T9-05 "false attribution via identity proxy" requires persistent
    memory for cross-user identity manipulation.  Without persistent
    session state, the attack pattern is infeasible.
    """
    if seed_id == "AP-T9-05" and not profile.has_persistent_memory:
        return True, (
            f"Rejected: seed {seed_id} (false attribution via identity proxy) "
            f"requires persistent memory for cross-user identity manipulation, "
            f"but profile has has_persistent_memory=False."
        )
    return False, None


def _rule_threat_requires_zone(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing zones required by the threat.

    Checks both ``required_zones`` (all must be present) and
    ``required_zones_any`` (at least one must be present).
    """
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    active = set(profile.zones_active)

    # AND semantics: all required_zones must be active
    required = prereqs.get("required_zones", [])
    missing = _missing_required_zones(required, active)
    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires zone(s) "
            f"{missing} but profile only has {sorted(active)}."
        )

    # OR semantics: at least one of required_zones_any must be active
    any_of = prereqs.get("required_zones_any", [])
    if _zone_any_unsatisfied(any_of, active):
        return True, (
            f"Rejected: threat {threat_id} requires at least one of "
            f"zone(s) {any_of} but profile only has {sorted(active)}."
        )

    return False, None


def _missing_required_zones(required: list[str], active: set[str]) -> list[str]:
    """Required zones that are not active, in declared order."""
    return [z for z in required if z not in active]


def _zone_any_unsatisfied(any_of: list[str], active: set[str]) -> bool:
    """True when OR-semantics zones exist but none is active."""
    return bool(any_of) and not active.intersection(any_of)


def _rule_threat_requires_capability(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing capabilities required by the threat."""
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    required_caps = prereqs.get("required_capabilities", [])
    if not required_caps:
        return False, None

    missing = _missing_required_caps(required_caps, profile)
    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires capability(ies) "
            f"{missing} but profile does not have them."
        )

    return False, None


_CAP_GETTERS: dict[str, str] = {
    "has_persistent_memory": "has_persistent_memory",
    "multi_agent": "multi_agent",
    "hitl": "hitl",
}


def _missing_required_caps(
    required_caps: list[str], profile: CapabilityProfile
) -> list[str]:
    """Required capabilities the profile lacks, in declared order."""
    missing = []
    for cap in required_caps:
        attr = _CAP_GETTERS.get(cap)
        if attr is None:
            continue
        if not getattr(profile, attr, False):
            missing.append(cap)
    return missing


RuleRunner = Callable[
    [str, str, str, CapabilityProfile], tuple[bool, str | None, str | None]
]


# --- Rule-based filter orchestration ---


def _run_rules_on_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None, str | None]:
    """Run all rules on a single (technique, entry_point) pair.

    Returns (True, rationale, rule_name) on first rejection,
    (False, None, None) if all pass.
    """
    for rule in _ALL_RULES:
        reject, rationale = rule(technique_id, entry_point_name, ep_type, profile)
        if reject:
            return True, rationale, rule.__name__
    return False, None, None


def apply_rule_based_filter(
    candidates: list[CandidateTriple],
    profile: CapabilityProfile,
    stage_records: list[StageRecord] | None = None,
    *,
    rule_runner: RuleRunner | None = None,
) -> tuple[list[CandidateTriple], list[CandidateTriple], list[RejectionRecord]]:
    """Run deterministic rules on candidates, rejecting structural impossibilities.

    For each candidate, every technique in its combo is checked against all
    rules.  If ALL techniques in a combo are rejected, the entire candidate
    is rejected.  If some but not all techniques are rejected, the combo is
    pruned to keep only compatible techniques (the candidate survives with
    the reduced combo).

    Args:
        candidates: Output of :func:`expand_candidates`.
        profile: Capability profile (provides entry-point directions).
        stage_records: Optional list to append a :class:`StageRecord`
            for the rule-pruning dedup stage.

    Returns:
        Tuple of (rule_passed, rule_rejected, rejection_verdicts).
        ``rule_passed`` candidates are deduplicated and proceed to the
        LLM filter.  ``rule_rejected`` candidates are dropped with
        rationales.  ``rejection_verdicts`` are RejectionRecord objects
        for provenance.
    """
    if not candidates:
        return [], [], []

    rule_passed: list[CandidateTriple] = []
    rule_rejected: list[CandidateTriple] = []
    rejection_verdicts: list[RejectionRecord] = []

    for candidate in candidates:
        rejected, records, passed = _rule_filter_one_candidate(
            candidate, profile, rule_runner
        )
        rule_rejected.extend(rejected)
        rejection_verdicts.extend(records)
        rule_passed.extend(passed)

    _log_rule_rejections(rule_rejected, rule_passed)

    # Canonicalize and deduplicate immediately after rule pruning —
    # pruning techniques may cause two formerly-distinct candidates to
    # converge to the same canonical identity.
    raw_passed_count = len(rule_passed)
    rule_passed = canonicalize_and_dedup(rule_passed, stage="rule_pruning")
    _rule_pruning_stage_record(stage_records, raw_passed_count, rule_passed)

    return rule_passed, rule_rejected, rejection_verdicts


def _rule_filter_one_candidate(
    candidate: CandidateTriple,
    profile: CapabilityProfile,
    rule_runner: RuleRunner | None = None,
) -> tuple[list[CandidateTriple], list[RejectionRecord], list[CandidateTriple]]:
    """Process one candidate into (rejected, rejection_records, passed)."""
    threat_reject, threat_rationale = _threat_rejection(candidate, profile)
    if threat_reject:
        return [candidate], [_threat_rejection_record(candidate, threat_rationale)], []

    ep_type = classify_entry_point(
        candidate.entry_point,
        candidate.direction or "bidirectional",
        candidate.controllability,
    )
    (
        compatible_ids,
        compatible_names,
        compatible_descs,
        combo_rationales,
        removed_tids,
        removed_rules,
        removed_reasons,
    ) = _technique_compatibilities(candidate, ep_type, profile, rule_runner)

    if not compatible_ids:
        # All techniques rejected -- reject the entire candidate.
        return (
            [candidate],
            [
                _full_rejection_record(
                    candidate,
                    combo_rationales,
                    removed_tids,
                    removed_rules,
                    removed_reasons,
                )
            ],
            [],
        )

    if len(compatible_ids) < len(candidate.atlas_technique_ids):
        # Partial pruning: some techniques removed from combo.
        candidate = _pruned_candidate(
            candidate,
            compatible_ids,
            compatible_names,
            compatible_descs,
            removed_tids,
            removed_rules,
            removed_reasons,
        )

    return [], [], [candidate]


def _threat_rejection_record(
    candidate: CandidateTriple, threat_rationale: str | None
) -> RejectionRecord:
    """A whole-candidate rejection from seed/threat prerequisites."""
    return RejectionRecord(
        candidate_id=candidate.candidate_id,
        entry_point=candidate.entry_point,
        atlas_technique_ids=candidate.atlas_technique_ids,
        rationale=threat_rationale or "Threat prerequisite not met.",
    )


def _log_rule_rejections(
    rule_rejected: list[CandidateTriple], rule_passed: list[CandidateTriple]
) -> None:
    """Log the rule-pruning outcome when any candidate was rejected."""
    if rule_rejected:
        logger.info(
            "Rule pre-filter: %d/%d candidates rejected, %d passed to LLM filter",
            len(rule_rejected),
            len(rule_rejected) + len(rule_passed),
            len(rule_passed),
        )


def _rule_pruning_stage_record(
    stage_records: list[StageRecord] | None,
    raw_passed_count: int,
    rule_passed: list[CandidateTriple],
) -> None:
    """Record the rule-pruning stage counts when a ledger is supplied."""
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="rule_pruning",
                input_count=raw_passed_count,
                output_count=len(rule_passed),
                collapsed_count=raw_passed_count - len(rule_passed),
            )
        )


# ---------------------------------------------------------------------------
# Post-filter: cap scenarios per attack pattern
# ---------------------------------------------------------------------------


def _threat_rejection(
    candidate: CandidateTriple,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Seed-level and threat-level prerequisite rejections."""
    threat_reject, threat_rationale = _rule_seed_profile_compatibility(
        candidate.seed_id,
        profile,
    )
    if not threat_reject:
        threat_reject, threat_rationale = _rule_threat_requires_zone(
            candidate.threat_id,
            profile,
        )
    if not threat_reject:
        threat_reject, threat_rationale = _rule_threat_requires_capability(
            candidate.threat_id,
            profile,
        )
    return threat_reject, threat_rationale


def _technique_compatibilities(
    candidate: CandidateTriple,
    ep_type: str,
    profile: CapabilityProfile,
    rule_runner: RuleRunner | None = None,
) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str], list[str]]:
    """Split one combo into compatible and removed techniques.

    Returns (compatible_ids, compatible_names, compatible_descs,
    combo_rationales, removed_tids, removed_rules, removed_reasons).
    """
    compatible_ids: list[str] = []
    compatible_names: list[str] = []
    compatible_descs: list[str] = []
    combo_rationales: list[str] = []
    removed_tids: list[str] = []
    removed_reasons: list[str] = []
    removed_rules: list[str] = []

    run_rule = rule_runner or _run_rules_on_technique

    for tid, tname, tdesc in zip(
        candidate.atlas_technique_ids,
        candidate.atlas_technique_names,
        candidate.atlas_technique_descriptions,
    ):
        reject, rationale, rule_name = run_rule(
            tid,
            candidate.entry_point,
            ep_type,
            profile,
        )
        if reject:
            combo_rationales.append(rationale)  # type: ignore[arg-type]
            removed_tids.append(tid)
            removed_reasons.append(rationale)  # type: ignore[arg-type]
            removed_rules.append(rule_name)  # type: ignore[arg-type]
        else:
            compatible_ids.append(tid)
            compatible_names.append(tname)
            compatible_descs.append(tdesc)

    return (
        compatible_ids,
        compatible_names,
        compatible_descs,
        combo_rationales,
        removed_tids,
        removed_rules,
        removed_reasons,
    )


def _removal_decisions_for(
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> tuple[RemovalDecision, ...]:
    """Per-removal decision records, one per removed technique."""
    return tuple(
        RemovalDecision(
            technique_id=tid,
            rule=rule_name or "unknown",
            reason=reason,
        )
        for tid, rule_name, reason in zip(removed_tids, removed_rules, removed_reasons)
    )


def _full_rejection_record(
    candidate: CandidateTriple,
    combo_rationales: list[str],
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> RejectionRecord:
    """A fully rejected combo, with per-technique removal decisions."""
    return RejectionRecord(
        candidate_id=candidate.candidate_id,
        entry_point=candidate.entry_point,
        atlas_technique_ids=candidate.atlas_technique_ids,
        rationale=combo_rationales[0] if combo_rationales else "Rule-rejected.",
        removal_decisions=_removal_decisions_for(
            removed_tids, removed_rules, removed_reasons
        ),
    )


def _pruned_candidate(
    candidate: CandidateTriple,
    compatible_ids: list[str],
    compatible_names: list[str],
    compatible_descs: list[str],
    removed_tids: list[str],
    removed_rules: list[str],
    removed_reasons: list[str],
) -> CandidateTriple:
    """Rebuild a partially pruned candidate with a new id and origin."""
    pruned = set(candidate.atlas_technique_ids) - set(compatible_ids)
    logger.info(
        "Rule pre-filter: pruned %s from combo for %s",
        pruned,
        candidate.entry_point,
    )
    new_candidate_id = compute_candidate_id(
        candidate.seed_id,
        candidate.entry_point_id,
        compatible_ids,
    )
    applied_rule = removed_rules[0] if removed_rules else None
    pruning_origin = CandidateOrigin(
        source_candidate_id=candidate.candidate_id,
        original_technique_ids=candidate.atlas_technique_ids,
        applied_rule=applied_rule,
        removed_technique_ids=tuple(removed_tids),
        removal_reasons=tuple(removed_reasons),
        removal_decisions=_removal_decisions_for(
            removed_tids, removed_rules, removed_reasons
        ),
        transform_stage="rule_pruning",
    )
    # Reconstruct the pruned candidate through model_validate so
    # canonical IDs are re-validated and nested collections are
    # not shared with the original.  Using model_validate instead
    # of model_copy(update=...) ensures the new candidate_id is
    # checked against the canonical recomputation.
    return CandidateTriple.model_validate(
        candidate.model_dump(mode="python")
        | {
            "atlas_technique_ids": tuple(compatible_ids),
            "atlas_technique_names": tuple(compatible_names),
            "atlas_technique_descriptions": tuple(compatible_descs),
            "candidate_id": new_candidate_id,
            "origins": candidate.origins + (pruning_origin,),
        }
    )
