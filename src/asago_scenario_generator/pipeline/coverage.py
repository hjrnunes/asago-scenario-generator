"""Post-generation coverage analysis.

Compares generated scenarios against the capability profile and threat surface
to flag coverage gaps:
  - Entry points with zero scenarios targeting them
  - Active zones with zero scenarios traversing them
  - In-scope threats that produced no scenarios

Also provides actor profile diversity analysis.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.coverage_planning import (
    CoverageSummary,
    CoverageUniverse,
    QualityGap,
    StageLedger,
)
from asago_scenario_generator.pipeline.generate.zones import active_narrative_zones

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coverage gap analysis (asago-scenario-generator-n63)
# ---------------------------------------------------------------------------


@dataclass
class EntryPointGap:
    """A structured entry-point coverage gap carrying canonical identity.

    Names are display labels only — canonical identity is carried by
    ``entry_point_id``.  This prevents display text from being used as a
    join key back to profile metadata.
    """

    entry_point_id: str
    name: str

    def to_dict(self) -> dict:
        return {"entry_point_id": self.entry_point_id, "name": self.name}


@dataclass
class GapAttributions:
    """Funnel-stage attribution for each coverage gap.

    Entry-point attributions are keyed by ``entry_point_id`` (canonical
    identity), not by display name.  Other attributions (zones, threats,
    attack patterns) remain keyed by their respective IDs.

    Each dict maps an uncovered item key to one of:
      - ``"no_seed"``: no seed was generated for this item
      - ``"no_candidate"``: seed existed but no candidate was expanded
      - ``"rejected"``: candidate existed but was rejected at filtering
      - ``"phantom_flagged"``: scenario was generated but dropped by phantom
        capability validation
      - ``"generation_failed"``: filtered seed existed but scenario generation failed
      - ``"out_of_scope"``: threat gated out before seed expansion
    """

    entry_points: dict[str, str] = field(default_factory=dict)
    zones: dict[str, str] = field(default_factory=dict)
    threats: dict[str, str] = field(default_factory=dict)
    attack_patterns: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_points": self.entry_points,
            "zones": self.zones,
            "threats": self.threats,
            "attack_patterns": self.attack_patterns,
        }


@dataclass
class CoverageGaps:
    """Structured result of coverage gap analysis."""

    uncovered_entry_points: list[EntryPointGap] = field(default_factory=list)
    uncovered_zones: list[str] = field(default_factory=list)
    uncovered_threats: list[str] = field(default_factory=list)
    uncovered_attack_patterns: list[str] = field(default_factory=list)
    gap_attributions: GapAttributions = field(default_factory=GapAttributions)

    @property
    def has_gaps(self) -> bool:
        return bool(
            self.uncovered_entry_points
            or self.uncovered_zones
            or self.uncovered_threats
            or self.uncovered_attack_patterns
        )

    def to_dict(self) -> dict:
        result: dict = {
            "uncovered_entry_points": [
                ep.to_dict() for ep in self.uncovered_entry_points
            ],
            "uncovered_zones": self.uncovered_zones,
            "uncovered_threats": self.uncovered_threats,
            "uncovered_attack_patterns": self.uncovered_attack_patterns,
        }
        # Only include attributions if there are any gaps.
        if self.has_gaps:
            result["gap_attributions"] = self.gap_attributions.to_dict()
        return result


def _normalize_entry_point(ep: str) -> str:
    """Normalize an entry point string for fuzzy comparison.

    LLM-generated ``narrative.entry_point`` values may differ from the
    canonical profile entry points in casing, whitespace, or trailing
    punctuation.  This helper collapses those differences so that coverage
    checks are resilient to minor variation.

    Steps:
      1. Lowercase.
      2. Strip leading/trailing whitespace.
      3. Collapse internal runs of whitespace to a single space.
      4. Remove trailing punctuation (period, comma, semicolon).
    """
    s = ep.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(".,;")
    return s


def _build_entry_point_name_lookup(
    profile: CapabilityProfile,
    active_zones: set[str],
) -> dict[str, set[str]]:
    """Build a normalized-name → set-of-entry_point_ids lookup from the profile.

    Using a set per name avoids collapsing same-name entry points with
    different canonical identities (e.g. different direction or
    controllability).  Only attacker-accessible EPs are in the coverage
    universe, so the fallback map excludes output-only, system-controlled,
    and inactive-zone entries (cmps.9 third review correction 2).
    """
    ep_name_to_ids: dict[str, set[str]] = {}
    for ep in profile.entry_points:
        if not is_attacker_accessible_ingress(ep, active_zones):
            continue
        key = _normalize_entry_point(ep.name)
        ep_name_to_ids.setdefault(key, set()).add(ep.entry_point_id)
    return ep_name_to_ids


def _record_scenario_usage(
    envelope: ScenarioEnvelope,
    ep_name_to_ids: dict[str, set[str]],
    used_entry_point_ids: set[str],
    traversed_zones: set[str],
    covered_threat_ids: set[str],
    covered_attack_pattern_ids: set[str],
) -> None:
    """Credit a scenario's entry point, zones, threats, and attack pattern."""
    cf = envelope.candidate_filter or {}
    ep_id = cf.get("entry_point_id")
    if ep_id:
        used_entry_point_ids.add(ep_id)
    else:
        # Fallback: resolve narrative entry point name against the
        # profile's canonical IDs.  This handles remediation scenarios
        # that don't carry candidate_filter provenance.  When a name
        # maps to exactly one canonical ID (unique match), credit it.
        # When a name maps to multiple canonical IDs (ambiguous), do
        # NOT credit any — the identity is unresolved.
        narrative_ep = envelope.narrative.entry_point
        matched_ids = ep_name_to_ids.get(_normalize_entry_point(narrative_ep))
        if matched_ids and len(matched_ids) == 1:
            used_entry_point_ids.update(matched_ids)
        # Ambiguous or unknown names must NOT inflate coverage.
    # Literal 'outside' narrative traversal is not internal traversal:
    # it never credits an active zone, so uncovered active zones are
    # reported accurately.
    traversed_zones.update(active_narrative_zones(envelope.narrative.zone_sequence))
    covered_threat_ids.update(envelope.faceting.taxonomy_chain.agentic_threat_ids)
    covered_attack_pattern_ids.add(envelope.faceting.taxonomy_chain.scenario_seed)


def _uncovered_attacker_entry_points(
    profile: CapabilityProfile,
    active_zones: set[str],
    used_entry_point_ids: set[str],
) -> list[EntryPointGap]:
    """Attacker-accessible entry points not referenced by any scenario."""
    uncovered_entry_points: list[EntryPointGap] = []
    for ep in profile.entry_points:
        if not is_attacker_accessible_ingress(ep, active_zones):
            continue
        if ep.entry_point_id not in used_entry_point_ids:
            uncovered_entry_points.append(
                EntryPointGap(entry_point_id=ep.entry_point_id, name=ep.name)
            )
    return uncovered_entry_points


def _in_scope_attack_ids(threat_surface: ThreatSurface) -> tuple[set[str], set[str]]:
    """All in-scope threat IDs and attack pattern IDs from the threat surface."""
    in_scope_threat_ids: set[str] = set()
    in_scope_attack_pattern_ids: set[str] = set()
    for entry in threat_surface.entries:
        in_scope_threat_ids.update(entry.agentic_threat_ids)
        in_scope_attack_pattern_ids.update(entry.attack_pattern_ids)
    return in_scope_threat_ids, in_scope_attack_pattern_ids


def _sorted_uncovered(in_scope_ids: set[str], covered_ids: set[str]) -> list[str]:
    """In-scope IDs with no coverage, sorted deterministically."""
    return sorted(i for i in in_scope_ids if i not in covered_ids)


def _log_coverage_gap_warnings(gaps: CoverageGaps) -> None:
    """Log a warning per uncovered category."""
    if gaps.uncovered_entry_points:
        logger.warning(
            "Coverage gap: %d entry point(s) with zero scenarios: %s",
            len(gaps.uncovered_entry_points),
            [ep.name for ep in gaps.uncovered_entry_points],
        )
    if gaps.uncovered_zones:
        logger.warning(
            "Coverage gap: %d active zone(s) with zero scenarios: %s",
            len(gaps.uncovered_zones),
            gaps.uncovered_zones,
        )
    if gaps.uncovered_threats:
        logger.warning(
            "Coverage gap: %d in-scope threat(s) with zero scenarios: %s",
            len(gaps.uncovered_threats),
            gaps.uncovered_threats,
        )
    if gaps.uncovered_attack_patterns:
        logger.warning(
            "Coverage gap: %d attack pattern(s) with zero scenarios: %s",
            len(gaps.uncovered_attack_patterns),
            gaps.uncovered_attack_patterns,
        )


def analyze_coverage_gaps(
    profile: CapabilityProfile,
    threat_surface: ThreatSurface,
    scenarios: list[ScenarioEnvelope],
) -> CoverageGaps:
    """Compare generated scenarios against the profile and threat surface.

    Identifies:
      1. Entry points from the profile that no scenario targets.
      2. Active zones from the profile that no scenario traverses.
      3. In-scope threats from the threat surface that produced no scenarios.

    Entry point matching uses normalized comparison (case-insensitive,
    whitespace-collapsed) so that minor LLM generation variations do not
    produce false coverage gaps.

    Args:
        profile: The capability profile from Stage 1.
        threat_surface: The threat surface from Stage 2.
        scenarios: The generated scenario envelopes from Stage 4.

    Returns:
        CoverageGaps with lists of uncovered entry points, zones, and threats.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    ep_name_to_ids = _build_entry_point_name_lookup(profile, active_zones)

    used_entry_point_ids: set[str] = set()
    traversed_zones: set[str] = set()
    covered_threat_ids: set[str] = set()
    covered_attack_pattern_ids: set[str] = set()
    for envelope in scenarios:
        _record_scenario_usage(
            envelope,
            ep_name_to_ids,
            used_entry_point_ids,
            traversed_zones,
            covered_threat_ids,
            covered_attack_pattern_ids,
        )

    uncovered_entry_points = _uncovered_attacker_entry_points(
        profile, active_zones, used_entry_point_ids
    )
    uncovered_zones = sorted(
        z for z in profile.zones_active if z not in traversed_zones
    )
    in_scope_threat_ids, in_scope_attack_pattern_ids = _in_scope_attack_ids(
        threat_surface
    )
    uncovered_threats = _sorted_uncovered(in_scope_threat_ids, covered_threat_ids)
    uncovered_attack_patterns = _sorted_uncovered(
        in_scope_attack_pattern_ids, covered_attack_pattern_ids
    )

    gaps = CoverageGaps(
        uncovered_entry_points=uncovered_entry_points,
        uncovered_zones=uncovered_zones,
        uncovered_threats=uncovered_threats,
        uncovered_attack_patterns=uncovered_attack_patterns,
    )
    _log_coverage_gap_warnings(gaps)
    return gaps


# ---------------------------------------------------------------------------
# Actor profile diversity analysis
# ---------------------------------------------------------------------------

# Threshold: flag if this fraction or more of scenarios share one actor type.
_MONOTONE_THRESHOLD = 0.8


@dataclass
class AttackerDiversityResult:
    """Result of actor profile diversity analysis."""

    model_counts: dict[str, int] = field(default_factory=dict)
    goal_counts: dict[str, int] = field(default_factory=dict)
    dominant_model: str | None = None
    dominant_fraction: float = 0.0
    is_flagged: bool = False

    def to_dict(self) -> dict:
        return {
            "model_counts": self.model_counts,
            "goal_counts": self.goal_counts,
            "dominant_model": self.dominant_model,
            "dominant_fraction": round(self.dominant_fraction, 3),
            "is_flagged": self.is_flagged,
        }


def _actor_type_of(envelope: ScenarioEnvelope) -> str:
    """Actor type from the envelope's actor profile, or ``"unknown"``."""
    return (
        envelope.actor_profile.actor_type
        if envelope.actor_profile is not None
        else "unknown"
    )


def _goal_category_of(envelope: ScenarioEnvelope) -> str:
    """Parent goal category from the actor profile, or ``"uncategorized"``."""
    profile = envelope.actor_profile
    if profile is not None and profile.goal_category_parent:
        return profile.goal_category_parent
    return "uncategorized"


def _count_actor_profiles(
    scenarios: list[ScenarioEnvelope],
) -> tuple[dict[str, int], dict[str, int]]:
    """Count actor types and goal categories across scenarios."""
    model_counts: dict[str, int] = {}
    goal_counts: dict[str, int] = {}
    for envelope in scenarios:
        actor_type = _actor_type_of(envelope)
        model_counts[actor_type] = model_counts.get(actor_type, 0) + 1
        goal_category = _goal_category_of(envelope)
        goal_counts[goal_category] = goal_counts.get(goal_category, 0) + 1
    return model_counts, goal_counts


def analyze_attacker_diversity(
    scenarios: list[ScenarioEnvelope],
) -> AttackerDiversityResult:
    """Analyze actor type diversity across generated scenarios.

    Reads each scenario's ``actor_profile.actor_type`` directly (set during
    Call 0) instead of scanning narrative text for keywords.  Envelopes
    without an actor profile are counted as ``"unknown"``.

    Flags when >80% of scenarios share the same actor type.

    Args:
        scenarios: The generated scenario envelopes.

    Returns:
        AttackerDiversityResult with counts, dominant type, and flag status.
    """
    if not scenarios:
        return AttackerDiversityResult()

    model_counts, goal_counts = _count_actor_profiles(scenarios)

    # Find the dominant actor type.
    dominant_model = max(model_counts, key=model_counts.get)  # type: ignore[arg-type]
    dominant_count = model_counts[dominant_model]
    dominant_fraction = dominant_count / len(scenarios)
    is_flagged = dominant_fraction > _MONOTONE_THRESHOLD

    if is_flagged:
        logger.warning(
            "Actor profile diversity: %.0f%% of scenarios use '%s' "
            "(threshold: %.0f%%). Consider varying threat actor types.",
            dominant_fraction * 100,
            dominant_model,
            _MONOTONE_THRESHOLD * 100,
        )

    return AttackerDiversityResult(
        model_counts=model_counts,
        goal_counts=goal_counts,
        dominant_model=dominant_model,
        dominant_fraction=dominant_fraction,
        is_flagged=is_flagged,
    )


# ---------------------------------------------------------------------------
# Combined output
# ---------------------------------------------------------------------------


def _coverage_plan_payload(coverage_plan: Any) -> dict:
    """Serialize the coverage plan via its model or plain dict contract."""
    if hasattr(coverage_plan, "model_dump"):
        return coverage_plan.model_dump(mode="json")
    return coverage_plan.to_dict()


def _finalization_payload(finalization_inventory: Any) -> dict:
    """Serialize the read-only finalization inventory."""
    return finalization_inventory.model_dump(mode="json")


def _stage_ledger_payload(stage_ledger: StageLedger | None) -> dict | None:
    """Serialize the stage ledger when it has recorded events."""
    if stage_ledger is not None and stage_ledger.events:
        return stage_ledger.to_dict()
    return None


def _attacker_diversity_payload(
    attacker_diversity: AttackerDiversityResult | None,
) -> dict | None:
    """Serialize the attacker-diversity result when present."""
    return attacker_diversity.to_dict() if attacker_diversity is not None else None


def _coverage_universe_payload(
    coverage_universe: CoverageUniverse | None,
) -> dict | None:
    """Serialize the coverage universe when present."""
    return coverage_universe.to_dict() if coverage_universe is not None else None


def _quality_gaps_payload(quality_gaps: list[QualityGap] | None) -> list[dict] | None:
    """Serialize quality gaps when any are present (empty lists are omitted)."""
    return [g.to_dict() for g in quality_gaps] if quality_gaps else None


def _coverage_summary_payload(coverage_summary: CoverageSummary | None) -> dict | None:
    """Serialize the coverage summary when present."""
    return coverage_summary.to_dict() if coverage_summary is not None else None


def _add_optional(report: dict, key: str, value: Any) -> None:
    """Add a report section when the value is present."""
    if value is not None:
        report[key] = value


def write_coverage_report(
    coverage_gaps: CoverageGaps,
    output_dir: Path,
    attacker_diversity: AttackerDiversityResult | None = None,
    *,
    coverage_universe: CoverageUniverse | None = None,
    quality_gaps: list[QualityGap] | None = None,
    coverage_plan: Any | None = None,
    coverage_summary: CoverageSummary | None = None,
    stage_ledger: StageLedger | None = None,
    finalization_inventory: Any | None = None,
) -> Path:
    """Write coverage analysis results to coverage-gaps.json.

    Args:
        coverage_gaps: Result from analyze_coverage_gaps.
        output_dir: Pipeline output directory.
        attacker_diversity: Optional result from analyze_attacker_diversity.
        coverage_universe: Optional serialized coverage universe from
            cmps.4 coverage-aware planning (feasible targets, typed
            exclusions, completeness, evidence refs).
        quality_gaps: Optional list of typed, stage-attributed quality
            gaps for uncovered feasible targets (cmps.4).
        coverage_plan: Optional versioned coverage plan with per-target
            ordered choices, primary selected/attempted state, and
            fallback_available (cmps.4 blocker 2).
        coverage_summary: Optional categorized coverage summary
            distinguishing covered, excluded, and gap categories (cmps.4
            blocker 3).
        stage_ledger: Optional stage ledger with actual per-target/candidate
            stage events (cmps.4 blocker 3).
        finalization_inventory: Optional read-only v3 lifecycle evidence.

    Returns:
        Path to the written coverage-gaps.json file.
    """
    report: dict = {
        "coverage_gaps": coverage_gaps.to_dict(),
    }
    _add_optional(
        report,
        "attacker_diversity",
        _attacker_diversity_payload(attacker_diversity),
    )
    _add_optional(
        report,
        "coverage_universe",
        _coverage_universe_payload(coverage_universe),
    )
    _add_optional(report, "quality_gaps", _quality_gaps_payload(quality_gaps))
    _add_optional(
        report,
        "coverage_plan",
        _coverage_plan_payload(coverage_plan) if coverage_plan is not None else None,
    )
    _add_optional(
        report,
        "coverage_summary",
        _coverage_summary_payload(coverage_summary),
    )
    _add_optional(report, "stage_ledger", _stage_ledger_payload(stage_ledger))
    _add_optional(
        report,
        "finalization",
        _finalization_payload(finalization_inventory)
        if finalization_inventory is not None
        else None,
    )

    path = output_dir / "coverage-gaps.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Coverage report written to %s", path)
    return path


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:33:42Z","module_hash":"7ed23191580b24680e4aa89f65933b810dc133bcdf3922e4afdde9592b6620c5","source_sha256":"20c763d61c40be37e9388def234d6c9ae38599a7ce537a68b392109929f132de","functions":[{"id":"func/EntryPointGap.to_dict","name":"to_dict","line":55,"end_line":56,"hash":"55fc4c9c6101c9e0c60c926ade0e17462acb6d45e791968556ab65c8ff077d97"},{"id":"func/GapAttributions.to_dict","name":"to_dict","line":82,"end_line":88,"hash":"d5ef467364648d28ce74c26553a4b367c9fe025b80fc7308231cf41f473ffbaf"},{"id":"func/CoverageGaps.has_gaps","name":"has_gaps","line":102,"end_line":108,"hash":"3f487c949b2602c0da8988da634baa91b67da103e98a466aca73b1d13c9bac13"},{"id":"func/CoverageGaps.to_dict","name":"to_dict","line":110,"end_line":122,"hash":"f12ef5897811a9780793b368bd92d31629be65075269309aa93ee0ad0bdda59d"},{"id":"func/_normalize_entry_point","name":"_normalize_entry_point","line":125,"end_line":142,"hash":"723c454157718bcad2d8370f998c95729b1123c483c151559b0e87310668361a"},{"id":"func/_build_entry_point_name_lookup","name":"_build_entry_point_name_lookup","line":145,"end_line":163,"hash":"7fe206b7fd4e4b4fa8e8e4e062430a8cd921984285aec15a00656737d220c4b8"},{"id":"func/_record_scenario_usage","name":"_record_scenario_usage","line":166,"end_line":196,"hash":"427e52166826c1c0cf1bcf4a97d0af8f5aa652ec4f0b0988f2a2bbec646ae21b"},{"id":"func/_uncovered_attacker_entry_points","name":"_uncovered_attacker_entry_points","line":199,"end_line":213,"hash":"2f6a867dcbbcd997461f7f6488cf926bb651ca9b7a73560b5659938a9f0a40b1"},{"id":"func/_in_scope_attack_ids","name":"_in_scope_attack_ids","line":216,"end_line":223,"hash":"0dcd81d6cff23457286c6e90a67ab74d668039b25890e219e272df999e4799c7"},{"id":"func/_sorted_uncovered","name":"_sorted_uncovered","line":226,"end_line":228,"hash":"3fafda33fef1d0550cc3c2d0da687073a861ff109e1dffb9d4121109e9b56df2"},{"id":"func/_log_coverage_gap_warnings","name":"_log_coverage_gap_warnings","line":231,"end_line":256,"hash":"bc50e847b04b54cef8ed91bfa63eec16e8e05193b12d859f24a04bc01952ed5a"},{"id":"func/analyze_coverage_gaps","name":"analyze_coverage_gaps","line":259,"end_line":321,"hash":"d98985d682b6de6661df9e9660f604992e6f94b806bf2f699a806d56663a6dad"},{"id":"func/AttackerDiversityResult.to_dict","name":"to_dict","line":342,"end_line":349,"hash":"161578991034b990172786bf6fe57e2be87e0c00715a35a9c7ebd7be17abd6de"},{"id":"func/_actor_type_of","name":"_actor_type_of","line":352,"end_line":358,"hash":"0b5b5acf0778108ac3ad05101db6c2d7bd0ba34fe42325f863a4daa362be5e10"},{"id":"func/_goal_category_of","name":"_goal_category_of","line":361,"end_line":366,"hash":"03d202f7568d86c624202b28645f43522e788c627537d94270f2d84e24a65909"},{"id":"func/_count_actor_profiles","name":"_count_actor_profiles","line":369,"end_line":380,"hash":"05ba4b95d6aea74eef1e0beccf4c29772f6582f43d5a97cb657d7b5606841726"},{"id":"func/analyze_attacker_diversity","name":"analyze_attacker_diversity","line":383,"end_line":426,"hash":"714373f857d8ac7d71fbc1f9d4ee1e5cbe41fc7fde8db1fd6cd74a2e55bb1064"},{"id":"func/_coverage_plan_payload","name":"_coverage_plan_payload","line":434,"end_line":438,"hash":"b541e041857eaceac9d69df3f4652054d6b0cb6df94a427aa69be2061893f8fe"},{"id":"func/_finalization_payload","name":"_finalization_payload","line":441,"end_line":443,"hash":"94067525aa8d74a0ec538f8a9644fd0593c01b8cd36a373af00ad6bc5d54e889"},{"id":"func/_stage_ledger_payload","name":"_stage_ledger_payload","line":446,"end_line":450,"hash":"4999b56b181c0d092dec29802f52f50c5742ab9775b626fb07b3737758a133af"},{"id":"func/_attacker_diversity_payload","name":"_attacker_diversity_payload","line":453,"end_line":457,"hash":"fa2649382c2278606edb080183f71a6592c18d268dbd4aa810faeb1fd96f3349"},{"id":"func/_coverage_universe_payload","name":"_coverage_universe_payload","line":460,"end_line":464,"hash":"4a220fcaa2cf535c8afb1ca58050e3e7544ab8068940719277743eff602ce037"},{"id":"func/_quality_gaps_payload","name":"_quality_gaps_payload","line":467,"end_line":469,"hash":"2f6e973a6aff63f19ce2542c56d078f5f1ce767358744f37a1dd572a1bad2f74"},{"id":"func/_coverage_summary_payload","name":"_coverage_summary_payload","line":472,"end_line":474,"hash":"22fc710ca5eb714f99684a78f89077864cb28517d7e4663f85f3d464cb971f61"},{"id":"func/_add_optional","name":"_add_optional","line":477,"end_line":480,"hash":"f4d33e4ee4519b5303e0abea0dd2b11ad613bd9777137b1bbd56183c1b5d92b7"},{"id":"func/write_coverage_report","name":"write_coverage_report","line":483,"end_line":555,"hash":"399812f798b2787fdca5896c33aac57a9ac1993f7c97ed216a39522cf55d3800"}]}
# mutate4py-manifest-end
