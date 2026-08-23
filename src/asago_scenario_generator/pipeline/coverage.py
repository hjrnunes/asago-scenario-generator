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
    # Collect entry point IDs used across all scenario provenance.
    # Resolve canonical entry_point_id from candidate_filter provenance
    # when available; for scenarios without provenance (e.g. remediation),
    # resolve the narrative entry point name against the profile's
    # canonical IDs.
    used_entry_point_ids: set[str] = set()
    traversed_zones: set[str] = set()
    covered_threat_ids: set[str] = set()
    covered_attack_pattern_ids: set[str] = set()

    # Build a normalized-name → set-of-entry_point_ids lookup from the
    # profile so we can resolve fallback narrative display names to
    # canonical IDs.  Using a set per name avoids collapsing same-name
    # entry points with different canonical identities (e.g. different
    # direction or controllability).  Normalization matches the old
    # _normalize_entry_point behaviour (case, whitespace, punctuation).
    # Only attacker-accessible EPs are in the coverage universe, so the
    # fallback map excludes output-only, system-controlled, and
    # inactive-zone entries (cmps.9 third review correction 2).
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    ep_name_to_ids: dict[str, set[str]] = {}
    for ep in profile.entry_points:
        if not is_attacker_accessible_ingress(ep, active_zones):
            continue
        key = _normalize_entry_point(ep.name)
        ep_name_to_ids.setdefault(key, set()).add(ep.entry_point_id)

    for envelope in scenarios:
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

    # 1. Uncovered entry points — compare using canonical entry_point_id.
    # Only attacker-accessible entry points are in the coverage universe
    # (cmps.9 third review correction 2).
    uncovered_entry_points: list[EntryPointGap] = []
    for ep in profile.entry_points:
        if not is_attacker_accessible_ingress(ep, active_zones):
            continue
        if ep.entry_point_id not in used_entry_point_ids:
            uncovered_entry_points.append(
                EntryPointGap(entry_point_id=ep.entry_point_id, name=ep.name)
            )

    # 2. Uncovered active zones
    uncovered_zones = sorted(
        z for z in profile.zones_active if z not in traversed_zones
    )

    # 3. Uncovered in-scope threats
    in_scope_threat_ids: set[str] = set()
    in_scope_attack_pattern_ids: set[str] = set()
    for entry in threat_surface.entries:
        in_scope_threat_ids.update(entry.agentic_threat_ids)
        in_scope_attack_pattern_ids.update(entry.attack_pattern_ids)

    uncovered_threats = sorted(
        t for t in in_scope_threat_ids if t not in covered_threat_ids
    )

    # 4. Uncovered in-scope attack patterns
    uncovered_attack_patterns = sorted(
        ap for ap in in_scope_attack_pattern_ids if ap not in covered_attack_pattern_ids
    )

    gaps = CoverageGaps(
        uncovered_entry_points=uncovered_entry_points,
        uncovered_zones=uncovered_zones,
        uncovered_threats=uncovered_threats,
        uncovered_attack_patterns=uncovered_attack_patterns,
    )

    # Log warnings for any gaps found.
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

    model_counts: dict[str, int] = {}
    goal_counts: dict[str, int] = {}
    for envelope in scenarios:
        actor_type = (
            envelope.actor_profile.actor_type
            if envelope.actor_profile is not None
            else "unknown"
        )
        model_counts[actor_type] = model_counts.get(actor_type, 0) + 1

        goal_category = (
            envelope.actor_profile.goal_category_parent
            if envelope.actor_profile is not None
            and envelope.actor_profile.goal_category_parent
            else "uncategorized"
        )
        goal_counts[goal_category] = goal_counts.get(goal_category, 0) + 1

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
    if attacker_diversity is not None:
        report["attacker_diversity"] = attacker_diversity.to_dict()
    if coverage_universe is not None:
        report["coverage_universe"] = coverage_universe.to_dict()
    if quality_gaps:
        report["quality_gaps"] = [g.to_dict() for g in quality_gaps]
    if coverage_plan is not None:
        if hasattr(coverage_plan, "model_dump"):
            report["coverage_plan"] = coverage_plan.model_dump(mode="json")
        else:
            report["coverage_plan"] = coverage_plan.to_dict()
    if coverage_summary is not None:
        report["coverage_summary"] = coverage_summary.to_dict()
    if stage_ledger is not None and stage_ledger.events:
        report["stage_ledger"] = stage_ledger.to_dict()
    if finalization_inventory is not None:
        report["finalization"] = finalization_inventory.model_dump(mode="json")
    path = output_dir / "coverage-gaps.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Coverage report written to %s", path)
    return path
