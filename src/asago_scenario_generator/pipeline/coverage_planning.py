"""Coverage-aware planning over authoritative candidate-v2 records.

Replaces the legacy post-validation raw-seed remediation generator with
coverage-aware selection that operates exclusively on fully qualified
ProjectedCandidate records via typed :class:`QualifiedCandidate` wrappers.

Key concepts
------------
* **Coverage universe** – canonical profile entry points with direction
  ``input`` or ``bidirectional`` and controllability ``direct`` or
  ``indirect``.  Output-only / system-controlled entries are excluded with
  typed reasons.  Completeness is derived from the profile, never from
  free-form input.
* **Qualified candidate** – a typed planned candidate carrying a complete
  :class:`ProjectedCandidate` plus accepted filter verdict/rationale, merged
  origins, rule-removal provenance, and an explicit deterministic rank with
  candidate-ID tie-break.
* **Fallback queue** – a deterministic ranked list of at most three
  :class:`QualifiedCandidate` choices per target.  The first choice is
  selected for generation; remaining choices are surfaced as
  ``fallback_available`` in the persisted coverage plan for downstream retry
  logic (cmps.5).
* **Stage ledger** – records actual stage events (rules, filter, projection,
  selection, generation, admission, quarantine) per target/candidate.  The
  furthest actual event determines gap attribution — never backward inference.
* **Quality gap** – a typed, stage-attributed reason emitted when no
  compatible candidate survives for a target.  Coverage is never fabricated.
* **Coverage plan** – a versioned, persisted artifact with per-target ordered
  choices, primary selected/attempted state, and ``fallback_available``
  excluding every selected/attempted candidate.

This module owns queue construction, selection, and surfacing the next
choice.  It does **not** implement cmps.5's retry / admission / quarantine
state machine.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.pipeline.candidates import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)
from asago_scenario_generator.pipeline.projection import ProjectedCandidate

logger = logging.getLogger(__name__)

# Maximum number of candidate choices per target in a fallback queue.
MAX_FALLBACK_CHOICES = 3

# Schema version for the persisted coverage plan.
COVERAGE_PLAN_SCHEMA_VERSION = "1"


class GenerationMode(str, Enum):
    """How qualified candidates are converted into finalization targets."""

    EXHAUSTIVE = "exhaustive"
    COVERAGE = "coverage"


# ---------------------------------------------------------------------------
# Coverage universe
# ---------------------------------------------------------------------------


class CoverageExclusionReason(str, Enum):
    """Typed reason for excluding an entry point from the coverage universe."""

    OUTPUT_ONLY = "output_only"
    SYSTEM_CONTROLLED = "system_controlled"
    INACTIVE_ZONE = "inactive_zone"
    NO_INGRESS_ZONE = "no_ingress_zone"


class CoverageCompleteness(str, Enum):
    """Whether the entry-point inventory is known to be complete.

    Derived from :attr:`CapabilityProfile.is_entry_point_inventory_complete`:
    ``confirmed_complete`` only when the operator has confirmed the inventory
    is exhaustive with evidence; ``not_applicable`` otherwise (inferred-partial
    inventory — completeness cannot be claimed).
    """

    NOT_APPLICABLE = "not_applicable"
    CONFIRMED_COMPLETE = "confirmed_complete"


@dataclass(frozen=True)
class CoverageTarget:
    """A feasible coverage target — an attacker-accessible ingress entry point.

    Carries the canonical ``entry_point_id``, display name, direction, and
    effective controllability.  Direction is always ``input`` or
    ``bidirectional``; controllability is always ``direct`` or ``indirect``.
    """

    entry_point_id: str
    name: str
    direction: str
    controllability: str


@dataclass(frozen=True)
class ExcludedTarget:
    """An entry point excluded from the coverage universe with a typed reason."""

    entry_point_id: str
    name: str
    direction: str
    controllability: str
    reason: CoverageExclusionReason


@dataclass
class CoverageUniverse:
    """The complete coverage universe: feasible targets plus typed exclusions.

    ``completeness`` is derived from the profile's
    ``is_entry_point_inventory_complete`` property — never from free-form
    input.  ``evidence_refs`` carries the operator-confirmed evidence sources
    when completeness is ``confirmed_complete``.
    """

    feasible_targets: list[CoverageTarget] = field(default_factory=list)
    excluded_targets: list[ExcludedTarget] = field(default_factory=list)
    completeness: CoverageCompleteness = CoverageCompleteness.NOT_APPLICABLE
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def feasible_target_ids(self) -> set[str]:
        """Set of entry_point_ids for all feasible targets."""
        return {t.entry_point_id for t in self.feasible_targets}

    def to_dict(self) -> dict:
        return {
            "feasible_targets": [
                {
                    "entry_point_id": t.entry_point_id,
                    "name": t.name,
                    "direction": t.direction,
                    "controllability": t.controllability,
                }
                for t in self.feasible_targets
            ],
            "excluded_targets": [
                {
                    "entry_point_id": e.entry_point_id,
                    "name": e.name,
                    "direction": e.direction,
                    "controllability": e.controllability,
                    "reason": e.reason.value,
                }
                for e in self.excluded_targets
            ],
            "completeness": self.completeness.value,
            "evidence_refs": list(self.evidence_refs),
        }


def _classify_exclusion(
    ep: EntryPoint,
    active_zones: set[str],
) -> CoverageExclusionReason | None:
    """Return the typed exclusion reason for a non-feasible entry point, or None if feasible."""
    if ep.direction == "output":
        return CoverageExclusionReason.OUTPUT_ONLY
    if ep.effective_controllability == "system":
        return CoverageExclusionReason.SYSTEM_CONTROLLED
    zone = ep.effective_ingress_zone
    if zone is None:
        return CoverageExclusionReason.NO_INGRESS_ZONE
    if zone not in active_zones:
        return CoverageExclusionReason.INACTIVE_ZONE
    return None


def build_coverage_universe(
    profile: CapabilityProfile,
) -> CoverageUniverse:
    """Build the coverage universe from the capability profile.

    Iterates every entry point in the profile.  Entry points with direction
    ``input`` or ``bidirectional`` and effective controllability ``direct``
    or ``indirect`` in an active zone are feasible targets.  All others are
    excluded with a typed reason.

    Completeness is derived from
    :attr:`CapabilityProfile.is_entry_point_inventory_complete` — the
    operator-confirmed property.  Free-form enum input is not accepted; an
    inferred profile cannot claim confirmed completeness.

    Args:
        profile: The capability profile from Stage 1.

    Returns:
        A :class:`CoverageUniverse` with feasible targets, typed
        exclusions, and profile-derived completeness.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    feasible: list[CoverageTarget] = []
    excluded: list[ExcludedTarget] = []

    for ep in profile.entry_points:
        if is_attacker_accessible_ingress(ep, active_zones):
            feasible.append(
                CoverageTarget(
                    entry_point_id=ep.entry_point_id,
                    name=ep.name,
                    direction=ep.direction,
                    controllability=ep.effective_controllability,
                )
            )
        else:
            reason = _classify_exclusion(ep, active_zones)
            if reason is None:
                reason = CoverageExclusionReason.NO_INGRESS_ZONE
            excluded.append(
                ExcludedTarget(
                    entry_point_id=ep.entry_point_id,
                    name=ep.name,
                    direction=ep.direction,
                    controllability=ep.effective_controllability,
                    reason=reason,
                )
            )

    if profile.is_entry_point_inventory_complete:
        completeness = CoverageCompleteness.CONFIRMED_COMPLETE
        evidence_refs = [e for e in profile.entry_point_evidence if e and e.strip()]
    else:
        completeness = CoverageCompleteness.NOT_APPLICABLE
        evidence_refs = []

    universe = CoverageUniverse(
        feasible_targets=feasible,
        excluded_targets=excluded,
        completeness=completeness,
        evidence_refs=evidence_refs,
    )
    logger.info(
        "Coverage universe: %d feasible target(s), %d excluded, completeness=%s",
        len(feasible),
        len(excluded),
        completeness.value,
    )
    return universe


# ---------------------------------------------------------------------------
# Qualified candidate — typed planned candidate over ProjectedCandidate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcceptedFilterRecord:
    """Typed accepted-filter evidence for one filter-stage candidate.

    When multiple accepted filter records converge on the same projected
    ``candidate_id``, all are preserved and merged canonically — no
    first-wins loss of provenance.
    """

    filter_candidate_id: str
    rationale: str
    origins: tuple[CandidateOrigin, ...] = ()
    rejection_rationales: tuple[RejectionRecord, ...] = ()
    pinned_entry_point: str = ""
    pinned_technique_ids: tuple[str, ...] = ()
    pinned_technique_names: tuple[str, ...] = ()
    seed: FilteredSeed | None = None

    def to_dict(self) -> dict:
        result = {
            "filter_candidate_id": self.filter_candidate_id,
            "rationale": self.rationale,
            "origins": [o.model_dump(mode="json") for o in self.origins],
            "rejection_rationales": [
                r.model_dump(mode="json") for r in self.rejection_rationales
            ],
            "pinned_entry_point": self.pinned_entry_point,
            "pinned_technique_ids": list(self.pinned_technique_ids),
            "pinned_technique_names": list(self.pinned_technique_names),
        }
        if self.seed is not None:
            result["seed"] = self.seed.model_dump(mode="json")
        return result

    @classmethod
    def from_dict(cls, data: dict) -> AcceptedFilterRecord:
        """Reconstruct an AcceptedFilterRecord from a serialized dict.

        The embedded ``seed`` (FilteredSeed) is model_validated so the
        complete generation seed survives round-trip deserialization.
        """
        seed_data = data.get("seed")
        seed = FilteredSeed.model_validate(seed_data) if seed_data else None
        return cls(
            filter_candidate_id=data["filter_candidate_id"],
            rationale=data["rationale"],
            origins=tuple(
                CandidateOrigin.model_validate(o) for o in data.get("origins", [])
            ),
            rejection_rationales=tuple(
                RejectionRecord.model_validate(r)
                for r in data.get("rejection_rationales", [])
            ),
            pinned_entry_point=data.get("pinned_entry_point", ""),
            pinned_technique_ids=tuple(data.get("pinned_technique_ids", [])),
            pinned_technique_names=tuple(data.get("pinned_technique_names", [])),
            seed=seed,
        )

    @classmethod
    def from_seed(cls, fseed: FilteredSeed) -> AcceptedFilterRecord:
        """Build from a FilteredSeed, preserving all provenance."""
        return cls(
            filter_candidate_id=fseed.candidate_id,
            rationale=fseed.accepted_rationale,
            origins=tuple(fseed.origins),
            rejection_rationales=tuple(fseed.rejection_rationales),
            pinned_entry_point=fseed.pinned_entry_point,
            pinned_technique_ids=tuple(fseed.pinned_technique_ids),
            pinned_technique_names=tuple(fseed.pinned_technique_names),
            seed=fseed,
        )


@dataclass(frozen=True)
class QualifiedCandidate:
    """A typed planned candidate carrying complete ProjectedCandidate plus
    a deterministic tuple of accepted filter records.

    Replaces the legacy ``(FilteredSeed, ProjectedCandidate)`` tuple.  The
    complete :class:`ProjectedCandidate` is the authoritative candidate-v2
    record.  When multiple accepted filter records converge on one projected
    candidate, all are preserved as a canonically sorted tuple — no
    first-wins loss of provenance.  An explicit deterministic rank with
    candidate-ID tie-break replaces the legacy pinned-technique-count ranking.
    """

    projected: ProjectedCandidate
    accepted_filters: tuple[AcceptedFilterRecord, ...]
    rank: int = 0

    @property
    def entry_point_id(self) -> str:
        """Canonical ingress entry point ID from the projected candidate."""
        return self.projected.canonical_ingress.entry_point_id

    @property
    def candidate_id(self) -> str:
        """Authoritative candidate-v2 ID from the projected candidate."""
        return self.projected.candidate_id

    @property
    def pattern_id(self) -> str:
        """Attack pattern ID from the projected candidate."""
        return self.projected.pattern_id

    @property
    def _sorted_filters(self) -> tuple[AcceptedFilterRecord, ...]:
        """Accepted filter records sorted by filter_candidate_id (canonical)."""
        return tuple(sorted(self.accepted_filters, key=lambda r: r.filter_candidate_id))

    @property
    def generation_seed(self) -> FilteredSeed:
        """Deterministically chosen FilteredSeed for ordinary generation.

        The seed with the lowest ``filter_candidate_id`` is chosen so that
        generation behaviour is deterministic and encounter-independent.
        """
        for record in self._sorted_filters:
            if record.seed is not None:
                return record.seed
        raise ValueError(
            "QualifiedCandidate has no seed-bearing accepted filter record"
        )

    @property
    def filtered_seed(self) -> FilteredSeed:
        """Backward-compatible alias for :attr:`generation_seed`."""
        return self.generation_seed

    @property
    def filter_candidate_id(self) -> str:
        """Filter-stage candidate ID (provenance only, not authoritative)."""
        if not self._sorted_filters:
            return ""
        return self._sorted_filters[0].filter_candidate_id

    @property
    def accepted_rationale(self) -> str:
        """First rationale (deterministically sorted) for backward compat."""
        if not self._sorted_filters:
            return ""
        return self._sorted_filters[0].rationale

    @property
    def merged_origins(self) -> list[CandidateOrigin]:
        """Merged origins from all accepted filter records, deduplicated."""
        seen: list[str] = []
        merged: list[CandidateOrigin] = []
        for record in self._sorted_filters:
            for origin in record.origins:
                key = origin.model_dump_json()
                if key not in seen:
                    seen.append(key)
                    merged.append(origin)
        return merged

    @property
    def origins(self) -> list[CandidateOrigin]:
        """Backward-compatible alias for :attr:`merged_origins`."""
        return self.merged_origins

    @property
    def merged_rejection_rationales(self) -> list[RejectionRecord]:
        """Merged rule-removal provenance from all accepted filter records."""
        seen: list[str] = []
        merged: list[RejectionRecord] = []
        for record in self._sorted_filters:
            for rr in record.rejection_rationales:
                key = rr.model_dump_json()
                if key not in seen:
                    seen.append(key)
                    merged.append(rr)
        return merged

    @property
    def rejection_rationales(self) -> list[RejectionRecord]:
        """Backward-compatible alias for :attr:`merged_rejection_rationales`."""
        return self.merged_rejection_rationales

    def to_plan_ref(self) -> dict:
        """Serialize to a content-addressed plan reference.

        Persists the complete validated ``ProjectedCandidate`` JSON (not
        a thin ref) plus the merged filter provenance tuple, so that a
        persisted fallback choice can be deserialized and reconstructed
        into an exact ``ProjectedCandidate`` usable by ordinary generation.
        """
        return {
            "candidate_id": self.candidate_id,
            "filter_candidate_id": self.filter_candidate_id,
            "pattern_id": self.pattern_id,
            "entry_point_id": self.entry_point_id,
            "rank": self.rank,
            "projected_candidate": self.projected.model_dump(mode="json"),
            "accepted_filters": [r.to_dict() for r in self._sorted_filters],
            "accepted_rationale": self.accepted_rationale,
            "origins": [o.model_dump(mode="json") for o in self.merged_origins],
            "rejection_rationales": [
                r.model_dump(mode="json") for r in self.merged_rejection_rationales
            ],
            "pinned_entry_point": (
                self._sorted_filters[0].pinned_entry_point
                if self._sorted_filters
                else ""
            ),
            "pinned_technique_ids": (
                list(self._sorted_filters[0].pinned_technique_ids)
                if self._sorted_filters
                else []
            ),
            "pinned_technique_names": (
                list(self._sorted_filters[0].pinned_technique_names)
                if self._sorted_filters
                else []
            ),
        }


def _qualified_sort_key(qc: QualifiedCandidate) -> tuple[str, str]:
    """Encounter-independent deterministic candidate-v2 sort key.

    Ranks by ``(pattern_id, candidate_id)`` — both are intrinsic
    content-addressed properties of the ProjectedCandidate, independent of
    filter-result arrival order.  ``candidate_id`` is the tie-break.
    """
    return (qc.pattern_id, qc.candidate_id)


def build_qualified_candidates(
    filtered_seeds: Sequence[FilteredSeed],
    projected_by_pattern: dict[str, list[ProjectedCandidate]],
) -> list[QualifiedCandidate]:
    """Fan out all valid projected matches and build typed qualified candidates.

    For each filtered seed, finds **all** projected candidates matching the
    same pattern and canonical ingress.  Multiple projected candidates with
    distinct concrete bindings for the same pattern+ingress are valid
    alternatives — they are fanned out, not treated as fatal ambiguity.

    Deduplication is by projected ``candidate_id`` — the authoritative
    candidate-v2 identity.  When multiple accepted filter records converge
    on the same projected ``candidate_id``, all filter provenance is
    **merged** into a deterministic sorted tuple — no first-wins loss.

    Ranking is **not** by pinned-technique subset/count and **not** by
    encounter order.  Deterministic ordering is by
    ``(pattern_id, candidate_id)`` — intrinsic candidate-v2 properties
    independent of filter-result arrival order.

    Args:
        filtered_seeds: Accepted candidates from the LLM filter stage.
        projected_by_pattern: Mapping from ``pattern_id`` to all projected
            candidates for that pattern.

    Returns:
        List of :class:`QualifiedCandidate` records, deduplicated by
        projected ``candidate_id``, with merged filter provenance.
    """
    # Accumulate accepted filter records per projected candidate_id.
    records_by_projected_id: dict[str, list[AcceptedFilterRecord]] = {}
    projected_by_id: dict[str, ProjectedCandidate] = {}

    for fseed in filtered_seeds:
        pc_list = projected_by_pattern.get(fseed.seed_id, [])
        matching_pcs = [
            pc
            for pc in pc_list
            if pc.canonical_ingress.entry_point_id == fseed.entry_point_id
        ]
        for pc in matching_pcs:
            projected_by_id.setdefault(pc.candidate_id, pc)
            records_by_projected_id.setdefault(pc.candidate_id, []).append(
                AcceptedFilterRecord.from_seed(fseed)
            )

    # Build QualifiedCandidate with merged, canonically sorted filter records.
    qualified = [
        QualifiedCandidate(
            projected=projected_by_id[cid],
            accepted_filters=tuple(
                sorted(records, key=lambda r: r.filter_candidate_id)
            ),
        )
        for cid, records in records_by_projected_id.items()
    ]
    # Deterministic encounter-independent ordering.
    qualified.sort(key=_qualified_sort_key)

    logger.info(
        "Qualified %d candidate(s) from %d filtered seed(s) (%d unique projected IDs).",
        len(qualified),
        len(filtered_seeds),
        len(records_by_projected_id),
    )
    return qualified


# ---------------------------------------------------------------------------
# Stage ledger — actual stage events per target/candidate
# ---------------------------------------------------------------------------


# Canonical stage names in pipeline order.
STAGE_RULES = "rules"
STAGE_FILTER = "filter"
STAGE_PROJECTION = "projection"
STAGE_SELECTION = "selection"
STAGE_GENERATION = "generation"
STAGE_ADMISSION = "admission"
STAGE_QUARANTINE = "quarantine"

_STAGE_ORDER = {
    STAGE_RULES: 0,
    STAGE_FILTER: 1,
    STAGE_PROJECTION: 2,
    STAGE_SELECTION: 3,
    STAGE_GENERATION: 4,
    STAGE_ADMISSION: 5,
    STAGE_QUARANTINE: 6,
}


@dataclass(frozen=True)
class StageEvent:
    """A recorded stage event for a target/candidate pair.

    Preserves the exact candidate/filter identity, pipeline stage, typed
    reason, and rationale/exception/limitation evidence.  The furthest
    actual event for a target determines its gap attribution.  The optional
    ``payload`` carries the complete typed model dump (e.g. a full
    ProjectionIssue or ProjectionLimitation) — not a reduced string.
    """

    entry_point_id: str
    candidate_id: str
    stage: str
    reason: str
    detail: str = ""
    payload: dict | None = None

    def to_dict(self) -> dict:
        result = {
            "entry_point_id": self.entry_point_id,
            "candidate_id": self.candidate_id,
            "stage": self.stage,
            "reason": self.reason,
            "detail": self.detail,
        }
        if self.payload is not None:
            result["payload"] = self.payload
        return result


@dataclass
class StageLedger:
    """Accumulates actual stage events per target/candidate.

    Events are recorded as they occur through the pipeline (rules, filter,
    projection, selection, generation, admission, quarantine).  The furthest
    actual event for a target determines its gap attribution — never
    backward set-membership inference.
    """

    events: list[StageEvent] = field(default_factory=list)

    def record(
        self,
        entry_point_id: str,
        candidate_id: str,
        stage: str,
        reason: str,
        detail: str = "",
        *,
        payload: dict | None = None,
    ) -> None:
        """Record a stage event."""
        self.events.append(
            StageEvent(
                entry_point_id=entry_point_id,
                candidate_id=candidate_id,
                stage=stage,
                reason=reason,
                detail=detail,
                payload=payload,
            )
        )

    def events_for(self, entry_point_id: str) -> list[StageEvent]:
        """All events for a target, in recording order."""
        return [e for e in self.events if e.entry_point_id == entry_point_id]

    def furthest_event(self, entry_point_id: str) -> StageEvent | None:
        """The furthest actual event for a target, by stage order.

        Returns the event with the highest stage order.  Ties break by
        recording order (last recorded wins).
        """
        target_events = self.events_for(entry_point_id)
        if not target_events:
            return None
        return max(
            target_events,
            key=lambda e: (_STAGE_ORDER.get(e.stage, -1), target_events.index(e)),
        )

    def candidate_ids_for_stage(self, entry_point_id: str, stage: str) -> list[str]:
        """Exact candidate IDs that reached a given stage for a target."""
        return [
            e.candidate_id
            for e in self.events
            if e.entry_point_id == entry_point_id and e.stage == stage
        ]

    def to_dict(self) -> dict:
        return {"events": [e.to_dict() for e in self.events]}


# ---------------------------------------------------------------------------
# Fallback queue construction
# ---------------------------------------------------------------------------


@dataclass
class TargetFallbackQueue:
    """Deterministic ranked fallback queue for a single coverage target.

    Bounded to at most :data:`MAX_FALLBACK_CHOICES` candidate choices.
    Each choice is a :class:`QualifiedCandidate` that preserves candidate
    ID, canonical ingress, projection, bindings, filter verdict/provenance,
    origins, and rule provenance.
    """

    entry_point_id: str
    choices: list[QualifiedCandidate] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return len(self.choices) == 0

    @property
    def first_choice(self) -> QualifiedCandidate | None:
        """The primary selection for this target, or None if no candidates."""
        return self.choices[0] if self.choices else None

    @property
    def remaining_choices(self) -> list[QualifiedCandidate]:
        """Fallback choices after the first (surfaced for cmps.5 retry)."""
        return self.choices[1:]

    def candidate_ids(self) -> list[str]:
        """All candidate IDs in this queue, in rank order."""
        return [qc.candidate_id for qc in self.choices]


def build_fallback_queues(
    qualified: list[QualifiedCandidate],
    universe: CoverageUniverse,
) -> dict[str, TargetFallbackQueue]:
    """Build deterministic ranked fallback queues per feasible coverage target.

    Each queue is bounded to at most :data:`MAX_FALLBACK_CHOICES` choices.
    Ranking is deterministic and **encounter-independent**: by
    ``(pattern_id, candidate_id)`` — intrinsic candidate-v2 properties, not
    filter-result arrival order.  ``candidate_id`` is the tie-break.
    Ranking is **not** by pinned-technique subset/count.

    Args:
        qualified: Qualified candidates from :func:`build_qualified_candidates`.
        universe: The coverage universe defining feasible targets.

    Returns:
        Mapping from ``entry_point_id`` to :class:`TargetFallbackQueue`.
        Targets with no candidates receive an empty queue.
    """
    by_target: dict[str, list[QualifiedCandidate]] = {}
    for qc in qualified:
        ep_id = qc.entry_point_id
        by_target.setdefault(ep_id, []).append(qc)

    queues: dict[str, TargetFallbackQueue] = {}
    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        candidates = by_target.get(ep_id, [])
        # Deterministic encounter-independent ranking by candidate-v2 policy.
        ranked = sorted(candidates, key=_qualified_sort_key)
        bounded = ranked[:MAX_FALLBACK_CHOICES]
        # Assign explicit deterministic ranks.
        choices = [replace(qc, rank=rank) for rank, qc in enumerate(bounded)]
        queues[ep_id] = TargetFallbackQueue(
            entry_point_id=ep_id,
            choices=choices,
        )

    return queues


# ---------------------------------------------------------------------------
# Coverage-aware selection
# ---------------------------------------------------------------------------


@dataclass
class SelectionResult:
    """Result of coverage-aware selection.

    ``selected`` is the final list of qualified candidates for generation.
    ``capped_count`` is the number of candidates removed by secondary
    per-pattern capping.  ``uncovered_target_ids`` lists feasible targets
    that received no candidate.  ``primary_candidate_ids`` maps target ID
    to the Phase-1 selected candidate ID.  ``attempted_candidate_ids`` is
    the complete set of candidates selected for generation (Phase 1 + 2).
    ``selection_limitation_target_ids`` lists targets where a per-pattern
    cap made coverage impossible (explicit limitation, not silent drop).
    """

    selected: list[QualifiedCandidate] = field(default_factory=list)
    capped_count: int = 0
    uncovered_target_ids: list[str] = field(default_factory=list)
    per_pattern_counts: dict[str, int] = field(default_factory=dict)
    primary_candidate_ids: dict[str, str] = field(default_factory=dict)
    attempted_candidate_ids: set[str] = field(default_factory=set)
    selection_limitation_target_ids: list[str] = field(default_factory=list)


def _solve_min_cost_assignment(
    target_ids: list[str],
    target_choices_map: dict[str, list[QualifiedCandidate]],
    max_per_pattern: int | None,
) -> dict[str, QualifiedCandidate]:
    """Solve global primary assignment via min-cost flow (successive shortest paths).

    Builds a bipartite flow network: source → targets → patterns → sink.
    Pattern→sink edges have convex costs so that the k-th unit (0-indexed)
    to a pattern costs ``k * CONCENTRATION_SCALE``, plus
    ``CAP_OVERFLOW_PENALTY * CONCENTRATION_SCALE`` if ``k >= max_per_pattern``.
    This minimizes concentration (spreads assignments across patterns) and
    cap overflow.

    Target→pattern edges have cost = candidate rank (0-indexed position in
    the sorted-by-candidate_id list of patterns for that target), providing
    canonical candidate-ID tie-breaking at lower priority than concentration.

    Complexity: O(N² · (N+M) · E) where N = targets, M = patterns,
    E = edges.  Polynomial and feasible for ~49 targets.

    Returns mapping from target_id to the assigned QualifiedCandidate.
    """
    from collections import deque

    N = len(target_ids)
    if N == 0:
        return {}

    # Collect unique patterns, sorted for determinism.
    all_patterns = sorted(
        {qc.pattern_id for choices in target_choices_map.values() for qc in choices}
    )
    M = len(all_patterns)
    pattern_idx = {p: i for i, p in enumerate(all_patterns)}

    # For each (target, pattern), pick the lowest candidate_id candidate.
    best_per_tp: dict[tuple[str, str], QualifiedCandidate] = {}
    for t_id in target_ids:
        for qc in target_choices_map[t_id]:
            key = (t_id, qc.pattern_id)
            if (
                key not in best_per_tp
                or qc.candidate_id < best_per_tp[key].candidate_id
            ):
                best_per_tp[key] = qc

    # Cost scaling: ensure lexicographic priority
    #   cap overflow > concentration > candidate tie-break
    CONCENTRATION_SCALE = 2 * N + 1  # > max total candidate tie-break (2*N)
    CAP_OVERFLOW_PENALTY = N * N + 1  # > max total concentration (N*(N-1)/2)

    # Build flow network.
    # Nodes: 0=source, 1..N=targets, N+1..N+M=patterns, N+M+1=sink
    source = 0
    sink = N + M + 1
    num_nodes = N + M + 2

    # Edge: [to, capacity, cost, rev_index]
    graph: list[list[list[int]]] = [[] for _ in range(num_nodes)]

    def add_edge(u: int, v: int, cap: int, cost: int) -> None:
        graph[u].append([v, cap, cost, len(graph[v])])
        graph[v].append([u, 0, -cost, len(graph[u]) - 1])

    # Source → targets (cap=1, cost=0).
    for i in range(N):
        add_edge(source, 1 + i, 1, 0)

    # Targets → patterns (cap=1, cost=rank for candidate-ID tie-break).
    for i, t_id in enumerate(target_ids):
        # Sort this target's patterns by the best candidate's candidate_id.
        target_patterns = sorted(
            {qc.pattern_id for qc in target_choices_map[t_id]},
            key=lambda p: best_per_tp[(t_id, p)].candidate_id,
        )
        for rank, p_id in enumerate(target_patterns):
            pi = pattern_idx[p_id]
            add_edge(1 + i, 1 + N + pi, 1, rank)

    # Patterns → sink with convex costs (cap=N per pattern, increasing cost).
    for pi in range(M):
        for k in range(N):
            base_cost = k * CONCENTRATION_SCALE
            if max_per_pattern is not None and k >= max_per_pattern:
                base_cost += CAP_OVERFLOW_PENALTY * CONCENTRATION_SCALE
            add_edge(1 + N + pi, sink, 1, base_cost)

    # Min-cost max-flow via successive shortest paths (SPFA / Bellman-Ford).
    total_flow = 0
    while total_flow < N:
        dist = [float("inf")] * num_nodes
        dist[source] = 0
        in_queue = [False] * num_nodes
        in_queue[source] = True
        queue: deque[int] = deque([source])
        parent_node = [-1] * num_nodes
        parent_edge_idx = [-1] * num_nodes

        while queue:
            u = queue.popleft()
            in_queue[u] = False
            for ei, edge in enumerate(graph[u]):
                v, cap, cost, _ = edge
                if cap > 0 and dist[u] + cost < dist[v]:
                    dist[v] = dist[u] + cost
                    parent_node[v] = u
                    parent_edge_idx[v] = ei
                    if not in_queue[v]:
                        queue.append(v)
                        in_queue[v] = True

        if dist[sink] == float("inf"):
            break  # No more augmenting paths.

        # Augment 1 unit of flow along the shortest path.
        v = sink
        while v != source:
            u = parent_node[v]
            ei = parent_edge_idx[v]
            graph[u][ei][1] -= 1  # reduce forward capacity
            rev_i = graph[u][ei][3]
            graph[v][rev_i][1] += 1  # increase reverse capacity
            v = u
        total_flow += 1

    # Extract assignment: check which target→pattern forward edges have flow.
    assignment: dict[str, QualifiedCandidate] = {}
    for i, t_id in enumerate(target_ids):
        for edge in graph[1 + i]:
            v = edge[0]
            # Pattern node range: [1+N, N+M]
            if 1 + N <= v <= N + M and edge[1] == 0:
                pi = v - 1 - N
                p_id = all_patterns[pi]
                assignment[t_id] = best_per_tp[(t_id, p_id)]
                break

    return assignment


def select_with_coverage_priority(
    qualified: list[QualifiedCandidate],
    fallback_queues: dict[str, TargetFallbackQueue],
    universe: CoverageUniverse,
    max_per_pattern: int | None = None,
) -> SelectionResult:
    """Select candidates with coverage-first priority via min-cost flow.

    **Hard objective:** Ensure exactly one unattempted primary candidate
    for every feasible coverage target that has candidates in its fallback
    queue.  A deterministic min-cost flow (successive shortest paths on a
    bipartite b-matching network) finds the globally optimal assignment in
    polynomial time — feasible for ~49 targets.

    Objective order (lexicographic):
    1. **Cover every feasible target** — maximize the number of targets
       with a primary assignment.
    2. **Minimize cap overflow** — the total number of assignments
       exceeding ``max_per_pattern`` (when set).
    3. **Maximize pattern diversity / minimize concentration** — convex
       per-pattern costs spread assignments across patterns.
    4. **Canonical candidate-ID tie-break** — lowest candidate_id per
       (target, pattern) pair, with deterministic SPFA node ordering.

    Cap-immune overflow is assigned only after maximizing feasible in-cap
    assignment.  Over-cap targets — including sole-choice overflows —
    receive an explicit ``selection_limitation``.  The first
    ``max_per_pattern`` targets (sorted by target ID) assigned to a pattern
    are in-cap; the rest are overflow.

    Only Phase-1 primaries are selected and attempted through the ordinary
    lifecycle.  All remaining choices stay as ``fallback_available`` in
    the coverage plan for cmps.5 retry logic.  Capping never discards a
    target's sole accepted candidate.

    Args:
        qualified: All qualified candidates.
        fallback_queues: Per-target fallback queues.
        universe: The coverage universe.
        max_per_pattern: Optional per-pattern cap.  Sole choices are
            cap-immune; impossible caps emit explicit limitations.

    Returns:
        :class:`SelectionResult` with the final selected list,
        primary/attempted candidate tracking, and selection limitations.
    """
    sorted_targets = sorted(universe.feasible_targets, key=lambda t: t.entry_point_id)

    # Collect the choice lists for targets that have candidates.
    target_choice_lists: list[tuple[str, list[QualifiedCandidate]]] = []
    for target in sorted_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        if queue is None or queue.is_empty:
            continue
        target_choice_lists.append((ep_id, list(queue.choices)))

    if not target_choice_lists:
        # No targets have candidates.
        uncovered = [t.entry_point_id for t in sorted_targets]
        return SelectionResult(
            selected=[],
            capped_count=0,
            uncovered_target_ids=uncovered,
            per_pattern_counts={},
            primary_candidate_ids={},
            attempted_candidate_ids=set(),
            selection_limitation_target_ids=[],
        )

    # Build the choices map for the min-cost flow solver.
    coverable_target_ids = [ep_id for ep_id, _ in target_choice_lists]
    target_choices_map: dict[str, list[QualifiedCandidate]] = {
        ep_id: choices for ep_id, choices in target_choice_lists
    }

    # Solve the global assignment via min-cost flow (polynomial, O(N²·(N+M)·E)).
    best_assignment = _solve_min_cost_assignment(
        coverable_target_ids,
        target_choices_map,
        max_per_pattern,
    )

    # Build the final selected list from the best assignment.
    # Deduplicate by candidate_id — one candidate may serve multiple targets.
    selected: list[QualifiedCandidate] = []
    selected_ids: set[str] = set()
    primary_ids: dict[str, str] = {}
    pattern_counts_final: dict[str, int] = {}
    limitations: list[str] = []

    # Process targets in sorted order for deterministic selected list.
    for ep_id, qc in sorted(best_assignment.items()):
        if qc.candidate_id not in selected_ids:
            rank = len(selected)
            selected.append(replace(qc, rank=rank))
            selected_ids.add(qc.candidate_id)
        primary_ids[ep_id] = qc.candidate_id
        pattern_counts_final[qc.pattern_id] = (
            pattern_counts_final.get(qc.pattern_id, 0) + 1
        )

    # Derive structured selection limitations for over-cap targets.
    # For each pattern, the first max_per_pattern targets (sorted by
    # target ID) are in-cap; the rest are overflow with explicit limitations.
    # This includes sole-choice overflows.
    if max_per_pattern is not None:
        # Group targets by their assigned pattern.
        targets_by_pattern: dict[str, list[str]] = {}
        for ep_id in sorted(best_assignment):
            qc = best_assignment[ep_id]
            targets_by_pattern.setdefault(qc.pattern_id, []).append(ep_id)

        for ep_ids in targets_by_pattern.values():
            count = len(ep_ids)
            if count > max_per_pattern:
                # First max_per_pattern targets (sorted) are in-cap;
                # the rest are overflow.
                overflow_ids = ep_ids[max_per_pattern:]
                limitations.extend(overflow_ids)

    uncovered = [
        t.entry_point_id for t in sorted_targets if t.entry_point_id not in primary_ids
    ]

    per_pattern: dict[str, int] = {}
    for qc in selected:
        per_pattern[qc.pattern_id] = per_pattern.get(qc.pattern_id, 0) + 1

    return SelectionResult(
        selected=selected,
        capped_count=0,
        uncovered_target_ids=uncovered,
        per_pattern_counts=per_pattern,
        primary_candidate_ids=primary_ids,
        attempted_candidate_ids=selected_ids,
        selection_limitation_target_ids=limitations,
    )


# ---------------------------------------------------------------------------
# Versioned coverage plan
# ---------------------------------------------------------------------------


@dataclass
class CoveragePlanEntry:
    """Per-target entry in the versioned coverage plan.

    ``ordered_choices`` is the full ranked list of qualified candidate
    references.  ``primary_candidate_id`` is the Phase-1 selected candidate
    (or None if uncovered).  ``primary_state`` tracks the lifecycle state
    of the primary candidate.  ``fallback_available`` lists choices that
    have not been selected or attempted — suitable for cmps.5 retry.
    """

    entry_point_id: str
    entry_point_name: str
    ordered_choices: list[dict]
    primary_candidate_id: str | None
    primary_state: str
    fallback_available: list[dict]
    target_id: str | None = None

    @property
    def effective_target_id(self) -> str:
        """Durable finalization identity, distinct from the canonical ingress."""
        return self.target_id or self.entry_point_id

    def to_dict(self) -> dict:
        return {
            "target_id": self.effective_target_id,
            "entry_point_id": self.entry_point_id,
            "entry_point_name": self.entry_point_name,
            "ordered_choices": self.ordered_choices,
            "primary_candidate_id": self.primary_candidate_id,
            "primary_state": self.primary_state,
            "fallback_available": self.fallback_available,
        }


@dataclass
class CoveragePlan:
    """Versioned coverage plan -- a manifest-inventoried artifact.

    Persists per-target ordered qualified choices, primary selected/attempted
    state, and ``fallback_available`` excluding every selected/attempted
    candidate.  Contains content-addressed provenance sufficient for cmps.5
    retry logic.  ``selection_limitation_target_ids`` records targets where
    a per-pattern cap could not be respected (coverage preserved, cap
    violated).
    """

    schema_version: str
    completeness: str
    evidence_refs: list[str]
    targets: list[CoveragePlanEntry]
    selection_limitation_target_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "completeness": self.completeness,
            "evidence_refs": list(self.evidence_refs),
            "targets": [t.to_dict() for t in self.targets],
            "selection_limitation_target_ids": list(
                self.selection_limitation_target_ids
            ),
        }


def build_coverage_plan(
    universe: CoverageUniverse,
    fallback_queues: dict[str, TargetFallbackQueue],
    selection_result: SelectionResult,
    generation_outcomes: dict[str, str] | None = None,
) -> CoveragePlan:
    """Build the versioned coverage plan from selection and generation outcomes.

    For each feasible target, records the ordered qualified choices, the
    primary selected/attempted candidate ID, its lifecycle state, and the
    fallback_available choices excluding every selected/attempted candidate.

    Args:
        universe: The coverage universe.
        fallback_queues: Per-target fallback queues.
        selection_result: The selection result with primary/attempted IDs.
        generation_outcomes: Optional mapping from candidate_id to lifecycle
            state (``"generated"``, ``"failed"``, ``"quarantined"``).  If
            absent, primary state is ``"selected"`` or ``"uncovered"``.

    Returns:
        A :class:`CoveragePlan` ready for persistence.
    """
    outcomes = generation_outcomes or {}
    attempted = selection_result.attempted_candidate_ids
    entries: list[CoveragePlanEntry] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        choices = queue.choices if queue else []
        ordered_refs = [qc.to_plan_ref() for qc in choices]

        primary_id = selection_result.primary_candidate_ids.get(ep_id)
        if primary_id is not None:
            state = outcomes.get(primary_id, "selected")
        else:
            state = "uncovered"

        # fallback_available: choices not selected or attempted.
        fallback = [
            qc.to_plan_ref() for qc in choices if qc.candidate_id not in attempted
        ]

        entries.append(
            CoveragePlanEntry(
                target_id=ep_id,
                entry_point_id=ep_id,
                entry_point_name=target.name,
                ordered_choices=ordered_refs,
                primary_candidate_id=primary_id,
                primary_state=state,
                fallback_available=fallback,
            )
        )

    return CoveragePlan(
        schema_version=COVERAGE_PLAN_SCHEMA_VERSION,
        completeness=universe.completeness.value,
        evidence_refs=list(universe.evidence_refs),
        targets=entries,
        selection_limitation_target_ids=list(
            selection_result.selection_limitation_target_ids
        ),
    )


@dataclass
class GenerationPlanningResult:
    """Complete planning result for either exhaustive or coverage generation.

    ``target_queues`` drives durable finalization.  ``coverage_queues`` remains
    keyed by canonical ingress and is used only for coverage-gap analysis.
    Keeping those concerns separate lets the finalization state machine remain
    target-scoped while exhaustive mode creates one target per candidate.
    """

    mode: GenerationMode
    selection: SelectionResult
    plan: CoveragePlan
    target_queues: dict[str, TargetFallbackQueue]
    coverage_queues: dict[str, TargetFallbackQueue]


def _exhaustive_target_id(candidate_id: str) -> str:
    """Return a stable, opaque finalization target ID for one candidate."""
    digest = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    return f"candidate-target:{digest}"


def _select_exhaustive_candidates(
    qualified: list[QualifiedCandidate],
    max_per_pattern: int | None,
) -> list[QualifiedCandidate]:
    """Select the exhaustive corpus, applying an explicit pattern cap if set.

    Within each pattern, candidates are selected round-robin across canonical
    ingresses before taking a second candidate from any ingress.  Ordering
    within an ingress is the existing intrinsic candidate-v2 sort order.
    """
    ranked = sorted(qualified, key=_qualified_sort_key)
    if max_per_pattern is None:
        return [replace(candidate, rank=rank) for rank, candidate in enumerate(ranked)]

    by_pattern: dict[str, dict[str, list[QualifiedCandidate]]] = {}
    for candidate in ranked:
        by_pattern.setdefault(candidate.pattern_id, {}).setdefault(
            candidate.entry_point_id, []
        ).append(candidate)

    selected: list[QualifiedCandidate] = []
    for pattern_id in sorted(by_pattern):
        by_ingress = by_pattern[pattern_id]
        ingress_ids = sorted(by_ingress)
        cursors = {entry_point_id: 0 for entry_point_id in ingress_ids}
        pattern_count = 0
        while pattern_count < max_per_pattern:
            progressed = False
            for entry_point_id in ingress_ids:
                cursor = cursors[entry_point_id]
                choices = by_ingress[entry_point_id]
                if cursor >= len(choices):
                    continue
                selected.append(choices[cursor])
                cursors[entry_point_id] = cursor + 1
                pattern_count += 1
                progressed = True
                if pattern_count >= max_per_pattern:
                    break
            if not progressed:
                break

    selected.sort(key=_qualified_sort_key)
    return [replace(candidate, rank=rank) for rank, candidate in enumerate(selected)]


def plan_generation(
    qualified: list[QualifiedCandidate],
    universe: CoverageUniverse,
    *,
    mode: GenerationMode | str = GenerationMode.EXHAUSTIVE,
    max_per_pattern: int | None = None,
) -> GenerationPlanningResult:
    """Plan qualified candidates for exhaustive corpus or coverage generation.

    Exhaustive mode creates one one-choice durable target per selected
    candidate.  Coverage mode preserves the historical one bounded fallback
    queue per feasible ingress.
    """
    generation_mode = GenerationMode(mode)
    if max_per_pattern is not None and max_per_pattern < 1:
        raise ValueError("max_per_pattern must be a positive integer")
    coverage_queues = build_fallback_queues(qualified, universe)
    if generation_mode is GenerationMode.COVERAGE:
        selection = select_with_coverage_priority(
            qualified,
            coverage_queues,
            universe,
            max_per_pattern=max_per_pattern,
        )
        plan = build_coverage_plan(universe, coverage_queues, selection)
        return GenerationPlanningResult(
            mode=generation_mode,
            selection=selection,
            plan=plan,
            target_queues=coverage_queues,
            coverage_queues=coverage_queues,
        )

    selected = _select_exhaustive_candidates(qualified, max_per_pattern)
    selected_ids = {candidate.candidate_id for candidate in selected}
    selected_ingresses = {candidate.entry_point_id for candidate in selected}
    target_names = {
        target.entry_point_id: target.name for target in universe.feasible_targets
    }
    target_queues: dict[str, TargetFallbackQueue] = {}
    plan_targets: list[CoveragePlanEntry] = []
    primary_candidate_ids: dict[str, str] = {}
    for candidate in selected:
        target_id = _exhaustive_target_id(candidate.candidate_id)
        queue_candidate = replace(candidate, rank=0)
        target_queues[target_id] = TargetFallbackQueue(
            entry_point_id=target_id,
            choices=[queue_candidate],
        )
        primary_candidate_ids[target_id] = candidate.candidate_id
        candidate_ref = queue_candidate.to_plan_ref()
        plan_targets.append(
            CoveragePlanEntry(
                target_id=target_id,
                entry_point_id=candidate.entry_point_id,
                entry_point_name=target_names.get(
                    candidate.entry_point_id, candidate.entry_point_id
                ),
                ordered_choices=[candidate_ref],
                primary_candidate_id=candidate.candidate_id,
                primary_state="selected",
                fallback_available=[],
            )
        )

    uncovered_target_ids = sorted(universe.feasible_target_ids - selected_ingresses)
    cap_limited_target_ids = sorted(
        target_id
        for target_id in uncovered_target_ids
        if not coverage_queues[target_id].is_empty
    )
    for target in sorted(
        universe.feasible_targets, key=lambda item: item.entry_point_id
    ):
        if target.entry_point_id not in uncovered_target_ids:
            continue
        target_queues[target.entry_point_id] = TargetFallbackQueue(
            entry_point_id=target.entry_point_id,
            choices=[],
        )
        plan_targets.append(
            CoveragePlanEntry(
                target_id=target.entry_point_id,
                entry_point_id=target.entry_point_id,
                entry_point_name=target.name,
                ordered_choices=[],
                primary_candidate_id=None,
                primary_state="uncovered",
                fallback_available=[],
            )
        )

    per_pattern_counts: dict[str, int] = {}
    for candidate in selected:
        per_pattern_counts[candidate.pattern_id] = (
            per_pattern_counts.get(candidate.pattern_id, 0) + 1
        )
    selection = SelectionResult(
        selected=selected,
        capped_count=len(qualified) - len(selected),
        uncovered_target_ids=uncovered_target_ids,
        per_pattern_counts=per_pattern_counts,
        primary_candidate_ids=primary_candidate_ids,
        attempted_candidate_ids=selected_ids,
        selection_limitation_target_ids=cap_limited_target_ids,
    )
    plan = CoveragePlan(
        schema_version=COVERAGE_PLAN_SCHEMA_VERSION,
        completeness=universe.completeness.value,
        evidence_refs=list(universe.evidence_refs),
        targets=plan_targets,
        selection_limitation_target_ids=cap_limited_target_ids,
    )
    return GenerationPlanningResult(
        mode=generation_mode,
        selection=selection,
        plan=plan,
        target_queues=target_queues,
        coverage_queues=coverage_queues,
    )


def deserialize_plan_ref(ref: dict) -> ProjectedCandidate:
    """Reconstruct an exact ``ProjectedCandidate`` from a persisted plan ref.

    The plan ref carries the complete validated ``ProjectedCandidate`` JSON
    (not a thin ref), so this round-trips through ``model_validate`` to
    produce a fully validated instance usable by ordinary generation.

    Args:
        ref: A serialized plan reference from :meth:`QualifiedCandidate.to_plan_ref`.

    Returns:
        A validated :class:`ProjectedCandidate` identical to the original.

    Raises:
        ValueError: If the ref does not contain a valid projected candidate.
    """
    pc_data = ref.get("projected_candidate")
    if pc_data is None:
        raise ValueError("plan ref missing 'projected_candidate' — cannot reconstruct")
    return ProjectedCandidate.model_validate(pc_data)


@dataclass(frozen=True)
class DeserializedPlanRef:
    """Typed result of deserializing a persisted plan reference.

    Carries the fully validated :class:`ProjectedCandidate`, the
    deterministically ordered accepted filter records, and the
    :class:`FilteredSeed` usable by ordinary generation.  The outer
    candidate/pattern/entry-point IDs are verified against the embedded
    data during deserialization — tampering is rejected.
    """

    projected: ProjectedCandidate
    accepted_filters: tuple[AcceptedFilterRecord, ...]
    rank: int

    @property
    def candidate_id(self) -> str:
        return self.projected.candidate_id

    @property
    def pattern_id(self) -> str:
        return self.projected.pattern_id

    @property
    def entry_point_id(self) -> str:
        return self.projected.canonical_ingress.entry_point_id

    @property
    def generation_seed(self) -> FilteredSeed:
        """Deterministic FilteredSeed for ordinary generation.

        The seed with the lowest ``filter_candidate_id`` is chosen —
        identical to :attr:`QualifiedCandidate.generation_seed`.
        """
        for record in self.accepted_filters:
            if record.seed is not None:
                return record.seed
        raise ValueError(
            "deserialized plan ref has no seed-bearing accepted filter record"
        )


def deserialize_qualified_candidate(ref: dict) -> DeserializedPlanRef:
    """Deserialize a persisted plan ref into a typed, verified contract.

    Reconstructs the complete :class:`ProjectedCandidate` and the
    deterministically ordered accepted filter records (each carrying its
    complete :class:`FilteredSeed`).  The following integrity checks are
    enforced:

    * The outer ``candidate_id``, ``pattern_id``, and ``entry_point_id``
      must agree with the embedded ``ProjectedCandidate`` data.
    * Accepted filter records must be in canonical (sorted by
      ``filter_candidate_id``) order with no duplicates.
    * Every accepted filter record's embedded seed must have an
      ``entry_point_id`` matching the projected candidate's ingress.

    Args:
        ref: A serialized plan reference from
            :meth:`QualifiedCandidate.to_plan_ref`.

    Returns:
        A :class:`DeserializedPlanRef` with the validated projected
        candidate, ordered filter records, and deterministic generation
        seed.

    Raises:
        ValueError: If any integrity check fails or embedded data is
            invalid.
    """
    # Validate the projected candidate through model_validate.
    pc = deserialize_plan_ref(ref)

    # Verify outer IDs agree with embedded projected candidate.
    outer_candidate_id = ref.get("candidate_id", "")
    if outer_candidate_id != pc.candidate_id:
        raise ValueError(
            f"plan ref outer candidate_id '{outer_candidate_id}' disagrees "
            f"with embedded projected candidate_id '{pc.candidate_id}'"
        )
    outer_pattern_id = ref.get("pattern_id", "")
    if outer_pattern_id != pc.pattern_id:
        raise ValueError(
            f"plan ref outer pattern_id '{outer_pattern_id}' disagrees "
            f"with embedded projected pattern_id '{pc.pattern_id}'"
        )
    outer_entry_point_id = ref.get("entry_point_id", "")
    if outer_entry_point_id != pc.canonical_ingress.entry_point_id:
        raise ValueError(
            f"plan ref outer entry_point_id '{outer_entry_point_id}' disagrees "
            f"with embedded projected ingress entry_point_id "
            f"'{pc.canonical_ingress.entry_point_id}'"
        )

    # Deserialize accepted filter records.
    raw_filters = ref.get("accepted_filters", [])
    if not raw_filters:
        raise ValueError("plan ref has no accepted filter records")

    records: list[AcceptedFilterRecord] = []
    for raw in raw_filters:
        record = AcceptedFilterRecord.from_dict(raw)
        if record.seed is None:
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' is missing seed"
            )
        # The serialized summary fields are not independent evidence.  They
        # must exactly be the canonical projection of the embedded seed.
        if record != AcceptedFilterRecord.from_seed(record.seed):
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' does not "
                "match its embedded FilteredSeed"
            )
        records.append(record)

    # Reject duplicate filter_candidate_ids.
    filter_ids = [r.filter_candidate_id for r in records]
    if len(set(filter_ids)) != len(filter_ids):
        from collections import Counter

        dupes = sorted(cid for cid, count in Counter(filter_ids).items() if count > 1)
        raise ValueError(f"plan ref has duplicate filter_candidate_ids: {dupes}")

    # Reject noncanonical filter order — must be sorted by filter_candidate_id.
    expected_order = sorted(filter_ids)
    if filter_ids != expected_order:
        raise ValueError(
            f"plan ref accepted_filters are not in canonical order "
            f"(sorted by filter_candidate_id): got {filter_ids}, "
            f"expected {expected_order}"
        )

    # Verify each seed's entry_point_id matches the projected ingress.
    for record in records:
        if record.seed is not None and (
            record.seed.entry_point_id != pc.canonical_ingress.entry_point_id
        ):
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' "
                f"seed entry_point_id '{record.seed.entry_point_id}' "
                f"disagrees with projected ingress "
                f"'{pc.canonical_ingress.entry_point_id}'"
            )

    rank = ref.get("rank", 0)

    # Validate duplicated outer summaries rather than trusting them.  This
    # keeps existing plan consumers compatible without creating a second,
    # mutable source of filter provenance.
    canonical_qc = QualifiedCandidate(
        projected=pc, accepted_filters=tuple(records), rank=rank
    )
    expected_outer = {
        "filter_candidate_id": canonical_qc.filter_candidate_id,
        "accepted_rationale": canonical_qc.accepted_rationale,
        "origins": [o.model_dump(mode="json") for o in canonical_qc.merged_origins],
        "rejection_rationales": [
            r.model_dump(mode="json") for r in canonical_qc.merged_rejection_rationales
        ],
        "pinned_entry_point": canonical_qc.generation_seed.pinned_entry_point,
        "pinned_technique_ids": list(canonical_qc.generation_seed.pinned_technique_ids),
        "pinned_technique_names": list(
            canonical_qc.generation_seed.pinned_technique_names
        ),
    }
    for field_name, expected in expected_outer.items():
        if ref.get(field_name) != expected:
            raise ValueError(
                f"plan ref outer {field_name} does not match accepted filter records"
            )

    return DeserializedPlanRef(
        projected=pc,
        accepted_filters=tuple(records),
        rank=rank,
    )


def revalidate_qualified_candidate(
    ref: dict,
    taxonomy_resolver: Any,
    snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    *,
    expected_catalog_pin: str | None = None,
) -> DeserializedPlanRef:
    """Deserialize AND authoritatively revalidate a plan ref.

    Combines :func:`deserialize_qualified_candidate` with authoritative
    requalification of the embedded :class:`ProjectedCandidate` against a
    trusted catalog and :class:`CapabilityFactSnapshot`.  The self-contained
    JSON is never trusted alone — the candidate is re-derived from the
    trusted catalog and compared to the deserialized projection.

    Args:
        ref: A serialized plan reference.
        taxonomy_resolver: Trusted taxonomy resolver for attack pattern
            validation.
        snapshot: Trusted :class:`CapabilityFactSnapshot` for projection
            requalification.

    Returns:
        A :class:`DeserializedPlanRef` if both deserialization and
        authoritative revalidation succeed.

    Raises:
        ValueError: If deserialization fails or the authoritative
            requalification drifts from the embedded projection.
    """
    from asago_scenario_generator.pipeline.projection import (
        compute_authoritative_catalog_pin,
        validate_projected_candidate,
    )

    deserialized = deserialize_qualified_candidate(ref)

    # Locate the matching record in the COMPLETE trusted catalog, then use
    # the direct validation contract.  Do not bounded-reproject: an exact
    # binding variant can validly sit beyond any chosen projection budget.
    trusted_pattern_id = deserialized.pattern_id
    trusted_record = next(
        (
            record
            for record in trusted_catalog
            if record.get("id") == trusted_pattern_id
        ),
        None,
    )
    if trusted_record is None:
        raise ValueError(
            f"authoritative drift: pattern '{trusted_pattern_id}' not found "
            f"in trusted catalog"
        )

    if expected_catalog_pin is None:
        expected_catalog_pin = compute_authoritative_catalog_pin(
            trusted_catalog, taxonomy_resolver
        )
    validated = validate_projected_candidate(
        deserialized.projected.model_dump(mode="json"),
        snapshot,
        trusted_record,
        taxonomy_resolver,
        expected_catalog_pin=expected_catalog_pin,
    )
    if validated != deserialized.projected:
        raise ValueError(
            "authoritative validation did not preserve persisted candidate"
        )

    return deserialized


# ---------------------------------------------------------------------------
# Typed quality gaps — from actual stage ledger evidence
# ---------------------------------------------------------------------------


class CoverageGapReason(str, Enum):
    """Typed, stage-attributed reason for a coverage quality gap."""

    NO_SEED = "no_seed"
    DETERMINISTIC_RULE_REJECTION = "deterministic_rule_rejection"
    FILTER_REJECTION = "filter_rejection"
    PROJECTION_REJECTION = "projection_rejection"
    SELECTION_LIMITATION = "selection_limitation"
    GENERATION_EXHAUSTION = "generation_exhaustion"
    ADMISSION_FAILURE = "admission_failure"
    PROJECTION_LIMITATION = "projection_limitation"


# Mapping from stage to gap reason when the furthest event is at that stage.
_STAGE_TO_GAP_REASON: dict[str, CoverageGapReason] = {
    STAGE_RULES: CoverageGapReason.DETERMINISTIC_RULE_REJECTION,
    STAGE_FILTER: CoverageGapReason.FILTER_REJECTION,
    STAGE_PROJECTION: CoverageGapReason.PROJECTION_REJECTION,
    STAGE_SELECTION: CoverageGapReason.SELECTION_LIMITATION,
    STAGE_GENERATION: CoverageGapReason.GENERATION_EXHAUSTION,
    STAGE_ADMISSION: CoverageGapReason.ADMISSION_FAILURE,
    STAGE_QUARANTINE: CoverageGapReason.ADMISSION_FAILURE,
}


@dataclass
class QualityGap:
    """A typed, stage-attributed quality gap for an uncovered target.

    Carries the target identity, the funnel stage where coverage fell out
    (determined from actual stage ledger evidence), and the exact candidate
    IDs / reasons that explain the gap.  Coverage is never fabricated — a
    gap is emitted rather than a synthetic scenario.
    """

    entry_point_id: str
    entry_point_name: str
    reason: CoverageGapReason
    candidate_ids: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_point_id": self.entry_point_id,
            "entry_point_name": self.entry_point_name,
            "reason": self.reason.value,
            "candidate_ids": self.candidate_ids,
            "detail": self.detail,
        }


# Categorized coverage summary for JSON and HTML reporting.
@dataclass
class CoverageSummary:
    """Categorized coverage summary distinguishing coverage outcomes.

    Categories:
    - ``covered_feasible``: targets with at least one generated+admitted scenario.
    - ``policy_exclusions``: targets excluded by policy (output-only, etc.).
    - ``structural_gaps``: targets with no candidate at rules/filter/projection stages.
    - ``selection_limitations``: targets with candidates but none selected.
    - ``runtime_generation_gaps``: targets where generation failed.
    - ``quarantine_admission_failures``: targets where scenarios were quarantined.
    - ``projection_limitations``: targets omitted by budget allocation.
    """

    covered_feasible: list[str] = field(default_factory=list)
    policy_exclusions: list[dict] = field(default_factory=list)
    structural_gaps: list[dict] = field(default_factory=list)
    selection_limitations: list[dict] = field(default_factory=list)
    runtime_generation_gaps: list[dict] = field(default_factory=list)
    quarantine_admission_failures: list[dict] = field(default_factory=list)
    projection_limitations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "covered_feasible": list(self.covered_feasible),
            "policy_exclusions": list(self.policy_exclusions),
            "structural_gaps": list(self.structural_gaps),
            "selection_limitations": list(self.selection_limitations),
            "runtime_generation_gaps": list(self.runtime_generation_gaps),
            "quarantine_admission_failures": list(self.quarantine_admission_failures),
            "projection_limitations": list(self.projection_limitations),
        }


def emit_quality_gaps(
    universe: CoverageUniverse,
    stage_ledger: StageLedger,
    selection_result: SelectionResult,
    fallback_queues: dict[str, TargetFallbackQueue],
    *,
    generated_target_ids: set[str] | None = None,
    quarantined_target_ids: set[str] | None = None,
    projection_limitation_target_ids: set[str] | None = None,
) -> tuple[list[QualityGap], CoverageSummary]:
    """Emit typed quality gaps from actual stage ledger evidence.

    For each feasible target that has no generated (and admitted) scenario,
    the furthest actual stage event from the ledger determines the gap
    reason.  Runtime evidence retains exact failed/quarantined candidate IDs.
    Coverage is never fabricated.

    Args:
        universe: The coverage universe.
        stage_ledger: The stage ledger with actual events.
        selection_result: The selection result.
        fallback_queues: Per-target fallback queues.
        generated_target_ids: Targets with at least one admitted scenario.
        quarantined_target_ids: Targets whose scenarios were quarantined.
        projection_limitation_target_ids: Targets omitted by budget allocation.

    Returns:
        Tuple of (quality_gaps, coverage_summary).
    """
    generated = generated_target_ids or set()
    quarantined = quarantined_target_ids or set()
    proj_limitations = projection_limitation_target_ids or set()

    gaps: list[QualityGap] = []
    covered: list[str] = []
    policy_exclusions: list[dict] = []
    structural_gaps: list[dict] = []
    selection_limitations: list[dict] = []
    runtime_gaps: list[dict] = []
    quarantine_failures: list[dict] = []
    projection_lims: list[dict] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        target_name = target.name

        if ep_id in generated:
            covered.append(ep_id)
            continue

        if ep_id in quarantined:
            # Exact quarantined candidate IDs from the ledger.
            quarantined_cids = stage_ledger.candidate_ids_for_stage(
                ep_id, STAGE_QUARANTINE
            )
            if not quarantined_cids:
                # Fallback to candidates that reached generation.
                quarantined_cids = stage_ledger.candidate_ids_for_stage(
                    ep_id, STAGE_GENERATION
                )
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.ADMISSION_FAILURE,
                candidate_ids=quarantined_cids,
                detail="Generated scenario(s) quarantined during validation.",
            )
            gaps.append(gap)
            quarantine_failures.append(gap.to_dict())
            continue

        if ep_id in proj_limitations:
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.PROJECTION_LIMITATION,
                candidate_ids=[],
                detail="Target omitted by projection budget allocation.",
            )
            gaps.append(gap)
            projection_lims.append(gap.to_dict())
            continue

        # Use actual stage ledger evidence for attribution.
        furthest = stage_ledger.furthest_event(ep_id)

        if furthest is not None:
            reason = _STAGE_TO_GAP_REASON.get(furthest.stage, CoverageGapReason.NO_SEED)
            # Exact candidate IDs from the furthest stage.
            stage_cids = stage_ledger.candidate_ids_for_stage(ep_id, furthest.stage)
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=reason,
                candidate_ids=stage_cids,
                detail=furthest.detail,
            )
            gaps.append(gap)

            # Categorize.
            if furthest.stage in (STAGE_RULES, STAGE_FILTER, STAGE_PROJECTION):
                structural_gaps.append(gap.to_dict())
            elif furthest.stage == STAGE_SELECTION:
                selection_limitations.append(gap.to_dict())
            elif furthest.stage == STAGE_GENERATION:
                runtime_gaps.append(gap.to_dict())
            elif furthest.stage in (STAGE_ADMISSION, STAGE_QUARANTINE):
                quarantine_failures.append(gap.to_dict())
        elif ep_id in selection_result.uncovered_target_ids:
            # Target had no candidates at all (no stage events).
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.NO_SEED,
                candidate_ids=[],
                detail="No seed or candidate was produced for this target.",
            )
            gaps.append(gap)
            structural_gaps.append(gap.to_dict())
        else:
            # No stage events and not uncovered — shouldn't happen, but
            # emit a no_seed gap rather than fabricating coverage.
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.NO_SEED,
                candidate_ids=[],
                detail="No stage evidence recorded for this target.",
            )
            gaps.append(gap)
            structural_gaps.append(gap.to_dict())

    # Policy exclusions from the universe.
    for exc in universe.excluded_targets:
        policy_exclusions.append(
            {
                "entry_point_id": exc.entry_point_id,
                "name": exc.name,
                "reason": exc.reason.value,
            }
        )

    summary = CoverageSummary(
        covered_feasible=covered,
        policy_exclusions=policy_exclusions,
        structural_gaps=structural_gaps,
        selection_limitations=selection_limitations,
        runtime_generation_gaps=runtime_gaps,
        quarantine_admission_failures=quarantine_failures,
        projection_limitations=projection_lims,
    )

    return gaps, summary
