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
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)

# Re-export these helpers for compatibility with existing planner consumers.
from asago_scenario_generator.pipeline.coverage_planning_flow import (  # noqa: F401
    _add_pattern_sink_edges,
    _add_target_pattern_edges,
    _augment_path,
    _best_candidate_per_target_pattern,
    _build_flow_network,
    _collect_pattern_index,
    _convex_pattern_cost,
    _extract_assignment,
    _flowing_pattern_edge,
    _relax_node,
    _solve_min_cost_assignment,
    _spfa_shortest_path,
    add_edge,
)
from asago_scenario_generator.pipeline.coverage_planning_universe import (  # noqa: F401
    CoverageCompleteness,
    CoverageExclusionReason,
    CoverageTarget,
    CoverageUniverse,
    ExcludedTarget,
    _classify_exclusion,
    _exclusion_from_entry,
    _target_from_entry,
    _universe_completeness,
    build_coverage_universe,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate

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
        return _merge_deduped(self._sorted_filters, lambda record: record.origins)

    @property
    def origins(self) -> list[CandidateOrigin]:
        """Backward-compatible alias for :attr:`merged_origins`."""
        return self.merged_origins

    @property
    def merged_rejection_rationales(self) -> list[RejectionRecord]:
        """Merged rule-removal provenance from all accepted filter records."""
        return _merge_deduped(
            self._sorted_filters, lambda record: record.rejection_rationales
        )

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
            **_first_filter_summary(self._sorted_filters),
        }


def _merge_deduped(
    records: Sequence[AcceptedFilterRecord],
    items_of: Any,
) -> list[Any]:
    """Merge items from accepted filter records, deduplicating by JSON identity.

    Order follows the canonically sorted filter records and preserves first
    occurrence per item — no first-wins loss of provenance.
    """
    seen: list[str] = []
    merged: list[Any] = []
    for record in records:
        for item in items_of(record):
            key = item.model_dump_json()
            if key not in seen:
                seen.append(key)
                merged.append(item)
    return merged


def _first_filter_summary(records: Sequence[AcceptedFilterRecord]) -> dict:
    """Pinned-technique summary of the first (canonically sorted) filter record."""
    if not records:
        return {
            "pinned_entry_point": "",
            "pinned_technique_ids": [],
            "pinned_technique_names": [],
        }
    first = records[0]
    return {
        "pinned_entry_point": first.pinned_entry_point,
        "pinned_technique_ids": list(first.pinned_technique_ids),
        "pinned_technique_names": list(first.pinned_technique_names),
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


def _target_choice_lists(
    sorted_targets: Sequence[CoverageTarget],
    fallback_queues: dict[str, TargetFallbackQueue],
) -> list[tuple[str, list[QualifiedCandidate]]]:
    """Collect the choice lists for targets that have candidates."""
    result: list[tuple[str, list[QualifiedCandidate]]] = []
    for target in sorted_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        if queue is None or queue.is_empty:
            continue
        result.append((ep_id, list(queue.choices)))
    return result


def _no_candidate_selection(
    sorted_targets: Sequence[CoverageTarget],
) -> SelectionResult:
    """Selection result when no feasible target has any candidate."""
    return SelectionResult(
        selected=[],
        capped_count=0,
        uncovered_target_ids=[t.entry_point_id for t in sorted_targets],
        per_pattern_counts={},
        primary_candidate_ids={},
        attempted_candidate_ids=set(),
        selection_limitation_target_ids=[],
    )


def _build_primary_selection(
    best_assignment: dict[str, QualifiedCandidate],
) -> tuple[list[QualifiedCandidate], set[str], dict[str, str]]:
    """Build the final selected list from the best assignment.

    Deduplicates by candidate_id — one candidate may serve multiple
    targets — and assigns deterministic ranks in sorted target order.
    """
    selected: list[QualifiedCandidate] = []
    selected_ids: set[str] = set()
    primary_ids: dict[str, str] = {}

    for ep_id, qc in sorted(best_assignment.items()):
        if qc.candidate_id not in selected_ids:
            rank = len(selected)
            selected.append(replace(qc, rank=rank))
            selected_ids.add(qc.candidate_id)
        primary_ids[ep_id] = qc.candidate_id
    return selected, selected_ids, primary_ids


def _derive_selection_limitations(
    best_assignment: dict[str, QualifiedCandidate],
    max_per_pattern: int | None,
) -> list[str]:
    """Derive structured selection limitations for over-cap targets.

    For each pattern, the first ``max_per_pattern`` targets (sorted by
    target ID) are in-cap; the rest are overflow with explicit limitations.
    This includes sole-choice overflows.
    """
    if max_per_pattern is None:
        return []
    targets_by_pattern: dict[str, list[str]] = {}
    for ep_id in sorted(best_assignment):
        qc = best_assignment[ep_id]
        targets_by_pattern.setdefault(qc.pattern_id, []).append(ep_id)

    limitations: list[str] = []
    for ep_ids in targets_by_pattern.values():
        limitations.extend(ep_ids[max_per_pattern:])
    return limitations


def _uncovered_target_ids(
    sorted_targets: Sequence[CoverageTarget],
    primary_ids: dict[str, str],
) -> list[str]:
    """Entry-point IDs of feasible targets without a primary assignment."""
    return [
        t.entry_point_id for t in sorted_targets if t.entry_point_id not in primary_ids
    ]


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
    target_choice_lists = _target_choice_lists(sorted_targets, fallback_queues)

    if not target_choice_lists:
        return _no_candidate_selection(sorted_targets)

    coverable_target_ids = [ep_id for ep_id, _ in target_choice_lists]
    target_choices_map: dict[str, list[QualifiedCandidate]] = {
        ep_id: choices for ep_id, choices in target_choice_lists
    }

    best_assignment = _solve_min_cost_assignment(
        coverable_target_ids,
        target_choices_map,
        max_per_pattern,
    )

    selected, selected_ids, primary_ids = _build_primary_selection(best_assignment)
    limitations = _derive_selection_limitations(best_assignment, max_per_pattern)
    uncovered = _uncovered_target_ids(sorted_targets, primary_ids)

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


def _plan_entry_for_target(
    target: CoverageTarget,
    queue: TargetFallbackQueue | None,
    primary_id: str | None,
    attempted: set[str],
    outcomes: dict[str, str],
) -> CoveragePlanEntry:
    """Build one coverage plan entry for a feasible target.

    ``ordered_choices`` is the full ranked list of qualified candidate
    references.  ``fallback_available`` lists choices that have not been
    selected or attempted — suitable for cmps.5 retry.
    """
    ep_id = target.entry_point_id
    choices = queue.choices if queue else []
    ordered_refs = [qc.to_plan_ref() for qc in choices]

    if primary_id is not None:
        state = outcomes.get(primary_id, "selected")
    else:
        state = "uncovered"

    fallback = [qc.to_plan_ref() for qc in choices if qc.candidate_id not in attempted]

    return CoveragePlanEntry(
        target_id=ep_id,
        entry_point_id=ep_id,
        entry_point_name=target.name,
        ordered_choices=ordered_refs,
        primary_candidate_id=primary_id,
        primary_state=state,
        fallback_available=fallback,
    )


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
        primary_id = selection_result.primary_candidate_ids.get(target.entry_point_id)
        entries.append(
            _plan_entry_for_target(
                target,
                fallback_queues.get(target.entry_point_id),
                primary_id,
                attempted,
                outcomes,
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


def _group_ranked_by_pattern_and_ingress(
    ranked: Sequence[QualifiedCandidate],
) -> dict[str, dict[str, list[QualifiedCandidate]]]:
    """Group ranked candidates by pattern_id, then by entry_point_id."""
    by_pattern: dict[str, dict[str, list[QualifiedCandidate]]] = {}
    for candidate in ranked:
        by_pattern.setdefault(candidate.pattern_id, {}).setdefault(
            candidate.entry_point_id, []
        ).append(candidate)
    return by_pattern


def _round_robin_within_pattern(
    by_ingress: dict[str, list[QualifiedCandidate]],
    max_per_pattern: int,
) -> list[QualifiedCandidate]:
    """Select up to ``max_per_pattern`` candidates round-robin across ingresses."""
    ingress_ids = sorted(by_ingress)
    cursors = dict.fromkeys(ingress_ids, 0)
    selected: list[QualifiedCandidate] = []
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
    return selected


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

    selected: list[QualifiedCandidate] = []
    by_pattern = _group_ranked_by_pattern_and_ingress(ranked)
    for pattern_id in sorted(by_pattern):
        selected.extend(
            _round_robin_within_pattern(by_pattern[pattern_id], max_per_pattern)
        )

    selected.sort(key=_qualified_sort_key)
    return [replace(candidate, rank=rank) for rank, candidate in enumerate(selected)]


def _exhaustive_target_entries(
    selected: Sequence[QualifiedCandidate],
    target_names: dict[str, str],
) -> tuple[dict[str, TargetFallbackQueue], list[CoveragePlanEntry], dict[str, str]]:
    """Build one one-choice durable target per selected candidate."""
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
    return target_queues, plan_targets, primary_candidate_ids


def _uncovered_exhaustive_entries(
    uncovered_target_ids: Sequence[str],
    universe: CoverageUniverse,
) -> tuple[dict[str, TargetFallbackQueue], list[CoveragePlanEntry]]:
    """Empty-queue entries for feasible targets left uncovered by the cap."""
    target_queues: dict[str, TargetFallbackQueue] = {}
    plan_targets: list[CoveragePlanEntry] = []
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
    return target_queues, plan_targets


def _cap_limited_target_ids(
    uncovered_target_ids: Sequence[str],
    coverage_queues: dict[str, TargetFallbackQueue],
) -> list[str]:
    """Uncovered targets whose queue had candidates — cap limited, not seedless."""
    return sorted(
        target_id
        for target_id in uncovered_target_ids
        if not coverage_queues[target_id].is_empty
    )


def _plan_coverage_generation(
    qualified: list[QualifiedCandidate],
    universe: CoverageUniverse,
    coverage_queues: dict[str, TargetFallbackQueue],
    max_per_pattern: int | None,
) -> tuple[SelectionResult, CoveragePlan]:
    """Coverage-mode selection and plan over the per-ingress fallback queues."""
    selection = select_with_coverage_priority(
        qualified,
        coverage_queues,
        universe,
        max_per_pattern=max_per_pattern,
    )
    plan = build_coverage_plan(universe, coverage_queues, selection)
    return selection, plan


def _plan_exhaustive_generation(
    qualified: list[QualifiedCandidate],
    universe: CoverageUniverse,
    coverage_queues: dict[str, TargetFallbackQueue],
    max_per_pattern: int | None,
) -> tuple[SelectionResult, CoveragePlan, dict[str, TargetFallbackQueue]]:
    """Exhaustive-mode selection, plan, and durable per-candidate targets."""
    selected = _select_exhaustive_candidates(qualified, max_per_pattern)
    selected_ids = {candidate.candidate_id for candidate in selected}
    selected_ingresses = {candidate.entry_point_id for candidate in selected}
    target_names = {
        target.entry_point_id: target.name for target in universe.feasible_targets
    }
    target_queues, plan_targets, primary_candidate_ids = _exhaustive_target_entries(
        selected, target_names
    )

    uncovered_target_ids = sorted(universe.feasible_target_ids - selected_ingresses)
    uncovered_queues, uncovered_entries = _uncovered_exhaustive_entries(
        uncovered_target_ids, universe
    )
    target_queues.update(uncovered_queues)
    plan_targets.extend(uncovered_entries)
    cap_limited_target_ids = _cap_limited_target_ids(
        uncovered_target_ids, coverage_queues
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
    return selection, plan, target_queues


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
        selection, plan = _plan_coverage_generation(
            qualified, universe, coverage_queues, max_per_pattern
        )
        return GenerationPlanningResult(
            mode=generation_mode,
            selection=selection,
            plan=plan,
            target_queues=coverage_queues,
            coverage_queues=coverage_queues,
        )

    selection, plan, target_queues = _plan_exhaustive_generation(
        qualified, universe, coverage_queues, max_per_pattern
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


def _verify_outer_identity(ref: dict, pc: ProjectedCandidate) -> None:
    """Verify the outer IDs agree with the embedded projected candidate."""
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


def _deserialize_filter_records(
    raw_filters: Sequence[dict],
) -> list[AcceptedFilterRecord]:
    """Deserialize accepted filter records, enforcing seed presence and fidelity.

    The serialized summary fields are not independent evidence — they must
    exactly be the canonical projection of the embedded seed.
    """
    if not raw_filters:
        raise ValueError("plan ref has no accepted filter records")

    records: list[AcceptedFilterRecord] = []
    for raw in raw_filters:
        record = AcceptedFilterRecord.from_dict(raw)
        if record.seed is None:
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' is missing seed"
            )
        if record != AcceptedFilterRecord.from_seed(record.seed):
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' does not "
                "match its embedded FilteredSeed"
            )
        records.append(record)
    return records


def _verify_canonical_filter_ids(records: Sequence[AcceptedFilterRecord]) -> None:
    """Reject duplicate and noncanonically ordered filter_candidate_ids."""
    filter_ids = [r.filter_candidate_id for r in records]
    if len(set(filter_ids)) != len(filter_ids):
        dupes = sorted(cid for cid, count in Counter(filter_ids).items() if count > 1)
        raise ValueError(f"plan ref has duplicate filter_candidate_ids: {dupes}")

    expected_order = sorted(filter_ids)
    if filter_ids != expected_order:
        raise ValueError(
            f"plan ref accepted_filters are not in canonical order "
            f"(sorted by filter_candidate_id): got {filter_ids}, "
            f"expected {expected_order}"
        )


def _verify_seed_ingress_agreement(
    records: Sequence[AcceptedFilterRecord], pc: ProjectedCandidate
) -> None:
    """Verify each seed's entry_point_id matches the projected ingress."""
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


def _verify_outer_summaries(
    ref: dict, records: Sequence[AcceptedFilterRecord], pc: ProjectedCandidate
) -> None:
    """Validate duplicated outer summaries rather than trusting them.

    This keeps existing plan consumers compatible without creating a second,
    mutable source of filter provenance.
    """
    canonical_qc = QualifiedCandidate(
        projected=pc, accepted_filters=tuple(records), rank=0
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

    _verify_outer_identity(ref, pc)
    records = _deserialize_filter_records(ref.get("accepted_filters", []))
    _verify_canonical_filter_ids(records)
    _verify_seed_ingress_agreement(records, pc)

    rank = ref.get("rank", 0)
    _verify_outer_summaries(ref, records, pc)

    return DeserializedPlanRef(
        projected=pc,
        accepted_filters=tuple(records),
        rank=rank,
    )


def _find_trusted_record(
    trusted_catalog: Sequence[dict[str, Any]], pattern_id: str
) -> dict[str, Any] | None:
    """Locate the matching record in the COMPLETE trusted catalog by pattern ID."""
    return next(
        (record for record in trusted_catalog if record.get("id") == pattern_id),
        None,
    )


def _expected_authoritative_pin(
    trusted_catalog: Sequence[dict[str, Any]],
    taxonomy_resolver: Any,
    expected_catalog_pin: str | None,
) -> str:
    """Resolve the authoritative catalog pin, computing it when not supplied."""
    if expected_catalog_pin is None:
        from asago_scenario_generator.pipeline.projection_qualification import (
            compute_authoritative_catalog_pin,
        )

        return compute_authoritative_catalog_pin(trusted_catalog, taxonomy_resolver)
    return expected_catalog_pin


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
        validate_projected_candidate,
    )

    deserialized = deserialize_qualified_candidate(ref)

    # Use the direct validation contract.  Do not bounded-reproject: an
    # exact binding variant can validly sit beyond any chosen projection
    # budget.
    trusted_pattern_id = deserialized.pattern_id
    trusted_record = _find_trusted_record(trusted_catalog, trusted_pattern_id)
    if trusted_record is None:
        raise ValueError(
            f"authoritative drift: pattern '{trusted_pattern_id}' not found "
            f"in trusted catalog"
        )

    pin = _expected_authoritative_pin(
        trusted_catalog, taxonomy_resolver, expected_catalog_pin
    )
    validated = validate_projected_candidate(
        deserialized.projected.model_dump(mode="json"),
        snapshot,
        trusted_record,
        taxonomy_resolver,
        expected_catalog_pin=pin,
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


def _quarantine_gap(target: CoverageTarget, stage_ledger: StageLedger) -> QualityGap:
    """Admission-failure gap with the exact quarantined (or generated) candidate IDs."""
    ep_id = target.entry_point_id
    quarantined_cids = stage_ledger.candidate_ids_for_stage(ep_id, STAGE_QUARANTINE)
    if not quarantined_cids:
        # Fallback to candidates that reached generation.
        quarantined_cids = stage_ledger.candidate_ids_for_stage(ep_id, STAGE_GENERATION)
    return QualityGap(
        entry_point_id=ep_id,
        entry_point_name=target.name,
        reason=CoverageGapReason.ADMISSION_FAILURE,
        candidate_ids=quarantined_cids,
        detail="Generated scenario(s) quarantined during validation.",
    )


def _projection_limitation_gap(target: CoverageTarget) -> QualityGap:
    """Budget-omission gap for a target excluded by projection allocation."""
    return QualityGap(
        entry_point_id=target.entry_point_id,
        entry_point_name=target.name,
        reason=CoverageGapReason.PROJECTION_LIMITATION,
        candidate_ids=[],
        detail="Target omitted by projection budget allocation.",
    )


def _furthest_stage_gap(
    target: CoverageTarget, stage_ledger: StageLedger
) -> tuple[QualityGap, StageEvent] | None:
    """Gap attributed to the furthest actual stage event for a target."""
    ep_id = target.entry_point_id
    furthest = stage_ledger.furthest_event(ep_id)
    if furthest is None:
        return None
    reason = _STAGE_TO_GAP_REASON.get(furthest.stage, CoverageGapReason.NO_SEED)
    gap = QualityGap(
        entry_point_id=ep_id,
        entry_point_name=target.name,
        reason=reason,
        candidate_ids=stage_ledger.candidate_ids_for_stage(ep_id, furthest.stage),
        detail=furthest.detail,
    )
    return gap, furthest


def _no_evidence_gap(target: CoverageTarget, uncovered: bool) -> QualityGap:
    """No-seed gap for a target with no stage ledger evidence."""
    detail = (
        "No seed or candidate was produced for this target."
        if uncovered
        else "No stage evidence recorded for this target."
    )
    return QualityGap(
        entry_point_id=target.entry_point_id,
        entry_point_name=target.name,
        reason=CoverageGapReason.NO_SEED,
        candidate_ids=[],
        detail=detail,
    )


def _categorize_furthest_gap(
    furthest: StageEvent,
    gap: QualityGap,
    structural_gaps: list[dict],
    selection_limitations: list[dict],
    runtime_gaps: list[dict],
    quarantine_failures: list[dict],
) -> None:
    """Route a stage-attributed gap into its coverage summary category."""
    if furthest.stage in (STAGE_RULES, STAGE_FILTER, STAGE_PROJECTION):
        structural_gaps.append(gap.to_dict())
    elif furthest.stage == STAGE_SELECTION:
        selection_limitations.append(gap.to_dict())
    elif furthest.stage == STAGE_GENERATION:
        runtime_gaps.append(gap.to_dict())
    elif furthest.stage in (STAGE_ADMISSION, STAGE_QUARANTINE):
        quarantine_failures.append(gap.to_dict())


def _policy_exclusion_dicts(universe: CoverageUniverse) -> list[dict]:
    """Serialized policy exclusions from the coverage universe."""
    return [
        {
            "entry_point_id": exc.entry_point_id,
            "name": exc.name,
            "reason": exc.reason.value,
        }
        for exc in universe.excluded_targets
    ]


def _normalize_gap_sets(
    generated_target_ids: set[str] | None,
    quarantined_target_ids: set[str] | None,
    projection_limitation_target_ids: set[str] | None,
) -> tuple[set[str], set[str], set[str]]:
    """Normalize optional target-ID sets to non-None sets."""
    return (
        generated_target_ids or set(),
        quarantined_target_ids or set(),
        projection_limitation_target_ids or set(),
    )


def _record_ledger_gap(
    target: CoverageTarget,
    stage_ledger: StageLedger,
    selection_result: SelectionResult,
    gaps: list[QualityGap],
    structural_gaps: list[dict],
    selection_limitations: list[dict],
    runtime_gaps: list[dict],
    quarantine_failures: list[dict],
) -> None:
    """Record the furthest-stage gap for a target with no special disposition."""
    furthest_gap = _furthest_stage_gap(target, stage_ledger)
    if furthest_gap is not None:
        gap, furthest = furthest_gap
        gaps.append(gap)
        _categorize_furthest_gap(
            furthest,
            gap,
            structural_gaps,
            selection_limitations,
            runtime_gaps,
            quarantine_failures,
        )
    else:
        uncovered = target.entry_point_id in selection_result.uncovered_target_ids
        gap = _no_evidence_gap(target, uncovered)
        gaps.append(gap)
        structural_gaps.append(gap.to_dict())


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
    generated, quarantined, proj_limitations = _normalize_gap_sets(
        generated_target_ids, quarantined_target_ids, projection_limitation_target_ids
    )

    gaps: list[QualityGap] = []
    covered: list[str] = []
    structural_gaps: list[dict] = []
    selection_limitations: list[dict] = []
    runtime_gaps: list[dict] = []
    quarantine_failures: list[dict] = []
    projection_lims: list[dict] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id

        if ep_id in generated:
            covered.append(ep_id)
            continue

        if ep_id in quarantined:
            gap = _quarantine_gap(target, stage_ledger)
            gaps.append(gap)
            quarantine_failures.append(gap.to_dict())
            continue

        if ep_id in proj_limitations:
            gap = _projection_limitation_gap(target)
            gaps.append(gap)
            projection_lims.append(gap.to_dict())
            continue

        _record_ledger_gap(
            target,
            stage_ledger,
            selection_result,
            gaps,
            structural_gaps,
            selection_limitations,
            runtime_gaps,
            quarantine_failures,
        )

    summary = CoverageSummary(
        covered_feasible=covered,
        policy_exclusions=_policy_exclusion_dicts(universe),
        structural_gaps=structural_gaps,
        selection_limitations=selection_limitations,
        runtime_generation_gaps=runtime_gaps,
        quarantine_admission_failures=quarantine_failures,
        projection_limitations=projection_lims,
    )

    return gaps, summary


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:10:29Z","module_hash":"bb1a920966654c2651c84b3efc3b4a0ac5c866af778129183ea51b0fe7c49ff8","source_sha256":"a81e4589e8f9aca7e5c42aa0c22eedfe597715d5b86f1e138fdc3ccc77b476b3","functions":[{"id":"func/AcceptedFilterRecord.to_dict","name":"to_dict","line":122,"end_line":136,"hash":"895c66083476a212fadeb09518b84a26e0ae3519db5c4667c48e1840061f19af"},{"id":"func/AcceptedFilterRecord.from_dict","name":"from_dict","line":139,"end_line":161,"hash":"b6a979ed71eae2a7edf1be233bfd3919aa20c7e08dbdf494d8faa0960131ad9b"},{"id":"func/AcceptedFilterRecord.from_seed","name":"from_seed","line":164,"end_line":175,"hash":"fb8daaa34c6c9a52434e0476ed334ccfc3c95ba1922423adceb36322149fbfa7"},{"id":"func/QualifiedCandidate.entry_point_id","name":"entry_point_id","line":196,"end_line":198,"hash":"4c90d31a9d298a8baaf7fc82170135af98ce4028d757e868ee79b7ddecdc76eb"},{"id":"func/QualifiedCandidate.candidate_id","name":"candidate_id","line":201,"end_line":203,"hash":"18359a0930acf8fbb2e5f5da638cf9dbf7ffd606f29e97b4f0e34d15caaa6b66"},{"id":"func/QualifiedCandidate.pattern_id","name":"pattern_id","line":206,"end_line":208,"hash":"f9858e04e831cdb2fc527797de20d7e3f5a3d3cf62d5ef40e735f9c7dc5dd7d9"},{"id":"func/QualifiedCandidate._sorted_filters","name":"_sorted_filters","line":211,"end_line":213,"hash":"986d63b88eb3308099fcb9c65f4a87fd13aa309d1c88f2a3ed39f3bc0c31b266"},{"id":"func/QualifiedCandidate.generation_seed","name":"generation_seed","line":216,"end_line":227,"hash":"93bf3fb72f4f29dfda038cce99bbff5de503babdd8b70b7252e5809e87836c8a"},{"id":"func/QualifiedCandidate.filtered_seed","name":"filtered_seed","line":230,"end_line":232,"hash":"29412d2a45c73f25b60c51c3d033e6a978884e8a492ec5af5573bb7efe588d5e"},{"id":"func/QualifiedCandidate.filter_candidate_id","name":"filter_candidate_id","line":235,"end_line":239,"hash":"ff0eb7961ec54757d721462a0d62f68022031c2a683d563e13e091b649ff09b0"},{"id":"func/QualifiedCandidate.accepted_rationale","name":"accepted_rationale","line":242,"end_line":246,"hash":"f495537fc4cdd36a5d19a34b495e13a7f625c7a034d3d8c462f2655e64001560"},{"id":"func/QualifiedCandidate.merged_origins","name":"merged_origins","line":249,"end_line":251,"hash":"dafbd89fa87db1ff680e8e207435c906860f7a872542b9c6465b5b4ad13b83b8"},{"id":"func/QualifiedCandidate.origins","name":"origins","line":254,"end_line":256,"hash":"f3c85e0ff1397fd4f57bf0be33693d33d74c8cb99ace792ae6101b3b6aa494e7"},{"id":"func/QualifiedCandidate.merged_rejection_rationales","name":"merged_rejection_rationales","line":259,"end_line":263,"hash":"83de3691d488b8cc856bc42339d805ed54e821d51318b8139633ee1f20edce7b"},{"id":"func/QualifiedCandidate.rejection_rationales","name":"rejection_rationales","line":266,"end_line":268,"hash":"ccfbff24bce2de425f29648d607739b15c56df574cd7de07a55ceb73099c1f46"},{"id":"func/QualifiedCandidate.to_plan_ref","name":"to_plan_ref","line":270,"end_line":292,"hash":"f3fb7f7859301982da1fba0b2a324e614a4f33c513f12c6283131481eeca2954"},{"id":"func/_merge_deduped","name":"_merge_deduped","line":295,"end_line":312,"hash":"909659007686a168778f90d8d8caa1b632b253cb93b1d97fedd7d7c3ff18b4ec"},{"id":"func/_first_filter_summary","name":"_first_filter_summary","line":315,"end_line":328,"hash":"62cba3766d3eaff5f740280ad787e70bee0c16dfdd25de263995cd4e2768eb2e"},{"id":"func/_qualified_sort_key","name":"_qualified_sort_key","line":331,"end_line":338,"hash":"df1baca948bd8c9e6c48a0deccd9d678137a9bc6e7f5550254303eac49bb3bd3"},{"id":"func/build_qualified_candidates","name":"build_qualified_candidates","line":341,"end_line":407,"hash":"2545eba90fdcd1a76d2977be2108b8a33fc9ec90113edbd70a339fcede69091b"},{"id":"func/StageEvent.to_dict","name":"to_dict","line":453,"end_line":463,"hash":"e2a5b4444d12358339efb39cdac5ff7e5a0454edb737bcc74e5ae1205d47ad81"},{"id":"func/StageLedger.record","name":"record","line":478,"end_line":498,"hash":"444ee5f32bf36ade8a90c479a8860983b5f92caa2f220e21435b578a41193a29"},{"id":"func/StageLedger.events_for","name":"events_for","line":500,"end_line":502,"hash":"0c93b9a78873af3c000fb4a37dbc09819e28afbea6f498efd3ed69bf547678fa"},{"id":"func/StageLedger.furthest_event","name":"furthest_event","line":504,"end_line":516,"hash":"ae4dfc4530524204475ae1acf158d9bf0bb0eb6dbefa6d0206dadb964710984b"},{"id":"func/StageLedger.candidate_ids_for_stage","name":"candidate_ids_for_stage","line":518,"end_line":524,"hash":"f487a6d1bece2665a92c0f1d16f4f8fd2def99b7a4df32c50c301f1efe8f5d2b"},{"id":"func/StageLedger.to_dict","name":"to_dict","line":526,"end_line":527,"hash":"300590329a744def24b69e38174bb2955cd7f3224b3897ed5be73de3a4dd33bb"},{"id":"func/TargetFallbackQueue.is_empty","name":"is_empty","line":549,"end_line":550,"hash":"39c0891c73589c9c021cb596ddf65b829cda2f870e922e82a5324de5e46c0511"},{"id":"func/TargetFallbackQueue.first_choice","name":"first_choice","line":553,"end_line":555,"hash":"80ad13ea46f0256c1b064caaf207cb42ea094cfa98981062ad88f4cc3a197176"},{"id":"func/TargetFallbackQueue.remaining_choices","name":"remaining_choices","line":558,"end_line":560,"hash":"cbf725ef10bf996d7b4840ca1b742c5c5a98a73e43d5c850afc0e490bbbe6dda"},{"id":"func/TargetFallbackQueue.candidate_ids","name":"candidate_ids","line":562,"end_line":564,"hash":"60222c61689c9151f1a42ce423af1748322e8114a3ab5d39dc4418df4dfc8f3e"},{"id":"func/build_fallback_queues","name":"build_fallback_queues","line":567,"end_line":606,"hash":"8ca33366c11ddcb3b94b30da0e21ac19fcaed1379761d351c2a5cb9a62c5adb3"},{"id":"func/_target_choice_lists","name":"_target_choice_lists","line":637,"end_line":649,"hash":"982c9009332f208972fdfecc762e9847ba4fdf5cdb64cd259c69705d5af68a17"},{"id":"func/_no_candidate_selection","name":"_no_candidate_selection","line":652,"end_line":664,"hash":"3267529214fb6c316ad9353939bf6a5de33a463b73b57324861977ea843c5fd5"},{"id":"func/_build_primary_selection","name":"_build_primary_selection","line":667,"end_line":685,"hash":"0278aa2f1f3579ccbc9aa53080130927a63ad740e0db8f4a5313c3ea0f0ded1d"},{"id":"func/_derive_selection_limitations","name":"_derive_selection_limitations","line":688,"end_line":708,"hash":"5d596c8b0d7c0d3a726bedc7822a1681592698597d56f9cac9f2eb5619d16832"},{"id":"func/_uncovered_target_ids","name":"_uncovered_target_ids","line":711,"end_line":718,"hash":"f5f5a985caacb5eb59f87c10a0b86d758e10255d399c190ffa41d88ea5695d08"},{"id":"func/select_with_coverage_priority","name":"select_with_coverage_priority","line":721,"end_line":800,"hash":"77bcd67018ac6baf0873d51695891111897d4695e7ae6e99d34c7709b1948efb"},{"id":"func/CoveragePlanEntry.effective_target_id","name":"effective_target_id","line":828,"end_line":830,"hash":"5a28b604819144ec116c6495f11d346b53ba77014577000aa0a6b52a7a1ed486"},{"id":"func/CoveragePlanEntry.to_dict","name":"to_dict","line":832,"end_line":841,"hash":"a10fb6781e7fd1e2367fa32e424785b92f594e4f46c24efee2bc9cc5816f69dd"},{"id":"func/CoveragePlan.to_dict","name":"to_dict","line":862,"end_line":871,"hash":"d77ea2bc0713d2b5b9ff51e0308010ab2819d15677275c5a4613e3ce680aa573"},{"id":"func/_plan_entry_for_target","name":"_plan_entry_for_target","line":874,"end_line":906,"hash":"6a54f48330d24069d626753ff4b572953e0b7abf8f8ad1169c557c90f0cc5b3e"},{"id":"func/build_coverage_plan","name":"build_coverage_plan","line":909,"end_line":956,"hash":"7b2cf5908867e175b376242d844db7d1ea21aea7aec7a8b74341bf35258aaeb5"},{"id":"func/_exhaustive_target_id","name":"_exhaustive_target_id","line":976,"end_line":979,"hash":"d1c920280ff5607a0799ee9a814e8f2af248fdd78ca7f26f2b1f7a4aee234b5f"},{"id":"func/_group_ranked_by_pattern_and_ingress","name":"_group_ranked_by_pattern_and_ingress","line":982,"end_line":991,"hash":"4f42bf8e89afee2e673488b7d650a67b6fcff06ec967bfdf617bc11a672f32d5"},{"id":"func/_round_robin_within_pattern","name":"_round_robin_within_pattern","line":994,"end_line":1018,"hash":"00b2a2d1cbcab85fb98a1aa098e1cdb0f466f0b4d76af36793094053ba5d785c"},{"id":"func/_select_exhaustive_candidates","name":"_select_exhaustive_candidates","line":1021,"end_line":1043,"hash":"f37276daaf7904b90613cd8bc2ad58a805e3d00a50e35a7675dd992d5d6aff38"},{"id":"func/_exhaustive_target_entries","name":"_exhaustive_target_entries","line":1046,"end_line":1076,"hash":"63b42e2906878eb23fcceb4a7b48fdacbb6524b2caf85912ce598c27d58eb832"},{"id":"func/_uncovered_exhaustive_entries","name":"_uncovered_exhaustive_entries","line":1079,"end_line":1106,"hash":"cd2c9fafc6f09333166ab07fc3860606b9319592598ada38f4f5bc6db20b4e23"},{"id":"func/_cap_limited_target_ids","name":"_cap_limited_target_ids","line":1109,"end_line":1118,"hash":"368c5f683a32744b2dbbffebaa408bea2cf48084d15be45c973b7d8a7b5d0740"},{"id":"func/_plan_coverage_generation","name":"_plan_coverage_generation","line":1121,"end_line":1135,"hash":"c35432aec291015bb9f67a8a3de801e13b117cb1af1c9c61f027e3a57b4d9175"},{"id":"func/_plan_exhaustive_generation","name":"_plan_exhaustive_generation","line":1138,"end_line":1186,"hash":"8f23eddfbe883be0bbc072b24db8f3f420d5c38282bb6b01fdf8ea466535d387"},{"id":"func/plan_generation","name":"plan_generation","line":1189,"end_line":1227,"hash":"20598bcf90b77cc15a1e474921e28c278e316a4b58f62884d03c259bcb315597"},{"id":"func/deserialize_plan_ref","name":"deserialize_plan_ref","line":1230,"end_line":1249,"hash":"bb33aeaa351b556dc5e39b4cce5089bccad153826a889cf2004fa72f1328441f"},{"id":"func/DeserializedPlanRef.candidate_id","name":"candidate_id","line":1268,"end_line":1269,"hash":"392222ebf0e61dfcdfcc4cf321374447c03fd07b3f1a8f0475b1e54102abe62d"},{"id":"func/DeserializedPlanRef.pattern_id","name":"pattern_id","line":1272,"end_line":1273,"hash":"6fb84a6f533ad80b48ef35b4a8ab0e0ddfbe36efb578fd04aada1b243a172998"},{"id":"func/DeserializedPlanRef.entry_point_id","name":"entry_point_id","line":1276,"end_line":1277,"hash":"ae338b92ecd9bade36d5d7e2beb434cf53b913154fd53abc7fe0ffb8c0f347ca"},{"id":"func/DeserializedPlanRef.generation_seed","name":"generation_seed","line":1280,"end_line":1291,"hash":"663824fd0cd8bb764885156913d637011e7abde214a2dff947a257a587c590eb"},{"id":"func/_verify_outer_identity","name":"_verify_outer_identity","line":1294,"end_line":1314,"hash":"1c56a4978d230833fcab990d566e1d9a4856404bfbb8a19a2bbd48dcf7798055"},{"id":"func/_deserialize_filter_records","name":"_deserialize_filter_records","line":1317,"end_line":1341,"hash":"e4ba48bec034586b53933f8f6809c8113b9492d2828478039e24ee4067847ade"},{"id":"func/_verify_canonical_filter_ids","name":"_verify_canonical_filter_ids","line":1344,"end_line":1357,"hash":"5248d63157037babf20676d98209441a1d3a3507d6b31e7fbb63eabcae1295a6"},{"id":"func/_verify_seed_ingress_agreement","name":"_verify_seed_ingress_agreement","line":1360,"end_line":1373,"hash":"05393a1864cb4a4e6102d3ba084721cca79872547cea4aa1e0ecd87fab5229f5"},{"id":"func/_verify_outer_summaries","name":"_verify_outer_summaries","line":1376,"end_line":1404,"hash":"1a4245661b90d19424a82b96f78b4793dd89f720ea2425e5eae07ea6cc913cd0"},{"id":"func/deserialize_qualified_candidate","name":"deserialize_qualified_candidate","line":1407,"end_line":1450,"hash":"b6329f191a64c2c16b7525220c379be7b9df4505551a73cbc66133ee9f246edf"},{"id":"func/_find_trusted_record","name":"_find_trusted_record","line":1453,"end_line":1460,"hash":"8a8e51b57787cdd7697481bdaf7a897953769d9540126ec2f5d0ce777d35bdbe"},{"id":"func/_expected_authoritative_pin","name":"_expected_authoritative_pin","line":1463,"end_line":1475,"hash":"454a28dbfb9979479e09313204e5b6395da289b5835cc80fa24ba92ad7adced1"},{"id":"func/revalidate_qualified_candidate","name":"revalidate_qualified_candidate","line":1478,"end_line":1541,"hash":"02863e50719ff9d52e34d6e21c22f5cf0fddf0e9cdc1de0a29375c9d852ed943"},{"id":"func/QualityGap.to_dict","name":"to_dict","line":1590,"end_line":1597,"hash":"f6b9f0414ddeb37f67ac935ffe72648495b040c0b7006de9c819eeaa4d900df7"},{"id":"func/CoverageSummary.to_dict","name":"to_dict","line":1623,"end_line":1632,"hash":"ade445b7ff3d39de97a0cb7accec152355d101be15138c10f24139760572026d"},{"id":"func/_quarantine_gap","name":"_quarantine_gap","line":1635,"end_line":1648,"hash":"6b0170a94c628b1ff568533839c433dd3734afe147c7f6855b24c9f3ae6daf7f"},{"id":"func/_projection_limitation_gap","name":"_projection_limitation_gap","line":1651,"end_line":1659,"hash":"83e24c65630eff6b62ee0e2e5d9de3ab387d6dcda133b07e5f5efaf7e5782779"},{"id":"func/_furthest_stage_gap","name":"_furthest_stage_gap","line":1662,"end_line":1678,"hash":"ad6491bee659579686e8206d0a480e80281c9f19eb31ff282cb71cb80f10c641"},{"id":"func/_no_evidence_gap","name":"_no_evidence_gap","line":1681,"end_line":1694,"hash":"76327e914178e5a25a7be6521e5ac68c8c1b9659797cc0189438ccc8bd1a4f82"},{"id":"func/_categorize_furthest_gap","name":"_categorize_furthest_gap","line":1697,"end_line":1713,"hash":"f141c0dc9a305a0c9ef639836a971f932089d1c889632d9c4e23e8a37c840b8c"},{"id":"func/_policy_exclusion_dicts","name":"_policy_exclusion_dicts","line":1716,"end_line":1725,"hash":"5dbc2b1bd4a832b7a0db2bd096b4f2d9c04afcb7503380e9e512015c7846d4f5"},{"id":"func/_normalize_gap_sets","name":"_normalize_gap_sets","line":1728,"end_line":1738,"hash":"78aae975757c4a8225b38e1d48487a32e910489b45e1b4548caecac539641314"},{"id":"func/_record_ledger_gap","name":"_record_ledger_gap","line":1741,"end_line":1768,"hash":"e0c62e361703a9651870003ef47f4dc91aafd1b2e2b6eddf9ebe2b8339dd471a"},{"id":"func/emit_quality_gaps","name":"emit_quality_gaps","line":1771,"end_line":1852,"hash":"10ba372f468c8136a799ef08021e7d60d3f7bbe995bb5c2d8d64bd6c2fded60f"}]}
# mutate4py-manifest-end
