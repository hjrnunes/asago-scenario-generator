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
        if len(ep_ids) > max_per_pattern:
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
    from asago_scenario_generator.pipeline.projection_qualification import (
        compute_authoritative_catalog_pin,
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
