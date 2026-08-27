"""Coverage-plan and planning-checkpoint contracts."""

from __future__ import annotations

from enum import Enum
import hashlib
from typing import Any, Literal

from pydantic import BaseModel, Field, JsonValue, model_validator

from asago_scenario_generator.pipeline.coverage_planning import (
    QualifiedCandidate,
    deserialize_qualified_candidate,
)
from .persistence_common import MAX_TARGET_CHOICES, SHA256_PATTERN, canonical_json_bytes


class StrictModel(BaseModel):
    """Persistence base: unknown fields are never silently accepted."""

    model_config = {"extra": "forbid", "use_enum_values": False}


class PlanningStageEventV1(StrictModel):
    # Global projection evidence and target-level budget evidence legitimately
    # have no candidate identity (and global issues have no target identity).
    entry_point_id: str
    candidate_id: str
    stage: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    detail: str = ""
    payload: JsonValue | None = None


def _qualification_facts_valid(source: str | None, sha256: str | None) -> None:
    if (source is None) != (sha256 is None):
        raise ValueError(
            "qualification facts source and SHA-256 must be present together"
        )
    if source is not None:
        source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if source_sha256 != sha256:
            raise ValueError("qualification facts source SHA-256 mismatch")


def _id_lists_sorted_unique(lists: tuple[list[str], ...]) -> None:
    if any(values != sorted(set(values)) for values in lists):
        raise ValueError("planning checkpoint ID lists must be sorted and unique")


def _ordered_unique_list(values: list[str]) -> None:
    if values != list(dict.fromkeys(values)):
        raise ValueError("planning checkpoint IDs must be ordered and unique")


def _fallback_lists_ordered_unique(
    fallback_candidate_ids: dict[str, list[str]],
) -> None:
    if any(ids != list(dict.fromkeys(ids)) for ids in fallback_candidate_ids.values()):
        raise ValueError("fallback candidate IDs must be ordered and unique")


class PlanningCheckpointV1(StrictModel):
    """Immutable pre-finalization evidence needed by the completion tail."""

    schema_version: Literal["1"] = "1"
    qualification_facts_source: str | None = None
    qualification_facts_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stage_events: list[PlanningStageEventV1]
    projection_limitation_target_ids: list[str]
    selected_candidate_ids: list[str]
    capped_count: int = Field(ge=0)
    uncovered_target_ids: list[str]
    per_pattern_counts: dict[str, int]
    primary_candidate_ids: dict[str, str]
    attempted_candidate_ids: list[str]
    selection_limitation_target_ids: list[str]
    fallback_candidate_ids: dict[str, list[str]]

    @model_validator(mode="after")
    def canonical_collections(self) -> PlanningCheckpointV1:
        _qualification_facts_valid(
            self.qualification_facts_source, self.qualification_facts_sha256
        )
        _id_lists_sorted_unique(
            (
                self.projection_limitation_target_ids,
                self.uncovered_target_ids,
                self.attempted_candidate_ids,
                self.selection_limitation_target_ids,
            )
        )
        _ordered_unique_list(self.selected_candidate_ids)
        _fallback_lists_ordered_unique(self.fallback_candidate_ids)
        return self


class TargetState(str, Enum):
    selected = "selected"
    admitted = "admitted"
    exhausted = "exhausted"


class QualifiedCandidateRef(StrictModel):
    """Complete candidate-v2 materialization plus merged filter provenance."""

    candidate_id: str = Field(min_length=1)
    filter_candidate_id: str
    pattern_id: str = Field(min_length=1)
    entry_point_id: str = Field(min_length=1)
    rank: int = Field(ge=0)
    projected_candidate: dict[str, Any]
    accepted_filters: list[dict[str, Any]]
    accepted_rationale: str
    origins: list[dict[str, Any]]
    rejection_rationales: list[dict[str, Any]]
    pinned_entry_point: str
    pinned_technique_ids: list[str]
    pinned_technique_names: list[str]

    @model_validator(mode="after")
    def _identity_matches_materialization(self) -> QualifiedCandidateRef:
        raw = self.model_dump(mode="json")
        deserialized = deserialize_qualified_candidate(raw)
        expected = QualifiedCandidate(
            projected=deserialized.projected,
            accepted_filters=deserialized.accepted_filters,
            rank=deserialized.rank,
        ).to_plan_ref()
        if canonical_json_bytes(raw) != canonical_json_bytes(expected):
            raise ValueError("qualified candidate provenance mirrors are not canonical")
        return self


def _queue_ids_unique(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if len(ids) != len(set(ids)):
        raise ValueError("ordered choices contain duplicate candidate IDs")
    if len(entry.attempted_candidate_ids) != len(set(entry.attempted_candidate_ids)):
        raise ValueError("attempted_candidate_ids contains duplicates")


def _queue_primary_identity_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.primary_candidate_id is not None and (
        not ids or ids[0] != entry.primary_candidate_id
    ):
        raise ValueError("primary candidate must be the first ordered choice")


def _queue_primary_required_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if ids and entry.primary_candidate_id is None:
        raise ValueError("nonempty ordered choices require a primary candidate")


def _queue_primary_valid(entry: object) -> None:
    _queue_primary_identity_valid(entry)
    _queue_primary_required_valid(entry)


def _queue_attempted_prefix_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.attempted_candidate_ids != ids[: len(entry.attempted_candidate_ids)]:
        raise ValueError("attempted_candidate_ids must be the exact ordered prefix")


def _queue_empty_exhausted_valid(entry: object) -> None:
    if not entry.ordered_choices and entry.target_state is not TargetState.exhausted:
        raise ValueError("empty target queues must already be exhausted")


def _queue_admitted_attempted_valid(entry: object) -> None:
    if entry.admitted_candidate_id is not None and (
        entry.admitted_candidate_id not in entry.attempted_candidate_ids
    ):
        raise ValueError("admitted candidate must have been attempted")


def _queue_admitted_state_valid(entry: object) -> None:
    if entry.admitted_candidate_id is not None:
        if entry.target_state is not TargetState.admitted:
            raise ValueError("admitted candidate requires target_state=admitted")
        admitted_index = [
            choice.candidate_id for choice in entry.ordered_choices
        ].index(entry.admitted_candidate_id)
        if len(entry.attempted_candidate_ids) != admitted_index + 1:
            raise ValueError("admitted target cannot contain later attempts")
    elif entry.target_state is TargetState.admitted:
        raise ValueError("target_state=admitted requires admitted_candidate_id")


def _queue_selected_valid(entry: object) -> None:
    if (
        entry.target_state is TargetState.selected
        and entry.admitted_candidate_id is not None
    ):
        raise ValueError("selected target must be nonterminal and not admitted")


def _queue_exhausted_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.target_state is TargetState.exhausted:
        if (
            entry.admitted_candidate_id is not None
            or entry.attempted_candidate_ids != ids
        ):
            raise ValueError(
                "exhausted target requires all choices attempted and none admitted"
            )


def _expected_fallback_ids(entry: object, ids: list[str]) -> list[str]:
    if entry.target_state is TargetState.admitted:
        return []
    attempted = set(entry.attempted_candidate_ids)
    return [candidate_id for candidate_id in ids if candidate_id not in attempted]


def _fallbacks_exclude_attempted(entry: object) -> None:
    fallbacks = [choice.candidate_id for choice in entry.fallback_available]
    attempted = set(entry.attempted_candidate_ids)
    if attempted.intersection(fallbacks):
        raise ValueError("fallback_available must exclude attempted candidates")


def _fallbacks_preserve_order(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    fallbacks = [choice.candidate_id for choice in entry.fallback_available]
    expected = _expected_fallback_ids(entry, ids)
    if fallbacks != expected:
        raise ValueError(
            "fallback_available must preserve unattempted ordered-choice order"
        )


def _fallbacks_match_choices(entry: object) -> None:
    ordered_by_id = {choice.candidate_id: choice for choice in entry.ordered_choices}
    if any(
        choice != ordered_by_id[choice.candidate_id]
        for choice in entry.fallback_available
    ):
        raise ValueError(
            "fallback_available entries must exactly equal their ordered choices"
        )


def _queue_fallbacks_valid(entry: object) -> None:
    _fallbacks_exclude_attempted(entry)
    _fallbacks_preserve_order(entry)
    _fallbacks_match_choices(entry)


def _queue_ranks_valid(entry: object) -> None:
    ranks = [choice.rank for choice in entry.ordered_choices]
    if ranks != list(range(len(ranks))):
        raise ValueError("ordered choice queue ranks must be contiguous from zero")


def _queue_target_match_valid(entry: object) -> None:
    if any(
        choice.entry_point_id != entry.entry_point_id
        for choice in entry.ordered_choices
    ):
        raise ValueError("every ordered choice must match its coverage target")


class CoverageTargetEntry(StrictModel):
    entry_point_id: str = Field(min_length=1)
    entry_point_name: str = Field(min_length=1)
    ordered_choices: list[QualifiedCandidateRef] = Field(max_length=MAX_TARGET_CHOICES)
    primary_candidate_id: str | None
    attempted_candidate_ids: list[str]
    admitted_candidate_id: str | None
    target_state: TargetState
    fallback_available: list[QualifiedCandidateRef] = Field(
        max_length=MAX_TARGET_CHOICES
    )
    target_id: str | None = Field(default=None, min_length=1)

    @property
    def effective_target_id(self) -> str:
        """Durable target identity, falling back for pre-field plan artifacts."""
        return self.target_id or self.entry_point_id

    @model_validator(mode="after")
    def _validate_queue(self) -> CoverageTargetEntry:
        _queue_ids_unique(self)
        _queue_primary_valid(self)
        _queue_attempted_prefix_valid(self)
        _queue_empty_exhausted_valid(self)
        _queue_admitted_attempted_valid(self)
        _queue_admitted_state_valid(self)
        _queue_selected_valid(self)
        _queue_exhausted_valid(self)
        _queue_fallbacks_valid(self)
        _queue_ranks_valid(self)
        _queue_target_match_valid(self)
        return self


def _target_ids_unique(targets: list[object]) -> None:
    target_ids = [target.effective_target_id for target in targets]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("coverage plan contains duplicate target IDs")


def _candidate_ids_unique(targets: list[object]) -> None:
    candidates = [
        choice.candidate_id for target in targets for choice in target.ordered_choices
    ]
    if len(candidates) != len(set(candidates)):
        raise ValueError("candidate IDs must be unique across coverage targets")


def _selection_limitations_valid(limitations: list[str], target_ids: list[str]) -> None:
    if len(limitations) != len(set(limitations)) or not set(limitations).issubset(
        target_ids
    ):
        raise ValueError(
            "selection limitations must uniquely reference coverage targets"
        )


def _completeness_evidence_valid(completeness: str, evidence_refs: list[str]) -> None:
    if completeness == "confirmed_complete" and not evidence_refs:
        raise ValueError("confirmed completeness requires evidence references")
    if completeness == "not_applicable" and evidence_refs:
        raise ValueError("not-applicable completeness forbids evidence references")


class CoveragePlanV2(StrictModel):
    schema_version: Literal["2"]
    completeness: Literal["not_applicable", "confirmed_complete"]
    evidence_refs: list[str]
    targets: list[CoverageTargetEntry]
    selection_limitation_target_ids: list[str]

    @model_validator(mode="after")
    def _unique_targets_and_candidates(self) -> CoveragePlanV2:
        _target_ids_unique(self.targets)
        _candidate_ids_unique(self.targets)
        target_ids = [target.effective_target_id for target in self.targets]
        _selection_limitations_valid(self.selection_limitation_target_ids, target_ids)
        _completeness_evidence_valid(self.completeness, self.evidence_refs)
        return self


PlanningCheckpointV1.model_rebuild(_types_namespace=globals())
