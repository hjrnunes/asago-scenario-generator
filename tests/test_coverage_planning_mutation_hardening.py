"""Focused adversarial coverage for coverage-planning helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline import coverage_planning as planning
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
)
from tests.helpers.projection_factory import get_projected_candidate


def test_stage_event_serialization_preserves_optional_payload() -> None:
    without_payload = planning.StageEvent("ep", "candidate", "rules", "reason")
    with_payload = planning.StageEvent(
        "ep",
        "candidate",
        "rules",
        "reason",
        payload={"code": "detail"},
    )

    assert "payload" not in without_payload.to_dict()
    assert with_payload.to_dict()["payload"] == {"code": "detail"}


def test_effective_target_id_falls_back_only_when_target_id_missing() -> None:
    entry_point = "ep:v1:" + "a" * 32
    entry = planning.CoveragePlanEntry(
        entry_point_id=entry_point,
        entry_point_name="Prompt",
        ordered_choices=[],
        primary_candidate_id=None,
        primary_state="uncovered",
        fallback_available=[],
    )
    explicit = planning.CoveragePlanEntry(
        entry_point_id=entry_point,
        entry_point_name="Prompt",
        ordered_choices=[],
        primary_candidate_id=None,
        primary_state="uncovered",
        fallback_available=[],
        target_id="target:explicit",
    )

    assert entry.effective_target_id == entry_point
    assert explicit.effective_target_id == "target:explicit"


def test_selection_limit_is_strictly_greater_than_cap() -> None:
    assignment = {
        "ep-a": SimpleNamespace(pattern_id="pattern"),
        "ep-b": SimpleNamespace(pattern_id="pattern"),
    }

    assert planning._derive_selection_limitations(assignment, 2) == []
    assert planning._derive_selection_limitations(assignment, 1) == ["ep-b"]


def test_exhaustive_target_entry_starts_choice_rank_at_zero() -> None:
    projected: ProjectedCandidate = get_projected_candidate()
    candidate = planning.QualifiedCandidate(projected=projected, accepted_filters=())

    queues, entries, primary_ids = planning._exhaustive_target_entries(
        [candidate],
        {candidate.entry_point_id: "Prompt"},
    )

    target_id = next(iter(queues))
    assert queues[target_id].choices[0].rank == 0
    assert entries[0].ordered_choices[0]["rank"] == 0
    assert primary_ids[target_id] == candidate.candidate_id


def test_canonical_filter_ids_accept_unique_sorted_records() -> None:
    records = (
        SimpleNamespace(filter_candidate_id="filter-a"),
        SimpleNamespace(filter_candidate_id="filter-b"),
    )

    planning._verify_canonical_filter_ids(records)


def test_canonical_filter_ids_names_only_duplicate_records() -> None:
    records = (
        SimpleNamespace(filter_candidate_id="filter-a"),
        SimpleNamespace(filter_candidate_id="filter-a"),
        SimpleNamespace(filter_candidate_id="filter-b"),
    )

    with pytest.raises(ValueError, match=r"\['filter-a'\]"):
        planning._verify_canonical_filter_ids(records)


def test_deserialized_plan_ref_defaults_missing_rank_to_zero(monkeypatch) -> None:
    projected = SimpleNamespace()
    monkeypatch.setattr(planning, "deserialize_plan_ref", lambda _ref: projected)
    monkeypatch.setattr(planning, "_verify_outer_identity", lambda _ref, _pc: None)
    monkeypatch.setattr(
        planning,
        "_deserialize_filter_records",
        lambda _raw: [],
    )
    monkeypatch.setattr(
        planning,
        "_verify_canonical_filter_ids",
        lambda _records: None,
    )
    monkeypatch.setattr(
        planning,
        "_verify_seed_ingress_agreement",
        lambda _records, _pc: None,
    )
    monkeypatch.setattr(
        planning,
        "_verify_outer_summaries",
        lambda _ref, _records, _pc: None,
    )

    result = planning.deserialize_qualified_candidate({})

    assert result.rank == 0
