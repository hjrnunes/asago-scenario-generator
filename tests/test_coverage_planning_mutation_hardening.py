"""Focused adversarial coverage for coverage-planning helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline import coverage_planning as planning


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
