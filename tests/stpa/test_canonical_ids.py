"""Tests for deterministic canonical ID allocation."""

from __future__ import annotations

from asago_scenario_generator.stpa.infra.canonical_ids import (
    allocate_canonical_ids,
    next_canonical_number,
)


def test_next_number_follows_the_highest_matching_id() -> None:
    ids = ["H-2", "H-10", "SC-40", "H-x", "H-3a", "pre-H-50"]
    assert next_canonical_number("H-", ids) == 11
    assert next_canonical_number("SC-", ids) == 41
    assert next_canonical_number("L-", ids) == 1


def test_allocation_keeps_handle_order_and_skips_used_numbers() -> None:
    mapping = allocate_canonical_ids("SC-", {"SC-1", "SC-4", "H-9"}, ["b", "a"])
    assert mapping == {"b": "SC-5", "a": "SC-6"}
    assert list(mapping) == ["b", "a"]


def test_allocation_starts_at_one_without_used_ids() -> None:
    assert allocate_canonical_ids("L-", (), ["x", "y"]) == {"x": "L-1", "y": "L-2"}


def test_repeated_handle_consumes_a_number_and_keeps_the_last() -> None:
    mapping = allocate_canonical_ids("H-", ["H-1"], ["a", "a", "b"])
    assert mapping == {"a": "H-3", "b": "H-4"}


def test_allocation_does_not_mutate_used_ids() -> None:
    used = {"H-1"}
    allocate_canonical_ids("H-", used, ["a"])
    assert used == {"H-1"}
