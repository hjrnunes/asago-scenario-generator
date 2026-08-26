"""Property tests for coverage-universe construction and seed helpers.

These properties pin attacker-accessible ingress classification, opaque
exhaustive target IDs, first-seen seed uniqueness, and convex pattern
costs. They are offline and never contact an LLM endpoint.
"""

from __future__ import annotations

import hashlib

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.pipeline.coverage_planning import _exhaustive_target_id
from asago_scenario_generator.pipeline.coverage_planning_flow import (
    _convex_pattern_cost,
)
from asago_scenario_generator.pipeline.coverage_planning_universe import (
    CoverageCompleteness,
    build_coverage_universe,
)
from asago_scenario_generator.pipeline.seeds import _dedupe_preserve_order

_MAX_EXAMPLES = 60
_NAMES = st.from_regex(r"[A-Za-z][A-Za-z0-9-]{2,11}", fullmatch=True)
_DIRECTIONS = st.sampled_from(("input", "output", "bidirectional"))
_CONTROLS = st.one_of(
    st.none(),
    st.sampled_from(("direct", "indirect", "system")),
)
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._",
    min_size=1,
    max_size=16,
)


def _profile(
    entries: list[EntryPoint],
    *,
    confirmed: bool = False,
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=entries,
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
        entry_point_completeness=(
            InventoryCompleteness.operator_confirmed_complete
            if confirmed
            else InventoryCompleteness.inferred_partial
        ),
        entry_point_evidence=["operator-review"] if confirmed else [],
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    specs=st.lists(
        st.tuples(_NAMES, _DIRECTIONS, _CONTROLS),
        min_size=1,
        max_size=5,
        unique_by=lambda item: item[0],
    )
)
def test_coverage_universe_partitions_every_entry_point(
    specs: list[tuple[str, str, str | None]],
) -> None:
    """Every profile entry is either a feasible target or a typed exclusion."""
    entries = [
        EntryPoint(name=name, direction=direction, controllability=control)
        for name, direction, control in specs
    ]
    profile = _profile(entries)
    universe = build_coverage_universe(profile)
    active = set(profile.zones_active)
    feasible_ids = {target.entry_point_id for target in universe.feasible_targets}
    excluded_ids = {target.entry_point_id for target in universe.excluded_targets}
    assert feasible_ids.isdisjoint(excluded_ids)
    assert feasible_ids | excluded_ids == {entry.entry_point_id for entry in entries}
    for entry in entries:
        if is_attacker_accessible_ingress(entry, active):
            assert entry.entry_point_id in feasible_ids
        else:
            assert entry.entry_point_id in excluded_ids
    assert universe.completeness is CoverageCompleteness.NOT_APPLICABLE
    assert build_coverage_universe(profile).feasible_target_ids == feasible_ids


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(candidate_id=_IDS)
def test_exhaustive_target_id_is_stable_and_opaque(candidate_id: str) -> None:
    """Durable target IDs hash the candidate identity and stay deterministic."""
    first = _exhaustive_target_id(candidate_id)
    digest = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    assert first == f"candidate-target:{digest}"
    assert first == _exhaustive_target_id(candidate_id)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(values=st.lists(_IDS, max_size=8))
def test_seed_dedupe_preserves_first_seen_order(values: list[str]) -> None:
    """Later duplicates never change first-seen seed order."""
    expected = list(dict.fromkeys(values))
    assert _dedupe_preserve_order(values) == expected
    assert _dedupe_preserve_order(values) == _dedupe_preserve_order(values)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    k=st.integers(min_value=0, max_value=8),
    cap=st.one_of(st.none(), st.integers(min_value=1, max_value=4)),
    scale=st.integers(min_value=1, max_value=20),
    penalty=st.integers(min_value=0, max_value=10),
)
def test_convex_pattern_cost_is_monotonic_in_flow_index(
    k: int, cap: int | None, scale: int, penalty: int
) -> None:
    """Later flow units never cost less than earlier ones."""
    current = _convex_pattern_cost(k, cap, scale, penalty)
    nxt = _convex_pattern_cost(k + 1, cap, scale, penalty)
    assert current == k * scale + (
        penalty * scale if cap is not None and k >= cap else 0
    )
    assert nxt >= current
    assert _convex_pattern_cost(k, cap, scale, penalty) == current
