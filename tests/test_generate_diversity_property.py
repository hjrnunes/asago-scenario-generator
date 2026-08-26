"""Property tests for generate-stage diversity helpers.

These properties pin ``assign_entry_point``, affinity scoring, and
structural-phase extraction in ``pipeline.generate.diversity``. They are
offline and never contact an LLM endpoint.
"""

from __future__ import annotations

from collections import Counter

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep
from asago_scenario_generator.pipeline.generate.constants import _PHASE_KEYWORDS
from asago_scenario_generator.pipeline.generate.diversity import (
    assign_entry_point,
    compute_entry_point_affinity,
    extract_structural_pattern,
)

_MAX_EXAMPLES = 60
_LABELS = st.from_regex(r"[A-Za-z][A-Za-z0-9-]{2,11}", fullmatch=True)
_ZONES = st.sampled_from(
    ("input", "reasoning", "tool_execution", "memory", "inter_agent")
)
_KNOWN_PHASES = frozenset(_PHASE_KEYWORDS) | {"other"}
_ACTIONS = st.sampled_from(
    (
        "I inject a payload",
        "I poison the retrieved documents",
        "The result persists in memory",
        "I bypass the reviewer",
        "I probe the exposed API",
        "unrelated wording",
    )
)


def _narrative(actions: list[str]) -> NarrativeLayer:
    steps = [
        NarrativeStep(
            step_number=index + 1,
            zone="input",
            action=action,
            effect=f"effect-{index}",
            projected_step_ids=(f"step.{index}",),
        )
        for index, action in enumerate(actions)
    ]
    return NarrativeLayer(
        title="Test",
        summary="A test scenario.",
        entry_point="chat",
        zone_sequence=["input"],
        steps=steps,
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    entry_points=st.lists(_LABELS, max_size=5, unique=True),
    zones=st.lists(_ZONES, max_size=5),
    total_seeds=st.integers(min_value=0, max_value=20),
)
def test_assign_entry_point_stays_inside_the_inventory(
    entry_points: list[str], zones: list[str], total_seeds: int
) -> None:
    """Assignment never invents an entry point outside the supplied list."""
    chosen = assign_entry_point(entry_points, zones, Counter(), total_seeds)
    affinity = compute_entry_point_affinity(entry_points, zones)
    assert set(affinity) == set(entry_points)
    assert all(0.0 <= score <= 1.0 for score in affinity.values())
    if not entry_points:
        assert chosen is None
        return
    assert chosen in entry_points
    assert assign_entry_point(entry_points, zones, Counter(), total_seeds) == chosen


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(actions=st.lists(_ACTIONS, min_size=1, max_size=6))
def test_structural_pattern_collapses_consecutive_duplicate_phases(
    actions: list[str],
) -> None:
    """Phase extraction is idempotent and never emits consecutive duplicates."""
    pattern = extract_structural_pattern(_narrative(actions))
    phases = pattern.split("->") if pattern else []
    assert all(phase in _KNOWN_PHASES for phase in phases)
    assert all(left != right for left, right in zip(phases, phases[1:]))
    assert extract_structural_pattern(_narrative(actions)) == pattern
