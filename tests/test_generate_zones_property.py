"""Property tests for generate-stage zone indexing and active-zone projection.

These properties pin ``projected_boundary_by_id`` and
``active_narrative_zones`` in ``pipeline.generate.zones``. They are
offline and never contact an LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.generate.zones import (
    OUTSIDE_ZONE,
    active_narrative_zones,
    projected_boundary_by_id,
)

_MAX_EXAMPLES = 60
_IDS = st.from_regex(r"[a-z][a-z0-9._-]{0,11}", fullmatch=True)
_BOUNDARIES = st.sampled_from(("outside", "crossing", "inside", None))
_ZONES = st.sampled_from(
    ("outside", "input", "reasoning", "tool_execution", "memory", "inter_agent")
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    records=st.lists(
        st.one_of(
            st.fixed_dictionaries(
                {"step_id": _IDS, "boundary_position": _BOUNDARIES}
            ),
            st.just("junk"),
            st.fixed_dictionaries({"step_id": st.integers(), "boundary_position": _BOUNDARIES}),
            st.fixed_dictionaries({"boundary_position": _BOUNDARIES}),
        ),
        max_size=8,
    )
)
def test_projected_boundary_by_id_indexes_only_string_step_ids(
    records: list[object],
) -> None:
    """Malformed transport records never appear in the boundary index."""
    expected: dict[str, str | None] = {}
    for item in records:
        if isinstance(item, dict) and isinstance(item.get("step_id"), str):
            expected[item["step_id"]] = item.get("boundary_position")
    assert projected_boundary_by_id(records) == expected
    assert projected_boundary_by_id(records) == projected_boundary_by_id(records)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(zones=st.lists(_ZONES, max_size=8))
def test_active_narrative_zones_drops_outside_and_preserves_order(
    zones: list[str],
) -> None:
    """``outside`` is never credited as internal traversal."""
    expected = [zone for zone in zones if zone != OUTSIDE_ZONE]
    assert active_narrative_zones(zones) == expected
    assert active_narrative_zones(zones) == active_narrative_zones(zones)
    if OUTSIDE_ZONE not in zones:
        assert active_narrative_zones(zones) == list(zones)
