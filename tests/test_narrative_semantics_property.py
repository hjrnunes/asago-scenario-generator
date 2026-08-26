"""Property tests for narrative zone-sequence derivation.

These properties pin ``_derive_zone_sequence`` in
``pipeline.generate.narrative_semantics``: adjacent duplicate zones
collapse, non-adjacent revisits stay. They are offline and never contact
an LLM endpoint.
"""

from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.generate.narrative_semantics import (
    _derive_zone_sequence,
)

_MAX_EXAMPLES = 60
_ZONES = ("input", "reasoning", "tool_execution", "memory", "inter_agent", "outside")


def _collapse_adjacent(zones: list[str]) -> list[str]:
    """Independent adjacent-duplicate collapse used as the expected oracle."""
    sequence: list[str] = []
    for zone in zones:
        if not sequence or sequence[-1] != zone:
            sequence.append(zone)
    return sequence


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(zones=st.lists(st.sampled_from(_ZONES), min_size=0, max_size=12))
def test_zone_sequence_collapses_only_adjacent_duplicates(zones: list[str]) -> None:
    """Derivation matches adjacent collapse and preserves non-adjacent revisits."""
    steps = [SimpleNamespace(zone=zone) for zone in zones]
    derived = _derive_zone_sequence(steps)
    assert derived == _collapse_adjacent(zones)
    assert all(
        derived[index] != derived[index + 1] for index in range(len(derived) - 1)
    )
    if zones:
        assert derived[0] == zones[0]
        assert derived[-1] == zones[-1]
