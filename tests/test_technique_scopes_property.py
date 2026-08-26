"""Property tests for scenario and projected-step ATLAS identity scopes.

These properties pin the deterministic helpers in
``pipeline.technique_scopes``: first-seen uniqueness, pin-over-seed
classification, and narrative ATLAS reference extraction. They are
offline and never contact an LLM endpoint.
"""

from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.technique_scopes import (
    narrative_reference_ids,
    projected_step_mapping_ids,
    scenario_classification_ids,
    stable_unique,
)

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._",
    min_size=1,
    max_size=16,
)
_ATLAS = st.from_regex(r"AML\.T\d{4}(?:\.\d{3})?", fullmatch=True)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(values=st.lists(st.one_of(_IDS, st.just("")), max_size=8))
def test_stable_unique_preserves_first_seen_nonempty_order(values: list[str]) -> None:
    """Empty strings drop out; later duplicates never change first-seen order."""
    expected = list(dict.fromkeys(value for value in values if value))
    assert stable_unique(values) == expected
    assert stable_unique(values) == stable_unique(values)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    pins=st.one_of(st.none(), st.lists(_IDS, max_size=6)),
    seeds=st.lists(_IDS, max_size=6),
)
def test_scenario_classification_prefers_pins_over_seed(
    pins: list[str] | None, seeds: list[str]
) -> None:
    """Qualified pins win when present; otherwise the seed list is used."""
    result = scenario_classification_ids(pins, seeds)
    source = pins or seeds
    assert result == stable_unique(source)
    assert result == scenario_classification_ids(pins, seeds)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    techniques=st.lists(_ATLAS, min_size=1, max_size=4, unique=True),
    extra=st.lists(_IDS, max_size=3),
)
def test_narrative_reference_ids_extract_atlas_tokens(
    techniques: list[str], extra: list[str]
) -> None:
    """Bracketed or bare ATLAS tokens survive among unrelated prose."""
    summary = " ".join(f"[{item}]" for item in techniques)
    action = " ".join(techniques + extra)
    narrative = SimpleNamespace(
        summary=summary,
        steps=[SimpleNamespace(action=action, effect="no technique here")],
    )
    extracted = narrative_reference_ids(narrative)
    assert extracted == stable_unique(techniques)
    assert extracted == narrative_reference_ids(narrative)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    selected=st.lists(_ATLAS, min_size=1, max_size=4, unique=True),
    ignored=st.lists(_ATLAS, max_size=3),
)
def test_projected_step_mapping_ids_keep_exact_atlas_step_scope(
    selected: list[str], ignored: list[str]
) -> None:
    """Only exact ATLAS step-scope mappings contribute identity."""
    mappings = [
        SimpleNamespace(
            scope="step",
            mapping=SimpleNamespace(
                taxonomy="ATLAS", decision="exact", ids=tuple(selected)
            ),
        ),
        SimpleNamespace(
            scope="scenario",
            mapping=SimpleNamespace(
                taxonomy="ATLAS", decision="exact", ids=tuple(ignored)
            ),
        ),
        SimpleNamespace(
            scope="step",
            mapping=SimpleNamespace(
                taxonomy="OWASP", decision="exact", ids=tuple(ignored)
            ),
        ),
    ]
    block = SimpleNamespace(projected_mappings=tuple(mappings))
    assert projected_step_mapping_ids(block) == stable_unique(selected)
    assert projected_step_mapping_ids(block) == projected_step_mapping_ids(block)
