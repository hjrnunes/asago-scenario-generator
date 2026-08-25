"""Property tests for the taxonomy report section extraction helpers.

Hypothesis-driven invariants over the pure HTML-extraction helpers in
``acceptance/runtime_features/taxonomy_report_sections`` (``_stats``,
``_coverage_card_statuses``, ``_visible``, ``_section_region``):

- **Parse stability**: building canonical stat/coverage markup from
  (label, count) / (title, status) pairs and re-parsing it recovers the
  exact mapping.
- **Noise invariance**: unrelated markup between stat spans never changes
  the parsed mapping.
- **Robustness**: arbitrary text never raises and yields only
  non-negative integer counts.
- **Markup fixpoint**: one tag-stripping pass over the rendered text
  leaves it unchanged (no residual markup survives ``_visible``).
- **Entity decoding**: every entity in the ``_visible`` table decodes to
  its documented character.
- **Fail-loudly contract**: a missing section/card marker raises instead
  of silently matching an empty region.

The helpers are pure and offline; no LLM endpoint is contacted.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from runtime_features.taxonomy_report_sections._helpers import (  # noqa: E402
    _section_region,
    _stats,
    _visible,
)
from runtime_features.taxonomy_report_sections.then_coverage import (  # noqa: E402
    _coverage_card_statuses,
)

# ---------------------------------------------------------------------------
# Generation pools
# ---------------------------------------------------------------------------

_LABEL = st.text(
    alphabet=st.characters(
        blacklist_characters="<>&",
        blacklist_categories=("Cs",),
    ),
    min_size=1,
    max_size=20,
)
# Noise that cannot accidentally form a span or an entity.
_SAFE_NOISE = st.text(alphabet="abc XYZ0123!?.,;:", max_size=12)
_COUNT = st.integers(min_value=0, max_value=10**6)
_STATUS = st.sampled_from(sorted({"Covered", "Gap", "Partial", "Excluded"}))


@settings(max_examples=200)
@given(
    pairs=st.lists(
        st.tuples(_LABEL, _COUNT),
        min_size=0,
        max_size=20,
        unique_by=lambda p: p[0],
    )
)
def test_stats_round_trip_recovers_label_counts(
    pairs: list[tuple[str, int]],
) -> None:
    region = "".join(
        f'<span class="stat-number">{count}</span>\n'
        f'<span class="stat-label">{label}</span>'
        for label, count in pairs
    )
    assert _stats(region) == dict(pairs)


@settings(max_examples=200)
@given(
    pairs=st.lists(
        st.tuples(_LABEL, _COUNT),
        min_size=0,
        max_size=15,
        unique_by=lambda p: p[0],
    ),
    noise=st.lists(_SAFE_NOISE, min_size=0, max_size=30),
)
def test_stats_ignores_noise_between_spans(
    pairs: list[tuple[str, int]],
    noise: list[str],
) -> None:
    parts: list[str] = []
    for i, (label, count) in enumerate(pairs):
        parts.append(noise[i] if i < len(noise) else "")
        parts.append(
            f'<span class="stat-number">{count}</span>'
            f'<span class="stat-label">{label}</span>'
        )
    parts.append(" ".join(noise[len(pairs) :]))
    assert _stats("".join(parts)) == dict(pairs)


@given(region=st.text())
def test_stats_never_raises_and_is_nonnegative(region: str) -> None:
    parsed = _stats(region)
    assert all(isinstance(value, int) and value >= 0 for value in parsed.values())


@settings(max_examples=100)
@given(
    pairs=st.lists(
        st.tuples(_LABEL, _STATUS),
        min_size=0,
        max_size=12,
        unique_by=lambda p: p[0],
    )
)
def test_coverage_card_statuses_round_trip(
    pairs: list[tuple[str, str]],
) -> None:
    region = "".join(
        f'<span class="coverage-card-title">{title}</span>'
        f'<span class="coverage-status coverage-status-ok">{status}</span>'
        for title, status in pairs
    )
    assert _coverage_card_statuses(region) == dict(pairs)


@given(region=st.text())
def test_coverage_card_statuses_never_raises(region: str) -> None:
    parsed = _coverage_card_statuses(region)
    assert all(isinstance(status, str) for status in parsed.values())


@given(fragment=st.text())
def test_visible_leaves_no_residual_markup(fragment: str) -> None:
    visible = _visible(fragment)
    assert re.sub(r"<[^>]+>", "", visible) == visible


_ENTITIES = {
    "&rarr;": "→",
    "&ndash;": "–",
    "&middot;": "·",
    "&mdash;": "—",
    "&amp;": "&",
    "&quot;": '"',
    "&nbsp;": " ",
    "&#10;": " ",
    "&and;": "∧",
    "&or;": "∨",
    "&bull;": "•",
}


@given(entity=st.sampled_from(sorted(_ENTITIES)))
def test_visible_decodes_known_entities(entity: str) -> None:
    expected = _ENTITIES[entity]
    if expected == " ":
        # The trailing strip() trims whitespace-only output, so anchor
        # whitespace entities between non-space characters.
        assert _visible(f"a{entity}b") == f"a{expected}b"
    else:
        assert _visible(entity) == expected


@given(section_id=st.text(alphabet="abc123-", min_size=1, max_size=12))
def test_section_region_missing_marker_raises(section_id: str) -> None:
    with pytest.raises(AssertionError):
        _section_region('<html id="sec-other">no such section</html>', section_id)
