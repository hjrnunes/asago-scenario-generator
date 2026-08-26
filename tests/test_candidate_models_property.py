"""Property tests for candidate identity on the models leaf."""

from __future__ import annotations

import hashlib

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.candidate_models import compute_candidate_id

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=16,
)
_TECHNIQUES = st.lists(_IDS, max_size=6)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(seed_id=_IDS, entry_point_id=_IDS, technique_ids=_TECHNIQUES)
def test_candidate_id_is_deterministic_and_order_insensitive(
    seed_id: str,
    entry_point_id: str,
    technique_ids: list[str],
) -> None:
    """The same identity always yields the same cand:v2 digest."""
    first = compute_candidate_id(seed_id, entry_point_id, technique_ids)
    second = compute_candidate_id(seed_id, entry_point_id, list(reversed(technique_ids)))
    third = compute_candidate_id(
        seed_id, entry_point_id, [*technique_ids, *technique_ids]
    )
    assert first == second == third
    assert first.startswith("cand:v2:")
    hex_part = first.split(":")[2]
    assert len(hex_part) == 32
    int(hex_part, 16)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    seed_id=_IDS,
    entry_point_id=_IDS,
    technique_ids=_TECHNIQUES,
    other_seed=_IDS,
)
def test_candidate_id_changes_when_seed_changes(
    seed_id: str,
    entry_point_id: str,
    technique_ids: list[str],
    other_seed: str,
) -> None:
    """A different seed produces a different identity when the rest is fixed."""
    left = compute_candidate_id(seed_id, entry_point_id, technique_ids)
    right = compute_candidate_id(other_seed, entry_point_id, technique_ids)
    if seed_id == other_seed:
        assert left == right
        return
    assert left != right


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(seed_id=_IDS, entry_point_id=_IDS, technique_ids=_TECHNIQUES)
def test_candidate_id_matches_sha256_prefix(
    seed_id: str,
    entry_point_id: str,
    technique_ids: list[str],
) -> None:
    """The published format is a 128-bit prefix of the sorted unique digest."""
    sorted_tech = tuple(sorted(set(technique_ids)))
    identity = f"{seed_id}|{entry_point_id}|{','.join(sorted_tech)}"
    expected = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    assert compute_candidate_id(seed_id, entry_point_id, technique_ids) == (
        f"cand:v2:{expected}"
    )
