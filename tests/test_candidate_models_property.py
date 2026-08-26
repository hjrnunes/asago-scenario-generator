"""Property tests for candidate identity on the models leaf."""

from __future__ import annotations

import hashlib

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    RemovalDecision,
    _canonicalize_and_dedup_origins,
    compute_candidate_id,
)

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
    second = compute_candidate_id(
        seed_id, entry_point_id, list(reversed(technique_ids))
    )
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


_STAGES = st.sampled_from(("expansion", "rule_pruning", "capping"))
_RULES = st.one_of(st.none(), st.sampled_from(("direct_vs_indirect", "threat_prereq")))
_REASONS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz ",
    min_size=1,
    max_size=24,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    source_id=_IDS,
    original=_TECHNIQUES,
    removed=_TECHNIQUES,
    stage=_STAGES,
    rule=_RULES,
    reason=_REASONS,
)
def test_origin_canonicalization_is_order_insensitive_and_idempotent(
    source_id: str,
    original: list[str],
    removed: list[str],
    stage: str,
    rule: str | None,
    reason: str,
) -> None:
    """Reversed origin fields collapse to one canonical provenance record."""
    decisions = tuple(
        RemovalDecision(technique_id=tid, rule=rule or "none", reason=reason)
        for tid in removed
    )
    first = CandidateOrigin(
        source_candidate_id=source_id,
        original_technique_ids=tuple(original),
        applied_rule=rule,
        removed_technique_ids=tuple(removed),
        removal_reasons=tuple(reason for _ in removed),
        removal_decisions=decisions,
        transform_stage=stage,
    )
    reversed_origin = CandidateOrigin(
        source_candidate_id=source_id,
        original_technique_ids=tuple(reversed(original)),
        applied_rule=rule,
        removed_technique_ids=tuple(reversed(removed)),
        removal_reasons=tuple(reason for _ in removed),
        removal_decisions=tuple(reversed(decisions)),
        transform_stage=stage,
    )
    canonical = _canonicalize_and_dedup_origins([first, reversed_origin, first])
    again = _canonicalize_and_dedup_origins(canonical)
    assert len(canonical) == 1
    assert again == canonical
    assert canonical[0].original_technique_ids == tuple(sorted(original))
    assert canonical[0].removed_technique_ids == tuple(sorted(removed))
