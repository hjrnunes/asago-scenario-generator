"""Property tests for the inward finalization-contract leaf.

These properties pin choice-queue ordering, identity matching, and
retry-owner selection.  They are offline and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.finalization_contracts import (
    GENERATION_ORDER,
    MAX_TARGET_CHOICES,
    CandidateValidation,
    GeneratedStage,
    LifecycleViolation,
    _candidate_identity_violation,
    earliest_generated_owner,
    ordered_target_choice_refs,
)

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=12,
)


@dataclass
class _ChoiceEntry:
    ordered_choices: list[dict[str, object]]
    fallback_available: list[dict[str, object]]
    primary_candidate_id: str | None


def _ref(candidate_id: str) -> dict[str, object]:
    return {"candidate_id": candidate_id}


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    primary=_IDS,
    fallbacks=st.lists(_IDS, max_size=6),
    extras=st.lists(_IDS, max_size=4),
)
def test_ordered_target_choice_refs_are_primary_first_unique_and_bounded(
    primary: str,
    fallbacks: list[str],
    extras: list[str],
) -> None:
    """Primary leads, later ids stay unique, and the queue never exceeds the cap."""
    ordered = [_ref(primary), *(_ref(item) for item in extras)]
    available = [_ref(item) for item in fallbacks]
    refs = ordered_target_choice_refs(
        _ChoiceEntry(ordered, available, primary)
    )
    ids = [ref["candidate_id"] for ref in refs]
    assert ids[0] == primary
    assert len(ids) == len(set(ids))
    assert len(ids) <= MAX_TARGET_CHOICES
    expected = [primary]
    for item in fallbacks:
        if item not in expected:
            expected.append(item)
        if len(expected) == MAX_TARGET_CHOICES:
            break
    assert ids == expected


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(left=_IDS, right=_IDS)
def test_candidate_identity_mismatch_is_nonretryable(
    left: str, right: str
) -> None:
    """A drifted revalidated identity is always a nonretryable violation."""
    violation = _candidate_identity_violation(left, right)
    if left == right:
        assert violation is None
        return
    assert violation is not None
    assert violation.code == "candidate_identity_mismatch"
    assert violation.retryable is False
    assert left in violation.detail
    assert right in violation.detail


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    candidate_id=st.one_of(st.none(), _IDS),
    extra=_IDS,
)
def test_validation_identity_helper_reads_live_candidate(
    candidate_id: str | None, extra: str
) -> None:
    """Identity extraction uses the live candidate and ignores missing ids."""

    class _Candidate:
        def __init__(self, value: str) -> None:
            self.candidate_id = value

    from asago_scenario_generator.pipeline.finalization_contracts import (
        _canonical_candidate_id,
    )

    if candidate_id is None:
        validation = CandidateValidation(candidate=object())
        assert _canonical_candidate_id(validation) is None
        return
    validation = CandidateValidation(candidate=_Candidate(candidate_id))
    assert _canonical_candidate_id(validation) == candidate_id
    assert _canonical_candidate_id(CandidateValidation(candidate=None)) is None
    assert extra  # keep the extra draw used for diversity


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    owners=st.lists(
        st.sampled_from(tuple(GENERATION_ORDER) + (None,)),
        max_size=6,
    ),
    retryable=st.lists(st.booleans(), min_size=1, max_size=6),
)
def test_earliest_generated_owner_is_generation_order_or_none(
    owners: list[GeneratedStage | None],
    retryable: list[bool],
) -> None:
    """Any nonretryable violation wins; otherwise the earliest generated owner."""
    if not owners:
        assert earliest_generated_owner(()) is None
        return
    flags = (retryable * len(owners))[: len(owners)]
    violations = tuple(
        LifecycleViolation(
            detail="x",
            owner=owner,
            retryable=flag,
        )
        for owner, flag in zip(owners, flags, strict=False)
    )
    result = earliest_generated_owner(violations)
    if any(not item.can_retry_generation for item in violations):
        assert result is None
        return
    present = {item.owner for item in violations}
    assert result == next(
        (stage for stage in GENERATION_ORDER if stage in present),
        None,
    )
