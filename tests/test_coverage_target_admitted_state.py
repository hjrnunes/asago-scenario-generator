"""An admitted coverage target names its admitted candidate and stops there."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.pipeline.coverage_planning import (
    AcceptedFilterRecord,
    QualifiedCandidate,
)
from asago_scenario_generator.pipeline.persistence_plan import (
    CoverageTargetEntry,
    TargetState,
)
from tests.helpers.projection_factory import get_projected_candidates
from tests.test_cmps4_coverage_planning import _make_fseed


def _choices() -> list[dict]:
    refs = []
    for rank, projected in enumerate(get_projected_candidates()):
        seed = _make_fseed(
            entry_point_id=projected.canonical_ingress.entry_point_id,
            candidate_id=f"filter-{rank}",
        )
        refs.append(
            QualifiedCandidate(
                projected=projected,
                accepted_filters=(AcceptedFilterRecord.from_seed(seed),),
                rank=rank,
            ).to_plan_ref()
        )
    return refs


def _entry(
    *,
    attempted: int,
    admitted: int | None,
    state: TargetState,
) -> CoverageTargetEntry:
    choices = _choices()
    ids = [choice["candidate_id"] for choice in choices]
    return CoverageTargetEntry.model_validate(
        {
            "entry_point_id": choices[0]["entry_point_id"],
            "entry_point_name": "user prompt",
            "ordered_choices": choices,
            "primary_candidate_id": ids[0],
            "attempted_candidate_ids": ids[:attempted],
            "admitted_candidate_id": None if admitted is None else ids[admitted],
            "target_state": state.value,
            "fallback_available": [],
        }
    )


@pytest.mark.parametrize("admitted", [0, 1])
def test_admitted_target_ends_at_its_admitted_candidate(admitted: int) -> None:
    entry = _entry(
        attempted=admitted + 1, admitted=admitted, state=TargetState.admitted
    )

    assert entry.admitted_candidate_id == entry.attempted_candidate_ids[-1]
    assert entry.target_state is TargetState.admitted


def test_admitted_candidate_requires_admitted_state() -> None:
    with pytest.raises(
        ValidationError, match="admitted candidate requires target_state=admitted"
    ):
        _entry(attempted=1, admitted=0, state=TargetState.selected)


def test_admitted_target_rejects_attempts_after_admission() -> None:
    with pytest.raises(
        ValidationError, match="admitted target cannot contain later attempts"
    ):
        _entry(attempted=2, admitted=0, state=TargetState.admitted)


def test_admitted_state_requires_an_admitted_candidate() -> None:
    with pytest.raises(
        ValidationError, match="target_state=admitted requires admitted_candidate_id"
    ):
        _entry(attempted=1, admitted=None, state=TargetState.admitted)
