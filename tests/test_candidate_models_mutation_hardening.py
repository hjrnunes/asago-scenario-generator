"""Adversarial tests for candidate-model validation and canonicalization."""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.candidate_models import (
    CandidateFunnel,
    CandidateOrigin,
)


def _valid_funnel_kwargs() -> dict[str, int]:
    """Return a valid funnel with nonzero headroom at each boundary."""
    return {
        "expanded_instances": 10,
        "unique_pre_rule_identities": 8,
        "rule_rejected": 2,
        "rule_transformed": 1,
        "post_rule_collapsed": 1,
        "filter_submitted": 5,
        "filter_accepted": 3,
        "qualified": 3,
        "selected": 3,
        "main_attempted": 3,
        "main_admitted": 2,
        "generation_failed": 1,
        "remediation_attempted": 0,
        "remediation_admitted": 0,
        "remediation_failed": 0,
        "attempted": 3,
        "admitted": 2,
        "quarantined": 1,
        "persisted_artifacts": 2,
    }


@pytest.mark.parametrize(
    "field_updates",
    [
        {"expanded_instances": 8, "unique_pre_rule_identities": 8},
        {"filter_accepted": 5, "filter_submitted": 5},
        {"projection_rejected": 3, "filter_accepted": 3},
        {"quarantined": 2, "admitted": 2},
    ],
)
def test_funnel_allows_subset_boundaries(
    field_updates: dict[str, int],
) -> None:
    """Inclusive subset boundaries remain valid at exact equality."""
    kwargs = _valid_funnel_kwargs()
    kwargs.update(field_updates)
    funnel = CandidateFunnel(**kwargs)
    assert funnel is not None


def test_funnel_reconciles_nonzero_main_and_remediation_counts() -> None:
    """Aggregate equations must add both nonzero generation paths."""
    kwargs = _valid_funnel_kwargs()
    kwargs.update(
        selected=2,
        qualified=2,
        main_attempted=2,
        main_admitted=1,
        generation_failed=1,
        remediation_attempted=1,
        remediation_admitted=1,
        remediation_failed=0,
        attempted=3,
        admitted=2,
        quarantined=2,
        persisted_artifacts=2,
    )
    funnel = CandidateFunnel(**kwargs)
    assert funnel.attempted == 3
    assert funnel.admitted == 2


def _origin(
    *,
    applied_rule: str | None = None,
    removed_technique_ids: tuple[str, ...] = (),
    removal_reasons: tuple[str, ...] = (),
) -> CandidateOrigin:
    """Construct a minimal candidate origin for canonicalization tests."""
    return CandidateOrigin(
        source_candidate_id="cand:source",
        original_technique_ids=("T2", "T1"),
        applied_rule=applied_rule,
        removed_technique_ids=removed_technique_ids,
        removal_reasons=removal_reasons,
        transform_stage="rule_pruning",
    )


