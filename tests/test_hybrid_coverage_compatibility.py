"""Compatibility proof for the observational Phase 2 surfaces."""

from __future__ import annotations

from acceptance.qa.taxonomy_risk.correspondence_support import (
    run_workflow_compatibility,
)


def _assert_compatibility(workflow: str) -> None:
    """Require a real before/after public-command comparison."""
    observation = run_workflow_compatibility(workflow)
    assert observation["exit_match"], observation["detail"]
    assert observation["artifacts_match"], observation["detail"]
    assert observation["counts_match"], observation["detail"]
    assert observation["prompts_match"], observation["detail"]
    assert observation["sidecars_present"], observation["detail"]
    assert observation["no_phase2_output"], observation["detail"]


def test_generate_is_unchanged_with_phase2_sidecars() -> None:
    """The taxonomy/risk workflow keeps exact prompts, counts, and artifacts."""
    _assert_compatibility("taxonomy/risk")


def test_stpa_run_is_unchanged_with_phase2_sidecars() -> None:
    """The STPA workflow keeps exact prompts, counts, and artifacts."""
    _assert_compatibility("STPA")
