"""Offline qualification of the cross-repo handoff round-trip checkpoint.

VAL-CROSS-001: corrected producer handoffs load and design in the consumer
without contract-kit changes, with zero model calls. Needs both packages on
the path (garak-venv python with ``PYTHONPATH=src:../asago-artifact-generator/src``).
"""

import pytest

crossrepo_roundtrip = pytest.importorskip("crossrepo_handoff_roundtrip")

pytest.importorskip("asago_artifact_generator")

from crossrepo_handoff_roundtrip import (  # noqa: E402
    AF_RUN1_DIR,
    DERIVED_AUTHORITY,
    OCCIAI_RUN_DIR,
    REVIEWED_AUTHORITY,
    build_derived_case,
    build_reviewed_case,
    round_trip,
)

_OcciaiFixtureMissing = not (
    AF_RUN1_DIR.is_dir() and OCCIAI_RUN_DIR.is_dir()
)


@pytest.mark.skipif(
    _OcciaiFixtureMissing,
    reason="sealed fixture runs under build/adaptive-runs/ are absent",
)
def test_reviewed_corrected_handoff_round_trips_and_compiles(tmp_path):
    """The reviewed (af-run1 fixture) corrected handoff loads with reviewed
    authority and designs to a compiled plan with positive fidelity."""
    handoff = build_reviewed_case()
    record = round_trip(
        handoff,
        profile_path=crossrepo_roundtrip.KLARNA_PROFILE_PATH,
        runtime_context_path=crossrepo_roundtrip.KLARNA_RUNTIME_CONTEXT_PATH,
        author_result={
            "stimulus_text": "Please refund 100.0 for ORD-101.",
            "requested_amount": 100.0,
            "rationale": "Checkpoint fixture stimulus.",
        },
        output_dir=tmp_path,
    )
    assert record["constraint_authorities"] == [REVIEWED_AUTHORITY]
    assert record["handoff_digest"] == handoff.content_digest
    assert record["compiled"] is True
    fidelity = record["fidelity"]
    assert fidelity["prerequisites_hold"]["answer"] is True
    assert fidelity["prerequisites_hold"]["authority"] == "observed"
    assert fidelity["detector_distinguishes"]["answer"] is True


@pytest.mark.skipif(
    _OcciaiFixtureMissing,
    reason="sealed fixture runs under build/adaptive-runs/ are absent",
)
def test_derived_corrected_handoff_never_publishes_reviewed_across_the_seam(
    tmp_path,
):
    """The derived (OcciAI fixture) corrected handoff carries the derived
    authority across the seam, and the consumer's design path runs to its
    honest typed outcome without any kit change."""
    handoff = build_derived_case()
    record = round_trip(
        handoff,
        profile_path=crossrepo_roundtrip.OCCIAI_PROFILE_PATH,
        runtime_context_path=crossrepo_roundtrip.OCCIAI_RUNTIME_CONTEXT_PATH,
        author_result={
            "stimulus_text": "Please commit draft DR-1 for PAT-104 to the EHR.",
            "rationale": "Checkpoint fixture stimulus.",
        },
        output_dir=tmp_path,
    )
    assert record["constraint_authorities"] == [DERIVED_AUTHORITY]
    assert record["handoff_digest"] == handoff.content_digest
    assert record["compiled"] is False
    assert record["exclusion"]["code"] == "unsupported-criterion-shape"
    assert record["exclusion"]["fidelity"]["prerequisites_hold"]["authority"] == (
        "unresolved"
    )
