"""Behavior of the semantic-generation summary projection."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline.finalization_contracts import GeneratedStage
from asago_scenario_generator.pipeline.persistence_summary import (
    _semantic_outcome,
    build_semantic_generation_summary,
)

_FALLBACK = "presentation_fallback:actor"


def _attempt(
    sequence: int,
    candidate_id: str,
    stage: GeneratedStage,
    *,
    semantic: dict[str, Any] | None = None,
    failed: bool = False,
    invocation_index: int = 0,
) -> SimpleNamespace:
    carrier = SimpleNamespace(semantic_evidence=semantic)
    return SimpleNamespace(
        sequence=sequence,
        candidate_id=candidate_id,
        stage=stage,
        invocation_index=invocation_index,
        call=None if failed else carrier,
        failure=carrier if failed else None,
    )


def _accepted(*warnings: str) -> dict[str, Any]:
    return {"attempts": [{"result": "accepted"}], "warnings": list(warnings)}


def _inventory(
    attempts: list[SimpleNamespace], admitted_ids: tuple[str, ...] = ()
) -> SimpleNamespace:
    return SimpleNamespace(
        stage_attempts=attempts,
        admission_decisions=[
            SimpleNamespace(candidate_id=cid, admitted=True) for cid in admitted_ids
        ],
    )


def test_semantic_outcome_without_evidence_reports_missing_evidence() -> None:
    assert _semantic_outcome(None) == ("missing_semantic_evidence", [])


def test_semantic_outcome_uses_the_latest_attempt_result_and_stringifies_warnings() -> (
    None
):
    semantic = {
        "attempts": [{"result": "retry"}, {"result": "accepted"}],
        "warnings": ["first", 2],
    }
    assert _semantic_outcome(semantic) == ("accepted", ["first", "2"])


def test_semantic_outcome_without_attempts_reports_missing_attempt_result() -> None:
    assert _semantic_outcome({"attempts": []}) == ("missing_attempt_result", [])
    assert _semantic_outcome({}) == ("missing_attempt_result", [])


def test_semantic_outcome_with_empty_result_reports_missing_attempt_result() -> None:
    assert _semantic_outcome({"attempts": [{"result": ""}]}) == (
        "missing_attempt_result",
        [],
    )


def test_summary_of_empty_inventory_lists_required_stages_only() -> None:
    assert build_semantic_generation_summary(_inventory([])) == {
        "schema_version": "1",
        "required_stages": ["actor", "narrative", "tree", "behavior"],
        "candidates": {},
        "stage_records": [],
    }


def test_summary_marks_complete_provider_semantics_when_every_stage_is_accepted() -> (
    None
):
    attempts = [
        _attempt(index, "cand-1", stage, semantic=_accepted())
        for index, stage in enumerate(GeneratedStage)
    ]
    summary = build_semantic_generation_summary(_inventory(attempts, ("cand-1",)))
    assert summary["candidates"]["cand-1"] == {
        "admitted": True,
        "complete_provider_semantics": True,
        "presentation_fallbacks": [],
        "stages": {stage.value: "accepted" for stage in GeneratedStage},
    }


def test_summary_orders_records_by_sequence_and_reports_missing_stage_as_incomplete() -> (
    None
):
    later = _attempt(5, "cand-1", GeneratedStage.tree, semantic=_accepted())
    earlier = _attempt(
        2, "cand-1", GeneratedStage.actor, semantic=None, invocation_index=3
    )
    summary = build_semantic_generation_summary(_inventory([later, earlier]))
    assert [record["stage"] for record in summary["stage_records"]] == [
        "actor",
        "tree",
    ]
    assert summary["stage_records"][0] == {
        "candidate_id": "cand-1",
        "stage": "actor",
        "invocation_index": 3,
        "outcome": "missing_semantic_evidence",
        "semantic_evidence": None,
    }
    candidate = summary["candidates"]["cand-1"]
    assert candidate["admitted"] is False
    assert candidate["complete_provider_semantics"] is False
    assert candidate["stages"] == {
        "actor": "missing_semantic_evidence",
        "tree": "accepted",
    }


def test_summary_reads_semantic_evidence_from_the_failure_carrier() -> None:
    attempt = _attempt(
        0,
        "cand-1",
        GeneratedStage.actor,
        semantic={"attempts": [{"result": "rejected"}]},
        failed=True,
    )
    summary = build_semantic_generation_summary(_inventory([attempt]))
    assert summary["candidates"]["cand-1"]["stages"] == {"actor": "rejected"}


def test_summary_without_call_or_failure_reports_missing_semantic_evidence() -> None:
    attempt = SimpleNamespace(
        sequence=0,
        candidate_id="cand-1",
        stage=GeneratedStage.actor,
        invocation_index=0,
        call=None,
        failure=None,
    )
    summary = build_semantic_generation_summary(_inventory([attempt]))
    assert summary["stage_records"][0]["outcome"] == "missing_semantic_evidence"


def test_summary_keeps_each_presentation_fallback_once_and_drops_other_warnings() -> (
    None
):
    attempts = [
        _attempt(
            0,
            "cand-1",
            GeneratedStage.actor,
            semantic=_accepted(_FALLBACK, "unrelated warning"),
        ),
        _attempt(
            1,
            "cand-1",
            GeneratedStage.narrative,
            semantic=_accepted(_FALLBACK, "presentation_fallback:narrative"),
        ),
    ]
    candidate = build_semantic_generation_summary(_inventory(attempts))["candidates"][
        "cand-1"
    ]
    assert candidate["presentation_fallbacks"] == [
        _FALLBACK,
        "presentation_fallback:narrative",
    ]


def test_summary_tracks_each_candidate_separately() -> None:
    attempts = [
        _attempt(0, "cand-1", GeneratedStage.actor, semantic=_accepted()),
        _attempt(1, "cand-2", GeneratedStage.actor, semantic=_accepted(_FALLBACK)),
    ]
    summary = build_semantic_generation_summary(_inventory(attempts, ("cand-2",)))
    assert summary["candidates"]["cand-1"]["admitted"] is False
    assert summary["candidates"]["cand-1"]["presentation_fallbacks"] == []
    assert summary["candidates"]["cand-2"]["admitted"] is True
    assert summary["candidates"]["cand-2"]["presentation_fallbacks"] == [_FALLBACK]
