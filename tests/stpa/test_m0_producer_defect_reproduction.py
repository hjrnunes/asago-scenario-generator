"""Reproduce the historical producer defects assigned to milestone M0.

These tests intentionally inspect sanitized snapshots of historical calls and
published artifacts. They document the defects without re-running a model
call, mutating the current producer behavior, or depending on ignored
qualification output under ``build/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "m0-producer-defects"


def _load_json(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _load_yaml(name: str) -> dict:
    return yaml.safe_load((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_s01_historical_publication_drops_grounded_semantic_proposition() -> None:
    """SCN-002 loses its patient and operation grounding at publication."""
    raw_call = _load_json("s01-scn-002-authoring.json")
    published = _load_yaml("s01-scn-002-published.yaml")

    assert raw_call["scenario_id"] == published["scenario_id"] == "SCN-002"
    raw_proposition = raw_call["response_content"]["unsafe_outcome"][
        "semantic_proposition"
    ]
    published_criterion = published["semantic_failure_criterion"]

    for grounded_detail in ("PAT-104", "get_education"):
        assert grounded_detail in raw_proposition
        assert grounded_detail not in published_criterion

    assert published_criterion != raw_proposition
    assert "unsafe behavior under examination occurs" in published_criterion


def test_p01_historical_revision_leaves_subject_mismatch_edge_failing() -> None:
    """The old revision response adds constraints but does not repair SC-1/H-1."""
    prompt = (FIXTURE_DIR / "p01-stage1a-revision-before-fix.j2").read_text(
        encoding="utf-8"
    )
    original_graph = _load_yaml("p01-original-graph.yaml")
    response = _load_json("p01-historical-revision-response.json")
    gates = _load_yaml("p01-historical-gates.yaml")

    assert "security_constraint_additions" in prompt
    assert "share no subject phrase" not in prompt
    assert "not by editing the existing constraint" not in prompt
    assert response["security_constraint_additions"]

    original_constraint = next(
        item
        for item in original_graph["security_constraints"]
        if item["constraint_id"] == "SC-1"
    )
    edited_constraint = next(
        item
        for item in response["security_constraint_edits"]
        if item["constraint_id"] == "SC-1"
    )
    assert edited_constraint["rule"] == original_constraint["rule"]
    assert edited_constraint["related_hazards"] == ["H-1"]

    assert (
        "constraint SC-1 and hazard H-1 share no subject phrase"
        in gates["failing_checks"]
    )
    assert gates["revision_attempted"] is True
    assert gates["revision_applied"] is False
    assert gates["passed"] is False
