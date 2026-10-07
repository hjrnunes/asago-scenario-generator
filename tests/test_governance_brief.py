"""Governance briefs share the brief model without changing pattern briefs."""

from __future__ import annotations

import hashlib
import json

import pytest

from asago_scenario_generator.models.obligation_consideration import (
    NeutralObligationBrief,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_governance_briefs,
    build_neutral_briefs,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.governance import _pattern

# Captured from the brief builder at 04a926bd, before the kind field existed.
PATTERN_BRIEF_DIGEST = (
    "a1e686a54926c3b5c9a92c506e94ea2708240415b4f3b25f9f0785977be02620"
)
PATTERN_BRIEF_JSON_SHA256 = (
    "48171f83240f65d2f3eb13b17f45a9a08e6070e57aef42ea44b1e13d4db85857"
)
PATTERN_BRIEF_JSON_LENGTH = 2949


def _plan_with_governance_row():
    # risk-b has no mapping to the pattern, so the planner keeps it as a
    # governance-only row.
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": _pattern().id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    return make_plan(risk_ids=("risk-a", "risk-b"), mappings=mappings)


def test_pattern_brief_bytes_and_digest_match_the_pre_kind_capture() -> None:
    brief = build_neutral_briefs(make_plan(), (_pattern(),))[0]

    raw = brief.model_dump_json()
    assert brief.semantic_digest == PATTERN_BRIEF_DIGEST
    assert hashlib.sha256(raw.encode()).hexdigest() == PATTERN_BRIEF_JSON_SHA256
    assert len(raw) == PATTERN_BRIEF_JSON_LENGTH
    assert "kind" not in json.loads(raw)
    assert brief.kind == "pattern"


def test_pattern_brief_loaded_from_pre_kind_bytes_keeps_its_digest() -> None:
    brief = build_neutral_briefs(make_plan(), (_pattern(),))[0]
    reloaded = NeutralObligationBrief.model_validate_json(brief.model_dump_json())

    assert reloaded == brief
    assert reloaded.semantic_digest == PATTERN_BRIEF_DIGEST


def test_governance_brief_carries_the_risk_and_no_pattern() -> None:
    plan = _plan_with_governance_row()

    briefs = build_governance_briefs(plan, risk_ids=("risk-b",))

    assert len(briefs) == 1
    brief = briefs[0]
    assert brief.kind == "governance"
    assert brief.risk_ref.risk_id == "risk-b"
    assert brief.attack_pattern_id is None
    assert brief.attack_pattern_name is None
    assert brief.attack_pattern_description is None
    assert brief.attack_pattern_semantic_digest is None
    assert brief.taxonomy_chain == ()
    assert brief.prerequisite_capabilities is None
    assert brief.plan_digest == plan.semantic_digest
    brief.assert_integrity()
    assert json.loads(brief.model_dump_json())["kind"] == "governance"


def test_governance_brief_round_trips_with_a_stable_digest() -> None:
    brief = build_governance_briefs(_plan_with_governance_row(), ("risk-b",))[0]

    reloaded = NeutralObligationBrief.model_validate_json(brief.model_dump_json())

    assert reloaded == brief
    assert reloaded.semantic_digest == brief.semantic_digest


def test_governance_briefs_cover_only_the_requested_governance_rows() -> None:
    plan = _plan_with_governance_row()

    assert build_governance_briefs(plan, risk_ids=()) == ()
    # risk-a resolved to a pattern, so it is not a governance-only row.
    assert build_governance_briefs(plan, risk_ids=("risk-a",)) == ()
    assert build_governance_briefs(plan, risk_ids=("unknown",)) == ()


def test_governance_brief_rejects_a_pattern_identity() -> None:
    brief = build_governance_briefs(_plan_with_governance_row(), ("risk-b",))[0]
    payload = brief.model_dump(mode="json", exclude={"semantic_digest"})
    payload["attack_pattern_id"] = "AP-X"

    with pytest.raises(ValueError, match="governance brief"):
        NeutralObligationBrief.model_validate(payload)


def test_pattern_brief_rejects_a_missing_pattern_identity() -> None:
    brief = build_neutral_briefs(make_plan(), (_pattern(),))[0]
    payload = brief.model_dump(mode="json", exclude={"semantic_digest"})
    payload["attack_pattern_id"] = None

    with pytest.raises(ValueError):
        NeutralObligationBrief.model_validate(payload)
