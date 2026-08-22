"""Ordinal wire protocol for advisory candidate filtering."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.pipeline.candidates import (
    BatchFilterDraftV2,
    FilterDecisionDraftV2,
    build_filter_map_response_model,
    reconcile_filter_map,
    reconcile_filter_ordinals,
)


def test_filter_draft_accepts_only_request_local_ordinals() -> None:
    draft = BatchFilterDraftV2(
        decisions=(
            FilterDecisionDraftV2(
                candidate="c0",
                relevant=True,
                rationale="The entry path supports the pattern.",
            ),
            FilterDecisionDraftV2(
                candidate="c1",
                relevant=False,
                rationale="The technique is incompatible.",
            ),
        )
    )

    decisions = reconcile_filter_ordinals(draft, ("c0", "c1"))

    assert decisions == {"c0": draft.decisions[0], "c1": draft.decisions[1]}
    assert "candidate_id" not in BatchFilterDraftV2.model_json_schema()


def test_filter_draft_rejects_unknown_missing_and_duplicate_ordinals() -> None:
    unknown = BatchFilterDraftV2(
        decisions=(FilterDecisionDraftV2(candidate="c9", relevant=True, rationale="x"),)
    )
    with pytest.raises(ValueError, match="unknown.*c9.*missing.*c0"):
        reconcile_filter_ordinals(unknown, ("c0",))

    duplicate = BatchFilterDraftV2(
        decisions=(
            FilterDecisionDraftV2(candidate="c0", relevant=True, rationale="x"),
            FilterDecisionDraftV2(candidate="c0", relevant=False, rationale="y"),
        )
    )
    with pytest.raises(ValueError, match="duplicate.*c0"):
        reconcile_filter_ordinals(duplicate, ("c0",))


def test_filter_decision_rejects_canonical_candidate_id() -> None:
    with pytest.raises(ValidationError):
        FilterDecisionDraftV2(
            candidate="cand:v2:0123456789abcdef0123456789abcdef",
            relevant=True,
            rationale="x",
        )


def test_filter_map_schema_requires_each_request_local_handle_once() -> None:
    response_model = build_filter_map_response_model(("c0", "c1"))
    schema = response_model.model_json_schema()

    assert set(schema["required"]) == {"c0", "c1"}
    assert set(schema["properties"]) == {"c0", "c1"}
    assert schema["additionalProperties"] is False

    draft = response_model.model_validate(
        {
            "c0": {"relevant": True, "rationale": "Relevant direct ingress."},
            "c1": {"relevant": False, "rationale": "Incompatible technique."},
        }
    )
    decisions = reconcile_filter_map(draft, ("c0", "c1"))

    assert decisions["c0"].relevant is True
    assert decisions["c1"].relevant is False


def test_filter_map_rejects_missing_or_unknown_handles_in_schema() -> None:
    response_model = build_filter_map_response_model(("c0", "c1"))

    with pytest.raises(ValidationError):
        response_model.model_validate(
            {"c0": {"relevant": True, "rationale": "Only one decision."}}
        )
    with pytest.raises(ValidationError):
        response_model.model_validate(
            {
                "c0": {"relevant": True, "rationale": "First."},
                "c1": {"relevant": False, "rationale": "Second."},
                "c2": {"relevant": True, "rationale": "Unknown."},
            }
        )
