"""Stage 1a section-aware correction.

A correction keeps the sections it leaves empty, replaces the sections it
supplies as complete collections, and fails closed on malformed request-local
handles before any repair request.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _merge_loss_analysis_correction,
    _Stage1aGapProviderDraft,
    derive_loss_analysis,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient

_PRIOR_RISK_LOSS = "Baseline request integrity is lost."
_PRIOR_USE_CASE_LOSS = "Service continuity is lost."
_PRIOR_HAZARD = "The request state becomes unsafe."
_PRIOR_CONSTRAINT = "The request must remain authorized."
_OBSOLETE_HAZARD = "The initial gap state is unsafe."
_OBSOLETE_CONSTRAINT = "The obsolete gap condition must be prevented."
_REPLACEMENT_HAZARD = "The corrected request state is unsafe."
_REPLACEMENT_CONSTRAINT = "The corrected request condition must be prevented."


def _risk_card() -> RiskCard:
    return RiskCard(
        risk_id="neutral-risk",
        risk_name="Request integrity risk",
        risk_description="A submitted request could be processed incorrectly.",
        taxonomy="neutral",
        confidence=0.9,
        grounding_confidence="high",
    )


def _risk_response(*, duplicate: bool = False) -> dict[str, Any]:
    loss = {
        "handle": "risk_base_loss",
        "description": _PRIOR_RISK_LOSS,
        "provenance": "risk_card",
        "source_risk_cards": ["neutral-risk"],
    }
    return {
        "risk_card_losses": [loss],
        "use_case_losses": [copy.deepcopy(loss)] if duplicate else [],
        "hazards": [
            {
                "handle": "risk_base_hazard",
                "description": _PRIOR_HAZARD,
                "related_losses": ["risk_base_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "risk_base_constraint",
                "rule": _PRIOR_CONSTRAINT,
                "related_hazards": ["risk_base_hazard"],
                "applies_when": [],
                "obligations": [],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": "neutral-risk",
                "disposition": "cited",
                "loss_ids": ["risk_base_loss"],
                "reason": None,
            }
        ],
    }


def _empty_gap_response() -> dict[str, Any]:
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }


def _reserved_handle_gap_response() -> dict[str, Any]:
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "handle": "H-1",
                "description": "The authoritative request state has changed semantics.",
                "related_losses": ["risk_base_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "current_constraint",
                "rule": "The current request condition must be prevented.",
                "related_hazards": ["H-1"],
                "applies_when": [],
                "obligations": [],
            }
        ],
    }


def _derive(
    tmp_path: Path, responses: list[dict[str, Any]]
) -> tuple[MockLLMClient, Any]:
    client = MockLLMClient(preserve_gap_extras=False)
    client.set_response_queue(responses)
    return client, derive_loss_analysis(
        llm_client=client,
        use_case_text="A service receives a request and records its processing result.",
        risk_cards=[_risk_card()],
        run_dir=tmp_path,
    )


def _steps(tmp_path: Path) -> list[tuple[str, bool]]:
    return [
        (entry["step"], entry["success"])
        for entry in read_calls_jsonl(tmp_path)
        if entry.get("stage") == "stage_1a"
    ]


def _descriptions(records: Any) -> set[str]:
    return {record.description for record in records}


def _rules(records: Any) -> set[str]:
    return {record.rule for record in records}


def _section_drafts(*, empty: bool) -> tuple[LossAnalysisDraft, LossAnalysisDraft]:
    hazard_id = "risk-base-hazard" if empty else "obsolete-hazard"
    prior = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "risk-base-loss",
                    "description": _PRIOR_RISK_LOSS,
                    "provenance": "risk_card",
                    "source_risk_cards": ["neutral-risk"],
                }
            ],
            "use_case_losses": [
                {
                    "loss_id": "gap-case-loss",
                    "description": _PRIOR_USE_CASE_LOSS,
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [
                {
                    "hazard_id": hazard_id,
                    "description": _PRIOR_HAZARD if empty else _OBSOLETE_HAZARD,
                    "related_losses": ["risk-base-loss" if empty else "gap-case-loss"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": (
                        "risk-base-constraint" if empty else "obsolete-constraint"
                    ),
                    "rule": _PRIOR_CONSTRAINT if empty else _OBSOLETE_CONSTRAINT,
                    "related_hazards": [hazard_id],
                    "applies_when": [],
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": "neutral-risk",
                    "disposition": "cited",
                    "loss_ids": ["risk-base-loss"],
                    "reason": None,
                }
            ],
        }
    )
    correction = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": []
            if empty
            else [
                {
                    "hazard_id": "gap-hazard",
                    "description": _REPLACEMENT_HAZARD,
                    "related_losses": ["gap-case-loss"],
                }
            ],
            "security_constraints": []
            if empty
            else [
                {
                    "constraint_id": "current-constraint",
                    "rule": _REPLACEMENT_CONSTRAINT,
                    "related_hazards": ["gap-hazard"],
                    "applies_when": [],
                }
            ],
            "risk_dispositions": [],
        }
    )
    return prior, correction


def test_empty_correction_sections_retain_every_prior_section() -> None:
    merged = _merge_loss_analysis_correction(*_section_drafts(empty=True))

    assert _descriptions(merged.risk_card_losses) == {_PRIOR_RISK_LOSS}
    assert _descriptions(merged.use_case_losses) == {_PRIOR_USE_CASE_LOSS}
    assert _descriptions(merged.hazards) == {_PRIOR_HAZARD}
    assert _rules(merged.security_constraints) == {_PRIOR_CONSTRAINT}


def test_populated_correction_sections_replace_their_prior_sections() -> None:
    merged = _merge_loss_analysis_correction(*_section_drafts(empty=False))

    assert _descriptions(merged.risk_card_losses) == {_PRIOR_RISK_LOSS}
    assert _descriptions(merged.use_case_losses) == {_PRIOR_USE_CASE_LOSS}
    assert _descriptions(merged.hazards) == {_REPLACEMENT_HAZARD}
    assert _rules(merged.security_constraints) == {_REPLACEMENT_CONSTRAINT}


def test_wire_keeps_five_required_collections_and_needs_no_correction(
    tmp_path: Path,
) -> None:
    client, _ = _derive(tmp_path, [_risk_response(), _empty_gap_response()])

    risk_schema = client.calls[0].response_format.model_json_schema()
    assert set(risk_schema["required"]) == {
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
        "risk_dispositions",
    }
    assert _steps(tmp_path) == [("risk_derivation", True), ("gap_analysis", True)]


def test_duplicate_local_handle_fails_closed_without_repair(tmp_path: Path) -> None:
    with pytest.raises(
        Exception, match="duplicate request-local loss handle 'risk_base_loss'"
    ):
        _derive(tmp_path, [_risk_response(duplicate=True), _empty_gap_response()])

    entries = read_calls_jsonl(tmp_path)
    assert _steps(tmp_path) == [("risk_derivation", False)]
    assert "risk_base_loss" in entries[0]["response_content"]


@pytest.mark.parametrize("label", ["hazard", "constraint"])
def test_duplicate_hazard_or_constraint_handle_is_rejected(label: str) -> None:
    draft = _empty_gap_response()
    draft["use_case_losses"] = [
        {
            "handle": "gap_loss",
            "description": _PRIOR_USE_CASE_LOSS,
            "provenance": "use_case",
            "source_risk_cards": [],
        }
    ]
    hazard = {
        "handle": "gap_hazard",
        "description": _REPLACEMENT_HAZARD,
        "related_losses": ["gap_loss"],
    }
    constraint = {
        "handle": "gap_constraint",
        "rule": _REPLACEMENT_CONSTRAINT,
        "related_hazards": ["gap_hazard"],
        "applies_when": [],
        "obligations": [],
    }
    draft["hazards"] = (
        [hazard, copy.deepcopy(hazard)] if label == "hazard" else [hazard]
    )
    draft["security_constraints"] = (
        [constraint, copy.deepcopy(constraint)]
        if label == "constraint"
        else [constraint]
    )

    with pytest.raises(ValueError, match=f"duplicate request-local {label} handle"):
        _Stage1aGapProviderDraft.model_validate(draft)


def test_reserved_canonical_handle_fails_closed_without_repair(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="reserved canonical graph ID"):
        _derive(tmp_path, [_risk_response(), _reserved_handle_gap_response()])

    entries = [e for e in read_calls_jsonl(tmp_path) if e.get("stage") == "stage_1a"]
    assert _steps(tmp_path) == [("risk_derivation", True), ("gap_analysis", False)]
    raw = entries[-1]["response_content"]
    assert "H-1" in raw
    assert "authoritative request state has changed semantics" in raw
