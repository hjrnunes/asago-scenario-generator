"""Duplicate loss and hazard references are validation findings.

A model answer that lists the same loss twice in a hazard's
``related_losses`` (or the same hazard twice in a security constraint's
``related_hazards``) is handled exactly like an unknown reference ID.  The
first Stage 1a calls (risk_derivation, gap_analysis) stop with a typed
``draft_references`` failure that names the duplicate and make no further
call.  The bounded hazard_graph_revision call sends the duplicate back to
the model in its one correction request and accepts a corrected answer.

Neither path de-duplicates silently: a repeated reference would otherwise
survive into the persisted loss analysis and fail later in the closed
systemic snapshot, which requires unique reference sets.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
    derive_loss_analysis,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    setup_sp1_mock_client,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)


def _risk_cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="atlas-001",
            risk_description="Risk atlas-001",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
    ]


def _stage1a_steps(run_dir: Path) -> list[str]:
    return [
        json.loads(line)["step"]
        for line in (run_dir / "calls.jsonl").read_text().splitlines()
        if json.loads(line)["stage"] == "stage_1a"
    ]


def _derive(tmp_path: Path, drafts: list[dict]) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, drafts)
    derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=_risk_cards(),
        run_dir=tmp_path,
    )
    return client


class TestStage1aDraftDuplicates:
    """A first-call duplicate stops typed, exactly like an unknown ID."""

    def test_risk_derivation_duplicate_loss_is_a_reference_finding(
        self, tmp_path
    ) -> None:
        risk = valid_risk_draft_dict()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]

        with pytest.raises(StageError) as exc_info:
            _derive(tmp_path, [risk, valid_gap_draft_dict()])

        message = str(exc_info.value)
        assert exc_info.value.step == "risk_derivation"
        assert "draft_references failure class" in message
        assert "no repair call was made" in message
        assert "hazards.related_losses duplicate IDs: H-1 -> L-1" in message
        assert "List each ID at most once" in message
        assert _stage1a_steps(tmp_path) == ["risk_derivation"]

    def test_risk_derivation_duplicate_hazard_is_a_reference_finding(
        self, tmp_path
    ) -> None:
        risk = valid_risk_draft_dict()
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-1"]

        with pytest.raises(StageError) as exc_info:
            _derive(tmp_path, [risk, valid_gap_draft_dict()])

        message = str(exc_info.value)
        assert "draft_references failure class" in message
        assert (
            "security_constraints.related_hazards duplicate IDs: SC-1 -> H-1" in message
        )
        assert _stage1a_steps(tmp_path) == ["risk_derivation"]

    def test_gap_analysis_duplicate_existing_loss_is_a_reference_finding(
        self, tmp_path
    ) -> None:
        gap = valid_gap_draft_dict()
        gap["hazards"][0]["related_losses"] = ["L-1", "L-2", "L-1"]

        with pytest.raises(StageError) as exc_info:
            _derive(tmp_path, [valid_risk_draft_dict(), gap])

        message = str(exc_info.value)
        assert exc_info.value.step == "gap_analysis"
        assert "hazards.related_losses duplicate IDs: H-2 -> L-1" in message
        assert _stage1a_steps(tmp_path) == ["risk_derivation", "gap_analysis"]

    def test_duplicates_and_unknown_ids_are_reported_together_and_sorted(
        self, tmp_path
    ) -> None:
        risk = valid_risk_draft_dict()
        risk["risk_card_losses"].append(
            {
                "loss_id": "L-2",
                "description": "Disclosure of account data",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        )
        risk["hazards"] = [
            {
                "hazard_id": "H-1",
                "description": "The agent executes an unintended payment.",
                "related_losses": ["L-1", "L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "The agent discloses account data.",
                "related_losses": ["L-2", "L-1", "L-2", "L-1"],
            },
        ]
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-2", "H-9"]

        with pytest.raises(StageError) as exc_info:
            _derive(tmp_path, [risk, valid_gap_draft_dict()])

        message = str(exc_info.value)
        assert (
            "risk_derivation draft has invalid cross-references: "
            "security_constraints.related_hazards unknown IDs: H-9; "
            "hazards.related_losses duplicate IDs: H-1 -> L-1, H-2 -> L-1, "
            "H-2 -> L-2"
        ) in message


def _sp1_client(revisions: list[dict]) -> MockLLMClient:
    client = setup_sp1_mock_client()
    gap = valid_gap_draft_dict()
    # Leave H-2 without a constraint so the density gate requests a revision.
    gap["security_constraints"] = []
    client.set_response_for(LossAnalysisDraft, [valid_risk_draft_dict(), gap])
    client.set_response_for(_Stage1aRevisionPatch, revisions)
    return client


def _run_sp1(tmp_path: Path, revisions: list[dict]):
    from asago_scenario_generator.stpa.system_model.run import run_sp1

    return run_sp1(
        llm_client=_sp1_client(revisions),
        use_case_text="Test use case",
        risk_cards=_risk_cards(),
        run_dir=tmp_path,
    )


def _revision_entries(run_dir: Path) -> list[dict]:
    return [
        entry
        for entry in (
            json.loads(line)
            for line in (run_dir / "calls.jsonl").read_text().splitlines()
        )
        if entry["step"] == "hazard_graph_revision"
    ]


def _trust_constraint(related_hazards: list[str]) -> dict:
    return {
        "handle": "trust_constraint",
        "rule": "The agent must preserve user trust.",
        "applies_when": ["through transparency"],
        "related_hazards": related_hazards,
        "obligations": [],
    }


def _revision(
    *,
    hazard_edits: list[dict] | None = None,
    hazard_additions: list[dict] | None = None,
    related_hazards: list[str] | None = None,
) -> dict:
    return {
        "hazard_edits": hazard_edits or [],
        "hazard_additions": hazard_additions or [],
        "security_constraint_edits": [],
        "security_constraint_additions": [
            _trust_constraint(related_hazards or ["H-2"])
        ],
    }


def _h2_edit(related_losses: list[str]) -> dict:
    return {
        "hazard_id": "H-2",
        "description": "The agent erodes user trust.",
        "related_losses": related_losses,
    }


def _assert_corrected(tmp_path: Path, expected_error: str) -> str:
    entries = _revision_entries(tmp_path)
    assert [entry["success"] for entry in entries] == [False, True]
    assert expected_error in entries[0]["error"]
    correction_prompt = entries[1]["user_prompt_text"]
    assert "Correction request: the prior graph revision response" in (
        correction_prompt
    )
    assert expected_error in correction_prompt
    return correction_prompt


class TestGraphRevisionDuplicates:
    """A revision duplicate gets the one correction request, then is accepted."""

    def test_hazard_edit_duplicate_loss_is_corrected(self, tmp_path) -> None:
        result = _run_sp1(
            tmp_path,
            [
                _revision(hazard_edits=[_h2_edit(["L-2", "L-2"])]),
                _revision(hazard_edits=[_h2_edit(["L-2"])]),
            ],
        )

        _assert_corrected(
            tmp_path,
            "hazard H-2 references duplicate loss ID(s): L-2",
        )
        assert result.stage_errors == []
        hazards = {hazard.hazard_id: hazard for hazard in result.loss_analysis.hazards}
        assert hazards["H-2"].related_losses == ["L-2"]

    def test_hazard_addition_duplicate_loss_names_its_handle(self, tmp_path) -> None:
        addition = {
            "handle": "trust_disclosure_hazard",
            "description": "The agent discloses trust signals without consent.",
            "related_losses": ["L-2", "L-1", "L-2"],
        }
        corrected = dict(addition, related_losses=["L-2", "L-1"])

        result = _run_sp1(
            tmp_path,
            [
                _revision(
                    hazard_additions=[addition],
                    related_hazards=["H-2", "trust_disclosure_hazard"],
                ),
                _revision(
                    hazard_additions=[corrected],
                    related_hazards=["H-2", "trust_disclosure_hazard"],
                ),
            ],
        )

        _assert_corrected(
            tmp_path,
            "hazard addition 'trust_disclosure_hazard' (assigned H-3) references "
            "duplicate loss ID(s): L-2",
        )
        # The mock Stage 2 review does not cover the added hazard, so only
        # the accepted Stage 1a graph is asserted here.
        added = {hazard.hazard_id: hazard for hazard in result.loss_analysis.hazards}[
            "H-3"
        ]
        assert added.related_losses == ["L-2", "L-1"]

    def test_constraint_duplicate_hazard_is_corrected(self, tmp_path) -> None:
        result = _run_sp1(
            tmp_path,
            [_revision(related_hazards=["H-2", "H-2"]), _revision()],
        )

        _assert_corrected(
            tmp_path,
            "security constraint addition 'trust_constraint' (assigned SC-2) "
            "references duplicate hazard ID(s): H-2",
        )
        assert result.stage_errors == []
        constraints = result.loss_analysis.security_constraints
        assert [
            c.related_hazards for c in constraints if c.constraint_id == "SC-2"
        ] == [["H-2"]]

    def test_restated_hazard_handle_that_collapses_to_a_cited_id_is_corrected(
        self, tmp_path
    ) -> None:
        restatement = {
            "handle": "trust_hazard_again",
            "description": "The agent erodes user trust.",
            "related_losses": ["L-2"],
        }

        result = _run_sp1(
            tmp_path,
            [
                _revision(
                    hazard_additions=[restatement],
                    related_hazards=["H-2", "trust_hazard_again"],
                ),
                _revision(),
            ],
        )

        _assert_corrected(
            tmp_path,
            "security constraint addition 'trust_constraint' (assigned SC-2) "
            "references duplicate hazard ID(s): H-2 (written as 'H-2', "
            "'trust_hazard_again')",
        )
        assert result.stage_errors == []
