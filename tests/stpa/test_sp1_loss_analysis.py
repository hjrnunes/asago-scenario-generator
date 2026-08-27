"""Tests for SP1 Stage 1a — Loss Analysis derivation (two-call split).

Covers the risk_derivation + gap_analysis split, ID continuation,
cross-reference validity, and call-log recording.
"""

from __future__ import annotations

import json
import warnings

import yaml

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
    LossProvenance,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import derive_loss_analysis
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
    valid_stage1_profile_dict,
)


def _make_risk_cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def _make_capability_profile() -> CapabilityProfile:
    return Stage1Profile(
        entry_points=[
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        confidence="medium",
        kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[{"name": "tool1", "description": "A tool"}],
    ).to_capability_profile()


def _observed_invalid_risk_draft() -> dict:
    """Return the sanitized run-3 risk draft shape."""
    draft = valid_risk_draft_dict()
    draft["security_constraints"] = [
        {
            "constraint_id": f"SC-{index}",
            "description": f"Constraint {index}",
            "related_hazards": [f"H-{index + 1}"],
        }
        for index in range(1, 7)
    ]
    # The observed response declared only H-1 while the constraints referred
    # to H-2 through H-7.
    return draft


def _corrected_risk_draft() -> dict:
    """Return a corrected risk draft without dropping constraints."""
    draft = _observed_invalid_risk_draft()
    draft["hazards"] = [
        {
            "hazard_id": f"H-{index}",
            "description": f"Hazard {index}",
            "related_losses": ["L-1"],
        }
        for index in range(1, 8)
    ]
    return draft


def _gap_draft_with_existing_references() -> dict:
    """Return a gap draft referencing both existing and new IDs."""
    draft = valid_gap_draft_dict()
    draft["hazards"][0].update(
        {
            "hazard_id": "H-8",
            "related_losses": ["L-1", "L-2"],
        }
    )
    draft["security_constraints"][0]["related_hazards"] = ["H-8", "H-1"]
    return draft


class TestStage1aLossAnalysis:
    """SP1 Stage 1a loss analysis derivation (two-call split)."""

    def test_la_01_valid_response_produces_valid_loss_analysis(self, tmp_path):
        """A valid two-call response produces a valid LossAnalysis."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, LossAnalysis)
        assert len(result.risk_card_losses) == 1
        assert len(result.use_case_losses) == 1

    def test_la_02_risk_card_losses_have_correct_provenance(self, tmp_path):
        """Risk-card-derived losses have correct provenance."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        for loss in result.risk_card_losses:
            assert loss.provenance == LossProvenance.risk_card
            assert len(loss.source_risk_cards) > 0

    def test_la_03_use_case_losses_have_correct_provenance(self, tmp_path):
        """Use-case-derived losses have correct provenance."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        for loss in result.use_case_losses:
            assert loss.provenance == LossProvenance.use_case
            assert len(loss.source_risk_cards) == 0

    def test_la_04_invalid_hazard_reference_fails(self, tmp_path):
        """Hazard referencing non-existent loss fails."""
        bad_risk = valid_risk_draft_dict()
        bad_risk["hazards"][0]["related_losses"] = ["L-99"]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [bad_risk, bad_risk],
        )
        with pytest.raises((ValidationError, ValueError, StageError), match="related_losses"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_04b_invalid_constraint_reference_fails(self, tmp_path):
        """Constraint referencing non-existent hazard fails."""
        bad_risk = valid_risk_draft_dict()
        bad_risk["security_constraints"][0]["related_hazards"] = ["H-99"]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [bad_risk, bad_risk],
        )
        with pytest.raises((ValidationError, ValueError, StageError), match="related_hazards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_05_risk_card_loss_missing_source_fails(self, tmp_path):
        """Risk-card loss with empty source_risk_cards fails."""
        bad_risk = valid_risk_draft_dict()
        bad_risk["risk_card_losses"][0]["source_risk_cards"] = []
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [bad_risk, valid_gap_draft_dict()],
        )
        with pytest.raises((ValidationError, ValueError, StageError), match="source_risk_cards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_06_use_case_loss_with_source_fails(self, tmp_path):
        """Use-case loss having source_risk_cards fails."""
        bad_gap = valid_gap_draft_dict()
        bad_gap["use_case_losses"][0]["source_risk_cards"] = ["atlas-001"]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), bad_gap],
        )
        with pytest.raises((ValidationError, ValueError, StageError), match="source_risk_cards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_07_renumbering_handles_non_sequential_ids(self, tmp_path):
        """Non-sequential or duplicate input IDs are renumbered to sequential."""
        # Risk draft uses L-5, L-10 (non-sequential)
        risk = valid_risk_draft_dict()
        risk["risk_card_losses"][0]["loss_id"] = "L-5"
        risk["hazards"][0]["related_losses"] = ["L-5"]
        risk["hazards"][0]["hazard_id"] = "H-7"
        risk["security_constraints"][0]["related_hazards"] = ["H-7"]
        risk["security_constraints"][0]["constraint_id"] = "SC-3"
        # Gap draft uses L-3, H-2 (also non-sequential)
        gap = valid_gap_draft_dict()
        gap["use_case_losses"][0]["loss_id"] = "L-3"
        gap["hazards"][0]["related_losses"] = ["L-3"]
        gap["hazards"][0]["hazard_id"] = "H-2"
        gap["security_constraints"][0]["related_hazards"] = ["H-2"]
        gap["security_constraints"][0]["constraint_id"] = "SC-9"
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        # After renumbering: L-1, L-2 / H-1, H-2 / SC-1, SC-2
        all_losses = result.risk_card_losses + result.use_case_losses
        assert [loss.loss_id for loss in all_losses] == ["L-1", "L-2"]
        assert [h.hazard_id for h in result.hazards] == ["H-1", "H-2"]
        assert [sc.constraint_id for sc in result.security_constraints] == ["SC-1", "SC-2"]
        # Cross-references updated
        assert result.hazards[0].related_losses == ["L-1"]
        assert result.hazards[1].related_losses == ["L-2"]
        assert result.security_constraints[0].related_hazards == ["H-1"]
        assert result.security_constraints[1].related_hazards == ["H-2"]

    def test_la_08_two_call_log_entries_recorded(self, tmp_path):
        """Two call-log entries are recorded with correct stage and step."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 2
        assert entries[0]["stage"] == "stage_1a"
        assert entries[0]["step"] == "risk_derivation"
        assert entries[1]["stage"] == "stage_1a"
        assert entries[1]["step"] == "gap_analysis"

    def test_la_09_loss_analysis_written_to_yaml(self, tmp_path):
        """loss-analysis.yaml exists and contains valid model."""
        from asago_scenario_generator.stpa.infra.yaml_io import read_yaml

        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "loss-analysis.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, LossAnalysis)
        assert isinstance(loaded, LossAnalysis)
        assert len(loaded.risk_card_losses) == 1

    def test_la_10_both_loss_types_coexist(self, tmp_path):
        """Both risk-card and use-case losses coexist after merge."""
        risk_draft = valid_risk_draft_dict()
        risk_draft["risk_card_losses"].append(
            {
                "loss_id": "L-10",
                "description": "Data exposure",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-002"],
            }
        )
        gap_draft = valid_gap_draft_dict()
        gap_draft["use_case_losses"].append(
            {
                "loss_id": "L-11",
                "description": "Regulatory non-compliance",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        )
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [risk_draft, gap_draft],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert len(result.risk_card_losses) == 2
        assert len(result.use_case_losses) == 2

    def test_la_11_every_hazard_links_to_loss(self, tmp_path):
        """Every hazard links to at least one loss."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        all_loss_ids = {
            loss.loss_id for loss in result.risk_card_losses + result.use_case_losses
        }
        for hazard in result.hazards:
            assert len(hazard.related_losses) >= 1
            for ref in hazard.related_losses:
                assert ref in all_loss_ids

    def test_la_12_every_constraint_links_to_hazard(self, tmp_path):
        """Every security constraint links to at least one hazard."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        all_hazard_ids = {h.hazard_id for h in result.hazards}
        for sc in result.security_constraints:
            assert len(sc.related_hazards) >= 1
            for ref in sc.related_hazards:
                assert ref in all_hazard_ids

    def test_la_13_ids_are_sequential_after_merge(self, tmp_path):
        """Loss, hazard, and SC IDs are sequential with no duplicates after merge."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        all_losses = result.risk_card_losses + result.use_case_losses
        loss_ids = [loss.loss_id for loss in all_losses]
        assert loss_ids == ["L-1", "L-2"]

        hazard_ids = [h.hazard_id for h in result.hazards]
        assert hazard_ids == ["H-1", "H-2"]

        sc_ids = [sc.constraint_id for sc in result.security_constraints]
        assert sc_ids == ["SC-1", "SC-2"]

    def test_la_14_gap_call_receives_kc_subcodes(self, tmp_path):
        """Gap analysis user prompt includes kc_subcodes from capability profile."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )
        profile = _make_capability_profile()
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
            capability_profile=profile,
        )
        # The gap call is the second call
        gap_call = client.calls[1]
        assert "kc_subcodes" in gap_call.user_prompt
        assert "KC1.1" in gap_call.user_prompt

    def test_la_15_empty_risk_cards_produces_empty_risk_losses(self, tmp_path):
        """Risk-grounded call with no risk cards produces empty risk_card_losses."""
        empty_risk = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [empty_risk, valid_gap_draft_dict()],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[],
            run_dir=tmp_path,
        )
        assert len(result.risk_card_losses) == 0
        assert len(result.use_case_losses) == 1

    def test_la_16_gap_hazard_can_reference_existing_loss(self, tmp_path):
        """Gap analysis hazards can reference existing loss IDs from risk call."""
        gap = valid_gap_draft_dict()
        # Gap hazard references L-1 (from risk call) in addition to its own L-2
        gap["hazards"][0]["related_losses"] = ["L-2", "L-1"]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), gap],
        )
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        # After renumbering, L-1 stays L-1 and L-2 stays L-2
        gap_hazard = result.hazards[1]
        assert "L-1" in gap_hazard.related_losses
        assert "L-2" in gap_hazard.related_losses

    def test_la_17_observed_misplaced_loss_containers_are_normalized(self, tmp_path):
        """Losses are classified by provenance, even in the wrong draft field.

        This is a sanitized reproduction of the Gemma response shape from
        the Klarna run: risk-card losses were returned in ``use_case_losses``
        and gap losses were returned in both containers.
        """
        risk_losses = [
            {
                "loss_id": f"L-{index}",
                "description": f"Risk loss {index}",
                "provenance": "risk_card",
                "source_risk_cards": [f"atlas-{index:03d}"],
            }
            for index in range(1, 6)
        ]
        gap_losses = [
            {
                "loss_id": f"L-{index}",
                "description": f"Use-case loss {index}",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
            for index in range(6, 9)
        ]
        risk = {
            "risk_card_losses": [],
            "use_case_losses": risk_losses,
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Risk hazard",
                    "related_losses": ["L-3", "L-4"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "description": "Risk constraint",
                    "related_hazards": ["H-1"],
                }
            ],
        }
        gap = {
            "risk_card_losses": [loss.copy() for loss in gap_losses],
            "use_case_losses": [loss.copy() for loss in gap_losses],
            "hazards": [
                {
                    "hazard_id": "H-2",
                    "description": "Gap hazard",
                    "related_losses": ["L-6", "L-8"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-2",
                    "description": "Gap constraint",
                    "related_hazards": ["H-2"],
                }
            ],
        }
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )

        assert [loss.loss_id for loss in result.risk_card_losses] == [
            f"L-{index}" for index in range(1, 6)
        ]
        assert [loss.loss_id for loss in result.use_case_losses] == [
            f"L-{index}" for index in range(6, 9)
        ]
        assert len(result.risk_card_losses) == 5
        assert len(result.use_case_losses) == 3
        all_loss_ids = {
            loss.loss_id
            for loss in result.risk_card_losses + result.use_case_losses
        }
        assert all(
            ref in all_loss_ids
            for hazard in result.hazards
            for ref in hazard.related_losses
        )

        # The final graph is fully typed before serialization; the warning is
        # promoted to an error so tolerated intermediate shapes cannot leak.
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            serialized = result.model_dump(mode="json")
        assert len(serialized["risk_card_losses"]) == 5
        assert len(serialized["use_case_losses"]) == 3

    def test_la_18_identical_duplicate_loss_is_deduplicated(self, tmp_path):
        """Identical duplicate loss records are emitted only once."""
        risk = valid_risk_draft_dict()
        gap = valid_gap_draft_dict()
        duplicate = risk["risk_card_losses"][0].copy()
        gap["risk_card_losses"] = [duplicate]
        gap["use_case_losses"] = [
            {
                "loss_id": "L-2",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ]

        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )

        all_losses = result.risk_card_losses + result.use_case_losses
        assert len(all_losses) == 2
        assert [loss.loss_id for loss in all_losses] == ["L-1", "L-2"]

    def test_la_19_conflicting_duplicate_loss_id_is_a_stage_error(self, tmp_path):
        """Conflicting duplicate IDs fail deterministically at the stage boundary."""
        risk = valid_risk_draft_dict()
        gap = valid_gap_draft_dict()
        gap["use_case_losses"][0].update(
            {
                "loss_id": "L-1",
                "description": "Conflicting loss payload",
            }
        )
        gap["hazards"][0]["related_losses"] = ["L-1"]

        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        with pytest.raises(StageError, match="conflicting duplicate loss ID 'L-1'"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_20_merge_validation_failure_is_a_stage_error(self, tmp_path):
        """Final merge validation never exposes a raw Pydantic exception."""
        bad_risk = valid_risk_draft_dict()
        bad_risk["risk_card_losses"][0]["source_risk_cards"] = []
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [bad_risk, valid_gap_draft_dict()],
        )

        with pytest.raises(StageError, match="stage_1a") as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )
        assert "source_risk_cards" in str(exc_info.value)

    def test_la_21_sp1_merge_failure_is_partial_and_manifested(self, tmp_path):
        """SP1 contains merge failures and persists the existing diagnostic schema."""
        bad_risk = valid_risk_draft_dict()
        bad_risk["risk_card_losses"][0]["source_risk_cards"] = []
        client = MockLLMClient()
        client.set_response_for(
            Stage1Profile,
            valid_stage1_profile_dict(),
        )
        client.set_response_for(
            LossAnalysisDraft,
            [bad_risk, valid_gap_draft_dict()],
        )

        # No ValidationError escapes the public SP1 seam.
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is None
        assert result.capability_profile is not None
        assert result.control_structure is None
        assert any(error.startswith("stage_1a/merge:") for error in result.stage_errors)

        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["stage_errors"] == result.stage_errors
        assert any(
            error.startswith("stage_1a/merge:") for error in manifest["stage_errors"]
        )

    def test_la_22_invalid_risk_references_retry_without_dropping_constraints(
        self, tmp_path
    ):
        """Invalid risk references get one corrective retry before the gap call."""
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [
                _observed_invalid_risk_draft(),
                _corrected_risk_draft(),
                _gap_draft_with_existing_references(),
            ],
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )

        assert len(result.hazards) == 8
        assert len(result.security_constraints) == 7
        all_loss_ids = {
            loss.loss_id
            for loss in result.risk_card_losses + result.use_case_losses
        }
        all_hazard_ids = {hazard.hazard_id for hazard in result.hazards}
        assert all(
            reference in all_loss_ids
            for hazard in result.hazards
            for reference in hazard.related_losses
        )
        assert all(
            reference in all_hazard_ids
            for constraint in result.security_constraints
            for reference in constraint.related_hazards
        )

        entries = [
            json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
        assert [entry["success"] for entry in stage1a_entries] == [False, True, True]
        assert stage1a_entries[0]["step"] == "risk_derivation"
        assert "related_hazards" in stage1a_entries[0]["error"]
        assert "validation" in stage1a_entries[0]["error"].lower()
        assert "validation feedback" in stage1a_entries[1]["user_prompt_text"].lower()

    def test_la_23_invalid_risk_references_fail_after_one_retry(self, tmp_path):
        """Retry exhaustion is a structural StageError and preserves call logs."""
        invalid = _observed_invalid_risk_draft()
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [invalid, invalid])

        with pytest.raises(StageError, match="stage_1a/risk_derivation") as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

        assert "related_hazards" in str(exc_info.value)
        entries = [
            json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert len(entries) == 2
        assert all(not entry["success"] for entry in entries)
        assert not (tmp_path / "loss-analysis.yaml").exists()

    def test_la_24_invalid_gap_references_retry_with_existing_and_local_ids(
        self, tmp_path
    ):
        """Gap references are validated against risk and corrected local IDs."""
        invalid_gap = _gap_draft_with_existing_references()
        invalid_gap["hazards"][0]["related_losses"] = ["L-1", "L-99"]
        corrected_gap = _gap_draft_with_existing_references()
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [valid_risk_draft_dict(), invalid_gap, corrected_gap],
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )

        assert len(result.hazards) == 2
        assert len(result.security_constraints) == 2
        assert {loss.loss_id for loss in result.use_case_losses} == {"L-2"}
        assert {hazard.hazard_id for hazard in result.hazards} == {"H-1", "H-2"}

        entries = [
            json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
        assert len(stage1a_entries) == 3
        assert [entry["success"] for entry in stage1a_entries] == [True, False, True]
        assert [entry["step"] for entry in stage1a_entries] == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis",
        ]
        assert "related_losses" in stage1a_entries[1]["error"]
        assert "validation feedback" in stage1a_entries[2]["user_prompt_text"].lower()
