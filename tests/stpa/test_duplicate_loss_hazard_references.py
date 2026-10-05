"""Duplicate loss and hazard references are validation findings.

A model answer that lists the same loss twice in a hazard's
``related_losses`` (or the same hazard twice in a security constraint's
``related_hazards``) is a validation finding, like an unknown reference ID.
When repeated IDs are a first Stage 1a draft's only reference problem
(risk_derivation, gap_analysis), the draft gets exactly one targeted repair
call that may only remove each repeat or replace it with a valid ID; a draft
that also names an unknown ID stops with a typed ``draft_references``
failure and no repair call (decision 47b, 2026-10-04).  The bounded
hazard_graph_revision call sends the duplicate back to the model in its one
correction request and accepts a corrected answer.

Neither path de-duplicates silently: a repeated reference would otherwise
survive into the persisted loss analysis and fail later in the closed
systemic snapshot, which requires unique reference sets.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    ReferenceRepairPlan,
    ReferenceRepairResponse,
    RepairRejected,
    merge_reference_repair,
    select_duplicate_reference_repairs,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    setup_sp1_mock_client,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1


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


def _derive_with_repair(
    tmp_path: Path, drafts: list[dict], repairs: list[dict]
) -> tuple[MockLLMClient, LossAnalysis]:
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, drafts)
    client.set_response_for(ReferenceRepairResponse, repairs)
    analysis = derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=_risk_cards(),
        run_dir=tmp_path,
    )
    return client, analysis


def _repair_entries(run_dir: Path) -> list[dict]:
    record = yaml.safe_load((run_dir / "loss-analysis-repair.yaml").read_text())
    return [entry for entry in record["records"] if entry["kind"] == "repair"]


def _call_entry(run_dir: Path, step: str) -> dict:
    return next(
        entry
        for entry in (
            json.loads(line)
            for line in (run_dir / "calls.jsonl").read_text().splitlines()
        )
        if entry["step"] == step
    )


def _hazard_repair(hazard_id: str, related_losses: list[str]) -> dict:
    return {
        "hazards": [{"hazard_id": hazard_id, "related_losses": related_losses}],
        "security_constraints": [],
    }


def _risk_with_second_loss() -> dict:
    risk = valid_risk_draft_dict()
    risk["risk_card_losses"].append(
        {
            "loss_id": "L-2",
            "description": "Disclosure of account data",
            "provenance": "risk_card",
            "source_risk_cards": ["atlas-001"],
        }
    )
    risk["risk_dispositions"][0]["loss_ids"] = ["L-1", "L-2"]
    return risk


def _gap_with_l3() -> dict:
    gap = valid_gap_draft_dict()
    gap["use_case_losses"][0]["loss_id"] = "L-3"
    gap["hazards"][0]["related_losses"] = ["L-3"]
    return gap


class TestStage1aDuplicateRepair:
    """A duplicates-only first draft gets exactly one targeted repair call."""

    def test_risk_derivation_duplicate_loss_is_repaired_once(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]

        _, analysis = _derive_with_repair(
            tmp_path,
            [risk, valid_gap_draft_dict()],
            [_hazard_repair("H-1", ["L-1"])],
        )

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        hazards = {hazard.hazard_id: hazard for hazard in analysis.hazards}
        assert hazards["H-1"].related_losses == ["L-1"]
        [entry] = _repair_entries(tmp_path)
        assert entry["stage"] == "risk_derivation"
        assert entry["identity"] == "H-1.related_losses"
        assert entry["outcome"] == "repaired"
        assert entry["proposed"]["references"] == ["L-1"]
        assert entry["applied"] == entry["proposed"]
        assert "hazards.related_losses duplicate IDs: H-1 -> L-1" in entry["reason"]

    def test_repeat_replaced_with_a_valid_loss_is_accepted(self, tmp_path) -> None:
        risk = _risk_with_second_loss()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]

        _, analysis = _derive_with_repair(
            tmp_path,
            [risk, _gap_with_l3()],
            [_hazard_repair("H-1", ["L-1", "L-2"])],
        )

        hazards = {hazard.hazard_id: hazard for hazard in analysis.hazards}
        assert hazards["H-1"].related_losses == ["L-1", "L-2"]

    def test_constraint_duplicate_hazard_is_repaired_once(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-1"]
        repair = {
            "hazards": [],
            "security_constraints": [
                {"constraint_id": "SC-1", "related_hazards": ["H-1"]}
            ],
        }

        _, analysis = _derive_with_repair(
            tmp_path, [risk, valid_gap_draft_dict()], [repair]
        )

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        constraints = {c.constraint_id: c for c in analysis.security_constraints}
        assert constraints["SC-1"].related_hazards == ["H-1"]
        [entry] = _repair_entries(tmp_path)
        assert entry["identity"] == "SC-1.related_hazards"
        assert entry["outcome"] == "repaired"

    def test_gap_analysis_duplicate_existing_loss_is_repaired_once(
        self, tmp_path
    ) -> None:
        gap = valid_gap_draft_dict()
        gap["hazards"][0]["related_losses"] = ["L-1", "L-2", "L-1"]

        _, analysis = _derive_with_repair(
            tmp_path,
            [valid_risk_draft_dict(), gap],
            [_hazard_repair("H-2", ["L-1", "L-2"])],
        )

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        hazards = {hazard.hazard_id: hazard for hazard in analysis.hazards}
        assert hazards["H-2"].related_losses == ["L-1", "L-2"]

    def test_rendered_repair_request_names_canonical_ids_and_choices(
        self, tmp_path
    ) -> None:
        risk = _risk_with_second_loss()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]

        _derive_with_repair(
            tmp_path,
            [risk, _gap_with_l3()],
            [_hazard_repair("H-1", ["L-1"])],
        )

        entry = _call_entry(tmp_path, "risk_derivation_repair")
        system_prompt = entry["system_prompt_text"]
        user_prompt = entry["user_prompt_text"]
        assert "compiled the prior response's local handles into" in system_prompt
        assert "canonical IDs before this repair" in system_prompt
        assert "## Targeted repair contract" in system_prompt
        assert (
            "### H-1.related_losses\n"
            "- **Hazard text:** The agent executes an unintended payment.\n"
            '- **Original list, verbatim:** ["L-1", "L-1"]\n'
            "- **Validation error:** hazards.related_losses duplicate IDs: "
            "H-1 -> L-1\n"
            "- **Repeated IDs:** L-1\n"
            "- **IDs to keep once each, in this order:**\n"
            "  - **L-1**: Unauthorized transaction\n"
            "- **Replacement IDs** (a repeated entry may become one of these):\n"
            "  - **L-2**: Disclosure of account data\n"
            "- **Permitted correction:**"
        ) in user_prompt
        assert (
            "- **Permitted correction:** for each repeated entry, remove the "
            "repeat or replace it with one listed replacement ID; keep L-1 once "
            "each in this order; name no ID outside the kept and replacement IDs"
        ) in user_prompt
        assert "Test use case" in user_prompt


class TestStage1aDuplicateRepairLimits:
    """Mixed findings stop without a call; a bad repair fails without a retry."""

    def test_duplicates_with_unknown_ids_stop_without_a_repair_call(
        self, tmp_path
    ) -> None:
        risk = _risk_with_second_loss()
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
        assert "draft_references failure class" in message
        assert "no repair call was made" in message
        assert (
            "risk_derivation draft has invalid cross-references: "
            "security_constraints.related_hazards unknown IDs: H-9; "
            "hazards.related_losses duplicate IDs: H-1 -> L-1, H-2 -> L-1, "
            "H-2 -> L-2"
        ) in message
        assert _stage1a_steps(tmp_path) == ["risk_derivation"]

    @pytest.mark.parametrize(
        ("repair", "expected"),
        [
            pytest.param(
                _hazard_repair("H-1", ["L-1", "L-1"]),
                "repair_duplicate_remaining: H-1.related_losses still lists L-1",
                id="duplicate-left",
            ),
            pytest.param(
                {
                    "hazards": [{"hazard_id": "H-1", "related_losses": ["L-1"]}],
                    "security_constraints": [
                        {"constraint_id": "SC-1", "related_hazards": ["H-1"]}
                    ],
                },
                "repair_identity_unknown: 'SC-1.related_hazards' is not a "
                "selected reference list",
                id="unselected-record",
            ),
            pytest.param(
                _hazard_repair("H-1", ["L-2"]),
                "repair_edit_forbidden: H-1.related_losses must keep L-1",
                id="kept-id-dropped",
            ),
            pytest.param(
                _hazard_repair("H-1", ["L-1", "L-9"]),
                "repair_reference_unknown: H-1.related_losses adds L-9",
                id="unknown-replacement",
            ),
            pytest.param(
                {"hazards": [], "security_constraints": []},
                "incomplete repair; no list was returned for: H-1.related_losses",
                id="list-missing",
            ),
        ],
    )
    def test_out_of_scope_repair_fails_typed_without_a_second_call(
        self, tmp_path, repair: dict, expected: str
    ) -> None:
        risk = _risk_with_second_loss()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]

        with pytest.raises(StageError) as exc_info:
            _derive_with_repair(tmp_path, [risk, _gap_with_l3()], [repair])

        assert expected in str(exc_info.value)
        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
        ]
        [entry] = _repair_entries(tmp_path)
        assert entry["identity"] == "H-1.related_losses"
        assert entry["outcome"] == "rejected"
        assert entry["applied"] == {}

    def test_repair_response_with_extra_fields_fails_typed(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]
        repair = {
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "related_losses": ["L-1"],
                    "description": "A rewritten hazard.",
                }
            ],
            "security_constraints": [],
        }

        with pytest.raises(StageError, match="targeted repair failed"):
            _derive_with_repair(tmp_path, [risk, valid_gap_draft_dict()], [repair])

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
        ]
        [entry] = _repair_entries(tmp_path)
        assert entry["outcome"] == "failed"
        assert entry["applied"] == {}


def _merge_plan() -> ReferenceRepairPlan:
    draft = LossAnalysisDraft.model_validate(_risk_with_second_loss())
    draft.hazards[0].related_losses = ["L-1", "L-1"]
    return ReferenceRepairPlan(
        prior=draft,
        selected=select_duplicate_reference_repairs(
            draft, valid_loss_ids={"L-1", "L-2"}, valid_hazard_ids={"H-1"}
        ),
    )


class TestReferenceRepairMerge:
    """The merge changes only the selected list and only as permitted."""

    def test_merge_preserves_every_other_field(self) -> None:
        plan = _merge_plan()

        merged = merge_reference_repair(
            plan,
            ReferenceRepairResponse.model_validate(_hazard_repair("H-1", ["L-1"])),
        )

        expected = plan.prior.model_dump(mode="json")
        expected["hazards"][0]["related_losses"] = ["L-1"]
        assert merged.model_dump(mode="json") == expected

    def test_list_returned_twice_is_rejected(self) -> None:
        response = ReferenceRepairResponse.model_validate(
            {
                "hazards": [
                    {"hazard_id": "H-1", "related_losses": ["L-1"]},
                    {"hazard_id": "H-1", "related_losses": ["L-1", "L-2"]},
                ]
            }
        )

        with pytest.raises(RepairRejected, match="repair_identity_duplicate"):
            merge_reference_repair(_merge_plan(), response)

    def test_more_replacements_than_repeats_are_rejected(self) -> None:
        draft = LossAnalysisDraft.model_validate(_risk_with_second_loss())
        draft.hazards[0].related_losses = ["L-1", "L-1"]
        plan = ReferenceRepairPlan(
            prior=draft,
            selected=select_duplicate_reference_repairs(
                draft, valid_loss_ids={"L-1", "L-2", "L-3"}, valid_hazard_ids=set()
            ),
        )
        response = ReferenceRepairResponse.model_validate(
            _hazard_repair("H-1", ["L-1", "L-2", "L-3"])
        )

        with pytest.raises(
            RepairRejected,
            match="adds 2 IDs but only 1 repeated entries may be replaced",
        ):
            merge_reference_repair(plan, response)


def _sp1_client(revisions: list[dict]) -> MockLLMClient:
    client = setup_sp1_mock_client()
    gap = valid_gap_draft_dict()
    # Leave H-2 without a constraint so the density gate requests a revision.
    gap["security_constraints"] = []
    client.set_response_for(LossAnalysisDraft, [valid_risk_draft_dict(), gap])
    client.set_response_for(_Stage1aRevisionPatch, revisions)
    return client


def _run_sp1(tmp_path: Path, revisions: list[dict]):
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
