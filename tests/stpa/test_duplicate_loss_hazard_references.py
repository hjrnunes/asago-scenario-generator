"""Duplicate loss and hazard references are validation findings.

A model answer that lists the same loss twice in a hazard's
``related_losses`` (or the same hazard twice in a security constraint's
``related_hazards``) is a validation finding, like an unknown reference ID.
In a first Stage 1a draft (risk_derivation, gap_analysis) a repeat gets no
repair call of its own: the reference gate reports it and the unit stops
(decision 243, 2026-10-08; the one targeted repair replaces unknown IDs only,
``test_stage1a_unknown_reference_correction.py``).  The repair-limit tests
below use an unknown ID to open that one call.  The bounded
hazard_graph_revision call sends the duplicate back to the model in its one
correction request and accepts a corrected answer.

Neither path de-duplicates silently: a repeated reference would otherwise
survive into the persisted loss analysis and fail later in the closed
systemic snapshot, which requires unique reference sets.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _Stage1aRevisionPatch,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    ReferenceRepairPlan,
    ReferenceRepairResponse,
    RepairRecord,
    RepairRejected,
    merge_reference_repair,
    run_targeted_repair,
    select_reference_repairs,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from tests.helpers.calls_log import read_calls_jsonl, stage1a_steps
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    setup_sp1_mock_client,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1


def _derive_with_repair(
    tmp_path: Path, drafts: list[dict], repairs: list[dict]
) -> tuple[MockLLMClient, LossAnalysis]:
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, drafts)
    client.set_response_for(ReferenceRepairResponse, repairs)
    analysis = derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )
    return client, analysis


def _repair_entries(run_dir: Path) -> list[dict]:
    record = yaml.safe_load((run_dir / "loss-analysis-repair.yaml").read_text())
    return [entry for entry in record["records"] if entry["kind"] == "repair"]


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


class TestStage1aReferenceRepairLimits:
    """A bad repair of an unknown ID gets no retry; the unknown ID is dropped."""

    @pytest.mark.parametrize(
        ("repair", "expected"),
        [
            pytest.param(
                _hazard_repair("H-1", ["L-1", "L-2", "L-2"]),
                "repair_duplicate_remaining: H-1.related_losses adds L-2",
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
    def test_out_of_scope_repair_is_rejected_without_a_second_call(
        self, tmp_path, repair: dict, expected: str
    ) -> None:
        risk = _risk_with_second_loss()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-9"]

        _, analysis = _derive_with_repair(tmp_path, [risk, _gap_with_l3()], [repair])

        assert stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        [entry] = _repair_entries(tmp_path)
        assert entry["identity"] == "H-1.related_losses"
        assert entry["outcome"] == "rejected"
        assert expected in entry["reason"]
        assert entry["applied"] == {}
        assert analysis.hazards[0].related_losses == ["L-1"]

    def test_repair_response_with_extra_fields_fails_typed(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-9"]
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

        assert stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
        ]
        [entry] = _repair_entries(tmp_path)
        assert entry["outcome"] == "failed"
        assert entry["applied"] == {}


def _merge_plan() -> ReferenceRepairPlan:
    draft = LossAnalysisDraft.model_validate(_risk_with_second_loss())
    draft.hazards[0].related_losses = ["L-1", "L-9"]
    return ReferenceRepairPlan(
        prior=draft,
        selected=select_reference_repairs(
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

    def test_more_replacements_than_unknown_entries_are_rejected(self) -> None:
        draft = LossAnalysisDraft.model_validate(_risk_with_second_loss())
        draft.hazards[0].related_losses = ["L-1", "L-9"]
        plan = ReferenceRepairPlan(
            prior=draft,
            selected=select_reference_repairs(
                draft, valid_loss_ids={"L-1", "L-2", "L-3"}, valid_hazard_ids={"H-1"}
            ),
        )
        response = ReferenceRepairResponse.model_validate(
            _hazard_repair("H-1", ["L-1", "L-2", "L-3"])
        )

        with pytest.raises(
            RepairRejected,
            match="adds 2 IDs but only 1 unknown entries may be replaced",
        ):
            merge_reference_repair(plan, response)


@pytest.mark.parametrize("outcome", ["repaired", "failed"])
def test_a_list_the_plan_selects_twice_is_recorded_once(tmp_path, outcome) -> None:
    plan = _merge_plan()
    plan = ReferenceRepairPlan(prior=plan.prior, selected=plan.selected * 2)
    assert len(plan.selected) == 2
    repair = _hazard_repair("H-1", ["L-1"])
    client = MockLLMClient()
    client.set_response_for(ReferenceRepairResponse, repair)
    record = RepairRecord()

    def validate(_draft: LossAnalysisDraft) -> None:
        if outcome == "failed":
            raise ValueError("graph validator rejects the repair")

    kwargs = dict(
        llm_client=client,
        loader=TemplateLoader(PROMPTS_DIR),
        run_dir=tmp_path,
        step="risk_derivation",
        temperature=0.4,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_validators=validate,
        normalizer=lambda _draft: [],
        repair_record=record,
    )
    if outcome == "failed":
        with pytest.raises(StageError, match="targeted repair failed"):
            run_targeted_repair(plan, **kwargs)
    else:
        run_targeted_repair(plan, **kwargs)

    [entry] = record.entries
    assert entry.identity == "H-1.related_losses"
    assert entry.outcome == outcome
    assert entry.proposed == {"entries": ["H-1.related_losses"], "references": ["L-1"]}
    if outcome == "repaired":
        assert entry.applied == entry.proposed
        assert entry.reason.count("unknown IDs") == 1
    else:
        assert entry.applied == {}
        assert entry.reason.endswith("; graph validator rejects the repair")


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
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )


def _revision_entries(run_dir: Path) -> list[dict]:
    return [
        entry
        for entry in read_calls_jsonl(run_dir)
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
