"""A Stage 1a draft that names an unknown ID gets one reference correction.

A risk_derivation or gap_analysis draft is otherwise well formed, but one
hazard's ``related_losses`` or one constraint's ``related_hazards`` names an
ID that no declared record has (for example a constraint that names its own
handle where the hazard handle belongs).  The draft gets exactly one
correction request through the existing reference-list repair; the request
carries the validator's finding and offers the declared IDs, with their
meanings, as replacements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    ReferenceRepairPlan,
    ReferenceRepairResponse,
    RepairRejected,
    merge_reference_repair,
    select_reference_repairs,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import MockLLMClient, valid_risk_draft_dict

# The gap_analysis response body a recorded run stopped on: the constraint
# lists its own handle in related_hazards instead of the hazard it declared.
RECORDED_GAP_RESPONSE = json.loads(
    '{"risk_card_losses": [], "use_case_losses": [{"handle": "merchant_loss", '
    '"description": "Financial or reputational harm to merchants due to '
    "incorrect refund processing or inaccurate representation of their "
    'policies.", "provenance": "use_case", "source_risk_cards": []}], '
    '"hazards": [{"handle": "merchant_policy_hazard", "description": "The '
    "assistant misrepresents merchant-specific policies or processes refunds "
    "against the wrong merchant via `process_refund` or `retrieve_policy` "
    'operations.", "related_losses": ["merchant_loss", "L-1"]}], '
    '"security_constraints": [{"handle": "merchant_policy_constraint", '
    '"rule": "The assistant must only process refunds or provide policy '
    "details that align with the merchant associated with the specific "
    '`order_id`.", "applies_when": ["a refund is requested via '
    '`process_refund`", "a policy is retrieved via `retrieve_policy`"], '
    '"behavior_class": "wrong_information", "related_hazards": '
    '["merchant_policy_constraint"]}]}'
)
GAP_HAZARD_TEXT = RECORDED_GAP_RESPONSE["hazards"][0]["description"]


def _constraint_repair(constraint_id: str, related_hazards: list[str]) -> dict:
    return {
        "hazards": [],
        "security_constraints": [
            {"constraint_id": constraint_id, "related_hazards": related_hazards}
        ],
    }


def _derive(
    tmp_path: Path,
    drafts: list[dict],
    repairs: list[dict],
    warnings: list[str] | None = None,
) -> LossAnalysis:
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, drafts)
    client.set_response_for(ReferenceRepairResponse, repairs)
    return derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
        normalization_warnings=warnings,
    )


def _stage1a_steps(run_dir: Path) -> list[str]:
    return [
        entry["step"]
        for entry in read_calls_jsonl(run_dir)
        if entry["stage"] == "stage_1a"
    ]


def _records(run_dir: Path, kind: str) -> list[dict]:
    record = yaml.safe_load((run_dir / "loss-analysis-repair.yaml").read_text())
    return [entry for entry in record["records"] if entry["kind"] == kind]


def _call_entry(run_dir: Path, step: str) -> dict:
    return next(entry for entry in read_calls_jsonl(run_dir) if entry["step"] == step)


class TestUnknownReferenceCorrection:
    """One correction request; a corrected list is accepted."""

    def test_recorded_gap_draft_is_corrected_once(self, tmp_path) -> None:
        analysis = _derive(
            tmp_path,
            [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE],
            [_constraint_repair("SC-2", ["H-2"])],
        )

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        constraints = {c.constraint_id: c for c in analysis.security_constraints}
        assert constraints["SC-2"].related_hazards == ["H-2"]
        [entry] = _records(tmp_path, "repair")
        assert entry["stage"] == "gap_analysis"
        assert entry["identity"] == "SC-2.related_hazards"
        assert entry["outcome"] == "repaired"
        assert entry["applied"]["references"] == ["H-2"]
        assert (
            "security_constraints.related_hazards unknown IDs: "
            "SC-2 -> merchant_policy_constraint"
        ) in entry["reason"]

    def test_request_carries_the_finding_and_the_declared_ids(self, tmp_path) -> None:
        _derive(
            tmp_path,
            [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE],
            [_constraint_repair("SC-2", ["H-2"])],
        )

        entry = _call_entry(tmp_path, "gap_analysis_repair")
        system_prompt = entry["system_prompt_text"]
        user_prompt = entry["user_prompt_text"]
        assert "names an ID that no declared record has" in system_prompt
        assert "You cannot declare a new record in\nthis repair." in system_prompt
        assert (
            "**Validation feedback:** gap_analysis draft has invalid "
            "cross-references: security_constraints.related_hazards unknown "
            "IDs: merchant_policy_constraint"
        ) in user_prompt
        assert (
            "### SC-2.related_hazards\n"
            "- **Security constraint text:** The assistant must only process "
            "refunds or provide policy details that align with the merchant "
            "associated with the specific `order_id`.\n"
            '- **Original list, verbatim:** ["merchant_policy_constraint"]\n'
            "- **Validation error:** security_constraints.related_hazards "
            "unknown IDs: SC-2 -> merchant_policy_constraint\n"
            "- **Unknown IDs:** merchant_policy_constraint\n"
            "- **IDs to keep:** none\n"
            "- **Replacement IDs** (an unknown entry may become one of these):\n"
            "  - **H-1**: The agent executes an unintended payment.\n"
            f"  - **H-2**: {GAP_HAZARD_TEXT}\n"
            "- **Permitted correction:** for each unknown entry, remove it or "
            "replace it with one listed replacement ID; the list has no other "
            "ID to keep; name no ID outside the replacement IDs and return at "
            "least one ID"
        ) in user_prompt

    def test_duplicate_and_unknown_ids_in_a_risk_draft_get_one_correction(
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
        risk["risk_dispositions"][0]["loss_ids"] = ["L-1", "L-2"]
        risk["hazards"] = [
            {
                "hazard_id": "H-1",
                "description": "The agent executes an unintended payment.",
                "related_losses": ["L-1", "L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": "The agent discloses account data.",
                "related_losses": ["L-2"],
            },
        ]
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-2", "H-9"]
        repair = {
            "hazards": [{"hazard_id": "H-1", "related_losses": ["L-1"]}],
            "security_constraints": [
                {"constraint_id": "SC-1", "related_hazards": ["H-1", "H-2"]}
            ],
        }
        gap = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }

        analysis = _derive(tmp_path, [risk, gap], [repair])

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        constraints = {c.constraint_id: c for c in analysis.security_constraints}
        assert constraints["SC-1"].related_hazards == ["H-1", "H-2"]
        identities = [entry["identity"] for entry in _records(tmp_path, "repair")]
        assert identities == ["H-1.related_losses", "SC-1.related_hazards"]

    def test_unknown_only_request_carries_no_repeated_id_wording(
        self, tmp_path
    ) -> None:
        _derive(
            tmp_path,
            [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE],
            [_constraint_repair("SC-2", ["H-2"])],
        )

        entry = _call_entry(tmp_path, "gap_analysis_repair")
        system_prompt = entry["system_prompt_text"]
        user_prompt = entry["user_prompt_text"]
        assert (
            "security constraint's `related_hazards` names an ID that no declared "
            "record has.\n"
        ) in system_prompt
        assert "Each list names an unknown ID: an ID that no declared record" in (
            system_prompt
        )
        assert "each names an\nID that no declared record has." in user_prompt
        assert "only. Replace each unknown entry" in user_prompt
        for repeated_wording in (
            "more than once",
            "repeated entry",
            "the repeat",
            "may also name",
        ):
            assert repeated_wording not in system_prompt
            assert repeated_wording not in user_prompt

    def test_a_request_with_repeated_and_unknown_ids_names_both(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["hazards"][0]["related_losses"] = ["L-1", "L-1"]
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-9"]
        repair = {
            "hazards": [{"hazard_id": "H-1", "related_losses": ["L-1"]}],
            "security_constraints": [
                {"constraint_id": "SC-1", "related_hazards": ["H-1"]}
            ],
        }
        gap = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }

        _derive(tmp_path, [risk, gap], [repair])

        entry = _call_entry(tmp_path, "risk_derivation_repair")
        system_prompt = entry["system_prompt_text"]
        user_prompt = entry["user_prompt_text"]
        assert (
            "names the same ID more than once\nor names an ID that no declared "
            "record has.\n"
        ) in system_prompt
        assert "Each list names one or more IDs more than once." in system_prompt
        assert "A list may also name an unknown ID" in system_prompt
        assert (
            "each names an\nID more than once or an ID that no declared record has."
        ) in user_prompt
        assert "only. Remove each repeated\nentry" in user_prompt
        assert "name. Replace each unknown entry" in user_prompt

    def test_an_empty_gap_list_still_stops_without_a_call(self, tmp_path) -> None:
        gap = json.loads(json.dumps(RECORDED_GAP_RESPONSE))
        gap["security_constraints"][0]["related_hazards"] = []

        with pytest.raises(StageError):
            _derive(tmp_path, [valid_risk_draft_dict(), gap], [])

        assert _stage1a_steps(tmp_path) == ["risk_derivation", "gap_analysis"]


def _unknown_plan() -> ReferenceRepairPlan:
    draft = LossAnalysisDraft.model_validate(valid_risk_draft_dict())
    draft.security_constraints[0].related_hazards = ["H-1", "constraint_handle"]
    draft.hazards.append(
        draft.hazards[0].model_copy(update={"hazard_id": "H-2"}, deep=True)
    )
    return ReferenceRepairPlan(
        prior=draft,
        selected=select_reference_repairs(
            draft, valid_loss_ids={"L-1"}, valid_hazard_ids={"H-1", "H-2"}
        ),
    )


class TestUnknownReferenceMerge:
    """The merge accepts only a list that names known IDs."""

    def test_selection_names_the_unknown_entry(self) -> None:
        [selected] = _unknown_plan().selected

        assert selected.identity == "SC-1.related_hazards"
        assert selected.unknown == ("constraint_handle",)
        assert selected.kept == ("H-1",)
        assert selected.replacement_ids == ("H-2",)

    def test_unknown_entry_replaced_with_a_declared_id_is_accepted(self) -> None:
        merged = merge_reference_repair(
            _unknown_plan(),
            ReferenceRepairResponse.model_validate(
                _constraint_repair("SC-1", ["H-1", "H-2"])
            ),
        )

        assert merged.security_constraints[0].related_hazards == ["H-1", "H-2"]

    @pytest.mark.parametrize(
        ("returned", "expected"),
        [
            pytest.param(
                ["H-1", "constraint_handle"],
                "repair_reference_unknown: SC-1.related_hazards adds constraint_handle",
                id="unknown-left",
            ),
            pytest.param(
                ["H-2"],
                "repair_edit_forbidden: SC-1.related_hazards must keep H-1",
                id="kept-id-dropped",
            ),
        ],
    )
    def test_out_of_scope_list_is_rejected(
        self, returned: list[str], expected: str
    ) -> None:
        with pytest.raises(RepairRejected, match=expected):
            merge_reference_repair(
                _unknown_plan(),
                ReferenceRepairResponse.model_validate(
                    _constraint_repair("SC-1", returned)
                ),
            )


class TestUnresolvedReferenceDrop:
    """A correction that still fails drops what it could not resolve.

    Deterministic code removes each unknown or repeated entry; a record whose
    list is left without a valid ID is dropped, and so is a constraint whose
    every hazard was dropped.  The draft is validated again, and only a draft
    that is still invalid stops the unit.
    """

    def test_unresolved_gap_constraint_is_dropped_and_recorded(self, tmp_path) -> None:
        warnings: list[str] = []
        analysis = _derive(
            tmp_path,
            [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE],
            [_constraint_repair("SC-2", ["merchant_policy_constraint"])],
            warnings,
        )

        assert _stage1a_steps(tmp_path) == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        assert [c.constraint_id for c in analysis.security_constraints] == ["SC-1"]
        assert [h.hazard_id for h in analysis.hazards] == ["H-1", "H-2"]
        [rejected] = _records(tmp_path, "repair")
        assert rejected["outcome"] == "rejected"
        [dropped] = _records(tmp_path, "reference_dropped")
        assert dropped["stage"] == "gap_analysis"
        assert dropped["identity"] == "SC-2.related_hazards"
        assert dropped["outcome"] == "dropped"
        assert dropped["proposed"] == {"references": ["merchant_policy_constraint"]}
        assert dropped["applied"] == {
            "references": [],
            "dropped_entries": ["merchant_policy_constraint"],
            "dropped_records": ["SC-2"],
        }
        assert (
            "gap_analysis reference SC-2.related_hazards dropped "
            "merchant_policy_constraint; SC-2 had no other valid ID and was dropped"
        ) in warnings

    def test_a_list_with_a_known_id_keeps_its_record(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["security_constraints"][0]["related_hazards"] = ["H-1", "H-9", "H-1"]

        analysis = _derive(
            tmp_path,
            [risk, _empty_gap()],
            [_constraint_repair("SC-1", ["H-9"])],
        )

        [constraint] = analysis.security_constraints
        assert constraint.related_hazards == ["H-1"]
        [dropped] = _records(tmp_path, "reference_dropped")
        assert dropped["identity"] == "SC-1.related_hazards"
        assert dropped["applied"] == {
            "references": ["H-1"],
            "dropped_entries": ["H-9", "H-1"],
            "dropped_records": [],
        }

    def test_a_dropped_hazard_drops_the_constraints_left_without_a_hazard(
        self, tmp_path
    ) -> None:
        gap = _two_hazard_gap()
        gap["hazards"][1]["related_losses"] = ["unknown_loss"]

        analysis = _derive(
            tmp_path,
            [valid_risk_draft_dict(), gap],
            [
                {
                    "hazards": [
                        {"hazard_id": "H-3", "related_losses": ["unknown_loss"]}
                    ],
                    "security_constraints": [],
                }
            ],
        )

        assert [h.hazard_id for h in analysis.hazards] == ["H-1", "H-2"]
        constraints = {c.constraint_id: c for c in analysis.security_constraints}
        assert sorted(constraints) == ["SC-1", "SC-2"]
        assert constraints["SC-2"].related_hazards == ["H-2"]
        dropped = {
            entry["identity"]: entry["applied"]
            for entry in _records(tmp_path, "reference_dropped")
        }
        assert dropped == {
            "H-3.related_losses": {
                "references": [],
                "dropped_entries": ["unknown_loss"],
                "dropped_records": ["H-3"],
            },
            "SC-2.related_hazards": {
                "references": ["H-2"],
                "dropped_entries": ["H-3"],
                "dropped_records": [],
            },
            "SC-3.related_hazards": {
                "references": [],
                "dropped_entries": ["H-3"],
                "dropped_records": ["SC-3"],
            },
        }

    def test_a_draft_still_invalid_after_the_drop_stops(self, tmp_path) -> None:
        risk = valid_risk_draft_dict()
        risk["security_constraints"] = []
        gap = _empty_gap()
        gap["security_constraints"] = [
            {
                "handle": "payment_constraint",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "behavior_class": "unauthorized_write",
                "related_hazards": ["payment_constraint"],
            }
        ]

        with pytest.raises(StageError) as exc_info:
            _derive(
                tmp_path,
                [risk, gap],
                [_constraint_repair("SC-1", ["payment_constraint"])],
            )

        message = str(exc_info.value)
        assert message.startswith("stage_1a/gap_analysis: targeted repair failed")
        assert "dropping the unresolved references left an invalid draft" in message
        assert "no security constraints were declared" in message
        assert "draft_references failure class" in message
        assert "Missing hazard declarations: payment_constraint" in message
        assert _records(tmp_path, "reference_dropped") == []

    def test_a_correction_without_a_response_stops_without_a_drop(
        self, tmp_path
    ) -> None:
        with pytest.raises(StageError, match="targeted repair failed"):
            _derive(tmp_path, [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE], [])

        assert not (tmp_path / "loss-analysis.yaml").exists()
        assert _records(tmp_path, "reference_dropped") == []


def _empty_gap() -> dict:
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }


def _two_hazard_gap() -> dict:
    """A gap draft with two hazards; SC-2 names both, SC-3 only the second."""
    gap = json.loads(json.dumps(RECORDED_GAP_RESPONSE))
    gap["hazards"].append(
        {
            "handle": "refund_hazard",
            "description": "The assistant refunds an order twice.",
            "related_losses": ["L-1"],
        }
    )
    gap["security_constraints"][0]["related_hazards"] = [
        "merchant_policy_hazard",
        "refund_hazard",
    ]
    gap["security_constraints"].append(
        {
            "handle": "refund_constraint",
            "rule": "The assistant must refund an order at most once.",
            "applies_when": ["a refund is requested via `process_refund`"],
            "behavior_class": "unauthorized_write",
            "related_hazards": ["refund_hazard"],
        }
    )
    return gap
