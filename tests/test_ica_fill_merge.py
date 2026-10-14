"""Findings of one slot that differ only by context row or pair become one ICA."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.ica_merge import (
    ICA_MERGES_FILENAME,
    IcaMerge,
    IcaMergedFinding,
    IcaMergeReport,
)
from asago_scenario_generator.pipeline.synthesis_persist import (
    _artifact_paths,
    _persist_ica_merges,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import _ica_merge_report
from asago_scenario_generator.stpa.obligation_aware import slot_filling
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
    ica_merge_entries,
    merge_equal_findings,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import _control_structure, _controls
from tests.helpers.scripted_client import ScriptedClient
from tests.stpa.test_ica_context_coverage import (
    _Client,
    _fill as _fill_icas,
    _finding as _row_finding,
    _payload as _reply,
    _request as _row_request,
    _slot as _row_slot,
    _structure as _row_structure,
)
from tests.test_ica_fill_pair import _request as _pair_request
from tests.test_ica_fill_pair import _two_constraint_analysis

SLOT_ID = "RESP-1:CA-1-1:INCORRECT"


def _draft_finding(
    deviation: str = "the reply states an unsupported answer",
    *,
    row: str | None = None,
    hazards: tuple[str, ...] = ("H-1",),
    constraints: tuple[str, ...] = ("SC-1",),
    pm: tuple[str, ...] = (),
    fb: tuple[str, ...] = (),
    context: str = "the user receives an unsupported answer",
    loss: str = "the protected operation is harmed",
) -> IcaFindingDraft:
    return IcaFindingDraft(
        deviation=IcaDeviationDraft(incorrect_value_or_effect=deviation),
        hazardous_context=context,
        loss_consequence=loss,
        related_hazard_ids=hazards,
        related_constraint_ids=constraints,
        process_model_refs=pm,
        feedback_refs=fb,
        context_row=row,
    )


def _slot_draft(
    findings: tuple[IcaFindingDraft, ...],
    results: tuple[tuple[str, tuple[int, ...]], ...] = (),
) -> SlotIcaDraft:
    return SlotIcaDraft(
        slot_id=SLOT_ID,
        is_na=False,
        findings=findings,
        consideration_results=tuple(
            ObligationIcaDraft(
                obligation_handle=handle,
                disposition="finding",
                finding_indexes=indexes,
                rationale=f"{handle} is expressed by these findings",
            )
            for handle, indexes in results
        ),
    )


class TestMergeEqualFindings:
    def test_same_triple_over_rows_and_pairs_is_one_finding(self) -> None:
        first = _draft_finding(
            row="CA-1-1:ctx-1",
            hazards=("H-2", "H-1"),
            constraints=("SC-2",),
            pm=("PM-1-1",),
            fb=("FB-1-1",),
        )
        second = _draft_finding(
            row="CA-1-1:ctx-2",
            hazards=("H-1", "H-3"),
            constraints=("SC-1", "SC-2"),
            pm=("PM-1-2", "PM-1-1"),
            fb=("FB-1-2",),
        )

        merged, groups = merge_equal_findings(_slot_draft((first, second)))

        [finding] = merged.findings
        assert groups == ((0, 1),)
        assert finding.context_row == "CA-1-1:ctx-1"
        assert finding.deviation == first.deviation
        assert finding.related_hazard_ids == ("H-2", "H-1", "H-3")
        assert finding.related_constraint_ids == ("SC-2", "SC-1")
        assert finding.process_model_refs == ("PM-1-1", "PM-1-2")
        assert finding.feedback_refs == ("FB-1-1", "FB-1-2")

    @pytest.mark.parametrize(
        "other",
        [
            {"deviation": "the reply omits a required caveat"},
            {"context": "the user is a minor"},
            {"loss": "a customer is harmed"},
        ],
        ids=["deviation", "hazardous-context", "loss-consequence"],
    )
    def test_findings_that_differ_in_the_key_stay_separate(self, other) -> None:
        findings = (_draft_finding(row="r1"), _draft_finding(row="r2", **other))

        merged, groups = merge_equal_findings(_slot_draft(findings))

        assert merged.findings == findings
        assert groups == ((0,), (1,))

    def test_text_is_compared_after_stripping(self) -> None:
        findings = (
            _draft_finding("a wrong value", context="a context", loss="a loss"),
            _draft_finding(" a wrong value ", context=" a context\n", loss=" a loss "),
        )

        merged, groups = merge_equal_findings(_slot_draft(findings))

        assert len(merged.findings) == 1
        assert groups == ((0, 1),)

    def test_groups_keep_the_order_of_first_appearance(self) -> None:
        a, b = "deviation a", "deviation b"
        findings = tuple(
            _draft_finding(text, row=f"r{index}")
            for index, text in enumerate((a, b, a, b, a))
        )

        merged, groups = merge_equal_findings(_slot_draft(findings))

        assert groups == ((0, 2, 4), (1, 3))
        assert [item.deviation.text for item in merged.findings] == [a, b]
        assert [item.context_row for item in merged.findings] == ["r0", "r1"]

    def test_finding_indexes_move_to_the_merged_index_without_repeats(self) -> None:
        findings = tuple(
            _draft_finding(text, row=f"r{index}")
            for index, text in enumerate(("a", "a", "a", "b", "b", "b", "c", "c", "c"))
        )
        draft = _slot_draft(
            findings,
            (("R1", (0, 3, 6)), ("R2", (0, 1, 2)), ("R3", (8, 4, 1))),
        )

        merged, _groups = merge_equal_findings(draft)

        assert [item.finding_indexes for item in merged.consideration_results] == [
            (0, 1, 2),
            (0,),
            (2, 1, 0),
        ]
        assert [item.obligation_handle for item in merged.consideration_results] == [
            "R1",
            "R2",
            "R3",
        ]

    def test_other_results_keep_their_text_and_disposition(self) -> None:
        findings = (_draft_finding(row="r1"), _draft_finding(row="r2"))
        draft = SlotIcaDraft(
            slot_id=SLOT_ID,
            is_na=False,
            findings=findings,
            consideration_results=(
                ObligationIcaDraft(
                    obligation_handle="R1",
                    disposition="unresolved",
                    rationale="no finding expresses it",
                ),
            ),
        )

        merged, _groups = merge_equal_findings(draft)

        assert merged.consideration_results == draft.consideration_results

    def test_nothing_to_merge_returns_the_draft_itself(self) -> None:
        draft = _slot_draft(
            (_draft_finding("a"), _draft_finding("b")), (("R1", (0, 1)),)
        )

        merged, groups = merge_equal_findings(draft)

        assert merged is draft
        assert groups == ((0,), (1,))

    def test_not_applicable_draft_is_returned_unchanged(self) -> None:
        draft = SlotIcaDraft(slot_id=SLOT_ID, is_na=True, na_rationale="not relevant")

        merged, groups = merge_equal_findings(draft)

        assert merged is draft
        assert groups == ()

    def test_a_merged_finding_that_fails_a_validator_raises(self, monkeypatch) -> None:
        # No reply can make the ordered union repeat an ID, so the validator
        # is reached by corrupting the union itself: it proves the merged
        # finding is built through validation.
        monkeypatch.setattr(
            slot_filling,
            "_ordered_union",
            lambda groups: tuple(item for group in groups for item in group),
        )
        findings = (_draft_finding(row="r1"), _draft_finding(row="r2"))

        with pytest.raises(ValueError, match="must contain unique references"):
            merge_equal_findings(_slot_draft(findings))


class TestMergeEntries:
    def _merged(self):
        findings = (
            _draft_finding("a", row="CA-1-1:ctx-1", hazards=("H-1",)),
            _draft_finding("b", row="CA-1-1:ctx-9"),
            _draft_finding(
                "a",
                row="CA-1-1:ctx-2",
                hazards=("H-2",),
                constraints=("SC-2",),
            ),
            _draft_finding("a", row=None, hazards=("H-3",), constraints=("SC-3",)),
        )
        draft = _slot_draft(findings)
        merged, groups = merge_equal_findings(draft)
        return draft, groups, merged

    def test_one_entry_per_merged_group_with_each_folded_finding(self) -> None:
        draft, groups, merged = self._merged()

        entries = ica_merge_entries(
            "RESP-1", SLOT_ID, draft, groups, tuple(f"{SLOT_ID}:{n}" for n in (1, 2))
        )

        assert entries == (
            IcaMerge(
                target_id="RESP-1",
                slot_id=SLOT_ID,
                ica_id=f"{SLOT_ID}:1",
                findings=(
                    IcaMergedFinding(
                        finding_index=0,
                        context_row="CA-1-1:ctx-1",
                        related_hazard_ids=("H-1",),
                        related_constraint_ids=("SC-1",),
                    ),
                    IcaMergedFinding(
                        finding_index=2,
                        context_row="CA-1-1:ctx-2",
                        related_hazard_ids=("H-2",),
                        related_constraint_ids=("SC-2",),
                    ),
                    IcaMergedFinding(
                        finding_index=3,
                        context_row=None,
                        related_hazard_ids=("H-3",),
                        related_constraint_ids=("SC-3",),
                    ),
                ),
            ),
        )
        assert len(merged.findings) == 2

    def test_no_entry_when_nothing_merges(self) -> None:
        draft = _slot_draft((_draft_finding("a"), _draft_finding("b")))
        _merged, groups = merge_equal_findings(draft)

        assert ica_merge_entries("RESP-1", SLOT_ID, draft, groups, ("i:1", "i:2")) == ()

    def test_report_orders_entries_and_round_trips(self) -> None:
        draft, groups, _merged = self._merged()
        [entry] = ica_merge_entries(
            "RESP-1", SLOT_ID, draft, groups, (f"{SLOT_ID}:1", f"{SLOT_ID}:2")
        )
        later = entry.model_copy(update={"target_id": "RESP-2"})

        report = IcaMergeReport(merges=(later, entry))

        assert [item.target_id for item in report.merges] == ["RESP-1", "RESP-2"]
        assert IcaMergeReport.from_yaml(report.to_yaml()) == report
        assert ICA_MERGES_FILENAME == "ica-merges.yaml"


class TestProviderMerge:
    def test_row_copies_compile_to_one_ica_with_the_first_row(self, tmp_path) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        client = _Client(
            _reply(
                slot.slot_id, _row_finding("CA-1-1:ctx-3"), _row_finding("CA-1-1:ctx-1")
            )
        )

        icas = _fill_icas(tmp_path, client, structure, slot)

        [ica] = icas
        assert ica.context_row == "CA-1-1:ctx-3"
        assert ica.process_model_context is not None
        assert len(client.calls) == 1

    def test_the_raw_reply_in_the_call_log_keeps_every_finding(self, tmp_path) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        client = _Client(
            _reply(
                slot.slot_id, _row_finding("CA-1-1:ctx-3"), _row_finding("CA-1-1:ctx-1")
            )
        )

        _fill_icas(tmp_path, client, structure, slot)

        [entry] = read_calls_jsonl(tmp_path)
        assert json.dumps(entry).count("CA-1-1:ctx-1") >= 1
        assert json.dumps(entry).count("CA-1-1:ctx-3") >= 1

    def test_a_coverage_supplement_runs_on_the_findings_as_written(
        self, tmp_path
    ) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        same_text = {
            "entries": [
                {
                    "gap_id": "context-gap-1",
                    "findings": [_row_finding("CA-1-1:ctx-2")],
                    "rationale": "a supplied answer can be misstated",
                }
            ]
        }
        client = _Client(_reply(slot.slot_id, _row_finding("CA-1-1:ctx-3")), same_text)

        icas = _fill_icas(tmp_path, client, structure, slot)

        assert len(client.calls) == 2
        assert [ica.context_row for ica in icas] == ["CA-1-1:ctx-3"]

    def test_pair_copies_merge_and_the_merged_references_are_checked(
        self, tmp_path
    ) -> None:
        request = _pair_request()
        slot_id = request.slots[0].slot_id

        def finding(pair: str) -> dict[str, Any]:
            return {
                "deviation": "the request is accepted before it is reviewed",
                "hazardous_context": "an unreviewed request reaches the process",
                "loss_consequence": "the protected operation is harmed",
                "governing_pairs": [pair],
                "process_model_refs": [],
                "feedback_refs": [],
                "context_row": None,
            }

        client = ScriptedClient(
            [
                {
                    "filled_slots": [
                        {
                            "slot_id": slot_id,
                            "is_na": False,
                            "na_rationale": None,
                            "findings": [finding("SC-1/H-1"), finding("SC-2/H-2")],
                            "consideration_results": {},
                        }
                    ]
                }
            ],
            model="fill-merge",
        )

        response = ObligationAwareLLMAdapter(
            client, run_dir=tmp_path, controls=_controls()
        ).fill(request)

        [ica] = response.filled_slots[0].icas
        assert ica.related_hazards == ["H-1", "H-2"]
        assert ica.related_constraints == ["SC-1", "SC-2"]
        [merge] = response.ica_merges
        assert merge.target_id == "RESP-1"
        assert merge.slot_id == slot_id
        assert merge.ica_id == ica.ica_id
        assert [item.finding_index for item in merge.findings] == [0, 1]
        assert [item.related_hazard_ids for item in merge.findings] == [
            ("H-1",),
            ("H-2",),
        ]
        assert [item.related_constraint_ids for item in merge.findings] == [
            ("SC-1",),
            ("SC-2",),
        ]

    def test_the_response_records_the_row_merge(self, tmp_path) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        request = _row_request(structure, slot)
        client = _Client(
            _reply(
                slot.slot_id, _row_finding("CA-1-1:ctx-3"), _row_finding("CA-1-1:ctx-1")
            )
        )

        response = ObligationAwareLLMAdapter(
            client, run_dir=tmp_path, controls=_controls()
        ).fill(request)

        [merge] = response.ica_merges
        assert merge.ica_id == f"{slot.slot_id}:1"
        assert [item.context_row for item in merge.findings] == [
            "CA-1-1:ctx-3",
            "CA-1-1:ctx-1",
        ]

    def test_no_entry_appears_when_nothing_merges(self, tmp_path) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        request = _row_request(structure, slot)
        client = _Client(
            _reply(
                slot.slot_id,
                _row_finding("CA-1-1:ctx-3"),
                _row_finding("CA-1-1:ctx-1", deviation="the reply names a person"),
            )
        )

        response = ObligationAwareLLMAdapter(
            client, run_dir=tmp_path, controls=_controls()
        ).fill(request)

        assert len(response.filled_slots[0].icas) == 2
        assert response.ica_merges == ()

    def test_the_fill_request_does_not_change_with_the_merge(self, tmp_path) -> None:
        structure = _row_structure()
        slot = _row_slot(structure)
        request = _row_request(structure, slot)
        copies = _reply(
            slot.slot_id, _row_finding("CA-1-1:ctx-3"), _row_finding("CA-1-1:ctx-1")
        )
        distinct = _reply(
            slot.slot_id,
            _row_finding("CA-1-1:ctx-3"),
            _row_finding("CA-1-1:ctx-1", deviation="the reply names a person"),
        )

        seen = []
        for reply in (copies, distinct):
            client = _Client(reply)
            ObligationAwareLLMAdapter(
                client, run_dir=tmp_path / str(len(seen)), controls=_controls()
            ).fill(request)
            seen.append(client.calls[0])

        system, user = build_synthesis_slot_prompts(
            target_id=request.target_id,
            slots=request.slots,
            routed_briefs=request.routed_briefs,
            routed_routes=request.routed_routes,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
        for call in seen:
            assert call["system_prompt"] == system
            assert call["user_prompt"] == user
        assert (
            seen[0]["response_format"].model_json_schema()
            == seen[1]["response_format"].model_json_schema()
        )
        assert "merge" not in system.lower()


class _CopyingModel:
    """Answer each request through the provider adapter, one copy-laden slot.

    Every slot but the INCORRECT one is N/A; the INCORRECT slot repeats one
    finding *copies* times.
    """

    def __init__(self, tmp_path, copies: int) -> None:
        self.tmp_path = tmp_path
        self.copies = copies
        self.requests = 0

    def fill(self, request):
        self.requests += 1
        finding = {
            "deviation": "the request is accepted before it is reviewed",
            "hazardous_context": "an unreviewed request reaches the process",
            "loss_consequence": "the protected operation is harmed",
            "governing_pairs": ["SC-1/H-1"],
            "process_model_refs": [],
            "feedback_refs": [],
            "context_row": None,
        }
        slots = [
            {
                "slot_id": slot.slot_id,
                "is_na": slot.uca_type.value != "INCORRECT",
                "na_rationale": None
                if slot.uca_type.value == "INCORRECT"
                else "No finding applies.",
                "findings": [finding] * self.copies
                if slot.uca_type.value == "INCORRECT"
                else [],
                "consideration_results": {},
            }
            for slot in request.slots
        ]
        client = ScriptedClient([{"filled_slots": slots}], model="fill-merge-run")
        return ObligationAwareLLMAdapter(
            client, run_dir=self.tmp_path / str(self.requests), controls=_controls()
        ).fill(request)


class TestFillRecord:
    def _run(self, tmp_path, copies: int):
        result = fill_synthesis_slots(
            _CopyingModel(tmp_path, copies),
            briefs=(),
            routes=(),
            loss_analysis=_two_constraint_analysis(),
            control_structure=_control_structure(),
            controls=_controls(),
        )
        return result, SLOT_ID

    def test_an_accepted_response_carries_its_merges_to_the_result(
        self, tmp_path
    ) -> None:
        result, slot = self._run(tmp_path, copies=3)

        [merge] = result.ica_merges
        assert merge.slot_id == slot
        assert merge.ica_id == f"{slot}:1"
        assert [item.finding_index for item in merge.findings] == [0, 1, 2]
        assert result.result.ica_merges == result.ica_merges
        [filled] = [s for s in result.ica_enumeration.slots if s.slot_id == slot]
        assert [ica.ica_id for ica in filled.icas] == [merge.ica_id]

    def test_a_slot_without_copies_leaves_the_result_empty(self, tmp_path) -> None:
        result, _slot = self._run(tmp_path, copies=1)

        assert result.ica_merges == ()


class TestPublication:
    def test_merges_publish_as_a_sidecar_next_to_the_other_ica_evidence(
        self, tmp_path
    ) -> None:
        result, _slot = TestFillRecord()._run(tmp_path / "fill", copies=3)
        report = _ica_merge_report(result)

        path = _persist_ica_merges(tmp_path, report)

        assert path == tmp_path / ICA_MERGES_FILENAME
        assert report is not None
        assert IcaMergeReport.from_yaml(path.read_text(encoding="utf-8")) == report
        assert [m.ica_id for m in report.merges] == list(
            m.ica_id for m in result.ica_merges
        )

    def test_nothing_merged_publishes_no_sidecar(self, tmp_path) -> None:
        result, _slot = TestFillRecord()._run(tmp_path / "fill", copies=1)

        report = _ica_merge_report(result)

        assert report is None
        assert _persist_ica_merges(tmp_path, report) is None
        assert not (tmp_path / ICA_MERGES_FILENAME).exists()

    def test_the_run_lists_the_sidecar_among_its_artifacts(self, tmp_path) -> None:
        path = tmp_path / ICA_MERGES_FILENAME

        paths = _artifact_paths(
            tmp_path,
            SimpleNamespace(target_observations=None),
            {},
            target_realization_path=None,
            operation_enrichment=None,
            report_path=None,
            ica_merges_path=path,
        )

        assert paths == {ICA_MERGES_FILENAME: path}
