"""Stage 3 context coverage for replies that depend on what a source supplies."""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.obligation_aware import (
    slot_filling as slot_filling_module,
)
from asago_scenario_generator.stpa.obligation_aware.context_coverage import (
    CONTEXT_COVERAGE_STAGE_SUFFIX,
    context_coverage_gaps,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROMPT_TEMPLATES_DIR,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    _SlotProviderPayload,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.obligation_aware import _controls, _loss_analysis

_PROCESS = ElementRef(type=ReferenceType.controlled_process, id="CP-1")
APPLICABLE = "the source supplies an applicable answer"
NONE = "the source supplies no applicable answer"


def _structure(
    effect_kind: ControlActionEffectKind = ControlActionEffectKind.model_output,
    source_kind: FeedbackSourceKind = FeedbackSourceKind.retrieved_content,
    extra_values: dict[str, list[str]] | None = None,
) -> ControlStructure:
    extra_values = extra_values or {}
    return ControlStructure(
        controlled_processes=(ControlledProcess(cp_id="CP-1", description="Chat."),),
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Answer questions from the approved source.",
                security_constraint_refs=["SC-1"],
                process_model_parts=(
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="What the source supplies for the request.",
                        values=[APPLICABLE, NONE],
                    ),
                    ProcessModelPart(
                        pm_id="PM-1-2",
                        description="Whether the reply names a person.",
                        values=["names a person", "names no person"],
                    ),
                    *(
                        ProcessModelPart(pm_id=pm_id, description=pm_id, values=values)
                        for pm_id, values in extra_values.items()
                    ),
                ),
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Reply to the user.",
                        target=_PROCESS,
                        effect_kind=effect_kind,
                        process_model_refs=["PM-1-1", "PM-1-2", *extra_values],
                    ),
                ),
                feedback_channels=(
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Source text for the request.",
                        updates="PM-1-1",
                        source=_PROCESS,
                        source_kind=source_kind,
                    ),
                    FeedbackChannel(
                        fb_id="FB-1-2",
                        description="Draft reply text.",
                        updates="PM-1-2",
                        source=_PROCESS,
                        source_kind=FeedbackSourceKind.other,
                    ),
                ),
            ),
        ),
    )


def _slot(structure: ControlStructure, uca_type: str = "INCORRECT"):
    return next(
        item for item in create_slots(structure) if item.uca_type.value == uca_type
    )


def _finding(row: str | None, refs: tuple[str, ...] = ("PM-1-1",), **changes) -> dict:
    return {
        "deviation": changes.get("deviation", "the reply states an unsupported answer"),
        "hazardous_context": "the user receives an answer the source does not support",
        "loss_consequence": "the protected operation is harmed",
        "related_hazard_ids": ["H-1"],
        "related_constraint_ids": ["SC-1"],
        "process_model_refs": list(refs),
        "feedback_refs": [],
        "context_row": row,
    }


def _payload(slot_id: str, *findings: dict) -> dict:
    return {
        "filled_slots": [
            {
                "slot_id": slot_id,
                "is_na": False,
                "na_rationale": None,
                "findings": list(findings),
                "consideration_results": [],
            }
        ]
    }


def _draft_slots(slot_id: str, *findings: dict):
    return _SlotProviderPayload.model_validate(
        _payload(slot_id, *findings)
    ).filled_slots


def _request(structure: ControlStructure, slot) -> SynthesisSlotRequest:
    return SynthesisSlotRequest(
        target_id="RESP-1",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        controls=_controls(),
    )


class TestGaps:
    def test_finding_citing_the_source_without_a_row_leaves_both_values(self) -> None:
        structure = _structure()
        slot = _slot(structure)

        [gap] = context_coverage_gaps(
            _draft_slots(slot.slot_id, _finding(None)), _request(structure, slot)
        )

        assert gap.slot_id == slot.slot_id
        assert gap.constraint_id == "SC-1"
        assert gap.process_model_id == "PM-1-1"
        assert gap.uncovered_values == (APPLICABLE, NONE)
        assert gap.row_ids == (
            "CA-1-1:ctx-1",
            "CA-1-1:ctx-2",
            "CA-1-1:ctx-3",
            "CA-1-1:ctx-4",
        )

    def test_covered_no_answer_context_leaves_the_applicable_answer(self) -> None:
        structure = _structure()
        slot = _slot(structure)

        [gap] = context_coverage_gaps(
            _draft_slots(slot.slot_id, _finding("CA-1-1:ctx-3")),
            _request(structure, slot),
        )

        assert gap.uncovered_values == (APPLICABLE,)
        assert gap.row_ids == ("CA-1-1:ctx-1", "CA-1-1:ctx-2")

    def test_source_value_beyond_the_first_rows_still_has_rows(self) -> None:
        # 64 combinations: a first-12 cut held PM-1-1 at APPLICABLE in every
        # row, so a finding on APPLICABLE left NONE uncovered and rowless.
        structure = _structure(
            extra_values={
                "PM-1-3": ["morning", "noon", "evening", "night"],
                "PM-1-4": ["web", "app", "phone", "kiosk"],
            }
        )
        slot = _slot(structure)
        rows = {
            row.row_id: dict(row.assignments)
            for row in control_action_context_rows(structure, "CA-1-1")
        }
        applicable = next(
            row_id for row_id, row in rows.items() if row["PM-1-1"] == APPLICABLE
        )

        [gap] = context_coverage_gaps(
            _draft_slots(slot.slot_id, _finding(applicable)),
            _request(structure, slot),
        )

        assert gap.uncovered_values == (NONE,)
        assert gap.row_ids
        assert all(rows[row_id]["PM-1-1"] == NONE for row_id in gap.row_ids)

    def test_both_source_states_covered_is_no_gap(self) -> None:
        structure = _structure()
        slot = _slot(structure)
        slots = _draft_slots(
            slot.slot_id, _finding("CA-1-1:ctx-3"), _finding("CA-1-1:ctx-2")
        )

        assert context_coverage_gaps(slots, _request(structure, slot)) == ()

    @pytest.mark.parametrize(
        ("structure", "uca_type", "refs"),
        [
            (_structure(), "INCORRECT", ("PM-1-2",)),
            (_structure(), "NOT_PROVIDED", ("PM-1-1",)),
            (
                _structure(effect_kind=ControlActionEffectKind.tool_call),
                "INCORRECT",
                ("PM-1-1",),
            ),
            (
                _structure(source_kind=FeedbackSourceKind.user_message),
                "INCORRECT",
                ("PM-1-1",),
            ),
            (
                _structure(source_kind=FeedbackSourceKind.operation_result),
                "INCORRECT",
                ("PM-1-1",),
            ),
        ],
        ids=[
            "non-source-variable",
            "not-provided",
            "tool-call",
            "user-fed",
            "operation-result-fed",
        ],
    )
    def test_other_slots_and_variables_have_no_gap(
        self, structure, uca_type, refs
    ) -> None:
        slot = _slot(structure, uca_type)

        assert (
            context_coverage_gaps(
                _draft_slots(slot.slot_id, _finding(None, refs)),
                _request(structure, slot),
            )
            == ()
        )


def _Client(slot_payload: dict, *supplements: object) -> ScriptedClient:
    """Return the slot payload, then each queued supplement response."""
    return ScriptedClient([slot_payload, *supplements], model="context-coverage")


def _fill(tmp_path, client: _Client, structure: ControlStructure, slot):
    request = _request(structure, slot)
    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(request)
    compiled, error = slot_filling_module._compile_response_slots(
        response,
        request=request,
        expected={slot.slot_id: slot},
        diagnostics=[],
        loss_analysis=request.loss_analysis,
        control_structure=structure,
    )
    assert error is None
    return compiled[slot.slot_id].icas


def _entries(tmp_path) -> list[dict]:
    return read_calls_jsonl(tmp_path)


CONTRADICTION = "the reply states a value that differs from the supplied answer"


class TestSupplement:
    def test_added_finding_for_the_uncovered_context_is_compiled(
        self, tmp_path
    ) -> None:
        structure = _structure()
        slot = _slot(structure)
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3")),
            {
                "entries": [
                    {
                        "gap_id": "context-gap-1",
                        "findings": [_finding("CA-1-1:ctx-2", deviation=CONTRADICTION)],
                        "rationale": "a supplied answer can be misstated",
                    }
                ]
            },
        )

        icas = _fill(tmp_path, client, structure, slot)

        assert [ica.context_row for ica in icas] == ["CA-1-1:ctx-3", "CA-1-1:ctx-2"]
        assert icas[1].deviation == CONTRADICTION
        assert icas[1].process_model_context == {
            "PM-1-1": APPLICABLE,
            "PM-1-2": "names no person",
        }
        entries = _entries(tmp_path)
        assert [e["success"] for e in entries] == [True, True]
        assert entries[1]["stage"].endswith(CONTEXT_COVERAGE_STAGE_SUFFIX)
        supplement = client.calls[1]
        assert "context-gap-1" in supplement["user_prompt"]
        assert "CA-1-1:ctx-1" in supplement["user_prompt"]
        assert APPLICABLE in supplement["user_prompt"]

    def test_no_supplement_call_without_a_gap(self, tmp_path) -> None:
        structure = _structure()
        slot = _slot(structure)
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3"), _finding("CA-1-1:ctx-1"))
        )

        icas = _fill(tmp_path, client, structure, slot)

        assert len(icas) == 2
        assert len(client.calls) == 1

    def test_assessment_with_no_unsafe_row_keeps_the_findings(self, tmp_path) -> None:
        structure = _structure()
        slot = _slot(structure)
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3")),
            {
                "entries": [
                    {
                        "gap_id": "context-gap-1",
                        "findings": [],
                        "rationale": "every listed row is safe",
                    }
                ]
            },
        )

        icas = _fill(tmp_path, client, structure, slot)

        assert [ica.context_row for ica in icas] == ["CA-1-1:ctx-3"]

    def test_finding_outside_the_gap_rows_is_corrected_then_dropped(
        self, tmp_path
    ) -> None:
        structure = _structure()
        slot = _slot(structure)
        wrong_row = {
            "entries": [
                {
                    "gap_id": "context-gap-1",
                    "findings": [_finding("CA-1-1:ctx-4")],
                    "rationale": "no answer either",
                }
            ]
        }
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3")), wrong_row, wrong_row
        )

        icas = _fill(tmp_path, client, structure, slot)

        assert [ica.context_row for ica in icas] == ["CA-1-1:ctx-3"]
        assert len(client.calls) == 3
        assert "CA-1-1:ctx-4" in client.calls[2]["user_prompt"]
        assert [e["success"] for e in _entries(tmp_path)] == [True, False, False]

    def test_slot_response_counts_the_supplement_requests(self, tmp_path) -> None:
        structure = _structure()
        slot = _slot(structure)
        wrong_row = {
            "entries": [
                {
                    "gap_id": "context-gap-1",
                    "findings": [_finding("CA-1-1:ctx-4")],
                    "rationale": "no answer either",
                }
            ]
        }
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3")), wrong_row, wrong_row
        )

        response = ObligationAwareLLMAdapter(
            client, run_dir=tmp_path, controls=_controls()
        ).fill(_request(structure, slot))

        assert len(client.calls) == 3
        assert response.provider_calls == 3

    def test_provider_failure_keeps_the_slot_findings(self, tmp_path) -> None:
        structure = _structure()
        slot = _slot(structure)
        client = _Client(
            _payload(slot.slot_id, _finding("CA-1-1:ctx-3")),
            RuntimeError("transport closed"),
        )

        icas = _fill(tmp_path, client, structure, slot)

        assert [ica.context_row for ica in icas] == ["CA-1-1:ctx-3"]


def _template(name: str) -> str:
    return " ".join((PROMPT_TEMPLATES_DIR / name).read_text(encoding="utf-8").split())


def test_slot_prompt_treats_each_source_state_as_its_own_context() -> None:
    text = _template("_source_limited_reply.j2")

    assert "misstates it, contradicts it, or adds details it does not contain" in text
    assert "the source supplies no applicable answer" in text
    assert '{% include "_source_limited_reply.j2" %}' in _template(
        "synthesis_ica_system.j2"
    )
    assert '{% include "_source_limited_reply.j2" %}' in _template(
        "synthesis_ica_context_system.j2"
    )
