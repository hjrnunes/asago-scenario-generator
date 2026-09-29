"""Stage 3 requests carry context rows through the prompt contract."""

from __future__ import annotations

import json

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.obligation_aware import (
    slot_filling as slot_filling_module,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    SlotIcaDraft,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

from tests.test_obligation_aware_stpa import _controls, _loss_analysis

_PROCESS = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _control_structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Pallet racking."),
        ),
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Move pallets between bays.",
                process_model_parts=(
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Whether the destination bay is free.",
                        values=["free", "occupied"],
                    ),
                ),
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Place a pallet in a bay.",
                        target=_PROCESS,
                        process_model_refs=["PM-1-1"],
                    ),
                ),
                feedback_channels=(
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Bay sensor reading.",
                        updates="PM-1-1",
                        source=_PROCESS,
                        source_kind=FeedbackSourceKind.operation_result,
                    ),
                ),
            ),
        ),
    )


def test_ica_prompt_keeps_findings_outside_the_context_table() -> None:
    """The context table narrows nothing: a deviation unsafe in a context no
    row expresses is still a finding, cited with context_row null."""
    from asago_scenario_generator.stpa.obligation_aware.prompts import (
        PROMPT_TEMPLATES_DIR,
    )

    text = " ".join(
        (PROMPT_TEMPLATES_DIR / "synthesis_ica_system.j2")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "it does not limit which deviations are unsafe" in text
    assert "write that finding as well, with `context_row: null`" in text
    assert "Use `context_row: null` only when" not in text


def test_context_rows_pass_preflight_and_fill_the_ica_context(tmp_path) -> None:
    structure = _control_structure()
    slot = next(
        item
        for item in create_slots(structure)
        if item.uca_type.value == "NOT_PROVIDED"
    )
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context="the destination bay is occupied"
                ),
                hazardous_context="the pallet is left in the aisle",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
                context_row="CA-1-1:ctx-2",
            ),
        ),
    )
    prompts: list[str] = []

    class Client:
        model = "context-rows"

        def complete(self, **kwargs):
            prompts.append(kwargs["user_prompt"])
            return LLMResult(
                content={"filled_slots": [draft.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    request = SynthesisSlotRequest(
        target_id="RESP-1",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        controls=_controls(),
    )
    provider = ObligationAwareLLMAdapter(
        Client(), run_dir=tmp_path, controls=_controls()
    )

    response = provider.fill(request)

    entries = [
        json.loads(line)
        for line in (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [entry["success"] for entry in entries] == [True]
    assert "CA-1-1:ctx-2" in prompts[0]
    compiled, error = slot_filling_module._compile_response_slots(
        response,
        request=request,
        expected={slot.slot_id: slot},
        diagnostics=[],
        loss_analysis=request.loss_analysis,
        control_structure=structure,
    )
    assert error is None
    ica = compiled[slot.slot_id].icas[0]
    assert ica.context_row == "CA-1-1:ctx-2"
    assert ica.process_model_context == {"PM-1-1": "occupied"}
