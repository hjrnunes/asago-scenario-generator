"""N/A rationale contract for slot filling.

The slot prompt does not ask for an argument about the action's absence,
because that raised the share of NOT_PROVIDED slots marked N/A. The only
deterministic check is that an N/A rationale is present and non-empty; its
meaning stays with the model.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot, UCAType
from asago_scenario_generator.stpa.obligation_aware.contracts import SlotIcaDraft
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _validate_compiled_slot,
    compile_ica_slot_draft,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _loss_analysis,
    _provider_slot_request,
)


def _not_provided_slot():
    slots = create_slots(_control_structure())
    return next(item for item in slots if item.uca_type is UCAType.not_provided)


def _na_draft(rationale: str | None) -> SlotIcaDraft:
    """Build an N/A draft that skips the draft model's own validation."""
    return SlotIcaDraft.model_construct(
        slot_id=_not_provided_slot().slot_id,
        is_na=True,
        na_rationale=rationale,
        findings=(),
        consideration_results=(),
    )


def _normalized_system_prompt() -> str:
    request = _provider_slot_request()
    system_prompt, _user_prompt = build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )
    return " ".join(system_prompt.split())


def test_prompt_does_not_ask_for_an_absence_argument() -> None:
    prompt = _normalized_system_prompt()

    assert "For a NOT_PROVIDED slot marked N/A" not in prompt
    assert "absence cannot be hazardous" not in prompt
    assert "lacks a requirement" not in prompt


def test_prompt_keeps_the_general_na_contract() -> None:
    prompt = _normalized_system_prompt()

    assert "a non-empty `na_rationale` citing a complete structural property" in prompt


@pytest.mark.parametrize("rationale", [None, "", "   ", "\n\t"])
def test_draft_compiler_rejects_an_absent_or_blank_na_rationale(rationale) -> None:
    slot = _not_provided_slot()

    with pytest.raises(ValueError, match="na_rationale"):
        compile_ica_slot_draft(
            _na_draft(rationale),
            slot=slot,
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
        )


def test_draft_compiler_keeps_a_present_rationale_unchanged() -> None:
    slot = _not_provided_slot()
    text = "Omitting the action cannot be hazardous because no request is pending."

    compiled = compile_ica_slot_draft(
        _na_draft(text),
        slot=slot,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )

    assert compiled.is_na
    assert compiled.na_justification == text


@pytest.mark.parametrize("justification", ["", "   "])
def test_compiled_slot_check_rejects_a_blank_na_justification(justification) -> None:
    slot = _not_provided_slot()
    compiled = ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        action_temporality=slot.action_temporality,
        uca_type=slot.uca_type,
        is_na=True,
        na_justification=justification,
    )

    with pytest.raises(ValueError, match="na_rationale"):
        _validate_compiled_slot(
            compiled,
            expected=slot,
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
        )
