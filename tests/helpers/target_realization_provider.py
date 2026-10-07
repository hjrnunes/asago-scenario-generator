"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import (
    SystemicControlAction,
    TargetDerivedICAOperationContext,
    TargetDerivedICARequest,
    TargetDerivedICASlot,
    TargetOperationObservation,
    TargetOperationReference,
)
from tests.helpers.target_realization import _baseline


_PAYMENT_SLOT = "RESP-1:CA-1-2:NOT_PROVIDED"


def _payment_ica_request() -> TargetDerivedICARequest:
    return TargetDerivedICARequest(
        baseline=_baseline(),
        target_derived_control_actions=(
            SystemicControlAction(
                control_action_id="CA-1-2",
                controller_id="RESP-1",
                description="Schedule a payment in the target.",
                effect_kind="tool_call",
                temporality="instantaneous",
                provenance="target_derived",
            ),
        ),
        target_derived_ica_slots=(
            TargetDerivedICASlot(
                slot_id=_PAYMENT_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-2",
                action_temporality="instantaneous",
                uca_type="NOT_PROVIDED",
            ),
        ),
        target_operation_context=(
            TargetDerivedICAOperationContext(
                control_action_id="CA-1-2",
                operation=TargetOperationObservation(
                    reference=TargetOperationReference(
                        resource_id="mcp:target:mini",
                        operation_id="schedule_payment",
                    ),
                    description="Schedule a payment for the supplied customer.",
                    input_schema={
                        "type": "object",
                        "properties": {"customer_id": {"type": "string"}},
                        "required": ["customer_id"],
                    },
                    state_changing=True,
                    state_effect="changes",
                    evidence_refs=("inventory:tool:schedule_payment",),
                ),
            ),
        ),
    )


def _payment_draft(*texts: str) -> dict:
    return {
        "findings": [
            {
                "slot_id": _PAYMENT_SLOT,
                "ica_id": f"provider-{index}",
                "ica_text": text,
                "hazardous_context": "An approved payment remains pending.",
                "loss_scenario": "The customer incurs a missed-payment loss.",
                "related_hazards": ["H-1"],
                "related_constraints": ["SC-1"],
            }
            for index, text in enumerate(texts)
        ]
    }


def _supported(*indexes: int) -> dict:
    return {
        "decisions": [
            {
                "ica_id": f"{_PAYMENT_SLOT}:{index}",
                "action_state": "absent",
                "hazard_path": "supported",
                "detail": "The exact slot and baseline references agree.",
            }
            for index in indexes
        ]
    }
