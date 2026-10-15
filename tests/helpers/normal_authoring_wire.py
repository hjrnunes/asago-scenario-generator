"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.helpers.sp3_scenario_continuity import (
    _loss_analysis,
    _structure_with_effect,
    _threat_of_type,
)
from tests.helpers.stage5_assembly import stage5_assembly


PROPOSITION = (
    "The get_education operation returns content for patient PAT-104 using "
    "the incorrect-specialty context instead of the patient's actual specialty."
)


def _wrong_timing_structure():
    """The standard structure whose action emits model output."""
    return _structure_with_effect(ControlActionEffectKind.model_output)


def _wrong_timing_context(
    scenario_id: str = "SCN-001", uca_type: UCAType = UCAType.wrong_timing
):
    """One context, WRONG_TIMING by default, with the standard causal sources."""
    return build_scenario_generation_context(
        _threat_of_type(uca_type),
        _wrong_timing_structure(),
        _loss_analysis(),
        scenario_id=scenario_id,
    )


def _tool_call_action_context():
    """The ``_wrong_timing_context`` context with a tool-call target action."""
    return build_scenario_generation_context(
        _threat_of_type(UCAType.wrong_timing),
        _structure_with_effect(ControlActionEffectKind.tool_call),
        _loss_analysis(),
        scenario_id="SCN-001",
    )


def _wrong_timing_assembly(context):
    """The assembly authority of a ``_wrong_timing_context`` context."""
    return stage5_assembly(
        context, _threat_of_type(context.ica.uca_type), _wrong_timing_structure()
    )


def _normal_payload() -> dict:
    """One valid normal-path draft: semantics and causal evidence only."""
    return {
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["The authorization state can remain stale."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Request an action using the stale state.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected authorization state can remain stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {"semantic_proposition": PROPOSITION},
    }


def _target_operation() -> TargetOperationObservation:
    """One documented tool operation, in the shape the caller holds."""
    return TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="orders",
            operation_id="refund_payment",
        ),
        description=(
            "Refund the payment for one order record up to the captured amount."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "number"},
            },
        },
    )


def _state_snapshot(content: str) -> TargetObservationSnapshot:
    """One quoted target state whose JSON text is ``content``."""
    return TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=content,
            ),
        ),
    )


def _record_observations() -> TargetObservationSnapshot:
    """One quoted target state holding the record facts the model must see."""
    return _state_snapshot(
        '{"order_id": "ORD-104", "refund_eligible": false, "owner_id": "cus-778"}'
    )
