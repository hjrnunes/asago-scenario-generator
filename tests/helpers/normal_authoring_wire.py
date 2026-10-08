"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.scenario_prod.stage5.defender import (
    populate_defender_bdi,
)
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
    _control_structure,
    _loss_analysis,
    _threat,
)


PROPOSITION = (
    "The get_education operation returns content for patient PAT-104 using "
    "the incorrect-specialty context instead of the patient's actual specialty."
)


def _wrong_timing_context(scenario_id: str = "SCN-A1-NORMAL"):
    """One WRONG_TIMING context with the standard four causal sources."""
    structure = _control_structure()
    action = (
        structure.responsibilities[0]
        .control_actions[0]
        .model_copy(update={"effect_kind": ControlActionEffectKind.model_output})
    )
    responsibility = structure.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    structure = structure.model_copy(update={"responsibilities": [responsibility]})
    threat = _threat()
    threat = threat.model_copy(
        update={
            "ica_slot_id": threat.ica_slot_id.replace(
                "INCORRECT", UCAType.wrong_timing.value
            ),
            "ica_id": threat.ica_id.replace("INCORRECT", UCAType.wrong_timing.value),
        }
    )
    return build_scenario_generation_context(
        threat,
        structure,
        _loss_analysis(),
        scenario_id=scenario_id,
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


def _wrong_timing_threat():
    threat = _threat()
    return threat.model_copy(
        update={
            "ica_slot_id": threat.ica_slot_id.replace(
                "INCORRECT", UCAType.wrong_timing.value
            ),
            "ica_id": threat.ica_id.replace("INCORRECT", UCAType.wrong_timing.value),
        }
    )


def _defender_bdi(context):
    return populate_defender_bdi(_control_structure(), "RESP-1")
