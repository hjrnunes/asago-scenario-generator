"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from tests.helpers.sp3_scenario_continuity import (
    _control_structure,
    _loss_analysis,
    _threat,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


def _typed_tool_context(uca_type=UCAType.incorrect):
    structure = _control_structure()
    action = (
        structure.responsibilities[0]
        .control_actions[0]
        .model_copy(update={"effect_kind": ControlActionEffectKind.tool_call})
    )
    responsibility = structure.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    structure = structure.model_copy(update={"responsibilities": [responsibility]})
    threat = _threat()
    threat = threat.model_copy(
        update={
            "ica_slot_id": threat.ica_slot_id.replace("INCORRECT", uca_type.value),
            "ica_id": threat.ica_id.replace("INCORRECT", uca_type.value),
        }
    )
    return build_scenario_generation_context(
        threat,
        structure,
        _loss_analysis(),
        scenario_id="SCN-STAGE5-ROLE-FREE",
    )


def _provider_payload() -> dict:
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
        "unsafe_outcome": {
            "semantic_proposition": (
                "The agent invokes the tool with a value the policy prohibits."
            ),
        },
    }


def _model_output_context():
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
    return build_scenario_generation_context(
        _threat(),
        structure,
        _loss_analysis(),
        scenario_id="SCN-STAGE5-MODEL-OUTPUT",
    )
