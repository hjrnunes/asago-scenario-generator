"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from tests.helpers.sp3_scenario_continuity import (
    _loss_analysis,
    _structure_with_effect,
    _threat,
    _threat_of_type,
)
from tests.helpers.stage5_assembly import stage5_assembly
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


def _typed_tool_context(uca_type=UCAType.incorrect):
    return build_scenario_generation_context(
        _threat_of_type(uca_type),
        _structure_with_effect(ControlActionEffectKind.tool_call),
        _loss_analysis(),
        scenario_id="SCN-001",
    )


def _typed_tool_assembly(context):
    """The assembly authority of a ``_typed_tool_context`` context."""
    return stage5_assembly(
        context,
        _threat_of_type(context.ica.uca_type),
        _structure_with_effect(ControlActionEffectKind.tool_call),
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
    return build_scenario_generation_context(
        _threat(),
        _structure_with_effect(ControlActionEffectKind.model_output),
        _loss_analysis(),
        scenario_id="SCN-001",
    )


def _model_output_assembly(context):
    """The assembly authority of a ``_model_output_context`` context."""
    return stage5_assembly(
        context,
        _threat(),
        _structure_with_effect(ControlActionEffectKind.model_output),
    )
