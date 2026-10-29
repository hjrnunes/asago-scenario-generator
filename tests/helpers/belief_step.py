"""Stage 5 specs for the belief step.

One has a code-filled and a model-chosen factor; the other has a code-filled
factor and a decision-rule factor, which states no belief.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from tests.helpers.normal_authoring_wire import (
    _normal_payload,
    _wrong_timing_assembly,
    _wrong_timing_context,
)
from tests.stpa.sp1_helpers import MockLLMClient

# The process-model factor's variable is filled by code; the control-action
# factor's is the model's choice.
CA_EVIDENCE = "The action runs the whole batch without a check."
# The selected controller's handle: the PM, its two feedback kinds, and the CA
# come first.
RULE_HANDLE = "cause_5"
RULE_EVIDENCE = (
    "The agent knows the batch is unapproved but its rule releases any batch "
    "under the daily limit."
)


def two_factor_payload() -> dict[str, Any]:
    """A Stage 5 reply with the PM factor (cause_1) and the CA factor (cause_4)."""
    payload = copy.deepcopy(_normal_payload())
    payload["causal_factors"] = [
        payload["causal_factors"][0],
        {
            "source_handle": "cause_4",
            "evidence": CA_EVIDENCE,
            "temporal_condition": None,
            "evidence_status": "structural_failure",
        },
    ]
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = ["cause_1", "cause_4"]
    return payload


def decision_rule_payload(*handles: str) -> dict[str, Any]:
    """A Stage 5 reply that declares ``handles``: cause_1 as in the normal
    reply and every other handle with the decision-rule evidence."""
    payload = copy.deepcopy(_normal_payload())
    base = payload["causal_factors"][0]
    payload["causal_factors"] = [
        base
        if handle == "cause_1"
        else {
            "source_handle": handle,
            "evidence": RULE_EVIDENCE,
            "temporal_condition": None,
            "evidence_status": "structural_failure",
        }
        for handle in handles
    ]
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = list(handles)
    return payload


def decision_rule_belief_spec(
    run_dir: Path, *handles: str
) -> tuple[ScenarioSpec, ControlStructure]:
    """Compile a reply with the PM factor and the decision-rule factor."""
    return belief_spec(
        run_dir, decision_rule_payload(*(handles or ("cause_1", RULE_HANDLE)))
    )


def belief_spec(
    run_dir: Path, payload: dict[str, Any] | None = None
) -> tuple[ScenarioSpec, ControlStructure]:
    """Compile the two-factor reply, or ``payload``; Stage 5 states no belief."""
    client = MockLLMClient()
    client.set_response_queue([payload or two_factor_payload()])
    context = _wrong_timing_context()
    assembly = _wrong_timing_assembly(context)
    spec, error = generate_bdi_for_context(client, context, run_dir, assembly=assembly)
    assert error is None and spec is not None, error
    return spec, assembly.control_structure
