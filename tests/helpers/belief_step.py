"""A Stage 5 spec with a code-filled and a model-chosen factor, for the belief step."""

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


def belief_spec(run_dir: Path) -> tuple[ScenarioSpec, ControlStructure]:
    """Compile the two-factor reply; Stage 5 states no belief."""
    client = MockLLMClient()
    client.set_response_queue([two_factor_payload()])
    context = _wrong_timing_context()
    assembly = _wrong_timing_assembly(context)
    spec, error = generate_bdi_for_context(client, context, run_dir, assembly=assembly)
    assert error is None and spec is not None, error
    return spec, assembly.control_structure
