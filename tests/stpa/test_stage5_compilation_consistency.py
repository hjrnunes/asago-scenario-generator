"""Regression coverage for Stage 5 provider/assembly consistency."""

from __future__ import annotations
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from tests.helpers.sp3_stage5_provider_contract import (
    _provider_payload,
    _typed_tool_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from tests.stpa.stage5_wire import normal_wire_queue


def test_stage5_rejects_condition_reference_outside_declared_factor_closure(
    tmp_path,
) -> None:
    context = _typed_tool_context(UCAType.wrong_timing)
    payload = _provider_payload()
    payload["causal_factors"][0]["temporal_condition"] = {
        "type": "delay",
        "reference_handle": "cause_2",
        "delay_ms": 250,
    }
    payload["unsafe_outcome"]["condition"] = {
        "type": "ordering",
        "reference_handle": "cause_1",
        "relation": "after",
    }
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([payload, payload]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "declared causal-factor source" in error
    assert client.call_count == 2


def test_stage5_resolves_explained_structural_ids_in_prose(tmp_path) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The selected control action CA-1-1 receives an unsafe argument."
    )
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([payload]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    proposition = result.unsafe_outcome.semantic_proposition
    assert proposition is not None
    assert "CA-1-1" not in proposition
    assert "Authorize a bounded batch of payment actions" in proposition
