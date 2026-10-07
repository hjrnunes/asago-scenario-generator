"""Focused regressions for the role-free Stage 5 provider boundary."""

from __future__ import annotations


from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)

from asago_scenario_generator.stpa.models.semantic_conditions import DelayCondition
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
import pytest
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from pydantic import ValidationError
from tests.stpa.stage5_wire import normal_wire_queue
import json
from tests.helpers.sp3_stage5_provider_contract import (
    _model_output_context,
    _provider_payload,
    _typed_tool_context,
)


def _model_output_payload() -> dict:
    payload = _provider_payload()
    payload["unsafe_outcome"] = {
        "semantic_proposition": (
            "The response authorizes an unsafe action prohibited by policy."
        ),
    }
    return payload


def _comparison_snapshot() -> TargetObservationSnapshot:
    return TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"amount":129,"plan_id":"PLAN21"}',
            ),
            TargetObservation(
                observation_ref="TARGET-READ-001",
                kind="read",
                source_name="lookup_business_state",
                source_description="Look up the current business state.",
                content_format="json",
                content='{"amount":129,"plan_id":"PLAN21"}',
            ),
        ),
    )


def test_context_materialization_derives_lineage_and_preserves_proposition(
    tmp_path,
) -> None:
    context = _model_output_context()
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([_model_output_payload()]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert result.unsafe_outcome is not None
    assert result.unsafe_outcome.semantic_proposition == (
        "The response authorizes an unsafe action prohibited by policy."
    )
    assert result.unsafe_outcome.hazard_refs == tuple(
        item.hazard_id for item in context.hazards
    )
    assert result.unsafe_outcome.constraint_refs == tuple(
        item.constraint_id for item in context.constraints
    )


@pytest.mark.parametrize("field", ("desires", "intentions"))
def test_context_provider_retries_empty_attacker_bdi_members(tmp_path, field) -> None:
    """Required attacker BDI members use the existing bounded repair path."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["attacker_bdi"][field] = []
    valid = _provider_payload()
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([invalid, valid]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 2
    assert field in client.calls[1].user_prompt


def test_context_provider_rejects_empty_attacker_intentions_after_bounded_retry(
    tmp_path,
) -> None:
    """An exhausted repair cannot publish a late invalid Stage 5 result."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["attacker_bdi"]["intentions"] = []
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([invalid, invalid]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert client.call_count == 2
    assert "intentions" in error


def test_stage5_resolves_local_temporal_reference_before_materialization(
    tmp_path,
) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["causal_factors"][0]["temporal_condition"] = {
        "type": "delay",
        "reference_handle": "cause_1",
        "delay_ms": 250,
    }
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([payload]))

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    condition = result.causal_factors[0].temporal_condition
    assert isinstance(condition, DelayCondition)
    assert condition.reference_ref == "PM-1-1"


def test_provider_schema_requires_proposition_and_owns_lineage() -> None:
    schema = _scenario_semantics_payload_type(1).model_json_schema()
    unsafe = schema["$defs"]["_ContextSemanticOutcomeDraft"]
    assert "semantic_proposition" in unsafe["required"]
    encoded = json.dumps(unsafe)
    assert "hazard_refs" not in encoded
    assert "constraint_refs" not in encoded


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("desires", [" "]),
        (
            "intentions",
            [{"description": " ", "source_handles": ["cause_1"]}],
        ),
    ),
)
def test_provider_rejects_blank_attacker_bdi_text(field, value) -> None:
    """The private wire shape rejects whitespace-only BDI text."""
    model = _scenario_semantics_payload_type(1)
    payload = _provider_payload()
    payload["attacker_bdi"][field] = value

    with pytest.raises(ValidationError, match=field):
        model.model_validate(payload)
