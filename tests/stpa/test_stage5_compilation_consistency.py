"""Regression coverage for Stage 5 provider/assembly consistency."""

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import (
    DelayCondition,
    DurationCondition,
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _causal_source_choices,
    _context_bdi_provider_payload_type,
    _context_provider_schema_kwargs,
    _context_bdi_provider_wire_types,
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_sp3_scenario_continuity import (
    _control_structure,
    _loss_analysis,
    _threat,
)
from .test_sp3_stage5_provider_contract import (
    _provider_payload,
    _typed_tool_context,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


def test_stage5_resolves_explained_structural_ids_in_prose(tmp_path) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The selected control action CA-1-1 receives an unsafe argument."
    )
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    proposition = result.unsafe_outcome.semantic_proposition
    assert proposition is not None
    assert "CA-1-1" not in proposition
    assert "Authorize a bounded batch of payment actions" in proposition


def test_stage5_retries_outcome_ordering_against_itself(tmp_path) -> None:
    context = _typed_tool_context(UCAType.wrong_timing)
    invalid = _provider_payload()
    invalid["unsafe_outcome"]["condition"] = {
        "type": "ordering",
        "reference_handle": "target_action",
        "relation": "before",
    }
    valid = _provider_payload()
    valid["unsafe_outcome"]["condition"] = {
        "type": "ordering",
        "reference_handle": "cause_1",
        "relation": "before",
    }
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 2
    assert result.unsafe_outcome.condition.reference_step_id == "S-1"


def test_stage5_prompt_and_schema_exclude_target_action_from_outcome_ordering() -> None:
    """Outcome ordering offers only distinct declared causal events."""
    context = _typed_tool_context(UCAType.wrong_timing)
    system, user = build_context_bdi_prompts(
        context,
        TemplateLoader(PROMPTS_DIR),
    )
    rendered = system + user

    assert "outcome ordering" in rendered
    assert "`target_action` itself" in rendered

    choices = _causal_source_choices(context)
    schema = _context_bdi_provider_payload_type(
        len(choices),
        **_context_provider_schema_kwargs(context, choices),
    ).model_json_schema()
    ordering = schema["$defs"]["_ContextOutcomeTemporalOrderingDraft4"]
    references = ordering["properties"]["reference_handle"]["enum"]

    assert references == [f"cause_{index}" for index in range(1, len(choices) + 1)]


def test_state_outcome_uses_explained_local_source_handle(tmp_path) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "state_value",
        "subject_ref": "cause_1",
        "property": "authorization",
        "operator": "equals",
        "expected": {
            "binding_ref": "SEM-test-authorization",
            "value_type": "boolean",
            "description": "The deployment-specific authorization value is unknown.",
            "minimum": None,
            "maximum": None,
        },
    }
    client = MockLLMClient()
    client.set_response_queue([payload])
    result, error = generate_bdi_for_context(client, context, tmp_path)
    assert error is None
    assert result is not None
    assert result.unsafe_outcome.condition.subject_ref == "PM-1-1"
    validator = Draft202012Validator(
        client.calls[0].response_format.model_json_schema()
    )
    assert not list(validator.iter_errors(payload))
    payload["unsafe_outcome"]["condition"]["subject_ref"] = "PM-1-1"
    assert list(validator.iter_errors(payload))
    assert "state_value.subject_ref" in client.calls[0].system_prompt


def test_stage5_route_retry_requires_one_declared_factor_binding(
    tmp_path,
) -> None:
    """A route correction must bind one factor the response actually declares."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["stimulus"] = {
        "category": "conversation",
        "description": "Earlier conversation turns establish the unsafe context.",
    }
    invalid["causal_factors"][0]["selected_for_route"] = False
    valid = _provider_payload()
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert result.execution_contract.delivery.factor_id == "CF-1"
    initial = client.calls[0].user_prompt
    assert "selected_for_route" in initial
    assert "exactly one" in initial
    correction = client.calls[1].user_prompt
    assert "execution_route_factor_binding_invalid" in correction
    assert "selected_for_route" in correction
    assert "causal_factors" in correction
    assert "exactly one" in correction
    assert "silently auto-add" in correction


def test_stage5_does_not_infer_a_missing_factor_binding(tmp_path) -> None:
    """Repeated mismatch remains a closed failure, never an inferred factor."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["stimulus"] = {
        "category": "conversation",
        "description": "Earlier conversation turns establish the unsafe context.",
    }
    invalid["causal_factors"][0]["selected_for_route"] = False
    client = MockLLMClient()
    client.set_response_queue([invalid, invalid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "exactly one declared causal factor" in error
    assert client.call_count == 2


def test_stage5_rejects_multiple_factor_bindings_without_first_fallback(
    tmp_path,
) -> None:
    """Two marked factors remain a closed failure, never a first-factor choice."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["causal_factors"].append(
        {
            "source_handle": "cause_2",
            "evidence": "The feedback timing is also part of the hypothesis.",
            "temporal_condition": None,
            "evidence_status": "structural_failure",
            "selected_for_route": True,
        }
    )
    invalid["attacker_bdi"]["intentions"][0]["source_handles"] = [
        "cause_1",
        "cause_2",
    ]
    client = MockLLMClient()
    client.set_response_queue([invalid, invalid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "exactly one declared causal factor" in error
    assert client.call_count == 2


def test_stage5_coerces_bare_temporal_placeholder_before_materialization(
    tmp_path,
) -> None:
    context = _typed_tool_context(UCAType.wrong_timing)
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "delay",
        "reference_handle": "cause_1",
        "delay_ms": "SEM-outcome-value-delay-threshold",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    condition = result.unsafe_outcome.condition
    assert isinstance(condition, DelayCondition)
    assert isinstance(condition.delay_ms, SemanticBindingPlaceholder)
    assert condition.delay_ms.value_type.value == "integer"


def test_stage5_scopes_repeated_temporal_placeholders_per_condition(tmp_path) -> None:
    context = _typed_tool_context(UCAType.wrong_timing)
    payload = _provider_payload()
    placeholder = {
        "binding_ref": "SEM-outcome-value-delay-threshold",
        "value_type": "integer",
        "description": "The unresolved delay threshold.",
        "minimum": 0,
        "maximum": None,
    }
    payload["causal_factors"][0]["temporal_condition"] = {
        "type": "delay",
        "reference_handle": "cause_1",
        "delay_ms": placeholder,
    }
    payload["unsafe_outcome"]["condition"] = {
        "type": "delay",
        "reference_handle": "cause_1",
        "delay_ms": placeholder,
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    factor_condition = result.causal_factors[0].temporal_condition
    outcome_condition = result.unsafe_outcome.condition
    assert factor_condition is not None
    assert isinstance(factor_condition, DelayCondition)
    assert isinstance(outcome_condition, DelayCondition)
    factor_ref = factor_condition.delay_ms.binding_ref
    outcome_ref = outcome_condition.delay_ms.binding_ref
    assert factor_ref != outcome_ref


def test_wrong_duration_does_not_enable_duration_for_discrete_action() -> None:
    with pytest.raises(ValueError, match="no provider unsafe-condition branch"):
        _context_bdi_provider_wire_types(
            1,
            uca_type=UCAType.wrong_duration,
            condition_reference_refs=("CA-1-1",),
            action_temporality=ControlActionTemporality.discrete,
        )


def test_stage5_keeps_wrong_duration_branch_parameterized_without_temporality(
    tmp_path,
) -> None:
    context = _typed_tool_context(UCAType.wrong_duration)
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "duration",
        "reference_handle": "cause_1",
        "duration_ms": "SEM-duration-threshold",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    condition = result.unsafe_outcome.condition
    assert isinstance(condition, DurationCondition)
    assert isinstance(condition.duration_ms, SemanticBindingPlaceholder)
    assert condition.duration_ms.value_type.value == "integer"


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
    client.set_response_queue([payload, payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "declared causal-factor source" in error
    assert client.call_count == 2


def test_exact_target_operation_selects_tool_call_implementation_kind(tmp_path) -> None:
    structure = _control_structure()
    action = (
        structure.responsibilities[0]
        .control_actions[0]
        .model_copy(update={"effect_kind": ControlActionEffectKind.agent_message})
    )
    responsibility = structure.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    structure = structure.model_copy(update={"responsibilities": [responsibility]})
    context = build_scenario_generation_context(
        _threat(),
        structure,
        _loss_analysis(),
        scenario_id="SCN-STAGE5-EXACT-OPERATION",
    )
    operation = TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="tool-refund", operation_id="process_refund"
        ),
        description="Refund an order by the requested amount.",
        input_schema={
            "type": "object",
            "properties": {"amount": {"type": "number"}},
            "required": ["amount"],
        },
        evidence_refs=("inventory:tool:process_refund:input_schema",),
    )
    system, user = build_context_bdi_prompts(
        context,
        TemplateLoader(PROMPTS_DIR),
        target_operation=operation,
    )
    assert "authoritative typed action kind for this request is `tool_call`" in (
        system + user
    )
    choices = _causal_source_choices(context)
    schema = _context_bdi_provider_payload_type(
        len(choices),
        ExecutionActionKind.tool_call,
        **_context_provider_schema_kwargs(
            context,
            choices,
            target_operation=operation,
        ),
    ).model_json_schema()
    unsafe_name = next(
        name
        for name in schema["$defs"]
        if name.startswith("_ContextUnsafeOutcomeDraft")
    )
    unsafe = schema["$defs"][unsafe_name]
    condition_schema = unsafe["properties"]["condition"]
    action_value_union = condition_schema["discriminator"]["mapping"]["action_value"]
    amount_ref = action_value_union["discriminator"]["mapping"]["amount"]
    amount_def = schema["$defs"][amount_ref.rsplit("/", 1)[-1]]
    assert {
        item.get("type")
        for item in amount_def["properties"]["expected"]["anyOf"]
        if "type" in item
    } == {"integer", "number"}

    route = schema["properties"]["execution_route"]
    executable_route_ref = route["discriminator"]["mapping"]["executable_route"]
    executable_route = schema["$defs"][executable_route_ref.rsplit("/", 1)[-1]]
    assert set(executable_route["properties"]) == {
        "disposition",
        "action_kind",
        "reason",
    }
    assert "delivery_class" not in executable_route["properties"]
    assert "selected_factor_handle" not in executable_route["properties"]
    factor = schema["$defs"]["_ContextCausalFactorDraft4"]
    assert factor["properties"]["selected_for_route"]["type"] == "boolean"
    assert "selected_for_route" in factor["required"]
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"].update(
        property="amount",
        operator="less_than",
        expected={
            "binding_ref": "SEM-test-refund-amount",
            "value_type": "number",
            "description": "The exact refund threshold is unknown.",
            "minimum": 0,
            "maximum": None,
        },
    )
    payload["execution_route"]["action_kind"] = "tool_call"
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        target_operation=operation,
    )

    assert error is None
    assert result is not None
    assert result.execution_contract.action_kind is ExecutionActionKind.tool_call
    target_requirement = next(
        item
        for item in result.execution_contract.resource_requirements
        if item.purpose.value == "target_action"
    )
    assert target_requirement.operation == "process_refund"
