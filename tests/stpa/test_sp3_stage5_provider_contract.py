"""Focused regressions for the role-free Stage 5 provider boundary."""

from __future__ import annotations

import json

import pytest
import yaml
from pydantic import ValidationError
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import DelayCondition
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _context_bdi_provider_payload_type,
    _context_bdi_provider_wire_types,
    _context_unsafe_condition_wire_types,
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_sp3_scenario_continuity import (
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


def test_context_prompt_does_not_supply_fabricated_outcome_values() -> None:
    """The prompt teaches condition selection without inventing unsafe facts."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = system + user
    assert '"expected": "approved"' not in rendered
    assert '"delay_ms": 1' not in rendered
    assert '"duration_ms": 1' not in rendered
    assert "complete examples for this exact request" not in rendered
    assert "event ordering" in rendered
    assert "actual argument name" in rendered


def test_unsafe_ordering_resolves_explained_handle_without_inventing_delay(tmp_path):
    context = _typed_tool_context(UCAType.wrong_timing)
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "ordering",
        "reference_handle": "cause_1",
        "relation": "after",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])
    result, error = generate_bdi_for_context(client, context, tmp_path)
    assert error is None
    assert result.unsafe_outcome.condition.model_dump() == {
        "type": "ordering",
        "reference_step_id": "S-1",
        "relation": "after",
    }


@pytest.mark.parametrize(
    "bad_condition",
    [
        {"property": "action_argument", "operator": "equals", "expected": "approved"},
        {"property": "amount", "operator": "equals", "expected": "approved"},
    ],
)
def test_tool_outcome_must_reference_an_observed_argument(tmp_path, bad_condition):
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
        argument_names=("amount",),
        evidence_refs=("inventory:tool:process_refund:input_schema",),
    )
    bad = _provider_payload()
    bad["unsafe_outcome"]["condition"].update(bad_condition)
    good = _provider_payload()
    good["unsafe_outcome"]["condition"].update(
        property="amount",
        operator="less_than",
        expected={
            "binding_ref": "SEM-provider-amount",
            "value_type": "number",
            "description": "The amount threshold is unknown in this deployment.",
            "minimum": 0,
            "maximum": None,
        },
    )
    client = MockLLMClient()
    client.set_response_queue([bad, good])
    result, error = generate_bdi_for_context(
        client, _typed_tool_context(), tmp_path, target_operation=operation
    )
    assert error is None
    assert client.call_count == 2
    assert result.unsafe_outcome.condition.property == "amount"
    # The schema confirms a number, but supplies no rule establishing zero as
    # the unsafe reference threshold. Keep the corrected argument parameterized.
    assert result.unsafe_outcome.condition.expected.value_type == "number"
    assert result.unsafe_outcome.semantic_binding_required is True
    assert "argument" in client.calls[1].user_prompt
    assert "inventory:tool:" not in client.calls[0].user_prompt
    assert "Refund an order by the requested amount." in client.calls[0].user_prompt


def test_numeric_argument_placeholder_is_specialized_and_retried(tmp_path) -> None:
    """A numeric target argument accepts only its specialized placeholder type."""
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
        argument_names=("amount",),
        evidence_refs=("inventory:tool:process_refund:input_schema",),
    )
    invalid = _provider_payload()
    invalid["unsafe_outcome"]["condition"].update(
        property="amount",
        operator="not_equals",
        expected={
            "binding_ref": "SEM-invalid-amount",
            "value_type": "string",
            "description": "An invalid amount binding.",
            "minimum": 0,
            "maximum": None,
        },
    )
    valid = _provider_payload()
    valid["unsafe_outcome"]["condition"].update(
        property="amount",
        operator="not_equals",
        expected={
            "binding_ref": "SEM-valid-amount",
            "value_type": "number",
            "description": "The eligible refund amount.",
            "minimum": 0,
            "maximum": None,
        },
    )
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

    result, error = generate_bdi_for_context(
        client, _typed_tool_context(), tmp_path, target_operation=operation
    )

    assert error is None
    assert result is not None
    assert client.call_count == 2
    assert result.unsafe_outcome.condition.expected.value_type.value == "number"
    schema = client.calls[0].response_format.model_json_schema()
    amount_branch = next(
        definition
        for definition in schema["$defs"].values()
        if definition.get("properties", {}).get("property", {}).get("const") == "amount"
    )
    binding_ref = next(
        item["$ref"]
        for item in amount_branch["properties"]["expected"]["anyOf"]
        if "$ref" in item
    )
    binding = schema["$defs"][binding_ref.rsplit("/", 1)[-1]]
    assert binding["properties"]["value_type"]["const"] == "number"
    assert "value_type" in client.calls[1].user_prompt


def test_context_literal_without_evidence_uses_exact_json_observation(
    tmp_path,
) -> None:
    """An exact JSON observation can ground a literal without provider prose."""
    snapshot = _comparison_snapshot()
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"].update(
        property="amount", operator="equals", expected=129
    )
    payload["unsafe_outcome"]["comparison_evidence"] = None
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
        target_observations=snapshot,
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected == 129
    record = yaml.safe_load(
        (
            tmp_path
            / "outcome-grounding"
            / f"{_typed_tool_context().context_digest}.yaml"
        ).read_text()
    )
    assert record["matched_observation_refs"] == [
        "TARGET-STATE",
        "TARGET-READ-001",
    ]
    assert record["matched_json_paths"] == [
        "TARGET-STATE:value:/amount",
        "TARGET-READ-001:value:/amount",
    ]
    assert record["grounding_origin"] == "deterministic_observed_json_presence"
    assert record["interpretation_independently_verified"] is False
    assert record.get("source_text") is None


def test_context_state_literal_without_evidence_uses_exact_json_observation(
    tmp_path,
) -> None:
    """State literals use the same exact observed-JSON grounding."""
    snapshot = _comparison_snapshot()
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "state_value",
        "subject_ref": "cause_1",
        "property": "plan_id",
        "operator": "equals",
        "expected": "PLAN21",
    }
    payload["unsafe_outcome"]["comparison_evidence"] = None
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
        target_observations=snapshot,
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected == "PLAN21"


def test_context_null_json_grounding_rejects_boolean_numeric_coercion(tmp_path) -> None:
    """A JSON number does not establish a Boolean literal by coercion."""
    snapshot = TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"enabled":1}',
            ),
        ),
    )
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"].update(
        property="enabled", operator="equals", expected=True
    )
    payload["unsafe_outcome"]["comparison_evidence"] = None
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
        target_observations=snapshot,
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected.value_type.value == "boolean"
    record = yaml.safe_load(
        (
            tmp_path
            / "outcome-grounding"
            / f"{_typed_tool_context().context_digest}.yaml"
        ).read_text()
    )
    assert record["grounding_origin"] == "unresolved"
    assert record.get("matched_observation_refs") in (None, [])


def test_context_unknown_typed_placeholder_does_not_retry(tmp_path) -> None:
    """An explicitly typed unknown remains valid without source evidence."""
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"].update(
        property="amount",
        operator="equals",
        expected={
            "binding_ref": "SEM-unknown-amount",
            "value_type": "integer",
            "description": "The deployment-specific amount threshold is unknown.",
            "minimum": 0,
            "maximum": None,
        },
    )
    payload["unsafe_outcome"]["comparison_evidence"] = None
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
        target_observations=_comparison_snapshot(),
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected.value_type.value == "integer"


def test_context_model_output_predicate_does_not_retry_without_evidence(
    tmp_path,
) -> None:
    """The compiler-owned model-output Boolean predicate is evidence-free."""
    client = MockLLMClient()
    client.set_response_queue([_model_output_payload()])

    result, error = generate_bdi_for_context(
        client,
        _model_output_context(),
        tmp_path,
        target_observations=_comparison_snapshot(),
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected is True


def test_context_analytical_model_output_predicate_does_not_retry_without_evidence(
    tmp_path,
) -> None:
    """The context action type still exempts an analytical model-output route."""
    payload = _model_output_payload()
    payload["causal_factors"][0]["selected_for_route"] = False
    payload["execution_route"] = {
        "disposition": "analytical_only",
        "gaps": [
            {
                "code": "operation_missing",
                "detail": "The delivery operation is not available for replay.",
                "evidence_handles": ["cause_1"],
            }
        ],
        "reason": "The model-output hypothesis remains analytical only.",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _model_output_context(),
        tmp_path,
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected is True


def test_context_malformed_literal_evidence_remains_parameterized(tmp_path) -> None:
    """An unmatched explicit citation does not fall back or trigger a retry."""
    snapshot = _comparison_snapshot()
    invalid = _provider_payload()
    invalid["unsafe_outcome"]["condition"].update(
        property="amount", operator="equals", expected=129
    )
    invalid["unsafe_outcome"]["comparison_evidence"] = {
        "source_ref": "TARGET-READ-001",
        "quote": '{"amount":128,"plan_id":"PLAN21"}',
        "rationale": "The source is intended to support the amount literal.",
    }
    client = MockLLMClient()
    client.set_response_queue([invalid])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
        target_observations=snapshot,
    )

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.unsafe_outcome.condition.expected.value_type.value == "integer"


def _provider_payload() -> dict:
    return {
        "stimulus": {
            "category": "user_message",
            "description": "A user request exercises the stale authorization state.",
        },
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
                "selected_for_route": True,
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_value",
                "control_action_id": "CA-1-1",
                "property": "action_argument",
                "operator": "equals",
                "expected": {
                    "binding_ref": "SEM-provider-value",
                    "value_type": "string",
                    "description": "The selected action value is unknown.",
                    "minimum": None,
                    "maximum": None,
                },
            },
            "semantic_proposition": None,
        },
        "execution_route": {
            "disposition": "executable_route",
            "action_kind": "tool_call",
            "reason": "The typed route observes the selected tool action after the request.",
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


def _model_output_payload() -> dict:
    payload = _provider_payload()
    payload["stimulus"] = {
        "category": "user_message",
        "description": "A user message reaches the selected response action.",
    }
    payload["unsafe_outcome"] = {
        "condition": {
            "type": "action_value",
            "control_action_id": "CA-1-1",
            "property": "semantic_proposition",
            "operator": "equals",
            "expected": True,
        },
        "semantic_proposition": (
            "The response authorizes an unsafe action prohibited by policy."
        ),
    }
    payload["execution_route"] = {
        "disposition": "executable_route",
        "action_kind": "model_output",
        "reason": "The user message exercises the selected process-model flaw.",
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


def test_context_provider_schema_requires_stimulus_and_hides_role_bookkeeping() -> None:
    schema = _context_bdi_provider_payload_type(
        1, ExecutionActionKind.tool_call
    ).model_json_schema()
    encoded = json.dumps(schema)

    assert "stimulus" in schema["properties"]
    assert "resource_role_handles" not in encoded
    assert "carrier_attacker_influence" not in encoded


def test_context_provider_schema_requires_proposition_and_owns_lineage() -> None:
    schema = _context_bdi_provider_payload_type(
        1,
        ExecutionActionKind.model_output,
        uca_type=UCAType.incorrect,
        target_action_id="CA-1-1",
    ).model_json_schema()
    unsafe = schema["$defs"]["_ContextUnsafeOutcomeDraft1"]
    assert "semantic_proposition" in unsafe["required"]
    encoded = json.dumps(unsafe)
    assert "hazard_refs" not in encoded
    assert "constraint_refs" not in encoded
    action_value_name = next(
        name
        for name in schema["$defs"]
        if name.startswith("_ContextUnsafeActionValueCondition")
    )
    action_value = schema["$defs"][action_value_name]
    assert action_value["properties"]["property"]["const"] == "semantic_proposition"
    assert action_value["properties"]["operator"]["const"] == "equals"
    assert action_value["properties"]["expected"]["const"] is True
    comparison = unsafe["properties"]["comparison_evidence"]["anyOf"]
    assert any(
        item.get("$ref", "").endswith("/ComparisonEvidence") for item in comparison
    )


def test_context_materialization_derives_lineage_and_preserves_proposition(
    tmp_path,
) -> None:
    context = _model_output_context()
    client = MockLLMClient()
    client.set_response_queue([_model_output_payload()])

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


def test_context_provider_schema_requires_discriminators_and_evidence_branches() -> (
    None
):
    """Provider wire tags and evidence status are required, not defaulted."""
    schema = _context_bdi_provider_payload_type(
        1,
        ExecutionActionKind.tool_call,
        uca_type=UCAType.incorrect,
        state_subject_refs=("PM-1-1",),
    ).model_json_schema()
    route = schema["$defs"]["_ExecutableRouteSelection1"]
    assert "disposition" in route["required"]

    unsafe = schema["$defs"]["_ContextUnsafeOutcomeDraft1"]
    condition = unsafe["properties"]["condition"]
    condition_defs = condition["oneOf"]
    assert condition_defs
    for branch in condition_defs:
        if "$ref" not in branch:
            continue
        name = branch["$ref"].rsplit("/", 1)[-1]
        assert "type" in schema["$defs"][name]["required"]

    factor = schema["$defs"]["_ContextCausalFactorDraft1"]
    assert "evidence_status" in factor["properties"]
    assert "evidence_status" in factor["required"]
    assert factor["properties"]["selected_for_route"]["type"] == "boolean"
    assert "selected_for_route" in factor["required"]
    route = schema["$defs"]["_ExecutableRouteSelection1"]
    assert "delivery_class" not in route["properties"]
    assert "selected_factor_handle" not in route["properties"]


def test_context_provider_schema_restricts_condition_families_to_selected_uca() -> None:
    """Request-specific condition unions do not advertise unrelated branches."""
    for uca_type, allowed in (
        (UCAType.not_provided, {"action_presence"}),
        (UCAType.incorrect, {"action_value", "state_value"}),
        (UCAType.wrong_timing, {"ordering", "delay", "window", "absence"}),
    ):
        schema = _context_bdi_provider_payload_type(
            1,
            ExecutionActionKind.tool_call,
            uca_type=uca_type,
            state_subject_refs=("PM-1-1",),
            condition_reference_refs=("CA-1-1", "PM-1-1"),
            condition_step_refs=("S-1", "S-2"),
        ).model_json_schema()
        refs = {
            item["$ref"].rsplit("/", 1)[-1]
            for item in schema["$defs"]["_ContextUnsafeOutcomeDraft1"]["properties"][
                "condition"
            ]["oneOf"]
        }
        types = {schema["$defs"][name]["properties"]["type"]["const"] for name in refs}
        assert types == allowed


def _unsafe_types(
    uca_type: UCAType | None,
    *,
    state_subject_refs: tuple[str, ...] = ("PM-1-1",),
    condition_reference_refs: tuple[str, ...] = ("CA-1-1",),
    condition_step_refs: tuple[str, ...] = ("S-1",),
    duration_eligible: bool = False,
    target_action_id: str | None = "CA-1-1",
):
    return _context_unsafe_condition_wire_types(
        1,
        uca_type=uca_type,
        target_action_id=target_action_id,
        state_subject_refs=state_subject_refs,
        condition_reference_refs=condition_reference_refs,
        condition_step_refs=condition_step_refs,
        duration_eligible=duration_eligible,
    )


@pytest.mark.parametrize(
    ("uca_type", "state_subject_refs", "duration_eligible", "expected"),
    (
        (UCAType.not_provided, (), False, {"action_presence"}),
        (UCAType.incorrect, (), False, {"action_value"}),
        (UCAType.incorrect, ("PM-1-1",), False, {"action_value", "state_value"}),
        (
            UCAType.wrong_timing,
            ("PM-1-1",),
            False,
            {"ordering", "delay", "window", "absence"},
        ),
        (UCAType.wrong_duration, (), True, {"duration"}),
        (
            None,
            ("PM-1-1",),
            True,
            {
                "action_presence",
                "action_value",
                "state_value",
                "ordering",
                "delay",
                "duration",
                "window",
                "absence",
            },
        ),
    ),
)
def test_unsafe_condition_wire_types_select_each_authorized_branch(
    uca_type,
    state_subject_refs,
    duration_eligible,
    expected,
) -> None:
    assert (
        set(
            _unsafe_types(
                uca_type,
                state_subject_refs=state_subject_refs,
                duration_eligible=duration_eligible,
            )
        )
        == expected
    )


def test_unsafe_condition_wire_types_keep_wrong_duration_parameterized() -> None:
    assert (
        _unsafe_types(
            UCAType.wrong_timing,
            condition_reference_refs=(),
            condition_step_refs=(),
        )
        == {}
    )
    assert set(_unsafe_types(UCAType.wrong_duration)) == {"duration"}


def test_unsafe_condition_wire_types_allow_unknown_target_action_id() -> None:
    condition_type = _unsafe_types(
        UCAType.not_provided,
        target_action_id=None,
    )["action_presence"]

    condition = condition_type.model_validate(
        {
            "type": "action_presence",
            "control_action_id": "CA-OTHER",
            "expected": "not_provided",
        }
    )
    assert condition.control_action_id == "CA-OTHER"


def test_context_provider_wire_factory_requires_reference_authority() -> None:
    with pytest.raises(ValueError, match="no provider unsafe-condition branch"):
        _context_bdi_provider_wire_types(1, uca_type=UCAType.wrong_duration)


def test_context_provider_wire_factory_keeps_wrong_duration_with_reference_authority():
    types = _context_bdi_provider_wire_types(
        1,
        uca_type=UCAType.wrong_duration,
        condition_reference_refs=("CA-1-1",),
        temporal_reference_handles=("target_action", "cause_1"),
    )
    schema = types["unsafe_outcome"].model_json_schema()
    condition_refs = schema["properties"]["condition"]["oneOf"]
    condition_names = {item["$ref"].rsplit("/", 1)[-1] for item in condition_refs}
    assert {
        schema["$defs"][name]["properties"]["type"]["const"] for name in condition_names
    } == {"duration"}


def test_context_provider_schema_temporal_branches_require_exact_fields() -> None:
    """Each temporal branch advertises only its own meaningful fields."""
    schema = _context_bdi_provider_payload_type(
        1,
        ExecutionActionKind.tool_call,
        temporal_reference_handles=("target_action", "cause_1"),
    ).model_json_schema()
    temporal = schema["$defs"]["_ContextCausalFactorDraft1"]["properties"][
        "temporal_condition"
    ]
    temporal = next(item for item in temporal["anyOf"] if "oneOf" in item)
    branches = {item["$ref"].rsplit("/", 1)[-1] for item in temporal["oneOf"]}
    expected = {
        "ordering": {"type", "reference_handle", "relation"},
        "delay": {"type", "reference_handle", "delay_ms"},
        "duration": {"type", "reference_handle", "duration_ms"},
        "window": {"type", "reference_handle", "window_from_ms", "window_to_ms"},
        "absence": {"type", "reference_handle", "until_step_handle"},
    }
    for name in branches:
        branch = schema["$defs"][name]
        branch_fields = set(branch["properties"])
        branch_type = branch["properties"]["type"]["const"]
        assert branch_fields == expected[branch_type]
        assert set(branch["required"]) == expected[branch_type]


def test_context_prompt_explains_branches_without_selecting_the_outcome() -> None:
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = system + user
    for concept in ("action_value", "state_value", "ordering", "bounded_assumption"):
        assert concept in rendered
    assert "evidence_status" in rendered
    assert "execution_route.disposition" in rendered
    assert "at least one nonblank" in rendered
    assert "empty arrays" in rendered
    assert "explicit authorization or eligibility rule" in rendered
    assert "record_id" in rendered
    assert "pseudo-list" in rendered
    assert "observation_ref` whose returned content contains `record-R`" in rendered
    assert "owner constraint in the rationale" in rendered
    assert "same causal story and the same" in rendered
    assert "unsupported alternatives" in rendered
    assert "no evidence" in rendered
    assert "source-supported concrete witness" in rendered
    assert "same field/event" in rendered


def test_context_provider_retries_one_missing_route_discriminator_with_focused_feedback(
    tmp_path,
) -> None:
    """A missing route tag gets one bounded repair with field-specific guidance."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["execution_route"].pop("disposition")
    valid = _provider_payload()
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert "missing_execution_route_disposition" in correction
    assert "preserve the intended unsafe proposition" in correction
    assert "Never copy a sample value or invent a threshold" in correction


@pytest.mark.parametrize("field", ("desires", "intentions"))
def test_context_provider_retries_empty_attacker_bdi_members(tmp_path, field) -> None:
    """Required attacker BDI members use the existing bounded repair path."""
    context = _typed_tool_context()
    invalid = _provider_payload()
    invalid["attacker_bdi"][field] = []
    valid = _provider_payload()
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

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
    client.set_response_queue([invalid, invalid])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert client.call_count == 2
    assert "intentions" in error


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
def test_context_provider_rejects_blank_attacker_bdi_text(field, value) -> None:
    """The private wire shape rejects whitespace-only BDI text."""
    model = _context_bdi_provider_payload_type(1, ExecutionActionKind.tool_call)
    payload = _provider_payload()
    payload["attacker_bdi"][field] = value

    with pytest.raises(ValidationError, match=field):
        model.model_validate(payload)


def test_context_provider_rejects_missing_discriminator_without_inference() -> None:
    """The strict wire model does not infer unsafe-condition type from fields."""
    model = _context_bdi_provider_payload_type(
        1,
        ExecutionActionKind.tool_call,
        uca_type=UCAType.incorrect,
        state_subject_refs=("PM-1-1",),
    )
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"].pop("type")
    with pytest.raises(ValidationError, match="discriminator 'type'"):
        model.model_validate(payload)


def test_stage5_derives_indirect_tool_roles_from_typed_choices(tmp_path) -> None:
    context = _typed_tool_context()
    client = MockLLMClient()
    payload = _provider_payload()
    payload["stimulus"]["category"] = "tool_content"
    payload["causal_factors"][0].update(
        evidence_status="bounded_assumption",
        bounded_assumption="The test can alter the supplied tool-result carrier.",
    )
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    assert [
        requirement.purpose.value
        for requirement in result.execution_contract.resource_requirements
    ] == ["stimulus_carrier", "target_action"]
    assert result.execution_contract.requested_environment_basis is None


def test_stage5_preserves_omitted_basis_for_resource_bearing_route(tmp_path) -> None:
    context = _typed_tool_context()
    client = MockLLMClient()
    client.set_response_queue([_provider_payload()])

    result, error = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        requested_environment_basis=None,
    )

    assert error is None
    assert result is not None
    assert result.execution_contract.requested_environment_basis is None


def test_stage5_prompt_explains_stimulus_categories_and_factor_delivery_choices() -> (
    None
):
    context = _typed_tool_context()
    system, user = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))
    rendered = f"{system}\n{user}"

    assert "retrieved_content" in rendered
    assert "file_upload" in rendered
    assert "traffic_load" in rendered
    assert "compatible_delivery_classes" in rendered
    assert "resource_role_handles" not in rendered


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
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert error is None
    assert result is not None
    condition = result.causal_factors[0].temporal_condition
    assert isinstance(condition, DelayCondition)
    assert condition.reference_ref == "PM-1-1"


def test_stage5_keeps_unsupported_stimulus_analytical(tmp_path) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["stimulus"] = {
        "category": "file_upload",
        "description": "An uploaded file contains the adversarial content.",
    }
    client = MockLLMClient()
    client.set_response_queue([payload, payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "has no supported delivery" in error


@pytest.mark.parametrize(
    ("stimulus_category", "source_handle", "expected_delivery"),
    (
        ("user_message", "cause_1", "direct_prompt"),
        ("conversation", "cause_2", "conversation_context"),
        ("tool_content", "cause_3", "indirect_content"),
    ),
)
def test_context_route_binds_declared_factor_and_derives_delivery(
    tmp_path,
    stimulus_category,
    source_handle,
    expected_delivery,
) -> None:
    """The context wire carries one factor binding and derives delivery."""
    payload = _provider_payload()
    payload["stimulus"] = {
        "category": stimulus_category,
        "description": "The typed stimulus reaches the selected action.",
    }
    factor = payload["causal_factors"][0]
    factor["source_handle"] = source_handle
    factor["selected_for_route"] = True
    factor["evidence"] = "The selected declared source explains the unsafe action."
    if expected_delivery == "indirect_content":
        factor.update(
            evidence_status="bounded_assumption",
            bounded_assumption="The test can alter the supplied tool-result carrier.",
        )
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = [source_handle]
    payload["execution_route"] = {
        "disposition": "executable_route",
        "action_kind": "tool_call",
        "reason": "The selected declared factor explains the typed route.",
    }

    client = MockLLMClient()
    client.set_response_queue([payload])
    result, error = generate_bdi_for_context(client, _typed_tool_context(), tmp_path)

    assert error is None
    assert result is not None
    assert result.execution_contract.delivery.delivery_class.value == expected_delivery
    assert result.execution_contract.delivery.factor_id == "CF-1"


def test_context_analytical_route_requires_no_factor_binding(tmp_path) -> None:
    """Unsupported delivery stays analytical with an explicit typed gap."""
    payload = _provider_payload()
    payload["stimulus"] = {
        "category": "file_upload",
        "description": "The attachment path is not a supported delivery primitive.",
    }
    payload["causal_factors"][0]["selected_for_route"] = False
    payload["execution_route"] = {
        "disposition": "analytical_only",
        "gaps": [
            {
                "code": "delivery_path_missing",
                "detail": "The attachment has no supported Stage 5 delivery primitive.",
                "evidence_handles": ["cause_1"],
            }
        ],
        "reason": "The route remains analytical because delivery is unsupported.",
    }

    client = MockLLMClient()
    client.set_response_queue([payload])
    result, error = generate_bdi_for_context(client, _typed_tool_context(), tmp_path)

    assert error is None
    assert result is not None
    assert result.execution_contract.disposition.value == "analytical_only"
    assert result.execution_contract.delivery is None
    assert result.execution_contract.gaps[0].code.value == "delivery_path_missing"


def test_stage5_requires_stimulus_for_the_normal_provider_shape(tmp_path) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload.pop("stimulus")
    client = MockLLMClient()
    client.set_response_queue([payload, payload])

    result, error = generate_bdi_for_context(client, context, tmp_path)

    assert result is None
    assert error is not None
    assert "stimulus" in error
