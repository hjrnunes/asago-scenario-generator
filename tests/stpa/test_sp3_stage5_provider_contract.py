"""Focused regressions for the role-free Stage 5 provider boundary."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

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
    _causal_source_choices,
    _context_bdi_provider_payload_type,
    _context_bdi_provider_wire_types,
    _context_expected_action_kind,
    _context_prompt_examples,
    _context_provider_schema_kwargs,
    _context_unsafe_condition_wire_types,
    _defender_belief_choices,
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_sp3_scenario_continuity import (
    _context,
    _control_structure,
    _loss_analysis,
    _threat,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)


def _typed_tool_context():
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
    return build_scenario_generation_context(
        _threat(),
        structure,
        _loss_analysis(),
        scenario_id="SCN-STAGE5-ROLE-FREE",
    )


def _provider_payload() -> dict:
    return {
        "stimulus": {
            "category": "retrieved_content",
            "description": "Retrieved content carries the stale authorization state.",
        },
        "defender_vulnerabilities": [
            {
                "belief_handle": "belief_1",
                "vulnerability": "The selected authorization state can remain stale.",
            }
        ],
        "attacker_bdi": {
            "beliefs": ["The authorization state can remain stale."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Cause retrieved content to exercise the stale state.",
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
            "condition": {
                "type": "action_value",
                "control_action_id": "CA-1-1",
                "property": "authorization_state",
                "operator": "equals",
                "expected": "approved",
            },
            "hazard_refs": ["H-MASS"],
            "constraint_refs": ["SC-MASS"],
        },
        "execution_route": {
            "disposition": "executable_route",
            "delivery_class": "indirect_content",
            "selected_factor_handle": "cause_1",
            "action_kind": "tool_call",
            "reason": "The typed route observes the selected tool action after retrieval.",
        },
    }


def test_context_provider_schema_requires_stimulus_and_hides_role_bookkeeping() -> None:
    schema = _context_bdi_provider_payload_type(
        1, 1, ExecutionActionKind.tool_call
    ).model_json_schema()
    encoded = json.dumps(schema)

    assert "stimulus" in schema["properties"]
    assert "resource_role_handles" not in encoded
    assert "carrier_attacker_influence" not in encoded


def test_context_provider_schema_requires_discriminators_and_evidence_branches() -> (
    None
):
    """Provider wire tags and evidence status are required, not defaulted."""
    schema = _context_bdi_provider_payload_type(
        1,
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


def test_context_provider_schema_restricts_condition_families_to_selected_uca() -> None:
    """Request-specific condition unions do not advertise unrelated branches."""
    for uca_type, allowed in (
        (UCAType.not_provided, {"action_presence"}),
        (UCAType.incorrect, {"action_value", "state_value"}),
        (UCAType.wrong_timing, {"ordering", "delay", "window", "absence"}),
    ):
        schema = _context_bdi_provider_payload_type(
            1,
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


def test_unsafe_condition_wire_types_skip_unbound_timing_and_reject_duration() -> None:
    assert (
        _unsafe_types(
            UCAType.wrong_timing,
            condition_reference_refs=(),
            condition_step_refs=(),
        )
        == {}
    )
    with pytest.raises(ValueError, match="no supported provider"):
        _unsafe_types(UCAType.wrong_duration)


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


def test_context_provider_wire_factory_rejects_empty_condition_union() -> None:
    with pytest.raises(ValueError, match="no provider unsafe-condition branch"):
        _context_bdi_provider_wire_types(1, 1, uca_type=UCAType.wrong_timing)


def test_context_provider_schema_temporal_branches_require_exact_fields() -> None:
    """Each temporal branch advertises only its own meaningful fields."""
    schema = _context_bdi_provider_payload_type(
        1,
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


def test_context_provider_prompt_contains_schema_valid_route_and_condition_fixtures() -> (
    None
):
    """Rendered examples include required route and condition discriminators."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = f"{system}\n{user}"
    assert '"disposition": "executable_route"' in rendered
    assert '"type": "action_value"' in rendered
    assert '"evidence_status": "structural_failure"' in rendered
    assert '"temporal_condition": null' in rendered


def _prompt_provider_types(context, *, duration_eligible: bool = False):
    choices = _causal_source_choices(context)
    schema_kwargs = _context_provider_schema_kwargs(context, choices)
    schema_kwargs["duration_eligible"] = duration_eligible
    provider_types = _context_bdi_provider_wire_types(
        len(choices),
        len(_defender_belief_choices(context)),
        _context_expected_action_kind(context),
        **schema_kwargs,
    )
    return choices, provider_types


def test_context_prompt_examples_cover_temporal_and_evidence_branches() -> None:
    context = _context()
    choices, provider_types = _prompt_provider_types(context, duration_eligible=True)
    aliases = dict(provider_types)
    for branch in ("ordering", "delay", "duration", "window", "absence"):
        aliases[f"_ContextTemporal{branch.title()}Draft"] = provider_types[branch]

    examples = _context_prompt_examples(context, choices, aliases)

    temporal = json.loads(examples["temporal_conditions"])
    assert {item["type"] for item in temporal} == {
        "ordering",
        "delay",
        "duration",
        "window",
        "absence",
    }
    evidence = json.loads(examples["evidence"])
    assert {item["evidence_status"] for item in evidence} == {
        "structural_failure",
        "reachable_capability",
        "bounded_assumption",
    }


def test_context_prompt_examples_skip_unavailable_evidence_branch() -> None:
    context = _typed_tool_context()
    choices, provider_types = _prompt_provider_types(context)
    provider_types = dict(provider_types)
    provider_types.pop("bounded_assumption")

    examples = _context_prompt_examples(context, choices, provider_types)

    evidence = json.loads(examples["evidence"])
    assert {item["evidence_status"] for item in evidence} == {"structural_failure"}


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
    assert '"disposition": "executable_route"' in correction
    assert "Do not infer the missing tag" in correction


def test_context_provider_rejects_missing_discriminator_without_inference() -> None:
    """The strict wire model does not infer unsafe-condition type from fields."""
    model = _context_bdi_provider_payload_type(
        1,
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
    client.set_response_queue([_provider_payload()])

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
