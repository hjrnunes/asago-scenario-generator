"""Public-seam regression tests for the corrected Stage 2 Call 2b contract.

These tests intentionally exercise the response parser and assembly boundary,
not the tolerant decoder.  Call 2b is semantic model output: missing meaning
must fail before canonical ID repair or fallback construction.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlledProcess,
    ElementRef,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlAction,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _call_2b_control_elements,
    _assemble_control_structure,
    _enrich_responsibilities,
    _stage2_id_list,
    _validate_responsibility_payload,
    parse_control_element_set_response,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from tests.stpa.sp1_helpers import MockLLMClient


def _responsibilities() -> ResponsibilitySet:
    return ResponsibilitySet(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Authorizes requests",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Request state")
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Verifies outcomes",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="Outcome state")
                ],
            ),
        ]
    )


def _valid_payload() -> dict:
    return {
        "control_actions": [
            {
                "ca_id": "CA-2-1",
                "description": "Verify the completed transaction",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "ca_id": "CA-1-1",
                "description": "Authorize the requested transaction",
                "target": {"type": "responsibility", "id": "RESP-2"},
            },
        ],
        "feedback": [
            {
                "fb_id": "FB-1-1",
                "description": "Report the authorization outcome",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "fb_id": "FB-2-1",
                "description": "Report the completed transaction result",
                "updates": "PM-2-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Transaction processor"}
        ],
    }


def test_call2b_prompt_declares_exact_semantic_fields_and_example() -> None:
    text = (PROMPTS_DIR / "stage2_call2b_system.j2").read_text()

    assert '"ca_id"' in text
    assert '"description"' in text
    assert '"target"' in text
    assert '"fb_id"' in text
    assert '"source"' in text
    assert '"feedback"' in text
    assert "`action`" in text
    assert "must not combine" in text.lower()
    assert "Start greenhouse heating" in text


def test_call2b_prompt_defines_typed_action_kinds_without_prose_inference() -> None:
    text = (PROMPTS_DIR / "stage2_call2b_system.j2").read_text()

    assert "text or structured output returned by the tested model" in text
    assert "structured invocation emitted by the tested agent" in text
    assert "change to session or persistent state" in text
    assert "internal message to another responsibility" in text
    assert "external side effect that is not merely model" in text
    assert "returning advice to a user" in text
    assert "structured loan-renewal invocation" in text
    assert "updating a session" in text
    assert "sending a risk flag" in text
    assert "activating a physical alarm" in text
    assert "never infer" in text.lower()


def test_call2b_parser_preserves_meaning_and_feedback_alias() -> None:
    parsed = parse_control_element_set_response(
        _valid_payload(), responsibilities=_responsibilities().responsibilities
    )

    assert isinstance(parsed, ControlElementSet)
    assert parsed.control_actions[0].description == "Verify the completed transaction"
    assert parsed.control_actions[0].target == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert parsed.feedback_channels[1].description == (
        "Report the completed transaction result"
    )


def test_call2b_parser_accepts_compact_explicit_reference_ids() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["target"] = "CP-1"
    payload["feedback"][0]["source"] = "CP-1"

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert parsed.control_actions[0].target == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert parsed.feedback_channels[0].source == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )


def test_call2b_parser_rejects_combined_action_carrier() -> None:
    payload = _valid_payload()
    payload["control_actions"] = [
        {
            "action": "CA-1-1 Authorize or reject the transaction",
            "target": {"type": "controlled_process", "id": "CP-1"},
        }
    ]

    with pytest.raises(ValueError, match="action|ca_id|description"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


@pytest.mark.parametrize(
    "missing_field",
    ["ca_id", "description"],
)
def test_call2b_parser_rejects_missing_semantic_field(missing_field: str) -> None:
    payload = _valid_payload()
    item = payload["control_actions"][0]
    item.pop(missing_field)

    with pytest.raises(ValueError, match=missing_field):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_parser_rejects_generated_placeholder_description() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["description"] = "Control action CA-2-1"

    with pytest.raises(ValueError, match="meaningful|placeholder"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


@pytest.mark.parametrize(
    ("collection", "field"),
    (("control_actions", "target"), ("feedback", "source")),
)
def test_call2b_parser_rejects_missing_semantic_reference(
    collection: str, field: str
) -> None:
    payload = _valid_payload()
    payload[collection][0].pop(field)

    with pytest.raises(ValueError, match=field):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_parser_rejects_reference_outside_supplied_structure() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["target"] = {
        "type": "controlled_process",
        "id": "CP-99",
    }

    with pytest.raises(ValueError, match="target|CP-99|reference"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_parser_rejects_empty_semantic_collections() -> None:
    payload = _valid_payload()
    payload["control_actions"] = []
    with pytest.raises(ValueError, match="control_actions|action"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_parser_requires_each_process_model_part_to_be_updated() -> None:
    payload = _valid_payload()
    payload["feedback"][0]["updates"] = "PM-1-1"
    payload["feedback"][1]["updates"] = "PM-1-1"

    with pytest.raises(ValueError, match="PM-2-1|feedback|updates"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_uses_strict_parser_on_bounded_schema_retry(tmp_path) -> None:
    invalid = _valid_payload()
    invalid["control_actions"][0] = {
        "action": "CA-2-1 Verify the completed transaction",
        "target": {"type": "controlled_process", "id": "CP-1"},
    }
    client = MockLLMClient()
    client.set_response_for(ControlElementSet, [invalid, _valid_payload()])

    parsed = _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=_responsibilities(),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )

    assert parsed.control_actions[0].description == "Verify the completed transaction"
    assert len(client.calls) == 2
    assert "combined action" in client.calls[1].user_prompt
    assert "ca_id" in client.calls[1].user_prompt
    assert "JSON schema" not in client.calls[1].user_prompt


def test_call2b_parser_rejects_unknown_semantic_field_even_with_description() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["action"] = "ignored carrier"

    with pytest.raises(ValueError, match="unexpected|action"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_call2b_parser_requires_explicit_owner_not_array_order() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["ca_id"] = "unowned-action"

    with pytest.raises(ValueError, match="owner|CA"):
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )


def test_assembly_assigns_reordered_actions_by_owner_encoded_in_id() -> None:
    responsibilities = _responsibilities()
    elements = parse_control_element_set_response(
        _valid_payload(), responsibilities=responsibilities.responsibilities
    )

    assembled = _assemble_control_structure(responsibilities, elements)

    by_resp = {item.resp_id: item for item in assembled.responsibilities}
    assert by_resp["RESP-1"].control_actions[0].description == (
        "Authorize the requested transaction"
    )
    assert by_resp["RESP-2"].control_actions[0].description == (
        "Verify the completed transaction"
    )


def test_normalized_assembly_rejects_unmatched_owner_instead_of_order_recovery() -> (
    None
):
    responsibilities = _responsibilities()
    elements = ControlElementSet(
        control_actions=[],
        feedback_channels=[],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Transaction processor")
        ],
    )

    # The direct assembly seam receives an element whose owner cannot be
    # represented by a responsibility.  No list-order distribution is valid.

    elements.control_actions.append(
        ControlAction(ca_id="CA-99-1", description="Unowned action")
    )
    with pytest.raises(ValueError, match="owner|responsibility|unmatched"):
        _enrich_responsibilities(responsibilities, elements)


def _payload_with(**changes) -> dict:
    payload = _valid_payload()
    for key, value in changes.items():
        if value is None:
            payload.pop(key)
        else:
            payload[key] = value
    return payload


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            _payload_with(controlled_processes=None, feedback=None),
            "Call 2b response is missing top-level collection(s): "
            "controlled_processes, feedback",
        ),
        (
            _payload_with(feedback_channels=[]),
            "Call 2b response must use one feedback collection, not both feedback "
            "and feedback_channels",
        ),
        (_payload_with(control_actions={}), "control_actions must be a list"),
        (
            _payload_with(controlled_processes="CP-1"),
            "controlled_processes must be a list",
        ),
        (
            _payload_with(feedback=None, feedback_channels={}),
            "feedback_channels must be a list",
        ),
        (
            _payload_with(feedback=[]),
            "feedback must contain at least one feedback channel",
        ),
    ],
)
def test_call2b_parser_rejects_malformed_top_level_collections(
    payload: dict, message: str
) -> None:
    with pytest.raises(ValueError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    assert str(exc_info.value) == message


def test_call2b_parser_accepts_historical_feedback_channels_spelling() -> None:
    payload = _valid_payload()
    payload["feedback_channels"] = payload.pop("feedback")

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert [item.fb_id for item in parsed.feedback_channels] == ["FB-1-1", "FB-2-1"]


def _action_error(action: object) -> str:
    payload = _valid_payload()
    payload["control_actions"][0] = action
    with pytest.raises(ValueError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    return str(exc_info.value)


def test_call2b_parser_rejects_a_non_object_action() -> None:
    assert _action_error("CA-2-1") == "control_actions[0] must be an object"


def test_call2b_parser_rejects_an_action_without_a_matching_owner() -> None:
    action = _valid_payload()["control_actions"][0]
    action["ca_id"] = "CA-3-1"

    assert _action_error(action) == (
        "control_actions[0] 'CA-3-1' has no matching responsibility owner; "
        "ownership cannot be recovered from array order"
    )


def test_call2b_parser_rejects_the_action_temporality_spelling() -> None:
    action = _valid_payload()["control_actions"][0]
    action["action_temporality"] = "discrete"

    assert _action_error(action) == (
        "control_actions[0] contains unexpected semantic field(s): action_temporality"
    )


@pytest.mark.parametrize("operation", ["", 7])
def test_call2b_parser_rejects_a_malformed_operation(operation: object) -> None:
    action = _valid_payload()["control_actions"][0]
    action["operation"] = operation

    assert _action_error(action) == (
        "control_actions[0] operation must be an operation name or null"
    )


def test_call2b_parser_keeps_temporality_and_operation() -> None:
    payload = _valid_payload()
    action = payload["control_actions"][0]
    action["temporality"] = "discrete"
    action["operation"] = "verify_transaction"

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert parsed.control_actions[0].temporality.value == "discrete"
    assert parsed.control_actions[0].operation == "verify_transaction"


def _feedback_error(channel: object) -> str:
    payload = _valid_payload()
    payload["feedback"][0] = channel
    with pytest.raises(ValueError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    return str(exc_info.value)


def test_call2b_parser_rejects_a_non_object_feedback_channel() -> None:
    assert _feedback_error("FB-1-1") == "feedback[0] must be an object"


@pytest.mark.parametrize("field", ["fb_id", "description", "updates", "source"])
def test_call2b_parser_rejects_a_feedback_channel_missing_a_field(field: str) -> None:
    channel = _valid_payload()["feedback"][0]
    channel.pop(field)

    assert _feedback_error(channel) == f"feedback[0] is missing {field}"


def test_call2b_parser_rejects_feedback_without_a_matching_owner() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["fb_id"] = "FB-3-1"

    assert _feedback_error(channel) == (
        "feedback[0] 'FB-3-1' has no matching responsibility owner; "
        "ownership cannot be recovered from array order"
    )


def test_call2b_parser_rejects_a_null_feedback_source() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["source"] = None

    assert _feedback_error(channel) == "feedback[0] requires a non-null source"


def test_call2b_parser_rejects_an_unknown_feedback_source_kind() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["source_kind"] = "telepathy"

    message = _feedback_error(channel)

    assert message.startswith("feedback[0] source_kind must be one of: ")
    assert message.endswith("got 'telepathy'")


def test_call2b_parser_keeps_a_valid_feedback_source_kind() -> None:
    payload = _valid_payload()
    payload["feedback"][0]["source_kind"] = "user_message"

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert parsed.feedback_channels[0].source_kind.value == "user_message"
    assert parsed.feedback_channels[1].source_kind is None


def test_call2b_parser_requires_an_action_for_every_responsibility() -> None:
    payload = _valid_payload()
    payload["control_actions"] = payload["control_actions"][:1]

    with pytest.raises(ValueError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    assert str(exc_info.value) == (
        "every responsibility requires a control action; missing owners: RESP-1"
    )


def test_call2b_parser_rejects_feedback_for_an_unknown_process_model_part() -> None:
    payload = _valid_payload()
    payload["feedback"].append(
        {
            "fb_id": "FB-2-2",
            "description": "Report an unrelated state",
            "updates": "PM-9-9",
            "source": {"type": "controlled_process", "id": "CP-1"},
        }
    )

    with pytest.raises(ValueError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    assert str(exc_info.value) == (
        "feedback[2] updates unknown process model part 'PM-9-9'"
    )


def test_stage2_id_list_defaults_and_deduplicates() -> None:
    assert _stage2_id_list(None, field_name="refs", item_label="x") == []
    assert _stage2_id_list(
        ["PM-1", "PM-2", "PM-1"], field_name="refs", item_label="x"
    ) == [
        "PM-1",
        "PM-2",
    ]


@pytest.mark.parametrize("value", ["PM-1", {"a": 1}, ["PM-1", ""], ["PM-1", 2]])
def test_stage2_id_list_rejects_other_shapes(value: object) -> None:
    with pytest.raises(ValueError) as exc_info:
        _stage2_id_list(value, field_name="refs", item_label="action")
    assert str(exc_info.value) == "action refs must be a list of IDs"


def _entry(**changes) -> dict:
    entry = {
        "id": "RESP-1",
        "description": "Authorizes requests",
        "responsibility_constraints": [],
        "security_constraint_refs": ["SC-1"],
        "process_model_parts": [],
    }
    entry.update(changes)
    return entry


@pytest.mark.parametrize(
    "value",
    [
        "not an object",
        {"responsibilities": "not a list"},
        {"responsibilities": ["not an object"]},
        {"responsibilities": [_entry(notes="", extra=None)]},
        {"responsibilities": [_entry()]},
    ],
    ids=["non-object", "non-list", "non-object-entry", "empty-unknown", "valid"],
)
def test_responsibility_payload_leaves_tolerable_shapes_to_the_parser(
    value: object,
) -> None:
    _validate_responsibility_payload(value)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (
            {"responsibilities": [], "extra": []},
            "unexpected responsibility collection(s): extra",
        ),
        (
            {"responsibilities": [_entry(), _entry(notes="keep")]},
            "unexpected responsibility collection field(s) at index 1: notes. "
            "Remove them; each responsibility contains only resp_id, description, "
            "responsibility_constraints, security_constraint_refs, and "
            "process_model_parts",
        ),
        (
            {"responsibilities": [{"id": "RESP-1"}]},
            "responsibility is missing security_constraint_refs at index 0",
        ),
        (
            {"responsibilities": [_entry(security_constraint_refs="SC-1")]},
            "security_constraint_refs must be a list at index 0",
        ),
    ],
)
def test_responsibility_payload_rejects_fields_the_parser_would_drop(
    value: dict, message: str
) -> None:
    with pytest.raises(ValueError) as exc_info:
        _validate_responsibility_payload(value)
    assert str(exc_info.value) == message
