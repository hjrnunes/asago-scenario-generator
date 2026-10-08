"""Public-seam regression tests for the corrected Stage 2 Call 2b contract.

These tests intentionally exercise the response parser and assembly boundary,
not the tolerant decoder.  Call 2b is semantic model output: missing meaning
must fail before canonical ID repair or fallback construction.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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
    UnknownReferenceError,
    _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK,
    _call_2b_control_elements,
    _assemble_control_structure,
    _enrich_responsibilities,
    _validate_responsibility_wire,
    parse_responsibility_set_response,
    parse_control_element_set_response,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from tests.helpers.calls_log import read_calls_jsonl
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


def _wire_errors(payload: object) -> list[tuple[str, str]]:
    """Return the (location, message) pairs a malformed Call 2b response raises."""
    with pytest.raises(ValidationError) as exc_info:
        parse_control_element_set_response(
            payload, responsibilities=_responsibilities().responsibilities
        )
    return [
        (".".join(str(part) for part in error["loc"]), error["msg"])
        for error in exc_info.value.errors()
    ]


def _has_error(errors: list[tuple[str, str]], location: str, fragment: str) -> bool:
    return any(loc == location and fragment in msg for loc, msg in errors)


@pytest.mark.parametrize(
    ("payload", "location", "fragment"),
    [
        (
            _payload_with(controlled_processes=None, feedback=None),
            "controlled_processes",
            "Field required",
        ),
        (
            _payload_with(controlled_processes=None, feedback=None),
            "feedback",
            "Field required",
        ),
        (
            _payload_with(feedback_channels=[]),
            "",
            "must use one feedback collection, not both feedback and feedback_channels",
        ),
        (_payload_with(control_actions={}), "control_actions", "valid list"),
        (_payload_with(controlled_processes="CP-1"), "controlled_processes", "list"),
        (
            _payload_with(feedback=None, feedback_channels={}),
            "feedback_channels",
            "list",
        ),
        (_payload_with(feedback=[]), "feedback", "at least 1 item"),
        (_payload_with(extra=[]), "extra", "Extra inputs are not permitted"),
    ],
    ids=[
        "missing-processes",
        "missing-feedback",
        "both-feedback-spellings",
        "actions-not-list",
        "processes-not-list",
        "feedback-channels-not-list",
        "empty-feedback",
        "unknown-collection",
    ],
)
def test_call2b_parser_rejects_malformed_top_level_collections(
    payload: dict, location: str, fragment: str
) -> None:
    assert _has_error(_wire_errors(payload), location, fragment)


def test_call2b_parser_rejects_a_non_object_response() -> None:
    assert _wire_errors(["not", "an", "object"])


def test_call2b_parser_accepts_historical_feedback_channels_spelling() -> None:
    payload = _valid_payload()
    payload["feedback_channels"] = payload.pop("feedback")

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert [item.fb_id for item in parsed.feedback_channels] == ["FB-1-1", "FB-2-1"]


def _action_errors(action: object) -> list[tuple[str, str]]:
    payload = _valid_payload()
    payload["control_actions"][0] = action
    return _wire_errors(payload)


def test_call2b_parser_rejects_a_non_object_action() -> None:
    assert _has_error(_action_errors("CA-2-1"), "control_actions.0", "")


def test_call2b_parser_rejects_an_action_without_a_matching_owner() -> None:
    action = _valid_payload()["control_actions"][0]
    action["ca_id"] = "CA-3-1"

    assert _has_error(
        _action_errors(action),
        "control_actions.0.ca_id",
        "'CA-3-1' has no matching responsibility owner; "
        "ownership cannot be recovered from array order",
    )


def test_call2b_parser_rejects_an_id_without_an_owner() -> None:
    action = _valid_payload()["control_actions"][0]
    action["ca_id"] = "first-action"

    assert _has_error(
        _action_errors(action),
        "control_actions.0.ca_id",
        "must encode an explicit owner using CA-X-Y; got 'first-action'",
    )


def test_call2b_parser_names_the_combined_action_field() -> None:
    action = _valid_payload()["control_actions"][0]
    action["action"] = "CA-2-1 Verify the completed transaction"

    assert _has_error(
        _action_errors(action),
        "control_actions.0",
        "uses combined action field 'action'; return separate ca_id and "
        "description fields",
    )


def test_call2b_parser_rejects_the_action_temporality_spelling() -> None:
    action = _valid_payload()["control_actions"][0]
    action["action_temporality"] = "discrete"

    assert _has_error(
        _action_errors(action),
        "control_actions.0.action_temporality",
        "Extra inputs are not permitted",
    )


@pytest.mark.parametrize("operation", ["", 7])
def test_call2b_parser_rejects_a_malformed_operation(operation: object) -> None:
    action = _valid_payload()["control_actions"][0]
    action["operation"] = operation

    assert _has_error(_action_errors(action), "control_actions.0.operation", "")


@pytest.mark.parametrize(
    ("target", "fragment"),
    [
        ("PM-1-1", "must name RESP-N or CP-N; got 'PM-1-1'"),
        (" ", "must name RESP-N or CP-N"),
        ({"type": "controlled_process", "id": "CP-1", "x": 1}, "Extra inputs"),
        ({"type": "process", "id": "CP-1"}, "Input should be"),
    ],
    ids=["unknown-prefix", "blank", "extra-field", "unknown-type"],
)
def test_call2b_parser_rejects_a_malformed_target(
    target: object, fragment: str
) -> None:
    action = _valid_payload()["control_actions"][0]
    action["target"] = target

    assert any(
        loc.startswith("control_actions.0.target") and fragment in msg
        for loc, msg in _action_errors(action)
    )


def test_call2b_parser_rejects_an_effect_that_contradicts_its_target() -> None:
    action = _valid_payload()["control_actions"][1]
    action["effect_kind"] = "tool_call"

    assert _has_error(
        _action_errors(action),
        "control_actions.0",
        "control actions targeting a responsibility must use "
        "effect_kind='agent_message'",
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
    assert parsed.control_actions[1].effect_kind.value == "agent_message"


def _feedback_errors(channel: object) -> list[tuple[str, str]]:
    payload = _valid_payload()
    payload["feedback"][0] = channel
    return _wire_errors(payload)


def test_call2b_parser_rejects_a_non_object_feedback_channel() -> None:
    assert _has_error(_feedback_errors("FB-1-1"), "feedback.0", "")


@pytest.mark.parametrize("field", ["fb_id", "description", "updates", "source"])
def test_call2b_parser_rejects_a_feedback_channel_missing_a_field(field: str) -> None:
    channel = _valid_payload()["feedback"][0]
    channel.pop(field)

    assert _has_error(
        _feedback_errors(channel), f"feedback.0.{field}", "Field required"
    )


def test_call2b_parser_rejects_feedback_without_a_matching_owner() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["fb_id"] = "FB-3-1"

    assert _has_error(
        _feedback_errors(channel),
        "feedback.0.fb_id",
        "'FB-3-1' has no matching responsibility owner; "
        "ownership cannot be recovered from array order",
    )


def test_call2b_parser_rejects_a_null_feedback_source() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["source"] = None

    assert _has_error(_feedback_errors(channel), "feedback.0.source", "")


def test_call2b_parser_rejects_an_unknown_feedback_source_kind() -> None:
    channel = _valid_payload()["feedback"][0]
    channel["source_kind"] = "telepathy"

    assert _has_error(
        _feedback_errors(channel), "feedback.0.source_kind", "Input should be"
    )


def test_assembly_numbers_a_named_controlled_process_by_position() -> None:
    payload = _valid_payload()
    payload["controlled_processes"][0]["cp_id"] = "CP-RESERVATIONS"
    for item in (payload["control_actions"][0], *payload["feedback"]):
        reference = item.get("target") or item["source"]
        reference["id"] = "CP-RESERVATIONS"
    responsibilities = _responsibilities()

    elements = parse_control_element_set_response(
        payload, responsibilities=responsibilities.responsibilities
    )
    assembled = _assemble_control_structure(responsibilities, elements)

    assert elements.controlled_processes[0].cp_id == "CP-RESERVATIONS"
    assert [process.cp_id for process in assembled.controlled_processes] == ["CP-1"]
    by_resp = {item.resp_id: item for item in assembled.responsibilities}
    assert by_resp["RESP-2"].control_actions[0].target == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert by_resp["RESP-1"].feedback_channels[0].source == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )


def test_call2b_parser_rejects_a_blank_controlled_process_id() -> None:
    payload = _valid_payload()
    payload["controlled_processes"][0]["cp_id"] = " "

    assert _has_error(
        _wire_errors(payload), "controlled_processes.0.cp_id", "non-empty"
    )


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


def test_call2b_parser_defaults_and_deduplicates_process_model_refs() -> None:
    payload = _valid_payload()
    payload["control_actions"][0]["process_model_refs"] = ["PM-2-1", "PM-2-1"]
    payload["control_actions"][1]["process_model_refs"] = None

    parsed = parse_control_element_set_response(
        payload, responsibilities=_responsibilities().responsibilities
    )

    assert parsed.control_actions[0].process_model_refs == ["PM-2-1"]
    assert parsed.control_actions[1].process_model_refs == []


@pytest.mark.parametrize("value", ["PM-2-1", {"a": 1}, ["PM-2-1", ""], ["PM-2-1", 2]])
def test_call2b_parser_rejects_other_process_model_ref_shapes(value: object) -> None:
    action = _valid_payload()["control_actions"][0]
    action["process_model_refs"] = value

    assert any(
        loc.startswith("control_actions.0.process_model_refs")
        for loc, _ in _action_errors(action)
    )


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


def _parsed_responsibilities(value: object) -> ResponsibilitySet:
    _validate_responsibility_wire(value)
    return parse_responsibility_set_response(value)


def test_responsibility_parser_keeps_a_valid_response() -> None:
    entry = _entry(
        responsibility_constraints=[{"rc_id": "RC-1-1", "description": "Bound"}],
        process_model_parts=[
            {"pm_id": "PM-1-1", "description": "Request state", "values": ["a"]}
        ],
    )

    parsed = _parsed_responsibilities({"responsibilities": [entry]})

    assert parsed.responsibilities[0].resp_id == "RESP-1"
    assert parsed.responsibilities[0].responsibility_constraints[0].rc_id == "RC-1-1"
    assert parsed.responsibilities[0].process_model_parts[0].values == ["a"]


def test_responsibility_parser_reads_a_generic_id_as_resp_id() -> None:
    parsed = _parsed_responsibilities({"responsibilities": [_entry()]})

    assert parsed.responsibilities[0].resp_id == "RESP-1"


def test_responsibility_parser_drops_an_unknown_field_that_holds_nothing() -> None:
    parsed = _parsed_responsibilities(
        {"responsibilities": [_entry(notes="", extra=None, feedback_source={})]}
    )

    assert parsed.responsibilities[0].description == "Authorizes requests"


def test_responsibility_parser_keeps_ids_for_normalization() -> None:
    entry = _entry(
        id="RESP-A",
        responsibility_constraints=[{"rc_id": "RC-A", "description": "Bound"}],
        process_model_parts=[{"pm_id": "PM_1", "description": "Request state"}],
    )

    parsed = _parsed_responsibilities({"responsibilities": [entry]})

    responsibility = parsed.responsibilities[0]
    assert responsibility.resp_id == "RESP-A"
    assert responsibility.responsibility_constraints[0].rc_id == "RC-A"
    assert responsibility.process_model_parts[0].pm_id == "PM_1"


def test_responsibility_parser_leaves_an_omitted_constraint_id_to_normalization() -> (
    None
):
    entry = _entry(
        responsibility_constraints=[{"rc_2-1": "RC-2-1", "description": "Bound"}]
    )

    parsed = _parsed_responsibilities({"responsibilities": [entry]})

    assert parsed.responsibilities[0].responsibility_constraints[0].rc_id == ""


@pytest.mark.parametrize(
    ("value", "location", "fragment"),
    [
        ({"responsibilities": [], "extra": []}, "extra", "Extra inputs"),
        ({"responsibilities": []}, "responsibilities", "at least 1 item"),
        ({"responsibilities": "not a list"}, "responsibilities", "valid list"),
        ({"responsibilities": ["not an object"]}, "responsibilities.0", ""),
        (
            {"responsibilities": [_entry(), _entry(notes="keep")]},
            "responsibilities.1",
            "unexpected responsibility field(s): notes. Remove them; each "
            "responsibility contains only resp_id, description, "
            "responsibility_constraints, security_constraint_refs, and "
            "process_model_parts",
        ),
        (
            {"responsibilities": [{"id": "RESP-1", "description": "Authorizes"}]},
            "responsibilities.0.security_constraint_refs",
            "Field required",
        ),
        (
            {"responsibilities": [_entry(security_constraint_refs="SC-1")]},
            "responsibilities.0.security_constraint_refs",
            "valid list",
        ),
        (
            {"responsibilities": [_entry(description="")]},
            "responsibilities.0.description",
            "",
        ),
    ],
    ids=[
        "unknown-collection",
        "empty",
        "non-list",
        "non-object-entry",
        "unknown-field",
        "missing-refs",
        "refs-not-list",
        "blank-description",
    ],
)
def test_responsibility_parser_rejects_fields_it_would_drop(
    value: dict, location: str, fragment: str
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _validate_responsibility_wire(value)
    assert any(
        ".".join(str(part) for part in error["loc"]) == location
        and fragment in error["msg"]
        for error in exc_info.value.errors()
    )


def test_responsibility_parser_rejects_a_non_object_response() -> None:
    with pytest.raises(ValidationError):
        _validate_responsibility_wire("not an object")


def _invented_reference_payload() -> dict:
    payload = _valid_payload()
    payload["control_actions"][0]["target"] = {
        "type": "responsibility",
        "id": "RESP-T_S",
    }
    payload["control_actions"][0]["effect_kind"] = "agent_message"
    payload["control_actions"][0]["process_model_refs"] = ["PM-1-1"]
    payload["feedback"][1]["source"] = {"type": "controlled_process", "id": "CP-9"}
    return payload


def _run_call_2b(client: MockLLMClient, tmp_path) -> ControlElementSet:
    return _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=_responsibilities(),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def test_call2b_parser_names_every_unknown_reference() -> None:
    with pytest.raises(UnknownReferenceError) as exc_info:
        parse_control_element_set_response(
            _invented_reference_payload(),
            responsibilities=_responsibilities().responsibilities,
        )

    assert [
        (item.location, item.value, item.owner) for item in exc_info.value.references
    ] == [
        ("control_actions[0].target", "RESP-T_S", None),
        ("feedback[1].source", "CP-9", None),
        ("control_actions[0].process_model_refs", "PM-1-1", "RESP-2"),
    ]


def test_call2b_sends_one_reference_correction_after_the_generic_retry(
    tmp_path,
) -> None:
    client = MockLLMClient()
    client.set_response_for(
        ControlElementSet,
        [
            _invented_reference_payload(),
            _invented_reference_payload(),
            _valid_payload(),
        ],
    )

    parsed = _run_call_2b(client, tmp_path)

    assert parsed.control_actions[0].target == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert len(client.calls) == 3
    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"] == "call_2b_control_elements"
    ]
    assert [(entry["attempt_number"], entry["success"]) for entry in attempts] == [
        (1, False),
        (2, False),
        (3, True),
    ]
    generic, typed = client.calls[1].user_prompt, client.calls[2].user_prompt
    assert "Unknown references" not in generic
    assert "Unknown references in the prior response:" in typed
    assert "- control_actions[0].target: RESP-T_S" in typed
    assert "- feedback[1].source: CP-9" in typed
    assert (
        "- control_actions[0].process_model_refs: PM-1-1 "
        "(not a process model part of RESP-2)" in typed
    )
    assert "- RESP-1 (responsibility): Authorizes requests" in typed
    assert "- CP-1 (controlled process): Transaction processor" in typed
    assert "- RESP-2: PM-2-1: Outcome state" in typed
    assert "Prior structured response to correct in place" in typed
    assert _INTERMEDIATE_VALIDATION_RETRY_FEEDBACK not in typed


def test_call2b_reference_correction_is_bounded(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        ControlElementSet,
        [_invented_reference_payload()] * 3 + [_valid_payload()],
    )

    with pytest.raises(StageError) as exc_info:
        _run_call_2b(client, tmp_path)

    assert len(client.calls) == 3
    assert "RESP-T_S" in exc_info.value.message


def test_call2b_other_failures_get_no_reference_correction(tmp_path) -> None:
    unserved = _valid_payload()
    unserved["control_actions"] = unserved["control_actions"][:1]
    client = MockLLMClient()
    client.set_response_for(ControlElementSet, [unserved, unserved, _valid_payload()])

    with pytest.raises(StageError):
        _run_call_2b(client, tmp_path)

    assert len(client.calls) == 2
