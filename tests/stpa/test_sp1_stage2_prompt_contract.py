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
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _call_2b_control_elements,
    _assemble_control_structure,
    _enrich_responsibilities,
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

    assembled = _assemble_control_structure(
        responsibilities, elements, normalize_ids=True
    )

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
    from asago_scenario_generator.stpa.models.control_structure import ControlAction

    elements.control_actions.append(
        ControlAction(ca_id="CA-99-1", description="Unowned action")
    )
    with pytest.raises(ValueError, match="owner|responsibility|unmatched"):
        _enrich_responsibilities(responsibilities, elements, normalize_ids=True)
