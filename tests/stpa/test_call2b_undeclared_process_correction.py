"""The Call 2b reference correction for a reply that declares no controlled process.

A provider can leave the optional `controlled_processes` collection out of its
reply. The client then fills it with `[]`, and every `CP-*` target and source
fails as unknown. The reference correction names that omission and the
undeclared processes; every other correction keeps its earlier text.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    UnknownReference,
    UnknownReferenceError,
    _call_2b_control_elements,
    _call_2b_reference_feedback,
    _ControlElementProviderSet,
    parse_control_element_set_response,
    parse_responsibility_set_response,
)
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "stpa"
    / "call2b_undeclared_processes_klarna.json"
)

OMISSION = (
    "The prior response left out `controlled_processes` (or sent it empty), so "
    "it declares no controlled process."
)
UNDECLARED_HEADER = "Controlled processes referenced but not declared:"


def _normalized(text: str) -> str:
    return " ".join(text.split())


def _responsibilities() -> list[Responsibility]:
    return [
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


def _feedback(failure: UnknownReferenceError) -> str:
    return _call_2b_reference_feedback(
        failure,
        responsibilities=_responsibilities(),
        loader=TemplateLoader(PROMPTS_DIR),
    )


def _process_refs(*values: str) -> list[UnknownReference]:
    return [
        UnknownReference(f"control_actions[{index}].target", value)
        for index, value in enumerate(values)
    ]


def test_reply_without_processes_gets_the_omission_paragraph() -> None:
    feedback = _feedback(UnknownReferenceError(_process_refs("CP-3", "CP-1", "CP-3")))

    assert OMISSION in _normalized(feedback)
    assert f"{UNDECLARED_HEADER}\n- CP-1\n- CP-3\n" in feedback
    assert feedback.index(UNDECLARED_HEADER) < feedback.index(
        "Unknown references in the prior response:"
    )


def test_reply_with_a_declared_process_gets_no_omission_paragraph() -> None:
    feedback = _feedback(
        UnknownReferenceError(
            _process_refs("CP-3"),
            [ControlledProcess(cp_id="CP-1", description="Transaction processor")],
        )
    )

    assert "left out `controlled_processes`" not in feedback
    assert UNDECLARED_HEADER not in feedback


@pytest.mark.parametrize(
    "references",
    [
        [UnknownReference("control_actions[0].target", "RESP-9")],
        [UnknownReference("control_actions[0].process_model_refs", "CP-1", "RESP-1")],
    ],
    ids=["responsibility-target", "process-model-ref"],
)
def test_unknown_references_that_name_no_process_get_no_omission_paragraph(
    references: list[UnknownReference],
) -> None:
    feedback = _feedback(UnknownReferenceError(references))

    assert UNDECLARED_HEADER not in feedback


def _omitting_payload() -> dict:
    """A reply as the stage parser receives it after the client filled `[]`."""
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
        "controlled_processes": [],
    }


def test_third_request_of_an_omission_chain_carries_the_paragraph(tmp_path) -> None:
    declared = _omitting_payload()
    declared["controlled_processes"] = [
        {"cp_id": "CP-1", "description": "Transaction processor"}
    ]
    client = MockLLMClient()
    client.set_response_for(
        ControlElementSet, [_omitting_payload(), _omitting_payload(), declared]
    )

    parsed = _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=ResponsibilitySet(responsibilities=_responsibilities()),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )

    assert [process.cp_id for process in parsed.controlled_processes] == ["CP-1"]
    assert len(client.calls) == 3
    generic, typed = client.calls[1].user_prompt, client.calls[2].user_prompt
    assert OMISSION not in _normalized(generic)
    assert OMISSION in _normalized(typed)
    assert f"{UNDECLARED_HEADER}\n- CP-1\n" in typed


def _klarna_failure() -> tuple[UnknownReferenceError, list[Responsibility]]:
    fixture = json.loads(FIXTURE.read_text())
    responsibilities = parse_responsibility_set_response(
        fixture["call_2a_reply"]
    ).responsibilities
    # The client hands the stage the provider model, which fills the key the
    # reply left out.
    reply = _ControlElementProviderSet.model_validate(
        fixture["call_2b_attempt_1_reply"]
    )
    with pytest.raises(UnknownReferenceError) as exc_info:
        parse_control_element_set_response(reply, responsibilities=responsibilities)
    return exc_info.value, responsibilities


def test_klarna_fixture_is_an_omission_with_only_process_references() -> None:
    fixture = json.loads(FIXTURE.read_text())
    failure, _ = _klarna_failure()

    assert "controlled_processes" not in fixture["call_2b_attempt_1_reply"]
    assert failure.controlled_processes == ()
    assert {item.value for item in failure.references} == {
        "CP-1",
        "CP-2",
        "CP-3",
        "CP-4",
    }


def test_klarna_reference_correction_names_each_undeclared_process() -> None:
    failure, responsibilities = _klarna_failure()

    feedback = _call_2b_reference_feedback(
        failure, responsibilities=responsibilities, loader=TemplateLoader(PROMPTS_DIR)
    )

    assert OMISSION in _normalized(feedback)
    assert f"{UNDECLARED_HEADER}\n- CP-1\n- CP-2\n- CP-3\n- CP-4\n" in feedback
