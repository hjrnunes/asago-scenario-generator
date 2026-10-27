"""A Call 2b reply that declares one controlled process ID more than once.

Canonical numbering gives each declaration its own ID, but a target or source
naming the shared ID resolves to neither, so assembly used to fail with no
correction left.  The parser now rejects the repeated declaration, the
generic correction carries the exact error naming it, and the reference
correction lists each declaration with its description.  Control action and
feedback IDs need no such check: nothing in the reply refers to them.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    DuplicateDeclarationError,
    ResponsibilitySet,
    UnknownReferenceError,
    _assemble_control_structure,
    _call_2b_control_elements,
    _call_2b_reference_feedback,
    parse_control_element_set_response,
    parse_responsibility_set_response,
)
from tests.helpers.sp1_control_structure import _responsibilities
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "stpa"
    / "call2b_duplicate_process_airbnb.json"
)
DUPLICATE_HEADER = "Controlled processes declared more than once:"
EXACT_ERROR = (
    "DuplicateDeclarationError: controlled process 'CP-2' is declared twice, at "
    "controlled_processes[1] and controlled_processes[2]; each cp_id must be "
    "declared once"
)


def _action(number: int, target: str) -> dict[str, Any]:
    return {
        "ca_id": f"CA-{number}-1",
        "description": f"Deliver the result of responsibility {number}",
        "target": {"type": "controlled_process", "id": target},
        "effect_kind": "tool_call",
        "temporality": "discrete",
        "operation": None,
        "process_model_refs": [f"PM-{number}-1"],
    }


def _reply(*processes: tuple[str, str]) -> dict[str, Any]:
    """Three owners; RESP-2 acts on CP-2 and reads its feedback from CP-2."""
    return {
        "control_actions": [_action(1, "CP-1"), _action(2, "CP-2"), _action(3, "CP-1")],
        "feedback": [
            {
                "fb_id": f"FB-{number}-1",
                "description": f"Report the state of responsibility {number}",
                "updates": f"PM-{number}-1",
                "source": {"type": "controlled_process", "id": cp_id},
                "source_kind": "operation_result",
            }
            for number, cp_id in ((1, "CP-1"), (2, "CP-2"), (3, "CP-1"))
        ],
        "controlled_processes": [
            {"cp_id": cp_id, "description": description}
            for cp_id, description in processes
        ],
    }


def _duplicate_reply() -> dict[str, Any]:
    return _reply(
        ("CP-1", "Caller interface"),
        ("CP-2", "Policy store"),
        ("CP-2", "Store of policies"),
    )


def _fixed_reply() -> dict[str, Any]:
    return _reply(("CP-1", "Caller interface"), ("CP-2", "Policy store"))


def _parse(payload: Any) -> Any:
    return parse_control_element_set_response(
        payload, responsibilities=_responsibilities()
    )


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_a_repeated_process_declaration_is_rejected_by_name() -> None:
    with pytest.raises(DuplicateDeclarationError) as exc_info:
        _parse(_duplicate_reply())

    failure = exc_info.value
    assert isinstance(failure, UnknownReferenceError)
    assert failure.references == ()
    (duplicate,) = failure.duplicates
    assert duplicate.cp_id == "CP-2"
    assert duplicate.declarations == (
        ("controlled_processes[1]", "Policy store"),
        ("controlled_processes[2]", "Store of policies"),
    )
    assert duplicate.references == ("control_actions[1].target", "feedback[1].source")
    assert str(failure) == EXACT_ERROR.removeprefix("DuplicateDeclarationError: ")


def test_a_process_declared_three_times_counts_each_declaration() -> None:
    payload = _duplicate_reply()
    payload["controlled_processes"].append({"cp_id": "CP-2", "description": "Rules"})

    with pytest.raises(DuplicateDeclarationError, match="declared 3 times, at "):
        _parse(payload)


def test_unknown_references_are_reported_with_the_repeated_declaration() -> None:
    payload = _duplicate_reply()
    payload["control_actions"][0]["target"]["id"] = "CP-9"

    with pytest.raises(DuplicateDeclarationError) as exc_info:
        _parse(payload)

    assert [item.value for item in exc_info.value.references] == ["CP-9"]
    assert [item.cp_id for item in exc_info.value.duplicates] == ["CP-2"]


def test_repeated_action_and_feedback_ids_are_numbered_apart() -> None:
    payload = _fixed_reply()
    payload["control_actions"].append(
        {**_action(1, "CP-2"), "description": "Fetch the applicable policy"}
    )
    payload["feedback"].append(
        {**payload["feedback"][0], "description": "Report the policy found"}
    )

    elements = _parse(payload)
    structure = _assemble_control_structure(
        ResponsibilitySet(responsibilities=_responsibilities()), elements
    )

    (first,) = [resp for resp in structure.responsibilities if resp.resp_id == "RESP-1"]
    assert [action.ca_id for action in first.control_actions] == ["CA-1-1", "CA-1-2"]
    assert [channel.fb_id for channel in first.feedback_channels] == [
        "FB-1-1",
        "FB-1-2",
    ]


def _run(client: MockLLMClient, run_dir: Path) -> Any:
    return _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=ResponsibilitySet(responsibilities=_responsibilities()),
        run_dir=run_dir,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def _client(*replies: Any) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue(list(replies))
    return client


def test_the_generic_correction_names_the_repeated_declaration(tmp_path) -> None:
    client = _client(_duplicate_reply(), _fixed_reply())

    parsed = _run(client, tmp_path)

    assert [process.cp_id for process in parsed.controlled_processes] == [
        "CP-1",
        "CP-2",
    ]
    assert len(client.calls) == 2
    generic = client.calls[1].user_prompt
    assert EXACT_ERROR in _normalized(generic)
    assert DUPLICATE_HEADER not in generic


def test_the_reference_correction_follows_a_second_repeated_declaration(
    tmp_path,
) -> None:
    client = _client(_duplicate_reply(), _duplicate_reply(), _fixed_reply())

    parsed = _run(client, tmp_path)

    assert len(parsed.controlled_processes) == 2
    assert len(client.calls) == 3
    typed = client.calls[2].user_prompt
    assert typed.startswith(client.calls[0].user_prompt)
    assert (
        f"{DUPLICATE_HEADER}\n"
        "- CP-2\n"
        "  - controlled_processes[1]: Policy store\n"
        "  - controlled_processes[2]: Store of policies\n"
        "  - named by: control_actions[1].target, feedback[1].source\n"
    ) in typed
    assert "Unknown references in the prior response:" not in typed
    assert EXACT_ERROR in _normalized(typed)


def test_a_third_repeated_declaration_stops_the_step(tmp_path) -> None:
    client = _client(_duplicate_reply(), _duplicate_reply(), _duplicate_reply())

    with pytest.raises(Exception, match="is declared twice"):
        _run(client, tmp_path)

    assert len(client.calls) == 3


def _recorded() -> tuple[dict[str, Any], list[Any]]:
    fixture = json.loads(FIXTURE.read_text())
    responsibilities = parse_responsibility_set_response(
        fixture["call_2a_reply"]
    ).responsibilities
    return fixture["call_2b_attempt_1_reply"], responsibilities


def test_the_recorded_reply_is_rejected_for_its_repeated_process() -> None:
    reply, responsibilities = _recorded()

    with pytest.raises(DuplicateDeclarationError) as exc_info:
        parse_control_element_set_response(
            json.dumps(reply), responsibilities=responsibilities
        )

    failure = exc_info.value
    assert failure.references == ()
    (duplicate,) = failure.duplicates
    assert duplicate.cp_id == "CP-POLICY_DOCS"
    assert duplicate.declarations == (
        ("controlled_processes[3]", "The platform policy document repository"),
        ("controlled_processes[7]", "Repository of platform policies"),
    )
    assert duplicate.references == ("control_actions[6].target", "feedback[4].source")

    feedback = _call_2b_reference_feedback(
        failure, responsibilities=responsibilities, loader=TemplateLoader(PROMPTS_DIR)
    )
    assert (
        f"{DUPLICATE_HEADER}\n"
        "- CP-POLICY_DOCS\n"
        "  - controlled_processes[3]: The platform policy document repository\n"
        "  - controlled_processes[7]: Repository of platform policies\n"
    ) in feedback


def test_the_recorded_reply_without_its_repeat_assembles() -> None:
    reply, responsibilities = _recorded()
    reply = copy.deepcopy(reply)
    del reply["controlled_processes"][7]

    elements = parse_control_element_set_response(
        json.dumps(reply), responsibilities=responsibilities
    )
    structure = _assemble_control_structure(
        ResponsibilitySet(responsibilities=responsibilities), elements
    )

    assert len(structure.controlled_processes) == 7
