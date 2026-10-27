"""A Call 2b action aimed at a responsibility takes the message effect.

An action that targets a responsibility is a message between controllers;
``agent_message`` is the only effect it can have.  A reply that names another
effect for such an action, and no operation, used to fail both Call 2b
attempts.  The parser now sets ``agent_message`` and records the change as a
cleanup transformation of the call, apart from model output.  An action that
names an operation still fails: an operation is an invocation, so its target
may be what is wrong.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    RESPONSIBILITY_MESSAGE_EFFECT_KIND,
    ResponsibilitySet,
    _call_2b_control_elements,
    parse_control_element_set_response,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.sp1_control_structure import _responsibilities
from tests.stpa.sp1_helpers import MockLLMClient

STEP = "call_2b_control_elements"


def _action(number: int, **fields: Any) -> dict[str, Any]:
    return {
        "ca_id": f"CA-{number}-1",
        "description": f"Deliver the result of responsibility {number}",
        "target": {"type": "controlled_process", "id": "CP-1"},
        "effect_kind": "model_output",
        "temporality": "discrete",
        "operation": None,
        "process_model_refs": [f"PM-{number}-1"],
        **fields,
    }


def _reply(*actions: dict[str, Any]) -> dict[str, Any]:
    return {
        "control_actions": list(actions),
        "feedback": [
            {
                "fb_id": f"FB-{number}-1",
                "description": f"Report the state of responsibility {number}",
                "updates": f"PM-{number}-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
                "source_kind": "operation_result",
            }
            for number in (1, 2, 3)
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Caller interface"}],
    }


def _memory_update(**fields: Any) -> dict[str, Any]:
    """The recorded shape: a state update aimed at the owner's responsibility."""
    return _action(
        3,
        **{
            "description": "Update conversational memory",
            "target": {"type": "responsibility", "id": "RESP-3"},
            "effect_kind": "state_change",
            **fields,
        },
    )


def _parse(payload: Any, cleanup: list[dict[str, Any]] | None = None) -> Any:
    return parse_control_element_set_response(
        payload,
        responsibilities=_responsibilities(),
        cleanup_transformations=cleanup,
    )


def test_a_state_change_aimed_at_a_responsibility_becomes_a_message() -> None:
    cleanup: list[dict[str, Any]] = []

    parsed = _parse(_reply(_action(1), _action(2), _memory_update()), cleanup)

    action = parsed.control_actions[2]
    assert action.effect_kind is ControlActionEffectKind.agent_message
    assert action.temporality is ControlActionTemporality.discrete
    assert action.operation is None
    assert action.process_model_refs == ["PM-3-1"]
    (record,) = cleanup
    assert record["name"] == RESPONSIBILITY_MESSAGE_EFFECT_KIND
    assert record["detail"] == (
        "set effect_kind to agent_message for actions that target a "
        "responsibility and name no operation; was: control_actions[2] "
        "CA-3-1: state_change"
    )
    assert record["input_pin"] != record["output_pin"]


def test_a_compact_responsibility_target_is_read_the_same_way() -> None:
    cleanup: list[dict[str, Any]] = []

    parsed = _parse(
        _reply(_action(1), _action(2), _memory_update(target="RESP-3")), cleanup
    )

    assert (
        parsed.control_actions[2].effect_kind is ControlActionEffectKind.agent_message
    )
    assert len(cleanup) == 1


def test_a_reply_that_needs_no_change_records_none() -> None:
    cleanup: list[dict[str, Any]] = []
    message = _memory_update(effect_kind="agent_message")

    parsed = _parse(_reply(_action(1), _action(2), message), cleanup)

    assert (
        parsed.control_actions[2].effect_kind is ControlActionEffectKind.agent_message
    )
    assert cleanup == []


def test_an_action_that_names_an_operation_keeps_its_rejection() -> None:
    action = _memory_update(effect_kind="tool_call", operation="save_memory")
    cleanup: list[dict[str, Any]] = []

    with pytest.raises(ValidationError, match="effect_kind='agent_message'"):
        _parse(_reply(_action(1), _action(2), action), cleanup)

    assert cleanup == []


def test_an_invalid_effect_is_left_for_the_wire_models() -> None:
    action = _memory_update(effect_kind="message")

    with pytest.raises(ValidationError, match="effect_kind"):
        _parse(_reply(_action(1), _action(2), action))


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


def _attempts(run_dir: Path) -> list[dict[str, Any]]:
    return [row for row in read_calls_jsonl(run_dir) if row["step"] == STEP]


def _cleanup_names(row: dict[str, Any]) -> list[str]:
    return [item["name"] for item in row.get("cleanup_transformations", [])]


def test_the_first_reply_passes_and_its_call_record_keeps_the_change(
    tmp_path: Path,
) -> None:
    client = _client(_reply(_action(1), _action(2), _memory_update()))

    parsed = _run(client, tmp_path)

    assert (
        parsed.control_actions[2].effect_kind is ControlActionEffectKind.agent_message
    )
    assert len(client.calls) == 1
    (attempt,) = _attempts(tmp_path)
    assert attempt["success"] is True
    assert RESPONSIBILITY_MESSAGE_EFFECT_KIND in _cleanup_names(attempt)


def test_a_missing_action_repair_reply_takes_the_same_change(tmp_path: Path) -> None:
    client = _client(
        _reply(_action(1), _action(2)),
        _reply(_action(1), _action(2)),
        {"control_actions": [_memory_update()]},
    )

    parsed = _run(client, tmp_path)

    assert [action.ca_id for action in parsed.control_actions] == [
        "CA-1-1",
        "CA-2-1",
        "CA-3-1",
    ]
    assert (
        parsed.control_actions[2].effect_kind is ControlActionEffectKind.agent_message
    )
    assert len(client.calls) == 3
    repair = _attempts(tmp_path)[2]
    assert repair["success"] is True
    assert RESPONSIBILITY_MESSAGE_EFFECT_KIND in _cleanup_names(repair)
