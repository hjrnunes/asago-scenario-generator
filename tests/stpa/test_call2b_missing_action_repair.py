"""Call 2b repairs a responsibility left without a control action.

A reply that serves every responsibility but one fails the stage post-check
with ``every responsibility requires a control action``.  The generic
correction carries that text only, and a reply may still miss the owner.  The
stage then sends one repair request that asks for control actions for exactly
the missing owners, merges them into the last reply, and checks the result
again.  A repair that fails stops the unit as before.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.call_log import jsonl_lines
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    _call_2b_control_elements,
    _MissingActionProviderSet,
)
from tests.stpa.sp1_helpers import MockLLMClient

STEP = "call_2b_control_elements"
REPAIR_OPENING = (
    "The prior response leaves these responsibilities without a control action:"
)


def _responsibilities() -> list[Responsibility]:
    return [
        Responsibility(
            resp_id=f"RESP-{number}",
            description=f"Responsibility {number} serves the use case",
            process_model_parts=[
                ProcessModelPart(pm_id=f"PM-{number}-1", description="State")
            ],
        )
        for number in (1, 2, 3)
    ]


def _action(number: int, *, effect_kind: str = "model_output") -> dict[str, Any]:
    return {
        "ca_id": f"CA-{number}-1",
        "description": f"Deliver the result of responsibility {number}",
        "target": {"type": "controlled_process", "id": "CP-1"},
        "effect_kind": effect_kind,
        "temporality": "discrete",
        "operation": None,
        "process_model_refs": [f"PM-{number}-1"],
    }


def _reply(*owners: int) -> dict[str, Any]:
    return {
        "control_actions": [_action(number) for number in owners],
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


def _bad_effect_reply(*owners: int) -> dict[str, Any]:
    """A reply whose responsibility-targeting action has the wrong effect kind."""
    reply = _reply(*owners)
    reply["control_actions"].append(
        {
            **_action(1),
            "ca_id": "CA-1-2",
            "target": {"type": "responsibility", "id": "RESP-2"},
            "effect_kind": "state_change",
        }
    )
    return reply


def _repair_reply(*numbers: int) -> dict[str, Any]:
    return {"control_actions": [_action(number) for number in numbers]}


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
    rows = [
        json.loads(line) for line in jsonl_lines((run_dir / "calls.jsonl").read_text())
    ]
    return [row for row in rows if row["step"] == STEP]


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_a_reply_that_misses_an_owner_twice_earns_one_repair(tmp_path: Path) -> None:
    client = _client(_reply(1, 2), _reply(1, 2), _repair_reply(3))

    parsed = _run(client, tmp_path)

    assert sorted(action.ca_id for action in parsed.control_actions) == [
        "CA-1-1",
        "CA-2-1",
        "CA-3-1",
    ]
    assert len(client.calls) == 3
    assert client.calls[2].response_format is _MissingActionProviderSet


def test_the_repair_follows_a_correction_that_fixes_another_defect(
    tmp_path: Path,
) -> None:
    client = _client(_bad_effect_reply(1, 2), _reply(1, 2), _repair_reply(3))

    parsed = _run(client, tmp_path)

    assert {action.ca_id for action in parsed.control_actions} == {
        "CA-1-1",
        "CA-2-1",
        "CA-3-1",
    }
    first_error = _attempts(tmp_path)[0]["error"]
    assert "effect_kind='agent_message'" in first_error
    assert len(client.calls) == 3


def test_the_repair_request_carries_the_owners_the_rule_and_the_structure(
    tmp_path: Path,
) -> None:
    client = _client(_reply(1), _reply(1), _repair_reply(2, 3))

    _run(client, tmp_path)

    original = client.calls[0].user_prompt
    repair = client.calls[2].user_prompt
    assert repair.startswith(original)
    assert REPAIR_OPENING not in _normalized(client.calls[1].user_prompt)
    request = _normalized(repair[len(original) :].split("Prior structured response")[0])
    assert REPAIR_OPENING in request
    assert "- RESP-2: Responsibility 2 serves the use case" in request
    assert "- RESP-3: Responsibility 3 serves the use case" in request
    assert "RESP-1" not in request
    assert repair.endswith(
        "Exact validation error from the prior response:\n"
        "ValueError: every responsibility requires a control action; "
        "missing owners: RESP-2, RESP-3\n\n"
        "Return one JSON object matching the response schema already supplied."
    )
    structure = repair.split("```json\n")[1].split("\n```")[0]
    assert json.loads(structure) == _reply(1)


def test_the_repair_is_the_next_attempt_of_the_step(tmp_path: Path) -> None:
    client = _client(_reply(1, 2), _reply(1, 2), _repair_reply(3))

    _run(client, tmp_path)

    rows = _attempts(tmp_path)
    assert [(row["step"], row["attempt_number"]) for row in rows] == [
        (STEP, 1),
        (STEP, 2),
        (STEP, 3),
    ]
    assert [row["success"] for row in rows] == [False, False, True]


def test_a_repair_reply_that_still_misses_an_owner_stops_the_unit(
    tmp_path: Path,
) -> None:
    client = _client(_reply(1), _reply(1), _repair_reply(2))

    with pytest.raises(StageError) as caught:
        _run(client, tmp_path)

    assert caught.value.step == STEP
    assert "missing owners: RESP-3" in str(caught.value)
    assert len(client.calls) == 3
    rows = _attempts(tmp_path)
    assert [row["attempt_number"] for row in rows] == [1, 2, 3]
    assert rows[2]["success"] is False
    assert "missing owners: RESP-3" in rows[2]["error"]


def test_the_repair_gets_no_second_request(tmp_path: Path) -> None:
    client = _client(_reply(1), _reply(1), _repair_reply(2), _repair_reply(2, 3))

    with pytest.raises(StageError):
        _run(client, tmp_path)

    assert len(client.calls) == 3


@pytest.mark.parametrize(
    "repair",
    [
        {"control_actions": []},
        {"control_actions": [_action(1)]},
        {"control_actions": [_action(3)], "feedback": []},
        "not json {",
        {"control_actions": [{**_action(3), "ca_id": "CA-9-1"}]},
        {
            "control_actions": [
                {**_action(3), "target": {"type": "responsibility", "id": "RESP-9"}}
            ]
        },
    ],
    ids=[
        "empty",
        "action-for-a-served-owner",
        "extra-collection",
        "undecodable",
        "unknown-owner",
        "unknown-target",
    ],
)
def test_a_repair_reply_outside_the_request_stops_the_unit(
    tmp_path: Path, repair: Any
) -> None:
    client = _client(_reply(1, 2), _reply(1, 2), repair)

    with pytest.raises(StageError):
        _run(client, tmp_path)

    assert len(client.calls) == 3
    assert _attempts(tmp_path)[2]["success"] is False


def test_a_failed_repair_names_itself_in_the_stage_error(tmp_path: Path) -> None:
    client = _client(_reply(1, 2), _reply(1, 2), _repair_reply(1))

    with pytest.raises(StageError) as caught:
        _run(client, tmp_path)

    assert "missing control action repair failed" in str(caught.value)


def test_a_repair_that_leaves_other_defects_still_stops_the_unit(
    tmp_path: Path,
) -> None:
    broken = _reply(1, 2)
    broken["feedback"] = broken["feedback"][:2]
    client = _client(broken, copy.deepcopy(broken), _repair_reply(3))

    with pytest.raises(StageError) as caught:
        _run(client, tmp_path)

    assert "process model part" in str(caught.value)
    assert len(client.calls) == 3


def test_a_reply_that_fails_the_same_schema_defect_twice_earns_no_repair(
    tmp_path: Path,
) -> None:
    client = _client(_bad_effect_reply(1, 2, 3), _bad_effect_reply(1, 2, 3))

    with pytest.raises(StageError):
        _run(client, tmp_path)

    assert len(client.calls) == 2
    assert all(
        call.response_format is not _MissingActionProviderSet for call in client.calls
    )


def test_a_reply_that_serves_every_owner_sends_no_repair(tmp_path: Path) -> None:
    client = _client(_reply(1, 2, 3))

    parsed = _run(client, tmp_path)

    assert len(parsed.control_actions) == 3
    assert len(client.calls) == 1
