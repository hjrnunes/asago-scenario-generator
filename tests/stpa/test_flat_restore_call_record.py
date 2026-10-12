"""The call record lists the drops the flat-reply restore made for the reply."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    decode_content,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.provider_call_record import (
    _Answer,
    _client,
    _completion,
    _Provider,
)

_ROUTING = _routing_provider_payload_type(1)
_IDS = (
    "controller_ids",
    "control_action_ids",
    "responsibility_ids",
    "process_model_part_ids",
    "feedback_channel_ids",
    "controlled_process_ids",
    "coordination_link_ids",
)


def _flat_route(**changes: Any) -> dict[str, Any]:
    route: dict[str, Any] = {
        "obligation_id": "ob:v1:" + "0" * 64,
        "semantic_assessment": {
            "mechanism_assessment": "plausible_in_system",
            "risk_alignment": "supported",
            "mechanism_rationale": "The path exists.",
            "risk_alignment_rationale": "It realizes the risk.",
        },
        "rationale": "Why this disposition.",
        "evidence": ["RESP-1 handles refunds."],
        "disposition": "targeted",
        "slot_ids": ["RESP-1:CA-1-1:NOT_PROVIDED"],
        **dict.fromkeys(_IDS, []),
        "hazard_ids": ["H-1"],
        "constraint_ids": ["SC-1"],
        "missing_concepts": None,
    }
    route.update(changes)
    return route


def _call(tmp_path: Path, route: dict[str, Any], **options: Any) -> Any:
    text = json.dumps({"routes": [route]})
    provider = _Provider(lambda **_: _completion(text))
    return call_with_policy(
        llm_client=_client(provider),
        system_prompt="s",
        user_prompt="u",
        response_format=_ROUTING,
        run_dir=tmp_path,
        stage="stage_x",
        step="route",
        policy=CorrectionPolicy(),
        **options,
    )


def _parse_routing(result: LLMResult, _cleanup: list[dict[str, Any]]) -> Any:
    return _ROUTING.model_validate(decode_content(result))


_DROPPED = [
    {
        "path": "/routes/0/controller_ids",
        "branch": "targeted",
        "reason": "null_to_default",
    },
    {
        "path": "/routes/0/missing_concepts",
        "branch": "targeted",
        "reason": "foreign_value",
    },
]


def test_a_successful_call_records_its_drops(tmp_path: Path) -> None:
    route = _flat_route(controller_ids=None, missing_concepts=[])
    outcome = _call(tmp_path, route)

    assert outcome.error is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["success"] is True
    assert entry["flat_restore_drops"] == _DROPPED
    assert json.loads(entry["raw_response"])["routes"][0]["missing_concepts"] == []


def test_a_stage_parser_call_records_its_drops(tmp_path: Path) -> None:
    route = _flat_route(controller_ids=None, missing_concepts=[])
    outcome = _call(tmp_path, route, response_parser=_parse_routing)

    assert outcome.error is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["flat_restore_drops"] == _DROPPED


def test_a_failed_call_records_the_drops_made_before_it_failed(
    tmp_path: Path,
) -> None:
    outcome = _call(tmp_path, _flat_route(slot_ids=None, missing_concepts=["x"]))

    assert outcome.value is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["success"] is False
    assert entry["flat_restore_drops"] == [
        {
            "path": "/routes/0/slot_ids",
            "branch": "targeted",
            "reason": "null_to_default",
        },
        {
            "path": "/routes/0/missing_concepts",
            "branch": "targeted",
            "reason": "foreign_value",
        },
    ]


def test_a_reply_in_flat_form_records_no_drop(tmp_path: Path) -> None:
    outcome = _call(tmp_path, _flat_route())

    assert outcome.error is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["flat_restore_drops"] == []


def test_a_response_type_without_unions_records_no_drop(tmp_path: Path) -> None:
    provider = _Provider(lambda **_: _completion('{"answer": "42"}'))
    call_with_policy(
        llm_client=_client(provider),
        system_prompt="s",
        user_prompt="u",
        response_format=_Answer,
        run_dir=tmp_path,
        stage="stage_x",
        step="answer",
        policy=CorrectionPolicy(),
    )

    [entry] = read_calls_jsonl(tmp_path)
    assert entry["flat_restore_drops"] == []


def test_an_undecodable_reply_records_no_drop(tmp_path: Path) -> None:
    provider = _Provider(lambda **_: _completion("not json"))
    outcome = call_with_policy(
        llm_client=_client(provider),
        system_prompt="s",
        user_prompt="u",
        response_format=_ROUTING,
        run_dir=tmp_path,
        stage="stage_x",
        step="route",
        policy=CorrectionPolicy(),
    )

    assert outcome.value is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["flat_restore_drops"] == []
