"""The Call 2b request requires `controlled_processes` and `feedback`.

The provider schema lists both collections in `required`. A reply that still
leaves `controlled_processes` out (a server that does not enforce the schema)
keeps its route: the stage parser reads the absent key as no declared process,
so every `CP-*` reference is unknown, and the reference correction names the
omission within the step's three requests.

The client here is the real `LLMClient` with a mocked transport, so its own
local parse of the reply runs; no request leaves the process. The fixture is
the trimmed rerun of a recorded MiniKlarna run, whose three Call 2b replies
all omit `controlled_processes`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    _call_2b_control_elements,
    _ControlElementProviderSet,
    parse_responsibility_set_response,
)

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "stpa"
    / "call2b_omitted_processes_l3_klarna.json"
)
OMISSION = (
    "The prior response left out `controlled_processes` (or sent it empty), so "
    "it declares no controlled process."
)
UNDECLARED = (
    "Controlled processes referenced but not declared:\n- CP-1\n- CP-2\n- CP-4\n"
)


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def _client(replies: list[str]) -> LLMClient:
    client = LLMClient(
        base_url="http://test-endpoint.invalid", api_key="test-key", model="test-model"
    )
    client._client = MagicMock()
    client._client.chat.completions.create.side_effect = [
        SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=reply), finish_reason="stop"
                )
            ],
        )
        for reply in replies
    ]
    return client


def _run(client: LLMClient, tmp_path):
    return _call_2b_control_elements(
        llm_client=client,
        use_case_text="A neutralized payments assistant answers order questions.",
        responsibility_set=parse_responsibility_set_response(
            _fixture()["call_2a_reply"]
        ),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )


def _sent(client: LLMClient) -> list[dict]:
    return [
        call.kwargs for call in client._client.chat.completions.create.call_args_list
    ]


def _user_prompt(kwargs: dict) -> str:
    return next(m["content"] for m in kwargs["messages"] if m["role"] == "user")


def _echoed_reply(prompt: str) -> str:
    match = re.search(
        r"Prior structured response to correct in place:\n```json\n(.*?)\n```",
        prompt,
        re.S,
    )
    assert match is not None
    return match.group(1)


def _declaring(reply_text: str) -> str:
    reply = json.loads(reply_text)
    reply["controlled_processes"] = [
        {"cp_id": cp_id, "description": f"Neutralized controlled process {cp_id}"}
        for cp_id in ("CP-1", "CP-2", "CP-4")
    ]
    return json.dumps(reply)


def test_provider_schema_requires_processes_and_feedback() -> None:
    required = _ControlElementProviderSet.model_json_schema()["required"]

    assert {"control_actions", "feedback", "controlled_processes"} <= set(required)


def test_call_2b_request_requires_processes_and_feedback(tmp_path) -> None:
    texts = _fixture()["call_2b_reply_texts"]
    client = _client([_declaring(texts[0])])

    _run(client, tmp_path)

    (sent,) = _sent(client)
    schema = sent["response_format"]["json_schema"]["schema"]
    assert {"control_actions", "feedback", "controlled_processes"} <= set(
        schema["required"]
    )


def test_omitting_replies_reach_the_reference_correction_in_three_requests(
    tmp_path,
) -> None:
    texts = _fixture()["call_2b_reply_texts"]
    client = _client(texts)

    with pytest.raises(StageError, match="UnknownReferenceError"):
        _run(client, tmp_path)

    sent = _sent(client)
    assert len(sent) == 3
    generic, typed = _user_prompt(sent[1]), _user_prompt(sent[2])
    assert "UnknownReferenceError" in generic
    assert OMISSION not in " ".join(generic.split())
    assert OMISSION in " ".join(typed.split())
    assert UNDECLARED in typed
    # Each correction shows the reply as the model wrote it, without an empty
    # collection the reply never contained.
    for prompt, reply in ((generic, texts[0]), (typed, texts[1])):
        echoed = _echoed_reply(prompt)
        assert '"controlled_processes"' not in echoed
        assert json.loads(echoed) == json.loads(reply)


def test_omission_chain_succeeds_when_the_third_reply_declares_them(tmp_path) -> None:
    texts = _fixture()["call_2b_reply_texts"]
    client = _client([texts[0], texts[1], _declaring(texts[2])])

    parsed = _run(client, tmp_path)

    assert len(_sent(client)) == 3
    assert [item.cp_id for item in parsed.controlled_processes] == [
        "CP-1",
        "CP-2",
        "CP-4",
    ]
