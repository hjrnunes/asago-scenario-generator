"""Call 2b names its feedback collection ``feedback`` everywhere it crosses a boundary.

The request schema asks for ``feedback``.  The client decodes the reply into
the provider model, and the parser and the correction prompt then read that
decoded model.  They used to read it under the attribute name
``feedback_channels``, so the parser accepted two spellings and a correction
showed the model its own reply under a name the schema never offered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import _stringify_response_content
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _call_2b_control_elements,
    _ControlElementProviderSet,
    parse_control_element_set_response,
)
from tests.stpa.sp1_helpers import MockLLMClient


def _responsibilities() -> list[Responsibility]:
    return [
        Responsibility(
            resp_id="RESP-1",
            description="Responsibility 1 serves the use case",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
        )
    ]


def _reply() -> dict[str, Any]:
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Deliver the result",
                "target": {"type": "controlled_process", "id": "CP-1"},
                "effect_kind": "model_output",
                "temporality": "discrete",
                "operation": None,
                "process_model_refs": ["PM-1-1"],
            }
        ],
        "feedback": [
            {
                "fb_id": "FB-1-1",
                "description": "Report the state",
                "updates": "PM-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
                "source_kind": "operation_result",
            }
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Caller interface"}],
    }


def _legacy_spelling(reply: dict[str, Any]) -> dict[str, Any]:
    renamed = dict(reply)
    renamed["feedback_channels"] = renamed.pop("feedback")
    return renamed


def test_the_wire_rejects_the_historical_spelling() -> None:
    with pytest.raises(ValidationError, match="feedback"):
        parse_control_element_set_response(
            _legacy_spelling(_reply()), responsibilities=_responsibilities()
        )


def test_the_wire_rejects_a_reply_that_carries_both_spellings() -> None:
    both = {**_reply(), "feedback_channels": _reply()["feedback"]}

    with pytest.raises(ValidationError):
        parse_control_element_set_response(both, responsibilities=_responsibilities())


def test_a_decoded_provider_reply_parses() -> None:
    decoded = _ControlElementProviderSet.model_validate(_reply())

    parsed = parse_control_element_set_response(
        decoded, responsibilities=_responsibilities()
    )

    assert [channel.fb_id for channel in parsed.feedback_channels] == ["FB-1-1"]


def test_the_decoded_provider_reply_names_the_collection_feedback() -> None:
    decoded = _ControlElementProviderSet.model_validate(_reply())

    text = _stringify_response_content(decoded)

    assert '"feedback"' in text
    assert "feedback_channels" not in text


def test_the_provider_model_accepts_only_the_provider_spelling() -> None:
    with pytest.raises(ValidationError):
        _ControlElementProviderSet.model_validate(_legacy_spelling(_reply()))


def test_the_request_schema_is_unchanged() -> None:
    schema = _ControlElementProviderSet.model_json_schema()

    assert list(schema["properties"]) == [
        "control_actions",
        "feedback",
        "controlled_processes",
    ]
    assert schema["required"] == ["control_actions", "feedback", "controlled_processes"]
    assert schema["properties"]["feedback"]["title"] == "Feedback"


def test_the_domain_envelope_keeps_its_reader() -> None:
    parsed = parse_control_element_set_response(_reply())

    assert isinstance(parsed, ControlElementSet)
    assert [channel.fb_id for channel in parsed.feedback_channels] == ["FB-1-1"]


def test_a_correction_shows_the_prior_reply_under_the_name_the_schema_uses(
    tmp_path: Path,
) -> None:
    responsibilities = [
        Responsibility(
            resp_id="RESP-1",
            description="Responsibility 1 serves the use case",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="State"),
                ProcessModelPart(pm_id="PM-1-2", description="Other state"),
            ],
        )
    ]
    fixed = _reply()
    fixed["feedback"].append(
        {**fixed["feedback"][0], "fb_id": "FB-1-2", "updates": "PM-1-2"}
    )
    client = MockLLMClient()
    client.set_response_queue(
        [_ControlElementProviderSet.model_validate(_reply()), fixed]
    )

    _call_2b_control_elements(
        llm_client=client,
        use_case_text="Test use case",
        responsibility_set=ResponsibilitySet(responsibilities=responsibilities),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.4,
    )

    correction = client.calls[1].user_prompt
    assert len(client.calls) == 2
    assert '"feedback": [{"fb_id": "FB-1-1"' in correction
    assert "feedback_channels" not in correction
