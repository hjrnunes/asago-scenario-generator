"""The revision delta is parsed by closed wire models before the merge.

A malformed nested object gets one correction request naming its exact path
in Pydantic's error format, IDs stay as written for normalization to repair,
and the baseline control structure survives when no valid delta arrives.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    _parse_revision_delta,
    run_revision,
)
from tests.helpers.revision_delta import _make_control_structure

_EMPTY_DELTA: dict[str, list[Any]] = {
    "new_responsibilities": [],
    "new_controlled_processes": [],
    "new_coordination_links": [],
    "modified_responsibilities": [],
    "dismissed_gaps": [],
}
# A captured provider failure: an unknown ``cl_id`` and no mechanism.
_MALFORMED_LINK_DELTA = {
    **_EMPTY_DELTA,
    "new_coordination_links": [{"cl_id": "CL-1", "description": "Missing mechanism"}],
}
_MALFORMED_LINK_ERROR = (
    "- new_coordination_links.0.cl_id: Extra inputs are not permitted (extra_forbidden)"
)


class _ScriptedProvider:
    model = "offline-revision-fixture"

    def __init__(self, payloads: list[Any]) -> None:
        self.payloads = payloads
        self.requests: list[dict[str, Any]] = []

    def complete(self, **kwargs: Any) -> LLMResult:
        index = min(len(self.requests), len(self.payloads) - 1)
        self.requests.append(kwargs)
        return LLMResult(
            content=json.dumps(self.payloads[index]),
            prompt_tokens=11,
            completion_tokens=7,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _responsibility(**fields: Any) -> dict[str, Any]:
    return {"resp_id": "RESP-1", "description": "Controller 1", **fields}


def _modified(**fields: Any) -> dict[str, Any]:
    return {**_EMPTY_DELTA, "modified_responsibilities": [_responsibility(**fields)]}


def test_unknown_nested_field_is_reported_at_its_path() -> None:
    with pytest.raises(ValidationError) as caught:
        _parse_revision_delta(_MALFORMED_LINK_DELTA)

    locations = [error["loc"] for error in caught.value.errors()]
    assert ("new_coordination_links", 0, "cl_id") in locations
    assert ("new_coordination_links", 0, "coordination_mechanism") in locations


@pytest.mark.parametrize(
    "delta, location",
    [
        ({**_EMPTY_DELTA, "": [True]}, ("",)),
        ({**_EMPTY_DELTA, "new_responsibilities": None}, ("new_responsibilities",)),
        (
            {**_EMPTY_DELTA, "new_responsibilities": [["RESP-5", "x"]]},
            ("new_responsibilities", 0),
        ),
        ({**_EMPTY_DELTA, "dismissed_gaps": [" "]}, ("dismissed_gaps", 0)),
        (
            _modified(feedback_channels=[{"fb_id": "FB-1-1", "description": "d"}]),
            ("modified_responsibilities", 0, "feedback_channels", 0, "updates"),
        ),
        (
            _modified(
                feedback_channels=[
                    {
                        "fb_id": "FB-1-1",
                        "description": "d",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                        "source_kind": "telepathy",
                    }
                ]
            ),
            ("modified_responsibilities", 0, "feedback_channels", 0, "source_kind"),
        ),
        (
            _modified(
                feedback_channels=[
                    {
                        "fb_id": "FB-1-1",
                        "description": "d",
                        "updates": "PM-1-1",
                        "source": {"id": "RESP-1", "source_kind": "user_message"},
                    }
                ]
            ),
            (
                "modified_responsibilities",
                0,
                "feedback_channels",
                0,
                "source",
                "source_kind",
            ),
        ),
        (
            _modified(control_actions=[{"ca_id": "CA-1-1", "description": "  "}]),
            ("modified_responsibilities", 0, "control_actions", 0, "description"),
        ),
        (
            {
                **_EMPTY_DELTA,
                "new_coordination_links": [
                    {
                        "link_id": "CL-1",
                        "source": "RESP-1",
                        "target": "RESP-2",
                        "shared_pm": "PM-1-1",
                        "coordination_mechanism": {"cm_id": "CM-1", "description": "d"},
                        "description": "d",
                    }
                ],
            },
            ("new_coordination_links", 0, "coordination_mechanism", "payload"),
        ),
    ],
    ids=[
        "unknown-top-level",
        "null-collection",
        "list-for-object",
        "blank-dismissal",
        "missing-updates",
        "unknown-source-kind",
        "unknown-ref-field",
        "blank-description",
        "missing-payload",
    ],
)
def test_malformed_carrier_is_rejected_at_its_path(
    delta: dict[str, Any], location: tuple[Any, ...]
) -> None:
    with pytest.raises(ValidationError) as caught:
        _parse_revision_delta(delta)

    assert location in [error["loc"] for error in caught.value.errors()]


@pytest.mark.parametrize("source", ["omitted", None], ids=["omitted", "null"])
def test_feedback_channel_without_a_source_is_a_valid_carrier(
    source: str | None,
) -> None:
    channel: dict[str, Any] = {
        "fb_id": "FB-1-2",
        "description": "Operator confirmation",
        "updates": "PM-1-1",
    }
    if source is None:
        channel["source"] = None

    delta = _parse_revision_delta(
        _modified(
            process_model_parts=[{"pm_id": "PM-1-1", "description": "State 1"}],
            feedback_channels=[channel],
        )
    )

    assert delta.modified_responsibilities[0].feedback_channels[0].source is None


def test_source_identifiers_stay_as_written_for_normalization() -> None:
    delta = _parse_revision_delta(
        {
            **_EMPTY_DELTA,
            "new_responsibilities": [
                {
                    "resp_id": "new-controller",
                    "description": "Review refunds",
                    "process_model_parts": [
                        {"pm_id": "PM-new", "description": "Refund state"}
                    ],
                }
            ],
            "new_controlled_processes": [
                {"cp_id": "CP-REFUNDS", "description": "Refund ledger"}
            ],
        }
    )

    assert delta.new_responsibilities[0].resp_id == "new-controller"
    assert delta.new_responsibilities[0].process_model_parts[0].pm_id == "PM-new"
    assert delta.new_controlled_processes[0].cp_id == "CP-REFUNDS"


def test_reference_type_and_effect_values_stay_as_written_for_assembly() -> None:
    delta = _parse_revision_delta(
        _modified(
            control_actions=[
                {
                    "ca_id": "CA-1-1",
                    "description": "Hand off",
                    "target": {"type": "agent_message", "id": "RESP-2"},
                    "effect_kind": "handoff",
                },
                {
                    "ca_id": "CA-1-2",
                    "description": "Message RESP-2",
                    "target": {"type": "responsibility", "id": "RESP-2"},
                    "effect_kind": "tool_call",
                },
            ],
            feedback_channels=[
                {
                    "fb_id": "FB-1-1",
                    "description": "User text",
                    "updates": "PM-1-1",
                    "source": {"type": "user_message", "id": "RESP-1"},
                }
            ],
        )
    )

    responsibility = delta.modified_responsibilities[0]
    assert responsibility.control_actions[0].target.type == "agent_message"
    assert responsibility.control_actions[0].effect_kind == "handoff"
    assert responsibility.control_actions[1].effect_kind == "tool_call"
    assert responsibility.feedback_channels[0].source.type == "user_message"


def test_a_text_where_an_object_belongs_is_corrected_without_a_class_name(
    tmp_path: Path,
) -> None:
    provider = _ScriptedProvider(
        [
            {
                **_EMPTY_DELTA,
                "new_responsibilities": ["RESP-5"],
                "modified_responsibilities": ["RESP-1"],
            },
            _EMPTY_DELTA,
        ]
    )

    run_revision(
        llm_client=provider,
        control_structure=_make_control_structure(),
        critic_findings=CriticFindings(),
        use_case_text="An offline controlled process",
        run_dir=tmp_path,
    )

    correction = provider.requests[1]["user_prompt"]
    assert (
        "- new_responsibilities.0: Input should be an object (model_type)" in correction
    )
    assert "- modified_responsibilities.0: Input should be an object (model_type)" in (
        correction
    )
    assert "_Revision" not in correction


@pytest.mark.parametrize(
    "payloads, failed",
    [
        ([_MALFORMED_LINK_DELTA, _EMPTY_DELTA], False),
        ([_MALFORMED_LINK_DELTA], True),
    ],
    ids=["corrected", "exhausted"],
)
def test_malformed_link_gets_one_correction_and_keeps_the_baseline(
    tmp_path: Path, payloads: list[Any], failed: bool
) -> None:
    baseline = _make_control_structure()
    provider = _ScriptedProvider(payloads)

    revised, warnings = run_revision(
        llm_client=provider,
        control_structure=baseline,
        critic_findings=CriticFindings(),
        use_case_text="An offline controlled process",
        run_dir=tmp_path,
    )

    assert len(provider.requests) == 2
    assert _MALFORMED_LINK_ERROR in provider.requests[1]["user_prompt"]
    assert revised == _make_control_structure()
    if not failed:
        assert warnings == []
        return
    assert warnings[0].startswith("Revision failed: ValidationError: ")
    assert warnings[1].startswith("Revision degraded: ")
