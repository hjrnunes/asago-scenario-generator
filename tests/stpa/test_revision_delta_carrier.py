"""The revision delta carrier is checked before tolerant construction.

A malformed nested object gets one correction request naming its exact path,
and the baseline control structure survives when no valid delta arrives.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    _validate_revision_delta_carrier,
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
    "new_coordination_links[0]: coordination_link contains unknown field(s): cl_id"
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
            content=self.payloads[index],
            prompt_tokens=11,
            completion_tokens=7,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def test_unknown_nested_field_is_reported_with_its_collection_index() -> None:
    with pytest.raises(ValueError) as caught:
        _validate_revision_delta_carrier(_MALFORMED_LINK_DELTA)

    assert str(caught.value) == _MALFORMED_LINK_ERROR


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
    delta = {
        **_EMPTY_DELTA,
        "modified_responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Controller 1",
                "process_model_parts": [{"pm_id": "PM-1-1", "description": "State 1"}],
                "feedback_channels": [channel],
            }
        ],
    }

    _validate_revision_delta_carrier(delta)


@pytest.mark.parametrize(
    "payloads, warning",
    [
        ([_MALFORMED_LINK_DELTA, _EMPTY_DELTA], None),
        (
            [_MALFORMED_LINK_DELTA],
            f"Revision failed: ValueError: {_MALFORMED_LINK_ERROR}",
        ),
    ],
    ids=["corrected", "exhausted"],
)
def test_malformed_link_gets_one_correction_and_keeps_the_baseline(
    tmp_path: Path, payloads: list[Any], warning: str | None
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
    assert warnings == ([] if warning is None else [warning])
