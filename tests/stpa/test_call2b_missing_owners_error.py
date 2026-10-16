"""The Call 2b post-check names every responsibility that has no control action."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.system_model.control_structure import (
    MissingControlActionsError,
    parse_control_element_set_response,
)
from tests.helpers.sp1_control_structure import _responsibilities


def _reply_serving_only_the_first() -> dict:
    return {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Deliver the result of responsibility 1",
                "target": {"type": "controlled_process", "id": "CP-1"},
                "effect_kind": "model_output",
                "temporality": "discrete",
            }
        ],
        "feedback": [
            {
                "fb_id": f"FB-{number}-1",
                "description": f"Report the state of responsibility {number}",
                "updates": f"PM-{number}-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            }
            for number in (1, 2, 3)
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Caller interface"}],
    }


def test_the_post_check_names_the_missing_owners() -> None:
    with pytest.raises(MissingControlActionsError) as caught:
        parse_control_element_set_response(
            _reply_serving_only_the_first(), responsibilities=_responsibilities()
        )

    assert caught.value.owners == (2, 3)
    assert str(caught.value) == (
        "every responsibility requires a control action; missing owners: RESP-2, RESP-3"
    )
    assert [process.cp_id for process in caught.value.controlled_processes] == ["CP-1"]


def test_the_typed_error_is_still_a_value_error() -> None:
    with pytest.raises(ValueError, match="missing owners: RESP-2, RESP-3"):
        parse_control_element_set_response(
            _reply_serving_only_the_first(), responsibilities=_responsibilities()
        )
