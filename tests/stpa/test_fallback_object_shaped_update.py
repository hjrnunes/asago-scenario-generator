"""The assembly fallback survives an object-shaped feedback ``updates`` value.

A live Call 2b response once wrote a feedback channel's ``updates`` as an
element reference object instead of a process-model ID.  Tolerant decoding
keeps the object, strict assembly then fails, and the fallback must drop the
channel instead of crashing.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlStructure,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _assemble_with_fallback,
)
from tests.fixtures.sp1 import load_sp1_fixture


def _assemble_with_object_update(tmp_path: Path) -> tuple[ControlStructure, list[str]]:
    elements = load_sp1_fixture("control_element_set", "with_controlled_process")
    elements["feedback_channels"][0]["updates"] = {
        "type": "responsibility",
        "id": "RESP-1",
    }
    return _assemble_with_fallback(
        ResponsibilitySet.model_validate(
            load_sp1_fixture("responsibility_set", "two_responsibilities")
        ),
        construct_model_unvalidated(elements, ControlElementSet),
        tmp_path,
        "test-model",
    )


def test_fallback_drops_an_object_shaped_feedback_update(tmp_path: Path) -> None:
    structure, warnings = _assemble_with_object_update(tmp_path)

    by_id = {resp.resp_id: resp for resp in structure.responsibilities}
    assert by_id["RESP-1"].feedback_channels == []
    assert [fb.fb_id for fb in by_id["RESP-2"].feedback_channels] == ["FB-2-1"]
    assert any("FB-1-1" in w and "updates" in w for w in warnings)


def test_fallback_derives_agent_message_for_an_action_on_a_responsibility(
    tmp_path: Path,
) -> None:
    structure, _ = _assemble_with_object_update(tmp_path)

    action = structure.responsibilities[1].control_actions[0]
    assert action.ca_id == "CA-2-1"
    assert action.effect_kind is ControlActionEffectKind.agent_message
