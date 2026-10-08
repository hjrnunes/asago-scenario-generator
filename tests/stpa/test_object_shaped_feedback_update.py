"""Assembly names an object-shaped feedback ``updates`` value.

A live Call 2b response once wrote a feedback channel's ``updates`` as an
element reference object instead of a process-model ID.  Tolerant decoding
keeps the object, strict assembly then fails, and the Stage 2 error must name
the channel and the value instead of crashing on the unhashable object.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _assemble_stage2_structure,
)
from tests.fixtures.sp1 import load_sp1_fixture


def test_assembly_names_an_object_shaped_feedback_update(tmp_path: Path) -> None:
    elements = load_sp1_fixture("control_element_set", "with_controlled_process")
    elements["feedback_channels"][0]["updates"] = {
        "type": "responsibility",
        "id": "RESP-1",
    }

    with pytest.raises(StageError) as exc_info:
        _assemble_stage2_structure(
            ResponsibilitySet.model_validate(
                load_sp1_fixture("responsibility_set", "two_responsibilities")
            ),
            construct_model_unvalidated(elements, ControlElementSet),
            tmp_path,
            "test-model",
        )

    assert exc_info.value.message == (
        "control structure failed validation; unresolved references: "
        "FeedbackChannel FB-1-1 updates {'type': 'responsibility', 'id': 'RESP-1'}"
    )
