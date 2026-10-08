"""Restructured Stage 1 and Stage 2 calls keep their retired outputs retired.

Call 2a emits responsibilities only, Call 3 returns coordination analysis
without the old connection set or its merge, Stage 1b leaves the boolean capability flags
to the derived profile, and the monolithic Call 2 templates stay deleted.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model import control_structure
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
    ResponsibilitySet,
)


@pytest.mark.parametrize(
    ("model", "field"),
    [
        (ResponsibilitySet, "control_actions"),
        (ResponsibilitySet, "feedback_channels"),
        (ResponsibilitySet, "controlled_processes"),
        (CoordinationAnalysis, "controlled_processes"),
        (CoordinationAnalysis, "connection_assignments"),
        (Stage1Profile, "has_persistent_memory"),
        (Stage1Profile, "multi_agent"),
        (Stage1Profile, "hitl"),
        (Stage1Profile, "zones_active"),
    ],
)
def test_retired_field_is_not_part_of_the_call_schema(
    model: type[BaseModel], field: str
) -> None:
    assert field not in model.model_fields
    assert field not in model.model_json_schema().get("properties", {})


@pytest.mark.parametrize("template", ["stage2_call2_system.j2", "stage2_call2_user.j2"])
def test_monolithic_call2_template_stays_deleted(template: str) -> None:
    assert not (PROMPTS_DIR / template).exists()


@pytest.mark.parametrize(
    "symbol", ["ConnectionSet", "merge_connection_set", "_merge_with_fallback"]
)
def test_call3_connection_set_merge_stays_removed(symbol: str) -> None:
    assert not hasattr(control_structure, symbol)
