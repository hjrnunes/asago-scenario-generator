"""Contracts for the shared SP1 payload files that unit tests load."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    RequirementSet,
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.critic import CriticFindings
from tests.fixtures.sp1 import load_sp1_fixture

_VARIANTS = [
    ("stage1_profile", "default", Stage1Profile),
    ("requirement_set", "two_requirements", RequirementSet),
    ("requirement_set", "one_requirement", RequirementSet),
    ("responsibility_set", "two_responsibilities", ResponsibilitySet),
    ("responsibility_set", "one_responsibility", ResponsibilitySet),
    ("control_element_set", "with_controlled_process", ControlElementSet),
    ("control_element_set", "responsibility_only", ControlElementSet),
    ("critic_findings", "two_gaps", CriticFindings),
    ("critic_findings", "no_unjustified", CriticFindings),
    ("critic_findings", "no_gaps_all_present", CriticFindings),
    ("loss_analysis", "two_losses", LossAnalysis),
]


@pytest.mark.parametrize(("name", "variant", "model"), _VARIANTS)
def test_every_shared_payload_validates_against_its_model(name, variant, model):
    model.model_validate(load_sp1_fixture(name, variant))


def test_a_caller_may_edit_its_payload_without_changing_the_next_one():
    first = load_sp1_fixture("loss_analysis", "two_losses")
    first["hazards"].clear()

    assert load_sp1_fixture("loss_analysis", "two_losses")["hazards"]
