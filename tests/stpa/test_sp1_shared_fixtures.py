"""Contracts for the SP1 payload files that the unit and acceptance layers share."""

from __future__ import annotations

import sys
from pathlib import Path

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
from tests.stpa import sp1_helpers

_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_ROOT / "acceptance"))

import runtime_shared  # noqa: E402

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


def test_the_two_layers_load_the_same_files():
    assert (
        runtime_shared._sp1_valid_stage1_profile_dict()
        == sp1_helpers.valid_stage1_profile_dict()
    )
    assert [c.model_dump() for c in runtime_shared._sp1_make_risk_cards()] == [
        c.model_dump() for c in sp1_helpers.make_risk_cards()
    ]


def test_each_layer_keeps_the_loss_analysis_variant_its_dependents_need():
    acceptance = runtime_shared._sp1_valid_la_dict()
    unit = sp1_helpers.valid_loss_analysis_dict()

    assert [
        loss["loss_id"]
        for loss in acceptance["risk_card_losses"] + acceptance["use_case_losses"]
    ] == ["L-1", "L-2", "L-3"]
    assert [
        loss["loss_id"] for loss in unit["risk_card_losses"] + unit["use_case_losses"]
    ] == ["L-1", "L-2"]


def test_a_caller_may_edit_its_payload_without_changing_the_next_one():
    first = load_sp1_fixture("loss_analysis", "two_losses")
    first["hazards"].clear()

    assert load_sp1_fixture("loss_analysis", "two_losses")["hazards"]
