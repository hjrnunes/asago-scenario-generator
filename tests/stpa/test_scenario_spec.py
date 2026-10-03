"""Tests for ScenarioSpec boundary schema validation.

Covers ScenarioSpec-01 through ScenarioSpec-11 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    FeedbackChannel,
    ElementRef,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from tests.stpa.helpers import make_minimal_control_structure


def _make_control_structure(
    with_resp2: bool = False,
) -> ControlStructure:
    if not with_resp2:
        return make_minimal_control_structure()
    responsibilities = [
        Responsibility(
            resp_id="RESP-1",
            description="Controller 1",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="State 1"),
            ],
            control_actions=[
                ControlAction(ca_id="CA-1-1", description="Action 1"),
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="Feedback 1",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
    ]
    responsibilities.append(
        Responsibility(
            resp_id="RESP-2",
            description="Controller 2",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-2-1", description="State 2"),
            ],
            control_actions=[
                ControlAction(ca_id="CA-2-1", description="Action 2"),
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-2-1",
                    description="Feedback 2",
                    updates="PM-2-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                )
            ],
        )
    )
    return ControlStructure(responsibilities=responsibilities)


def _make_scenario_spec(
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
    belief_pm_id: str = "PM-1-1",
    desire_resp_id: str = "RESP-1",
    intention_ca_id: str = "CA-1-1",
    provenance: str = "structural",
    catalog_context: list[CatalogMapping] | None = None,
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance=provenance,
        ),
        target_controller=target_controller,
        target_control_action=target_control_action,
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id=belief_pm_id,
                    content="Believes X",
                    vulnerability="Vuln",
                )
            ],
            desires=[
                DefenderDesire(resp_id=desire_resp_id, content="Wants Y"),
            ],
            intentions=[
                DefenderIntention(ca_id=intention_ca_id, content="Intends Z"),
            ],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["Attacker believes"],
            desires=["Attacker wants"],
            intentions=["Attacker intends"],
        ),
        catalog_context=catalog_context or [],
        loss_scenario="Loss scenario text",
    )


class TestScenarioSpecValidation:
    """ScenarioSpec boundary schema validation rules."""

    def test_ss_01_valid_scenario_spec_passes(self):
        """SS-01: valid scenario spec passes validation."""
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        spec.validate_against(cs)

    def test_ss_02_belief_nonexistent_pm_fails(self):
        """SS-02: defender belief referencing non-existent PM fails."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(belief_pm_id="PM-99-1")
        with pytest.raises(ValueError, match="pm_id"):
            spec.validate_against(cs)

    def test_ss_03_desire_nonexistent_resp_fails(self):
        """SS-03: defender desire referencing non-existent RESP fails."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(desire_resp_id="RESP-99")
        with pytest.raises(ValueError, match="resp_id"):
            spec.validate_against(cs)

    def test_ss_04_intention_nonexistent_ca_fails(self):
        """SS-04: defender intention referencing non-existent CA fails."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(intention_ca_id="CA-99-1")
        with pytest.raises(ValueError, match="ca_id"):
            spec.validate_against(cs)

    def test_ss_05_target_controller_nonexistent_fails(self):
        """SS-05: target_controller referencing non-existent RESP fails."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(target_controller="RESP-99")
        with pytest.raises(ValueError, match="target_controller"):
            spec.validate_against(cs)

    def test_ss_06_target_control_action_nonexistent_fails(self):
        """SS-06: target_control_action referencing non-existent CA fails."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(target_control_action="CA-99-1")
        with pytest.raises(ValueError, match="target_control_action"):
            spec.validate_against(cs)

    def test_ss_07_target_ca_not_belonging_to_controller_fails(self):
        """SS-07: target_control_action not belonging to target_controller fails."""
        cs = _make_control_structure(with_resp2=True)
        spec = _make_scenario_spec(
            target_controller="RESP-1",
            target_control_action="CA-2-1",
        )
        with pytest.raises(ValueError, match="target_control_action"):
            spec.validate_against(cs)

    def test_ss_08_threat_source_structural_provenance_passes(self):
        """SS-08: threat source with structural provenance passes."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(provenance="structural")
        spec.validate_against(cs)

    def test_ss_09_threat_source_catalog_only_provenance_passes(self):
        """SS-09: threat source with catalog_only provenance passes."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(provenance="catalog_only")
        spec.validate_against(cs)

    def test_ss_10_attacker_bdi_free_form_strings_passes(self):
        """SS-10: attacker BDI with free-form strings passes."""
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        spec.attacker_bdi = AttackerBDI(
            beliefs=["attacker belief 1", "attacker belief 2"],
            desires=["attacker desire"],
            intentions=["attacker intention"],
        )
        spec.validate_against(cs)

    def test_ss_11_scenario_spec_with_catalog_context_passes(self):
        """SS-11: scenario spec with catalog context passes."""
        cs = _make_control_structure()
        spec = _make_scenario_spec(
            catalog_context=[
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T2-T3",
                    name="Prompt injection",
                    confidence="high",
                )
            ]
        )
        spec.validate_against(cs)
        assert spec.catalog_context[0].id == "T2-T3"
