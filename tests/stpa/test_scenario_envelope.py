"""Tests for ScenarioEnvelope boundary schema validation.

Covers ScenarioEnvelope-01 through ScenarioEnvelope-04 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)


def _make_scenario_spec(scenario_id: str = "SCN-001") -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id="PM-1-1", content="Belief", vulnerability="Vuln")
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Scenario",
    )


def _make_envelope(
    scenario_id: str = "SCN-001",
    spec: ScenarioSpec | None = None,
    target_responsibility: str = "RESP-1",
    ica_type: UCAType = UCAType.not_provided,
    provenance: str = "structural",
    catalog_mappings: list[CatalogMapping] | None = None,
) -> ScenarioEnvelope:
    return ScenarioEnvelope(
        scenario_id=scenario_id,
        scenario_spec=spec or _make_scenario_spec(scenario_id),
        narrative="Narrative text",
        attack_tree={"root": {"children": []}},
        gherkin_spec=GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given ..."],
            when=["When ..."],
            then_expected=["Then should ..."],
            then_actual=["But ..."],
        ),
        target_responsibility=target_responsibility,
        ica_type=ica_type,
        catalog_mappings=catalog_mappings or [],
        provenance=provenance,
    )


class TestScenarioEnvelope:
    """ScenarioEnvelope wrapping and faceting metadata."""

    def test_se_01_valid_envelope_passes(self):
        """SE-01: valid envelope with all artifacts passes validation."""
        envelope = _make_envelope()
        assert envelope is not None
        assert envelope.narrative == "Narrative text"

    def test_se_02_envelope_scenario_id_matches_spec(self):
        """SE-02: envelope scenario_id matches spec scenario_id."""
        envelope = _make_envelope(scenario_id="SCN-001")
        assert envelope.scenario_id == envelope.scenario_spec.scenario_id

    def test_se_02b_envelope_scenario_id_mismatch_fails(self):
        """SE-02b: envelope scenario_id mismatching spec fails."""
        with pytest.raises(ValidationError) as exc_info:
            _make_envelope(
                scenario_id="SCN-002",
                spec=_make_scenario_spec("SCN-001"),
            )
        assert "scenario_id" in str(exc_info.value)

    def test_se_03_faceting_metadata_derived_from_spec(self):
        """SE-03: envelope faceting metadata derived from spec."""
        envelope = _make_envelope(
            target_responsibility="RESP-1",
            ica_type=UCAType.not_provided,
            provenance="structural",
        )
        assert envelope.target_responsibility == "RESP-1"
        assert envelope.ica_type == UCAType.not_provided
        assert envelope.provenance == "structural"

    def test_se_04_envelope_with_catalog_mappings_passes(self):
        """SE-04: envelope with catalog mappings in faceting passes."""
        envelope = _make_envelope(
            catalog_mappings=[
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T2-T3",
                    name="Prompt injection",
                    confidence="high",
                )
            ]
        )
        assert len(envelope.catalog_mappings) == 1
        assert envelope.catalog_mappings[0].id == "T2-T3"
