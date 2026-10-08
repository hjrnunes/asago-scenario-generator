"""Unit tests for SP3 Stage 6 envelope assembly."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from tests.helpers.scenario_deduplication import _scenario_spec


class TestAssembly:
    """Tests for ScenarioEnvelope assembly."""

    def test_assemble_envelope(self):
        spec = _scenario_spec()
        narrative = "A narrative text."
        attack_tree = {
            "root": "r",
            "branches": [{"category": "controller_side", "label": "l", "children": []}],
            "leaves": [],
        }
        gherkin_spec = GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        )
        gherkin_raw = "feature: Test\nscenario: Test\n"

        envelope = assemble_envelope(
            "SCN-001",
            spec,
            narrative,
            attack_tree,
            gherkin_spec,
            gherkin_raw,
        )
        assert envelope.scenario_id == "SCN-001"
        assert envelope.scenario_spec.scenario_id == "SCN-001"
        assert envelope.narrative == narrative
        assert envelope.attack_tree == attack_tree
        assert envelope.gherkin_spec == gherkin_spec
        assert envelope.gherkin_raw == gherkin_raw
        assert envelope.target_responsibility == "RESP-1"
        assert envelope.ica_type == UCAType.not_provided
        assert envelope.provenance == "structural"
