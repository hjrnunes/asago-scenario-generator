"""Tests for the causal-factor models and the ``assemble_envelope`` entry point.

Covers causal-factor kinds and namespaces, and the unchanged
``assemble_envelope`` entry point.
"""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope


def _factor(
    kind: CausalFactorKind,
    source_id: str,
    description: str = "Factor",
) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=description)


class TestCausalFactorModels:
    """Causal factor mapping with stable source identifiers."""

    def test_ex01_causal_factors_map_kinds_and_sources(self):
        """EXEC-01: causal factors carry kind and stable source identifier."""
        factors = [
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ]
        assert factors[0].kind == CausalFactorKind.process_model_flaw
        assert factors[0].source_id == "PM-1-1"
        assert factors[1].kind == CausalFactorKind.feedback_delay
        assert factors[1].source_id == "FB-1-1"

    def test_ex02_factor_source_identifier_is_required(self):
        """EXEC-02: every causal factor needs a non-empty source identifier."""
        with pytest.raises(ValidationError):
            CausalFactor(
                kind=CausalFactorKind.sensor_anomaly, source_id="", description="x"
            )

    @pytest.mark.parametrize(
        ("kind", "source_id"),
        [
            (CausalFactorKind.process_model_flaw, "FB-1-1"),
            (CausalFactorKind.feedback_delay, "PM-1-1"),
            (CausalFactorKind.sensor_anomaly, "CA-1-1"),
            (CausalFactorKind.actuator_anomaly, "FB-1-1"),
        ],
    )
    def test_factor_kind_requires_matching_namespace(self, kind, source_id):
        """A factor cannot claim an identifier from another STPA namespace."""
        with pytest.raises(ValidationError, match="namespace"):
            _factor(kind, source_id)


class TestBackwardCompatibility:
    """Existing contracts remain unchanged when new inputs are omitted."""

    def test_assemble_envelope_unchanged(self):
        """assemble_envelope still assembles without execution inputs."""
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

        spec = ScenarioSpec(
            scenario_id="SCN-001",
            threat_source=ThreatSource(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                provenance="structural",
            ),
            target_controller="RESP-1",
            target_control_action="CA-1-1",
            ica_type=UCAType.not_provided,
            defender_bdi=DefenderBDI(
                beliefs=[
                    DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")
                ],
                desires=[DefenderDesire(resp_id="RESP-1", content="d")],
                intentions=[DefenderIntention(ca_id="CA-1-1", content="i")],
            ),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
            loss_scenario="loss",
        )
        gherkin = GherkinSpec(
            feature="F",
            scenario="S",
            given=[],
            when=[],
            then_expected=[],
            then_actual=[],
        )
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="N",
            attack_tree={},
            gherkin_spec=gherkin,
        )
        assert isinstance(envelope, ScenarioEnvelope)
        assert envelope.scenario_id == "SCN-001"
        assert envelope.system_context is None
        assert envelope.consumer_hints is None

