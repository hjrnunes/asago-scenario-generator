"""Tests for the post-SP3 STPA execution projection models.

Covers causal-factor kinds and namespaces, temporal assertion and vector
validation, and the unchanged ``assemble_envelope`` entry point.
"""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
    CausalFactorKind,
    TemporalActionVector,
    TemporalAssertion,
    TemporalPredicate,
    candidate_id_for,
    predicate_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing


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

    def test_predicate_mapping_is_canonical_per_kind(self):
        """Every factor kind maps to exactly one executable predicate."""
        assert (
            predicate_for(CausalFactorKind.process_model_flaw)
            is TemporalPredicate.model_flawed
        )
        assert (
            predicate_for(CausalFactorKind.feedback_delay)
            is TemporalPredicate.feedback_delayed
        )
        assert (
            predicate_for(CausalFactorKind.sensor_anomaly)
            is TemporalPredicate.sensor_anomalous
        )
        assert (
            predicate_for(CausalFactorKind.actuator_anomaly)
            is TemporalPredicate.actuator_anomalous
        )

class TestTemporalAssertionValidation:
    """Temporal assertion predicate consistency."""

    def test_predicate_must_match_kind(self):
        """An assertion whose predicate contradicts its kind is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            TemporalAssertion(
                assertion_id="TA-1",
                order_index=0,
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                predicate=TemporalPredicate.actuator_anomalous,
            )
        assert "inconsistent with kind" in str(exc_info.value)


class TestTemporalActionVectorValidation:
    """Canonical deterministic vector invariants."""

    def test_empty_vector_is_valid(self):
        """An empty causal factor set yields an empty vector."""
        vector = TemporalActionVector(
            candidate_id=candidate_id_for(CONTROLLER, CONTROL_ACTION, UCA_TYPE),
            control_action_id=CONTROL_ACTION,
        )
        assert vector.assertions == []
        assert vector.steps == []

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

