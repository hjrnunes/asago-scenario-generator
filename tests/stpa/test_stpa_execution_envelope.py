"""Tests for the post-SP3 STPA execution projection.

Covers STPA-EXEC-01 through STPA-EXEC-06 from the Gherkin feature file:
candidate execution envelope assembly, canonical traceability, temporal
assertions, sensor/actuator anomaly steps, envelope/vector linkage, and
the empty (no-invented-behavior) contract.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    ScenarioStep,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalAssertion,
    TemporalPredicate,
    candidate_id_for,
    predicate_for,
    step_kind_for,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
    assemble_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    derive_temporal_action_vector,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing


def _factor(
    kind: CausalFactorKind,
    source_id: str,
    description: str = "Factor",
) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=description)


def _vector(causal_factors: list[CausalFactor]) -> TemporalActionVector:
    return derive_temporal_action_vector(
        causal_factors,
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
    )


def _envelope(
    causal_factors: list[CausalFactor] | None = None,
    derive_temporal_vector: bool = False,
) -> CandidateExecutionEnvelope:
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=causal_factors,
        derive_temporal_vector=derive_temporal_vector,
    )


def _sources_of(steps: list[ScenarioStep]) -> list[str]:
    return [step.source_id for step in steps]


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

    def test_step_kind_mapping_is_canonical_per_kind(self):
        """Every factor kind maps to exactly one scenario step kind."""
        assert (
            step_kind_for(CausalFactorKind.process_model_flaw)
            is ScenarioStepKind.process_model_flaw
        )
        assert (
            step_kind_for(CausalFactorKind.feedback_delay)
            is ScenarioStepKind.feedback_delay
        )
        assert (
            step_kind_for(CausalFactorKind.sensor_anomaly)
            is ScenarioStepKind.sensor_anomaly
        )
        assert (
            step_kind_for(CausalFactorKind.actuator_anomaly)
            is ScenarioStepKind.actuator_anomaly
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

    def test_duplicate_assertion_id_rejected(self):
        """Duplicate assertion ids break canonical traceability."""
        vector = _vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        duplicated = vector.model_copy(
            update={
                "assertions": [
                    vector.assertions[0],
                    vector.assertions[0].model_copy(update={"source_id": "FB-1-1"}),
                ]
            }
        )
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(duplicated.model_dump())
        assert "duplicate assertion id" in str(exc_info.value)

    def test_order_index_must_be_dense(self):
        """Order indexes must equal the deterministic list positions."""
        vector = _vector([_factor(CausalFactorKind.feedback_delay, "FB-1-1")])
        broken = vector.model_dump()
        broken["assertions"][0]["order_index"] = 3
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(broken)
        assert "is not its deterministic position" in str(exc_info.value)

    def test_sequence_ids_must_be_canonical(self):
        """Sequence positions cannot be decoupled from their stable IDs."""
        vector = _vector([_factor(CausalFactorKind.feedback_delay, "FB-1-1")])
        broken = vector.model_dump()
        broken["assertions"][0]["assertion_id"] = "TA-9"
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(broken)
        assert "canonical identifier 'TA-1'" in str(exc_info.value)

    def test_vector_candidate_id_must_target_vector_action(self):
        """A vector cannot claim a different control action in its identity."""
        vector = _vector([_factor(CausalFactorKind.feedback_delay, "FB-1-1")])
        broken = vector.model_dump()
        broken["candidate_id"] = "EXEC:RESP-1:CA-9-9:WRONG_TIMING"
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(broken)
        assert "canonical" in str(exc_info.value)

    def test_vector_candidate_id_must_use_known_uca_type(self):
        """A vector identity cannot contain an unknown UCA type."""
        vector = _vector([_factor(CausalFactorKind.feedback_delay, "FB-1-1")])
        broken = vector.model_dump()
        broken["candidate_id"] = "EXEC:RESP-1:CA-1-1:NOT_A_UCA"
        with pytest.raises(ValidationError, match="unknown UCA type"):
            TemporalActionVector.model_validate(broken)

    def test_vector_candidate_id_must_name_controller(self):
        """A vector identity cannot omit its controller identifier."""
        vector = _vector([_factor(CausalFactorKind.feedback_delay, "FB-1-1")])
        broken = vector.model_dump()
        broken["candidate_id"] = "EXEC::CA-1-1:WRONG_TIMING"
        with pytest.raises(ValidationError, match="canonical"):
            TemporalActionVector.model_validate(broken)

    def test_vector_steps_must_be_reordered_by_canonical_sequence(self):
        """Scenario steps cannot be reordered while retaining their IDs."""
        vector = _vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        broken = vector.model_dump()
        broken["steps"][0], broken["steps"][1] = (
            broken["steps"][1],
            broken["steps"][0],
        )
        with pytest.raises(ValidationError, match="scenario step"):
            TemporalActionVector.model_validate(broken)

    def test_steps_must_end_with_unsafe_control_action(self):
        """Non-empty steps end with the UCA step for the targeted action."""
        vector = _vector([_factor(CausalFactorKind.sensor_anomaly, "FB-1-1")])
        truncated = vector.model_dump()
        truncated["steps"] = truncated["steps"][:-1]
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(truncated)
        assert "must end with the unsafe control action step" in str(exc_info.value)

    def test_uca_step_must_reference_target_action(self):
        """The final UCA step references the vector's control action."""
        vector = _vector([_factor(CausalFactorKind.actuator_anomaly, "CA-1-1")])
        broken = vector.model_dump()
        broken["steps"][-1]["source_id"] = "CA-9-9"
        with pytest.raises(ValidationError) as exc_info:
            TemporalActionVector.model_validate(broken)
        assert "vector targets" in str(exc_info.value)


class TestDeriveTemporalActionVector:
    """STPA-EXEC-03/04/06: deterministic temporal projection."""

    def test_ex03_two_factors_yield_two_executable_assertions(self):
        """EXEC-03: a flaw and a delay produce 2 executable assertions."""
        factors = [
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ]
        vector = _vector(factors)
        assert len(vector.assertions) == 2
        assert [a.predicate for a in vector.assertions] == [
            TemporalPredicate.model_flawed,
            TemporalPredicate.feedback_delayed,
        ]
        assert all(a.assertion_id and a.source_id for a in vector.assertions)

    def test_ex03_assertions_are_executable(self):
        """EXEC-03: every assertion carries an explicit predicate and order."""
        vector = _vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        for index, assertion in enumerate(vector.assertions):
            assert assertion.predicate in TemporalPredicate
            assert assertion.order_index == index

    def test_ex03_steps_follow_causal_factor_order(self):
        """EXEC-03: scenario steps follow the causal-factor order."""
        factors = [
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ]
        vector = _vector(factors)
        assert _sources_of(vector.steps)[:2] == ["PM-1-1", "FB-1-1"]
        assert vector.steps[-1].kind == ScenarioStepKind.unsafe_control_action

    def test_ex03_factor_steps_reference_factors_before_control_action(self):
        """EXEC-03: PM and FB steps appear before the CA step."""
        factors = [
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ]
        vector = _vector(factors)
        sources = _sources_of(vector.steps)
        assert sources.index("PM-1-1") < sources.index(CONTROL_ACTION)
        assert sources.index("FB-1-1") < sources.index(CONTROL_ACTION)

    def test_ex04_sensor_and_actuator_anomaly_steps(self):
        """EXEC-04: sensor and actuator anomalies produce typed steps."""
        factors = [
            _factor(CausalFactorKind.sensor_anomaly, "FB-1-1"),
            _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
        ]
        vector = _vector(factors)
        assert len(vector.assertions) == 2
        assert [step.kind for step in vector.steps[:2]] == [
            ScenarioStepKind.sensor_anomaly,
            ScenarioStepKind.actuator_anomaly,
        ]
        assert [step.source_id for step in vector.steps[:2]] == ["FB-1-1", "CA-1-1"]

    def test_ex04_every_step_has_deterministic_order(self):
        """EXEC-04: every scenario step has a deterministic order."""
        vector = _vector(
            [
                _factor(CausalFactorKind.sensor_anomaly, "FB-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ]
        )
        assert [step.order_index for step in vector.steps] == [0, 1, 2]
        assert [step.step_id for step in vector.steps] == ["S-1", "S-2", "S-3"]

    def test_ex06_no_factors_invent_nothing(self):
        """EXEC-06: no causal factors means no assertions and no steps."""
        vector = _vector([])
        assert vector.assertions == []
        assert vector.steps == []

    def test_vector_is_linked_to_canonical_candidate_id(self):
        """The derived vector carries the canonical candidate identifier."""
        vector = _vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ]
        )
        assert vector.candidate_id == candidate_id_for(
            CONTROLLER, CONTROL_ACTION, UCA_TYPE
        )
        assert vector.candidate_id == "EXEC:RESP-1:CA-1-1:WRONG_TIMING"

    def test_derivation_is_deterministic(self):
        """Identical inputs produce identical canonical representations."""
        factors = [
            _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
            _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
        ]
        first = _vector(factors).model_dump(mode="json")
        second = _vector(factors).model_dump(mode="json")
        assert first == second


class TestAssembleCandidateEnvelope:
    """STPA-EXEC-01/02/05: candidate execution envelope assembly."""

    def test_ex01_envelope_identifies_controller_and_control_action(self):
        """EXEC-01: the envelope identifies controller and control action."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        assert envelope.controller_id == "RESP-1"
        assert envelope.control_action_id == "CA-1-1"

    def test_ex01_envelope_retains_uca_type(self):
        """EXEC-01: the envelope retains the UCA type."""
        envelope = _envelope([_factor(CausalFactorKind.process_model_flaw, "PM-1-1")])
        assert envelope.uca_type == UCAType.wrong_timing

    def test_ex01_envelope_maps_causal_factors(self):
        """EXEC-01: the envelope maps the causal factors with sources."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        assert [f.source_id for f in envelope.causal_factors] == ["PM-1-1", "FB-1-1"]

    def test_ex01_envelope_is_platform_neutral(self):
        """EXEC-01: the envelope is structurally platform-neutral."""
        envelope = _envelope([])
        assert envelope.platform_neutral is True

    def test_ex02_envelope_has_canonical_candidate_identifier(self):
        """EXEC-02: the envelope has a canonical candidate identifier."""
        envelope = _envelope([_factor(CausalFactorKind.process_model_flaw, "PM-1-1")])
        assert envelope.candidate_id == candidate_id_for(
            CONTROLLER, CONTROL_ACTION, UCA_TYPE
        )

    def test_ex02_every_mapped_factor_has_source_identifier(self):
        """EXEC-02: every mapped causal factor has a source identifier."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        assert all(f.source_id for f in envelope.causal_factors)

    def test_ex02_envelope_links_uca_to_control_action(self):
        """EXEC-02: the envelope links the UCA to its control action."""
        envelope = _envelope([_factor(CausalFactorKind.process_model_flaw, "PM-1-1")])
        assert envelope.uca_ref == uca_ref_for(CONTROLLER, CONTROL_ACTION, UCA_TYPE)
        assert CONTROL_ACTION in envelope.uca_ref

    def test_ex05_envelope_contains_linked_temporal_vector(self):
        """EXEC-05: assembly with assertions links the vector to the candidate."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ],
            derive_temporal_vector=True,
        )
        assert envelope.temporal_vector is not None
        assert len(envelope.temporal_vector.assertions) == 2
        assert envelope.temporal_vector.candidate_id == envelope.candidate_id

    def test_ex05_envelope_retains_canonical_control_action_description(self):
        """EXEC-05: the envelope retains the canonical CA description."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ],
            derive_temporal_vector=True,
        )
        assert envelope.control_action_description == "Action"

    def test_no_vector_by_default(self):
        """Default assembly leaves the temporal vector absent."""
        envelope = _envelope([_factor(CausalFactorKind.process_model_flaw, "PM-1-1")])
        assert envelope.temporal_vector is None

    def test_unknown_controller_raises(self):
        """Assembly rejects an unknown controller identifier."""
        with pytest.raises(ValueError) as exc_info:
            assemble_candidate_envelope(
                make_minimal_control_structure(),
                controller_id="RESP-9",
                control_action_id=CONTROL_ACTION,
                uca_type=UCA_TYPE,
            )
        assert "RESP-9" in str(exc_info.value)

    def test_unknown_control_action_raises(self):
        """Assembly rejects an unknown control action identifier."""
        with pytest.raises(ValueError) as exc_info:
            assemble_candidate_envelope(
                make_minimal_control_structure(),
                controller_id=CONTROLLER,
                control_action_id="CA-9-9",
                uca_type=UCA_TYPE,
            )
        assert "CA-9-9" in str(exc_info.value)

    def test_unknown_factor_source_raises(self):
        """Assembly rejects causal factors outside the structural namespaces."""
        with pytest.raises(ValueError) as exc_info:
            _envelope([_factor(CausalFactorKind.sensor_anomaly, "PM-1-1")])
        assert "not a known FB identifier" in str(exc_info.value)

    def test_envelope_is_json_serializable(self):
        """The envelope round-trips through JSON without adapter payloads."""
        envelope = _envelope(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ],
            derive_temporal_vector=True,
        )
        payload = json.loads(envelope.model_dump_json())
        restored = CandidateExecutionEnvelope.model_validate(payload)
        assert restored == envelope

    def test_envelope_rejects_noncanonical_candidate_id(self):
        """Envelope identity must agree with its structural fields."""
        payload = _envelope([]).model_dump()
        payload["candidate_id"] = "EXEC:RESP-1:CA-1-1:NOT_PROVIDED"
        with pytest.raises(ValidationError, match="canonical candidate"):
            CandidateExecutionEnvelope.model_validate(payload)

    def test_envelope_rejects_noncanonical_uca_reference(self):
        """Envelope UCA references cannot point at another UCA."""
        payload = _envelope([]).model_dump()
        payload["uca_ref"] = "RESP-1:CA-1-1:NOT_PROVIDED"
        with pytest.raises(ValidationError, match="canonical UCA reference"):
            CandidateExecutionEnvelope.model_validate(payload)

    def test_envelope_rejects_vector_for_another_candidate(self):
        """Envelope and temporal vector must share candidate identity."""
        payload = _envelope([], derive_temporal_vector=True).model_dump()
        payload["temporal_vector"]["candidate_id"] = (
            "EXEC:RESP-2:CA-1-1:WRONG_TIMING"
        )
        with pytest.raises(ValidationError, match="temporal vector"):
            CandidateExecutionEnvelope.model_validate(payload)


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

    def test_new_inputs_are_optional(self):
        """assemble_candidate_envelope defaults do not require new inputs."""
        envelope = _envelope()
        assert envelope.causal_factors == []
        assert envelope.temporal_vector is None
