"""Tests for the neutral per-kind causal-factor registry.

The registry is the single canonical source for causal-factor behavior
(namespace, predicate, step kind, step text) consumed by the execution
envelope models, Stage 5/6 assembly, and narrative derivation.  No caller
hand-authors a per-kind mapping.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalPredicate,
    behavior_for,
    collect_source_ids,
    namespace_for,
    predicate_for,
    step_kind_for,
    step_text_for,
    validate_factor_sources,
)
from tests.stpa.helpers import make_minimal_control_structure

_PER_KIND = {
    CausalFactorKind.process_model_flaw: {
        "namespace": "PM",
        "predicate": TemporalPredicate.model_flawed,
        "step_kind": ScenarioStepKind.process_model_flaw,
    },
    CausalFactorKind.feedback_delay: {
        "namespace": "FB",
        "predicate": TemporalPredicate.feedback_delayed,
        "step_kind": ScenarioStepKind.feedback_delay,
    },
    CausalFactorKind.sensor_anomaly: {
        "namespace": "FB",
        "predicate": TemporalPredicate.sensor_anomalous,
        "step_kind": ScenarioStepKind.sensor_anomaly,
    },
    CausalFactorKind.actuator_anomaly: {
        "namespace": "CA",
        "predicate": TemporalPredicate.actuator_anomalous,
        "step_kind": ScenarioStepKind.actuator_anomaly,
    },
}


class TestCanonicalPerKindRegistry:
    """One registry entry per kind; every behavior lookup is canonical."""

    def test_every_kind_has_one_behavior_entry(self):
        """All four causal-factor kinds are covered by the registry."""
        for kind, expected in _PER_KIND.items():
            behavior = behavior_for(kind)
            assert behavior.namespace == expected["namespace"]
            assert behavior.predicate == expected["predicate"]
            assert behavior.step_kind == expected["step_kind"]
            assert "{source}" in behavior.step_text
            assert "{action}" in behavior.step_text

    def test_accessors_delegate_to_registry(self):
        """predicate_for/step_kind_for/namespace_for are registry reads."""
        kind = CausalFactorKind.feedback_delay
        assert predicate_for(kind) == _PER_KIND[kind]["predicate"]
        assert step_kind_for(kind) == _PER_KIND[kind]["step_kind"]
        assert namespace_for(kind) == _PER_KIND[kind]["namespace"]
        assert step_text_for(kind) == behavior_for(kind).step_text


class TestCausalFactorBoundarySchema:
    """CausalFactor carries kind, source, evidence, and optional timing."""

    def test_declared_timing_is_optional(self):
        """A factor without timing evidence remains valid."""
        factor = CausalFactor(
            kind=CausalFactorKind.process_model_flaw,
            source_id="PM-1-1",
            description="declared evidence",
        )
        assert factor.declared_timing is None

    def test_declared_timing_is_preserved(self):
        """Declared timing text is carried verbatim on the factor."""
        factor = CausalFactor(
            kind=CausalFactorKind.feedback_delay,
            source_id="FB-1-1",
            description="declared evidence",
            declared_timing="delay 250 milliseconds",
        )
        assert factor.declared_timing == "delay 250 milliseconds"

    def test_kind_requires_matching_namespace(self):
        """A PM factor cannot claim a CA source ID."""
        with pytest.raises(ValidationError):
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="CA-1-1",
                description="evidence",
            )


class TestFactorSourceValidationAgainstControlStructure:
    """validate_factor_sources checks existence, not just prefixes."""

    def test_known_sources_validate(self):
        """PM-1-1/FB-1-1/CA-1-1 factor sources validate against the structure."""
        validate_factor_sources(
            make_minimal_control_structure(),
            [
                CausalFactor(
                    kind=CausalFactorKind.process_model_flaw,
                    source_id="PM-1-1",
                    description="e",
                ),
                CausalFactor(
                    kind=CausalFactorKind.feedback_delay,
                    source_id="FB-1-1",
                    description="e",
                ),
                CausalFactor(
                    kind=CausalFactorKind.actuator_anomaly,
                    source_id="CA-1-1",
                    description="e",
                ),
            ],
        )

    @pytest.mark.parametrize(
        ("kind", "source_id"),
        [
            (CausalFactorKind.process_model_flaw, "PM-99-1"),
            (CausalFactorKind.feedback_delay, "FB-99-1"),
            (CausalFactorKind.sensor_anomaly, "FB-99-1"),
            (CausalFactorKind.actuator_anomaly, "CA-99-1"),
        ],
    )
    def test_unknown_source_fails_closed(self, kind, source_id):
        """A reference to an unknown ID is a causal-factor validation error."""
        with pytest.raises(ValueError) as excinfo:
            validate_factor_sources(
                make_minimal_control_structure(),
                [
                    CausalFactor(
                        kind=kind, source_id=source_id, description="evidence"
                    )
                ],
            )
        message = str(excinfo.value)
        assert "Causal factor" in message
        assert source_id in message
        assert "not a known" in message
        assert "control structure" in message

    def test_collect_source_ids_groups_by_namespace(self):
        """collect_source_ids maps each kind to its control-structure IDs."""
        source_ids = collect_source_ids(make_minimal_control_structure())
        assert source_ids[CausalFactorKind.process_model_flaw] == {"PM-1-1"}
        assert source_ids[CausalFactorKind.feedback_delay] == {"FB-1-1"}
        assert source_ids[CausalFactorKind.sensor_anomaly] == {"FB-1-1"}
        assert source_ids[CausalFactorKind.actuator_anomaly] == {"CA-1-1"}
