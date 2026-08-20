"""Tests for the typed temporal execution constraint union (STPA-TEMPORAL).

Declared timing selects exactly one discriminated constraint variant with
canonical units, relevant fields only, and namespace-bound references.
Unknown timing yields ``constraint=None`` with ``requires_binding`` and
never invents behavior; runtime observations stay out of the projection.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
    CausalFactorKind,
    TemporalActionVector,
    TemporalAssertion,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.temporal_constraints import (
    AbsenceConstraint,
    DelayConstraint,
    DurationConstraint,
    OrderingConstraint,
    UcaOutcomeConstraint,
    WindowConstraint,
    is_structural_reference,
    parse_declared_timing,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    derive_temporal_action_vector,
)

UCA_TYPE = UCAType.wrong_timing


def _factor(kind: CausalFactorKind, source_id: str, timing: str | None = None):
    return CausalFactor(
        kind=kind,
        source_id=source_id,
        description=source_id,
        declared_timing=timing,
    )


class TestDeclaredTimingSelectsOneVariant:
    """STPA-TEMPORAL-01: declared timing maps to exactly one variant."""

    @pytest.mark.parametrize(
        ("source_id", "timing", "expected_type", "expected_unit", "expected_value"),
        [
            ("PM-1-1", "ordering before S-2", "ordering", "", ""),
            ("FB-1-1", "delay 250 milliseconds", "delay", "ms", "250"),
            ("CA-1-1", "duration 2 seconds", "duration", "s", "2"),
            ("FB-1-1", "window from 100 to 500 milliseconds", "window", "ms", "100-500"),
            ("CA-1-1", "absence until S-2", "absence", "", ""),
        ],
    )
    def test_vector_assertion_constraint_variant(
        self, source_id, timing, expected_type, expected_unit, expected_value
    ):
        """The derived assertion carries exactly the declared variant."""
        kind = {
            "PM-1-1": CausalFactorKind.process_model_flaw,
            "FB-1-1": CausalFactorKind.feedback_delay,
            "CA-1-1": CausalFactorKind.actuator_anomaly,
        }[source_id]
        vector = derive_temporal_action_vector(
            [_factor(kind, source_id, timing)],
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=UCA_TYPE,
        )
        assertion = vector.assertions[0]
        assert assertion.constraint is not None
        constraint = assertion.constraint
        assert constraint.type == expected_type
        assert assertion.requires_binding is False

        if expected_type == "ordering":
            assert constraint.ordering == "before"
            assert constraint.reference == "S-2"
        elif expected_type == "delay":
            assert constraint.delay_ms == 250
            assert constraint.reference == "FB-1-1"
        elif expected_type == "duration":
            assert constraint.duration_s == 2
            assert constraint.reference == "CA-1-1"
        elif expected_type == "window":
            assert constraint.window_from_ms == 100
            assert constraint.window_to_ms == 500
            assert constraint.reference == "FB-1-1"
        elif expected_type == "absence":
            assert constraint.reference == "S-2"

        dump = constraint.model_dump(mode="json")
        if expected_type == "delay":
            assert set(dump) == {"type", "delay_ms", "reference"}
        elif expected_type == "duration":
            assert set(dump) == {"type", "duration_s", "reference"}
        elif expected_type == "window":
            assert set(dump) == {"type", "window_from_ms", "window_to_ms", "reference"}
        elif expected_type == "ordering":
            assert set(dump) == {"type", "ordering", "reference"}
        elif expected_type == "absence":
            assert set(dump) == {"type", "reference"}

    def test_value_string_renders(self):
        """The canonical value can be rendered from the typed fields."""
        constraint = parse_declared_timing(
            "window from 100 to 500 milliseconds", "FB-1-1"
        )
        rendered = f"{constraint.window_from_ms}-{constraint.window_to_ms}"
        assert rendered == "100-500"


class TestCanonicalUnitNormalization:
    """STPA-TEMPORAL-02: numeric timing uses canonical ms/s units only."""

    def test_seconds_convert_to_canonical_ms_for_delay(self):
        """A declared 2-second delay normalizes to 2000 ms."""
        constraint = parse_declared_timing("delay 2 seconds", "FB-1-1")
        assert isinstance(constraint, DelayConstraint)
        assert constraint.delay_ms == 2000

    def test_milliseconds_convert_to_canonical_s_for_duration(self):
        """A declared 1000-millisecond duration normalizes to 1 s."""
        constraint = parse_declared_timing("duration 1000 milliseconds", "CA-1-1")
        assert isinstance(constraint, DurationConstraint)
        assert constraint.duration_s == 1

    def test_repeated_derivation_is_byte_identical(self):
        """Repeated derivation preserves values, units, and discriminators."""
        factors = [
            _factor(
                CausalFactorKind.feedback_delay, "FB-1-1", "delay 1000 milliseconds"
            ),
            _factor(
                CausalFactorKind.actuator_anomaly, "CA-1-1", "duration 2 seconds"
            ),
        ]
        first = derive_temporal_action_vector(
            factors, controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        second = derive_temporal_action_vector(
            factors, controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        assert first.model_dump(mode="json") == second.model_dump(mode="json")

    def test_constraint_is_typed_not_free_form_text(self):
        """The vector carries typed constraints, never raw timing prose."""
        vector = derive_temporal_action_vector(
            [_factor(CausalFactorKind.feedback_delay, "FB-1-1", "delay 250 milliseconds")],
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=UCA_TYPE,
        )
        dump = vector.model_dump(mode="json")
        assert "delay 250 milliseconds" not in str(dump)
        assert dump["assertions"][0]["constraint"]["delay_ms"] == 250


class TestUnknownTimingRequiresBinding:
    """STPA-TEMPORAL-03: unknown timing never invents a constraint."""

    def test_unknown_timing_yields_null_constraint_and_requires_binding(self):
        """Unknown timing keeps the predicate and demands explicit binding."""
        factor = _factor(
            CausalFactorKind.feedback_delay, "FB-1-1", timing="unknown"
        )
        vector = derive_temporal_action_vector(
            [factor], controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        assertion = vector.assertions[0]
        assert assertion.constraint is None
        assert assertion.requires_binding is True
        assert assertion.predicate.value == "FEEDBACK_DELAYED"
        assert assertion.source_id == "FB-1-1"

    def test_missing_timing_yields_null_constraint(self):
        """No declared timing is the same as unknown timing."""
        factor = _factor(CausalFactorKind.feedback_delay, "FB-1-1", timing=None)
        vector = derive_temporal_action_vector(
            [factor], controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        assertion = vector.assertions[0]
        assert assertion.constraint is None
        assert assertion.requires_binding is True

    def test_projection_invents_no_duration_delay_or_window(self):
        """The vector dump contains no guessed numeric timing."""
        factor = _factor(CausalFactorKind.feedback_delay, "FB-1-1", timing="unknown")
        vector = derive_temporal_action_vector(
            [factor], controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        dump = vector.model_dump(mode="json")
        assert dump["assertions"][0]["constraint"] is None
        for key in ("delay_ms", "duration_s", "window_from_ms", "window_to_ms"):
            assert key not in dump["assertions"][0]


class TestConstraintReferenceNamespaceBound:
    """STPA-TEMPORAL-04: constraint references are namespace-bound."""

    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            ("PM-1-1", True),
            ("FB-1-1", True),
            ("CA-1-1", True),
            ("S-2", True),
            ("H-1", False),
            ("runtime-1", False),
        ],
    )
    def test_reference_namespace_acceptance(self, reference, expected):
        """Only PM-/FB-/CA-/S-* references resolve."""
        assert is_structural_reference(reference) is expected

    @pytest.mark.parametrize("reference", ["H-1", "runtime-1"])
    def test_foreign_reference_fails_construction(self, reference):
        """A temporal assertion with a foreign reference fails validation."""
        with pytest.raises(ValidationError):
            TemporalAssertion(
                assertion_id="TA-1",
                order_index=0,
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                predicate="FEEDBACK_DELAYED",
                constraint=DelayConstraint(delay_ms=100, reference=reference),
            )

    @pytest.mark.parametrize(
        "reference",
        ["PM-1-1", "FB-1-1", "CA-1-1", "S-2"],
    )
    def test_accepted_reference_resolves(self, reference):
        """Accepted references construct a valid typed constraint."""
        constraint = DelayConstraint(delay_ms=100, reference=reference)
        assert constraint.reference == reference


class TestUcaOutcomeMapping:
    """STPA-TEMPORAL-05: the final UCA outcome mapping is explicit."""

    def test_vector_has_uca_constraint_for_final_outcome(self):
        """The derived vector maps the final UCA outcome explicitly."""
        vector = derive_temporal_action_vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ],
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=UCA_TYPE,
        )
        assert vector.uca_constraint is not None
        assert vector.uca_constraint.control_action_id == "CA-1-1"
        assert vector.uca_constraint.uca_type == UCA_TYPE

    def test_final_step_is_uca_step_for_ca_1_1(self):
        """The final scenario step remains the UCA step for CA-1-1."""
        vector = derive_temporal_action_vector(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ],
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=UCA_TYPE,
        )
        assert vector.steps[-1].kind.value == "UNSAFE_CONTROL_ACTION"
        assert vector.steps[-1].source_id == "CA-1-1"

    def test_empty_vector_has_no_uca_constraint(self):
        """Explicit empty factors produce no outcome mapping."""
        vector = derive_temporal_action_vector(
            [], controller_id="RESP-1", control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        assert vector.uca_constraint is None
        assert vector.assertions == []
        assert vector.steps == []

    def test_runtime_observations_absent_from_projection(self):
        """No observation or runtime field exists anywhere in the vector."""
        vector = derive_temporal_action_vector(
            [_factor(CausalFactorKind.feedback_delay, "FB-1-1")],
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=UCA_TYPE,
        )
        dump = vector.model_dump(mode="json")
        assert "runtime" not in dump
        assert "observation" not in dump


class TestUcaOutcomeConstraintModel:
    """The outcome mapping model is explicit and typed."""

    def test_maps_control_action_and_uca_type(self):
        """UcaOutcomeConstraint identifies CA-1-1 and WRONG_TIMING."""
        mapping = UcaOutcomeConstraint(
            control_action_id="CA-1-1", uca_type=UCA_TYPE
        )
        assert mapping.model_dump(mode="json") == {
            "type": "uca_outcome",
            "control_action_id": "CA-1-1",
            "uca_type": "WRONG_TIMING",
        }
