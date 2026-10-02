"""Tests for the typed temporal execution constraint union (STPA-TEMPORAL).

Constraint references are namespace-bound, and the UCA outcome constraint
maps the control action and UCA type.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactorKind,
    TemporalAssertion,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.temporal_constraints import (
    DelayConstraint,
    UcaOutcomeConstraint,
    is_structural_reference,
)

UCA_TYPE = UCAType.wrong_timing


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
