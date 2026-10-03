"""Tests for the causal-factor kind-to-namespace map and source validation.

The map is the single canonical source for the control-structure
identifier prefix each factor kind must cite.  No caller hand-authors a
per-kind mapping.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    collect_source_ids,
    namespace_for,
    validate_factor_sources,
)
from tests.stpa.helpers import make_minimal_control_structure


class TestKindNamespaces:
    """Every kind maps to exactly one control-structure namespace prefix."""

    @pytest.mark.parametrize(
        ("kind", "namespace"),
        [
            (CausalFactorKind.process_model_flaw, "PM"),
            (CausalFactorKind.feedback_delay, "FB"),
            (CausalFactorKind.sensor_anomaly, "FB"),
            (CausalFactorKind.actuator_anomaly, "CA"),
        ],
    )
    def test_namespace_prefix_per_kind(self, kind, namespace):
        """The four kinds keep their PM, FB, FB, and CA prefixes."""
        assert namespace_for(kind) == namespace

    def test_every_kind_has_a_namespace(self):
        """No causal-factor kind is missing from the namespace map."""
        for kind in CausalFactorKind:
            assert namespace_for(kind)


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
                [CausalFactor(kind=kind, source_id=source_id, description="evidence")],
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
