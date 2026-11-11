"""Tests for EnrichedThreatSet boundary schema validation."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)


def _make_structural_threat(
    ica_slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
) -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=ica_slot_id,
        ica_text="Unsafe control action text",
        hazardous_context="Context",
        loss_scenario="Scenario",
    )


def _make_coverage_analysis(
    structural_coverage: dict | None = None,
    by_ica_type: dict[str, int] | None = None,
    by_controller: dict[str, int] | None = None,
) -> CoverageAnalysis:
    return CoverageAnalysis(
        structural_coverage=structural_coverage
        or {"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
        by_ica_type=by_ica_type or {},
        by_controller=by_controller or {},
    )


class TestEnrichedThreatSet:
    """EnrichedThreatSet boundary schema validation rules."""

    def test_ets_01_valid_threat_set_passes(self):
        """ETS-01: valid enriched threat set passes validation."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(),
        )
        assert ets is not None

    def test_ets_05_coverage_with_by_ica_type_and_by_controller(self):
        """ETS-05: coverage analysis with by_ica_type and by_controller passes."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(
                by_ica_type={"NOT_PROVIDED": 5, "INCORRECT": 3},
                by_controller={"RESP-1": 4, "RESP-2": 4},
            ),
        )
        assert ets.coverage_analysis.by_ica_type["NOT_PROVIDED"] == 5

    def test_a_threat_carries_no_catalog_labels(self):
        """A structural threat holds the ICA and its links, and no catalog label."""
        fields = set(StructuralThreat.model_fields)

        assert not {"catalog_mappings", "na_reconciliation_flag"} & fields
        assert set(CoverageAnalysis.model_fields) == {
            "structural_coverage",
            "by_ica_type",
            "by_controller",
        }
