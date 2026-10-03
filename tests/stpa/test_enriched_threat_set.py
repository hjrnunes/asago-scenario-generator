"""Tests for EnrichedThreatSet boundary schema validation.

Covers EnrichedThreatSet-01 through EnrichedThreatSet-08 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CatalogMapping,
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)


def _make_structural_threat(
    ica_slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    na_reconciliation_flag: bool = False,
    catalog_mappings: list[CatalogMapping] | None = None,
) -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=ica_slot_id,
        ica_text="Unsafe control action text",
        hazardous_context="Context",
        loss_scenario="Scenario",
        catalog_mappings=catalog_mappings or [],
        na_reconciliation_flag=na_reconciliation_flag,
    )


def _make_coverage_analysis(
    structural_coverage: dict | None = None,
    by_ica_type: dict[str, int] | None = None,
    by_controller: dict[str, int] | None = None,
    catalog_correspondence: dict | None = None,
    uncovered_owasp_threats: list[str] | None = None,
    uncovered_reason: str | None = None,
    structural_consideration: dict | None = None,
    na_quality: dict | None = None,
) -> CoverageAnalysis:
    return CoverageAnalysis(
        structural_coverage=structural_coverage
        or {"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
        by_ica_type=by_ica_type or {},
        by_controller=by_controller or {},
        catalog_correspondence=catalog_correspondence or {},
        uncovered_owasp_threats=uncovered_owasp_threats or [],
        uncovered_reason=uncovered_reason,
        structural_consideration=structural_consideration or {},
        na_quality=na_quality or {},
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

    def test_ets_02_threat_with_catalog_mapping_passes(self):
        """ETS-02: structural threat with catalog mapping passes."""
        ets = EnrichedThreatSet(
            structural_threats=[
                _make_structural_threat(
                    catalog_mappings=[
                        CatalogMapping(
                            catalog="OWASP_AGENTIC",
                            id="T2-T3",
                            name="Prompt injection",
                            confidence="high",
                        )
                    ]
                )
            ],
            coverage_analysis=_make_coverage_analysis(),
        )
        assert ets.structural_threats[0].catalog_mappings[0].id == "T2-T3"

    @pytest.mark.parametrize("confidence", ["high", "medium", "low"])
    def test_ets_03_catalog_mapping_confidence_levels(self, confidence):
        """ETS-03: all confidence levels are accepted."""
        mapping = CatalogMapping(
            catalog="OWASP_AGENTIC",
            id="T2-T3",
            name="Threat",
            confidence=confidence,
        )
        assert mapping.confidence == confidence

    def test_ets_04_na_reconciliation_flag_true_passes(self):
        """ETS-04: structural threat with na_reconciliation_flag true passes."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat(na_reconciliation_flag=True)],
            coverage_analysis=_make_coverage_analysis(),
        )
        assert ets.structural_threats[0].na_reconciliation_flag is True

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

    def test_ets_06_coverage_with_uncovered_owasp_threats(self):
        """ETS-06: coverage analysis with uncovered OWASP threats passes."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(
                uncovered_owasp_threats=["T10", "T15"],
                uncovered_reason="no structural slot matched",
            ),
        )
        assert ets.coverage_analysis.uncovered_owasp_threats == ["T10", "T15"]

    def test_ets_07_coverage_with_slot_level_eval_metrics(self):
        """ETS-07: coverage analysis with slot-level eval metrics passes."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(
                structural_consideration={
                    "total_slots": 10,
                    "considered": 8,
                    "rate": 0.8,
                },
                na_quality={
                    "na_count": 2,
                    "quality_count": 2,
                    "quality_rate": 1.0,
                },
            ),
        )
        assert ets.coverage_analysis.structural_consideration["rate"] == 0.8
        assert ets.coverage_analysis.na_quality["quality_rate"] == 1.0

    def test_ets_08_catalog_correspondence_with_zero_supplements(self):
        """ETS-08: catalog correspondence with catalog_only_supplements zero passes."""
        ets = EnrichedThreatSet(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(
                catalog_correspondence={
                    "structural_with_match": 8,
                    "structural_unmapped": 0,
                    "catalog_only_supplements": 0,
                }
            ),
        )
        assert (
            ets.coverage_analysis.catalog_correspondence["catalog_only_supplements"]
            == 0
        )
