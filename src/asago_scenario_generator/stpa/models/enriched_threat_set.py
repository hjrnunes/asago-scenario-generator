"""EnrichedThreatSet boundary schema (Section 4.4 of the STPA-Sec foundation spec).

SP2 output, consumed by SP3.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CatalogMapping(BaseModel):
    """A mapping from a structural threat to a catalog entry."""

    catalog: str  # "OWASP_AGENTIC", "ATLAS", "OWASP_ASI"
    id: str  # catalog-specific ID
    name: str
    confidence: Literal["high", "medium", "low"]


class StructuralThreat(BaseModel):
    """A structural threat derived from ICA enumeration."""

    ica_slot_id: str
    provenance: Literal["structural"] = "structural"
    ica_id: str | None = None
    ica_text: str
    hazardous_context: str
    loss_scenario: str
    related_hazards: list[str] = Field(default_factory=list)
    related_constraints: list[str] = Field(default_factory=list)
    catalog_mappings: list[CatalogMapping] = Field(default_factory=list)
    na_reconciliation_flag: bool = False


class CoverageAnalysis(BaseModel):
    """Coverage analysis metrics for the enriched threat set."""

    structural_coverage: dict = Field(
        description="total_slots, non_na, na, coverage_rate.",
    )
    by_ica_type: dict[str, int] = Field(default_factory=dict)
    by_controller: dict[str, int] = Field(default_factory=dict)
    catalog_correspondence: dict = Field(
        default_factory=dict,
        description="structural_with_match, structural_unmapped, catalog_only_supplements.",
    )
    na_reconciliation_flags: list[str] = Field(default_factory=list)
    uncovered_owasp_threats: list[str] = Field(default_factory=list)
    uncovered_reason: str | None = None
    # Slot-level eval metrics (computed by SP2, consumed by SP3)
    structural_consideration: dict = Field(
        default_factory=dict,
        description="total_slots, considered, rate, by_ica_type, by_responsibility.",
    )
    na_quality: dict = Field(
        default_factory=dict,
        description="na_count, quality_count, quality_rate.",
    )


class EnrichedThreatSet(BaseModel):
    """Enriched threat set: structural threats + coverage analysis."""

    structural_threats: list[StructuralThreat]
    coverage_analysis: CoverageAnalysis
