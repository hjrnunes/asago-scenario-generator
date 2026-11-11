"""EnrichedThreatSet boundary schema (Section 4.4 of the STPA-Sec foundation spec).

SP2 output, consumed by SP3.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


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


class CoverageAnalysis(BaseModel):
    """Coverage analysis metrics for the enriched threat set."""

    structural_coverage: dict = Field(
        description="total_slots, non_na, na, coverage_rate.",
    )
    by_ica_type: dict[str, int] = Field(default_factory=dict)
    by_controller: dict[str, int] = Field(default_factory=dict)


class EnrichedThreatSet(BaseModel):
    """Enriched threat set: structural threats + coverage analysis."""

    structural_threats: list[StructuralThreat]
    coverage_analysis: CoverageAnalysis
