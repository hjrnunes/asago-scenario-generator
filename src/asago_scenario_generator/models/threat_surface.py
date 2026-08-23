"""Threat-surface output contracts for taxonomy threat-surface derivation.

These Pydantic shapes are the persisted and resumed artifact of Stage 2:
``pipeline.io.write_threat_surface`` serialises them to
``threat-surface.yaml`` and ``pipeline.runner`` reconstructs them from
disk with ``ThreatSurface.model_validate``.  Consumers of the shape
therefore import it from the model layer, never from the derivation
algorithm in ``pipeline.threats``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from asago_scenario_generator.models.scenario import RiskCardRef


class ThreatSurfaceEntry(BaseModel):
    """One risk card's resolved threat-surface membership."""

    risk_card: RiskCardRef
    owasp_llm_ids: list[str]
    agentic_threat_ids: list[str]
    atlas_technique_ids: list[str] = Field(default_factory=list)
    attack_pattern_ids: list[str] = Field(default_factory=list)
    owasp_asi_ids: list[str] = Field(default_factory=list)
    governance_only: bool = False


class ThreatSurface(BaseModel):
    """The complete threat surface for a capability profile."""

    entries: list[ThreatSurfaceEntry]
    governance_only: list[ThreatSurfaceEntry]
