"""Threat-surface output contracts for taxonomy threat-surface derivation.

These Pydantic shapes are shared inputs to deterministic taxonomy preparation
and obligation planning. Consumers import the shape from the model layer,
never from the derivation algorithm in ``pipeline.threats``.
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
