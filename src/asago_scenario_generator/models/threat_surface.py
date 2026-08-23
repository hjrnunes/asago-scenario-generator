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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-23T04:10:41Z","module_hash":"7a49ec4871b25237ad803133fa412176abdac1cee69db1f18f1d4d55ca0e3bf5","source_sha256":"3336410d347349314670776784a7ce1303d7ab2af1d17df021e0c245ad0f5869","functions":[]}
# mutate4py-manifest-end
