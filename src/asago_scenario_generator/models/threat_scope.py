"""Threat-scope gating output contracts for taxonomy capability gating.

``data.threat_gating.determine_threat_scope`` produces these shapes and
``pipeline.threats`` consumes them to build the threat surface.  The
contracts live in the model layer so the gating logic and its pipeline
consumer depend on a stable shape rather than on each other's modules.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatScopeEntry(BaseModel):
    """A threat that is in scope for the assessed system."""

    threat_id: str = Field(description="Threat ID (e.g. 'T2')")
    threat_name: str = Field(description="Human-readable threat name")
    attack_pattern_ids: list[str] = Field(
        default_factory=list,
        description="Attack pattern IDs applicable to this system (e.g. ['AP-T2-01', 'AP-T2-03'])",
    )
    gating_reason: str = Field(
        description="Why this threat is in scope (e.g. 'always in scope', 'has_persistent_memory is true')",
    )


class OutOfScopeEntry(BaseModel):
    """A group of threats that are out of scope, with the reason."""

    threat_ids: list[str] = Field(description="Threat IDs that are out of scope")
    reason: str = Field(description="Why these threats are out of scope")


class ThreatScope(BaseModel):
    """The complete threat scope determination for a capability profile."""

    in_scope: list[ThreatScopeEntry] = Field(default_factory=list)
    out_of_scope: list[OutOfScopeEntry] = Field(default_factory=list)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-23T04:10:41Z","module_hash":"9d276a3e1e7efe5051d0541eb653c77419fe0748dc5e2765088e36061894c1a1","source_sha256":"23a9988df729047d057ef72cad57d8c5e625cafff6369a7e3a00bef31a903272","functions":[]}
# mutate4py-manifest-end
