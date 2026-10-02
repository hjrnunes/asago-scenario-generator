"""Stage 3: Deterministic Scenario Seed Expansion.

Enumerates all attack patterns from the in-scope threat surface entries,
producing one ScenarioSeed per AP-* pattern with full provenance.
"""

from __future__ import annotations


from pydantic import BaseModel, Field

from asago_scenario_generator.models.scenario import RiskCardRef


class ScenarioSeed(BaseModel):
    seed_id: str = Field(description="Attack pattern ID, e.g. 'AP-T7-01'.")
    threat_id: str = Field(description="Parent threat ID, e.g. 'T7'.")
    threat_name: str
    threat_description: str = ""
    attack_pattern_name: str
    attack_pattern_description: str
    risk_card_ref: RiskCardRef
    contributing_risk_cards: list[RiskCardRef] = Field(
        default_factory=list,
        description="All risk cards that contributed to this seed (including the primary).",
    )
    owasp_llm_ids: list[str]
    agentic_threat_ids: list[str]
    atlas_technique_ids: list[str] = Field(default_factory=list)
    owasp_asi_ids: list[str] = Field(default_factory=list)
    # SSSOM provenance fields (populated from attack-pattern provenance)
    owasp_origin: str | None = None
    laaf_technique_ids: list[str] = Field(default_factory=list)
    atlas_provenance_ids: list[str] = Field(default_factory=list)
    # Seed-level constraints (populated from attack-pattern YAML)
    min_complexity: str | None = Field(
        default=None,
        description=(
            "Minimum actor capability level for this seed. "
            "One of 'novice', 'intermediate', 'advanced', 'expert'. "
            "When set, actors below this level are bumped up."
        ),
    )
    required_capabilities: list[str] | None = Field(
        default=None,
        description=(
            "Capability requirements for this seed, e.g. 'multi_agent', "
            "'persistent_memory', 'tool_execution'. When set, seeds are "
            "rejected during candidate filtering if the profile does not "
            "meet the requirements."
        ),
    )
    kill_chain: list[dict] | None = Field(
        default=None,
        description="Kill chain scaffold from attack pattern, if available.",
    )
