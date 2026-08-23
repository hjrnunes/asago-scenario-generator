"""Stage 3: Deterministic Scenario Seed Expansion.

Enumerates all attack patterns from the in-scope threat surface entries,
producing one ScenarioSeed per AP-* pattern with full provenance.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from asago_scenario_generator.data.loaders import (
    build_pattern_provenance_index,
    load_agentic_threats,
    load_attack_pattern_provenance,
    load_attack_patterns,
)
from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.models.scenario import RiskCardRef

_DEFAULT_THREATS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


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


_KCX_TO_CAPABILITY: dict[str, list[str]] = {
    "KCX-MAGENT": ["multi_agent"],
    "KCX-PMEM": ["persistent_memory"],
    "KCX-SHMEM": ["multi_agent", "persistent_memory"],
    "KCX-VSTORE": ["persistent_memory"],
    "KCX-HITL": ["hitl"],
    "KCX-AUDIT": ["audit"],
    "KCX-PSTATE": ["persistent_state"],
}


def _extract_seed_constraints(
    pattern: dict,
) -> tuple[str | None, list[str] | None]:
    """Extract min_complexity and required_capabilities from a pattern dict.

    Reads ``prerequisite_capabilities`` from the attack-pattern YAML and maps
    KCX sub-codes in ``kc_requires`` to a list of capability requirement
    strings.  Also reads the top-level ``min_complexity`` field if present.

    Returns:
        (min_complexity, required_capabilities) — either may be None.
    """
    min_complexity: str | None = pattern.get("min_complexity")
    prereqs = pattern.get("prerequisite_capabilities") or {}

    kc_req = prereqs.get("kc_requires") or {}
    all_kcs = set(kc_req.get("all", []))

    caps: list[str] = []
    for kcx, capability_strings in _KCX_TO_CAPABILITY.items():
        if kcx in all_kcs:
            caps.extend(capability_strings)

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for c in caps:
        if c not in seen:
            seen.add(c)
            deduped.append(c)

    return min_complexity, deduped if deduped else None


def expand_seeds(
    threat_surface: ThreatSurface,
    threats_path: str | Path | None = None,
    attack_patterns_path: str | Path | None = None,
) -> list[ScenarioSeed]:
    """Expand threat surface entries into individual scenario seeds.

    Iterates AP-* attack pattern IDs directly from the threat surface,
    looking up pattern metadata (name, description) from the AP-* YAML.

    Args:
        threat_surface: Output from Stage 2.
        threats_path: Optional path to OWASP agentic threats YAML.
        attack_patterns_path: Optional path to abstract attack patterns YAML.

    Returns:
        List of ScenarioSeed, one per in-scope attack pattern.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)

    # Load abstract attack patterns
    patterns = load_attack_patterns(attack_patterns_path)

    # Build SSSOM provenance index for LAAF and ATLAS lookups
    prov_index: dict[str, dict[str, list[str]]] = {}
    try:
        prov_mappings = load_attack_pattern_provenance()
        prov_index = build_pattern_provenance_index(prov_mappings)
    except FileNotFoundError:
        pass

    seen: dict[str, ScenarioSeed] = {}

    for entry in threat_surface.entries:
        if entry.governance_only:
            continue

        for ap_id in entry.attack_pattern_ids:
            pattern = patterns.get(ap_id)
            if pattern is None:
                continue

            threat_id = pattern["threat_id"]
            threat = threats.get(threat_id)
            threat_name = threat["name"] if threat else ""
            threat_description = threat.get("description", "").strip() if threat else ""

            attack_pattern_name = pattern["name"]
            attack_pattern_desc = pattern["description"].strip()
            kill_chain = pattern.get("kill_chain")

            # Extract SSSOM provenance for this pattern
            pattern_prov = prov_index.get(ap_id, {})
            prov_owasp_ids = pattern_prov.get("owasp-agentic", [])
            prov_laaf_ids = pattern_prov.get("laaf", [])
            prov_atlas_ids = pattern_prov.get("mitre-atlas", [])

            # Extract seed-level constraints from YAML
            seed_min_complexity, seed_required_caps = _extract_seed_constraints(pattern)

            if ap_id in seen:
                # Merge: union taxonomy IDs, collect contributing risk cards
                existing = seen[ap_id]
                merged_owasp = list(
                    dict.fromkeys(existing.owasp_llm_ids + entry.owasp_llm_ids)
                )
                merged_agentic = list(
                    dict.fromkeys(
                        existing.agentic_threat_ids + entry.agentic_threat_ids
                    )
                )
                # Add the new risk card to contributing list (dedup by risk_id)
                known_ids = {r.risk_id for r in existing.contributing_risk_cards}
                new_contribs = list(existing.contributing_risk_cards)
                if entry.risk_card.risk_id not in known_ids:
                    new_contribs.append(entry.risk_card)

                # Filter this entry's ATLAS provenance against zone-3 gating
                # (entry.atlas_technique_ids is the broad risk-level pool)
                atlas_pool_set = set(entry.atlas_technique_ids)
                filtered_atlas_prov = [
                    aid for aid in prov_atlas_ids if aid in atlas_pool_set
                ]

                # atlas_technique_ids = union of curated provenance across
                # contributing risk cards (not the broad risk-level pool)
                merged_prov = list(
                    dict.fromkeys(existing.atlas_technique_ids + filtered_atlas_prov)
                )

                merged_asi = list(
                    dict.fromkeys(existing.owasp_asi_ids + entry.owasp_asi_ids)
                )

                seen[ap_id] = existing.model_copy(
                    update={
                        "owasp_llm_ids": merged_owasp,
                        "agentic_threat_ids": merged_agentic,
                        "atlas_technique_ids": merged_prov,
                        "owasp_asi_ids": merged_asi,
                        "contributing_risk_cards": new_contribs,
                        "atlas_provenance_ids": merged_prov,
                    }
                )
            else:
                # Filter ATLAS provenance: only include IDs that survived
                # zone-3 gating (i.e. present in entry.atlas_technique_ids)
                atlas_set = set(entry.atlas_technique_ids)
                filtered_atlas_prov = [
                    aid for aid in prov_atlas_ids if aid in atlas_set
                ]

                seen[ap_id] = ScenarioSeed(
                    seed_id=ap_id,
                    threat_id=threat_id,
                    threat_name=threat_name,
                    threat_description=threat_description,
                    attack_pattern_name=attack_pattern_name,
                    attack_pattern_description=attack_pattern_desc,
                    risk_card_ref=entry.risk_card,
                    contributing_risk_cards=[entry.risk_card],
                    owasp_llm_ids=entry.owasp_llm_ids,
                    agentic_threat_ids=entry.agentic_threat_ids,
                    atlas_technique_ids=filtered_atlas_prov,
                    owasp_asi_ids=entry.owasp_asi_ids,
                    owasp_origin=prov_owasp_ids[0] if prov_owasp_ids else None,
                    laaf_technique_ids=prov_laaf_ids,
                    atlas_provenance_ids=filtered_atlas_prov,
                    min_complexity=seed_min_complexity,
                    required_capabilities=seed_required_caps,
                    kill_chain=kill_chain,
                )

    return list(seen.values())
