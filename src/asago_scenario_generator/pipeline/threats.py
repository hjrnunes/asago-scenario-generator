"""Stage 2: Deterministic Threat Surface Determination.

Primary path — three-hop taxonomy chain with no LLM calls:
  Hop 1  Risk Atlas ID  -> OWASP LLM Top 10 IDs  (via SSSOM)
  Hop 2  LLM Top 10 IDs -> OWASP Agentic Threat IDs (via cross-taxonomy, reversed)
  Hop 3  Filter by capability profile (via threat_gating)

Direct path — for agentic-only threats with no LLM predecessor:
  T-threats mapped directly to capability profile features (via t_direct
  in cross-taxonomy-mappings.yaml), bypassing the LLM hop entirely.
  These threats (T7-T10, T14-T16) are new to agentic AI and have no
  cross-reference to any LLM Top 10 entry.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from asago_scenario_generator.data.loaders import load_cross_taxonomy_mappings
from asago_scenario_generator.data.sssom import build_risk_to_llm_index, load_sssom
from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.models import CapabilityProfile, RiskCard
from asago_scenario_generator.models.scenario import RiskCardRef

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Capability-gated ATLAS technique IDs
# ---------------------------------------------------------------------------
# ATLAS techniques that are semantically meaningful only when the system has
# specific capabilities.  Techniques in this set are filtered from the seed
# list when the required capability is absent.

_KC6_GATED_TECHNIQUES: frozenset[str] = frozenset(
    {
        "AML.T0053",  # AI Agent Tool Invocation — requires operational environment
        "AML.T0070",  # RAG Poisoning — requires retrieval tools
        "AML.T0066",  # Retrieval Content Crafting — requires retrieval tools
        "AML.T0071",  # Embedding Manipulation — requires retrieval/embedding
        "AML.T0025",  # Resource Exhaustion via Embedding — requires retrieval/embedding
    }
)

_KC6_SUBCODES: frozenset[str] = frozenset(
    {
        "KC6.1.1",
        "KC6.1.2",
        "KC6.2.1",
        "KC6.2.2",
        "KC6.3.1",
        "KC6.3.2",
        "KC6.3.3",
        "KC6.4",
        "KC6.5",
        "KC6.6",
        "KC6.7",
    }
)


class ThreatSurfaceEntry(BaseModel):
    risk_card: RiskCardRef
    owasp_llm_ids: list[str]
    agentic_threat_ids: list[str]
    atlas_technique_ids: list[str] = Field(default_factory=list)
    attack_pattern_ids: list[str] = Field(default_factory=list)
    owasp_asi_ids: list[str] = Field(default_factory=list)
    governance_only: bool = False


class ThreatSurface(BaseModel):
    entries: list[ThreatSurfaceEntry]
    governance_only: list[ThreatSurfaceEntry]


def _build_llm_to_t_index(cross_taxonomy: dict[str, Any]) -> dict[str, list[str]]:
    """Reverse the t_to_llm section to get LLM ID -> list of T-threat IDs."""
    index: dict[str, list[str]] = defaultdict(list)
    for mapping in cross_taxonomy.get("t_to_llm", []):
        t_id = mapping["source"]
        llm_id = mapping["target"]
        if llm_id not in index or t_id not in index[llm_id]:
            index[llm_id].append(t_id)
    return dict(index)


def _build_t_to_atlas_index(
    cross_taxonomy: dict[str, Any],
) -> dict[str, list[str]]:
    """Build T-threat ID -> list of ATLAS technique IDs from t_to_atlas.

    Each t_to_atlas entry has 'source' (T-threat ID) and 'targets'
    (list of AML.T IDs). Multiple entries for the same T-threat are
    merged with deduplication.
    """
    index: dict[str, list[str]] = defaultdict(list)
    for mapping in cross_taxonomy.get("t_to_atlas", []):
        t_id = mapping["source"]
        for atlas_id in mapping.get("targets", []):
            if atlas_id not in index[t_id]:
                index[t_id].append(atlas_id)
    return dict(index)


def _build_t_to_asi_index(
    cross_taxonomy: dict[str, Any],
) -> dict[str, list[str]]:
    """Build T-threat ID -> list of OWASP ASI Top 10 IDs from t_to_asi.

    Each t_to_asi entry has 'source' (T-threat ID) and 'target'
    (a single ASI ID string, or null for no match). Multiple entries
    for the same T-threat are merged with deduplication. Entries where
    target is null are skipped.
    """
    index: dict[str, list[str]] = defaultdict(list)
    for mapping in cross_taxonomy.get("t_to_asi", []):
        t_id = mapping["source"]
        asi_id = mapping.get("target")
        if asi_id is not None and asi_id not in index[t_id]:
            index[t_id].append(asi_id)
    return dict(index)


def _build_direct_t_mappings(
    cross_taxonomy: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract the t_direct mappings from cross-taxonomy data.

    Returns the raw list of direct mapping dicts, each containing
    'source' (T-threat ID) and 'profile_match' (capability requirements).
    """
    return list(cross_taxonomy.get("t_direct", []))


def _resolve_direct_threats(
    cross_taxonomy: dict[str, Any],
    in_scope_ids: set[str],
) -> set[str]:
    """Resolve T-threats reachable via the direct path.

    Returns the set of T-threat IDs that:
      1. Have a t_direct mapping in cross-taxonomy-mappings.yaml
      2. Pass threat gating (are in in_scope_ids — already KC-filtered)

    Profile matching is no longer needed here — ``determine_threat_scope``
    already uses KC sub-codes to decide which threats are in scope.

    Args:
        cross_taxonomy: Parsed cross-taxonomy-mappings.yaml.
        in_scope_ids: Set of threat IDs that passed gating.

    Returns:
        Set of T-threat IDs reachable via the direct path.
    """
    direct_mappings = _build_direct_t_mappings(cross_taxonomy)
    return {m["source"] for m in direct_mappings if m["source"] in in_scope_ids}


def _make_risk_card_ref(card: RiskCard) -> RiskCardRef:
    kwargs: dict[str, Any] = dict(
        risk_id=card.risk_id,
        risk_name=card.risk_name,
        risk_description=card.risk_description,
        taxonomy=card.taxonomy,
        confidence=card.confidence,
        grounding_confidence=card.grounding_confidence,
    )
    # Populate causal chain fields from the RiskCard when available
    for field in ("threat", "threat_source", "vulnerability", "consequence", "impact"):
        value = getattr(card, field, None)
        if value is not None:
            kwargs[field] = value
    return RiskCardRef(**kwargs)


def determine_threat_surface(
    profile: CapabilityProfile,
    risk_cards: list[RiskCard],
    sssom_path: str | Path,
    cross_taxonomy_path: str | Path,
    threats_path: str | Path | None = None,
    kc_mapping_path: str | Path | None = None,
    attack_patterns_path: str | Path | None = None,
) -> ThreatSurface:
    """Walk the taxonomy chain to build the threat surface.

    Uses two paths to resolve T-threats:
      1. Three-hop chain: Risk Atlas → LLM Top 10 → T-threat → gating
      2. Direct path: T-threat → capability profile match → gating
         (for agentic-only threats with no LLM predecessor)

    Args:
        profile: System capability profile from Stage 1.
        risk_cards: Risk cards from policy-mapper extraction.
        sssom_path: Path to the SSSOM TSV mapping file.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml.
        threats_path: Optional path to OWASP agentic threats YAML.
        kc_mapping_path: Optional path to the KC sub-code -> threat
            mapping YAML used for scope gating. Defaults to the bundled
            kc-threat-mapping.yaml.
        attack_patterns_path: Optional path to an attack-patterns YAML
            used for gating. Defaults to the bundled attack-pattern
            catalog.

    Returns:
        ThreatSurface with actionable entries and governance-only entries.
    """
    # --- Hop 1: Risk Atlas ID -> LLM Top 10 IDs ---
    sssom_mappings = load_sssom(sssom_path)
    risk_to_llm = build_risk_to_llm_index(sssom_mappings)

    # --- Hop 2: LLM Top 10 IDs -> Agentic Threat IDs (reversed t_to_llm) ---
    cross_taxonomy = load_cross_taxonomy_mappings(cross_taxonomy_path)
    llm_to_t = _build_llm_to_t_index(cross_taxonomy)

    # --- ATLAS technique lookup: T-threat -> ATLAS technique IDs ---
    t_to_atlas = _build_t_to_atlas_index(cross_taxonomy)

    # --- ASI lookup: T-threat -> OWASP ASI Top 10 IDs ---
    t_to_asi = _build_t_to_asi_index(cross_taxonomy)

    # --- Hop 3: Filter by capability profile ---
    threat_scope = determine_threat_scope(
        profile, threats_path, kc_mapping_path, attack_patterns_path
    )
    in_scope_ids = {e.threat_id for e in threat_scope.in_scope}
    # Build threat_id -> applicable attack pattern IDs
    threat_attack_patterns: dict[str, list[str]] = {
        e.threat_id: e.attack_pattern_ids for e in threat_scope.in_scope
    }

    # --- Direct path: T-threats reachable without LLM hop ---
    direct_t_ids = _resolve_direct_threats(cross_taxonomy, in_scope_ids)

    # Track which direct-path threats were already reached via the LLM hop
    # so we can detect truly unreachable threats
    llm_reached_t_ids: set[str] = set()

    entries: list[ThreatSurfaceEntry] = []
    governance_only: list[ThreatSurfaceEntry] = []

    for card in risk_cards:
        ref = _make_risk_card_ref(card)
        llm_ids = list(dict.fromkeys(risk_to_llm.get(card.risk_id, [])))

        if not llm_ids:
            governance_only.append(
                ThreatSurfaceEntry(
                    risk_card=ref,
                    owasp_llm_ids=[],
                    agentic_threat_ids=[],
                    attack_pattern_ids=[],
                    governance_only=True,
                )
            )
            continue

        # Collect all T-threats reachable from these LLM IDs
        all_t_ids: list[str] = []
        for llm_id in llm_ids:
            for t_id in llm_to_t.get(llm_id, []):
                if t_id not in all_t_ids:
                    all_t_ids.append(t_id)

        # Filter to in-scope threats only
        scoped_t_ids = [t for t in all_t_ids if t in in_scope_ids]
        llm_reached_t_ids.update(scoped_t_ids)

        # Append direct-path threats only when they share at least one
        # ATLAS technique with the three-hop threats already on this card.
        # This prevents broadcasting every direct threat to every risk card,
        # keeping agentic_threat_ids specific to each scenario.
        card_atlas: set[str] = set()
        for t_id in scoped_t_ids:
            card_atlas.update(t_to_atlas.get(t_id, []))
        for dt_id in sorted(direct_t_ids):
            if dt_id not in scoped_t_ids:
                dt_atlas = set(t_to_atlas.get(dt_id, []))
                if card_atlas & dt_atlas:
                    scoped_t_ids.append(dt_id)

        if not scoped_t_ids:
            governance_only.append(
                ThreatSurfaceEntry(
                    risk_card=ref,
                    owasp_llm_ids=llm_ids,
                    agentic_threat_ids=[],
                    attack_pattern_ids=[],
                    governance_only=True,
                )
            )
            continue

        # Collect attack pattern IDs from in-scope threats
        all_ap_ids: list[str] = []
        for t_id in scoped_t_ids:
            for ap_id in threat_attack_patterns.get(t_id, []):
                if ap_id not in all_ap_ids:
                    all_ap_ids.append(ap_id)

        # Collect ATLAS technique IDs for all in-scope T-threats
        all_atlas: list[str] = []
        for t_id in scoped_t_ids:
            for atlas_id in t_to_atlas.get(t_id, []):
                if atlas_id not in all_atlas:
                    all_atlas.append(atlas_id)

        # Collect OWASP ASI Top 10 IDs for all in-scope T-threats
        all_asi: list[str] = []
        for t_id in scoped_t_ids:
            for asi_id in t_to_asi.get(t_id, []):
                if asi_id not in all_asi:
                    all_asi.append(asi_id)

        # Filter capability-gated ATLAS techniques
        has_kc6 = bool(_KC6_SUBCODES.intersection(profile.kc_subcodes))
        if not has_kc6:
            gated = [aid for aid in all_atlas if aid in _KC6_GATED_TECHNIQUES]
            if gated:
                logger.warning(
                    "ATLAS technique filter: removing KC6-gated techniques %s "
                    "for risk %s (kc_subcodes=%s)",
                    gated,
                    card.risk_id,
                    profile.kc_subcodes,
                )
                all_atlas = [
                    aid for aid in all_atlas if aid not in _KC6_GATED_TECHNIQUES
                ]

        entries.append(
            ThreatSurfaceEntry(
                risk_card=ref,
                owasp_llm_ids=llm_ids,
                agentic_threat_ids=scoped_t_ids,
                atlas_technique_ids=all_atlas,
                attack_pattern_ids=all_ap_ids,
                owasp_asi_ids=all_asi,
            )
        )

    return ThreatSurface(entries=entries, governance_only=governance_only)
