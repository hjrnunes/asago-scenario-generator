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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from asago_scenario_generator.data.loaders import (
    load_cross_taxonomy_mappings,
    load_kc_threat_mapping,
)
from asago_scenario_generator.data.sssom import build_risk_to_llm_index, load_sssom
from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.models import CapabilityProfile, RiskCard
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.models.threat_scope import ThreatScope
from asago_scenario_generator.models.threat_surface import (
    ThreatSurface,
    ThreatSurfaceEntry,
)

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


def _kc6_subcodes(kc_mapping: dict[str, Any]) -> frozenset[str]:
    """Return the KC6-family sub-codes declared by the KC mapping data.

    The family is derived from both the structured ``kc_subcodes``
    section and the compact ``kc_to_threats`` keys so the ATLAS KC6 gate
    stays aligned with the pinned taxonomy regardless of which shape a
    mapping file uses (acceptance fixtures declare only the compact
    section).
    """
    declared = {
        entry["kc_subcode"]
        for entry in kc_mapping.get("kc_subcodes", [])
        if str(entry.get("kc_subcode", "")).startswith("KC6.")
    }
    compact = {
        code for code in kc_mapping.get("kc_to_threats", {}) if code.startswith("KC6.")
    }
    return frozenset(declared | compact)


def _build_llm_to_t_index(cross_taxonomy: dict[str, Any]) -> dict[str, list[str]]:
    """Reverse the t_to_llm section to get LLM ID -> list of T-threat IDs."""
    index: dict[str, list[str]] = defaultdict(list)
    for mapping in cross_taxonomy.get("t_to_llm", []):
        t_id = mapping["source"]
        llm_id = mapping["target"]
        if t_id not in index[llm_id]:
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
        if asi_id is None:
            continue
        if asi_id not in index[t_id]:
            index[t_id].append(asi_id)
    return dict(index)


def _resolve_direct_threats(
    cross_taxonomy: dict[str, Any],
    in_scope_ids: set[str],
) -> set[str]:
    """Resolve in-scope T-threats reachable via the direct path.

    Returns the T-threat IDs that have a t_direct mapping in
    cross-taxonomy-mappings.yaml and pass threat gating.
    ``determine_threat_scope`` already performs the KC sub-code gating;
    per-card ATLAS-overlap joins happen in :func:`_join_direct_overlap`.
    """
    direct_mappings = cross_taxonomy.get("t_direct", [])
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


# ---------------------------------------------------------------------------
# Per-card resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SurfaceContext:
    """Bundled taxonomy indices and gating state for per-card resolution."""

    risk_to_llm: dict[str, list[str]]
    llm_to_t: dict[str, list[str]]
    t_to_atlas: dict[str, list[str]]
    t_to_asi: dict[str, list[str]]
    threat_attack_patterns: dict[str, list[str]]
    in_scope_ids: set[str]
    direct_t_ids: set[str]
    has_kc6: bool
    kc_subcodes: list[str]


def _scoped_threats(threat_scope: ThreatScope) -> tuple[set[str], dict[str, list[str]]]:
    """Split the scope into in-scope IDs and per-threat attack-pattern IDs."""
    in_scope_ids = {e.threat_id for e in threat_scope.in_scope}
    threat_attack_patterns = {
        e.threat_id: e.attack_pattern_ids for e in threat_scope.in_scope
    }
    return in_scope_ids, threat_attack_patterns


def _resolve_three_hop_threats(
    ctx: _SurfaceContext, risk_id: str
) -> tuple[list[str], list[str]]:
    """Resolve a card's OWASP LLM IDs and its in-scope three-hop threats.

    Both lists keep first-seen order: LLM IDs in SSSOM row order, and
    T-threats in traversal order across the card's LLM IDs.
    """
    llm_ids = list(dict.fromkeys(ctx.risk_to_llm.get(risk_id, [])))
    three_hop: list[str] = []
    for llm_id in llm_ids:
        for t_id in ctx.llm_to_t.get(llm_id, []):
            if t_id in ctx.in_scope_ids and t_id not in three_hop:
                three_hop.append(t_id)
    return llm_ids, three_hop


def _join_direct_overlap(ctx: _SurfaceContext, three_hop: list[str]) -> list[str]:
    """Append direct-path threats that share an ATLAS technique with the card.

    A direct-path threat joins the card only when it was not already
    reached via the LLM hop and its ATLAS techniques overlap the
    card's three-hop techniques.  This keeps ``agentic_threat_ids``
    specific to each scenario instead of broadcasting every direct
    threat to every card.
    """
    card_atlas: set[str] = set()
    for t_id in three_hop:
        card_atlas.update(ctx.t_to_atlas.get(t_id, []))
    joined = list(three_hop)
    for dt_id in sorted(ctx.direct_t_ids):
        if dt_id in three_hop:
            continue
        if card_atlas & set(ctx.t_to_atlas.get(dt_id, [])):
            joined.append(dt_id)
    return joined


def _collect_first_seen(
    ids_by_owner: dict[str, list[str]], owners: list[str]
) -> list[str]:
    """De-duplicated first-seen union of IDs across owners."""
    collected: list[str] = []
    for owner in owners:
        for id_ in ids_by_owner.get(owner, []):
            if id_ not in collected:
                collected.append(id_)
    return collected


def _apply_kc6_gate(
    ctx: _SurfaceContext, risk_id: str, atlas_ids: list[str]
) -> list[str]:
    """Drop capability-gated ATLAS techniques when the profile lacks KC6."""
    if ctx.has_kc6:
        return atlas_ids
    gated = sorted(_KC6_GATED_TECHNIQUES.intersection(atlas_ids))
    if not gated:
        return atlas_ids
    logger.warning(
        "ATLAS technique filter: removing KC6-gated techniques %s "
        "for risk %s (kc_subcodes=%s)",
        gated,
        risk_id,
        ctx.kc_subcodes,
    )
    return [aid for aid in atlas_ids if aid not in _KC6_GATED_TECHNIQUES]


def _governance_entry(ref: RiskCardRef, llm_ids: list[str]) -> ThreatSurfaceEntry:
    """An entry retained for governance visibility only."""
    return ThreatSurfaceEntry(
        risk_card=ref,
        owasp_llm_ids=llm_ids,
        agentic_threat_ids=[],
        attack_pattern_ids=[],
        governance_only=True,
    )


def _actionable_entry(
    ctx: _SurfaceContext,
    ref: RiskCardRef,
    llm_ids: list[str],
    threat_ids: list[str],
    risk_id: str,
) -> ThreatSurfaceEntry:
    """A fully resolved entry with de-duplicated first-seen ID unions."""
    return ThreatSurfaceEntry(
        risk_card=ref,
        owasp_llm_ids=llm_ids,
        agentic_threat_ids=threat_ids,
        atlas_technique_ids=_apply_kc6_gate(
            ctx, risk_id, _collect_first_seen(ctx.t_to_atlas, threat_ids)
        ),
        attack_pattern_ids=_collect_first_seen(ctx.threat_attack_patterns, threat_ids),
        owasp_asi_ids=_collect_first_seen(ctx.t_to_asi, threat_ids),
    )


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


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
    kc_mapping = load_kc_threat_mapping(kc_mapping_path)
    threat_scope = determine_threat_scope(
        profile, threats_path, kc_mapping_path, attack_patterns_path
    )
    in_scope_ids, threat_attack_patterns = _scoped_threats(threat_scope)

    ctx = _SurfaceContext(
        risk_to_llm=risk_to_llm,
        llm_to_t=llm_to_t,
        t_to_atlas=t_to_atlas,
        t_to_asi=t_to_asi,
        threat_attack_patterns=threat_attack_patterns,
        in_scope_ids=in_scope_ids,
        direct_t_ids=_resolve_direct_threats(cross_taxonomy, in_scope_ids),
        has_kc6=bool(_kc6_subcodes(kc_mapping).intersection(profile.kc_subcodes)),
        kc_subcodes=profile.kc_subcodes,
    )

    entries: list[ThreatSurfaceEntry] = []
    governance_only: list[ThreatSurfaceEntry] = []

    for card in risk_cards:
        ref = _make_risk_card_ref(card)
        llm_ids, three_hop = _resolve_three_hop_threats(ctx, card.risk_id)

        if not llm_ids:
            governance_only.append(_governance_entry(ref, []))
            continue

        threat_ids = _join_direct_overlap(ctx, three_hop)
        if not threat_ids:
            governance_only.append(_governance_entry(ref, llm_ids))
            continue

        entries.append(_actionable_entry(ctx, ref, llm_ids, threat_ids, card.risk_id))

    return ThreatSurface(entries=entries, governance_only=governance_only)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-23T04:21:05Z","module_hash":"bddf230110b914bad9ed94bd0d1b7fcb7dec6f5336b36c01359c8fff97b013d1","source_sha256":"204ea4492e66975972f66f0d9ff0fc1f77837a1a3c344252f46dc81d81d7c84d","functions":[{"id":"func/_kc6_subcodes","name":"_kc6_subcodes","line":58,"end_line":75,"hash":"abd9d69b6c0acd7caeee3fb5de20dc8225708c0178ad66c13f8c4e6e8fadc6ff"},{"id":"func/_build_llm_to_t_index","name":"_build_llm_to_t_index","line":78,"end_line":86,"hash":"21c5ca36b45dee54c523dd07498fbc994664b081bbe66f26f85f2b3f43fa355e"},{"id":"func/_build_t_to_atlas_index","name":"_build_t_to_atlas_index","line":89,"end_line":104,"hash":"667d2fa86679e38163edc0516b76b616c6ec3ba332438aceb4c613fa5d5abd8b"},{"id":"func/_build_t_to_asi_index","name":"_build_t_to_asi_index","line":107,"end_line":125,"hash":"75042ea289a44542bf586decfc616654cd6e5bfdaa9e2ccfd9534a6111696fed"},{"id":"func/_resolve_direct_threats","name":"_resolve_direct_threats","line":128,"end_line":140,"hash":"687dc49a594368537098a01e74ebd9d1af2f748145bc38609fca3393976d5cef"},{"id":"func/_make_risk_card_ref","name":"_make_risk_card_ref","line":143,"end_line":157,"hash":"be449e59231046e2d8031a43a4bb1837ca5dbea867e431536745021c308d6023"},{"id":"func/_scoped_threats","name":"_scoped_threats","line":180,"end_line":186,"hash":"f7ba94cb7e39326c481afa1041bc4a344543693168f8758d71cbf85f7bb6cf51"},{"id":"func/_resolve_three_hop_threats","name":"_resolve_three_hop_threats","line":189,"end_line":203,"hash":"41c89bfd438bb4e4e44f0b4b87cd9dceb990a48d74d231ceb441e0e50ff65818"},{"id":"func/_join_direct_overlap","name":"_join_direct_overlap","line":206,"end_line":224,"hash":"059161dd90acb1278a7b32d3012dd5932f7c25243ec8836e929ce6fccb77c082"},{"id":"func/_collect_first_seen","name":"_collect_first_seen","line":227,"end_line":236,"hash":"0d48405f9eb942c056e7a91cd206791cf6582cb0f8814df11acba35d7ce48aed"},{"id":"func/_apply_kc6_gate","name":"_apply_kc6_gate","line":239,"end_line":255,"hash":"b36363fa075265ed86fe39f131ad8062b0f2b5b8ad12c4cd488bb0f9bd6958df"},{"id":"func/_governance_entry","name":"_governance_entry","line":258,"end_line":266,"hash":"7d2510286f3825b7a0c8fc29fe54fd1d2325412c41e41cc2ef132bc0884d2165"},{"id":"func/_actionable_entry","name":"_actionable_entry","line":269,"end_line":286,"hash":"4cc7b5efe43cf567e06a91252cf918e87f5746716dda207c0aa2adc41d22d6f8"},{"id":"func/determine_threat_surface","name":"determine_threat_surface","line":294,"end_line":377,"hash":"a12a5eb40757e4e63b7f08d1233cd5b9647d3ecf5ab57abc08572a42dcc5942b"}]}
# mutate4py-manifest-end
