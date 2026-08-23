"""Provenance and scenario-seed rendering for the taxonomy/risk report.

Renders the provenance chain flowchart, the SSSOM provenance block, and
the Scenario Seed block for scenario cards, and hosts the
taxonomy-derived display lookups and tooltip helpers those sections --
and the rest of the taxonomy/risk report template -- rely on.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_DESCRIPTIONS
from asago_scenario_generator.data.loaders import (
    load_attack_goals_taxonomy,
    load_attack_patterns,
    load_threat_goal_affinity,
)
from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
)
from asago_scenario_generator.models.capability_profile import (
    ZONE_NAMES as _ZONE_NAMES_TUPLE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zone colour palette
# ---------------------------------------------------------------------------

ZONE_COLORS: dict[str, str] = {
    "input": "#3b82f6",  # blue
    "reasoning": "#8b5cf6",  # purple
    "tool_execution": "#f97316",  # orange
    "memory": "#22c55e",  # green
    "inter_agent": "#ef4444",  # red
}

ZONE_NAMES: dict[str, str] = dict(ZONE_DISPLAY_NAMES)

ZONE_BG_COLORS: dict[str, str] = {
    "input": "#1e3a5f",
    "reasoning": "#3b1f6e",
    "tool_execution": "#5c2d0e",
    "memory": "#0f3d1e",
    "inter_agent": "#5c1111",
}

# Abbreviated zone labels for compact table cells
ZONE_ABBREVS: dict[str, str] = {
    "input": "INP",
    "reasoning": "RSN",
    "tool_execution": "TXE",
    "memory": "MEM",
    "inter_agent": "IPC",
}

# Legacy int-to-string mapping for backward compatibility with old data
_INT_TO_ZONE_NAME: dict[int, str] = dict(enumerate(_ZONE_NAMES_TUPLE, 1))

# ---------------------------------------------------------------------------
# OWASP Agentic Threat names (stable taxonomy v1.1)
# ---------------------------------------------------------------------------

THREAT_NAMES: dict[str, str] = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking & Goal Manipulation",
    "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability",
    "T9": "Identity Spoofing & Impersonation / Agent Identity Compromise",
    "T10": "Overwhelming Human in the Loop",
    "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
    "T16": "Insecure Inter-Agent Protocol Abuse",
    "T17": "Supply Chain Compromise",
}

_ATLAS_TECHNIQUE_NAMES: dict[str, str] = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0015": "LLM Capability Escalation",
    "AML.T0016": "Obtain Capabilities",
    "AML.T0020": "Poison Training Data",
    "AML.T0021": "Establish Accounts",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Resource Exhaustion via Embedding",
    "AML.T0029": "Denial of AI Service",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "Unsafe Deserialisation via LLM",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0047": "AI-Enabled Product or Service",
    "AML.T0048": "External Harms",
    "AML.T0049": "Spearphishing via AI",
    "AML.T0051.000": "Direct Prompt Injection",
    "AML.T0051.001": "Indirect Prompt Injection",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0060": "Publish Hallucinated Entities",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "Output Manipulation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "Embedding Manipulation",
}

_OWASP_LLM_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ---------------------------------------------------------------------------
# Taxonomy-derived lookup tables (loaded once at import time)
# ---------------------------------------------------------------------------

_THREAT_DESCRIPTIONS: dict[str, str] = {}
_ATTACK_PATTERN_INFO: dict[str, dict[str, Any]] = {}


def _load_taxonomy_lookups() -> None:
    """Populate _THREAT_DESCRIPTIONS from the taxonomy YAML."""
    taxonomy_path = (
        Path(__file__).resolve().parents[3]
        / "data"
        / "taxonomies"
        / "owasp-agentic-threats"
        / "owasp-agentic-threats-v1.1.yaml"
    )
    if not taxonomy_path.exists():
        logger.warning(
            "Taxonomy YAML not found at %s; tooltips will be thin", taxonomy_path
        )
        return
    try:
        data = yaml.safe_load(taxonomy_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load taxonomy YAML: %s", exc)
        return

    threats = data.get("threats", {})
    for tid, info in threats.items():
        desc = info.get("description", "")
        if desc:
            _THREAT_DESCRIPTIONS[tid] = desc.strip()


def _load_attack_pattern_lookups() -> None:
    """Populate _ATTACK_PATTERN_INFO from the attack patterns YAML (name/description only).

    SSSOM provenance is no longer loaded here; provenance data is read from
    scenario seed metadata at render time instead.
    """
    try:
        patterns = load_attack_patterns()
        for pid, pat in patterns.items():
            _ATTACK_PATTERN_INFO[pid] = {
                "name": pat["name"],
                "description": pat["description"].strip(),
            }
    except FileNotFoundError:
        pass


_load_taxonomy_lookups()
_load_attack_pattern_lookups()


def _truncate(text: str, max_len: int = 200) -> str:
    """Truncate text to *max_len* characters, appending '...' if cut."""
    if len(text) <= max_len:
        return text
    # Try to break at the end of a sentence within the limit
    sentence_end = text.rfind(". ", 0, max_len)
    if sentence_end > 0:
        return text[: sentence_end + 1]
    return text[:max_len] + "..."


def _normalize_zone(zone: int | str) -> str:
    """Normalize a zone value to a canonical string name.

    Accepts both legacy integer zone IDs (1-5) and string zone names.
    Returns the canonical string name, or the input as-is if unrecognized.
    """
    if isinstance(zone, int):
        return _INT_TO_ZONE_NAME.get(zone, str(zone))
    return str(zone)


def _threat_id_tooltip(tid: str) -> str:
    """Return a data-tooltip attribute string for a threat ID like 'T7'."""
    # Extract base threat ID (e.g. T7 from AP-T7-01)
    base = tid.split("-")[0] if "-" in tid else tid
    name = THREAT_NAMES.get(base, "")
    if not name:
        return ""
    desc = _THREAT_DESCRIPTIONS.get(base, "")
    if desc:
        short_desc = _truncate(desc)
        return f' data-tooltip="{_esc(base)} — {_esc(name)}: {_esc(short_desc)}"'
    return f' data-tooltip="{_esc(base)} — {_esc(name)}"'


def _attack_pattern_tooltip(ap_id: str, seed_meta: dict[str, Any] | None = None) -> str:
    """Return a data-tooltip attribute for an attack pattern ID like 'AP-T7-01'.

    When *seed_meta* (scenario_seed_metadata dict) is provided, provenance
    data is read from it instead of from the module-level _ATTACK_PATTERN_INFO.
    """
    if ap_id in _ATTACK_PATTERN_INFO:
        info = _ATTACK_PATTERN_INFO[ap_id]
        name = _esc(info["name"])
        desc = _truncate(_esc(info["description"]), 200)
        # Provenance comes from seed metadata when available
        owasp_origin = ""
        laaf: list[str] = []
        atlas: list[str] = []
        if seed_meta:
            owasp_origin = seed_meta.get("owasp_origin") or ""
            laaf = seed_meta.get("laaf_technique_ids") or []
            atlas = seed_meta.get("atlas_provenance_ids") or []
        origin_suffix = f" (derived from {_esc(owasp_origin)})" if owasp_origin else ""
        prov_parts: list[str] = []
        if laaf:
            prov_parts.append(f"LAAF: {', '.join(_esc(t) for t in laaf)}")
        if atlas:
            prov_parts.append(f"ATLAS: {', '.join(_esc(t) for t in atlas)}")
        prov_suffix = f" | Provenance: {'; '.join(prov_parts)}" if prov_parts else ""
        return f' data-tooltip="{name}: {desc}{origin_suffix}{prov_suffix}"'
    return ""


def _technique_id_tooltip(technique_id: str) -> str:
    """Return a data-tooltip attribute for an ATLAS technique ID."""
    name = _ATLAS_TECHNIQUE_NAMES.get(technique_id, "")
    if not name:
        return ""
    desc = ATLAS_TECHNIQUE_DESCRIPTIONS.get(technique_id, "")
    if desc:
        return f' data-tooltip="{_esc(technique_id)} — {_esc(name)}&#10;{_esc(desc)}"'
    return f' data-tooltip="MITRE ATLAS: {_esc(technique_id)} — {_esc(name)}"'


def _build_provenance_block(scenario: dict[str, Any]) -> str:
    """Build a Provenance section for AP-* scenario seeds.

    Reads provenance data (OWASP origin, LAAF correspondences, ATLAS
    correspondences) from the scenario's ``scenario_seed_metadata`` dict
    instead of from the module-level SSSOM-loaded lookup tables.

    Returns empty string for non-AP seeds or when no provenance data exists.
    """
    meta = scenario.get("scenario_seed_metadata") or {}
    scenario_seed = meta.get("seed_id", "")

    if not scenario_seed or not scenario_seed.startswith("AP-"):
        return ""

    owasp_origin = meta.get("owasp_origin") or ""
    laaf = meta.get("laaf_technique_ids") or []
    atlas = meta.get("atlas_provenance_ids") or []

    if not owasp_origin and not laaf and not atlas:
        return ""

    rows = ""
    if owasp_origin:
        origin_tip = _attack_pattern_tooltip(owasp_origin) if owasp_origin else ""
        rows += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
            f'<span style="min-width:100px;font-size:11px;font-weight:600;'
            f'color:var(--text-muted);text-transform:uppercase;">Origin</span>'
            f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
            f"font-weight:600;background:rgba(99,102,241,0.15);"
            f"color:var(--accent);font-family:'SF Mono','Fira Code',"
            f'monospace;"{origin_tip}>{_esc(owasp_origin)}</span>'
            f"</div>"
        )
    if laaf:
        laaf_badges = "".join(
            f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
            f"font-weight:600;background:rgba(34,197,94,0.15);"
            f"color:#22c55e;font-family:'SF Mono','Fira Code',"
            f'monospace;margin-right:4px;">{_esc(lid)}</span>'
            for lid in laaf
        )
        rows += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;'
            f'flex-wrap:wrap;">'
            f'<span style="min-width:100px;font-size:11px;font-weight:600;'
            f'color:var(--text-muted);text-transform:uppercase;"'
            f' data-tooltip="LLM Agent Attack Framework technique correspondences"'
            f">LAAF</span>"
            f"{laaf_badges}"
            f"</div>"
        )
    if atlas:
        atlas_badges = "".join(
            f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
            f"font-weight:600;background:rgba(249,115,22,0.15);"
            f"color:#f97316;font-family:'SF Mono','Fira Code',"
            f'monospace;margin-right:4px;"'
            f"{_technique_id_tooltip(aid)}>{_esc(aid)}</span>"
            for aid in atlas
        )
        rows += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;'
            f'flex-wrap:wrap;">'
            f'<span style="min-width:100px;font-size:11px;font-weight:600;'
            f'color:var(--text-muted);text-transform:uppercase;"'
            f' data-tooltip="MITRE ATLAS technique correspondences"'
            f">ATLAS</span>"
            f"{atlas_badges}"
            f"</div>"
        )

    return f"""
        <div class="scenario-section">
          <details class="expandable" open>
            <summary>SSSOM Provenance</summary>
            <div style="padding:12px 0 4px;">
              {rows}
            </div>
          </details>
        </div>"""


def _build_seed_metadata_block(scenario: dict[str, Any]) -> str:
    """Build a Scenario Seed section from scenario_seed_metadata.

    Returns an HTML block showing the seed's attack pattern name, description,
    threat context, and OWASP origin. Returns empty string when metadata
    is absent.
    """
    meta = scenario.get("scenario_seed_metadata")
    if not meta:
        return ""

    attack_pattern_name = meta.get("attack_pattern_name") or meta.get(
        "mechanism_name", ""
    )
    attack_pattern_description = meta.get("attack_pattern_description") or meta.get(
        "mechanism_description", ""
    )
    seed_id = meta.get("seed_id", "")
    threat_id = meta.get("threat_id", "")
    threat_name = meta.get("threat_name", "")
    owasp_origin = meta.get("owasp_origin", "")

    if not attack_pattern_name and not seed_id:
        return ""

    # Threat span with tooltip
    threat_html = ""
    if threat_id:
        tip = _threat_id_tooltip(threat_id)
        threat_label = (
            f"{_esc(threat_id)} &mdash; {_esc(threat_name)}"
            if threat_name
            else _esc(threat_id)
        )
        threat_html = (
            f"<span><strong>Threat:</strong> <span{tip}>{threat_label}</span></span>"
        )

    # Origin span
    origin_html = ""
    if owasp_origin:
        origin_tip = _attack_pattern_tooltip(owasp_origin)
        origin_html = (
            f"<span><strong>Origin:</strong> "
            f"<span{origin_tip}>{_esc(owasp_origin)}</span></span>"
        )

    # Seed ID span
    seed_html = ""
    if seed_id:
        seed_html = f"<span><strong>Seed:</strong> {_esc(seed_id)}</span>"

    meta_row_items = " ".join(
        item for item in [seed_html, threat_html, origin_html] if item
    )

    # Attack pattern description (truncated for display)
    desc_html = ""
    if attack_pattern_description:
        desc_html = (
            f'<div style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;">'
            f"{_esc(attack_pattern_description)}"
            f"</div>"
        )

    # Attack pattern name
    name_html = ""
    if attack_pattern_name:
        name_html = (
            f'<div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">'
            f"{_esc(attack_pattern_name)}"
            f"</div>"
        )

    return f"""
        <div class="scenario-section">
          <details class="expandable" open>
            <summary>Scenario Seed</summary>
            <div style="padding:12px 0 4px;">
              {name_html}
              {desc_html}
              <div style="display:flex;gap:16px;font-size:12px;">
                {meta_row_items}
              </div>
            </div>
          </details>
        </div>"""


def _build_provenance_chain(
    scenario: dict[str, Any],
    threat_surface: dict[str, Any] | None = None,
    capability_profile: dict[str, Any] | None = None,
) -> str:
    """Build a flowchart showing the full input derivation chain.

    Steps 1-3 (Risk Card -> OWASP LLM IDs -> Agentic Threats) flow vertically,
    then steps 4a/4b/4c (Attack Pattern, Attack Goal, ATLAS Techniques) fan
    out as three parallel inputs that converge before step 5 (Entry Point)
    and step 6 (Zone Sequence). Uses lazy-loaded taxonomy data for attack
    goals and affinities.
    """
    faceting = scenario.get("faceting", {})
    rc = faceting.get("risk_card", {})
    tc = faceting.get("taxonomy_chain", {})
    cp = faceting.get("capability_profile", {})
    meta = scenario.get("scenario_seed_metadata") or {}
    actor = scenario.get("actor_profile") or {}

    arrow = '<div class="prov-arrow">&#9660;</div>'
    steps: list[str] = []

    # --- Step 1: Risk Card ---
    risk_id = rc.get("risk_id", "")
    risk_name = rc.get("risk_name", "")
    taxonomy = rc.get("taxonomy", "")
    confidence = rc.get("confidence", 0)
    conf_display = (
        f"{confidence:.2f}" if isinstance(confidence, (int, float)) else str(confidence)
    )
    taxonomy_badge = (
        f'<span class="prov-badge prov-badge-accent">{_esc(taxonomy)}</span>'
        if taxonomy
        else ""
    )
    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">1. Risk Card</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-kv"><span class="prov-kv-label">Risk ID</span>'
        f"<span class=\"prov-kv-value\" style=\"font-family:'SF Mono','Fira Code',monospace;\">{_esc(risk_id)}</span></div>"
        f'<div class="prov-kv"><span class="prov-kv-label">Risk Name</span>'
        f'<span class="prov-kv-value">{_esc(risk_name)}</span></div>'
        f'<div class="prov-kv"><span class="prov-kv-label">Taxonomy</span>'
        f'<span class="prov-kv-value">{taxonomy_badge}</span></div>'
        f'<div class="prov-kv"><span class="prov-kv-label">Confidence</span>'
        f'<span class="prov-kv-value">{_esc(conf_display)}</span></div>'
        f"</div></div>"
    )

    # --- Step 2: OWASP LLM IDs ---
    owasp_ids = tc.get("owasp_llm_ids", [])
    owasp_badges = (
        "".join(
            f'<span class="prov-badge prov-badge-blue"'
            f' data-tooltip="{_esc(_OWASP_LLM_NAMES.get(lid, ""))}"'
            f">{_esc(lid)}</span>"
            for lid in owasp_ids
        )
        if owasp_ids
        else '<span class="prov-badge prov-badge-muted">none</span>'
    )
    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">2. OWASP LLM IDs &mdash; SSSOM Mapping</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-item-row">{owasp_badges}</div>'
        f"</div></div>"
    )

    # --- Step 3: Agentic Threats ---
    threat_ids = tc.get("agentic_threat_ids", [])
    threat_badges = (
        "".join(
            f'<span class="prov-badge prov-badge-orange"'
            f"{_threat_id_tooltip(tid)}>"
            f"{_esc(tid)}</span>"
            for tid in threat_ids
        )
        if threat_ids
        else '<span class="prov-badge prov-badge-muted">none</span>'
    )
    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">3. Agentic Threats (surviving)</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-item-row">{threat_badges}</div>'
        f"</div></div>"
    )

    # --- Step 4: Attack Pattern ---
    seed_id = meta.get("seed_id", "")
    ap_name = meta.get("attack_pattern_name", "")
    ap_desc = meta.get("attack_pattern_description", "")
    seed_threat_id = meta.get("threat_id", "")
    seed_threat_name = meta.get("threat_name", "")
    ap_desc_html = (
        f'<div class="prov-kv"><span class="prov-kv-label">Description</span>'
        f'<span class="prov-kv-value" style="font-size:12px;color:var(--text-muted);">'
        f"{_esc(_truncate(ap_desc, 300))}</span></div>"
        if ap_desc
        else ""
    )
    # Collect all attack pattern IDs from threat surface entries matching this threat
    all_ap_ids: list[str] = []
    if threat_surface and seed_threat_id:
        for entry in threat_surface.get("entries", []):
            if seed_threat_id in entry.get("agentic_threat_ids", []):
                all_ap_ids.extend(entry.get("attack_pattern_ids", []))
        # Deduplicate while preserving order
        all_ap_ids = list(dict.fromkeys(all_ap_ids))

    ap_selection_html = ""
    if all_ap_ids:
        ap_items = ""
        for ap_id in all_ap_ids:
            ap_tip_name = _ATTACK_PATTERN_INFO.get(ap_id, {}).get("name", "")
            tip = f' data-tooltip="{_esc(ap_tip_name)}"' if ap_tip_name else ""
            if ap_id == seed_id:
                ap_items += (
                    f'<span class="prov-highlight"{tip}>'
                    f"<span style=\"font-family:'SF Mono','Fira Code',monospace;font-size:11px;"
                    f'font-weight:700;color:var(--accent);">{_esc(ap_id)}</span></span>'
                )
            else:
                ap_items += (
                    f'<span class="prov-badge prov-badge-muted prov-dim"{tip}>'
                    f"{_esc(ap_id)}</span>"
                )
        ap_selection_html = (
            f'<div class="prov-item-row" style="margin-top:6px;">{ap_items}</div>'
        )

    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">4a. Attack Pattern '
        f'<span style="font-size:9px;color:var(--text-muted);font-variant:normal;">'
        f"(highlighted = selected for this seed)</span></div>"
        f'<div class="prov-step-content">'
        f'<div class="prov-kv"><span class="prov-kv-label">Seed ID</span>'
        f"<span class=\"prov-kv-value\" style=\"font-family:'SF Mono','Fira Code',monospace;\">{_esc(seed_id)}</span></div>"
        f'<div class="prov-kv"><span class="prov-kv-label">Name</span>'
        f'<span class="prov-kv-value" style="font-weight:600;">{_esc(ap_name)}</span></div>'
        f"{ap_desc_html}"
        f'<div class="prov-kv"><span class="prov-kv-label">Threat</span>'
        f'<span class="prov-kv-value"><span{_threat_id_tooltip(seed_threat_id)}>'
        f"{_esc(seed_threat_id)} &mdash; {_esc(seed_threat_name)}</span></span></div>"
        f"{ap_selection_html}"
        f"</div></div>"
    )

    # --- Step 5: Attack Goal ---
    goal_cat = actor.get("goal_category", "")
    goal_name = actor.get("goal_category_name", "")
    goal_parent = actor.get("goal_category_parent", "")

    # Load affinity and taxonomy data
    affinity_html = ""
    goals_grid_html = ""
    try:
        affinity_map = load_threat_goal_affinity()
        goals_taxonomy = load_attack_goals_taxonomy()
        categories = goals_taxonomy.get("categories", [])

        # Show affinity explanation for this scenario's threat
        if seed_threat_id and seed_threat_id in affinity_map:
            aff = affinity_map[seed_threat_id]
            primary_cats = aff.get("primary", [])
            secondary_cats = aff.get("secondary", [])

            # Find which category the selected goal belongs to
            selected_cat_id = ""
            for cat in categories:
                for sg in cat.get("sub_goals", []):
                    if sg.get("id") == goal_cat:
                        selected_cat_id = cat.get("id", "")
                        break
                if selected_cat_id:
                    break

            # Build plain-language explanation
            if selected_cat_id and selected_cat_id in primary_cats:
                tier_badge = '<span class="prov-badge prov-badge-green">primary</span>'
                other_primary = [c for c in primary_cats if c != selected_cat_id]
                context_parts: list[str] = []
                if other_primary:
                    context_parts.append(f"also primary: {', '.join(other_primary)}")
                if secondary_cats:
                    context_parts.append(f"secondary: {', '.join(secondary_cats)}")
                context_span = (
                    f' <span style="color:var(--text-muted);">'
                    f"({' | '.join(context_parts)})</span>"
                    if context_parts
                    else ""
                )
            elif selected_cat_id and selected_cat_id in secondary_cats:
                tier_badge = (
                    '<span class="prov-badge prov-badge-amber">secondary</span>'
                )
                other_secondary = [c for c in secondary_cats if c != selected_cat_id]
                context_parts = []
                if primary_cats:
                    context_parts.append(f"primary: {', '.join(primary_cats)}")
                if other_secondary:
                    context_parts.append(
                        f"also secondary: {', '.join(other_secondary)}"
                    )
                context_span = (
                    f' <span style="color:var(--text-muted);">'
                    f"({' | '.join(context_parts)})</span>"
                    if context_parts
                    else ""
                )
            else:
                # Fallback: could not determine tier
                tier_badge = ""
                primary_str = ", ".join(primary_cats)
                secondary_str = ", ".join(secondary_cats)
                context_span = (
                    f' <span style="color:var(--text-muted);">'
                    f"(primary: {_esc(primary_str)} | secondary: {_esc(secondary_str)})</span>"
                )

            affinity_html = (
                f'<div style="margin:6px 0 8px;padding:8px 12px;background:var(--bg-primary);'
                f'border-radius:6px;border:1px solid var(--border);font-size:12px;">'
                f"&lsquo;{_esc(selected_cat_id or goal_parent)}&rsquo; &mdash; "
                f"{tier_badge} affinity for {_esc(seed_threat_id)}"
                f"{context_span}"
                f"</div>"
            )

        # Build goal category badges showing all sub-goals with selection highlight
        # Build a lookup: sub-goal id -> tier
        tier_lookup: dict[str, str] = {}
        if seed_threat_id and seed_threat_id in affinity_map:
            aff = affinity_map[seed_threat_id]
            for cat_id in aff.get("primary", []):
                for cat in categories:
                    if cat.get("id") == cat_id:
                        for sg in cat.get("sub_goals", []):
                            tier_lookup[sg["id"]] = "primary"
            for cat_id in aff.get("secondary", []):
                for cat in categories:
                    if cat.get("id") == cat_id:
                        for sg in cat.get("sub_goals", []):
                            tier_lookup[sg["id"]] = "secondary"
            for cat_id in aff.get("excluded", []):
                for cat in categories:
                    if cat.get("id") == cat_id:
                        for sg in cat.get("sub_goals", []):
                            tier_lookup[sg["id"]] = "excluded"

        goal_items = ""
        for cat in categories:
            cat_id = cat.get("id", "")
            cat_name = cat.get("name", "")
            for sg in cat.get("sub_goals", []):
                sg_id = sg.get("id", "")
                sg_name = sg.get("name", "")
                tier = tier_lookup.get(sg_id, "")
                is_selected = sg_id == goal_cat

                # Tier badge
                tier_badge = ""
                if tier == "primary":
                    tier_badge = '<span class="prov-badge prov-badge-green" style="font-size:9px;padding:1px 5px;">PRIMARY</span>'
                elif tier == "secondary":
                    tier_badge = '<span class="prov-badge prov-badge-amber" style="font-size:9px;padding:1px 5px;">SECONDARY</span>'
                elif tier == "excluded":
                    tier_badge = '<span class="prov-badge prov-badge-red prov-dim" style="font-size:9px;padding:1px 5px;">EXCLUDED</span>'

                if is_selected:
                    goal_items += (
                        f'<span class="prov-highlight" data-tooltip="{_esc(cat_name)}: {_esc(sg_name)}">'
                        f"<span style=\"font-family:'SF Mono','Fira Code',monospace;font-size:11px;font-weight:700;"
                        f'color:var(--accent);">{_esc(sg_id)}</span> '
                        f"{tier_badge}"
                        f"</span>"
                    )
                else:
                    dim_cls = " prov-dim" if tier == "excluded" else ""
                    goal_items += (
                        f'<span class="prov-badge prov-badge-muted{dim_cls}"'
                        f' data-tooltip="{_esc(cat_name)}: {_esc(sg_name)}">'
                        f"{_esc(sg_id)} {tier_badge}</span>"
                    )
        if goal_items:
            goals_grid_html = (
                f'<div class="prov-item-row" style="margin-top:6px;">{goal_items}</div>'
            )
    except Exception:  # noqa: BLE001, S110
        pass  # Taxonomy files not available; skip enrichment

    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">4b. Attack Goal</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-kv"><span class="prov-kv-label">Selected</span>'
        f'<span class="prov-kv-value" style="font-weight:600;">'
        f"{_esc(goal_cat)} &mdash; {_esc(goal_name)}</span></div>"
        f'<div class="prov-kv"><span class="prov-kv-label">Category</span>'
        f'<span class="prov-kv-value">{_esc(goal_parent)}</span></div>'
        f"{affinity_html}"
        f"{goals_grid_html}"
        f"</div></div>"
    )

    # --- Step 6: Scenario ATLAS classifications ---
    cf = scenario.get("candidate_filter", {}) or {}
    # Support both plural (new) and singular (old YAML) field names
    pinned_ids_raw = cf.get("pinned_technique_ids") or []
    if not pinned_ids_raw:
        old_id = cf.get("pinned_technique_id", "")
        pinned_ids_raw = [old_id] if old_id else []
    selected_atlas = set(pinned_ids_raw)
    # Get all available techniques from threat surface entry matching this risk card
    all_atlas: list[str] = []
    if threat_surface:
        for entry in threat_surface.get("entries", []):
            entry_rc = entry.get("risk_card", {})
            if entry_rc.get("risk_id") == risk_id:
                all_atlas = entry.get("atlas_technique_ids", [])
                break

    if all_atlas or selected_atlas:
        # Merge to get a complete set
        all_ids = list(dict.fromkeys(list(all_atlas) + list(selected_atlas)))
        atlas_items = ""
        for tid in all_ids:
            name = _ATLAS_TECHNIQUE_NAMES.get(tid, "")
            tip = (
                f' data-tooltip="MITRE ATLAS: {_esc(tid)} &mdash; {_esc(name)}"'
                if name
                else ""
            )
            if tid in selected_atlas:
                atlas_items += (
                    f'<span class="prov-highlight"{tip}>'
                    f"<span style=\"font-family:'SF Mono','Fira Code',monospace;font-size:11px;"
                    f'font-weight:700;color:#f97316;">{_esc(tid)}</span></span>'
                )
            else:
                atlas_items += (
                    f'<span class="prov-badge prov-badge-muted prov-dim"{tip}>'
                    f"{_esc(tid)}</span>"
                )
        atlas_body = f'<div class="prov-item-row">{atlas_items}</div>'
    else:
        atlas_body = '<span class="prov-badge prov-badge-muted">none</span>'

    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">4c. Scenario classifications '
        f'<span style="font-size:9px;color:var(--text-muted);font-variant:normal;">'
        f"(highlighted = pinned for this scenario)</span></div>"
        f'<div class="prov-step-content">{atlas_body}</div></div>'
    )

    # --- Step 5: Entry Point ---
    selected_ep = cp.get("entry_point", "")
    all_eps: list[str] = []
    if capability_profile:
        all_eps = capability_profile.get("entry_points", [])

    if all_eps:
        ep_items = ""
        for ep in all_eps:
            if ep == selected_ep:
                ep_items += (
                    f'<span class="prov-highlight">'
                    f'<span style="font-size:12px;font-weight:600;color:var(--accent);">'
                    f"{_esc(ep)}</span></span>"
                )
            else:
                ep_items += (
                    f'<span class="prov-badge prov-badge-muted prov-dim">'
                    f"{_esc(ep)}</span>"
                )
        ep_body = f'<div class="prov-item-row">{ep_items}</div>'
    elif selected_ep:
        ep_body = (
            f'<span class="prov-badge prov-badge-accent">{_esc(selected_ep)}</span>'
        )
    else:
        ep_body = '<span class="prov-badge prov-badge-muted">none</span>'

    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">5. Entry Point '
        f'<span style="font-size:9px;color:var(--text-muted);font-variant:normal;">'
        f"(highlighted = selected)</span></div>"
        f'<div class="prov-step-content">{ep_body}</div></div>'
    )

    # --- Step 6: Zone Sequence ---
    zones_traversed = cp.get("zones_traversed", [])
    zone_crumbs = ""
    for i, z in enumerate(zones_traversed):
        zn = _normalize_zone(z)
        color = ZONE_COLORS.get(zn, "#666")
        bg = ZONE_BG_COLORS.get(zn, "#333")
        display = ZONE_DISPLAY_NAMES.get(zn, zn)
        zone_crumbs += (
            f'<span class="zone-crumb" style="background:{bg};color:{color};"'
            f' data-tooltip="{_esc(display)}">{_esc(zn)}</span>'
        )
        if i < len(zones_traversed) - 1:
            zone_crumbs += '<span class="zone-crumb-arrow">&rarr;</span>'

    steps.append(
        f'<div class="prov-step">'
        f'<div class="prov-step-label">6. Zone Sequence</div>'
        f'<div class="prov-step-content">'
        f'<div class="zone-breadcrumb">{zone_crumbs}</div>'
        f"</div></div>"
    )

    # --- Candidate Filter Results (optional, between parallel and converge) ---
    candidate_filter = scenario.get("candidate_filter") or {}
    filter_html = ""
    if candidate_filter:
        pinned_ep = candidate_filter.get("pinned_entry_point", "")
        # Support both plural (new) and singular (old YAML) field names
        pinned_tids = candidate_filter.get("pinned_technique_ids") or []
        if not pinned_tids:
            old_tid = candidate_filter.get("pinned_technique_id", "")
            pinned_tids = [old_tid] if old_tid else []
        pinned_tnames = candidate_filter.get("pinned_technique_names") or []
        if not pinned_tnames:
            old_tname = candidate_filter.get("pinned_technique_name", "")
            pinned_tnames = [old_tname] if old_tname else []
        rejections = candidate_filter.get("rejection_rationales", [])

        # Accepted combination badges
        pinned_tid_display = " + ".join(pinned_tids) if pinned_tids else ""
        pinned_tname_display = ", ".join(pinned_tnames) if pinned_tnames else ""
        accepted_html = (
            f'<div style="margin-bottom:8px;">'
            f'<span style="font-size:11px;font-weight:600;color:var(--text-muted);">'
            f"Accepted:</span> "
            f'<span class="prov-accepted-badge">{_esc(pinned_ep)}</span> '
            f'<span class="prov-accepted-badge">'
            f"{_esc(pinned_tid_display)}{': ' + _esc(pinned_tname_display) if pinned_tname_display else ''}"
            f"</span>"
            f"</div>"
        )

        # Rejected combinations collapsible
        rejected_html = ""
        reject_count = len(rejections)
        if reject_count > 0:
            reject_items = ""
            for rv in rejections:
                rv_ep = rv.get("entry_point", "")
                # Support both plural (new) and singular (old YAML) for rejection verdicts
                rv_tids = rv.get("atlas_technique_ids") or []
                if not rv_tids:
                    old_rv_tid = rv.get("atlas_technique_id", "")
                    rv_tids = [old_rv_tid] if old_rv_tid else []
                rv_tid_display = " + ".join(rv_tids)
                rv_rationale = rv.get("rationale", "")
                reject_items += (
                    f'<div class="prov-rejected-row">'
                    f'<span class="prov-badge prov-badge-muted">{_esc(rv_ep)}</span> '
                    f'<span class="prov-badge prov-badge-muted">{_esc(rv_tid_display)}</span>'
                    f'<div class="prov-rationale">{_esc(rv_rationale)}</div>'
                    f"</div>"
                )
            rejected_html = (
                f'<details style="margin-top:6px;">'
                f"<summary>Rejected combinations ({reject_count})</summary>"
                f'<div style="margin-top:6px;">{reject_items}</div>'
                f"</details>"
            )

        filter_html = (
            f'<div class="prov-filter-results">'
            f'<div class="prov-step-label">Candidate Filter Results</div>'
            f'<div class="prov-step-content">'
            f"{accepted_html}"
            f"{rejected_html}"
            f"</div></div>"
        )

    # Assemble with arrows -- steps 0-2 vertical, 3-5 parallel, 6-7 vertical
    parts: list[str] = []

    # Steps 0-2: vertical chain with arrows
    for i in range(3):
        parts.append(steps[i])
        parts.append(arrow)

    # Fork label
    parts.append(
        '<div class="prov-fork-label">&#9662; parallel inputs to generation</div>'
    )

    # Steps 3-5: parallel row (Attack Pattern, Attack Goal, ATLAS Techniques)
    parts.append(f'<div class="prov-parallel-row">{steps[3]}{steps[4]}{steps[5]}</div>')

    # Candidate filter results (if available)
    if filter_html:
        parts.append(arrow)
        parts.append(filter_html)

    # Merge arrow
    parts.append('<div class="prov-fork-label">&#9662; converge</div>')

    # Steps 6-7: vertical chain with arrow between them
    parts.append(steps[6])
    parts.append(arrow)
    parts.append(steps[7])

    return f'<div class="prov-chain">{"".join(parts)}</div>'
