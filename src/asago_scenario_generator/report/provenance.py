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


def _record_threat_description(threat_id: str, info: dict[str, Any]) -> None:
    """Record a non-empty threat description under *threat_id*."""
    desc = info.get("description", "")
    if desc:
        _THREAT_DESCRIPTIONS[threat_id] = desc.strip()


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
        _record_threat_description(tid, info)


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


# ---------------------------------------------------------------------------
# Small display/lookup helpers
# ---------------------------------------------------------------------------


def _meta_text_or_default(meta: dict[str, Any], key: str, default: str = "") -> str:
    """Return ``meta[key]`` when truthy, else *default* ('' by default)."""
    value = meta.get(key)
    if value:
        return value
    return default


def _meta_list_or_default(meta: dict[str, Any], key: str) -> list[Any]:
    """Return ``meta[key]`` when truthy, else ``[]``."""
    value = meta.get(key)
    if value:
        return value
    return []


def _meta_text_with_fallback(
    meta: dict[str, Any], primary_key: str, fallback_key: str
) -> str:
    """Return the primary value, falling back to *fallback_key* when empty."""
    value = meta.get(primary_key)
    if value:
        return value
    return meta.get(fallback_key, "")


def _scenario_dict(scenario: dict[str, Any], key: str) -> dict[str, Any]:
    """Return ``scenario[key]`` when truthy, else ``{}``."""
    value = scenario.get(key)
    if value:
        return value
    return {}


def _join_text(values: list[str], sep: str) -> str:
    """Join *values* with *sep*, or '' when empty."""
    if values:
        return sep.join(values)
    return ""


def _join_escaped(values: list[Any]) -> str:
    """Escape and join values with ', '."""
    return ", ".join(_esc(value) for value in values)


def _join_nonempty(items: list[str]) -> str:
    """Join non-empty strings with a single space."""
    kept = []
    for item in items:
        if item:
            kept.append(item)
    return " ".join(kept)


def _reject(values: list[Any], excluded: Any) -> list[Any]:
    """Return *values* without *excluded*, preserving order."""
    kept = []
    for value in values:
        if value != excluded:
            kept.append(value)
    return kept


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


def _seed_provenance_parts(
    seed_meta: dict[str, Any] | None,
) -> tuple[str, list[str], list[str]]:
    """Extract (owasp_origin, laaf ids, atlas ids) from seed metadata."""
    if not seed_meta:
        return "", [], []
    owasp_origin = _meta_text_or_default(seed_meta, "owasp_origin")
    laaf = _meta_list_or_default(seed_meta, "laaf_technique_ids")
    atlas = _meta_list_or_default(seed_meta, "atlas_provenance_ids")
    return owasp_origin, laaf, atlas


def _provenance_labels(laaf: list[str], atlas: list[str]) -> list[str]:
    """Build LAAF/ATLAS provenance label parts from id lists."""
    labels = []
    if laaf:
        labels.append(f"LAAF: {_join_escaped(laaf)}")
    if atlas:
        labels.append(f"ATLAS: {_join_escaped(atlas)}")
    return labels


def _provenance_suffix(laaf: list[str], atlas: list[str]) -> str:
    """Build the '| Provenance: ...' suffix from LAAF/ATLAS id lists."""
    labels = _provenance_labels(laaf, atlas)
    if not labels:
        return ""
    return f" | Provenance: {'; '.join(labels)}"


def _attack_pattern_tooltip(ap_id: str, seed_meta: dict[str, Any] | None = None) -> str:
    """Return a data-tooltip attribute for an attack pattern ID like 'AP-T7-01'.

    When *seed_meta* (scenario_seed_metadata dict) is provided, provenance
    data is read from it instead of from the module-level _ATTACK_PATTERN_INFO.
    """
    if ap_id not in _ATTACK_PATTERN_INFO:
        return ""
    info = _ATTACK_PATTERN_INFO[ap_id]
    name = _esc(info["name"])
    desc = _truncate(_esc(info["description"]), 200)
    # Provenance comes from seed metadata when available
    owasp_origin, laaf, atlas = _seed_provenance_parts(seed_meta)
    origin_suffix = f" (derived from {_esc(owasp_origin)})" if owasp_origin else ""
    prov_suffix = _provenance_suffix(laaf, atlas)
    return f' data-tooltip="{name}: {desc}{origin_suffix}{prov_suffix}"'


def _technique_id_tooltip(technique_id: str) -> str:
    """Return a data-tooltip attribute for an ATLAS technique ID."""
    name = _ATLAS_TECHNIQUE_NAMES.get(technique_id, "")
    if not name:
        return ""
    desc = ATLAS_TECHNIQUE_DESCRIPTIONS.get(technique_id, "")
    if desc:
        return f' data-tooltip="{_esc(technique_id)} — {_esc(name)}&#10;{_esc(desc)}"'
    return f' data-tooltip="MITRE ATLAS: {_esc(technique_id)} — {_esc(name)}"'


# ---------------------------------------------------------------------------
# SSSOM provenance block
# ---------------------------------------------------------------------------


def _build_origin_row(owasp_origin: str) -> str:
    """Render the OWASP origin row of the SSSOM provenance block."""
    if not owasp_origin:
        return ""
    origin_tip = _attack_pattern_tooltip(owasp_origin)
    return (
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
        f'<span style="min-width:100px;font-size:11px;font-weight:600;'
        f'color:var(--text-muted);text-transform:uppercase;">Origin</span>'
        f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
        f"font-weight:600;background:rgba(99,102,241,0.15);"
        f"color:var(--accent);font-family:'SF Mono','Fira Code',"
        f'monospace;"{origin_tip}>{_esc(owasp_origin)}</span>'
        f"</div>"
    )


def _build_laaf_row(laaf: list[str]) -> str:
    """Render the LAAF correspondences row of the SSSOM provenance block."""
    if not laaf:
        return ""
    laaf_badges = "".join(
        f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
        f"font-weight:600;background:rgba(34,197,94,0.15);"
        f"color:#22c55e;font-family:'SF Mono','Fira Code',"
        f'monospace;margin-right:4px;">{_esc(lid)}</span>'
        for lid in laaf
    )
    return (
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;'
        f'flex-wrap:wrap;">'
        f'<span style="min-width:100px;font-size:11px;font-weight:600;'
        f'color:var(--text-muted);text-transform:uppercase;"'
        f' data-tooltip="LLM Agent Attack Framework technique correspondences"'
        f">LAAF</span>"
        f"{laaf_badges}"
        f"</div>"
    )


def _build_atlas_row(atlas: list[str]) -> str:
    """Render the ATLAS correspondences row of the SSSOM provenance block."""
    if not atlas:
        return ""
    atlas_badges = "".join(
        f'<span style="padding:3px 10px;border-radius:4px;font-size:12px;'
        f"font-weight:600;background:rgba(249,115,22,0.15);"
        f"color:#f97316;font-family:'SF Mono','Fira Code',"
        f'monospace;margin-right:4px;"'
        f"{_technique_id_tooltip(aid)}>{_esc(aid)}</span>"
        for aid in atlas
    )
    return (
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;'
        f'flex-wrap:wrap;">'
        f'<span style="min-width:100px;font-size:11px;font-weight:600;'
        f'color:var(--text-muted);text-transform:uppercase;"'
        f' data-tooltip="MITRE ATLAS technique correspondences"'
        f">ATLAS</span>"
        f"{atlas_badges}"
        f"</div>"
    )


def _build_provenance_block(scenario: dict[str, Any]) -> str:
    """Build a Provenance section for AP-* scenario seeds.

    Reads provenance data (OWASP origin, LAAF correspondences, ATLAS
    correspondences) from the scenario's ``scenario_seed_metadata`` dict
    instead of from the module-level SSSOM-loaded lookup tables.

    Returns empty string for non-AP seeds or when no provenance data exists.
    """
    meta = scenario.get("scenario_seed_metadata")
    if not meta:
        return ""
    scenario_seed = meta.get("seed_id", "")

    if not scenario_seed.startswith("AP-"):
        return ""

    owasp_origin, laaf, atlas = _seed_provenance_parts(meta)

    rows = ""
    rows += _build_origin_row(owasp_origin)
    rows += _build_laaf_row(laaf)
    rows += _build_atlas_row(atlas)

    if not rows:
        return ""

    return f"""
        <div class="scenario-section">
          <details class="expandable" open>
            <summary>SSSOM Provenance</summary>
            <div style="padding:12px 0 4px;">
              {rows}
            </div>
          </details>
        </div>"""


# ---------------------------------------------------------------------------
# Scenario Seed block
# ---------------------------------------------------------------------------


def _build_seed_threat_span(threat_id: str, threat_name: str) -> str:
    """Render the Threat span for the Scenario Seed block."""
    if not threat_id:
        return ""
    tip = _threat_id_tooltip(threat_id)
    threat_label = (
        f"{_esc(threat_id)} &mdash; {_esc(threat_name)}"
        if threat_name
        else _esc(threat_id)
    )
    return f"<span><strong>Threat:</strong> <span{tip}>{threat_label}</span></span>"


def _build_seed_origin_span(owasp_origin: str) -> str:
    """Render the Origin span for the Scenario Seed block."""
    if not owasp_origin:
        return ""
    origin_tip = _attack_pattern_tooltip(owasp_origin)
    return (
        f"<span><strong>Origin:</strong> "
        f"<span{origin_tip}>{_esc(owasp_origin)}</span></span>"
    )


def _build_seed_id_span(seed_id: str) -> str:
    """Render the Seed ID span for the Scenario Seed block."""
    if not seed_id:
        return ""
    return f"<span><strong>Seed:</strong> {_esc(seed_id)}</span>"


def _build_seed_desc_html(attack_pattern_description: str) -> str:
    """Render the (truncated) attack pattern description for the seed block."""
    if not attack_pattern_description:
        return ""
    return (
        f'<div style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;">'
        f"{_esc(attack_pattern_description)}"
        f"</div>"
    )


def _build_seed_name_html(attack_pattern_name: str) -> str:
    """Render the attack pattern name for the seed block."""
    if not attack_pattern_name:
        return ""
    return (
        f'<div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">'
        f"{_esc(attack_pattern_name)}"
        f"</div>"
    )


def _build_seed_metadata_block(scenario: dict[str, Any]) -> str:
    """Build a Scenario Seed section from scenario_seed_metadata.

    Returns an HTML block showing the seed's attack pattern name, description,
    threat context, and OWASP origin. Returns empty string when metadata
    is absent.
    """
    meta = scenario.get("scenario_seed_metadata")
    if not meta:
        return ""

    attack_pattern_name = _meta_text_with_fallback(
        meta, "attack_pattern_name", "mechanism_name"
    )
    attack_pattern_description = _meta_text_with_fallback(
        meta, "attack_pattern_description", "mechanism_description"
    )
    seed_id = meta.get("seed_id", "")
    threat_id = meta.get("threat_id", "")
    threat_name = meta.get("threat_name", "")
    owasp_origin = meta.get("owasp_origin", "")

    if not attack_pattern_name:
        if not seed_id:
            return ""

    seed_html = _build_seed_id_span(seed_id)
    threat_html = _build_seed_threat_span(threat_id, threat_name)
    origin_html = _build_seed_origin_span(owasp_origin)
    meta_row_items = _join_nonempty((seed_html, threat_html, origin_html))
    desc_html = _build_seed_desc_html(attack_pattern_description)
    name_html = _build_seed_name_html(attack_pattern_name)

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


# ---------------------------------------------------------------------------
# Provenance chain steps
# ---------------------------------------------------------------------------


def _format_confidence(confidence: Any) -> str:
    """Format a risk-card confidence value for display."""
    if isinstance(confidence, (int, float)):
        return f"{confidence:.2f}"
    return str(confidence)


def _build_risk_card_step(rc: dict[str, Any]) -> str:
    """Render step 1 (Risk Card) of the provenance chain."""
    risk_id = rc.get("risk_id", "")
    risk_name = rc.get("risk_name", "")
    taxonomy = rc.get("taxonomy", "")
    confidence = rc.get("confidence", 0)
    conf_display = _format_confidence(confidence)
    taxonomy_badge = (
        f'<span class="prov-badge prov-badge-accent">{_esc(taxonomy)}</span>'
        if taxonomy
        else ""
    )
    return (
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


def _build_owasp_step(tc: dict[str, Any]) -> str:
    """Render step 2 (OWASP LLM IDs) of the provenance chain."""
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
    return (
        f'<div class="prov-step">'
        f'<div class="prov-step-label">2. OWASP LLM IDs &mdash; SSSOM Mapping</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-item-row">{owasp_badges}</div>'
        f"</div></div>"
    )


def _build_agentic_threats_step(tc: dict[str, Any]) -> str:
    """Render step 3 (Agentic Threats) of the provenance chain."""
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
    return (
        f'<div class="prov-step">'
        f'<div class="prov-step-label">3. Agentic Threats (surviving)</div>'
        f'<div class="prov-step-content">'
        f'<div class="prov-item-row">{threat_badges}</div>'
        f"</div></div>"
    )


def _collect_attack_pattern_ids(
    threat_surface: dict[str, Any] | None, seed_threat_id: str
) -> list[str]:
    """Collect deduplicated attack pattern IDs whose entry matches the seed threat."""
    if not threat_surface:
        return []
    if not seed_threat_id:
        return []
    all_ap_ids: list[str] = []
    for entry in threat_surface.get("entries", []):
        if seed_threat_id in entry.get("agentic_threat_ids", []):
            all_ap_ids.extend(entry.get("attack_pattern_ids", []))
    # Deduplicate while preserving order
    return list(dict.fromkeys(all_ap_ids))


def _build_ap_selection(ap_ids: list[str], seed_id: str) -> str:
    """Render the attack-pattern selection row for step 4a."""
    if not ap_ids:
        return ""
    ap_items = ""
    for ap_id in ap_ids:
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
    return f'<div class="prov-item-row" style="margin-top:6px;">{ap_items}</div>'


def _build_attack_pattern_step(
    meta: dict[str, Any], threat_surface: dict[str, Any] | None
) -> str:
    """Render step 4a (Attack Pattern) of the provenance chain."""
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
    all_ap_ids = _collect_attack_pattern_ids(threat_surface, seed_threat_id)
    ap_selection_html = _build_ap_selection(all_ap_ids, seed_id)

    return (
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


def _load_goals_taxonomy() -> tuple[dict[str, Any], list[Any]]:
    """Load threat-goal affinity and goal taxonomy; empty on failure."""
    try:
        affinity_map = load_threat_goal_affinity()
        goals_taxonomy = load_attack_goals_taxonomy()
        return affinity_map, goals_taxonomy.get("categories", [])
    except Exception:  # noqa: BLE001, S110
        return {}, []


def _find_goal_category(categories: list[Any], goal_cat: str) -> str:
    """Return the category id whose sub-goal matches *goal_cat*, or ''."""
    for cat in categories:
        for sg in cat.get("sub_goals", []):
            if sg.get("id") == goal_cat:
                return cat.get("id", "")
    return ""


def _tier_context_parts(entries: list[tuple[str, list[str]]]) -> list[str]:
    """Build 'label: items' context parts for non-empty *entries*."""
    parts = []
    for label, cats in entries:
        if cats:
            parts.append(f"{label}: {', '.join(cats)}")
    return parts


def _goal_tier_context(
    primary_cats: list[str], secondary_cats: list[str], selected_cat_id: str
) -> tuple[str, list[str] | None]:
    """Classify the selected goal category tier.

    Returns ``(badge_html, context_parts)`` for a known tier, or
    ``("", None)`` when the category cannot be classified.
    """
    if selected_cat_id in primary_cats:
        badge = '<span class="prov-badge prov-badge-green">primary</span>'
        entries = (
            ("also primary", _reject(primary_cats, selected_cat_id)),
            ("secondary", secondary_cats),
        )
    elif selected_cat_id in secondary_cats:
        badge = '<span class="prov-badge prov-badge-amber">secondary</span>'
        entries = (
            ("primary", primary_cats),
            ("also secondary", _reject(secondary_cats, selected_cat_id)),
        )
    else:
        return "", None
    return badge, _tier_context_parts(entries)


def _goal_context_span(
    primary_cats: list[str], secondary_cats: list[str], parts: list[str] | None
) -> str:
    """Render the affinity context span; *parts* None means unclassified tier."""
    if parts is None:
        primary_str = ", ".join(primary_cats)
        secondary_str = ", ".join(secondary_cats)
        return (
            f' <span style="color:var(--text-muted);">'
            f"(primary: {_esc(primary_str)} | secondary: {_esc(secondary_str)})</span>"
        )
    if not parts:
        return ""
    return f' <span style="color:var(--text-muted);">({" | ".join(parts)})</span>'


def _build_affinity_block(
    affinity_map: dict[str, Any],
    categories: list[Any],
    seed_threat_id: str,
    goal_cat: str,
    goal_parent: str,
) -> str:
    """Render the plain-language affinity explanation for the selected goal."""
    if seed_threat_id not in affinity_map:
        return ""
    aff = affinity_map[seed_threat_id]
    primary_cats = aff.get("primary", [])
    secondary_cats = aff.get("secondary", [])

    selected_cat_id = _find_goal_category(categories, goal_cat)
    badge, parts = _goal_tier_context(primary_cats, secondary_cats, selected_cat_id)
    context_span = _goal_context_span(primary_cats, secondary_cats, parts)

    display_id = selected_cat_id
    if not display_id:
        display_id = goal_parent

    return (
        f'<div style="margin:6px 0 8px;padding:8px 12px;background:var(--bg-primary);'
        f'border-radius:6px;border:1px solid var(--border);font-size:12px;">'
        f"&lsquo;{_esc(display_id)}&rsquo; &mdash; "
        f"{badge} affinity for {_esc(seed_threat_id)}"
        f"{context_span}"
        f"</div>"
    )


def _tier_id_groups(aff: dict[str, Any]) -> dict[str, list[str]]:
    """Threat-affinity category id groups per tier."""
    return {
        "primary": aff.get("primary", []),
        "secondary": aff.get("secondary", []),
        "excluded": aff.get("excluded", []),
    }


def _assign_tier_for_category(
    lookup: dict[str, str], categories: list[Any], cat_id: str, tier: str
) -> None:
    """Record every sub-goal of *cat_id* under *tier* in *lookup*."""
    for cat in categories:
        if cat.get("id") == cat_id:
            for sg in cat.get("sub_goals", []):
                lookup[sg["id"]] = tier


def _build_tier_lookup(
    affinity_map: dict[str, Any], categories: list[Any], seed_threat_id: str
) -> dict[str, str]:
    """Map every sub-goal id to its affinity tier for the scenario's threat."""
    lookup: dict[str, str] = {}
    if seed_threat_id not in affinity_map:
        return lookup
    aff = affinity_map[seed_threat_id]
    for tier, cat_ids in _tier_id_groups(aff).items():
        for cat_id in cat_ids:
            _assign_tier_for_category(lookup, categories, cat_id, tier)
    return lookup


_TIER_BADGES: dict[str, str] = {
    "primary": (
        '<span class="prov-badge prov-badge-green" style="font-size:9px;'
        'padding:1px 5px;">PRIMARY</span>'
    ),
    "secondary": (
        '<span class="prov-badge prov-badge-amber" style="font-size:9px;'
        'padding:1px 5px;">SECONDARY</span>'
    ),
    "excluded": (
        '<span class="prov-badge prov-badge-red prov-dim" style="font-size:9px;'
        'padding:1px 5px;">EXCLUDED</span>'
    ),
}


def _goal_item_html(sg: dict[str, Any], tier: str, goal_cat: str, cat_name: str) -> str:
    """Render one sub-goal badge for the goals grid."""
    sg_id = sg.get("id", "")
    sg_name = sg.get("name", "")
    is_selected = sg_id == goal_cat

    tier_badge = _TIER_BADGES.get(tier, "")
    tip = f' data-tooltip="{_esc(cat_name)}: {_esc(sg_name)}"'
    if is_selected:
        return (
            f'<span class="prov-highlight"{tip}>'
            f"<span style=\"font-family:'SF Mono','Fira Code',monospace;font-size:11px;font-weight:700;"
            f'color:var(--accent);">{_esc(sg_id)}</span> '
            f"{tier_badge}"
            f"</span>"
        )
    dim_cls = ""
    if tier == "excluded":
        dim_cls = " prov-dim"
    return (
        f'<span class="prov-badge prov-badge-muted{dim_cls}"'
        f"{tip}>"
        f"{_esc(sg_id)} {tier_badge}</span>"
    )


def _build_goal_grid(
    categories: list[Any], tier_lookup: dict[str, str], goal_cat: str
) -> str:
    """Render the sub-goal badge grid for step 4b, or '' when no goals exist."""
    goal_items = ""
    for cat in categories:
        cat_name = cat.get("name", "")
        for sg in cat.get("sub_goals", []):
            sg_id = sg.get("id", "")
            tier = tier_lookup.get(sg_id, "")
            goal_items += _goal_item_html(sg, tier, goal_cat, cat_name)
    if not goal_items:
        return ""
    return f'<div class="prov-item-row" style="margin-top:6px;">{goal_items}</div>'


def _build_attack_goal_step(seed_threat_id: str, actor: dict[str, Any]) -> str:
    """Render step 4b (Attack Goal) of the provenance chain."""
    goal_cat = actor.get("goal_category", "")
    goal_name = actor.get("goal_category_name", "")
    goal_parent = actor.get("goal_category_parent", "")

    affinity_map, categories = _load_goals_taxonomy()
    affinity_html = _build_affinity_block(
        affinity_map, categories, seed_threat_id, goal_cat, goal_parent
    )
    tier_lookup = _build_tier_lookup(affinity_map, categories, seed_threat_id)
    goals_grid_html = _build_goal_grid(categories, tier_lookup, goal_cat)

    return (
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


def _field_values_or_legacy(
    data: dict[str, Any], plural_key: str, singular_key: str
) -> list[str]:
    """Return plural field values, falling back to a legacy singular field."""
    values = _meta_list_or_default(data, plural_key)
    if values:
        return values
    old = data.get(singular_key, "")
    if old:
        return [old]
    return []


def _collect_atlas_for_risk_card(
    threat_surface: dict[str, Any] | None, risk_id: str
) -> list[str]:
    """Return the first entry's ATLAS techniques whose risk card matches *risk_id*."""
    if not threat_surface:
        return []
    for entry in threat_surface.get("entries", []):
        entry_rc = entry.get("risk_card", {})
        if entry_rc.get("risk_id") == risk_id:
            return entry.get("atlas_technique_ids", [])
    return []


def _build_atlas_items(all_ids: list[str], selected_atlas: set[str]) -> str:
    """Render ATLAS technique badges, highlighting pinned techniques."""
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
    return atlas_items


def _build_atlas_step(
    cf: dict[str, Any], risk_id: str, threat_surface: dict[str, Any] | None
) -> str:
    """Render step 4c (Scenario ATLAS classifications) of the provenance chain."""
    pinned_ids_raw = _field_values_or_legacy(
        cf, "pinned_technique_ids", "pinned_technique_id"
    )
    selected_atlas = set(pinned_ids_raw)
    all_atlas = _collect_atlas_for_risk_card(threat_surface, risk_id)

    if all_atlas:
        atlas_body = f'<div class="prov-item-row">{_build_atlas_items(_atlas_merge(all_atlas, selected_atlas), selected_atlas)}</div>'
    elif selected_atlas:
        atlas_body = f'<div class="prov-item-row">{_build_atlas_items(_atlas_merge(all_atlas, selected_atlas), selected_atlas)}</div>'
    else:
        atlas_body = '<span class="prov-badge prov-badge-muted">none</span>'

    return (
        f'<div class="prov-step">'
        f'<div class="prov-step-label">4c. Scenario classifications '
        f'<span style="font-size:9px;color:var(--text-muted);font-variant:normal;">'
        f"(highlighted = pinned for this scenario)</span></div>"
        f'<div class="prov-step-content">{atlas_body}</div></div>'
    )


def _atlas_merge(all_atlas: list[str], selected_atlas: set[str]) -> list[str]:
    """Merge available and selected ATLAS ids, deduplicated in order."""
    return list(dict.fromkeys(list(all_atlas) + list(selected_atlas)))


def _build_ep_badges(all_eps: list[str], selected_ep: str) -> str:
    """Render entry-point badges, highlighting the selected one."""
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
                f'<span class="prov-badge prov-badge-muted prov-dim">{_esc(ep)}</span>'
            )
    return f'<div class="prov-item-row">{ep_items}</div>'


def _build_entry_point_step(
    cp: dict[str, Any], capability_profile: dict[str, Any] | None
) -> str:
    """Render step 5 (Entry Point) of the provenance chain."""
    selected_ep = cp.get("entry_point", "")
    all_eps = capability_profile.get("entry_points", []) if capability_profile else []

    if all_eps:
        ep_body = _build_ep_badges(all_eps, selected_ep)
    elif selected_ep:
        ep_body = (
            f'<span class="prov-badge prov-badge-accent">{_esc(selected_ep)}</span>'
        )
    else:
        ep_body = '<span class="prov-badge prov-badge-muted">none</span>'

    return (
        f'<div class="prov-step">'
        f'<div class="prov-step-label">5. Entry Point '
        f'<span style="font-size:9px;color:var(--text-muted);font-variant:normal;">'
        f"(highlighted = selected)</span></div>"
        f'<div class="prov-step-content">{ep_body}</div></div>'
    )


def _build_zone_crumbs(zones: list[Any]) -> str:
    """Render the zone-sequence breadcrumb trail."""
    zone_crumbs = ""
    for i, z in enumerate(zones):
        zn = _normalize_zone(z)
        color = ZONE_COLORS.get(zn, "#666")
        bg = ZONE_BG_COLORS.get(zn, "#333")
        display = ZONE_DISPLAY_NAMES.get(zn, zn)
        zone_crumbs += (
            f'<span class="zone-crumb" style="background:{bg};color:{color};"'
            f' data-tooltip="{_esc(display)}">{_esc(zn)}</span>'
        )
        if i < len(zones) - 1:
            zone_crumbs += '<span class="zone-crumb-arrow">&rarr;</span>'
    return zone_crumbs


def _build_zone_sequence_step(cp: dict[str, Any]) -> str:
    """Render step 6 (Zone Sequence) of the provenance chain."""
    zones_traversed = cp.get("zones_traversed", [])
    zone_crumbs = _build_zone_crumbs(zones_traversed)
    return (
        f'<div class="prov-step">'
        f'<div class="prov-step-label">6. Zone Sequence</div>'
        f'<div class="prov-step-content">'
        f'<div class="zone-breadcrumb">{zone_crumbs}</div>'
        f"</div></div>"
    )


def _build_rejected_combinations(rejections: list[dict[str, Any]]) -> str:
    """Render the rejected-combinations collapsible for candidate filter results."""
    reject_count = len(rejections)
    if reject_count < 1:
        return ""
    reject_items = ""
    for rv in rejections:
        rv_ep = rv.get("entry_point", "")
        rv_tids = _field_values_or_legacy(
            rv, "atlas_technique_ids", "atlas_technique_id"
        )
        rv_tid_display = _join_text(rv_tids, " + ")
        rv_rationale = rv.get("rationale", "")
        reject_items += (
            f'<div class="prov-rejected-row">'
            f'<span class="prov-badge prov-badge-muted">{_esc(rv_ep)}</span> '
            f'<span class="prov-badge prov-badge-muted">{_esc(rv_tid_display)}</span>'
            f'<div class="prov-rationale">{_esc(rv_rationale)}</div>'
            f"</div>"
        )
    return (
        f'<details style="margin-top:6px;">'
        f"<summary>Rejected combinations ({reject_count})</summary>"
        f'<div style="margin-top:6px;">{reject_items}</div>'
        f"</details>"
    )


def _build_accepted_badges(
    pinned_ep: str, pinned_tids: list[str], pinned_tnames: list[str]
) -> str:
    """Render the accepted-combination badges for candidate filter results."""
    pinned_tid_display = _join_text(pinned_tids, " + ")
    pinned_tname_display = _join_text(pinned_tnames, ", ")
    tid_name_suffix = ""
    if pinned_tname_display:
        tid_name_suffix = ": " + _esc(pinned_tname_display)
    return (
        f'<div style="margin-bottom:8px;">'
        f'<span style="font-size:11px;font-weight:600;color:var(--text-muted);">'
        f"Accepted:</span> "
        f'<span class="prov-accepted-badge">{_esc(pinned_ep)}</span> '
        f'<span class="prov-accepted-badge">'
        f"{_esc(pinned_tid_display)}{tid_name_suffix}"
        f"</span>"
        f"</div>"
    )


def _build_candidate_filter_block(candidate_filter: dict[str, Any] | None) -> str:
    """Render the Candidate Filter Results block, or '' when absent."""
    if not candidate_filter:
        return ""
    pinned_ep = candidate_filter.get("pinned_entry_point", "")
    pinned_tids = _field_values_or_legacy(
        candidate_filter, "pinned_technique_ids", "pinned_technique_id"
    )
    pinned_tnames = _field_values_or_legacy(
        candidate_filter, "pinned_technique_names", "pinned_technique_name"
    )
    rejections = candidate_filter.get("rejection_rationales", [])

    accepted_html = _build_accepted_badges(pinned_ep, pinned_tids, pinned_tnames)
    rejected_html = _build_rejected_combinations(rejections)

    return (
        f'<div class="prov-filter-results">'
        f'<div class="prov-step-label">Candidate Filter Results</div>'
        f'<div class="prov-step-content">'
        f"{accepted_html}"
        f"{rejected_html}"
        f"</div></div>"
    )


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
    meta = _scenario_dict(scenario, "scenario_seed_metadata")
    actor = _scenario_dict(scenario, "actor_profile")
    cf = _scenario_dict(scenario, "candidate_filter")

    seed_threat_id = meta.get("threat_id", "")
    risk_id = rc.get("risk_id", "")

    arrow = '<div class="prov-arrow">&#9660;</div>'

    steps: list[str] = [
        _build_risk_card_step(rc),
        _build_owasp_step(tc),
        _build_agentic_threats_step(tc),
        _build_attack_pattern_step(meta, threat_surface),
        _build_attack_goal_step(seed_threat_id, actor),
        _build_atlas_step(cf, risk_id, threat_surface),
        _build_entry_point_step(cp, capability_profile),
        _build_zone_sequence_step(cp),
    ]

    filter_html = _build_candidate_filter_block(cf)

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
