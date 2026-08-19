"""HTML template components for the asago-scenario-generator report.

CSS styles, JavaScript interactivity, and HTML section builders.
Each section builder is a function returning an HTML string.
"""

from __future__ import annotations

import html
import json
import logging
import math
import re
from numbers import Real
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_DESCRIPTIONS
from asago_scenario_generator.data.loaders import (
    load_attack_goals_taxonomy,
    load_attack_patterns,
    load_kc_threat_mapping,
    load_threat_goal_affinity,
)
from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    CapabilityProfile,
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

# Tooltip strings for structural_exposure enum values
_STRUCTURAL_EXPOSURE_TOOLTIPS: dict[str, str] = {
    "single_point_of_failure": "Only one control blocks this attack path",
    "convergence_point": "Multiple attack paths flow through this single control",
    "probabilistic_control": (
        "Relies on an LLM guardrail or classifier — not a binary pass/fail gate"
    ),
    "defense_in_depth_claim": ("Multiple controls back each other up on this path"),
}

# Tooltip strings for gate types
_GATE_TOOLTIPS: dict[str, str] = {
    "AND": "All child steps must succeed for this attack to proceed",
    "OR": "Any one child step is sufficient for this attack to proceed",
    "LEAF": "Concrete attack action — no sub-steps",
}

# Tooltip strings for priority signal fields
_SIGNAL_TOOLTIPS: dict[str, str] = {
    "technique_maturity": (
        "How proven this attack technique is: feasible (theoretically possible), "
        "demonstrated (shown in lab), realized (observed in the wild)"
    ),
    "architecture_match": (
        "How the threat maps to this system: explicit (directly matches a "
        "declared capability) or inferred (indirectly relevant based on "
        "system profile)"
    ),
    "attack_complexity": "Difficulty of executing this attack: low/medium/high",
    "risk_impact": "Potential damage if attack succeeds: low/medium/high/critical",
    "risk_likelihood": "Probability of this attack being attempted: low/medium/high",
    "structural_exposure": (
        "How exposed this attack path is based on the defensive architecture"
    ),
}

# ---------------------------------------------------------------------------
# Signal → numeric mapping for bar-chart decomposition
# ---------------------------------------------------------------------------

_SIGNAL_NUMERIC: dict[str, dict[str, float]] = {
    "technique_maturity": {
        "theoretical": 0.17,
        "feasible": 0.33,
        "demonstrated": 0.67,
        "realized": 1.0,
    },
    "risk_impact": {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75,
        "critical": 1.0,
    },
    "risk_likelihood": {
        "low": 0.33,
        "medium": 0.67,
        "high": 1.0,
    },
    "attack_complexity": {
        # INVERTED — high complexity = harder = lower score contribution
        "high": 0.33,
        "medium": 0.67,
        "low": 1.0,
    },
    "architecture_match": {
        "none": 0.0,
        "inferred": 0.5,
        "implicit": 0.5,
        "explicit": 1.0,
    },
    "structural_exposure": {
        "none": 0.0,
        "defense_in_depth_claim": 0.25,
        "probabilistic_control": 0.5,
        "convergence_point": 0.75,
        "single_point_of_failure": 1.0,
    },
}

# Ordered list of signals and their display colors
_SIGNAL_COLORS: list[tuple[str, str, str]] = [
    ("technique_maturity", "#6366f1", "Technique Maturity"),
    ("risk_impact", "#ef4444", "Risk Impact"),
    ("risk_likelihood", "#f59e0b", "Risk Likelihood"),
    ("attack_complexity", "#06b6d4", "Attack Complexity"),
    ("architecture_match", "#8b5cf6", "Architecture Match"),
    ("structural_exposure", "#ec4899", "Structural Exposure"),
]

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


def _esc(text: str | None) -> str:
    """HTML-escape text safely."""
    if text is None:
        return ""
    return html.escape(str(text))


_USAGE_METRIC_FIELDS: tuple[str, ...] = (
    "prompt_tokens",
    "completion_tokens",
    "duration_ms",
)


def _is_valid_usage_metric(value: Any) -> bool:
    """Return whether a usage value is a finite real number."""
    if isinstance(value, bool):
        return False
    if not isinstance(value, Real):
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    return True


def _usage_metrics(
    entry: dict[str, Any],
    *,
    call_label: str,
) -> dict[str, int | float | None]:
    """Validate and normalize usage metrics from one call-log entry.

    Missing fields retain the historical zero default.  Explicit ``None``
    means that telemetry was unavailable and is kept as ``None`` for display,
    while totals treat it as zero.  Values of any other nonnumeric type are
    rejected before report rendering can attempt arithmetic on them.
    """
    metrics: dict[str, int | float | None] = {}
    for field in _USAGE_METRIC_FIELDS:
        value = entry.get(field, 0)
        if value is None:
            metrics[field] = None
            continue
        if not _is_valid_usage_metric(value):
            raise ValueError(
                f"Invalid usage metric {field}={value!r} for call "
                f"{call_label!r}; expected a finite number or null."
            )
        metrics[field] = value
    return metrics


def _usage_call_label(entry: dict[str, Any], index: int) -> str:
    """Return a stable, user-facing label for a call-log entry."""
    return str(entry.get("call") or entry.get("step") or f"call {index}")


def _usage_warning_html(
    call_label: str,
    metrics: dict[str, int | float | None],
) -> str:
    """Render a warning for the unavailable fields in one call."""
    unavailable = [field for field in _USAGE_METRIC_FIELDS if metrics[field] is None]
    if not unavailable:
        return ""
    fields = ", ".join(unavailable)
    return (
        '<div class="warning-banner" role="status">'
        '<span class="warning-banner-icon">!</span>'
        f"<span>Warning: call <strong>{_esc(call_label)}</strong> has "
        f"unavailable usage metrics: {_esc(fields)}.</span>"
        "</div>"
    )


def _usage_summary(metrics: dict[str, int | float | None]) -> str:
    """Format usage metrics, preserving the established numeric layout."""
    if all(metrics[field] is not None for field in _USAGE_METRIC_FIELDS):
        return (
            f"{metrics['prompt_tokens']} prompt / "
            f"{metrics['completion_tokens']} completion tokens, "
            f"{metrics['duration_ms']}ms"
        )
    return ", ".join(
        f"{field}={'unavailable' if metrics[field] is None else metrics[field]}"
        for field in _USAGE_METRIC_FIELDS
    )


def _usage_failure_suffix(entry: dict[str, Any]) -> str:
    """Format the failure marker for a call-log entry when needed."""
    if entry.get("success", True):
        return ""
    error = _esc(str(entry.get("error", "")))
    return f" FAILED{f': {error}' if error else ''}"


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


def _priority_color(composite: float) -> str:
    if composite >= 0.7:
        return "#ef4444"
    if composite >= 0.4:
        return "#f59e0b"
    return "#22c55e"


def _priority_label(composite: float) -> str:
    if composite >= 0.7:
        return "HIGH"
    if composite >= 0.4:
        return "MEDIUM"
    return "LOW"


def _node_tip(
    col_idx: int,
    node_id: str,
    risk_tips: dict[str, str] | None = None,
) -> str:
    """Return a tooltip string for a Sankey node, based on its column.

    Col 0: risk name + description from *risk_tips* dict.
    Col 1: OWASP LLM Top 10 ID + name from ``_OWASP_LLM_NAMES``.
    Col 2: Agentic threat ID + name + description from ``THREAT_NAMES``
           and ``_THREAT_DESCRIPTIONS``.
    Col 3: Attack-pattern name + description from ``_ATTACK_PATTERN_INFO``.
    """
    if col_idx == 0:
        name = (risk_tips or {}).get(node_id, "")
        return f"{node_id}: {name}" if name else node_id
    if col_idx == 1:
        name = _OWASP_LLM_NAMES.get(node_id, "")
        return f"{node_id}: {name}" if name else node_id
    if col_idx == 2:
        name = THREAT_NAMES.get(node_id, "")
        desc = _THREAT_DESCRIPTIONS.get(node_id, "")
        parts = node_id
        if name:
            parts += f": {name}"
        if desc:
            parts += f" — {_truncate(desc, 150)}"
        return parts
    if col_idx == 3:
        info = _ATTACK_PATTERN_INFO.get(node_id, {})
        name = info.get("name", "")
        desc = info.get("description", "")
        parts = node_id
        if name:
            parts += f": {name}"
        if desc:
            parts += f" — {_truncate(desc, 150)}"
        return parts
    return node_id


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------


def build_css() -> str:
    return """
<style>
:root {
  --bg-primary: #0f1117;
  --bg-secondary: #1a1d2e;
  --bg-card: #1e2235;
  --bg-card-hover: #252a40;
  --text-primary: #e8eaed;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  --border: #2d3348;
  --accent: #6366f1;
  --accent-glow: rgba(99, 102, 241, 0.15);
  --zone-input: #3b82f6;
  --zone-reasoning: #8b5cf6;
  --zone-tool-execution: #f97316;
  --zone-memory: #22c55e;
  --zone-inter-agent: #ef4444;
  --high: #ef4444;
  --medium: #f59e0b;
  --low: #22c55e;
  --sidebar-width: 260px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  display: flex;
  min-height: 100vh;
}

/* Sidebar */
.sidebar {
  position: fixed;
  top: 0; left: 0;
  width: var(--sidebar-width);
  height: 100vh;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  padding: 24px 0;
  overflow-y: auto;
  z-index: 100;
  display: flex;
  flex-direction: column;
}

.sidebar-brand {
  padding: 0 20px 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}

.sidebar-brand h1 {
  font-size: 16px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.5px;
}

.sidebar-brand .subtitle {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

.sidebar nav { flex: 1; }

.sidebar a {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 20px;
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
  border-left: 3px solid transparent;
}

.sidebar a:hover {
  background: var(--accent-glow);
  color: var(--text-primary);
  border-left-color: var(--accent);
}

.sidebar a .nav-icon {
  width: 18px;
  text-align: center;
  font-size: 14px;
}

/* Main content */
.main-content {
  margin-left: var(--sidebar-width);
  flex: 1;
  padding: 40px 48px;
  max-width: 1200px;
}

/* Section */
.section {
  margin-bottom: 56px;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}

.section-header h2 {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
}

.section-header .badge {
  background: var(--accent-glow);
  color: var(--accent);
  font-size: 11px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 12px;
}

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
  transition: border-color 0.2s ease;
}

.card:hover { border-color: #3d4460; }

/* Zone strip (compact horizontal badges) */
.zone-strip {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  align-items: center;
}

.zone-chip {
  display: inline-flex;
  align-items: center;
  height: 24px;
  padding: 0 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  border: 1px solid;
  white-space: nowrap;
}

.zone-chip.active {
  box-shadow: 0 1px 4px rgba(0,0,0,0.2);
}

.zone-chip.inactive {
  background: transparent !important;
  border-color: #2d3348 !important;
  color: #4b5563 !important;
  font-weight: 400;
  font-size: 10px;
  height: 20px;
  padding: 0 7px;
  opacity: 0.6;
}

/* Capability flags inline */
.flags-inline {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
}

.flag-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--text-secondary);
}

.flag-chip .flag-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

.flag-chip .flag-dot.on { background: var(--low); }
.flag-chip .flag-dot.off { background: #3d4460; }

.flag-chip .flag-label { font-weight: 500; }
.flag-chip .flag-value {
  color: var(--text-muted);
  font-size: 11px;
}

.flag-true { color: var(--low); font-weight: 600; }
.flag-false { color: var(--text-muted); }

/* Capability flags table (used in other sections) */
.flags-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 16px;
}

.flags-table th {
  text-align: left;
  padding: 10px 16px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
}

.flags-table td {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}

/* Entry points compact */
.entry-point-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.entry-point-list li {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  background: var(--bg-secondary);
  border-radius: 4px;
  font-size: 12px;
}

.ep-direction {
  flex-shrink: 0;
  font-size: 11px;
  color: var(--text-muted);
  min-width: 16px;
  text-align: center;
}

.ep-name { color: var(--text-primary); }

/* Profile sub-section dividers */
.profile-row {
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
}

.profile-row:last-child { border-bottom: none; }

.profile-row-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 6px;
}

/* Threat surface */
.view-toggle {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.view-toggle button {
  padding: 8px 18px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
}

.view-toggle button.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.view-toggle button:hover:not(.active) {
  background: var(--bg-card-hover);
  color: var(--text-primary);
}

.view-panel { display: none; }
.view-panel.active { display: block; }

/* Risk card table */
.risk-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}

.risk-table th {
  text-align: left;
  padding: 10px 14px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 1;
}

.risk-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: top;
}

.risk-table tr:hover td { background: var(--bg-card-hover); }

.status-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.status-actionable { background: rgba(34,197,94,0.15); color: #22c55e; }
.status-governance { background: rgba(245,158,11,0.15); color: #f59e0b; }

/* Sankey flow */
.sankey-container {
  position: relative;
  overflow-x: auto;
  padding: 20px 0;
}

.sankey-svg {
  width: 100%;
  min-height: 300px;
}

.sankey-node {
  cursor: default;
}

.sankey-node rect {
  rx: 4;
  ry: 4;
}

.sankey-node text {
  fill: var(--text-primary);
  font-size: 11px;
  font-weight: 500;
}

.sankey-link {
  fill: none;
  stroke-opacity: 0.2;
  transition: stroke-opacity 0.2s;
}

.sankey-link:hover {
  stroke-opacity: 0.5;
}

/* Scenarios */
.scenario-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.scenario-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-secondary);
  flex-wrap: wrap;
  gap: 10px;
}

.scenario-header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.scenario-id {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
  color: var(--accent);
  font-weight: 600;
}

.scenario-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
}

.priority-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.scenario-body { padding: 24px; }

.scenario-section {
  margin-bottom: 24px;
}

.scenario-section:last-child { margin-bottom: 0; }

.scenario-section-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.scenario-summary {
  font-size: 14px;
  line-height: 1.7;
  color: var(--text-secondary);
}

/* Zone breadcrumb */
.zone-breadcrumb {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 10px;
}

.zone-crumb {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: auto;
  height: 24px;
  padding: 0 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.zone-crumb-arrow {
  color: var(--text-muted);
  font-size: 14px;
  margin: 0 2px;
}

/* Attack tree */
.attack-tree { font-size: 13px; }

.attack-tree details {
  margin-left: 20px;
  border-left: 2px solid var(--border);
  padding-left: 16px;
  margin-bottom: 4px;
}

.attack-tree details > summary {
  cursor: pointer;
  padding: 8px 12px;
  border-radius: 6px;
  background: var(--bg-secondary);
  margin-bottom: 4px;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  transition: background 0.15s ease;
}

.attack-tree details > summary:hover { background: var(--bg-card-hover); }

.attack-tree details > summary::-webkit-details-marker { display: none; }
.attack-tree details > summary::marker { display: none; content: ''; }

.attack-tree details > summary::before {
  content: '\\25B6';
  font-size: 9px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
}

.attack-tree details[open] > summary::before {
  transform: rotate(90deg);
}

.tree-leaf {
  margin-left: 20px;
  border-left: 2px solid var(--border);
  padding: 8px 12px 8px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 13px;
  margin-bottom: 4px;
}

.gate-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 22px;
  padding: 0 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.gate-and { background: rgba(139,92,246,0.2); color: #a78bfa; }
.gate-or { background: rgba(59,130,246,0.2); color: #60a5fa; }
.gate-leaf { background: rgba(107,114,128,0.2); color: #9ca3af; }

.zone-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: auto;
  height: 22px;
  padding: 0 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  color: white;
}
.kc-subcodes-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.kc-badge {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  color: white;
  cursor: default;
}
.kc-badge[data-cat="KC1"] { background: #5b8def; }
.kc-badge[data-cat="KC2"] { background: #9b59b6; }
.kc-badge[data-cat="KC3"] { background: #27ae60; }
.kc-badge[data-cat="KC4"] { background: #e67e22; }
.kc-badge[data-cat="KC5"] { background: #16a085; }
.kc-badge[data-cat="KC6"] { background: #c0392b; }

.tree-label { color: var(--text-primary); }

.tree-meta {
  font-size: 11px;
  color: var(--text-muted);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

/* Behavior spec */
.feature-spec { font-size: 13px; }

.feature-step {
  padding: 10px 14px;
  border-radius: 6px;
  margin-bottom: 6px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  flex-wrap: wrap;
}

.step-keyword {
  font-weight: 700;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
  min-width: 60px;
  flex-shrink: 0;
}

.step-text {
  color: var(--text-primary);
  flex: 1;
  min-width: 200px;
}

.step-given { background: rgba(59,130,246,0.08); border-left: 3px solid #3b82f6; }
.step-given .step-keyword { color: #3b82f6; }

.step-when { background: rgba(139,92,246,0.08); border-left: 3px solid #8b5cf6; }
.step-when .step-keyword { color: #8b5cf6; }

.step-and { background: rgba(139,92,246,0.05); border-left: 3px solid #6366f1; }
.step-and .step-keyword { color: #6366f1; }

.step-then { background: rgba(34,197,94,0.08); border-left: 3px solid #22c55e; }
.step-then .step-keyword { color: #22c55e; }

.step-but { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; }
.step-but .step-keyword { color: #ef4444; }

.step-star { background: rgba(245,158,11,0.08); border-left: 3px solid #f59e0b; }
.step-star .step-keyword { color: #f59e0b; }

.step-docstring {
  margin: 4px 0 4px 70px;
  padding: 10px 14px;
  background: var(--bg-primary);
  border-radius: 6px;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  color: var(--text-muted);
  white-space: pre-wrap;
  word-break: break-word;
  border: 1px solid var(--border);
  max-height: 200px;
  overflow-y: auto;
}

/* Priority signals */
.signals-panel {
  margin-top: 8px;
}

.signals-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}

.signal-item {
  padding: 10px 14px;
  background: var(--bg-secondary);
  border-radius: 6px;
  border: 1px solid var(--border);
}

.signal-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 4px;
}

.signal-value {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

/* Signal decomposition chart */
.signal-chart {
  margin-bottom: 24px;
}
.signal-bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
  height: 28px;
}
.signal-bar-label {
  width: 60px;
  font-size: 11px;
  font-weight: 700;
  color: var(--text-secondary);
  text-align: right;
  flex-shrink: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.signal-bar-track {
  flex: 1;
  display: flex;
  height: 20px;
  border-radius: 4px;
  overflow: hidden;
  background: var(--bg-secondary);
}
.signal-segment {
  height: 100%;
  position: relative;
  cursor: default;
  transition: opacity 0.15s ease;
  min-width: 2px;
}
.signal-segment:hover {
  opacity: 0.8;
}
.signal-segment .tooltip {
  display: none;
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg-primary);
  border: 1px solid var(--border);
  padding: 6px 10px;
  border-radius: 6px;
  white-space: nowrap;
  font-size: 11px;
  font-weight: 500;
  color: var(--text-primary);
  z-index: 10;
  margin-bottom: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}
.signal-segment:hover .tooltip { display: block; }
.signal-bar-score {
  width: 40px;
  font-size: 11px;
  font-weight: 700;
  color: var(--text-primary);
  text-align: left;
  flex-shrink: 0;
}
.signal-legend {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin-top: 8px;
}
.signal-legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: var(--text-secondary);
}
.signal-legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  flex-shrink: 0;
}

/* Filter controls */
/* Dashboard stats bar */
.stats-bar {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
  flex-wrap: wrap;
  align-items: stretch;
}

.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  min-width: 120px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  border-left: 4px solid var(--accent);
}

.stat-card .stat-number {
  font-size: 28px;
  font-weight: 800;
  color: var(--text-primary);
  line-height: 1;
}

.stat-card .stat-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.severity-donut {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  position: relative;
  flex-shrink: 0;
}

.severity-donut::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: var(--bg-card);
}

.coverage-gap-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  border-left: 4px solid var(--text-muted);
  min-width: 140px;
}

.coverage-gap-card .stat-number {
  font-size: 28px;
  font-weight: 800;
  color: var(--text-secondary);
  line-height: 1;
}

.coverage-gap-card .stat-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

/* Coverage heatmap matrix */
.coverage-matrix {
  display: grid;
  gap: 2px;
  margin-bottom: 24px;
  background: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 16px;
  overflow-x: auto;
}

.matrix-header {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.3px;
  padding: 8px 6px;
  text-align: center;
  color: var(--text-primary);
  border-radius: 4px;
}

.matrix-row-label {
  font-size: 12px;
  font-weight: 600;
  padding: 8px 10px;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  white-space: nowrap;
}

.matrix-cell {
  padding: 8px 6px;
  text-align: center;
  font-size: 13px;
  font-weight: 700;
  border-radius: 4px;
  cursor: pointer;
  transition: transform 0.1s ease, box-shadow 0.1s ease;
  min-width: 48px;
  color: var(--text-primary);
}

.matrix-cell:hover {
  transform: scale(1.1);
  box-shadow: 0 2px 8px rgba(0,0,0,0.4);
  z-index: 1;
}

.matrix-cell.empty {
  background: rgba(255,255,255,0.03);
  color: var(--text-muted);
  cursor: default;
}

.matrix-cell.empty:hover {
  transform: none;
  box-shadow: none;
}

/* Chip/tag filters */
.chip-group {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

.chip-group-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-right: 4px;
  white-space: nowrap;
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 14px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid;
  user-select: none;
  white-space: nowrap;
}

.filter-chip:hover {
  opacity: 0.85;
}

.filter-chip.active {
  box-shadow: 0 0 0 1px currentColor;
}

/* Expand/collapse toggle */
.toggle-all-btn {
  padding: 4px 12px;
  background: var(--bg-card);
  color: var(--text-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
  margin-left: 8px;
}

.toggle-all-btn:hover {
  background: var(--bg-card-hover);
  color: var(--text-primary);
}

.scenario-card .scenario-header {
  cursor: pointer;
}

.scenario-card.collapsed .scenario-tabs {
  display: none;
}

.scenario-header .collapse-indicator {
  font-size: 14px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
  margin-left: 4px;
}

.scenario-card.collapsed .collapse-indicator {
  transform: rotate(-90deg);
}

.filter-bar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
  padding: 16px;
  background: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
  align-items: center;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.filter-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.filter-select, .filter-input {
  padding: 6px 10px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 12px;
  min-width: 140px;
}

.filter-select:focus, .filter-input:focus {
  outline: none;
  border-color: var(--accent);
}

.filter-btn {
  padding: 6px 14px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  align-self: flex-end;
  transition: opacity 0.15s ease;
}

.filter-btn:hover { opacity: 0.85; }

/* Raw data */
.raw-tabs {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

.raw-tab {
  padding: 6px 14px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.15s ease;
}

.raw-tab.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.raw-tab:hover:not(.active) {
  background: var(--bg-card-hover);
  color: var(--text-primary);
}

.raw-panel {
  display: none;
  position: relative;
}

.raw-panel.active { display: block; }

.copy-btn {
  position: absolute;
  top: 10px;
  right: 10px;
  padding: 5px 12px;
  background: var(--bg-card-hover);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 11px;
  font-weight: 500;
  z-index: 2;
  transition: all 0.15s ease;
}

.copy-btn:hover {
  background: var(--accent);
  color: white;
}

.code-block {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 600px;
  overflow-y: auto;
}

/* Syntax highlighting for YAML */
.yaml-key { color: #60a5fa; }
.yaml-string { color: #a78bfa; }
.yaml-number { color: #f59e0b; }
.yaml-bool { color: #22c55e; }
.yaml-null { color: #6b7280; font-style: italic; }
.yaml-comment { color: #4b5563; font-style: italic; }

/* Gherkin highlighting */
.gherkin-keyword { color: #60a5fa; font-weight: 700; }
.gherkin-tag { color: #f59e0b; }
.gherkin-string { color: #a78bfa; }
.gherkin-comment { color: #4b5563; font-style: italic; }

/* Details/summary for priority signals */
details.expandable > summary {
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  list-style: none;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 0;
}

details.expandable > summary::-webkit-details-marker { display: none; }
details.expandable > summary::marker { display: none; content: ''; }

details.expandable > summary::before {
  content: '\\25B6';
  font-size: 8px;
  transition: transform 0.2s ease;
}

details.expandable[open] > summary::before {
  transform: rotate(90deg);
}

/* Scenario count badge */
.count-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 24px;
  height: 24px;
  padding: 0 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 700;
  background: var(--accent);
  color: white;
}

/* Score bar */
.score-bar-container {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
}

.score-bar-track {
  flex: 1;
  height: 6px;
  background: var(--bg-primary);
  border-radius: 3px;
  overflow: hidden;
  max-width: 120px;
}

.score-bar-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s ease;
}

.score-bar-label {
  font-size: 12px;
  font-weight: 700;
  font-family: 'SF Mono', 'Fira Code', monospace;
  min-width: 36px;
}

/* Coverage section */
.coverage-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}

.coverage-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.coverage-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}

.coverage-card-title {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.coverage-status {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
}

.coverage-status-green { background: rgba(34,197,94,0.15); color: #22c55e; }
.coverage-status-amber { background: rgba(245,158,11,0.15); color: #f59e0b; }
.coverage-status-red { background: rgba(239,68,68,0.15); color: #ef4444; }

.coverage-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.coverage-list li {
  padding: 6px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  margin-bottom: 4px;
  font-size: 13px;
  border-left: 3px solid var(--high);
  color: var(--text-secondary);
}

.coverage-reason {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 1px 6px;
  border-radius: 3px;
  margin-left: 6px;
  background: rgba(245,158,11,0.12);
  color: #f59e0b;
  vertical-align: middle;
}

.coverage-empty {
  padding: 12px;
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
  font-style: italic;
}

/* Diversity section */
.diversity-bar-chart {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
}

.diversity-bar-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.diversity-bar-label {
  min-width: 130px;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  text-transform: capitalize;
}

.diversity-bar-track {
  flex: 1;
  height: 20px;
  background: var(--bg-primary);
  border-radius: 4px;
  overflow: hidden;
}

.diversity-bar-fill {
  height: 100%;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  padding-right: 6px;
  font-size: 11px;
  font-weight: 700;
  color: white;
  min-width: 24px;
}

.diversity-bar-count {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  min-width: 24px;
  text-align: right;
}

.warning-banner {
  background: rgba(245,158,11,0.1);
  border: 1px solid rgba(245,158,11,0.3);
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: #f59e0b;
}

.warning-banner-icon {
  font-size: 18px;
  flex-shrink: 0;
}

/* Entry point distribution */
.ep-dist-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 8px;
  margin-top: 12px;
}

.ep-dist-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  border: 1px solid var(--border);
  font-size: 12px;
}

.ep-dist-name {
  color: var(--text-secondary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-right: 8px;
}

.ep-dist-count {
  font-weight: 700;
  color: var(--accent);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

/* Legend row */
.legend {
  display: flex;
  gap: 16px;
  align-items: center;
  margin-top: 8px;
  font-size: 11px;
  color: var(--text-muted);
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
}

/* Count badges for compact AP/threat lists */
.count-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  background: rgba(99, 102, 241, 0.15);
  color: var(--accent);
  cursor: help;
  white-space: nowrap;
}

/* Overflow safety for wide table cells */
.risk-table td,
.roster-table td {
  overflow-wrap: break-word;
  word-break: break-word;
  text-overflow: ellipsis;
  overflow: hidden;
}

/* CSS tooltips — JS-positioned fixed overlay (immune to overflow clipping) */
[data-tooltip] {
  cursor: help;
}
#tooltip-overlay {
  position: fixed;
  padding: 6px 10px;
  background: #1a1a2e;
  color: #e0e0e0;
  border: 1px solid #333;
  border-radius: 4px;
  font-size: 0.8rem;
  max-width: 400px;
  white-space: pre-line;
  z-index: 10000;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

/* Scorecard */
.scorecard-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.scorecard-stat {
  text-align: center;
  padding: 16px 12px;
  background: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border);
}

.scorecard-stat-value {
  font-size: 28px;
  font-weight: 800;
  color: var(--accent);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.scorecard-stat-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-top: 4px;
}

.scorecard-group {
  margin-bottom: 16px;
}

.scorecard-group-title {
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-secondary);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}

.scorecard-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.scorecard-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
}

.scorecard-badge-green {
  background: rgba(34,197,94,0.12);
  color: #22c55e;
  border: 1px solid rgba(34,197,94,0.25);
}

.scorecard-badge-yellow {
  background: rgba(245,158,11,0.12);
  color: #f59e0b;
  border: 1px solid rgba(245,158,11,0.25);
}

.scorecard-badge-red {
  background: rgba(239,68,68,0.12);
  color: #ef4444;
  border: 1px solid rgba(239,68,68,0.25);
}

.scorecard-detail-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 8px;
}

.scorecard-detail-table th {
  text-align: left;
  padding: 8px 12px;
  background: var(--bg-secondary);
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
}

.scorecard-detail-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  color: var(--text-secondary);
}

.scorecard-detail-table td:first-child {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 12px;
  color: var(--text-primary);
}

/* Scorecard Outliers Panel */
.scorecard-outliers {
  margin-bottom: 20px;
  padding: 16px;
  border-radius: 8px;
  border: 1px solid rgba(245,158,11,0.35);
  background: rgba(245,158,11,0.06);
}

.scorecard-outliers-title {
  font-size: 14px;
  font-weight: 700;
  color: #f59e0b;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.scorecard-outliers-clear {
  margin-bottom: 20px;
  padding: 14px 16px;
  border-radius: 8px;
  border: 1px solid rgba(34,197,94,0.25);
  background: rgba(34,197,94,0.06);
  font-size: 13px;
  font-weight: 600;
  color: #22c55e;
  display: flex;
  align-items: center;
  gap: 6px;
}

.scorecard-outliers table {
  width: 100%;
  border-collapse: collapse;
}

.scorecard-outliers th {
  text-align: left;
  padding: 6px 10px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}

.scorecard-outliers td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  color: var(--text-secondary);
}

.scorecard-outliers td:first-child {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  color: var(--text-primary);
}

/* Threat-Technique Matrix */
.matrix-table {
  width: max-content;
  border-collapse: collapse;
  font-size: 12px;
}

.matrix-table th {
  text-align: left;
  padding: 8px 10px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 3;
  white-space: nowrap;
}

.matrix-table th.matrix-col-header {
  text-align: center;
  width: 28px;
  min-width: 28px;
  max-width: 28px;
  padding: 6px 2px;
  height: 130px;
  vertical-align: bottom;
}

.matrix-col-header-text {
  writing-mode: vertical-lr;
  transform: rotate(180deg);
  white-space: nowrap;
  font-size: 10px;
  display: inline-block;
  max-height: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Sticky first two columns (Threat ID + Name) */
.matrix-table th.matrix-sticky-col {
  position: sticky;
  z-index: 4;
  background: var(--bg-secondary);
}
.matrix-table th.matrix-sticky-col-0 { left: 0; }
.matrix-table th.matrix-sticky-col-1 { left: 60px; }

.matrix-table td.matrix-sticky-col {
  position: sticky;
  z-index: 2;
  background: var(--bg-card);
}
.matrix-table td.matrix-sticky-col-0 { left: 0; }
.matrix-table td.matrix-sticky-col-1 { left: 60px; }

.matrix-table tr:hover td.matrix-sticky-col {
  background: var(--bg-card-hover);
}

.matrix-table tr.matrix-row-greyed td.matrix-sticky-col {
  background: var(--bg-card);
}

.matrix-table td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  vertical-align: middle;
}

.matrix-table tr:hover td { background: var(--bg-card-hover); }

.matrix-table tr.matrix-row-greyed td {
  color: var(--text-muted);
  opacity: 0.45;
}

.matrix-table tr.matrix-row-greyed:hover td {
  background: transparent;
}

.matrix-table td.matrix-cell {
  text-align: center;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  width: 28px;
  min-width: 28px;
  max-width: 28px;
  padding: 6px 2px;
}

.matrix-count-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 4px;
  background: rgba(99, 102, 241, 0.18);
  color: var(--accent);
  font-weight: 700;
  font-size: 11px;
  text-decoration: none;
  cursor: help;
}

.matrix-count-link:hover {
  background: rgba(99, 102, 241, 0.35);
}

.matrix-table td.matrix-cell a {
  color: var(--accent);
  text-decoration: none;
  font-weight: 500;
}

.matrix-table td.matrix-cell a:hover {
  text-decoration: underline;
}

/* Roster table */
.roster-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
.roster-table th:nth-child(1) { width: 16%; }
.roster-table th:nth-child(2) { width: 6%; }
.roster-table th:nth-child(3) { width: 16%; }
.roster-table th:nth-child(4) { width: 16%; }
.roster-table th:nth-child(5) { width: 16%; }
.roster-table th:nth-child(6) { width: 10%; }
.roster-table th:nth-child(7) { width: 20%; }

.roster-table th {
  text-align: left;
  padding: 8px 12px;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 1;
}

.roster-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: top;
}

.roster-table tr:hover td { background: var(--bg-card-hover); }

.roster-table td a {
  color: var(--accent);
  text-decoration: none;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 12px;
  font-weight: 600;
}

.roster-table td a:hover { text-decoration: underline; }

.roster-zone-badges {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.call-log-pre {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  font-size: 11px;
  font-family: 'SF Mono', 'Fira Code', monospace;
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 400px;
  overflow-y: auto;
}

details.call-anomaly {
  border-left: 3px solid #e67e22;
  padding-left: 6px;
}

.call-anomaly-badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
  margin-left: 6px;
  background: #5a3600;
  color: #f5b041;
  vertical-align: middle;
}

/* Provenance chain flowchart */
.prov-chain {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0;
  padding: 8px 0;
}

.prov-step {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  background: var(--bg-secondary);
}

.prov-step-label {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  color: var(--text-muted);
  margin-bottom: 6px;
  font-variant: small-caps;
}

.prov-step-content {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
}

.prov-arrow {
  font-size: 18px;
  color: var(--text-muted);
  line-height: 1;
  padding: 2px 0;
  text-align: center;
  user-select: none;
}

.prov-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  margin: 2px 3px 2px 0;
}

.prov-badge-accent {
  background: rgba(99,102,241,0.15);
  color: var(--accent);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.prov-badge-blue {
  background: rgba(59,130,246,0.15);
  color: #60a5fa;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.prov-badge-orange {
  background: rgba(249,115,22,0.15);
  color: #f97316;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.prov-badge-green {
  background: rgba(34,197,94,0.15);
  color: #22c55e;
}

.prov-badge-amber {
  background: rgba(245,158,11,0.15);
  color: #f59e0b;
}

.prov-badge-red {
  background: rgba(239,68,68,0.15);
  color: #ef4444;
}

.prov-badge-muted {
  background: rgba(107,114,128,0.10);
  color: var(--text-muted);
}

.prov-highlight {
  border: 2px solid var(--accent);
  background: rgba(99,102,241,0.08);
  border-radius: 6px;
  padding: 4px 10px;
  margin: 2px 3px 2px 0;
  display: inline-block;
}

.prov-dim {
  opacity: 0.45;
}

.prov-item-row {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
  margin-top: 4px;
}

.prov-kv {
  display: flex;
  gap: 6px;
  align-items: baseline;
  margin-bottom: 4px;
}

.prov-kv-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  min-width: 80px;
  flex-shrink: 0;
}

.prov-kv-value {
  font-size: 13px;
  color: var(--text-primary);
}

/* Provenance chain parallel layout */
.prov-parallel-row {
  display: flex;
  gap: 12px;
  width: 100%;
}

.prov-parallel-row .prov-step {
  flex: 1;
  width: 100%;
  min-width: 0;
}

.prov-parallel-row .prov-kv {
  flex-direction: column;
  gap: 2px;
}

.prov-parallel-row .prov-kv-label {
  min-width: unset;
}

.prov-fork-label {
  font-size: 10px;
  color: var(--text-muted);
  letter-spacing: 0.3px;
  padding: 2px 0;
  text-align: center;
  user-select: none;
}

/* Candidate filter results in provenance chain */
.prov-filter-results {
  width: 100%;
  max-width: 660px;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  background: var(--bg-secondary);
}

.prov-filter-results summary {
  cursor: pointer;
  font-size: 12px;
  color: var(--text-muted);
  font-weight: 600;
}

.prov-filter-results summary:hover {
  color: var(--text-secondary);
}

.prov-accepted-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  background: rgba(34,197,94,0.15);
  color: #4ade80;
  margin: 2px 3px 2px 0;
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.prov-rejected-row {
  opacity: 0.6;
  padding: 6px 0;
  border-bottom: 1px solid rgba(45,51,72,0.5);
}

.prov-rejected-row:last-child {
  border-bottom: none;
}

.prov-rationale {
  font-style: italic;
  color: #888;
  font-size: 0.85em;
  margin-top: 2px;
}

/* Quality badges on tab headers */
.tab-quality-badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 500;
  margin-left: 5px;
  padding: 1px 5px;
  border-radius: 8px;
  background: rgba(34,197,94,0.12);
  color: #22c55e;
  vertical-align: middle;
  line-height: 1.4;
}
.tab-quality-badge.tab-warn {
  background: rgba(245,158,11,0.15);
  color: #f59e0b;
}
.tab-quality-badge.tab-fail {
  background: rgba(239,68,68,0.15);
  color: #ef4444;
}

/* CSS-only scenario tabs */
.scenario-tabs > input[type="radio"] {
  display: none;
}

.tab-bar > label {
  display: inline-block;
  padding: 8px 14px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: color 0.15s, border-color 0.15s;
  user-select: none;
}

.tab-bar > label:hover {
  color: var(--text-primary);
}

.scenario-tabs > .tab-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 0;
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  background: var(--bg-card);
}

.tab-panels > .tab-panel {
  display: none;
  padding: 24px;
}

.scenario-tabs > input:nth-of-type(1):checked ~ .tab-panels > .tab-panel:nth-child(1),
.scenario-tabs > input:nth-of-type(2):checked ~ .tab-panels > .tab-panel:nth-child(2),
.scenario-tabs > input:nth-of-type(3):checked ~ .tab-panels > .tab-panel:nth-child(3),
.scenario-tabs > input:nth-of-type(4):checked ~ .tab-panels > .tab-panel:nth-child(4),
.scenario-tabs > input:nth-of-type(5):checked ~ .tab-panels > .tab-panel:nth-child(5),
.scenario-tabs > input:nth-of-type(6):checked ~ .tab-panels > .tab-panel:nth-child(6),
.scenario-tabs > input:nth-of-type(7):checked ~ .tab-panels > .tab-panel:nth-child(7),
.scenario-tabs > input:nth-of-type(8):checked ~ .tab-panels > .tab-panel:nth-child(8),
.scenario-tabs > input:nth-of-type(9):checked ~ .tab-panels > .tab-panel:nth-child(9) {
  display: block;
}

.scenario-tabs > input:nth-of-type(1):checked ~ .tab-bar > label:nth-child(1),
.scenario-tabs > input:nth-of-type(2):checked ~ .tab-bar > label:nth-child(2),
.scenario-tabs > input:nth-of-type(3):checked ~ .tab-bar > label:nth-child(3),
.scenario-tabs > input:nth-of-type(4):checked ~ .tab-bar > label:nth-child(4),
.scenario-tabs > input:nth-of-type(5):checked ~ .tab-bar > label:nth-child(5),
.scenario-tabs > input:nth-of-type(6):checked ~ .tab-bar > label:nth-child(6),
.scenario-tabs > input:nth-of-type(7):checked ~ .tab-bar > label:nth-child(7),
.scenario-tabs > input:nth-of-type(8):checked ~ .tab-bar > label:nth-child(8),
.scenario-tabs > input:nth-of-type(9):checked ~ .tab-bar > label:nth-child(9) {
  color: var(--text-primary);
  border-bottom-color: var(--accent);
}
</style>
"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def build_js() -> str:
    return """
<script>
// Tooltip overlay — fixed positioning immune to overflow clipping
(function() {
  var tip = document.createElement('div');
  tip.id = 'tooltip-overlay';
  document.body.appendChild(tip);
  document.addEventListener('mouseover', function(e) {
    var el = e.target.closest('[data-tooltip]');
    if (!el) { tip.style.opacity = '0'; return; }
    tip.textContent = el.getAttribute('data-tooltip');
    tip.style.opacity = '1';
    var rect = el.getBoundingClientRect();
    var tipRect = tip.getBoundingClientRect();
    var left = rect.left + rect.width / 2 - tipRect.width / 2;
    var top = rect.top - tipRect.height - 6;
    if (top < 4) top = rect.bottom + 6;
    if (left < 4) left = 4;
    if (left + tipRect.width > window.innerWidth - 4) left = window.innerWidth - tipRect.width - 4;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  });
  document.addEventListener('mouseout', function(e) {
    if (e.target.closest('[data-tooltip]')) tip.style.opacity = '0';
  });
})();

// View toggle
function toggleView(viewId, btn) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.view-toggle button').forEach(b => b.classList.remove('active'));
  document.getElementById(viewId).classList.add('active');
  btn.classList.add('active');
}

// Raw data tabs
function switchRawTab(tabId, btn) {
  document.querySelectorAll('.raw-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.raw-tab').forEach(t => t.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  btn.classList.add('active');
}

// Copy to clipboard
function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  const text = el.innerText || el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// Scenario filtering — chip-based multi-select
function filterScenarios() {
  var activeThreats = [];
  var activeZones = [];
  var activePriorities = [];
  document.querySelectorAll('.filter-chip.active[data-filter-type="threat"]').forEach(function(c) {
    activeThreats.push(c.getAttribute('data-filter-value'));
  });
  document.querySelectorAll('.filter-chip.active[data-filter-type="zone"]').forEach(function(c) {
    activeZones.push(c.getAttribute('data-filter-value'));
  });
  document.querySelectorAll('.filter-chip.active[data-filter-type="priority"]').forEach(function(c) {
    activePriorities.push(c.getAttribute('data-filter-value'));
  });

  document.querySelectorAll('.scenario-card[data-scenario]').forEach(function(card) {
    var show = true;

    if (activeThreats.length > 0) {
      var cardThreats = card.dataset.threats.toLowerCase().split(',');
      var matchesThreat = activeThreats.some(function(t) {
        return cardThreats.some(function(ct) { return ct.indexOf(t.toLowerCase()) >= 0; });
      });
      if (!matchesThreat) show = false;
    }
    if (activeZones.length > 0) {
      var cardZones = card.dataset.zones.split(',');
      var matchesZone = activeZones.some(function(z) {
        return cardZones.indexOf(z) >= 0;
      });
      if (!matchesZone) show = false;
    }
    if (activePriorities.length > 0) {
      if (activePriorities.indexOf(card.dataset.priority) < 0) show = false;
    }

    card.style.display = show ? '' : 'none';
  });

  // Update visible count
  var visible = document.querySelectorAll('.scenario-card[data-scenario]:not([style*="display: none"])').length;
  var total = document.querySelectorAll('.scenario-card[data-scenario]').length;
  var counter = document.getElementById('scenario-counter');
  if (counter) {
    if (visible === total) {
      counter.textContent = 'Showing all ' + total;
    } else {
      counter.textContent = 'Showing ' + visible + ' of ' + total;
    }
  }
}

function toggleChip(el) {
  el.classList.toggle('active');
  // Update filled/outline style
  if (el.classList.contains('active')) {
    el.style.background = el.getAttribute('data-active-bg');
    el.style.color = el.getAttribute('data-active-color');
  } else {
    el.style.background = 'transparent';
    el.style.color = el.getAttribute('data-active-color');
  }
  filterScenarios();
}

function resetFilters() {
  document.querySelectorAll('.filter-chip.active').forEach(function(c) {
    c.classList.remove('active');
    c.style.background = 'transparent';
    c.style.color = c.getAttribute('data-active-color');
  });
  filterScenarios();
}

// Coverage matrix: click a cell to filter by threat + zone
function filterByCell(threatId, zone) {
  // Clear all chips first
  document.querySelectorAll('.filter-chip.active').forEach(function(c) {
    c.classList.remove('active');
    c.style.background = 'transparent';
    c.style.color = c.getAttribute('data-active-color');
  });
  // Activate matching threat chip
  document.querySelectorAll('.filter-chip[data-filter-type="threat"]').forEach(function(c) {
    if (c.getAttribute('data-filter-value') === threatId) {
      c.classList.add('active');
      c.style.background = c.getAttribute('data-active-bg');
      c.style.color = c.getAttribute('data-active-color');
    }
  });
  // Activate matching zone chip
  document.querySelectorAll('.filter-chip[data-filter-type="zone"]').forEach(function(c) {
    if (c.getAttribute('data-filter-value') === zone) {
      c.classList.add('active');
      c.style.background = c.getAttribute('data-active-bg');
      c.style.color = c.getAttribute('data-active-color');
    }
  });
  filterScenarios();
}

// Expand/collapse all scenario cards
function toggleAllCards() {
  var btn = document.getElementById('toggle-all-btn');
  var cards = document.querySelectorAll('.scenario-card[data-scenario]');
  var allCollapsed = true;
  cards.forEach(function(c) { if (!c.classList.contains('collapsed')) allCollapsed = false; });
  if (allCollapsed) {
    cards.forEach(function(c) { c.classList.remove('collapsed'); });
    if (btn) btn.textContent = 'Collapse All';
  } else {
    cards.forEach(function(c) { c.classList.add('collapsed'); });
    if (btn) btn.textContent = 'Expand All';
  }
}

function toggleCard(cardEl) {
  cardEl.classList.toggle('collapsed');
  // Update global button text
  var btn = document.getElementById('toggle-all-btn');
  if (btn) {
    var cards = document.querySelectorAll('.scenario-card[data-scenario]');
    var allCollapsed = true;
    cards.forEach(function(c) { if (!c.classList.contains('collapsed')) allCollapsed = false; });
    btn.textContent = allCollapsed ? 'Expand All' : 'Collapse All';
  }
}
</script>
"""


# ---------------------------------------------------------------------------
# Section 0a: Pipeline Methodology
# ---------------------------------------------------------------------------


def build_methodology_section() -> str:
    """Return HTML for a collapsible card explaining the scenario generation pipeline.

    The content is static -- it describes the five pipeline stages so readers
    can cross-reference the funnel numbers shown in the Run Summary.
    """
    return """
    <div id="sec-methodology" class="section">
      <div class="section-header">
        <h2>Pipeline Methodology</h2>
      </div>

      <details open class="card" style="background:var(--bg-secondary);border-left:4px solid var(--accent);cursor:default;">
        <summary style="font-weight:600;font-size:14px;cursor:pointer;color:var(--text-primary);margin-bottom:8px;">
          How scenarios are generated
        </summary>
        <div style="font-size:14px;line-height:1.8;color:var(--text-secondary);">
          <ol style="margin:0;padding-left:1.4em;">
            <li><strong>Seeds</strong> &mdash; Attack patterns are enumerated from every
            in-scope threat surface entry, producing the initial seed set.</li>
            <li><strong>Candidate expansion</strong> &mdash; Each seed is crossed with
            the system&rsquo;s entry points and relevant ATLAS techniques to build the
            full candidate pool (shown as <em>Candidates</em> in the Run Summary
            funnel).</li>
            <li><strong>LLM filtering</strong> &mdash; An LLM evaluates each candidate
            for plausibility and relevance, accepting or rejecting it with a
            rationale (shown as <em>Accepted</em> in the funnel).</li>
            <li><strong>Scenario generation</strong> &mdash; One LLM call per accepted
            candidate produces an attack tree, narrative, and behavior
            specification (<em>Scenarios Generated</em>).</li>
            <li><strong>Coverage analysis</strong> &mdash; Uncovered threat / zone
            combinations are identified so the assessment can be extended in
            follow-up runs.</li>
          </ol>
        </div>
      </details>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 0b: Use Case
# ---------------------------------------------------------------------------


def build_use_case_section(use_case_text: str) -> str:
    """Build a styled section showing the use case description.

    Args:
        use_case_text: Free-text description of the AI system under assessment.

    Returns:
        HTML string for the use case section, or empty string if text is empty.
    """
    if not use_case_text or not use_case_text.strip():
        return ""

    # Preserve line breaks by converting newlines to <br> tags
    paragraphs = use_case_text.strip().split("\n")
    formatted = "<br>\n".join(_esc(p) for p in paragraphs)

    return f"""
    <div id="sec-use-case" class="section">
      <details class="expandable">
        <summary class="section-header" style="cursor:pointer;">
          <h2 style="display:inline;">System Under Assessment</h2>
        </summary>
        <div class="card" style="background:var(--bg-secondary);border-left:4px solid var(--accent);margin-top:12px;">
          <div style="font-size:14px;line-height:1.8;color:var(--text-secondary);">
            {formatted}
          </div>
        </div>
      </details>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 1: Capability Profile
# ---------------------------------------------------------------------------


def _build_kc_descriptions() -> dict[str, str]:
    """Load KC sub-code → description mapping for report tooltips."""
    mapping = load_kc_threat_mapping()
    return {
        sc["kc_subcode"]: sc["description"] for sc in mapping.get("kc_subcodes", [])
    }


def _kc_category(kc: str) -> str:
    """Extract category prefix from a KC sub-code (e.g. 'KC6.2.2' → 'KC6')."""
    parts = kc.split(".")
    return parts[0] if parts else kc


def _corpus_applicability_label(
    corpus_claims: list[dict[str, Any]],
) -> str:
    """Human-readable label for closed-world corpus claim applicability.

    Consumes typed, category-specific :class:`CorpusClaimApplicability`
    records persisted in ``SemanticValidation.corpus_claim_applicability``
    (cmps.9 review correction 2).  Does not infer from completeness strings.
    """
    if not corpus_claims:
        return "Not assessed"
    parts: list[str] = []
    for claim in corpus_claims:
        category = claim.get("category", "unknown")
        status = claim.get("status", "unknown")
        cat_label = category.replace("_", " ")
        parts.append(f"{cat_label} claims {status}")
    return "; ".join(parts)


def build_capability_profile_section(
    profile: dict[str, Any],
    *,
    corpus_claims: list[dict[str, Any]] | None = None,
) -> str:
    raw_zones_active = profile.get("zones_active", [])
    zones_active = {_normalize_zone(z) for z in raw_zones_active}

    # Zone chips — compact horizontal strip
    zone_chips = []
    for z in _ZONE_NAMES_TUPLE:
        active = z in zones_active
        cls = "active" if active else "inactive"
        color = ZONE_COLORS[z]
        bg = ZONE_BG_COLORS[z] if active else ""
        style = f"background:{bg};border-color:{color};color:{color};" if active else ""
        zone_chips.append(
            f'<span class="zone-chip {cls}" style="{style}">'
            f"{_esc(ZONE_DISPLAY_NAMES[z])}</span>"
        )

    # Flags — inline chips with dot indicators
    bool_flags = [
        ("Memory", profile.get("has_persistent_memory", False)),
        ("Multi-Agent", profile.get("multi_agent", False)),
        ("HITL", profile.get("hitl", False)),
    ]
    confidence = profile.get("confidence", "unknown")
    flag_chips = []
    for label, val in bool_flags:
        dot_cls = "on" if val else "off"
        flag_chips.append(
            f'<span class="flag-chip">'
            f'<span class="flag-dot {dot_cls}"></span>'
            f'<span class="flag-label">{_esc(label)}</span>'
            f"</span>"
        )
    # Confidence as a text chip
    conf_tip = (
        "Profile inference confidence — how clearly the use-case "
        "description signals these capabilities"
    )
    flag_chips.append(
        f'<span class="flag-chip" data-tooltip="{_esc(conf_tip)}">'
        f'<span class="flag-label">Confidence:</span>'
        f'<span class="flag-value">{_esc(str(confidence).capitalize())}</span>'
        f"</span>"
    )

    # Entry points — extract name/direction from dicts or strings
    _DIR_ARROWS = {"input": "←", "output": "→", "bidirectional": "↔"}
    eps = profile.get("entry_points", [])
    ep_items = []
    for ep in eps:
        if isinstance(ep, dict):
            name = ep.get("name", str(ep))
            direction = ep.get("direction", "bidirectional")
        else:
            name = str(ep)
            direction = "bidirectional"
        arrow = _DIR_ARROWS.get(direction, "↔")
        ep_items.append(
            f"<li>"
            f'<span class="ep-direction" title="{_esc(direction)}">{arrow}</span>'
            f'<span class="ep-name">{_esc(name)}</span>'
            f"</li>"
        )

    ep_html = ""
    if ep_items:
        ep_html = f"""
        <div class="profile-row">
          <div class="profile-row-label">Entry Points</div>
          <ul class="entry-point-list">{"".join(ep_items)}</ul>
        </div>"""

    def _resource_list(
        entries: list[dict[str, Any]], id_field: str, empty_label: str
    ) -> str:
        if not entries:
            return f'<span style="color:var(--text-muted);">{_esc(empty_label)}</span>'
        items = []
        for entry in entries:
            name = entry.get("name", "Unnamed")
            canonical_id = entry.get(id_field, "Unavailable")
            items.append(
                "<li>"
                f'<span class="ep-name">{_esc(name)}</span> '
                f'<code class="tree-meta">{_esc(canonical_id)}</code>'
                "</li>"
            )
        return f'<ul class="entry-point-list">{"".join(items)}</ul>'

    tools_html = _resource_list(
        profile.get("tool_inventory") or [], "tool_id", "No tools inventoried"
    )
    integrations_html = _resource_list(
        profile.get("external_integrations") or [],
        "integration_id",
        "No external integrations inventoried",
    )

    def _enum_str(v: str) -> str:
        """Extract string value from a possible enum object."""
        return str(v.value if hasattr(v, "value") else v)

    entry_point_completeness = _enum_str(
        profile.get("entry_point_completeness", "unknown")
    )
    entry_point_evidence = profile.get("entry_point_evidence") or []
    tool_inventory_completeness = _enum_str(
        profile.get("tool_inventory_completeness", "unknown")
    )
    tool_inventory_evidence = profile.get("tool_inventory_evidence") or []

    def _evidence_html(evidence: list[str]) -> str:
        if not evidence:
            return '<span style="color:var(--text-muted);">No evidence sources recorded</span>'
        return (
            '<ul class="entry-point-list">'
            + "".join(f"<li>{_esc(source)}</li>" for source in evidence)
            + "</ul>"
        )

    entry_point_evidence_html = _evidence_html(entry_point_evidence)
    tool_inventory_evidence_html = _evidence_html(tool_inventory_evidence)

    # KC sub-codes
    kc_subcodes = profile.get("kc_subcodes", [])
    kc_html = ""
    if kc_subcodes:
        kc_descs = _build_kc_descriptions()
        kc_badges = []
        for kc in sorted(kc_subcodes):
            cat = _kc_category(kc)
            desc = _esc(kc_descs.get(kc, ""))
            kc_badges.append(
                f'<span class="kc-badge" data-cat="{cat}" title="{desc}">{_esc(kc)}</span>'
            )
        kc_html = f"""
        <div class="profile-row">
          <div class="profile-row-label">System Capabilities (KC Sub-Codes)</div>
          <div class="kc-subcodes-grid">{"".join(kc_badges)}</div>
        </div>"""

    return f"""
    <div id="sec-profile" class="section">
      <div class="section-header">
        <h2>Capability Profile</h2>
        <span class="badge">Schneider 5-Zone</span>
      </div>

      <div class="card">
        <div class="profile-row">
          <div class="profile-row-label">Active Zones</div>
          <div class="zone-strip">{"".join(zone_chips)}</div>
        </div>

        <div class="profile-row">
          <div class="profile-row-label">Capability Flags</div>
          <div class="flags-inline">{"".join(flag_chips)}</div>
        </div>
        {ep_html}
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory</div>
          {tools_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">External Integrations</div>
          {integrations_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Entry-Point Inventory Completeness</div>
          <span class="flag-value">{_esc(entry_point_completeness.replace("_", " ").title())}</span>
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Entry-Point Inventory Evidence</div>
          {entry_point_evidence_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory Completeness</div>
          <span class="flag-value">{_esc(tool_inventory_completeness.replace("_", " ").title())}</span>
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Tool Inventory Evidence</div>
          {tool_inventory_evidence_html}
        </div>
        <div class="profile-row">
          <div class="profile-row-label">Corpus Claim Applicability</div>
          <span class="flag-value">{_esc(_corpus_applicability_label(corpus_claims or []))}</span>
        </div>
        {kc_html}
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2: Threat Surface
# ---------------------------------------------------------------------------


def build_threat_surface_section(
    threat_surface: dict[str, Any],
    scenarios: list[dict] | None = None,
) -> str:
    entries = threat_surface.get("entries", [])
    governance = threat_surface.get("governance_only", [])
    all_entries = entries + governance

    # Build per-threat-ID scenario index sets for deduplication across entries.
    # Each scenario may reference multiple threat IDs; an entry may list
    # multiple threat IDs.  We want *distinct* scenario counts per entry.
    _tid_to_scenarios: dict[str, list[tuple[int, str]]] = {}
    if scenarios:
        for idx, sc in enumerate(scenarios):
            tids = (
                sc.get("faceting", {})
                .get("taxonomy_chain", {})
                .get("agentic_threat_ids", [])
            )
            composite = sc.get("priority", {}).get("composite", 0)
            label = _priority_label(composite).lower()
            for tid in tids:
                _tid_to_scenarios.setdefault(tid, []).append((idx, label))
    has_outcomes = bool(_tid_to_scenarios)

    # Option A: Table
    table_rows = ""
    for entry in all_entries:
        rc = entry.get("risk_card", {})
        gov = entry.get("governance_only", False)
        status_cls = "status-governance" if gov else "status-actionable"
        status_text = "GOV" if gov else "ACT"
        status_tip = (
            "Governance: maps to organizational controls, not directly testable"
            if gov
            else "Actionable: maps to testable agentic threat scenarios"
        )

        # Build LLM IDs with tooltips
        raw_llm = entry.get("owasp_llm_ids", [])
        if raw_llm:
            llm_spans = ", ".join(
                f'<span data-tooltip="OWASP Top 10 for LLM Applications '
                f'— standardized LLM vulnerability category">{_esc(lid)}</span>'
                for lid in raw_llm
            )
        else:
            llm_spans = "-"

        # Build agentic threat IDs with tooltips (count badge for 3+)
        raw_tids = entry.get("agentic_threat_ids", [])
        if not raw_tids:
            tid_spans = "-"
        elif len(raw_tids) <= 2:
            tid_spans = ", ".join(
                f"<span{_threat_id_tooltip(tid)}>{_esc(tid)}</span>" for tid in raw_tids
            )
        else:
            tid_tooltip_lines = "&#10;".join(
                f"{_esc(tid)} — {_esc(THREAT_NAMES.get(tid, ''))}" for tid in raw_tids
            )
            tid_spans = (
                f'<span class="count-badge" data-tooltip="{tid_tooltip_lines}">'
                f"{len(raw_tids)} threats</span>"
            )

        # Build attack pattern IDs with tooltips (count badge for 3+)
        raw_aps = entry.get("attack_pattern_ids", [])
        if not raw_aps:
            sub_spans = "-"
        elif len(raw_aps) <= 2:
            ap_parts: list[str] = []
            for ap_id in raw_aps:
                ap_parts.append(
                    f"<span{_attack_pattern_tooltip(ap_id)}>{_esc(ap_id)}</span>"
                )
            sub_spans = ", ".join(ap_parts)
        else:
            ap_tooltip_lines = "&#10;".join(
                f"{_esc(ap_id)}: {_esc(_ATTACK_PATTERN_INFO.get(ap_id, {}).get('name', ''))}"
                for ap_id in raw_aps
            )
            sub_spans = (
                f'<span class="count-badge" data-tooltip="{ap_tooltip_lines}">'
                f"{len(raw_aps)} patterns</span>"
            )

        # Risk ID tooltip for atlas-* IDs
        risk_id = rc.get("risk_id", "")
        risk_id_tip = ""
        if risk_id.startswith("atlas-"):
            risk_id_tip = (
                ' data-tooltip="IBM AI Risk Atlas — standardized AI risk identifier"'
            )

        conf = rc.get("confidence", 0)
        conf_display = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)

        # Outcomes cell — unique scenarios across this entry's agentic threat IDs
        outcomes_cell = ""
        if has_outcomes:
            seen: dict[int, str] = {}  # scenario_idx -> priority label
            for tid in raw_tids:
                for idx, label in _tid_to_scenarios.get(tid, []):
                    if idx not in seen:
                        seen[idx] = label
            total = len(seen)
            h = sum(1 for lbl in seen.values() if lbl == "high")
            m = sum(1 for lbl in seen.values() if lbl == "medium")
            lo = sum(1 for lbl in seen.values() if lbl == "low")
            if total:
                parts: list[str] = []
                if h:
                    parts.append(
                        f'<span style="background:var(--high);color:#fff;'
                        f'padding:1px 6px;border-radius:9px;font-size:.8em;">'
                        f"{h} high</span>"
                    )
                if m:
                    parts.append(
                        f'<span style="background:var(--medium);color:#fff;'
                        f'padding:1px 6px;border-radius:9px;font-size:.8em;">'
                        f"{m} med</span>"
                    )
                if lo:
                    parts.append(
                        f'<span style="background:var(--low);color:#fff;'
                        f'padding:1px 6px;border-radius:9px;font-size:.8em;">'
                        f"{lo} low</span>"
                    )
                badge_html = " ".join(parts)
                outcomes_cell = (
                    f"<td data-tooltip=\"Scenarios generated from this entry's"
                    f' threat IDs">{total} scenarios {badge_html}</td>'
                )
            else:
                outcomes_cell = (
                    '<td style="color:var(--muted);">'
                    '<span style="opacity:.5;">0 scenarios</span></td>'
                )

        table_rows += f"""
        <tr>
          <td{risk_id_tip}>{_esc(risk_id)}</td>
          <td>{_esc(rc.get("risk_name", ""))}</td>
          <td><span class="status-badge {status_cls}" data-tooltip="{_esc(status_tip)}">{status_text}</span></td>
          <td data-tooltip="Upstream extraction confidence — how strongly the policy text maps to this risk">{conf_display}</td>
          <td>{llm_spans}</td>
          <td>{tid_spans}</td>
          <td>{sub_spans}</td>
          {outcomes_cell}
        </tr>"""

    # Build risk_id -> risk_name lookup for Sankey tooltips
    risk_tips: dict[str, str] = {}
    for entry in entries:
        rc = entry.get("risk_card", {})
        rid = rc.get("risk_id", "")
        rname = rc.get("risk_name", "")
        if rid and rname:
            risk_tips[rid] = rname

    # Option B: Sankey-style SVG
    sankey_svg = _build_sankey_svg(entries, risk_tips=risk_tips)

    # Column widths for fixed table layout — vary with/without Outcomes column
    if has_outcomes:
        _rw = ["14%", "18%", "9%", "8%", "9%", "11%", "14%", "17%"]
        outcomes_th = f'<th style="width:{_rw[7]}">Outcomes</th>'
    else:
        _rw = ["15%", "21%", "10%", "9%", "10%", "13%", "22%"]
        outcomes_th = ""

    return f"""
    <div id="sec-threats" class="section">
      <div class="section-header">
        <h2>Threat Surface</h2>
        <span class="badge">{len(entries)} actionable / {len(governance)} governance</span>
      </div>

      <div class="view-toggle">
        <button class="active" onclick="toggleView('view-table', this)">Table View</button>
        <button onclick="toggleView('view-sankey', this)">Flow Diagram</button>
      </div>

      <div id="view-table" class="view-panel active">
        <div class="card" style="overflow-x:auto;">
          <table class="risk-table">
            <thead>
              <tr>
                <th style="width:{_rw[0]}">Risk ID</th>
                <th style="width:{_rw[1]}">Risk Name</th>
                <th style="width:{_rw[2]}">Status</th>
                <th style="width:{_rw[3]}">Confidence</th>
                <th style="width:{_rw[4]}">LLM Top 10</th>
                <th style="width:{_rw[5]}">Agentic Threats</th>
                <th style="width:{_rw[6]}">Attack Patterns</th>
                {outcomes_th}
              </tr>
            </thead>
            <tbody>{table_rows}</tbody>
          </table>
        </div>
      </div>

      <div id="view-sankey" class="view-panel">
        <div class="card">
          <div class="sankey-container">{sankey_svg}</div>
          <div id="sankey-tip" style="display:none;position:absolute;padding:6px 10px;background:#1a1a2e;color:#e0e0e0;border:1px solid #333;border-radius:4px;font-size:0.8rem;max-width:400px;white-space:normal;z-index:1000;pointer-events:none;"></div>
        </div>
      </div>

      <script>
      (function() {{
        var tip = document.getElementById('sankey-tip');
        document.querySelectorAll('.sankey-node[data-tip]').forEach(function(g) {{
          g.addEventListener('mouseenter', function() {{
            tip.textContent = g.getAttribute('data-tip');
            tip.style.display = 'block';
          }});
          g.addEventListener('mousemove', function(e) {{
            tip.style.left = (e.pageX + 12) + 'px';
            tip.style.top = (e.pageY - 28) + 'px';
          }});
          g.addEventListener('mouseleave', function() {{
            tip.style.display = 'none';
          }});
        }});
      }})();
      </script>
    </div>
    """


def _build_sankey_svg(
    entries: list[dict[str, Any]],
    risk_tips: dict[str, str] | None = None,
) -> str:
    """Build a pure SVG Sankey-style flow diagram."""
    if not entries:
        return '<p style="color:var(--text-muted);text-align:center;padding:40px;">No actionable entries to visualize.</p>'

    # Collect unique nodes for each column
    risk_ids: list[str] = []
    llm_ids_set: list[str] = []
    threat_ids_set: list[str] = []
    scenario_ids_set: list[str] = []

    for e in entries:
        rc = e.get("risk_card", {})
        rid = rc.get("risk_id", "")
        if rid and rid not in risk_ids:
            risk_ids.append(rid)
        for lid in e.get("owasp_llm_ids", []):
            if lid and lid not in llm_ids_set:
                llm_ids_set.append(lid)
        for tid in e.get("agentic_threat_ids", []):
            if tid and tid not in threat_ids_set:
                threat_ids_set.append(tid)
        for ap_id in e.get("attack_pattern_ids", []):
            if ap_id and ap_id not in scenario_ids_set:
                scenario_ids_set.append(ap_id)

    # Layout constants
    col_x = [40, 240, 440, 640]
    node_w = 140
    node_h = 30
    node_gap = 8
    top_pad = 50
    colors = ["#3b82f6", "#8b5cf6", "#f97316", "#ef4444"]
    label_names = ["Risk Atlas", "LLM Top 10", "Agentic Threats", "Attack Patterns"]

    columns = [risk_ids, llm_ids_set, threat_ids_set, scenario_ids_set]

    # Calculate total height
    max_nodes = max(len(c) for c in columns) if columns else 1
    svg_h = max(top_pad + max_nodes * (node_h + node_gap) + 40, 200)

    # Center each column vertically
    def node_y(col_idx: int, item_idx: int) -> float:
        col = columns[col_idx]
        total_h = len(col) * node_h + (len(col) - 1) * node_gap
        start_y = top_pad + (svg_h - top_pad - 20 - total_h) / 2
        return start_y + item_idx * (node_h + node_gap)

    # Build node positions
    node_pos: dict[str, tuple[float, float, float, float]] = {}
    svg_nodes = ""

    for ci, col in enumerate(columns):
        for ni, name in enumerate(col):
            x = col_x[ci]
            y = node_y(ci, ni)
            node_pos[f"{ci}:{name}"] = (x, y, x + node_w, y + node_h)

            truncated = name if len(name) <= 20 else name[:17] + "..."
            tip = _esc(_node_tip(ci, name, risk_tips))
            svg_nodes += f"""
            <g class="sankey-node" data-tip="{tip}">
              <rect x="{x}" y="{y}" width="{node_w}" height="{node_h}"
                    fill="{colors[ci]}" opacity="0.8"/>
              <text x="{x + node_w / 2}" y="{y + node_h / 2 + 4}"
                    text-anchor="middle" font-size="10" fill="white" font-weight="600"
                    pointer-events="none">
                {_esc(truncated)}
              </text>
            </g>"""

    # Build links
    svg_links = ""
    link_colors = ["#3b82f6", "#8b5cf6", "#f97316"]

    for e in entries:
        rc = e.get("risk_card", {})
        rid = rc.get("risk_id", "")

        # Risk -> LLM
        for lid in e.get("owasp_llm_ids", []):
            svg_links += _sankey_link(node_pos, f"0:{rid}", f"1:{lid}", link_colors[0])

        # LLM -> Threat
        for lid in e.get("owasp_llm_ids", []):
            for tid in e.get("agentic_threat_ids", []):
                svg_links += _sankey_link(
                    node_pos, f"1:{lid}", f"2:{tid}", link_colors[1]
                )

        # Threat -> Attack Pattern
        for tid in e.get("agentic_threat_ids", []):
            for ap_id in e.get("attack_pattern_ids", []):
                svg_links += _sankey_link(
                    node_pos, f"2:{tid}", f"3:{ap_id}", link_colors[2]
                )

    # Column headers
    svg_headers = ""
    for ci, label in enumerate(label_names):
        svg_headers += f"""
        <text x="{col_x[ci] + node_w / 2}" y="30" text-anchor="middle"
              fill="var(--text-muted)" font-size="11" font-weight="600"
              text-transform="uppercase" letter-spacing="0.5">{_esc(label)}</text>"""

    return f"""
    <svg class="sankey-svg" viewBox="0 0 820 {svg_h}" xmlns="http://www.w3.org/2000/svg">
      {svg_headers}
      {svg_links}
      {svg_nodes}
    </svg>
    """


def _sankey_link(
    node_pos: dict[str, tuple[float, float, float, float]],
    from_key: str,
    to_key: str,
    color: str,
) -> str:
    if from_key not in node_pos or to_key not in node_pos:
        return ""
    _x1, y1, x1r, y1b = node_pos[from_key]
    x2, y2, _x2r, y2b = node_pos[to_key]
    sx = x1r
    sy = (y1 + y1b) / 2
    ex = x2
    ey = (y2 + y2b) / 2
    cp1 = (sx + ex) / 2
    return (
        f'<path class="sankey-link" d="M{sx},{sy} C{cp1},{sy} {cp1},{ey} {ex},{ey}"'
        f' stroke="{color}" stroke-width="2"/>'
    )


# ---------------------------------------------------------------------------
# Section 2b: Coverage Gaps
# ---------------------------------------------------------------------------


def _coverage_status(count: int) -> tuple[str, str]:
    """Return (css_class, label) based on the number of uncovered items."""
    if count == 0:
        return "coverage-status-green", "Covered"
    if count <= 2:
        return "coverage-status-amber", f"{count} gap{'s' if count != 1 else ''}"
    return "coverage-status-red", f"{count} gaps"


# Human-readable labels for pipeline funnel-stage attribution codes.
_GAP_REASON_LABELS: dict[str, str] = {
    "deterministic_rule_rejection": "rejected by deterministic rules",
    "filter_rejection": "filtered out by LLM filter",
    "projection_rejection": "no compatible projection",
    "selection_limitation": "cap overflow (coverage preserved)",
    "generation_exhaustion": "generation exhausted",
    "admission_failure": "admission failure",
    "projection_limitation": "projection budget limit",
    "no_seed": "no seed generated",
    "no_candidate": "no candidate expanded",
    "rejected": "filtered out",
    "generation_failed": "generation failed",
    "out_of_scope": "out of scope",
}


def _attribution_span(reason: str) -> str:
    """Return an HTML span with a human-readable attribution label."""
    label = _GAP_REASON_LABELS.get(reason, reason)
    return f' <span class="coverage-reason">{_esc(label)}</span>'


def build_coverage_section(coverage_data: dict[str, Any]) -> str:
    """Build the Coverage Gaps section from loaded coverage-gaps.json data.

    Args:
        coverage_data: Parsed JSON from ``coverage-gaps.json``.

    Returns:
        HTML string for the coverage gaps section.
    """
    gaps = coverage_data.get("coverage_gaps", {})
    uncovered_eps = gaps.get("uncovered_entry_points", [])
    uncovered_zones = gaps.get("uncovered_zones", [])
    uncovered_threats = gaps.get("uncovered_threats", [])
    uncovered_aps = gaps.get("uncovered_attack_patterns", [])
    universe_data = coverage_data.get("coverage_universe", {})
    completeness = universe_data.get("completeness", "not_applicable")
    attributions = gaps.get("gap_attributions", {})
    ep_attributions = attributions.get("entry_points", {})

    total_gaps = (
        len(uncovered_eps)
        + len(uncovered_zones)
        + len(uncovered_threats)
        + len(uncovered_aps)
    )

    # Entry points card
    ep_cls, ep_label = _coverage_status(len(uncovered_eps))
    if uncovered_eps:
        ep_items_parts: list[str] = []
        for ep in uncovered_eps:
            if isinstance(ep, dict):
                name = ep.get("name", "")
                ep_id = ep.get("entry_point_id", "")
                attr = ep_attributions.get(ep_id, "")
            else:
                # Legacy string fallback.
                name = str(ep)
                attr = ep_attributions.get(ep, "")
            attr_span = _attribution_span(attr) if attr else ""
            ep_items_parts.append(f"<li>{_esc(name)}{attr_span}</li>")
        ep_items = "".join(ep_items_parts)
        ep_body = f'<ul class="coverage-list">{ep_items}</ul>'
    else:
        if completeness == "confirmed_complete":
            ep_message = "All confirmed entry points have scenario coverage."
        else:
            ep_message = (
                "All identified feasible entry points have scenario coverage; "
                "inventory completeness is not confirmed."
            )
        ep_body = f'<div class="coverage-empty">{ep_message}</div>'

    # Zones card
    z_cls, z_label = _coverage_status(len(uncovered_zones))
    if uncovered_zones:
        z_items = "".join(
            f"<li>{_esc(ZONE_DISPLAY_NAMES.get(_normalize_zone(z), str(z)))}</li>"
            for z in uncovered_zones
        )
        z_body = f'<ul class="coverage-list">{z_items}</ul>'
    else:
        z_body = '<div class="coverage-empty">All active zones are traversed by scenarios.</div>'

    # Threats card
    t_cls, t_label = _coverage_status(len(uncovered_threats))
    if uncovered_threats:
        t_items = "".join(f"<li>{_esc(t)}</li>" for t in uncovered_threats)
        t_body = f'<ul class="coverage-list">{t_items}</ul>'
    else:
        t_body = '<div class="coverage-empty">All in-scope threats have scenario coverage.</div>'

    # Attack patterns card
    ap_cls, ap_label = _coverage_status(len(uncovered_aps))
    if uncovered_aps:
        ap_items = "".join(f"<li>{_esc(ap)}</li>" for ap in uncovered_aps)
        ap_body = f'<ul class="coverage-list">{ap_items}</ul>'
    else:
        ap_body = '<div class="coverage-empty">All in-scope attack patterns have scenario coverage.</div>'

    # Overall status badge
    if total_gaps == 0:
        badge_text = (
            "Full Coverage"
            if completeness == "confirmed_complete"
            else "Known Targets Covered"
        )
    else:
        badge_text = f"{total_gaps} gap{'s' if total_gaps != 1 else ''}"

    # --- cmps.4: Categorized coverage summary (blocker 3) ---
    summary = coverage_data.get("coverage_summary", {})
    summary_html = ""
    if summary:
        covered = summary.get("covered_feasible", [])
        policy_exc = summary.get("policy_exclusions", [])
        struct_gaps = summary.get("structural_gaps", [])
        sel_lims = summary.get("selection_limitations", [])
        runtime_gaps = summary.get("runtime_generation_gaps", [])
        quarantine_fails = summary.get("quarantine_admission_failures", [])
        proj_lims = summary.get("projection_limitations", [])

        def _cat_card(title: str, items: list, css_cls: str = "") -> str:
            if not items:
                return ""
            parts = []
            for item in items:
                if isinstance(item, dict):
                    primary = (
                        item.get("entry_point_name")
                        or item.get("name")
                        or item.get("entry_point_id")
                        or ""
                    )
                    reason = item.get("reason")
                    reason_span = _attribution_span(reason) if reason else ""
                    detail = item.get("detail")
                    detail_span = (
                        f' <span class="coverage-reason">{_esc(detail)}</span>'
                        if detail
                        else ""
                    )
                    candidate_ids = item.get("candidate_ids") or []
                    cand_span = (
                        f' <code class="candidate-id">{_esc(", ".join(candidate_ids))}</code>'
                        if candidate_ids
                        else ""
                    )
                    parts.append(
                        f"<li>{_esc(primary)}{reason_span}{detail_span}{cand_span}</li>"
                    )
                else:
                    parts.append(f"<li>{_esc(str(item))}</li>")
            return (
                f'<div class="coverage-card">'
                f'<div class="coverage-card-header">'
                f'<span class="coverage-card-title">{_esc(title)}</span>'
                f'<span class="coverage-status {css_cls}">{len(items)}</span>'
                f'</div><ul class="coverage-list">{"".join(parts)}</ul></div>'
            )

        cat_cards = []
        if covered:
            cat_cards.append(
                f'<div class="coverage-card">'
                f'<div class="coverage-card-header">'
                f'<span class="coverage-card-title">Covered Feasible Targets</span>'
                f'<span class="coverage-status coverage-status-green">{len(covered)}</span>'
                f'</div><ul class="coverage-list">'
                + "".join(f"<li>{_esc(t)}</li>" for t in covered)
                + "</ul></div>"
            )
        if policy_exc:
            cat_cards.append(_cat_card("Policy Exclusions", policy_exc))
        if struct_gaps:
            cat_cards.append(
                _cat_card(
                    "Structural / Projection Gaps", struct_gaps, "coverage-status-red"
                )
            )
        if sel_lims:
            cat_cards.append(
                _cat_card("Selection Limitations", sel_lims, "coverage-status-amber")
            )
        if runtime_gaps:
            cat_cards.append(
                _cat_card(
                    "Runtime Generation Gaps", runtime_gaps, "coverage-status-red"
                )
            )
        if quarantine_fails:
            cat_cards.append(
                _cat_card(
                    "Quarantine / Admission Failures",
                    quarantine_fails,
                    "coverage-status-red",
                )
            )
        if proj_lims:
            cat_cards.append(
                _cat_card("Projection Limitations", proj_lims, "coverage-status-amber")
            )

        if cat_cards:
            summary_html = (
                '<div class="coverage-grid" style="margin-top:1rem">'
                + "".join(cat_cards)
                + "</div>"
            )

    # --- cmps.4: Coverage plan (blocker 2) ---
    plan = coverage_data.get("coverage_plan", {})
    plan_html = ""
    if plan and plan.get("targets"):
        plan_rows = []
        for entry in plan["targets"]:
            ep_id = entry.get("entry_point_id", "")
            ep_name = entry.get("entry_point_name", "")
            primary = entry.get("primary_candidate_id") or "—"
            state = entry.get("primary_state", "—")
            fb_count = len(entry.get("fallback_available", []))
            choices = entry.get("ordered_choices", [])
            choice_ids = [c.get("candidate_id", "") for c in choices]
            plan_rows.append(
                f"<tr><td>{_esc(ep_name)}</td><td>{_esc(primary)}</td>"
                f"<td>{_esc(state)}</td>"
                f"<td>{_esc(', '.join(choice_ids))}</td>"
                f"<td>{fb_count}</td></tr>"
            )
        plan_html = (
            '<div style="margin-top:1rem">'
            "<h3>Coverage Plan (schema v"
            + _esc(str(plan.get("schema_version", "")))
            + ")</h3>"
            '<table class="data-table"><thead><tr>'
            "<th>Target</th><th>Primary Candidate</th><th>State</th>"
            "<th>Ordered Choices</th><th>Fallback Available</th>"
            "</tr></thead><tbody>" + "".join(plan_rows) + "</tbody></table></div>"
        )

    # --- cmps.4 blocker 4: Coverage universe completeness and bounded set ---
    universe_html = ""
    if universe_data:
        evidence_refs = universe_data.get("evidence_refs", [])
        feasible_targets = universe_data.get("feasible_targets", [])
        excluded_targets = universe_data.get("excluded_targets", [])

        completeness_label = (
            "Confirmed Complete"
            if completeness == "confirmed_complete"
            else "Not Applicable (Inferred Partial)"
        )
        completeness_cls = (
            "coverage-status-green"
            if completeness == "confirmed_complete"
            else "coverage-status-amber"
        )

        # Bounded canonical target set.
        target_items = "".join(
            f"<li>{_esc(t.get('name', t.get('entry_point_id', '')))}"
            f" <code>{_esc(t.get('entry_point_id', ''))}</code>"
            f" <span class='coverage-status coverage-status-green'>"
            f"{_esc(t.get('direction', ''))}/{_esc(t.get('controllability', ''))}"
            f"</span></li>"
            for t in feasible_targets
        )
        excluded_items = "".join(
            f"<li>{_esc(e.get('name', e.get('entry_point_id', '')))}"
            f" <span class='coverage-status coverage-status-red'>"
            f"{_esc(e.get('reason', ''))}</span></li>"
            for e in excluded_targets
        )
        evidence_html = (
            "<div class='coverage-empty'>Evidence: "
            + ", ".join(_esc(e) for e in evidence_refs)
            + "</div>"
            if evidence_refs
            else "<div class='coverage-empty'>No operator-confirmed evidence</div>"
        )

        universe_html = (
            '<div style="margin-top:1rem">'
            "<h3>Coverage Universe</h3>"
            '<div class="coverage-card">'
            '<div class="coverage-card-header">'
            '<span class="coverage-card-title">Inventory Completeness</span>'
            f'<span class="coverage-status {completeness_cls}">'
            f"{_esc(completeness_label)}</span>"
            "</div>"
            f"{evidence_html}"
            "</div>"
            '<div class="coverage-grid" style="margin-top:0.5rem">'
            f'<div class="coverage-card">'
            '<div class="coverage-card-header">'
            f'<span class="coverage-card-title">'
            f"Feasible Targets ({len(feasible_targets)})</span>"
            '</div><ul class="coverage-list">' + target_items + "</ul></div>"
            f'<div class="coverage-card">'
            '<div class="coverage-card-header">'
            f'<span class="coverage-card-title">'
            f"Excluded Targets ({len(excluded_targets)})</span>"
            '</div><ul class="coverage-list">' + excluded_items + "</ul></div>"
            "</div></div>"
        )

    return f"""
    <div id="sec-coverage" class="section">
      <div class="section-header">
        <h2>Coverage Analysis</h2>
        <span class="badge">{badge_text}</span>
      </div>

      <div class="coverage-grid">
        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Entry Points</span>
            <span class="coverage-status {ep_cls}">{ep_label}</span>
          </div>
          {ep_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Active Zones</span>
            <span class="coverage-status {z_cls}">{z_label}</span>
          </div>
          {z_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">In-Scope Threats</span>
            <span class="coverage-status {t_cls}">{t_label}</span>
          </div>
          {t_body}
        </div>

        <div class="coverage-card">
          <div class="coverage-card-header">
            <span class="coverage-card-title">Attack Patterns</span>
            <span class="coverage-status {ap_cls}">{ap_label}</span>
          </div>
          {ap_body}
        </div>
      </div>
      {summary_html}
      {universe_html}
      {plan_html}
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2c: Threat-Technique Matrix
# ---------------------------------------------------------------------------


def _technique_id_tooltip(technique_id: str) -> str:
    """Return a data-tooltip attribute for an ATLAS technique ID."""
    name = _ATLAS_TECHNIQUE_NAMES.get(technique_id, "")
    if not name:
        return ""
    desc = ATLAS_TECHNIQUE_DESCRIPTIONS.get(technique_id, "")
    if desc:
        return f' data-tooltip="{_esc(technique_id)} — {_esc(name)}&#10;{_esc(desc)}"'
    return f' data-tooltip="MITRE ATLAS: {_esc(technique_id)} — {_esc(name)}"'


def build_threat_technique_section(
    scenarios: list[dict[str, Any]],
    in_scope_threats: list[str] | None = None,
) -> str:
    """Build the Threat-Technique Matrix section.

    Contains two tables:
    1. Cross-reference matrix: threats (rows) x techniques (columns) with scenario links
    2. Scenario roster: one row per scenario with key metadata

    Args:
        scenarios: List of parsed scenario envelope dicts.
        in_scope_threats: Explicit list of in-scope threat IDs (e.g. from threat gating).
            If None, derives from scenarios and shows all T1-T17.

    Returns:
        HTML string for the section, or empty string if no scenarios.
    """
    if not scenarios:
        return ""

    # --- Build scenario ID -> title lookup ---
    sid_titles: dict[str, str] = {}
    for s in scenarios:
        s_id = s.get("scenario_id", "")
        s_title = s.get("narrative", {}).get("title", "")
        if s_id and s_title:
            sid_titles[s_id] = s_title

    # --- Collect data from scenarios ---
    # Map: threat_id -> technique_id -> list[scenario_id]
    threat_tech_map: dict[str, dict[str, list[str]]] = {}
    # Collect all technique IDs appearing in this batch
    all_techniques: list[str] = []
    # Collect per-scenario metadata for roster
    roster_rows: list[dict[str, Any]] = []

    for s in scenarios:
        sid = s.get("scenario_id", "")
        faceting = s.get("faceting", {})
        tc = faceting.get("taxonomy_chain", {})
        cp = faceting.get("capability_profile", {})

        threat_ids = tc.get("agentic_threat_ids", [])
        technique_ids = tc.get("atlas_technique_ids", [])
        scenario_seed = tc.get("scenario_seed", "")
        zones_traversed = [_normalize_zone(z) for z in cp.get("zones_traversed", [])]

        actor_profile = s.get("actor_profile", {}) or {}
        actor_type = actor_profile.get("actor_type", "")
        capability_level = actor_profile.get("capability_level", "")

        # Extract pinned technique(s) from candidate_filter
        # Support both plural (new) and singular (old YAML) field names
        candidate_filter = s.get("candidate_filter", {}) or {}
        pinned_technique_ids = candidate_filter.get("pinned_technique_ids") or []
        if not pinned_technique_ids:
            # Backward compat: old YAML has singular field
            old_id = candidate_filter.get("pinned_technique_id", "")
            pinned_technique_ids = [old_id] if old_id else []
        pinned_technique_names = candidate_filter.get("pinned_technique_names") or []
        if not pinned_technique_names:
            old_name = candidate_filter.get("pinned_technique_name", "")
            pinned_technique_names = [old_name] if old_name else []
        # Extract parent threat from scenario_seed (e.g. "AP-T10-01" -> "T10")
        parent_threat = ""
        if scenario_seed:
            parts = scenario_seed.split("-")
            if len(parts) >= 2:
                parent_threat = parts[1]
        if not parent_threat and threat_ids:
            parent_threat = threat_ids[0]

        # Populate cross-reference map
        for tid in threat_ids:
            base_tid = tid.split("-")[0] if "-" in tid else tid
            if base_tid not in threat_tech_map:
                threat_tech_map[base_tid] = {}
            for tech_id in technique_ids:
                if tech_id not in threat_tech_map[base_tid]:
                    threat_tech_map[base_tid][tech_id] = []
                if sid not in threat_tech_map[base_tid][tech_id]:
                    threat_tech_map[base_tid][tech_id].append(sid)
                if tech_id not in all_techniques:
                    all_techniques.append(tech_id)

        # Collect roster row
        roster_rows.append(
            {
                "scenario_id": sid,
                "threat": parent_threat,
                "threat_ids": threat_ids,
                "attack_pattern": scenario_seed,
                "pinned_technique_ids": pinned_technique_ids,
                "pinned_technique_names": pinned_technique_names,
                "technique_ids": technique_ids,
                "actor_type": actor_type,
                "capability_level": capability_level,
                "zones_traversed": zones_traversed,
            }
        )

    # Sort techniques for consistent column order
    all_techniques.sort()

    # All T1-T17 rows; greyed if no scenarios map to that threat
    all_threat_ids = [f"T{i}" for i in range(1, 18)]

    # --- Build Table 1: Cross-reference matrix ---
    # Column headers (rotated)
    tech_headers = ""
    for tech_id in all_techniques:
        tech_tip = _technique_id_tooltip(tech_id)
        tech_headers += (
            f'<th class="matrix-col-header"{tech_tip}>'
            f'<span class="matrix-col-header-text">{_esc(tech_id)}</span></th>'
        )

    # Rows
    matrix_rows = ""
    for tid in all_threat_ids:
        threat_name = THREAT_NAMES.get(tid, "")
        has_scenarios = tid in threat_tech_map
        row_cls = "" if has_scenarios else " matrix-row-greyed"
        tip = _threat_id_tooltip(tid)

        cells = ""
        for tech_id in all_techniques:
            scenario_ids = threat_tech_map.get(tid, {}).get(tech_id, [])
            if scenario_ids:
                count = len(scenario_ids)
                tooltip_lines = "&#10;".join(
                    f"{_esc(s_id)}: {_esc(sid_titles.get(s_id, ''))}"
                    if s_id in sid_titles
                    else _esc(s_id)
                    for s_id in scenario_ids
                )
                # Link to the first scenario for click convenience
                first_sid = scenario_ids[0]
                cells += (
                    f'<td class="matrix-cell">'
                    f'<a class="matrix-count-link" '
                    f'href="#scenario-{_esc(first_sid)}" '
                    f'data-tooltip="{tooltip_lines}">'
                    f"{count}</a></td>"
                )
            else:
                cells += '<td class="matrix-cell"></td>'

        matrix_rows += (
            f'<tr class="{row_cls.strip()}">'
            f'<td class="matrix-sticky-col matrix-sticky-col-0"{tip}>'
            f"<strong>{_esc(tid)}</strong></td>"
            f'<td class="matrix-sticky-col matrix-sticky-col-1">'
            f"{_esc(threat_name)}</td>"
            f"{cells}"
            f"</tr>"
        )

    matrix_html = f"""
      <div class="card" style="overflow-x:auto;margin-bottom:24px;">
        <div class="scenario-section-title">Cross-Reference Matrix</div>
        <table class="matrix-table">
          <thead>
            <tr>
              <th class="matrix-sticky-col matrix-sticky-col-0">Threat</th>
              <th class="matrix-sticky-col matrix-sticky-col-1">Name</th>
              {tech_headers}
            </tr>
          </thead>
          <tbody>{matrix_rows}</tbody>
        </table>
      </div>"""

    # --- Build Table 2: Scenario roster ---
    roster_rows.sort(key=lambda r: r["scenario_id"])

    roster_body = ""
    for row in roster_rows:
        sid = row["scenario_id"]
        # Threat column: show parent threat with tooltip of full agentic_threat_ids
        parent_threat = row["threat"]
        if parent_threat:
            full_threats = "&#10;".join(row["threat_ids"]) if row["threat_ids"] else ""
            threat_tip = f' data-tooltip="{_esc(full_threats)}"' if full_threats else ""
            threat_spans = (
                f"<span{_threat_id_tooltip(parent_threat)}>{_esc(parent_threat)}</span>"
                if not threat_tip
                else f"<span{threat_tip}>{_esc(parent_threat)}</span>"
            )
        else:
            # Fallback: show all threat_ids
            threat_spans = ", ".join(
                f"<span{_threat_id_tooltip(t)}>{_esc(t)}</span>"
                for t in row["threat_ids"]
            )
        sub = row["attack_pattern"]
        # Technique column: show pinned technique(s) with tooltip of name(s)
        pinned_ids = row["pinned_technique_ids"]
        if pinned_ids:
            pinned_names_list = row["pinned_technique_names"]
            if len(pinned_ids) == 1:
                pinned_name_display = pinned_names_list[0] if pinned_names_list else ""
                tech_tip = (
                    f' data-tooltip="{_esc(pinned_name_display)}"'
                    if pinned_name_display
                    else ""
                )
                tech_spans = f"<span{tech_tip}>{_esc(pinned_ids[0])}</span>"
            else:
                # Multi-technique: show count badge with tooltip of all IDs
                combo_display = " + ".join(pinned_ids)
                names_display = (
                    ", ".join(pinned_names_list) if pinned_names_list else combo_display
                )
                tech_tip = f' data-tooltip="{_esc(names_display)}"'
                tech_spans = f'<span class="count-badge"{tech_tip}>{len(pinned_ids)} techniques</span>'
        else:
            # Fallback: show all technique_ids
            tech_spans = ", ".join(
                f"<span{_technique_id_tooltip(t)}>{_esc(t)}</span>"
                for t in row["technique_ids"]
            )
        actor_display = (
            row["actor_type"].replace("-", " ").replace("_", " ").title()
            if row["actor_type"]
            else ""
        )
        cap_display = row["capability_level"].title() if row["capability_level"] else ""

        zone_badges = ""
        for z in row["zones_traversed"]:
            zc = ZONE_COLORS.get(z, "#666")
            zbg = ZONE_BG_COLORS.get(z, "#333")
            zname = ZONE_DISPLAY_NAMES.get(z, z)
            zabbr = ZONE_ABBREVS.get(z, z)
            zone_badges += (
                f'<span class="zone-badge" style="background:{zbg};'
                f'color:{zc};" data-tooltip="{_esc(zname)}">{_esc(zabbr)}</span>'
            )

        sid_tip = (
            f' data-tooltip="{_esc(sid_titles[sid])}"' if sid in sid_titles else ""
        )
        sub_tip = _attack_pattern_tooltip(sub) if sub else ""

        roster_body += (
            f"<tr>"
            f'<td><a href="#scenario-{_esc(sid)}"{sid_tip}>{_esc(sid)}</a></td>'
            f"<td>{threat_spans}</td>"
            f"<td><span{sub_tip}>{_esc(sub)}</span></td>"
            f"<td>{tech_spans}</td>"
            f"<td>{_esc(actor_display)}</td>"
            f"<td>{_esc(cap_display)}</td>"
            f'<td><div class="roster-zone-badges">{zone_badges}</div></td>'
            f"</tr>"
        )

    roster_html = f"""
      <div class="card" style="overflow-x:auto;">
        <div class="scenario-section-title">Scenario Roster</div>
        <table class="roster-table">
          <thead>
            <tr>
              <th>Scenario ID</th>
              <th>Threat</th>
              <th>Attack Pattern</th>
              <th>Technique</th>
              <th>Actor Type</th>
              <th>Capability</th>
              <th>Zones Traversed</th>
            </tr>
          </thead>
          <tbody>{roster_body}</tbody>
        </table>
      </div>"""

    # Active threats count
    active_count = sum(1 for t in all_threat_ids if t in threat_tech_map)

    return f"""
    <div id="sec-threat-matrix" class="section">
      <div class="section-header">
        <h2>Threat&ndash;Technique Matrix</h2>
        <span class="badge">{active_count}/{len(all_threat_ids)} threats &middot; {len(all_techniques)} techniques &middot; {len(scenarios)} scenarios</span>
      </div>

      {matrix_html}
      {roster_html}
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2d: Actor Profile Distribution
# ---------------------------------------------------------------------------

_DIVERSITY_COLORS: dict[str, str] = {
    "cybercriminal": "#ef4444",  # red
    "nation-state": "#1e40af",  # dark blue
    "malicious-insider": "#f97316",  # orange
    "negligent-insider": "#f59e0b",  # amber/yellow
    "competitor": "#8b5cf6",  # purple
    "hacktivist": "#22c55e",  # green
    "supply-chain-actor": "#14b8a6",  # teal
    "adversarial-user": "#ec4899",  # pink/rose
    "automated-agent": "#6b7280",  # gray
    "unknown": "#4b5563",  # dark gray
}


def build_attacker_diversity_section(scenarios: list[dict[str, Any]]) -> str:
    """Build the Actor Profile Distribution section from scenario data.

    Computes actor type distribution directly from the loaded scenario dicts
    rather than relying on pre-computed data in ``coverage-gaps.json``.

    Args:
        scenarios: List of parsed scenario envelope dicts (from YAML files).

    Returns:
        HTML string for the actor profile distribution section, or empty string
        if no scenarios are provided.
    """
    if not scenarios:
        return ""

    # Count actor types directly from scenario dicts
    model_counts: dict[str, int] = {}
    for s in scenarios:
        actor_profile = s.get("actor_profile")
        if actor_profile and isinstance(actor_profile, dict):
            actor_type = actor_profile.get("actor_type", "unknown")
        else:
            actor_type = "unknown"
        model_counts[actor_type] = model_counts.get(actor_type, 0) + 1

    total = sum(model_counts.values()) if model_counts else 1

    # Compute dominant type and monotone flag (>80% threshold)
    dominant_model = max(model_counts, key=model_counts.get)  # type: ignore[arg-type]
    dominant_count = model_counts[dominant_model]
    dominant_fraction = dominant_count / total
    is_flagged = dominant_fraction > 0.8

    # Warning banner if monotone
    warning_html = ""
    if is_flagged:
        dominant_display = dominant_model.replace("-", " ").replace("_", " ").title()
        pct = int(dominant_fraction * 100)
        warning_html = (
            '<div class="warning-banner">'
            '<span class="warning-banner-icon">&#9888;</span>'
            f"<span>Low actor diversity: {pct}% of scenarios use the "
            f"<strong>{_esc(dominant_display)}</strong> actor type. "
            f"Consider varying threat actor types for broader coverage.</span>"
            "</div>"
        )

    # Bar chart
    bars_html = ""
    for model, count in sorted(model_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        color = _DIVERSITY_COLORS.get(model, "#6b7280")
        display_name = model.replace("-", " ").replace("_", " ").title()
        bars_html += f"""
        <div class="diversity-bar-row">
          <span class="diversity-bar-label">{_esc(display_name)}</span>
          <div class="diversity-bar-track">
            <div class="diversity-bar-fill" style="width:{pct:.0f}%;background:{color};">
              {count}
            </div>
          </div>
          <span class="diversity-bar-count">{pct:.0f}%</span>
        </div>"""

    unique_types = len(model_counts)

    # --- Goal category distribution ---
    _GOAL_COLORS: dict[str, str] = {
        "availability": "#ef4444",
        "integrity": "#f59e0b",
        "privacy": "#8b5cf6",
        "abuse": "#0d9488",
    }
    goal_counts: dict[str, int] = {}
    for s in scenarios:
        actor_profile = s.get("actor_profile")
        if actor_profile and isinstance(actor_profile, dict):
            gcp = actor_profile.get("goal_category_parent", "")
            if gcp:
                goal_counts[gcp] = goal_counts.get(gcp, 0) + 1

    goal_section_html = ""
    if goal_counts:
        goal_total = sum(goal_counts.values())
        goal_bars_html = ""
        for goal, count in sorted(
            goal_counts.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / goal_total * 100) if goal_total > 0 else 0
            color = _GOAL_COLORS.get(goal.lower(), "#6b7280")
            display_name = goal.replace("-", " ").replace("_", " ").title()
            goal_bars_html += f"""
        <div class="diversity-bar-row">
          <span class="diversity-bar-label">{_esc(display_name)}</span>
          <div class="diversity-bar-track">
            <div class="diversity-bar-fill" style="width:{pct:.0f}%;background:{color};">
              {count}
            </div>
          </div>
          <span class="diversity-bar-count">{pct:.0f}%</span>
        </div>"""
        unique_goals = len(goal_counts)
        goal_section_html = f"""
      <div style="margin-top:20px;">
        <h3 style="font-size:15px;font-weight:600;margin:0 0 10px;">Goal Category Distribution
          <span class="badge" style="margin-left:8px;">{unique_goals} categor{"ies" if unique_goals != 1 else "y"}</span>
        </h3>
        <div class="card">
          <div class="diversity-bar-chart">{goal_bars_html}</div>
        </div>
      </div>"""

    return f"""
    <div id="sec-diversity" class="section">
      <div class="section-header">
        <h2>Actor Profile Distribution</h2>
        <span class="badge">{unique_types} type{"s" if unique_types != 1 else ""}</span>
      </div>

      {warning_html}

      <div class="card">
        <div class="diversity-bar-chart">{bars_html}</div>
      </div>

      {goal_section_html}
    </div>
    """


# ---------------------------------------------------------------------------
# Section 3: Scenarios
# ---------------------------------------------------------------------------


def build_scenarios_section(
    scenarios: list[dict[str, Any]],
    feature_files: dict[str, str],
    call_logs: dict[str, list[dict]] | None = None,
    threat_surface: dict[str, Any] | None = None,
    capability_profile: dict[str, Any] | None = None,
    scenarios_generated: int | None = None,
    scorecard_data: dict[str, Any] | None = None,
) -> str:
    if not scenarios:
        return (
            '<div id="sec-scenarios" class="section">'
            '<div class="section-header"><h2>Scenarios</h2></div>'
            '<p style="color:var(--text-muted);">No scenarios generated.</p>'
            "</div>"
        )

    # ------------------------------------------------------------------
    # Pre-compute priority counts for the dashboard header.
    # ------------------------------------------------------------------
    total_count = len(scenarios)
    high_count = 0
    medium_count = 0
    low_count = 0
    for s in scenarios:
        composite = s.get("priority", {}).get("composite", 0)
        label = _priority_label(composite)
        if label == "HIGH":
            high_count += 1
        elif label == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1

    # Donut gradient
    high_pct = (high_count / total_count * 100) if total_count else 0
    medium_pct = (medium_count / total_count * 100) if total_count else 0
    donut_gradient = (
        f"conic-gradient("
        f"var(--high) 0% {high_pct:.1f}%, "
        f"var(--medium) {high_pct:.1f}% {high_pct + medium_pct:.1f}%, "
        f"var(--low) {high_pct + medium_pct:.1f}% 100%"
        f")"
    )

    # ------------------------------------------------------------------
    # Collect all threat IDs, zones, and build coverage matrix (Bead 2)
    # ------------------------------------------------------------------
    all_threat_ids: list[str] = []
    all_zones: set[str] = set()
    # Per-scenario threat-zone pairs for coverage matrix
    coverage_counts: dict[tuple[str, str], int] = {}
    for s in scenarios:
        fac = s.get("faceting", {})
        tc = fac.get("taxonomy_chain", {})
        cp = fac.get("capability_profile", {})
        scenario_threats = tc.get("agentic_threat_ids", [])
        scenario_zones = [_normalize_zone(z) for z in cp.get("zones_traversed", [])]
        for tid in scenario_threats:
            if tid not in all_threat_ids:
                all_threat_ids.append(tid)
        for z in scenario_zones:
            all_zones.add(z)
        # Build coverage matrix counts
        for tid in scenario_threats:
            for z in scenario_zones:
                coverage_counts[(tid, z)] = coverage_counts.get((tid, z), 0) + 1

    sorted_threats = sorted(all_threat_ids)
    # Use canonical zone order, filtered to zones present in scenarios
    canonical_zones = [z for z in ZONE_COLORS if z in all_zones]

    # Coverage gap: threat x zone combos with 0 scenarios
    total_combos = len(sorted_threats) * len(canonical_zones) if canonical_zones else 0
    covered_combos = sum(
        1
        for t in sorted_threats
        for z in canonical_zones
        if coverage_counts.get((t, z), 0) > 0
    )
    coverage_gaps = total_combos - covered_combos

    # ------------------------------------------------------------------
    # Dashboard header HTML (Bead 1)
    # ------------------------------------------------------------------
    dashboard_html = f"""
      <div class="stats-bar">
        <div class="stat-card" style="border-left-color:var(--accent);">
          <span class="stat-number">{total_count}</span>
          <span class="stat-label">In Report</span>
          {"" if scenarios_generated is None or scenarios_generated == total_count else f'<span class="stat-sublabel" style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">of {scenarios_generated} generated</span>'}
        </div>
        <div class="stat-card" style="border-left-color:var(--high);">
          <span class="stat-number">{high_count}</span>
          <span class="stat-label">High Priority</span>
        </div>
        <div class="stat-card" style="border-left-color:var(--medium);">
          <span class="stat-number">{medium_count}</span>
          <span class="stat-label">Medium Priority</span>
        </div>
        <div class="stat-card" style="border-left-color:var(--low);">
          <span class="stat-number">{low_count}</span>
          <span class="stat-label">Low Priority</span>
        </div>
        <div class="severity-donut" style="background:{donut_gradient};" data-tooltip="High: {high_count} | Medium: {medium_count} | Low: {low_count}"></div>
        <div class="coverage-gap-card">
          <span class="stat-number">{coverage_gaps}</span>
          <span class="stat-label">Coverage Gaps</span>
        </div>
      </div>
    """

    # ------------------------------------------------------------------
    # Priority signal decomposition chart
    # ------------------------------------------------------------------
    sorted_scenarios = sorted(
        scenarios,
        key=lambda sc: sc.get("priority", {}).get("composite", 0),
        reverse=True,
    )

    signal_rows = ""
    for s in sorted_scenarios:
        sid = s.get("scenario_id", "")
        priority = s.get("priority", {})
        composite = priority.get("composite", 0)
        signals = priority.get("signals", {})
        short_id = sid.split("-")[-1][:6] if "-" in sid else sid[:6]

        # Build stacked segments
        segments = ""
        total_numeric = 0.0
        segment_values: list[tuple[str, str, str, float, str]] = []
        for sig_key, sig_color, sig_label in _SIGNAL_COLORS:
            raw_val = str(signals.get(sig_key, ""))
            mapping = _SIGNAL_NUMERIC.get(sig_key, {})
            numeric = mapping.get(raw_val, 0.0)
            total_numeric += numeric
            segment_values.append((sig_key, sig_color, sig_label, numeric, raw_val))

        # Normalise segment widths so total bar fills proportional to
        # composite score — each segment is (numeric / total) * 100% of
        # the bar track, and the track itself is scaled by composite.
        for sig_key, sig_color, sig_label, numeric, raw_val in segment_values:
            if total_numeric > 0 and numeric > 0:
                pct = (numeric / total_numeric) * 100
                display_val = raw_val.replace("_", " ") if raw_val else "n/a"
                segments += (
                    f'<div class="signal-segment"'
                    f' style="width:{pct:.1f}%;background:{sig_color};">'
                    f'<span class="tooltip">'
                    f"{_esc(sig_label)}: {_esc(display_val)}"
                    f"</span>"
                    f"</div>"
                )

        bar_width_pct = composite * 100

        signal_rows += (
            f'<div class="signal-bar-row">'
            f'<div class="signal-bar-label"'
            f' title="{_esc(s.get("narrative", {}).get("title", sid))}">'
            f"{_esc(short_id)}</div>"
            f'<div class="signal-bar-track"'
            f' style="max-width:{bar_width_pct:.0f}%;">'
            f"{segments}</div>"
            f'<div class="signal-bar-score">{composite:.2f}</div>'
            f"</div>"
        )

    # Build signal legend
    signal_legend_items = ""
    for _key, color, label in _SIGNAL_COLORS:
        signal_legend_items += (
            f'<span class="signal-legend-item">'
            f'<span class="signal-legend-dot"'
            f' style="background:{color};"></span>'
            f"{_esc(label)}</span>"
        )

    signal_chart_html = (
        f'<div class="signal-chart">{signal_rows}</div>'
        f'<div class="signal-legend">{signal_legend_items}</div>'
    )

    # ------------------------------------------------------------------
    # Coverage heatmap matrix (Bead 2)
    # ------------------------------------------------------------------
    matrix_html = ""
    if sorted_threats and canonical_zones:
        max_count = max(coverage_counts.values()) if coverage_counts else 1
        matrix_html += (
            f'<div class="scenario-section-title" style="margin-top:24px;"'
            f' data-tooltip="Click a cell to filter scenarios by that threat'
            f' and zone combination">Threat x Zone Coverage</div>'
            f'<div class="coverage-matrix" style="grid-template-columns:'
            f' 140px repeat({len(canonical_zones)}, 1fr);">'
        )
        # Header row: empty corner + zone names
        matrix_html += '<div class="matrix-header"></div>'
        for z in canonical_zones:
            zcolor = ZONE_COLORS.get(z, "#666")
            display = ZONE_DISPLAY_NAMES.get(z, z)
            matrix_html += (
                f'<div class="matrix-header"'
                f' style="background:rgba({_hex_to_rgb_css(zcolor)},0.15);'
                f'color:{zcolor};">{_esc(display)}</div>'
            )
        # Data rows
        for tid in sorted_threats:
            tname = THREAT_NAMES.get(tid, "")
            row_label = f"{tid}"
            row_tooltip = f"{tid} — {tname}" if tname else tid
            matrix_html += (
                f'<div class="matrix-row-label"'
                f' data-tooltip="{_esc(row_tooltip)}">{_esc(row_label)}</div>'
            )
            for z in canonical_zones:
                count = coverage_counts.get((tid, z), 0)
                zcolor = ZONE_COLORS.get(z, "#666")
                if count > 0:
                    opacity = 0.2 + 0.8 * (count / max_count)
                    matrix_html += (
                        f'<div class="matrix-cell"'
                        f" onclick=\"filterByCell('{_esc(tid)}','{_esc(z)}')\""
                        f' style="background:rgba({_hex_to_rgb_css(zcolor)},'
                        f'{opacity:.2f});"'
                        f' data-tooltip="{_esc(tid)} x'
                        f" {_esc(ZONE_DISPLAY_NAMES.get(z, z))}:"
                        f' {count} scenario{"s" if count != 1 else ""}">'
                        f"{count}</div>"
                    )
                else:
                    matrix_html += (
                        f'<div class="matrix-cell empty"'
                        f' data-tooltip="{_esc(tid)} x'
                        f" {_esc(ZONE_DISPLAY_NAMES.get(z, z))}:"
                        f' no scenarios">0</div>'
                    )
        matrix_html += "</div>"

    # ------------------------------------------------------------------
    # Entry point distribution (existing)
    # ------------------------------------------------------------------
    ep_counts: dict[str, int] = {}
    for s in scenarios:
        ep = s.get("narrative", {}).get("entry_point", "")
        if ep:
            ep_counts[ep] = ep_counts.get(ep, 0) + 1

    ep_dist_items = ""
    for ep_name, ep_count in sorted(
        ep_counts.items(), key=lambda x: x[1], reverse=True
    ):
        ep_dist_items += (
            f'<div class="ep-dist-item">'
            f'<span class="ep-dist-name" data-tooltip="{_esc(ep_name)}">'
            f"{_esc(ep_name)}</span>"
            f'<span class="ep-dist-count">{ep_count}</span>'
            f"</div>"
        )

    ep_dist_html = ""
    if ep_counts:
        ep_dist_html = f"""
      <div class="card" style="margin-bottom:24px;">
        <div class="scenario-section-title">Entry Point Distribution</div>
        <div class="ep-dist-grid">{ep_dist_items}</div>
      </div>"""

    # ------------------------------------------------------------------
    # Chip/tag filters (Bead 3) — replaces the old <select> dropdowns
    # ------------------------------------------------------------------
    threat_chips = ""
    for tid in sorted_threats:
        tname = THREAT_NAMES.get(tid, "")
        chip_label = f"{tid} — {tname}" if tname else tid
        threat_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="threat" data-filter-value="{_esc(tid)}"'
            f' data-active-bg="rgba({_hex_to_rgb_css("#6366f1")},0.25)"'
            f' data-active-color="#6366f1"'
            f' style="border-color:#6366f1;color:#6366f1;background:transparent;">'
            f"{_esc(chip_label)}</span>"
        )

    zone_chips = ""
    for z in canonical_zones:
        zcolor = ZONE_COLORS.get(z, "#666")
        display = ZONE_DISPLAY_NAMES.get(z, z)
        zone_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="zone" data-filter-value="{_esc(z)}"'
            f' data-active-bg="rgba({_hex_to_rgb_css(zcolor)},0.25)"'
            f' data-active-color="{zcolor}"'
            f' style="border-color:{zcolor};color:{zcolor};background:transparent;">'
            f"{_esc(display)}</span>"
        )

    priority_chip_data = [
        ("high", "High", "#ef4444"),
        ("medium", "Medium", "#f59e0b"),
        ("low", "Low", "#22c55e"),
    ]
    priority_chips = ""
    for pval, plabel, pcolor in priority_chip_data:
        priority_chips += (
            f'<span class="filter-chip" onclick="toggleChip(this)"'
            f' data-filter-type="priority" data-filter-value="{pval}"'
            f' data-active-bg="rgba({_hex_to_rgb_css(pcolor)},0.25)"'
            f' data-active-color="{pcolor}"'
            f' style="border-color:{pcolor};color:{pcolor};background:transparent;">'
            f"{plabel}</span>"
        )

    filter_html = f"""
      <div class="filter-bar" style="margin-top:24px;flex-direction:column;align-items:flex-start;gap:10px;">
        <div style="display:flex;align-items:center;gap:8px;width:100%;justify-content:space-between;">
          <span style="font-size:12px;font-weight:600;color:var(--text-primary);">Filters</span>
          <button class="filter-btn" onclick="resetFilters()">Clear All</button>
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Threats</span>
          {threat_chips}
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Zones</span>
          {zone_chips}
        </div>
        <div class="chip-group">
          <span class="chip-group-label">Priority</span>
          {priority_chips}
        </div>
      </div>
    """

    # ------------------------------------------------------------------
    # Pre-compute LLM call stats for anomaly detection
    # ------------------------------------------------------------------
    _call_logs = call_logs or {}
    call_stats: dict[str, float] | None = None
    all_durations: list[float] = []
    all_prompt_tokens: list[float] = []
    all_completion_tokens: list[float] = []
    for _sid, _entries in _call_logs.items():
        for _idx, _e in enumerate(_entries):
            _metrics = _usage_metrics(
                _e,
                call_label=_usage_call_label(_e, _idx),
            )
            if _metrics["duration_ms"] is not None:
                all_durations.append(float(_metrics["duration_ms"]))
            if _metrics["prompt_tokens"] is not None:
                all_prompt_tokens.append(float(_metrics["prompt_tokens"]))
            if _metrics["completion_tokens"] is not None:
                all_completion_tokens.append(float(_metrics["completion_tokens"]))

    if (
        len(all_durations) >= 3
        and len(all_prompt_tokens) >= 3
        and len(all_completion_tokens) >= 3
    ):

        def _mean_std(vals: list[float]) -> tuple[float, float]:
            n = len(vals)
            m = sum(vals) / n
            variance = sum((v - m) ** 2 for v in vals) / n
            return m, math.sqrt(variance)

        dur_mean, dur_std = _mean_std(all_durations)
        pt_mean, pt_std = _mean_std(all_prompt_tokens)
        ct_mean, ct_std = _mean_std(all_completion_tokens)
        call_stats = {
            "dur_mean": dur_mean,
            "dur_std": dur_std,
            "pt_mean": pt_mean,
            "pt_std": pt_std,
            "ct_mean": ct_mean,
            "ct_std": ct_std,
        }

    # ------------------------------------------------------------------
    # Scenario cards (existing + Bead 4: collapse indicator)
    # ------------------------------------------------------------------
    cards_html = ""
    for s in scenarios:
        cards_html += _build_scenario_card(
            s,
            feature_files,
            _call_logs,
            threat_surface=threat_surface,
            capability_profile=capability_profile,
            scorecard_data=scorecard_data,
            call_stats=call_stats,
        )

    return f"""
    <div id="sec-scenarios" class="section">
      <div class="section-header">
        <h2>Scenarios</h2>
        <span class="badge" id="scenario-counter">Showing all {len(scenarios)}</span>
        <button class="toggle-all-btn" id="toggle-all-btn" onclick="toggleAllCards()">Collapse All</button>
      </div>

      {dashboard_html}

      <div class="scenario-section-title" data-tooltip="Each bar decomposes a scenario's composite priority score into its 6 contributing signals. Bar width is proportional to the composite score.">Priority Signal Decomposition</div>
      {signal_chart_html}

      {matrix_html}

      {ep_dist_html}

      {filter_html}

      {cards_html}
    </div>
    """


_CAPABILITY_COLORS: dict[str, str] = {
    "novice": "#22c55e",  # green
    "intermediate": "#3b82f6",  # blue
    "advanced": "#f97316",  # orange
    "expert": "#ef4444",  # red
}

_CAPABILITY_TOOLTIPS: dict[str, str] = {
    "novice": "Limited technical skills, relies on public tools and tutorials",
    "intermediate": "Moderate skills, can adapt existing tools and techniques",
    "advanced": (
        "Deep expertise, can develop custom tools and discover vulnerabilities"
    ),
    "expert": (
        "Elite capabilities, can chain novel zero-days and develop bespoke frameworks"
    ),
}


def _build_actor_profile_block(scenario: dict[str, Any]) -> str:
    """Build a collapsible Actor Profile block for a scenario card.

    Returns an empty string when the scenario has no ``actor_profile``.
    """
    actor_profile = scenario.get("actor_profile")
    if not actor_profile:
        return ""

    actor_type = actor_profile.get("actor_type", "unknown")
    capability_level = actor_profile.get("capability_level", "")
    goal_category_name = actor_profile.get("goal_category_name", "")
    beliefs = actor_profile.get("beliefs", [])
    desires = actor_profile.get("desires", [])
    intentions = actor_profile.get("intentions", [])
    resources = actor_profile.get("resources", [])

    type_color = _DIVERSITY_COLORS.get(actor_type, "#6b7280")
    type_display = actor_type.replace("-", " ").replace("_", " ").title()

    cap_color = _CAPABILITY_COLORS.get(capability_level, "#6b7280")
    cap_display = capability_level.title() if capability_level else ""
    cap_tip = _CAPABILITY_TOOLTIPS.get(capability_level, "")
    cap_tip_attr = f' data-tooltip="{_esc(cap_tip)}"' if cap_tip else ""

    resources_items = (
        "".join(f"<li>{_esc(r)}</li>" for r in resources)
        if resources
        else "<li>None specified</li>"
    )

    beliefs_items = "".join(f"<li>{_esc(b)}</li>" for b in beliefs)
    desires_items = "".join(f"<li>{_esc(d)}</li>" for d in desires)
    intentions_items = "".join(f"<li>{_esc(i)}</li>" for i in intentions)

    list_style = 'style="margin:4px 0 0 16px;padding:0;font-size:13px;color:var(--text-secondary);line-height:1.6;"'

    # Build access provenance sub-block (cmps.6)
    access = actor_profile.get("access")
    access_html = ""
    if access:
        _ingress = access.get("ingress_mode", "")
        _access_cls = access.get("access_class", "")
        _ep_id = access.get("initial_entry_point_id", "")
        _access_lines = [
            f"<li>Ingress: <strong>{_esc(_ingress)}</strong></li>",
            f"<li>Access class: <strong>{_esc(_access_cls)}</strong></li>",
            f"<li>Entry point ID: <code>{_esc(_ep_id)}</code></li>",
        ]
        if access.get("influence_source"):
            _access_lines.append(
                f"<li>Influence source: <code>{_esc(access['influence_source'])}</code></li>"
            )
        if access.get("influence_mechanism"):
            _access_lines.append(
                f"<li>Influence mechanism: {_esc(access['influence_mechanism'])}</li>"
            )
        if access.get("trust_boundary_id"):
            _access_lines.append(
                f"<li>Trust boundary ID: <code>{_esc(access['trust_boundary_id'])}</code></li>"
            )
        if access.get("material_insider_advantage"):
            _access_lines.append(
                f"<li>Material insider advantage: {_esc(access['material_insider_advantage'])}</li>"
            )
        access_html = (
            '<div style="margin-bottom:8px;">'
            '<strong style="color:var(--text-muted);font-size:11px;">ACCESS PROVENANCE:</strong>'
            f"<ul {list_style}>{''.join(_access_lines)}</ul>"
            "</div>"
        )

    return f"""
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
              <span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(type_color)},0.15);color:{type_color};">{_esc(type_display)}</span>
              {f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(cap_color)},0.15);color:{cap_color};"{cap_tip_attr}>{_esc(cap_display)}</span>' if cap_display else ""}
              {f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css("#0d9488")},0.15);color:#0d9488;">{_esc(goal_category_name.replace("-", " ").replace("_", " ").title())}</span>' if goal_category_name else ""}
            </div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6;">
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">BELIEFS:</strong>
                <ul {list_style}>{beliefs_items}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">DESIRES:</strong>
                <ul {list_style}>{desires_items}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">INTENTIONS:</strong>
                <ul {list_style}>{intentions_items}</ul>
              </div>
              <div style="margin-bottom:8px;">
                <strong style="color:var(--text-muted);font-size:11px;">RESOURCES:</strong>
                <ul {list_style}>{resources_items}</ul>
              </div>
              {access_html}
              </div>"""


def _build_complexity_assessment_block(scenario: dict[str, Any]) -> str:
    """Build the deterministic attack-complexity assessment block (cmps.7).

    Shows the versioned assessment — candidate lower bound, final
    required level, rule version, and typed reasons — distinctly from
    the actor's own capability level.  Returns an empty string when the
    scenario carries no ``attack_complexity_assessment``.
    """
    assessment = scenario.get("attack_complexity_assessment") or {}
    lower = assessment.get("candidate_lower_bound") or {}
    if not lower:
        return ""
    final = assessment.get("final") or {}
    rule_version = _esc(str(assessment.get("rule_version", "")))

    def _level_badge(level: str) -> str:
        color = _CAPABILITY_COLORS.get(level, "#6b7280")
        return (
            '<span style="display:inline-block;padding:3px 10px;border-radius:4px;'
            f"font-size:12px;font-weight:600;background:rgba({_hex_to_rgb_css(color)},0.15);"
            f'color:{color};">{_esc(level.title() if level else "")}</span>'
        )

    final_level = final.get("required_level", "")
    summary_lines = [
        f"<li>Candidate lower bound: {_level_badge(lower.get('required_level', ''))}</li>",
    ]
    if final_level:
        summary_lines.append(
            f"<li>Final required level: {_level_badge(final_level)}</li>"
        )
    else:
        summary_lines.append(
            "<li>Final required level: "
            '<span style="color:var(--text-muted);font-style:italic;">'
            "not yet assessed</span></li>"
        )

    reason_items = ""
    for reason in final.get("reasons") or lower.get("reasons") or []:
        refs = ", ".join(
            f"{_esc(ref.get('kind', ''))}:{_esc(ref.get('ref_id', ''))}"
            for ref in reason.get("evidence", [])
        )
        reason_items += (
            "<li>"
            f"<code>{_esc(reason.get('rule_id', ''))}</code> "
            f"&rarr; <strong>{_esc(reason.get('required_level', ''))}</strong>: "
            f"{_esc(reason.get('detail', ''))}"
            f' <span style="color:var(--text-muted);">[{refs}]</span>'
            "</li>"
        )
    reasons_html = ""
    if reason_items:
        reasons_html = (
            '<div style="margin-bottom:8px;">'
            '<strong style="color:var(--text-muted);font-size:11px;">REASONS:</strong>'
            f'<ul style="margin:4px 0 0 16px;padding:0;font-size:13px;'
            f'color:var(--text-secondary);line-height:1.6;">{reason_items}</ul>'
            "</div>"
        )

    return (
        '<div style="margin-top:12px;border-top:1px solid var(--border);'
        'padding-top:10px;">'
        '<strong style="color:var(--text-muted);font-size:11px;" '
        'data-tooltip="Deterministic, versioned attack-complexity assessment '
        "(cmps.7). Distinct from the actor's immutable capability level: it "
        "is the capability the attack path requires, derived only from typed "
        'projection and realized-action evidence.">'
        f"ATTACK COMPLEXITY (RULE V{rule_version}):</strong>"
        '<ul style="margin:4px 0 0 16px;padding:0;font-size:13px;'
        'color:var(--text-secondary);line-height:1.9;list-style:none;">'
        f"{''.join(summary_lines)}</ul>"
        f"{reasons_html}"
        "</div>"
    )


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


def _build_generation_inputs_block(scenario: dict[str, Any]) -> str:
    """Build a Generation Inputs expandable section showing every datum
    that participates in scenario generation, organized by LLM call.

    Returns an HTML block with four grouped sub-tables (one per LLM call)
    in vertical key-value layout.
    """
    meta = scenario.get("scenario_seed_metadata") or {}
    actor = scenario.get("actor_profile") or {}
    narrative = scenario.get("narrative") or {}
    attack_tree = scenario.get("attack_tree") or {}
    faceting = scenario.get("faceting") or {}
    tc = faceting.get("taxonomy_chain") or {}
    cp = faceting.get("capability_profile") or {}

    # --- helpers ---
    def _val(v: Any, join_sep: str = "; ") -> str:
        """Format a value for display. Lists are joined; None/empty -> em dash."""
        if v is None:
            return "—"
        if isinstance(v, list):
            if not v:
                return "—"
            return join_sep.join(str(item) for item in v)
        s = str(v)
        return s if s else "—"

    def _row(label: str, value: str, *, hint: bool = False, tooltip: str = "") -> str:
        """Build a single table row. hint=True renders italic/muted label."""
        tip_attr = f' data-tooltip="{_esc(tooltip)}"' if tooltip else ""
        if hint:
            label_html = (
                f'<td style="white-space:nowrap;padding:4px 12px 4px 0;'
                f"font-size:12px;color:var(--text-muted);font-style:italic;"
                f'vertical-align:top;"{tip_attr}>{_esc(label)}</td>'
            )
        else:
            label_html = (
                f'<td style="white-space:nowrap;padding:4px 12px 4px 0;'
                f"font-size:12px;font-weight:600;color:var(--text-muted);"
                f'vertical-align:top;"{tip_attr}>{_esc(label)}</td>'
            )
        val_html = (
            f'<td style="padding:4px 0;font-size:12px;'
            f'color:var(--text-secondary);word-break:break-word;">'
            f"{value}</td>"
        )
        return f"<tr>{label_html}{val_html}</tr>"

    def _enriched_threat(tid: str, tname: str) -> str:
        """Threat ID with tooltip and name."""
        if not tid:
            return "—"
        tip = _threat_id_tooltip(tid)
        label = f"{_esc(tid)} — {_esc(tname)}" if tname else _esc(tid)
        return f"<span{tip}>{label}</span>"

    def _enriched_techniques(ids: list[str] | None) -> str:
        """ATLAS technique IDs with tooltips."""
        if not ids:
            return "—"
        parts = []
        for tid in ids:
            tip = _technique_id_tooltip(tid)
            parts.append(f"<span{tip}>{_esc(tid)}</span>")
        return "; ".join(parts)

    def _call_header(idx: int, name: str) -> str:
        return (
            f'<div style="font-size:11px;font-weight:700;'
            f"color:var(--text-muted);text-transform:uppercase;"
            f"letter-spacing:0.5px;margin:14px 0 4px;"
            f'padding-bottom:3px;border-bottom:1px solid var(--border);">'
            f"Call {idx}: {_esc(name)}</div>"
        )

    def _table(rows: str) -> str:
        return (
            f'<table style="width:100%;border-collapse:collapse;'
            f'margin-bottom:4px;">{rows}</table>'
        )

    # --- shared values ---
    attack_pattern = _val(meta.get("attack_pattern_name") or meta.get("mechanism_name"))
    attack_pattern_desc = _val(
        meta.get("attack_pattern_description") or meta.get("mechanism_description")
    )
    threat_html = _enriched_threat(
        meta.get("threat_id", ""), meta.get("threat_name", "")
    )
    zones_html = _val(cp.get("zones_traversed"))
    atlas_html = _enriched_techniques(tc.get("atlas_technique_ids"))
    goal_cat = actor.get("goal_category", "")
    goal_name = actor.get("goal_category_name", "")
    goal_parent = actor.get("goal_category_parent", "")
    goal_display = (
        f"{_esc(goal_name)} ({_esc(goal_cat)})" if goal_name else _val(goal_cat)
    )

    # ---- Call 0: Actor Profile ----
    call0_rows = "".join(
        [
            _row("Attack pattern", attack_pattern),
            _row("Attack pattern description", attack_pattern_desc),
            _row("Threat", threat_html),
            _row("System zones", zones_html),
            _row("ATLAS techniques", atlas_html),
            _row("Attack goal", goal_display),
            _row("Attack goal category", _val(goal_parent)),
            _row(
                "Diversity hint: preferred actor type",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
            _row(
                "Diversity hint: excluded actor types",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
        ]
    )

    # ---- Call 1: Narrative ----
    owasp_html = _val(tc.get("owasp_llm_ids"))
    call1_rows = "".join(
        [
            _row("Attack pattern", attack_pattern),
            _row("Attack pattern description", attack_pattern_desc),
            _row("Threat", threat_html),
            _row("System zones", zones_html),
            _row("Entry point", _val(cp.get("entry_point"))),
            _row("OWASP LLM IDs", owasp_html),
            _row("ATLAS techniques", atlas_html),
            _row("Actor type", _val(actor.get("actor_type"))),
            _row("Capability level", _val(actor.get("capability_level"))),
            _row("Beliefs", _val(actor.get("beliefs"))),
            _row("Desires", _val(actor.get("desires"))),
            _row("Intentions", _val(actor.get("intentions"))),
            _row("Resources", _val(actor.get("resources"))),
            _row("Attack goal", goal_display),
            _row("Attack goal category", _val(goal_parent)),
            _row(
                "Diversity hint: preferred entry point",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
            _row(
                "Diversity hint: excluded patterns",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
        ]
    )

    # ---- Call 2: Attack Tree ----
    call2_rows = "".join(
        [
            _row("Attack pattern", attack_pattern),
            _row("Threat", threat_html),
            _row("System zones", zones_html),
            _row("ATLAS techniques", atlas_html),
            _row("Actor type", _val(actor.get("actor_type"))),
            _row("Capability level", _val(actor.get("capability_level"))),
            _row("Narrative title", _val(narrative.get("title"))),
            _row("Narrative summary", _val(narrative.get("summary"))),
            _row("Entry point", _val(narrative.get("entry_point"))),
            _row("Zone sequence", _val(narrative.get("zone_sequence"))),
        ]
    )

    # ---- Call 3: Behavior Spec ----
    call3_rows = "".join(
        [
            _row("Narrative title", _val(narrative.get("title"))),
            _row("Entry point", _val(narrative.get("entry_point"))),
            _row("Zone sequence", _val(narrative.get("zone_sequence"))),
            _row("Attack tree goal", _val(attack_tree.get("goal"))),
            _row("Actor type", _val(actor.get("actor_type"))),
            _row("Capability level", _val(actor.get("capability_level"))),
        ]
    )

    content = (
        _call_header(0, "Actor Profile")
        + _table(call0_rows)
        + _call_header(1, "Narrative")
        + _table(call1_rows)
        + _call_header(2, "Attack Tree")
        + _table(call2_rows)
        + _call_header(3, "Behavior Spec")
        + _table(call3_rows)
    )

    return f'<div style="padding:12px 0 4px;">{content}</div>'


def _collect_used_technique_ids(
    scenario: dict[str, Any], gherkin_text: str
) -> set[str]:
    """Collect technique IDs actually referenced in the attack tree and Gherkin."""
    ids: set[str] = set()
    _tid_re = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")

    def _walk_tree(node: dict[str, Any]) -> None:
        tid = node.get("technique_id")
        if tid:
            ids.add(tid)
        for child in node.get("children") or []:
            _walk_tree(child)

    root = scenario.get("attack_tree", {}).get("root")
    if root:
        _walk_tree(root)
    ids |= set(_tid_re.findall(gherkin_text))
    return ids


def _build_atlas_techniques_block(
    scenario: dict[str, Any], gherkin_text: str = ""
) -> str:
    """Build an ATLAS Techniques section showing *used* technique IDs + names.

    Intersects the seed's ``atlas_technique_ids`` pool with techniques actually
    referenced in the attack tree and Gherkin spec.  Returns empty string when
    no techniques are present.
    """
    used = _collect_used_technique_ids(scenario, gherkin_text)
    if not used:
        return ""
    technique_ids = sorted(used)

    if not technique_ids:
        return ""

    badges = ""
    for tid in technique_ids:
        name = _ATLAS_TECHNIQUE_NAMES.get(tid, "")
        label = f"{tid}: {name}" if name else tid
        tip = _technique_id_tooltip(tid)
        badges += (
            f'<span style="display:inline-block;padding:3px 10px;border-radius:4px;'
            f"font-size:12px;font-weight:600;background:rgba(249,115,22,0.15);"
            f"color:#f97316;font-family:'SF Mono','Fira Code',monospace;"
            f'margin:0 4px 4px 0;"{tip}>{_esc(label)}</span>'
        )

    return f"""
            <div style="display:flex;flex-wrap:wrap;">
              {badges}
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

    # --- Step 6: ATLAS Techniques ---
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
        f'<div class="prov-step-label">4c. ATLAS Techniques '
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


def _build_scenario_card(
    scenario: dict[str, Any],
    feature_files: dict[str, str],
    call_logs: dict[str, list[dict]] | None = None,
    threat_surface: dict[str, Any] | None = None,
    capability_profile: dict[str, Any] | None = None,
    scorecard_data: dict[str, Any] | None = None,
    call_stats: dict[str, float] | None = None,
) -> str:
    sid = scenario.get("scenario_id", "")
    narrative = scenario.get("narrative", {})
    title = narrative.get("title", "")
    summary = narrative.get("summary", "")
    entry_point = narrative.get("entry_point", "")
    zone_sequence = narrative.get("zone_sequence", [])
    composite = scenario.get("priority", {}).get("composite", 0)
    priority_label = _priority_label(composite)
    priority_color = _priority_color(composite)

    # Data attributes for filtering
    faceting = scenario.get("faceting", {})
    tc = faceting.get("taxonomy_chain", {})
    threats = ",".join(tc.get("agentic_threat_ids", []))
    cp = faceting.get("capability_profile", {})
    zones = ",".join(_normalize_zone(z) for z in cp.get("zones_traversed", []))

    # Zone breadcrumb
    breadcrumb = ""
    for i, z in enumerate(zone_sequence):
        zn = _normalize_zone(z)
        color = ZONE_COLORS.get(zn, "#666")
        bg = ZONE_BG_COLORS.get(zn, "#333")
        display = ZONE_DISPLAY_NAMES.get(zn, zn)
        breadcrumb += f'<span class="zone-crumb" style="background:{bg};color:{color};" data-tooltip="{_esc(display)}">{_esc(zn)}</span>'
        if i < len(zone_sequence) - 1:
            breadcrumb += '<span class="zone-crumb-arrow">&rarr;</span>'

    # Attack tree
    attack_tree_data = scenario.get("attack_tree", {})
    root = attack_tree_data.get("root")
    attack_tree_html = _build_attack_tree_node(root, capability_profile) if root else ""
    tree_goal = attack_tree_data.get("goal", "")

    # Behavior spec from feature file
    feature_content = feature_files.get(sid, "")
    behavior_html = _build_behavior_spec(feature_content)

    # Priority signals
    signals = scenario.get("priority", {}).get("signals", {})
    signals_html = _build_priority_signals(signals)

    # Generation inputs: per-call grouped sub-tables
    generation_inputs_html = _build_generation_inputs_block(scenario)

    # Provenance chain flowchart
    provenance_chain_html = _build_provenance_chain(
        scenario, threat_surface=threat_surface, capability_profile=capability_profile
    )

    # ATLAS techniques section
    atlas_techniques_html = _build_atlas_techniques_block(scenario, feature_content)

    # LLM call log section (inner content only, no <details> wrapper)
    call_log_html = ""
    _logs = (call_logs or {}).get(sid, [])
    if _logs:
        _CALL_DISPLAY_NAMES = {
            "actor_profile": "Actor Profile",
            "narrative": "Narrative",
            "attack_tree": "Attack Tree",
            "behavior_spec": "Behavior Spec",
        }
        call_items = ""
        for idx, entry in enumerate(_logs):
            call_name = entry.get("call", "")
            display_name = _CALL_DISPLAY_NAMES.get(call_name, call_name)
            call_label = _usage_call_label(entry, idx)
            usage = _usage_metrics(entry, call_label=call_label)
            ptokens = usage["prompt_tokens"]
            ctokens = usage["completion_tokens"]
            dur = usage["duration_ms"]
            sys_prompt = _esc(entry.get("system_prompt", ""))
            usr_prompt = _esc(entry.get("user_prompt", ""))
            response_raw = entry.get("response", "")
            if isinstance(response_raw, (dict, list)):
                response_text = _esc(
                    json.dumps(response_raw, indent=2, ensure_ascii=False)
                )
            else:
                response_text = _esc(str(response_raw))

            # Anomaly detection badges
            anomaly_badges = ""
            is_anomaly = False
            if call_stats is not None:
                _threshold = 2.0
                if (
                    dur is not None
                    and call_stats["dur_std"] > 0
                    and dur
                    > call_stats["dur_mean"] + _threshold * call_stats["dur_std"]
                ):
                    anomaly_badges += '<span class="call-anomaly-badge">⚠ slow</span>'
                    is_anomaly = True
                if (
                    ptokens is not None
                    and call_stats["pt_std"] > 0
                    and ptokens
                    > call_stats["pt_mean"] + _threshold * call_stats["pt_std"]
                ) or (
                    ctokens is not None
                    and call_stats["ct_std"] > 0
                    and ctokens
                    > call_stats["ct_mean"] + _threshold * call_stats["ct_std"]
                ):
                    anomaly_badges += (
                        '<span class="call-anomaly-badge">⚠ high tokens</span>'
                    )
                    is_anomaly = True

            detail_cls = "expandable call-anomaly" if is_anomaly else "expandable"
            failure_suffix = _usage_failure_suffix(entry)
            warning_html = _usage_warning_html(call_label, usage)
            call_items += f"""
            {warning_html}
            <details class="{detail_cls}">
              <summary>Call {idx}: {_esc(display_name)} ({_esc(_usage_summary(usage))}){failure_suffix}{anomaly_badges}</summary>
              <div style="padding:8px 0;">
                <h4 style="margin:8px 0 4px;font-size:12px;color:var(--text-muted);">System Prompt</h4>
                <pre class="call-log-pre">{sys_prompt}</pre>
                <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">User Prompt</h4>
                <pre class="call-log-pre">{usr_prompt}</pre>
                <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">Response</h4>
                <pre class="call-log-pre">{response_text}</pre>
              </div>
            </details>"""
        call_log_html = call_items

    # Sanitised scenario ID for unique radio input IDs
    safe_sid = re.sub(r"[^a-zA-Z0-9_-]", "_", sid)

    # ------------------------------------------------------------------
    # Quality badges for tab headers (from eval scorecard)
    # ------------------------------------------------------------------
    bspec_badge = ""
    tree_badge = ""
    narr_badge = ""

    # Behavior Spec badge: step count from feature content
    if feature_content:
        step_count = sum(
            1
            for line in feature_content.splitlines()
            if re.match(r"\s*(Given|When|Then|And|But)\b", line)
        )
        bspec_badge = f'<span class="tab-quality-badge">{step_count} steps</span>'

    if scorecard_data:
        eval_block = scorecard_data.get("evaluation", {})

        # Attack Tree badge: consistency metrics below 1.0
        consistency = (
            eval_block.get("consistency", {}).get("per_scenario", {}).get(sid, {})
        )
        tree_badge_parts: list[str] = []
        zone_align = consistency.get("zone_alignment")
        if zone_align is not None and zone_align < 1.0:
            tree_badge_parts.append(
                f'<span class="tab-quality-badge tab-warn">'
                f"zones: {zone_align:.2f}</span>"
            )
        step_node = consistency.get("step_node_correspondence")
        if step_node is not None and step_node < 1.0:
            tree_badge_parts.append(
                f'<span class="tab-quality-badge tab-warn">'
                f"step-node: {step_node:.2f}</span>"
            )
        tree_badge = "".join(tree_badge_parts)

        # Narrative badge: plausibility violations
        plausibility = (
            eval_block.get("plausibility", {}).get("per_scenario", {}).get(sid)
        )
        if plausibility:
            n_violations = len(plausibility)
            narr_badge = (
                f'<span class="tab-quality-badge tab-fail">'
                f"{n_violations} violation{'s' if n_violations != 1 else ''}"
                f"</span>"
            )

    return f"""
    <div class="scenario-card" id="scenario-{_esc(sid)}" data-scenario="{_esc(sid)}"
         data-threats="{_esc(threats)}" data-zones="{_esc(zones)}"
         data-priority="{_esc(priority_label.lower())}">
      <div class="scenario-header" onclick="toggleCard(this.parentElement)">
        <div class="scenario-header-left">
          <span class="collapse-indicator">&#9660;</span>
          <span class="scenario-id">{_esc(sid)}</span>
          <span class="scenario-title">{_esc(title)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="score-bar-container">
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:{composite * 100:.0f}%;background:{priority_color};"></div>
            </div>
            <span class="score-bar-label" style="color:{priority_color};">{composite:.2f}</span>
          </div>
          <span class="priority-badge" style="background:rgba({_hex_to_rgb_css(priority_color)},0.15);color:{priority_color};">
            {priority_label}
          </span>
        </div>
      </div>
      <div class="scenario-tabs">
        <input type="radio" id="tab-{safe_sid}-prov" name="tabs-{safe_sid}" checked>
        <input type="radio" id="tab-{safe_sid}-gen" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-actor" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-atlas" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-narr" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-tree" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-bspec" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-prio" name="tabs-{safe_sid}">
        <input type="radio" id="tab-{safe_sid}-llm" name="tabs-{safe_sid}">
        <div class="tab-bar">
          <label for="tab-{safe_sid}-prov">Provenance</label>
          <label for="tab-{safe_sid}-gen">Generation Inputs</label>
          <label for="tab-{safe_sid}-actor">Actor Profile</label>
          <label for="tab-{safe_sid}-atlas">ATLAS Techniques</label>
          <label for="tab-{safe_sid}-narr">Narrative{narr_badge}</label>
          <label for="tab-{safe_sid}-tree">Attack Tree{tree_badge}</label>
          <label for="tab-{safe_sid}-bspec">Behavior Spec{bspec_badge}</label>
          <label for="tab-{safe_sid}-prio">Priority Signals</label>
          <label for="tab-{safe_sid}-llm">LLM Calls</label>
        </div>
        <div class="tab-panels">
          <div class="tab-panel">
            {provenance_chain_html}
          </div>
          <div class="tab-panel">
            {generation_inputs_html}
          </div>
          <div class="tab-panel">
            {_build_actor_profile_block(scenario)}
            {_build_complexity_assessment_block(scenario)}
          </div>
          <div class="tab-panel">
            {atlas_techniques_html}
          </div>
          <div class="tab-panel">
            <p class="scenario-summary">{_esc(summary)}</p>
            <div style="margin-top:12px;font-size:13px;color:var(--text-secondary);">
              <strong style="color:var(--text-muted);font-size:11px;">ENTRY POINT:</strong> {_esc(entry_point)}
            </div>
            <div style="margin-top:8px;">
              <strong style="color:var(--text-muted);font-size:11px;">ZONE SEQUENCE:</strong>
              <div class="zone-breadcrumb">{breadcrumb}</div>
            </div>
          </div>
          <div class="tab-panel">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;font-style:italic;">
              Goal: {_esc(tree_goal)}
            </div>
            <div class="attack-tree">{attack_tree_html}</div>
          </div>
          <div class="tab-panel">
            <div class="feature-spec">{behavior_html}</div>
          </div>
          <div class="tab-panel">
            {signals_html}
          </div>
          <div class="tab-panel">
            {call_log_html}
          </div>
        </div>
      </div>
    </div>
    """


def _hex_to_rgb_css(hex_color: str) -> str:
    """Convert #rrggbb to 'r,g,b' for rgba."""
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def _build_attack_tree_node(
    node: dict[str, Any] | None,
    profile_data: dict[str, Any] | None = None,
) -> str:
    if node is None:
        return ""

    gate = node.get("gate", "LEAF")
    raw_zone = node.get("zone")
    zone = _normalize_zone(raw_zone) if raw_zone is not None else None
    label = node.get("label", "")
    action = node.get("action") or {}
    action_kind = action.get("kind")
    children = node.get("children") or []
    threat_id = node.get("threat_id")
    technique_id = node.get("technique_id")
    control_point = node.get("control_point")
    structural_exposure = node.get("structural_exposure")

    gate_cls = {"AND": "gate-and", "OR": "gate-or", "LEAF": "gate-leaf"}.get(
        gate, "gate-leaf"
    )
    gate_symbol = {"AND": "&and;", "OR": "&or;", "LEAF": "&bull;"}.get(gate, "&bull;")
    gate_tip = _GATE_TOOLTIPS.get(gate, "")
    gate_title = f' data-tooltip="{_esc(gate_tip)}"' if gate_tip else ""
    zone_color = ZONE_COLORS.get(zone, "#9ca3af")
    zone_bg = ZONE_BG_COLORS.get(zone, "#374151")
    boundary = action.get("boundary")
    zone_display = (
        ZONE_DISPLAY_NAMES.get(zone, zone)
        if zone is not None
        else "External"
        if action_kind == "external_precondition" or boundary == "external"
        else "N/A"
    )

    meta_parts = []
    if action_kind:
        action_display = action_kind.replace("_", " ").title()
        meta_parts.append(f'<span class="tree-meta">{_esc(action_display)}</span>')

    profile = None
    if profile_data:
        try:
            profile = CapabilityProfile.model_validate(dict(profile_data))
        except ValueError:
            logger.debug(
                "Could not validate capability profile for report ID resolution"
            )

    def _resolved_name(resource_id: str | None, resource_kind: str) -> str | None:
        if not resource_id or profile is None:
            return None
        if resource_kind == "tool":
            resource = profile.resolve_tool(resource_id)
        elif resource_kind == "integration":
            resource = profile.resolve_integration(resource_id)
        else:
            resource = profile.resolve_entry_point(resource_id)
        return resource.name if resource else None

    id_specs = []
    if action_kind == "tool_invocation":
        id_specs.append(("Tool", action.get("tool_id"), "tool"))
        if action.get("integration_id"):
            id_specs.append(
                ("Integration", action.get("integration_id"), "integration")
            )
    elif action_kind == "integration_interaction":
        id_specs.append(("Integration", action.get("integration_id"), "integration"))
    elif action_kind == "initial_ingress":
        id_specs.append(("Entry Point", action.get("entry_point_id"), "entry_point"))
    for resource_label, resource_id, resource_kind in id_specs:
        resolved = _resolved_name(resource_id, resource_kind)
        display = resolved or "Unresolved"
        meta_parts.append(
            f'<span class="tree-meta">{_esc(resource_label)}: {_esc(display)} '
            f"(<code>{_esc(resource_id or 'Missing ID')}</code>)</span>"
        )
    if boundary:
        meta_parts.append(
            f'<span class="tree-meta">Boundary: {_esc(str(boundary).title())}</span>'
        )
    if action_kind == "impact" and action.get("target"):
        meta_parts.append(
            f'<span class="tree-meta">Target: {_esc(action["target"])}</span>'
        )
    if action_kind == "external_precondition" and action.get("access_provenance"):
        meta_parts.append(
            f'<span class="tree-meta">Evidence: {_esc(action["access_provenance"])}</span>'
        )
    if threat_id:
        meta_parts.append(
            f'<span class="tree-meta"{_threat_id_tooltip(threat_id)}>'
            f"{_esc(threat_id)}</span>"
        )
    if technique_id:
        tech_tip = ""
        if technique_id.startswith("AML.T"):
            name = _ATLAS_TECHNIQUE_NAMES.get(technique_id, "")
            label = f"{technique_id} — {name}" if name else technique_id
            tech_tip = f' data-tooltip="MITRE ATLAS: {_esc(label)}"'
        meta_parts.append(
            f'<span class="tree-meta"{tech_tip}>{_esc(technique_id)}</span>'
        )
    if control_point:
        meta_parts.append(
            f'<span class="tree-meta" style="color:var(--medium);" '
            f'data-tooltip="Defensive control that should block or detect this '
            f'attack step">{_esc(control_point)}</span>'
        )
    if structural_exposure:
        se_str = str(structural_exposure)
        se_display = se_str.replace("_", " ").title()
        se_tip = _STRUCTURAL_EXPOSURE_TOOLTIPS.get(se_str, "Structural exposure")
        meta_parts.append(
            f'<span class="tree-meta" style="color:var(--high);" '
            f'data-tooltip="{_esc(se_tip)}">{_esc(se_display)}</span>'
        )
    meta_html = " ".join(meta_parts)

    if gate == "LEAF" or not children:
        return f"""
        <div class="tree-leaf">
          <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
          <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">{_esc(zone_display)}</span>
          <span class="tree-label">{_esc(label)}</span>
          {meta_html}
        </div>"""

    children_html = "".join(_build_attack_tree_node(c, profile_data) for c in children)
    return f"""
    <details open>
      <summary>
        <span class="gate-badge {gate_cls}"{gate_title}>{gate_symbol}</span>
        <span class="zone-badge" style="background:{zone_bg};color:{zone_color};">{_esc(zone_display)}</span>
        <span class="tree-label">{_esc(label)}</span>
        {meta_html}
      </summary>
      {children_html}
    </details>"""


def _build_behavior_spec(feature_content: str) -> str:
    if not feature_content:
        return '<p style="color:var(--text-muted);">No behavior specification available.</p>'

    lines = feature_content.strip().split("\n")
    result = []
    in_docstring = False
    docstring_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Handle docstrings (triple-quoted blocks)
        if stripped.startswith('"""') and not in_docstring:
            in_docstring = True
            docstring_lines = [stripped[3:]]
            continue
        if in_docstring:
            if stripped.endswith('"""'):
                docstring_lines.append(stripped[:-3])
                ds_text = "\n".join(docstring_lines).strip()
                result.append(f'<div class="step-docstring">{_esc(ds_text)}</div>')
                in_docstring = False
                docstring_lines = []
            else:
                docstring_lines.append(stripped)
            continue

        # Skip @id lines and empty lines
        if stripped.startswith("@") or not stripped:
            if stripped.startswith("@"):
                pass  # skip tags
            continue

        # Parse Gherkin keywords
        keyword = None
        text = stripped
        step_class = ""

        for kw, cls in [
            ("Feature:", ""),
            ("Background:", ""),
            ("Scenario:", ""),
            ("Given ", "step-given"),
            ("When ", "step-when"),
            ("And ", "step-and"),
            ("Then ", "step-then"),
            ("But ", "step-but"),
            ("* ", "step-star"),
        ]:
            if stripped.startswith(kw):
                keyword = kw.strip().rstrip(":")
                text = stripped[len(kw) :]
                step_class = cls
                break

        if not keyword:
            # Continuation or description line
            if stripped and not stripped.startswith("#"):
                result.append(
                    f'<div style="padding:4px 14px 4px 70px;font-size:13px;color:var(--text-secondary);">{_esc(stripped)}</div>'
                )
            continue

        # Feature/Background/Scenario headers
        if keyword in ("Feature", "Background", "Scenario"):
            result.append(
                f'<div style="padding:10px 0 6px;font-size:14px;font-weight:700;color:var(--text-primary);">'
                f'<span style="color:var(--accent);">{_esc(keyword)}:</span> {_esc(text)}</div>'
            )
            continue

        # Extract zone badge from text — supports both legacy "(Zone 2)" and
        # string-based "(Zone reasoning)" or "(Zone Tool Execution)" formats
        zone_badge = ""
        zone_match = re.search(r"\(.*?[Zz]one\s+(\S+(?:\s+\S+)*).*?\)", text)
        if zone_match:
            zone_token = zone_match.group(1).rstrip(")")
            zn = None
            if zone_token.isdigit():
                zn = _INT_TO_ZONE_NAME.get(int(zone_token))
            elif zone_token in set(_ZONE_NAMES_TUPLE):
                zn = zone_token
            else:
                # Try matching against display names
                for name, display in ZONE_DISPLAY_NAMES.items():
                    if zone_token.lower() in display.lower():
                        zn = name
                        break
            if zn:
                zc = ZONE_COLORS.get(zn, "#666")
                zbg = ZONE_BG_COLORS.get(zn, "#333")
                zone_display_name = ZONE_DISPLAY_NAMES.get(zn, zn)
                zone_badge = f'<span class="zone-badge" style="background:{zbg};color:{zc};margin-left:6px;">{_esc(zone_display_name)}</span>'

        result.append(
            f'<div class="feature-step {step_class}">'
            f'<span class="step-keyword">{_esc(keyword)}</span>'
            f'<span class="step-text">{_esc(text)}{zone_badge}</span>'
            f"</div>"
        )

    return "\n".join(result)


def _build_priority_signals(signals: dict[str, Any]) -> str:
    if not signals:
        return ""

    display_map = {
        "technique_maturity": "Technique Maturity",
        "risk_impact": "Risk Impact",
        "risk_likelihood": "Risk Likelihood",
        "attack_complexity": "Attack Complexity",
        "architecture_match": "Architecture Match",
        "structural_exposure": "Structural Exposure",
    }

    items = ""
    for key, label in display_map.items():
        value = signals.get(key, "-")
        if isinstance(value, str):
            display = value.replace("_", " ").title()
        else:
            display = str(value)
        tip = _SIGNAL_TOOLTIPS.get(key, "")
        tip_attr = f' data-tooltip="{_esc(tip)}"' if tip else ""
        items += f"""
        <div class="signal-item"{tip_attr}>
          <div class="signal-label">{_esc(label)}</div>
          <div class="signal-value">{_esc(display)}</div>
        </div>"""

    return f'<div class="signals-grid">{items}</div>'


# ---------------------------------------------------------------------------
# Section: Pipeline LLM Calls (non-scenario)
# ---------------------------------------------------------------------------


def _build_pipeline_call_item(
    entry: dict[str, Any],
    index: int,
    display_names: dict[str, str],
) -> tuple[dict[str, int | float | None], str]:
    """Build one pipeline call item and return its normalized usage metrics."""
    call_name = entry.get("call", "")
    display_name = display_names.get(call_name, call_name)
    call_label = _usage_call_label(entry, index)
    usage = _usage_metrics(entry, call_label=call_label)
    sys_prompt = _esc(entry.get("system_prompt", ""))
    usr_prompt = _esc(entry.get("user_prompt", ""))
    response_raw = entry.get("response", "")
    if isinstance(response_raw, (dict, list)):
        response_text = _esc(json.dumps(response_raw, indent=2, ensure_ascii=False))
    else:
        response_text = _esc(str(response_raw))

    seed_label = ""
    seed_id = entry.get("seed_id")
    if seed_id:
        seed_label = f" (seed: {_esc(seed_id)})"

    failure_suffix = _usage_failure_suffix(entry)
    warning_html = _usage_warning_html(call_label, usage)
    item_html = f"""
        {warning_html}
        <details class="expandable">
          <summary>Call {index}: {_esc(display_name)}{seed_label} ({_esc(_usage_summary(usage))}){failure_suffix}</summary>
          <div style="padding:8px 0;">
            <h4 style="margin:8px 0 4px;font-size:12px;color:var(--text-muted);">System Prompt</h4>
            <pre class="call-log-pre">{sys_prompt}</pre>
            <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">User Prompt</h4>
            <pre class="call-log-pre">{usr_prompt}</pre>
            <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">Response</h4>
            <pre class="call-log-pre">{response_text}</pre>
          </div>
        </details>"""
    return usage, item_html


def _usage_totals(
    normalized_usage: list[dict[str, int | float | None]],
) -> tuple[int | float, int | float, int | float]:
    """Sum available metrics while treating unavailable telemetry as zero."""
    return (
        sum((usage["prompt_tokens"] or 0) for usage in normalized_usage),
        sum((usage["completion_tokens"] or 0) for usage in normalized_usage),
        sum((usage["duration_ms"] or 0) for usage in normalized_usage),
    )


def build_pipeline_calls_section(call_logs: list[dict[str, Any]]) -> str:
    """Build an expandable section showing non-scenario LLM calls.

    These are pipeline-level calls such as capability profile inference and
    candidate filtering, logged to the top-level ``calls.jsonl``.  The UI
    mirrors the collapsible prompt/response pattern used for per-scenario
    call logs.
    """
    if not call_logs:
        return ""

    _CALL_DISPLAY_NAMES: dict[str, str] = {
        "capability_profile": "Capability Profile Inference",
        "candidate_filter": "Candidate Filter",
    }

    call_items: list[str] = []
    normalized_usage: list[dict[str, int | float | None]] = []
    for idx, entry in enumerate(call_logs):
        usage, item_html = _build_pipeline_call_item(
            entry,
            idx,
            _CALL_DISPLAY_NAMES,
        )
        normalized_usage.append(usage)
        call_items.append(item_html)

    # Compute aggregate stats.
    total_prompt, total_completion, total_duration = _usage_totals(normalized_usage)
    call_items_html = "".join(call_items)

    return f"""
    <section id="sec-pipeline-calls" class="section">
      <h2>Pipeline LLM Calls</h2>
      <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">
        Non-scenario LLM calls made during pipeline execution.
        {len(call_logs)} call(s) &middot;
        {total_prompt:,} prompt tokens &middot;
        {total_completion:,} completion tokens &middot;
        {total_duration:,}ms total
      </p>
      {call_items_html}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 4: Raw Data
# ---------------------------------------------------------------------------


def build_raw_data_section(raw_files: dict[str, str]) -> str:
    if not raw_files:
        return ""

    tabs_html = ""
    panels_html = ""

    for i, (filename, content) in enumerate(raw_files.items()):
        active = " active" if i == 0 else ""
        tab_id = f"raw-{i}"

        tabs_html += f'<button class="raw-tab{active}" onclick="switchRawTab(\'{tab_id}\', this)">{_esc(filename)}</button>'

        if filename.endswith((".yaml", ".yml")):
            highlighted = _highlight_yaml(content)
        elif filename.endswith(".feature"):
            highlighted = _highlight_gherkin(content)
        else:
            highlighted = _esc(content)

        panels_html += f"""
        <div id="{tab_id}" class="raw-panel{active}">
          <button class="copy-btn" onclick="copyToClipboard('{tab_id}-code')">Copy</button>
          <div class="code-block" id="{tab_id}-code">{highlighted}</div>
        </div>"""

    return f"""
    <div id="sec-raw" class="section">
      <div class="section-header">
        <h2>Raw Data</h2>
        <span class="badge">{len(raw_files)} files</span>
      </div>
      <div class="raw-tabs">{tabs_html}</div>
      {panels_html}
    </div>
    """


def _highlight_yaml(text: str) -> str:
    """Simple regex-based YAML syntax highlighting."""
    lines = text.split("\n")
    result = []
    for line in lines:
        escaped = _esc(line)

        # Comments
        if escaped.strip().startswith("#"):
            result.append(f'<span class="yaml-comment">{escaped}</span>')
            continue

        # Key-value pairs
        m = re.match(r"^(\s*)([\w_-]+)(\s*:\s*)(.*)", escaped)
        if m:
            indent, key, colon, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(
                f'{indent}<span class="yaml-key">{key}</span>{colon}{highlighted_value}'
            )
            continue

        # List items
        m = re.match(r"^(\s*-\s+)(.*)", escaped)
        if m:
            prefix, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(f"{prefix}{highlighted_value}")
            continue

        result.append(escaped)

    return "\n".join(result)


def _highlight_yaml_value(value: str) -> str:
    v = value.strip()
    if not v or v == "":
        return value
    if v in ("null", "~"):
        return f'<span class="yaml-null">{value}</span>'
    if v in ("true", "false"):
        return f'<span class="yaml-bool">{value}</span>'
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return f'<span class="yaml-number">{value}</span>'
    if (v.startswith("'") and v.endswith("'")) or (
        v.startswith('"') and v.endswith('"')
    ):
        return f'<span class="yaml-string">{value}</span>'
    return value


def _highlight_gherkin(text: str) -> str:
    """Simple regex-based Gherkin syntax highlighting."""
    lines = text.split("\n")
    result = []
    for line in lines:
        escaped = _esc(line)

        if escaped.strip().startswith("#"):
            result.append(f'<span class="gherkin-comment">{escaped}</span>')
            continue

        if escaped.strip().startswith("@"):
            result.append(f'<span class="gherkin-tag">{escaped}</span>')
            continue

        for kw in [
            "Feature:",
            "Background:",
            "Scenario:",
            "Scenario Outline:",
            "Given ",
            "When ",
            "Then ",
            "And ",
            "But ",
            "* ",
        ]:
            ekw = _esc(kw)
            if escaped.strip().startswith(ekw):
                idx = escaped.index(ekw)
                escaped = (
                    escaped[:idx]
                    + f'<span class="gherkin-keyword">{ekw}</span>'
                    + escaped[idx + len(ekw) :]
                )
                break

        # Highlight triple-quoted strings
        if "&quot;&quot;&quot;" in escaped:
            escaped = escaped.replace(
                "&quot;&quot;&quot;",
                '<span class="gherkin-string">&quot;&quot;&quot;</span>',
            )

        result.append(escaped)

    return "\n".join(result)


# ---------------------------------------------------------------------------
# Run Summary
# ---------------------------------------------------------------------------


def build_run_summary_section(
    manifest: dict[str, Any],
    scenarios_in_report: int,
    *,
    high_count: int = 0,
    medium_count: int = 0,
    low_count: int = 0,
    coverage_gaps: int | None = None,
) -> str:
    """Build a Run Summary section showing pipeline funnel metrics.

    Args:
        manifest: Parsed ``run-manifest.yaml`` dict.
        scenarios_in_report: Count of scenarios actually rendered in the report.
        high_count: Number of HIGH priority scenarios (composite >= 0.7).
        medium_count: Number of MEDIUM priority scenarios (0.4 <= composite < 0.7).
        low_count: Number of LOW priority scenarios (composite < 0.4).
        coverage_gaps: Total coverage gaps count, or *None* if unavailable.

    Returns:
        HTML string for the run summary section, or empty string if manifest
        is empty/None.
    """
    if not manifest:
        return ""

    seeds = manifest.get("seeds_generated", 0)
    funnel = manifest.get("funnel", {})
    expanded = funnel.get("expanded_instances", manifest.get("candidates_expanded", 0))
    accepted = funnel.get("filter_accepted", manifest.get("candidates_accepted", 0))
    # Derive rejected count from funnel fields, not list lengths.
    rejected = funnel.get(
        "rule_rejected",
        0,
    ) + max(funnel.get("filter_submitted", 0) - funnel.get("filter_accepted", 0), 0)
    generated = manifest.get("scenarios_generated", 0)
    failed = manifest.get("scenarios_failed", 0)

    # Rejection rate
    rejection_rate = f"{rejected / expanded * 100:.1f}%" if expanded > 0 else "N/A"

    # Config
    config = manifest.get("config", {})
    model_name = _esc(str(config.get("model", "unknown")))
    temperature = config.get("temperature", "N/A")

    # Timestamps & duration
    ts_start = manifest.get("timestamp_start", "")
    ts_end = manifest.get("timestamp_end", "")
    duration_str = ""
    if ts_start and ts_end:
        try:
            from datetime import datetime

            fmt_options = [
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
            ]
            dt_start = dt_end = None
            for fmt in fmt_options:
                try:
                    dt_start = datetime.strptime(str(ts_start), fmt)  # noqa: DTZ007
                    break
                except ValueError:
                    continue
            for fmt in fmt_options:
                try:
                    dt_end = datetime.strptime(str(ts_end), fmt)  # noqa: DTZ007
                    break
                except ValueError:
                    continue
            if dt_start and dt_end:
                delta = dt_end - dt_start
                total_secs = int(delta.total_seconds())
                mins, secs = divmod(abs(total_secs), 60)
                hours, mins = divmod(mins, 60)
                if hours > 0:
                    duration_str = f"{hours}h {mins}m {secs}s"
                else:
                    duration_str = f"{mins}m {secs}s"
        except Exception:  # noqa: BLE001, S110
            pass

    # Format timestamps for display (strip microseconds)
    display_start = str(ts_start).split(".")[0] if ts_start else "N/A"
    display_end = str(ts_end).split(".")[0] if ts_end else "N/A"

    # Build funnel steps
    funnel_steps = [
        ("Seeds Generated", seeds, "#3b82f6"),
        ("Candidates Expanded", expanded, "#8b5cf6"),
        ("Candidates Accepted", accepted, "#22c55e"),
        ("Scenarios Generated", generated, "#f59e0b"),
        ("In Report", scenarios_in_report, "#6366f1"),
    ]

    funnel_html = ""
    for i, (label, count, color) in enumerate(funnel_steps):
        arrow = (
            '<span style="color:var(--text-muted);font-size:18px;'
            'margin:0 4px;">&#8594;</span>'
            if i < len(funnel_steps) - 1
            else ""
        )
        funnel_html += (
            f'<div class="stat-card" style="border-left-color:{color};">'
            f'<span class="stat-number">{count}</span>'
            f'<span class="stat-label">{_esc(label)}</span>'
            f"</div>"
            f"{arrow}"
        )

    # Secondary stats
    duration_card = ""
    if duration_str:
        duration_card = (
            '<div class="stat-card" style="border-left-color:#6b7280;">'
            f'<span class="stat-number" style="font-size:20px;">'
            f"{_esc(duration_str)}</span>"
            '<span class="stat-label">Duration</span>'
            "</div>"
        )

    # Priority breakdown row
    total_priority = high_count + medium_count + low_count
    high_pct = (high_count / total_priority * 100) if total_priority else 0
    medium_pct = (medium_count / total_priority * 100) if total_priority else 0
    donut_gradient = (
        f"conic-gradient("
        f"var(--high) 0% {high_pct:.1f}%, "
        f"var(--medium) {high_pct:.1f}% {high_pct + medium_pct:.1f}%, "
        f"var(--low) {high_pct + medium_pct:.1f}% 100%"
        f")"
    )
    coverage_card = ""
    if coverage_gaps is not None:
        coverage_card = (
            '<div class="coverage-gap-card">'
            f'<span class="stat-number">{coverage_gaps}</span>'
            '<span class="stat-label">Coverage Gaps</span>'
            "</div>"
        )

    priority_html = f"""
      <div class="card">
        <div class="scenario-section-title">Outcome Summary</div>
        <div class="stats-bar">
          <div class="stat-card" style="border-left-color:var(--high);">
            <span class="stat-number">{high_count}</span>
            <span class="stat-label">High Priority</span>
          </div>
          <div class="stat-card" style="border-left-color:var(--medium);">
            <span class="stat-number">{medium_count}</span>
            <span class="stat-label">Medium Priority</span>
          </div>
          <div class="stat-card" style="border-left-color:var(--low);">
            <span class="stat-number">{low_count}</span>
            <span class="stat-label">Low Priority</span>
          </div>
          <div class="severity-donut" style="background:{donut_gradient};" data-tooltip="High: {high_count} | Medium: {medium_count} | Low: {low_count}"></div>
          {coverage_card}
        </div>
      </div>
    """

    return f"""
    <div id="sec-run-summary" class="section">
      <div class="section-header">
        <h2>Run Summary</h2>
      </div>

      <div class="card">
        <div class="scenario-section-title">Pipeline Funnel</div>
        <div class="stats-bar" style="align-items:center;">
          {funnel_html}
        </div>
      </div>

      {priority_html}

      <div class="stats-bar">
        <div class="stat-card" style="border-left-color:#ef4444;">
          <span class="stat-number">{failed}</span>
          <span class="stat-label">Failed</span>
        </div>
        <div class="stat-card" style="border-left-color:#f97316;">
          <span class="stat-number">{rejected}</span>
          <span class="stat-label">Rejected</span>
        </div>
        <div class="stat-card" style="border-left-color:#f97316;">
          <span class="stat-number" style="font-size:20px;">{rejection_rate}</span>
          <span class="stat-label">Rejection Rate</span>
        </div>
        {duration_card}
      </div>

      <div class="card" style="background:var(--bg-secondary);">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;font-size:13px;">
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Model</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{model_name}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Temperature</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{temperature}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Start</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{_esc(display_start)}</div>
          </div>
          <div>
            <span style="color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">End</span>
            <div style="color:var(--text-primary);font-weight:600;margin-top:4px;font-family:'SF Mono','Fira Code',monospace;">{_esc(display_end)}</div>
          </div>
        </div>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 5: Glossary appendix
# ---------------------------------------------------------------------------


def build_glossary_section() -> str:
    """Build the Glossary & Methodology appendix section."""
    # Build threat ID rows
    threat_rows = ""
    for tid, tname in THREAT_NAMES.items():
        threat_rows += (
            f"<tr><td><code>{_esc(tid)}</code></td><td>{_esc(tname)}</td></tr>"
        )

    return (
        """
    <div id="glossary" class="section">
      <div class="section-header">
        <h2>Glossary &amp; Methodology</h2>
      </div>

      <!-- Terms glossary -->
      <div class="card">
        <div class="scenario-section-title">Threat IDs (OWASP Agentic Threats)</div>
        <table class="flags-table">
          <thead><tr><th>ID</th><th>Name</th></tr></thead>
          <tbody>"""
        + threat_rows
        + """</tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Domain Terms</div>
        <table class="flags-table">
          <thead><tr><th>Term</th><th>Definition</th></tr></thead>
          <tbody>
            <tr><td><strong>Scenario Seed</strong></td><td>An abstract attack pattern (AP-*) selected for scenario generation, carrying threat provenance and taxonomy chain references</td></tr>
            <tr><td><strong>Attack Pattern</strong></td><td>A domain-agnostic attack technique derived from an OWASP Agentic Threat (T1&ndash;T17). Each pattern specifies prerequisites and maps to ATLAS/LAAF techniques via SSSOM provenance</td></tr>
            <tr><td><strong>Threat Surface</strong></td><td>The set of IBM AI Risk Atlas risks applicable to the target system, mapped to OWASP agentic threats and attack patterns</td></tr>
            <tr><td><strong>Capability Profile</strong></td><td>A Schneider 5-zone decomposition of the target system&rsquo;s capabilities, entry points, and architecture</td></tr>
            <tr><td><strong>Actor Profile</strong></td><td>A BDI (Beliefs, Desires, Intentions) threat actor model generated for each scenario, with type, capability level, and attack goal</td></tr>
            <tr><td><strong>Attack Goal</strong></td><td>One of 27 sub-goals across 4 categories (availability, integrity, privacy, abuse) assigned to each actor to direct the scenario&rsquo;s intent</td></tr>
            <tr><td><strong>Narrative</strong></td><td>A zone-annotated attack story describing the step-by-step attack path through the system</td></tr>
            <tr><td><strong>Attack Tree</strong></td><td>An AND/OR decomposition of the attack into individual steps with zone, technique, and control-point annotations</td></tr>
            <tr><td><strong>Behavior Spec</strong></td><td>A Gherkin feature specification for each scenario, enabling tool-neutral test automation</td></tr>
            <tr><td><strong>Priority Signals</strong></td><td>Composite scoring across technique maturity, risk impact, likelihood, attack complexity, architecture match, and structural exposure</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Taxonomy References</div>
        <table class="flags-table">
          <thead><tr><th>Prefix / Pattern</th><th>Description</th></tr></thead>
          <tbody>
            <tr>
              <td><code>LLM01</code>&ndash;<code>LLM10</code></td>
              <td>OWASP Top 10 for LLM Applications &mdash; standardized LLM vulnerability categories</td>
            </tr>
            <tr>
              <td><code>AML.T*</code></td>
              <td>MITRE ATLAS &mdash; Adversarial Threat Landscape for AI Systems technique identifier</td>
            </tr>
            <tr>
              <td><code>atlas-*</code></td>
              <td>IBM AI Risk Atlas &mdash; standardized AI risk identifier</td>
            </tr>
            <tr>
              <td><code>AP-T&lt;n&gt;-&lt;nn&gt;</code></td>
              <td>Abstract attack pattern &mdash; domain-agnostic scenario seed derived from OWASP agentic threat T&lt;n&gt;</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Status Badges</div>
        <table class="flags-table">
          <thead><tr><th>Badge</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr>
              <td><span class="status-badge status-actionable">ACT</span></td>
              <td>Actionable — maps to testable agentic threat scenarios</td>
            </tr>
            <tr>
              <td><span class="status-badge status-governance">GOV</span></td>
              <td>Maps to organizational controls, not directly testable</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Attack Tree Fields</div>
        <table class="flags-table">
          <thead><tr><th>Field / Value</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td><strong>Gate: AND</strong></td><td>All child steps must succeed for this attack to proceed</td></tr>
            <tr><td><strong>Gate: OR</strong></td><td>Any one child step is sufficient for this attack to proceed</td></tr>
            <tr><td><strong>Gate: LEAF</strong></td><td>Concrete attack action &mdash; no sub-steps</td></tr>
            <tr><td><strong>control_point</strong></td><td>Defensive control that should block or detect this attack step</td></tr>
            <tr><td><strong>single_point_of_failure</strong></td><td>Only one control blocks this attack path</td></tr>
            <tr><td><strong>convergence_point</strong></td><td>Multiple attack paths flow through this single control</td></tr>
            <tr><td><strong>probabilistic_control</strong></td><td>Relies on an LLM guardrail or classifier &mdash; not a binary pass/fail gate</td></tr>
            <tr><td><strong>defense_in_depth_claim</strong></td><td>Multiple controls back each other up on this path</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Priority Signals</div>
        <table class="flags-table">
          <thead><tr><th>Signal</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td><strong>technique_maturity</strong></td><td>How proven this attack technique is: <em>feasible</em> (theoretically possible), <em>demonstrated</em> (shown in lab), <em>realized</em> (observed in the wild)</td></tr>
            <tr><td><strong>architecture_match</strong></td><td>How the threat maps to this system: <em>explicit</em> (directly matches a declared capability) or <em>inferred</em> (indirectly relevant based on system profile)</td></tr>
            <tr><td><strong>attack_complexity</strong></td><td>Difficulty of executing this attack: low / medium / high</td></tr>
            <tr><td><strong>risk_impact</strong></td><td>Potential damage if attack succeeds: low / medium / high / critical</td></tr>
            <tr><td><strong>risk_likelihood</strong></td><td>Probability of this attack being attempted: low / medium / high</td></tr>
            <tr><td><strong>composite_score</strong></td><td>Combines the above signals into a single 0&ndash;1 score for prioritization</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="scenario-section-title">Confidence Values</div>
        <table class="flags-table">
          <thead><tr><th>Context</th><th>Meaning</th></tr></thead>
          <tbody>
            <tr><td>Threat Surface table</td><td>Upstream extraction confidence &mdash; how strongly the policy text maps to this risk</td></tr>
            <tr><td>Capability Profile</td><td>Profile inference confidence &mdash; how clearly the use-case description signals these capabilities</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Methodology -->
      <div class="card">
        <div class="scenario-section-title">Methodology Overview</div>

        <div style="margin-bottom:18px;">
          <strong style="color:var(--text-primary);">Schneider 5-Zone Model</strong>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">
            A capability decomposition framework that maps an AI agent&rsquo;s attack surface into five functional zones:
          </p>
          <ul style="font-size:13px;color:var(--text-secondary);margin:6px 0 0 20px;list-style:disc;">
            <li><strong>Input Surfaces:</strong> External interfaces where user or system input enters the agent</li>
            <li><strong>Planning &amp; Reasoning:</strong> The agent&rsquo;s decision-making and reasoning engine</li>
            <li><strong>Tool Execution:</strong> External tool and API calls the agent can make</li>
            <li><strong>Memory &amp; State:</strong> Persistent storage, context windows, and state management</li>
            <li><strong>Inter-Agent Communication:</strong> Message passing between agents in multi-agent systems</li>
          </ul>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:8px;">
            <strong>KC Sub-Codes</strong> from the OWASP Securing Agentic Applications Guide describe granular capabilities within each zone (e.g. KC6.1.1 limited API vs KC6.2.2 extensive code execution), enabling precise threat gating beyond the coarse zone model.
          </p>
        </div>

        <div style="margin-bottom:18px;">
          <strong style="color:var(--text-primary);">Abstract Attack Patterns &amp; Provenance</strong>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">
            OWASP agentic threats (T1&ndash;T17) are decomposed into <strong>abstract attack patterns</strong>
            (AP-*) that serve as data-driven scenario seeds. Each pattern is linked via
            <strong>SSSOM provenance</strong> mappings that cross-reference
            LAAF techniques and MITRE&nbsp;ATLAS tactic IDs. Patterns carry
            <strong>prerequisite_capabilities</strong> declarations so that only patterns whose
            prerequisites are satisfied by the system&rsquo;s capability profile are selected for
            scenario generation.
          </p>
        </div>

        <div>
          <strong style="color:var(--text-primary);">Asago Scenario Generator 4-Stage Pipeline</strong>
          <ol style="font-size:13px;color:var(--text-secondary);margin:6px 0 0 20px;">
            <li><strong>Capability Profile:</strong> Infer the agent&rsquo;s capabilities, active zones, and entry points from a use-case description</li>
            <li><strong>Threat Surface:</strong> Map the capability profile against risk taxonomies (IBM AI Risk Atlas, OWASP LLM Top&nbsp;10) and determine which agentic threats apply</li>
            <li><strong>Scenario Seeds:</strong> Select abstract attack patterns (AP-*) whose prerequisite capabilities match the system profile; each pattern carries SSSOM provenance linking back to OWASP, LAAF, and ATLAS sources</li>
            <li><strong>Scenario Generation:</strong> Use an LLM to generate full red-team scenarios for each pattern, including narrative, attack trees, behavior specifications (Gherkin with injected ATLAS technique&nbsp;IDs), and priority signals</li>
          </ol>
        </div>
      </div>

      <!-- External links -->
      <div class="card">
        <div class="scenario-section-title">External References</div>
        <ul style="list-style:none;padding:0;margin:0;">
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              OWASP Agentic AI Threats &amp; Mitigations &#8599;
            </a>
          </li>
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              OWASP Top 10 for LLM Applications &#8599;
            </a>
          </li>
          <li style="padding:8px 0;border-bottom:1px solid var(--border);">
            <a href="https://atlas.mitre.org/" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              MITRE ATLAS &#8599;
            </a>
          </li>
          <li style="padding:8px 0;">
            <a href="https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:13px;">
              IBM AI Risk Atlas &#8599;
            </a>
          </li>
        </ul>
      </div>
    </div>
    """
    )


# ---------------------------------------------------------------------------
# Section 6: Eval Scorecard
# ---------------------------------------------------------------------------


_SCORECARD_METRIC_TOOLTIPS: dict[str, str] = {
    # Consistency group
    "Consistency": (
        "How well scenario narratives, attack trees, and behavior specs "
        "agree on zones, entry points, and attack steps"
    ),
    "Mean": (
        "Average consistency score across all scenarios (0-1). "
        "Combines zone alignment, entry point agreement, and "
        "step-node correspondence"
    ),
    "Zone Alignment": (
        "Fraction of zones in the narrative zone-sequence that also "
        "appear in the attack-tree nodes (0-1)"
    ),
    "Entry Point Agreement": (
        "1 if the narrative entry point matches the attack-tree root zone, 0 otherwise"
    ),
    "Step-Node Correspondence": (
        "Fraction of Gherkin steps whose zone tag matches an "
        "attack-tree node zone (0-1)"
    ),
    # Gherkin group
    "Gherkin Quality": (
        "Structural quality of generated Gherkin behavior specifications"
    ),
    "Parse Success Rate": (
        "Fraction of generated feature files that parse without syntax errors (0-1)"
    ),
    "Mean Step Count": (
        "Average number of Given/When/Then steps per scenario. Higher "
        "counts indicate more detailed specifications"
    ),
    "Inconsistent Tag Groups": (
        "Number of scenario groups where Gherkin tags disagree with "
        "scenario metadata (0 is best)"
    ),
    "Background Warnings": (
        "Feature files missing a Background section that sets up the agent context"
    ),
    # Grounding group
    "Grounding": (
        "Whether generated IDs and references resolve to real taxonomy entries"
    ),
    "Threat ID Validity": (
        "Fraction of threat IDs in scenarios that match known OWASP "
        "Agentic Threat IDs (0-1)"
    ),
    "Dangling References": (
        "Number of taxonomy IDs referenced in scenarios that do not "
        "exist in the source taxonomy (0 is best)"
    ),
    "Technique ID Grounding": (
        "Fraction of ATLAS technique IDs in scenarios that resolve to "
        "known MITRE ATLAS techniques (0-1)"
    ),
    "Ungrounded Technique Refs": (
        "Number of ATLAS technique references that do not match any "
        "known technique (0 is best)"
    ),
    # Diversity group
    "Diversity": (
        "How well scenarios cover different attack surfaces, actor "
        "types, and entry points"
    ),
    "EP Entropy": (
        "Shannon entropy of entry-point distribution. Higher values "
        "mean more evenly distributed entry points"
    ),
    "EP Coverage": (
        "Fraction of declared system entry points that appear in at "
        "least one scenario (0-1)"
    ),
    "Active Zone Coverage": (
        "Fraction of active capability zones that are targeted by at "
        "least one scenario (0-1)"
    ),
    "Zone Violations": (
        "Scenarios that target zones not declared as active in the "
        "capability profile (0 is best)"
    ),
    "Actor Type Entropy": (
        "Shannon entropy of actor-type distribution. Higher values "
        "indicate more diverse attacker personas"
    ),
    "Capability Evenness": (
        "How evenly capability levels (novice to expert) are "
        "distributed across scenarios (0-1)"
    ),
    "Title Uniqueness": (
        "Fraction of scenario titles that are unique. Detects "
        "duplicate or near-duplicate generations (1 is best)"
    ),
    # Technique Agreement group
    "Technique Agreement": (
        "Whether narrative, attack tree, and behavior spec reference "
        "the same set of ATLAS technique IDs"
    ),
    "Mean Technique Agreement": (
        "Average Jaccard similarity of technique ID sets across all "
        "three lenses (narrative, tree, spec). 1.0 means perfect agreement"
    ),
    # Plausibility group
    "Plausibility": (
        "Whether attack steps are realistic given the actor's declared capability level"
    ),
    "Capability Violations": (
        "Number of scenarios where attack complexity exceeds the "
        "actor's capability level (0 is best)"
    ),
}


def _scorecard_badge(
    value: float, label: str, *, invert: bool = False, tooltip: str = ""
) -> str:
    """Return a colored badge for a metric value.

    Args:
        value: Numeric metric value (0-1 scale for rates, raw for counts).
        label: Display label for the badge.
        invert: When True, lower values are better (e.g. violation counts).
        tooltip: Optional tooltip text. If empty, looks up from
                 ``_SCORECARD_METRIC_TOOLTIPS`` using *label*.
    """
    if invert:
        # For counts: 0 = green, >0 = red
        css_cls = "scorecard-badge-green" if value == 0 else "scorecard-badge-red"
    else:
        if value >= 0.9:
            css_cls = "scorecard-badge-green"
        elif value >= 0.7:
            css_cls = "scorecard-badge-yellow"
        else:
            css_cls = "scorecard-badge-red"
    if isinstance(value, float) and not value.is_integer():
        display = f"{value:.2f}"
    else:
        display = str(int(value))
    tip = tooltip or _SCORECARD_METRIC_TOOLTIPS.get(label, "")
    tip_attr = f' data-tooltip="{_esc(tip)}"' if tip else ""
    return f'<span class="scorecard-badge {css_cls}"{tip_attr}>{_esc(label)}: {display}</span>'


def _collect_scorecard_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, float | int | str, str]]:
    """Scan scorecard evaluation data and return outlier rows.

    Each row is ``(severity, scenario_id, group, metric, value, css_cls)``
    where *severity* is ``"red"`` or ``"yellow"`` (for sort ordering) and
    *css_cls* is the badge CSS class.

    Returns:
        Sorted list: red items first, then yellow, each alphabetical by
        scenario ID within its severity tier.
    """
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []

    # --- Per-scenario consistency ---
    per_scenario_c = ev.get("consistency", {}).get("per_scenario", {})
    for sid, metrics in per_scenario_c.items():
        za = metrics.get("zone_alignment", 1.0)
        if za < 0.9:
            css = "scorecard-badge-red" if za < 0.7 else "scorecard-badge-yellow"
            sev = "red" if za < 0.7 else "yellow"
            outliers.append((sev, sid, "Consistency", "Zone Alignment", za, css))
        epa = metrics.get("entry_point_agreement", 1)
        if epa < 1:
            outliers.append(
                (
                    "red",
                    sid,
                    "Consistency",
                    "Entry Point Agreement",
                    epa,
                    "scorecard-badge-red",
                )
            )
        snc = metrics.get("step_node_correspondence", 1.0)
        if snc < 0.9:
            css = "scorecard-badge-red" if snc < 0.7 else "scorecard-badge-yellow"
            sev = "red" if snc < 0.7 else "yellow"
            outliers.append(
                (sev, sid, "Consistency", "Step-Node Correspondence", snc, css)
            )

    # --- Per-scenario technique agreement ---
    ta = ev.get("technique_agreement", {})
    per_scenario_ta = ta.get("per_scenario", {})
    for sid, detail in per_scenario_ta.items():
        score = detail.get("technique_agreement", 1.0)
        missing_narr = detail.get("missing_from_narrative", [])
        missing_tree = detail.get("missing_from_tree", [])
        missing_spec = detail.get("missing_from_spec", [])
        if score < 0.9:
            css = "scorecard-badge-red" if score < 0.7 else "scorecard-badge-yellow"
            sev = "red" if score < 0.7 else "yellow"
            outliers.append(
                (sev, sid, "Technique Agreement", "Technique Agreement", score, css)
            )
        elif missing_narr or missing_tree or missing_spec:
            parts = []
            if missing_narr:
                parts.append(f"narrative: {', '.join(missing_narr)}")
            if missing_tree:
                parts.append(f"tree: {', '.join(missing_tree)}")
            if missing_spec:
                parts.append(f"spec: {', '.join(missing_spec)}")
            outliers.append(
                (
                    "yellow",
                    sid,
                    "Technique Agreement",
                    "Missing Techniques",
                    "; ".join(parts),
                    "scorecard-badge-yellow",
                )
            )

    # --- Per-scenario plausibility ---
    per_scenario_p = ev.get("plausibility", {}).get("per_scenario", {})
    for sid, issues in per_scenario_p.items():
        if issues and isinstance(issues, list):
            for issue in issues:
                outliers.append(
                    (
                        "red",
                        sid,
                        "Plausibility",
                        "Capability Violation",
                        str(issue),
                        "scorecard-badge-red",
                    )
                )

    # --- Aggregate diversity outliers ---
    diversity = ev.get("diversity", {})
    tu = diversity.get("title_uniqueness", 1.0)
    if isinstance(tu, (int, float)) and tu < 0.7:
        css = "scorecard-badge-red" if tu < 0.5 else "scorecard-badge-yellow"
        sev = "red" if tu < 0.5 else "yellow"
        outliers.append((sev, "(aggregate)", "Diversity", "Title Uniqueness", tu, css))

    ep_ent = diversity.get("entry_point_entropy", {})
    if isinstance(ep_ent, dict):
        ep_cov = ep_ent.get("entry_point_coverage", 1.0)
        if ep_cov < 0.7:
            css = "scorecard-badge-red" if ep_cov < 0.5 else "scorecard-badge-yellow"
            sev = "red" if ep_cov < 0.5 else "yellow"
            outliers.append(
                (sev, "(aggregate)", "Diversity", "EP Coverage", ep_cov, css)
            )

    # --- Aggregate plausibility ---
    violation_count = ev.get("plausibility", {}).get(
        "capability_complexity_violation_count", 0
    )
    if violation_count > 0:
        outliers.append(
            (
                "red",
                "(aggregate)",
                "Plausibility",
                "Capability Violations",
                violation_count,
                "scorecard-badge-red",
            )
        )

    # Sort: red first, then yellow; within each tier, alphabetical by scenario
    severity_order = {"red": 0, "yellow": 1}
    outliers.sort(key=lambda r: (severity_order.get(r[0], 2), r[1]))
    return outliers


def _build_outliers_panel(
    outliers: list[tuple[str, str, str, str, float | int | str, str]],
) -> str:
    """Render the outliers summary panel HTML.

    Args:
        outliers: Rows from :func:`_collect_scorecard_outliers`.

    Returns:
        HTML string for the outliers panel.
    """
    if not outliers:
        return (
            '<div class="scorecard-outliers-clear">'
            "✅ All scenarios pass quality checks"
            "</div>"
        )

    rows = ""
    for _sev, sid, group, metric, value, css in outliers:
        if isinstance(value, float):
            display = f"{value:.2f}"
        elif isinstance(value, int):
            display = str(value)
        else:
            display = str(value)
        rows += (
            f"<tr>"
            f"<td>{_esc(sid)}</td>"
            f"<td>{_esc(group)}</td>"
            f"<td>{_esc(metric)}</td>"
            f'<td><span class="scorecard-badge {css}">{_esc(display)}</span></td>'
            f"</tr>"
        )

    return (
        '<div class="scorecard-outliers">'
        '<div class="scorecard-outliers-title">'
        "⚠ Quality Outliers</div>"
        "<table>"
        "<thead><tr>"
        "<th>Scenario</th><th>Group</th><th>Metric</th><th>Value</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
        "</div>"
    )


def _build_versioned_scorecard_section(scorecard_data: dict[str, Any]) -> str:
    """Render strict typed metrics without inferring meaning from missing values."""
    labels = (
        ("presence_coverage", "Presence / Coverage"),
        ("validity_grounding", "Validity / Grounding"),
        ("cross_artifact_agreement", "Cross-artifact Agreement"),
        ("semantic_quality_diagnostics", "Semantic Quality / Diagnostics"),
        ("release_qualification", "Release Qualification"),
    )
    groups = ""
    for key, label in labels:
        metrics = scorecard_data.get(key, {}).get("metrics", {})
        rows = ""
        for metric_id, metric in metrics.items():
            status = str(metric.get("status", "error"))
            css = {
                "pass": "scorecard-badge-green",
                "fail": "scorecard-badge-red",
                "not_applicable": "scorecard-badge-yellow",
                "error": "scorecard-badge-red",
            }.get(status, "scorecard-badge-red")
            numerator = metric.get("numerator")
            denominator = metric.get("denominator")
            fraction = "—"
            if numerator is not None:
                fraction = str(numerator)
                if denominator is not None:
                    fraction += f" / {denominator}"
            value = metric.get("value")
            rendered_value = "—" if value is None else f"{float(value):.4f}"
            evidence = "; ".join(str(item) for item in metric.get("evidence", []))
            affected = ", ".join(str(item) for item in metric.get("affected_ids", []))
            rows += (
                "<tr>"
                f"<td>{_esc(metric_id)}</td>"
                f'<td><span class="scorecard-badge {css}">{_esc(status)}</span></td>'
                f"<td>{_esc(fraction)}</td><td>{_esc(rendered_value)}</td>"
                f"<td>{_esc(evidence)}</td><td>{_esc(affected) or '—'}</td>"
                "</tr>"
            )
        groups += f"""
        <div class="scorecard-group">
          <div class="scorecard-group-title">{_esc(label)}</div>
          <table class="scorecard-detail-table">
            <thead><tr><th>Metric</th><th>Status</th><th>Numerator / Denominator</th>
            <th>Bounded Value</th><th>Evidence</th><th>Affected IDs</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""
    qualification = scorecard_data.get("qualification", {})
    qualification_status = str(qualification.get("status", "error"))
    failures = qualification.get("failed_gate_ids", [])
    errors = qualification.get("error_gate_ids", [])
    not_applicable = qualification.get("not_applicable_gate_ids", [])
    return f"""
    <div id="sec-scorecard" class="section">
      <div class="section-header"><h2>Versioned Eval Scorecard</h2>
        <span class="badge">Schema v{_esc(scorecard_data.get("schema_version", ""))}</span>
      </div>
      <div class="card">
        <div class="scorecard-summary">
          <div class="scorecard-stat"><div class="scorecard-stat-value">{scorecard_data.get("scenario_count", 0)}</div><div class="scorecard-stat-label">Admitted Scenarios</div></div>
          <div class="scorecard-stat"><div class="scorecard-stat-value">{scorecard_data.get("feature_file_count", 0)}</div><div class="scorecard-stat-label">Verified Features</div></div>
          <div class="scorecard-stat"><div class="scorecard-stat-value">{_esc(qualification_status)}</div><div class="scorecard-stat-label">Qualification</div></div>
        </div>
        <p><strong>Qualification failures:</strong> {_esc(", ".join(failures)) or "none"}</p>
        <p><strong>Qualification errors:</strong> {_esc(", ".join(errors)) or "none"}</p>
        <p><strong>Not applicable (excluded):</strong> {_esc(", ".join(not_applicable)) or "none"}</p>
        {groups}
      </div>
    </div>"""


def build_scorecard_section(scorecard_data: dict[str, Any]) -> str:
    """Build the Eval Scorecard HTML section from parsed YAML data.

    Args:
        scorecard_data: Parsed dict from ``eval-scorecard.yaml``.

    Returns:
        HTML string for the scorecard section, or empty string if data is empty.
    """
    if not scorecard_data:
        return ""

    if scorecard_data.get("schema_version") == "1":
        return _build_versioned_scorecard_section(scorecard_data)

    ev = scorecard_data.get("evaluation", {})
    if not ev:
        return ""

    scenario_count = ev.get("scenario_count", 0)
    feature_file_count = ev.get("feature_file_count", 0)

    # --- Summary stats ---
    summary_html = f"""
    <div class="scorecard-summary">
      <div class="scorecard-stat">
        <div class="scorecard-stat-value">{scenario_count}</div>
        <div class="scorecard-stat-label">Scenarios</div>
      </div>
      <div class="scorecard-stat">
        <div class="scorecard-stat-value">{feature_file_count}</div>
        <div class="scorecard-stat-label">Feature Files</div>
      </div>
    </div>"""

    # --- Outliers panel (rendered after summary, before metric groups) ---
    outliers = _collect_scorecard_outliers(ev)
    outliers_html = _build_outliers_panel(outliers)

    # --- Consistency ---
    consistency = ev.get("consistency", {})
    consistency_badges = ""
    if consistency:
        mean = consistency.get("mean", 0)
        stddev = consistency.get("stddev", 0)
        consistency_badges += _scorecard_badge(mean, "Mean")
        consistency_badges += _scorecard_badge(
            1.0 - stddev,
            f"Stddev: {stddev:.3f}",
            invert=False,
            tooltip=(
                "Standard deviation of per-scenario consistency scores. "
                "Lower values mean more uniform quality across scenarios"
            ),
        )

    per_scenario_consistency = consistency.get("per_scenario", {})
    consistency_detail = ""
    if per_scenario_consistency:
        rows = ""
        for sid, metrics in per_scenario_consistency.items():
            za = metrics.get("zone_alignment", 0)
            epa = metrics.get("entry_point_agreement", 0)
            snc = metrics.get("step_node_correspondence", 0)
            za_cls = (
                "scorecard-badge-green"
                if za >= 0.9
                else ("scorecard-badge-yellow" if za >= 0.7 else "scorecard-badge-red")
            )
            epa_cls = "scorecard-badge-green" if epa == 1 else "scorecard-badge-red"
            snc_cls = (
                "scorecard-badge-green"
                if snc >= 0.9
                else ("scorecard-badge-yellow" if snc >= 0.7 else "scorecard-badge-red")
            )
            rows += (
                f"<tr>"
                f"<td>{_esc(sid)}</td>"
                f'<td><span class="scorecard-badge {za_cls}">{za:.2f}</span></td>'
                f'<td><span class="scorecard-badge {epa_cls}">{epa}</span></td>'
                f'<td><span class="scorecard-badge {snc_cls}">{snc:.2f}</span></td>'
                f"</tr>"
            )
        consistency_detail = f"""
        <details class="expandable" style="margin-top:10px;">
          <summary>Per-Scenario Breakdown</summary>
          <table class="scorecard-detail-table">
            <thead><tr>
              <th>Scenario</th>
              <th data-tooltip="{_esc(_SCORECARD_METRIC_TOOLTIPS.get("Zone Alignment", ""))}">Zone Alignment</th>
              <th data-tooltip="{_esc(_SCORECARD_METRIC_TOOLTIPS.get("Entry Point Agreement", ""))}">Entry Point Agreement</th>
              <th data-tooltip="{_esc(_SCORECARD_METRIC_TOOLTIPS.get("Step-Node Correspondence", ""))}">Step-Node Correspondence</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </details>"""

    consistency_tip = _SCORECARD_METRIC_TOOLTIPS.get("Consistency", "")
    consistency_html = f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(consistency_tip)}">Consistency</div>
      <div class="scorecard-metrics">{consistency_badges}</div>
      {consistency_detail}
    </div>"""

    # --- Gherkin ---
    gherkin = ev.get("gherkin", {})
    gherkin_badges = ""
    if gherkin:
        psr = gherkin.get("parse_success_rate", 0)
        msc = gherkin.get("mean_step_count", 0)
        tag_con = gherkin.get("tag_consistency", {})
        ig = tag_con.get("inconsistent_groups", 0)
        bm_warnings = gherkin.get("background_missing_warnings", [])
        gherkin_badges += _scorecard_badge(psr, "Parse Success Rate")
        msc_tip = _SCORECARD_METRIC_TOOLTIPS.get("Mean Step Count", "")
        gherkin_badges += (
            f'<span class="scorecard-badge scorecard-badge-green"'
            f' data-tooltip="{_esc(msc_tip)}">'
            f"Mean Step Count: {msc:.1f}</span>"
        )
        gherkin_badges += _scorecard_badge(ig, "Inconsistent Tag Groups", invert=True)
        if bm_warnings:
            bw_tip = _SCORECARD_METRIC_TOOLTIPS.get("Background Warnings", "")
            gherkin_badges += (
                f'<span class="scorecard-badge scorecard-badge-yellow"'
                f' data-tooltip="{_esc(bw_tip)}">'
                f"Background Warnings: {len(bm_warnings)}</span>"
            )

    gherkin_tip = _SCORECARD_METRIC_TOOLTIPS.get("Gherkin Quality", "")
    gherkin_html = (
        f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(gherkin_tip)}">Gherkin Quality</div>
      <div class="scorecard-metrics">{gherkin_badges}</div>
    </div>"""
        if gherkin_badges
        else ""
    )

    # --- Grounding ---
    grounding = ev.get("grounding", {})
    grounding_badges = ""
    if grounding:
        tiv = grounding.get("threat_id_validity", 0)
        dr = grounding.get("dangling_references", 0)
        tig = grounding.get("technique_id_grounding", 0)
        utr = grounding.get("ungrounded_technique_references", 0)
        grounding_badges += _scorecard_badge(tiv, "Threat ID Validity")
        grounding_badges += _scorecard_badge(dr, "Dangling References", invert=True)
        grounding_badges += _scorecard_badge(tig, "Technique ID Grounding")
        grounding_badges += _scorecard_badge(
            utr, "Ungrounded Technique Refs", invert=True
        )

    grounding_tip = _SCORECARD_METRIC_TOOLTIPS.get("Grounding", "")
    grounding_html = (
        f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(grounding_tip)}">Grounding</div>
      <div class="scorecard-metrics">{grounding_badges}</div>
    </div>"""
        if grounding_badges
        else ""
    )

    # --- Technique Agreement ---
    technique_agreement = ev.get("technique_agreement", {})
    technique_agreement_html = ""
    if technique_agreement:
        mta = technique_agreement.get("mean_technique_agreement", 0)
        ta_badges = _scorecard_badge(mta, "Mean Technique Agreement")

        ta_per_scenario = technique_agreement.get("per_scenario", {})
        ta_detail = ""
        if ta_per_scenario:
            ta_rows = ""
            for sid, detail in ta_per_scenario.items():
                score = detail.get("technique_agreement", 0)
                missing_narr = ", ".join(detail.get("missing_from_narrative", []))
                missing_tree = ", ".join(detail.get("missing_from_tree", []))
                missing_spec = ", ".join(detail.get("missing_from_spec", []))
                score_cls = (
                    "scorecard-badge-green"
                    if score >= 0.9
                    else (
                        "scorecard-badge-yellow"
                        if score >= 0.7
                        else "scorecard-badge-red"
                    )
                )
                ta_rows += (
                    f"<tr>"
                    f"<td>{_esc(sid)}</td>"
                    f'<td><span class="scorecard-badge {score_cls}">{score:.2f}</span></td>'
                    f"<td>{_esc(missing_narr) or '-'}</td>"
                    f"<td>{_esc(missing_tree) or '-'}</td>"
                    f"<td>{_esc(missing_spec) or '-'}</td>"
                    f"</tr>"
                )
            ta_detail = f"""
        <details class="expandable" style="margin-top:10px;">
          <summary>Per-Scenario Disagreements</summary>
          <table class="scorecard-detail-table">
            <thead><tr>
              <th>Scenario</th>
              <th>Agreement</th>
              <th data-tooltip="Technique IDs present in tree/spec but missing from narrative">Missing from Narrative</th>
              <th data-tooltip="Technique IDs present in narrative/spec but missing from attack tree">Missing from Tree</th>
              <th data-tooltip="Technique IDs present in narrative/tree but missing from behavior spec">Missing from Spec</th>
            </tr></thead>
            <tbody>{ta_rows}</tbody>
          </table>
        </details>"""

        ta_tip = _SCORECARD_METRIC_TOOLTIPS.get("Technique Agreement", "")
        technique_agreement_html = f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(ta_tip)}">Technique Agreement</div>
      <div class="scorecard-metrics">{ta_badges}</div>
      {ta_detail}
    </div>"""

    # --- Diversity ---
    diversity = ev.get("diversity", {})
    diversity_badges = ""
    if diversity:
        ep_ent = diversity.get("entry_point_entropy", {})
        if isinstance(ep_ent, dict):
            entropy = ep_ent.get("entropy", 0)
            ep_cov = ep_ent.get("entry_point_coverage", 0)
            ep_ent_tip = _SCORECARD_METRIC_TOOLTIPS.get("EP Entropy", "")
            diversity_badges += (
                f'<span class="scorecard-badge scorecard-badge-green"'
                f' data-tooltip="{_esc(ep_ent_tip)}">'
                f"EP Entropy: {entropy:.2f}</span>"
            )
            diversity_badges += _scorecard_badge(ep_cov, "EP Coverage")

        zone_cov = diversity.get("zone_coverage", {})
        if isinstance(zone_cov, dict):
            azc = zone_cov.get("active_zone_coverage", 0)
            diversity_badges += _scorecard_badge(azc, "Active Zone Coverage")
            violations = zone_cov.get("out_of_scope_zone_violations", [])
            if violations:
                diversity_badges += _scorecard_badge(
                    len(violations), "Zone Violations", invert=True
                )

        ate = diversity.get("actor_type_entropy", 0)
        if isinstance(ate, (int, float)):
            diversity_badges += _scorecard_badge(ate, "Actor Type Entropy")

        cle = diversity.get("capability_level_evenness", 0)
        if isinstance(cle, (int, float)):
            diversity_badges += _scorecard_badge(cle, "Capability Evenness")

        tu = diversity.get("title_uniqueness", 0)
        if isinstance(tu, (int, float)):
            diversity_badges += _scorecard_badge(tu, "Title Uniqueness")

    diversity_tip = _SCORECARD_METRIC_TOOLTIPS.get("Diversity", "")
    diversity_html = (
        f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(diversity_tip)}">Diversity</div>
      <div class="scorecard-metrics">{diversity_badges}</div>
    </div>"""
        if diversity_badges
        else ""
    )

    # --- Plausibility ---
    plausibility = ev.get("plausibility", {})
    plausibility_html = ""
    if plausibility:
        violation_count = plausibility.get("capability_complexity_violation_count", 0)
        plausibility_badges = _scorecard_badge(
            violation_count, "Capability Violations", invert=True
        )

        per_scenario_p = plausibility.get("per_scenario", {})
        violations_detail = ""
        if per_scenario_p:
            violation_items = ""
            for sid, issues in per_scenario_p.items():
                if issues and isinstance(issues, list):
                    for issue in issues:
                        violation_items += (
                            f"<tr><td>{_esc(sid)}</td><td>{_esc(str(issue))}</td></tr>"
                        )
            if violation_items:
                violations_detail = f"""
        <details class="expandable" style="margin-top:10px;">
          <summary>Violation Details</summary>
          <table class="scorecard-detail-table">
            <thead><tr><th>Scenario</th><th>Issue</th></tr></thead>
            <tbody>{violation_items}</tbody>
          </table>
        </details>"""

        plausibility_tip = _SCORECARD_METRIC_TOOLTIPS.get("Plausibility", "")
        plausibility_html = f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(plausibility_tip)}">Plausibility</div>
      <div class="scorecard-metrics">{plausibility_badges}</div>
      {violations_detail}
    </div>"""

    return f"""
    <div id="sec-scorecard" class="section">
      <div class="section-header">
        <h2>Eval Scorecard</h2>
        <span class="badge">Tier 1 Metrics</span>
      </div>

      <div class="card">
        {summary_html}
        {outliers_html}
        {consistency_html}
        {gherkin_html}
        {grounding_html}
        {technique_agreement_html}
        {diversity_html}
        {plausibility_html}
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Full page assembly
# ---------------------------------------------------------------------------


def build_full_page(
    profile_html: str,
    threats_html: str,
    scenarios_html: str,
    raw_html: str,
    coverage_html: str = "",
    diversity_html: str = "",
    use_case_html: str = "",
    scorecard_html: str = "",
    threat_technique_html: str = "",
    run_summary_html: str = "",
    methodology_html: str = "",
    pipeline_calls_html: str = "",
    title: str = "Asago Scenario Generator Report",
) -> str:
    # Conditionally add sidebar links for optional sections
    run_summary_nav = ""
    if run_summary_html:
        run_summary_nav = '<a href="#sec-run-summary"><span class="nav-icon">&#9654;</span> Run Summary</a>'
    methodology_nav = ""
    if methodology_html:
        methodology_nav = '<a href="#sec-methodology"><span class="nav-icon">&#9881;</span> Methodology</a>'
    use_case_nav = ""
    if use_case_html:
        use_case_nav = (
            '<a href="#sec-use-case"><span class="nav-icon">&#9673;</span> Use Case</a>'
        )
    coverage_nav = ""
    if coverage_html:
        coverage_nav = '<a href="#sec-coverage"><span class="nav-icon">&#9635;</span> Coverage Analysis</a>'
    diversity_nav = ""
    if diversity_html:
        diversity_nav = '<a href="#sec-diversity"><span class="nav-icon">&#9783;</span> Actor Profiles</a>'
    scorecard_nav = ""
    if scorecard_html:
        scorecard_nav = '<a href="#sec-scorecard"><span class="nav-icon">&#9745;</span> Eval Scorecard</a>'
    threat_technique_nav = ""
    if threat_technique_html:
        threat_technique_nav = '<a href="#sec-threat-matrix"><span class="nav-icon">&#9638;</span> Threat–Technique Matrix</a>'
    pipeline_calls_nav = ""
    if pipeline_calls_html:
        pipeline_calls_nav = '<a href="#sec-pipeline-calls"><span class="nav-icon">&#9998;</span> Pipeline LLM Calls</a>'

    glossary_html = build_glossary_section()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_esc(title)}</title>
  {build_css()}
</head>
<body>
  <aside class="sidebar">
    <div class="sidebar-brand">
      <h1>ASAGO SCENARIO GENERATOR</h1>
      <div class="subtitle">Red-Team Report</div>
    </div>
    <nav>
      {run_summary_nav}
      {methodology_nav}
      {use_case_nav}
      <a href="#sec-profile"><span class="nav-icon">&#9670;</span> Capability Profile</a>
      <a href="#sec-threats"><span class="nav-icon">&#9888;</span> Threat Surface</a>
      {coverage_nav}
      {threat_technique_nav}
      {diversity_nav}
      <a href="#sec-scenarios"><span class="nav-icon">&#9733;</span> Scenarios</a>
      {scorecard_nav}
      {pipeline_calls_nav}
      <a href="#sec-raw"><span class="nav-icon">&#128196;</span> Raw Data</a>
      <a href="#glossary"><span class="nav-icon">&#128214;</span> Glossary</a>
    </nav>
  </aside>

  <main class="main-content">
    {run_summary_html}
    {methodology_html}
    {use_case_html}
    {profile_html}
    {threats_html}
    {coverage_html}
    {threat_technique_html}
    {diversity_html}
    {scenarios_html}
    {scorecard_html}
    {pipeline_calls_html}
    {raw_html}
    {glossary_html}
  </main>

  {build_js()}
</body>
</html>
"""
