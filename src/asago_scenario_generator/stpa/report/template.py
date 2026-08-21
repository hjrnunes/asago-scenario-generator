"""HTML template components for the STPA report.

Self-contained HTML with inline CSS/JS — no external dependencies.
Section builders return HTML strings.  ``build_html`` assembles the
final document.

Public API (used by :mod:`asago_scenario_generator.stpa.report.generator`):

- ``build_html`` — top-level assembler.
- ``build_sp1_card`` — SP1 flow card.
- ``build_sp2_card`` — SP2 flow card.
- ``build_sp3_card`` — SP3 flow card.
- ``build_llm_call_inspector`` — LLM call inspector section.
- ``build_run_manifest`` — run manifest section.
- ``extract_metric_rate`` — rate extraction helper.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

__all__ = [
    "build_html",
    "build_sp1_card",
    "build_sp2_card",
    "build_sp3_card",
    "build_llm_call_inspector",
    "build_run_manifest",
    "extract_metric_rate",
]


def _esc(text: str | None) -> str:
    """HTML-escape text safely for the standalone STPA renderer."""
    return "" if text is None else html.escape(str(text))


# ---------------------------------------------------------------------------
# Escaping and syntax highlighting
# ---------------------------------------------------------------------------


def _highlight_yaml(text: str) -> str:
    """Simple regex-based YAML syntax highlighting."""
    lines = text.split("\n")
    result: list[str] = []
    for line in lines:
        escaped = _esc(line)
        if escaped.strip().startswith("#"):
            result.append(f'<span class="yaml-comment">{escaped}</span>')
            continue
        m = re.match(r"^(\s*)([\w.-]+)(\s*:\s*)(.*)", escaped)
        if m:
            indent, key, colon, value = m.groups()
            result.append(
                f'{indent}<span class="yaml-key">{key}</span>{colon}'
                f"{_highlight_yaml_value(value)}"
            )
            continue
        m = re.match(r"^(\s*-\s+)(.*)", escaped)
        if m:
            prefix, value = m.groups()
            result.append(f"{prefix}{_highlight_yaml_value(value)}")
            continue
        result.append(escaped)
    return "\n".join(result)


def _is_quoted_string(v: str) -> bool:
    """Check if *v* is a single- or double-quoted YAML string."""
    return (v.startswith("'") and v.endswith("'")) or (
        v.startswith('"') and v.endswith('"')
    )


def _yaml_value_class(v: str) -> str | None:
    """Return the CSS class for a YAML scalar value, or None."""
    if v in ("null", "~"):
        return "yaml-null"
    if v in ("true", "false"):
        return "yaml-bool"
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return "yaml-number"
    if _is_quoted_string(v):
        return "yaml-string"
    return None


def _highlight_yaml_value(value: str) -> str:
    v = value.strip()
    if not v:
        return value
    css = _yaml_value_class(v)
    if css:
        return f'<span class="{css}">{value}</span>'
    return value


def _pretty_print_if_json(content: str) -> str:
    """If content looks like JSON, pretty-print it. Otherwise escape as-is."""
    if not isinstance(content, str):
        return _esc(content)
    stripped = content.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
            return _esc(pretty)
        except (ValueError, TypeError):
            pass
    return _esc(content)


_GHERKIN_KEYWORDS = [
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
]


def _apply_gherkin_keyword_highlight(escaped: str) -> str:
    """Apply keyword highlighting to a single escaped Gherkin line."""
    for kw in _GHERKIN_KEYWORDS:
        ekw = _esc(kw)
        if escaped.strip().startswith(ekw):
            idx = escaped.index(ekw)
            css = _gherkin_keyword_class(kw.strip())
            return (
                escaped[:idx]
                + f'<span class="{css}">{ekw}</span>'
                + escaped[idx + len(ekw) :]
            )
    return escaped


def _highlight_gherkin(text: str) -> str:
    """Render Gherkin as structured HTML with styled step rows.

    Parses Gherkin text line-by-line and produces flexbox step rows
    with colored keyword labels (matching the non-STPA report style).
    """
    if not text:
        return ""
    lines = text.strip().split("\n")
    result: list[str] = []
    in_docstring = False
    docstring_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith('"""') and not in_docstring:
            in_docstring = True
            remainder = stripped[3:]
            docstring_lines = [remainder] if remainder else []
            continue
        if in_docstring:
            if stripped.endswith('"""'):
                remainder = stripped[:-3]
                if remainder:
                    docstring_lines.append(remainder)
                ds_text = "\n".join(docstring_lines).strip()
                result.append(
                    f'<div class="step-docstring">"""\n{_esc(ds_text)}\n"""</div>'
                )
                in_docstring = False
                docstring_lines = []
            else:
                docstring_lines.append(stripped)
            continue

        if stripped.startswith("@"):
            result.append(f'<div class="gherkin-tag-line">{_esc(stripped)}</div>')
            continue
        if stripped.startswith("#"):
            result.append(f'<div class="gherkin-comment-line">{_esc(stripped)}</div>')
            continue
        if not stripped:
            continue

        keyword = None
        step_text = stripped
        step_class = ""

        for kw, cls in [
            ("Feature:", ""),
            ("Background:", ""),
            ("Scenario:", ""),
            ("Scenario Outline:", ""),
            ("Given ", "step-given"),
            ("When ", "step-when"),
            ("And ", "step-and"),
            ("Then ", "step-then"),
            ("But ", "step-but"),
            ("* ", "step-star"),
        ]:
            if stripped.startswith(kw):
                keyword = kw.strip().rstrip(":")
                step_text = stripped[len(kw) :].strip()
                step_class = cls
                break

        if not keyword:
            result.append(
                f'<div style="padding:4px 14px 4px 70px;font-size:13px;color:var(--text-secondary);">{_esc(stripped)}</div>'
            )
            continue

        if keyword in ("Feature", "Background", "Scenario", "Scenario Outline"):
            result.append(
                f'<div style="padding:10px 0 6px;font-size:14px;font-weight:700;color:var(--text-primary);">'
                f'<span style="color:var(--accent);">{_esc(keyword)}:</span> {_esc(step_text)}</div>'
            )
            continue

        result.append(
            f'<div class="feature-step {step_class}">'
            f'<span class="step-keyword">{_esc(keyword)}</span> '
            f'<span class="step-text">{_esc(step_text)}</span>'
            f"</div>"
        )

    return "\n".join(result)


def _gherkin_keyword_class(keyword: str) -> str:
    """Return the CSS class for a Gherkin keyword."""
    mapping = {
        "Given:": "step-given",
        "When:": "step-when",
        "Then:": "step-then",
        "But:": "step-but",
        "And:": "step-and",
        "Feature:": "step-given",
        "Background:": "step-given",
        "Scenario:": "step-when",
        "Scenario": "step-when",
        "Outline:": "step-when",
        "*": "step-star",
    }
    return mapping.get(keyword, "gherkin-keyword")


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------


def _build_css() -> str:
    return """<style>
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
  --green: #22c55e;
  --yellow: #f59e0b;
  --red: #ef4444;
  --blue: #3b82f6;
  --purple: #8b5cf6;
  --indigo: #6366f1;
  --orange: #f97316;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
}
.container { max-width: 1400px; margin: 0 auto; padding: 40px 24px 80px; }

/* Hero */
.hero {
  background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 32px;
}
.hero h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
.hero-meta { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }
.hero-stat { display: flex; flex-direction: column; gap: 2px; }
.hero-stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.hero-stat-value { font-size: 18px; font-weight: 700; color: var(--text-primary); }
.hero-metrics { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
.hero-metric { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; }
.hero-metric-name { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.hero-metric-value { font-size: 16px; font-weight: 700; }

/* Flow cards */
.flow-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 0;
  overflow: hidden;
}
.flow-card > summary {
  cursor: pointer;
  padding: 18px 24px;
  font-size: 18px;
  font-weight: 700;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--bg-secondary);
}
.flow-card > summary::-webkit-details-marker { display: none; }
.flow-card > summary::before {
  content: '\\25B6'; font-size: 10px; color: var(--text-muted); transition: transform 0.2s;
}
.flow-card[open] > summary::before { transform: rotate(90deg); }
.flow-card-body { padding: 24px; }

/* Produces arrow */
.produces-arrow {
  text-align: center;
  font-size: 24px;
  color: var(--text-muted);
  padding: 8px 0;
  user-select: none;
}

/* Subsection */
.subsection { margin-bottom: 20px; }
.subsection-title {
  font-size: 13px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 10px;
  padding-bottom: 6px; border-bottom: 1px solid var(--border);
}

/* Tables */
.data-table { width: 100%; border-collapse: collapse; margin-bottom: 12px; }
.data-table th {
  text-align: left; padding: 8px 12px; background: var(--bg-secondary);
  color: var(--text-secondary); font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border);
}
.data-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; word-break: break-word; overflow-wrap: break-word; }
.data-table td:first-child { white-space: nowrap; word-break: normal; overflow-wrap: normal; }
.data-table tr:hover td { background: var(--bg-card-hover); }

/* Zone chips */
.zone-chip {
  display: inline-flex; align-items: center; height: 24px; padding: 0 10px;
  border-radius: 4px; font-size: 11px; font-weight: 600; margin: 2px;
  background: var(--accent-glow); color: var(--accent); border: 1px solid var(--border);
}

/* Scenario cards */
.scenario-card {
  background: var(--bg-secondary); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 12px; overflow: hidden;
}
.scenario-card > summary {
  cursor: pointer; padding: 12px 18px; font-size: 14px; font-weight: 600;
  list-style: none; display: flex; align-items: center; gap: 8px;
}
.scenario-card > summary::-webkit-details-marker { display: none; }
.scenario-card > summary::before {
  content: '\\25B6'; font-size: 8px; color: var(--text-muted); transition: transform 0.2s;
}
.scenario-card[open] > summary::before { transform: rotate(90deg); }
.scenario-card-body { padding: 16px 18px; }
.scenario-section { margin-bottom: 16px; }
.scenario-section:last-child { margin-bottom: 0; }
.scenario-section-title {
  font-size: 11px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 8px;
}

/* BDI */
.bdi-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.bdi-block { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
.bdi-block h4 { font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px; }
.bdi-item { font-size: 12px; color: var(--text-primary); margin-bottom: 4px; line-height: 1.5; }
.bdi-item-vuln { font-size: 11px; color: var(--text-muted); font-style: italic; }

/* Narrative */
.narrative-text { font-size: 13px; line-height: 1.7; color: var(--text-secondary); white-space: pre-wrap; }

/* Attack tree — expandable node rendering */
.attack-tree { font-size: 13px; }
.attack-tree > details > summary,
.attack-tree > .tree-leaf {
  margin-left: 0;
}
.attack-tree details {
  margin-left: 20px; border-left: 2px solid var(--border); padding-left: 14px;
  margin-bottom: 4px;
}
.attack-tree details > summary {
  cursor: pointer; padding: 8px 12px; list-style: none;
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.attack-tree details > summary::-webkit-details-marker { display: none; }
.attack-tree details > summary::before {
  content: '\\25B6'; font-size: 8px; color: var(--text-muted); transition: transform 0.2s;
}
.attack-tree details[open] > summary::before { transform: rotate(90deg); }
.attack-tree .tree-leaf {
  margin-left: 20px; border-left: 2px solid var(--border);
  padding: 8px 12px 8px 16px; margin-bottom: 4px;
  display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap;
}
.tree-node-label { color: var(--text-primary); }
.tree-node-details { font-size: 11px; color: var(--text-muted); margin-top: 4px; width: 100%; padding-left: 40px; }
.cat-badge {
  display: inline-flex; align-items: center; height: 20px; padding: 0 8px;
  border-radius: 4px; font-size: 10px; font-weight: 600;
}
.cat-badge.controller_side { background: rgba(59,130,246,0.2); color: #60a5fa; }
.cat-badge.path_side { background: rgba(34,197,94,0.2); color: #4ade80; }
.cat-badge.coordination_gap { background: rgba(249,115,22,0.2); color: #fb923c; }
.gate-badge {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 28px; height: 20px; padding: 0 6px; border-radius: 4px;
  font-size: 10px; font-weight: 700; font-family: monospace; margin-right: 6px;
}
.gate-or { background: rgba(59,130,246,0.2); color: #60a5fa; }
.gate-and { background: rgba(139,92,246,0.2); color: #a78bfa; }
.gate-leaf { background: rgba(107,114,128,0.2); color: #9ca3af; }
.cat-controller_side { border-left-color: var(--blue); }
.cat-path_side { border-left-color: var(--green); }
.cat-coordination_gap { border-left-color: var(--orange); }
.tree-empty { font-size: 13px; color: var(--text-muted); font-style: italic; padding: 12px; }

/* Gherkin behavior spec — structured step rendering */
.feature-spec { font-size: 13px; }
.gherkin-block {
  background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px; line-height: 1.6; overflow-x: auto;
}
.feature-step {
  padding: 10px 14px; border-radius: 6px; margin-bottom: 6px;
  display: flex; align-items: flex-start; gap: 10px; flex-wrap: wrap;
}
.step-keyword {
  font-weight: 700; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.3px; min-width: 60px; flex-shrink: 0;
}
.step-text { color: var(--text-primary); flex: 1; min-width: 200px; }
.step-given { background: rgba(59,130,246,0.08); border-left: 3px solid #3b82f6; }
.step-given .step-keyword { color: #3b82f6; }
.step-when { background: rgba(139,92,246,0.08); border-left: 3px solid #8b5cf6; }
.step-when .step-keyword { color: #8b5cf6; }
.step-then { background: rgba(34,197,94,0.08); border-left: 3px solid #22c55e; }
.step-then .step-keyword { color: #22c55e; }
.step-but { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; }
.step-but .step-keyword { color: #ef4444; }
.step-and { background: rgba(99,102,241,0.08); border-left: 3px solid #6366f1; }
.step-and .step-keyword { color: #6366f1; }
.step-star { background: rgba(245,158,11,0.08); border-left: 3px solid #f59e0b; }
.step-star .step-keyword { color: #f59e0b; }
.step-docstring { padding: 8px 14px; font-size: 12px; color: var(--text-muted); font-style: italic; white-space: pre-wrap; }
.gherkin-tag-line { padding: 4px 14px; font-size: 12px; color: #f59e0b; }
.gherkin-comment-line { padding: 4px 14px; font-size: 12px; color: #4b5563; font-style: italic; }

/* YAML highlighting */
.yaml-key { color: #60a5fa; }
.yaml-string { color: #a78bfa; }
.yaml-number { color: #f59e0b; }
.yaml-bool { color: #22c55e; }
.yaml-null { color: #6b7280; font-style: italic; }
.yaml-comment { color: #4b5563; font-style: italic; }
.code-block {
  background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px; font-family: monospace; font-size: 12px; line-height: 1.6;
  white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto;
}

/* Collapsible raw YAML */
details.raw-yaml > summary {
  cursor: pointer; font-size: 12px; font-weight: 600; color: var(--text-muted);
  padding: 6px 0; list-style: none;
}
details.raw-yaml > summary::-webkit-details-marker { display: none; }
details.raw-yaml > summary::before { content: '\\25B6 '; font-size: 8px; }
details.raw-yaml[open] > summary::before { content: '\\25BC '; }

/* Eval gauges */
.eval-gauge-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.eval-gauge-name { min-width: 180px; font-size: 12px; font-weight: 600; color: var(--text-secondary); }
.eval-gauge-track {
  flex: 1; height: 20px; background: var(--bg-primary); border-radius: 4px;
  overflow: hidden; max-width: 300px;
}
.eval-gauge-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.eval-gauge-fill.green { background: var(--green); }
.eval-gauge-fill.yellow { background: var(--yellow); }
.eval-gauge-fill.red { background: var(--red); }
.eval-gauge-pct { font-size: 12px; font-weight: 700; font-family: monospace; min-width: 40px; }
.scorecard-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
.scorecard-badge-green { background: rgba(34,197,94,0.12); color: #22c55e; border: 1px solid rgba(34,197,94,0.25); }
.scorecard-badge-yellow { background: rgba(245,158,11,0.12); color: #f59e0b; border: 1px solid rgba(245,158,11,0.25); }
.scorecard-badge-red { background: rgba(239,68,68,0.12); color: #ef4444; border: 1px solid rgba(239,68,68,0.25); }

/* LLM Call Inspector */
.call-entry {
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px;
  margin-bottom: 8px; overflow: hidden;
}
.call-entry.failed { border-left: 3px solid var(--red); }
.call-entry > summary {
  cursor: pointer; padding: 10px 14px; font-size: 13px; list-style: none;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.call-entry > summary::-webkit-details-marker { display: none; }
.call-entry > summary::before { content: '\\25B6'; font-size: 8px; color: var(--text-muted); transition: transform 0.2s; }
.call-entry[open] > summary::before { transform: rotate(90deg); }
.call-meta { font-size: 12px; color: var(--text-secondary); }
.call-meta-stage { font-family: monospace; font-weight: 600; color: var(--accent); }
.call-fail-indicator { color: var(--red); font-weight: 700; font-size: 11px; }
.call-success-indicator { color: var(--green); font-weight: 700; font-size: 11px; }
.call-entry-body { padding: 12px 14px; }
.call-summary-bar {
  display: flex; gap: 20px; flex-wrap: wrap; padding: 12px 16px;
  background: var(--bg-secondary); border-radius: 6px; margin-bottom: 12px;
}
.call-summary-stat { font-size: 13px; }
.call-summary-stat strong { font-size: 18px; font-weight: 800; color: var(--accent); }

/* Run manifest */
.manifest-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
.manifest-item { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; }
.manifest-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
.manifest-value { font-size: 14px; font-weight: 600; word-break: break-all; }

/* Sticky nav */
#sticky-nav {
  position: fixed; top: 20px; right: 20px; width: 140px;
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px; z-index: 100; opacity: 0; transition: opacity 0.3s;
}
#sticky-nav.visible { opacity: 1; }
#sticky-nav a {
  display: block; padding: 6px 10px; color: var(--text-secondary);
  text-decoration: none; font-size: 12px; font-weight: 500; border-radius: 4px;
}
#sticky-nav a:hover { background: var(--accent-glow); color: var(--text-primary); }

/* Coverage */
.coverage-rate { font-size: 20px; font-weight: 700; color: var(--accent); }

/* Copy button */
.copy-btn {
  padding: 4px 10px; background: var(--bg-card-hover); border: 1px solid var(--border);
  border-radius: 4px; color: var(--text-secondary); cursor: pointer; font-size: 11px;
}
.copy-btn:hover { background: var(--accent); color: white; }

/* Scenario tabs */
.scenario-tabs {
  display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 12px;
}
.scenario-tab {
  padding: 8px 16px; cursor: pointer; font-size: 12px; font-weight: 600;
  color: var(--text-muted); border: 1px solid transparent; border-bottom: none;
  border-radius: 6px 6px 0 0; background: transparent; transition: all 0.15s;
}
.scenario-tab:hover { color: var(--text-secondary); background: var(--bg-card-hover); }
.scenario-tab.active {
  color: var(--accent); border-color: var(--border); border-bottom: 1px solid var(--bg-card);
  background: var(--bg-card); position: relative; top: 1px;
}
.scenario-tab-content { display: none; }
.scenario-tab-content.active { display: block; }

/* Section spacing */
.flow-card.sp3-section { margin-bottom: 32px; }
</style>"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def _build_js() -> str:
    return """<script>
// Sticky nav visibility on scroll
window.addEventListener('scroll', function() {
  var nav = document.getElementById('sticky-nav');
  if (window.scrollY > 200) {
    nav.classList.add('visible');
  } else {
    nav.classList.remove('visible');
  }
});
// Copy to clipboard
document.querySelectorAll('.copy-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var target = document.getElementById(btn.getAttribute('data-target'));
    if (target) {
      navigator.clipboard.writeText(target.textContent).then(function() {
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      });
    }
  });
});
// Scenario tab switching
document.addEventListener('click', function(e) {
  if (e.target && e.target.classList.contains('scenario-tab')) {
    var tabBar = e.target.parentElement;
    var tabContainer = tabBar.parentElement;
    // Deactivate all tabs
    tabBar.querySelectorAll('.scenario-tab').forEach(function(t) { t.classList.remove('active'); });
    tabContainer.querySelectorAll('.scenario-tab-content').forEach(function(c) { c.classList.remove('active'); });
    // Activate clicked tab
    e.target.classList.add('active');
    var target = e.target.getAttribute('data-tab');
    var content = tabContainer.querySelector('[data-tab-content="' + target + '"]');
    if (content) content.classList.add('active');
  }
});
</script>"""


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_sticky_nav() -> str:
    """Build the sticky mini-navigation with links to major sections."""
    links = [
        ("SP1", "#sp1"),
        ("SP2", "#sp2"),
        ("SP3", "#sp3"),
        ("Calls", "#calls"),
        ("Manifest", "#manifest"),
    ]
    items = "\n".join(f'    <a href="{href}">{label}</a>' for label, href in links)
    return f'<nav id="sticky-nav" class="sticky-nav">\n{items}\n  </nav>'


def _build_hero_summary(
    run_id: str | None,
    created_at: str | None,
    scenario_count: int | None,
    eval_metrics: dict[str, float] | None,
) -> str:
    """Build the hero summary section."""
    run_id_html = _esc(run_id) if run_id else "N/A"
    ts_html = _esc(created_at) if created_at else "N/A"
    count_html = str(scenario_count) if scenario_count is not None else "N/A"

    metrics_html = ""
    if eval_metrics:
        metric_items = []
        for name, rate in eval_metrics.items():
            pct = f"{rate * 100:.0f}%"
            metric_items.append(
                f'    <div class="hero-metric">'
                f'<div class="hero-metric-name">{_esc(name)}</div>'
                f'<div class="hero-metric-value">{_esc(pct)}</div>'
                f"</div>"
            )
        metrics_html = (
            f'  <div class="hero-metrics">\n{chr(10).join(metric_items)}\n  </div>'
        )
    else:
        metrics_html = '  <div class="hero-metrics"><div class="hero-metric"><div class="hero-metric-name">Eval</div><div class="hero-metric-value">N/A</div></div></div>'

    return (
        f'<section id="hero" class="hero">\n'
        f"  <h1>STPA-Sec Report</h1>\n"
        f'  <div class="hero-meta">\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Run ID</div><div class="hero-stat-value">{run_id_html}</div></div>\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Timestamp</div><div class="hero-stat-value">{ts_html}</div></div>\n'
        f'    <div class="hero-stat"><div class="hero-stat-label">Scenarios</div><div class="hero-stat-value">{count_html}</div></div>\n'
        f"  </div>\n"
        f"{metrics_html}\n"
        f"</section>"
    )


def _build_raw_yaml_section(filename: str, raw_text: str) -> str:
    """Build a collapsible raw YAML section."""
    highlighted = _highlight_yaml(raw_text)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "-", filename)
    return (
        f'<details class="raw-yaml" data-filename="{_esc(filename)}">\n'
        f"  <summary>Raw YAML: {_esc(filename)}</summary>\n"
        f'  <div class="code-block" id="raw-{safe_id}">{highlighted}</div>\n'
        f"</details>"
    )


def _build_raw_yaml_sections(
    raw_texts: dict[str, str] | None,
    filenames: tuple[str, ...],
) -> list[str]:
    """Build raw YAML sections for the given filenames if present."""
    if not raw_texts:
        return []
    return [
        _build_raw_yaml_section(fname, raw_texts[fname])
        for fname in filenames
        if fname in raw_texts
    ]


def _build_table_rows(rows_data: list[tuple], cell_count: int) -> str:
    """Build ``<tr>`` elements from a list of tuples."""
    return "\n".join(
        "      <tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>"
        for row in rows_data
    )


def _build_data_table(
    headers: list[str],
    rows: str,
    table_id: str = "",
) -> str:
    """Build a complete ``<table class="data-table">`` element."""
    th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return (
        f'    <table class="data-table"><thead><tr>{th}</tr></thead>\n'
        f"    <tbody>\n{rows}\n    </tbody></table>"
    )


def _build_losses_table(losses: list[dict]) -> str:
    """Build the losses data table, or empty string if no losses."""
    if not losses:
        return ""
    rows = _build_table_rows(
        [
            (loss["id"], loss["description"], loss.get("provenance", ""))
            for loss in losses
        ],
        3,
    )
    return _build_data_table(["ID", "Description", "Provenance"], rows)


def _build_hazards_table(hazards: list) -> str:
    """Build the hazards data table, or empty string if no hazards."""
    if not hazards:
        return ""
    rows = _build_table_rows(
        [(h.hazard_id, h.description) for h in hazards],
        2,
    )
    return _build_data_table(["Hazard ID", "Description"], rows)


def _build_constraints_table(constraints: list) -> str:
    """Build the constraints data table, or empty string if no constraints."""
    if not constraints:
        return ""
    rows = _build_table_rows(
        [(sc.constraint_id, sc.description) for sc in constraints],
        2,
    )
    return _build_data_table(["Constraint ID", "Description"], rows)


def _build_sp1_losses_section(loss_analysis: Any) -> str:
    """Build the losses, hazards, and constraints subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Losses, Hazards & Constraints</div>')

    for table in (
        _build_losses_table(list(_loss_analysis_losses(loss_analysis))),
        _build_hazards_table(loss_analysis.hazards),
        _build_constraints_table(loss_analysis.security_constraints),
    ):
        if table:
            parts.append(table)

    parts.append("</div>")
    return "\n".join(parts)


def _build_sp1_capability_section(
    capability_profile: Any, kc_display: dict[str, str] | None = None
) -> str:
    """Build the capability profile subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Capability Profile</div>')
    zones = getattr(capability_profile, "zones_active", [])
    if zones:
        chips = " ".join(f'<span class="zone-chip">{_esc(z)}</span>' for z in zones)
        parts.append(f"    <div>{chips}</div>")
    kcs = getattr(capability_profile, "kc_subcodes", [])
    if kcs:
        parts.append('    <div class="kc-list" style="margin-top:12px;">')
        for kc in kcs:
            label = (kc_display or {}).get(kc, "")
            if label and label != kc:
                parts.append(
                    f'      <div class="kc-item" style="margin-bottom:4px;">'
                    f'<code style="color:var(--accent);font-weight:600;">{_esc(kc)}</code>'
                    f' — <span style="color:var(--text-secondary);font-size:12px;">{_esc(label)}</span>'
                    f"</div>"
                )
            else:
                parts.append(
                    f'      <div class="kc-item" style="margin-bottom:4px;">'
                    f'<code style="color:var(--accent);font-weight:600;">{_esc(kc)}</code>'
                    f"</div>"
                )
        parts.append("    </div>")
    parts.append("</div>")
    return "\n".join(parts)


def _build_sp1_control_section(control_structure: Any) -> str:
    """Build the control structure subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Control Structure</div>')
    if control_structure.responsibilities:
        rows = _build_table_rows(
            [(r.resp_id, r.description) for r in control_structure.responsibilities],
            2,
        )
        parts.append(_build_data_table(["Responsibility", "Description"], rows))
    parts.append("</div>")
    return "\n".join(parts)


def build_sp1_card(
    loss_analysis: Any | None,
    capability_profile: Any | None,
    control_structure: Any | None,
    raw_texts: dict[str, str] | None,
    kc_display: dict[str, str] | None = None,
) -> str:
    """Build the SP1 flow card."""
    body_parts: list[str] = []

    if loss_analysis is not None:
        body_parts.append(_build_sp1_losses_section(loss_analysis))

    if capability_profile is not None:
        body_parts.append(_build_sp1_capability_section(capability_profile, kc_display))

    if control_structure is not None:
        body_parts.append(_build_sp1_control_section(control_structure))

    body_parts.extend(
        _build_raw_yaml_sections(
            raw_texts,
            ("loss-analysis.yaml", "capability-profile.yaml", "control-structure.yaml"),
        )
    )

    body = "\n".join(body_parts)
    return (
        f'<details id="sp1" class="flow-card">\n'
        f"  <summary>SP1 — Loss Analysis & Control Structure</summary>\n"
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f"</details>"
    )


def _loss_to_dict(loss: Any) -> dict[str, str]:
    """Convert a loss model to a flat dict for rendering."""
    provenance = (
        loss.provenance.value
        if hasattr(loss.provenance, "value")
        else str(loss.provenance)
    )
    return {
        "id": loss.loss_id,
        "description": loss.description,
        "provenance": provenance,
    }


def _loss_analysis_losses(loss_analysis: Any) -> list[dict[str, str]]:
    """Extract all losses from a LossAnalysis as flat dicts."""
    result: list[dict[str, str]] = []
    for loss in getattr(loss_analysis, "risk_card_losses", []) or []:
        result.append(_loss_to_dict(loss))
    for loss in getattr(loss_analysis, "use_case_losses", []) or []:
        result.append(_loss_to_dict(loss))
    return result


def _build_sp2_ica_section(ica_enumeration: Any) -> str:
    """Build the ICA enumeration subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">ICA Enumeration</div>')
    if ica_enumeration.slots:
        rows = "\n".join(
            f"      <tr><td>{_esc(s.slot_id)}</td>"
            f"<td>{'N/A' if s.is_na else str(len(s.icas))}</td></tr>"
            for s in ica_enumeration.slots
        )
        parts.append(
            f'    <table class="data-table"><thead><tr><th>Slot ID</th><th>ICAs</th></tr></thead>\n'
            f"    <tbody>\n{rows}\n    </tbody></table>"
        )
    parts.append("</div>")
    return "\n".join(parts)


def _build_sp2_enrichment_section(enriched_threats: Any) -> str:
    """Build the catalog enrichment subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Catalog Enrichment</div>')
    if enriched_threats.structural_threats:
        rows: list[str] = []
        for t in enriched_threats.structural_threats:
            mappings = ", ".join(m.id for m in (t.catalog_mappings or []))
            rows.append(
                f"      <tr><td>{_esc(t.ica_slot_id)}</td><td>{_esc(mappings)}</td></tr>"
            )
        parts.append(
            f'    <table class="data-table"><thead><tr><th>ICA Slot</th><th>Catalog Mappings</th></tr></thead>\n'
            f"    <tbody>\n{chr(10).join(rows)}\n    </tbody></table>"
        )
    parts.append("</div>")
    return "\n".join(parts)


def _build_sp2_coverage_section(enriched_threats: Any) -> str:
    """Build the coverage analysis subsection of SP2."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Coverage Analysis</div>')
    cov = enriched_threats.coverage_analysis
    sc = getattr(cov, "structural_coverage", {}) or {}
    if isinstance(sc, dict):
        rate = sc.get("coverage_rate")
        if rate is not None:
            pct = f"{float(rate) * 100:.1f}%"
            parts.append(f'    <p class="coverage-rate">{_esc(pct)}</p>')
    parts.append("</div>")
    return "\n".join(parts)


def build_sp2_card(
    ica_enumeration: Any | None,
    enriched_threats: Any | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the SP2 flow card."""
    body_parts: list[str] = []

    if ica_enumeration is not None:
        body_parts.append(_build_sp2_ica_section(ica_enumeration))

    if enriched_threats is not None:
        body_parts.append(_build_sp2_enrichment_section(enriched_threats))
        body_parts.append(_build_sp2_coverage_section(enriched_threats))

    body_parts.extend(
        _build_raw_yaml_sections(
            raw_texts,
            ("ica-enumeration.yaml", "enriched-threats.yaml"),
        )
    )

    body = "\n".join(body_parts)
    return (
        f'<details id="sp2" class="flow-card">\n'
        f"  <summary>SP2 — ICA Enumeration & Threat Enrichment</summary>\n"
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f"</details>"
    )


def _parse_tree_dict(tree_dict: dict) -> tuple[str, list, list]:
    """Extract root, branches, and leaves from a tree dict."""
    root = tree_dict.get("root", "")
    branches = tree_dict.get("branches") or []
    leaves = tree_dict.get("leaves") or []
    return root, branches, leaves


def _has_tree_content(root: str, branches: list, leaves: list) -> bool:
    """Check if a parsed tree has any non-empty content."""
    return bool(root or branches or leaves)


def _build_attack_tree_visual(tree_dict: dict | None) -> str:
    """Build a visual attack tree using expandable details nodes.

    The tree dict has:
      - root: str (the root goal)
      - branches: list of {category, label, children: [...]}
      - leaves: list of str
    """
    if not tree_dict:
        return '<div class="tree-empty">No attack tree data available.</div>'

    root, branches, leaves = _parse_tree_dict(tree_dict)

    if not _has_tree_content(root, branches, leaves):
        return '<div class="tree-empty">No attack tree data available.</div>'

    parts: list[str] = ['<div class="attack-tree">']

    if root:
        parts.append(
            f"  <details open><summary>"
            f'<span class="gate-badge gate-or">&or;</span>'
            f'<span class="tree-node-label">{_esc(root)}</span>'
            f"</summary>"
        )

    for branch in branches:
        parts.extend(_build_tree_branch_node(branch))

    for leaf in leaves:
        parts.append(
            f'  <div class="tree-leaf">'
            f'<span class="gate-badge gate-leaf">&bull;</span>'
            f'<span class="tree-node-label">{_esc(leaf)}</span></div>'
        )

    if root:
        parts.append("  </details>")

    parts.append("</div>")
    return "\n".join(parts)


_CAT_DISPLAY = {
    "controller_side": "Controller",
    "path_side": "Path",
    "coordination_gap": "Coordination",
}


def _build_tree_branch_node(branch: dict) -> list[str]:
    """Build HTML for a single branch node with its children."""
    category = branch.get("category", "")
    label = branch.get("label", "")
    cat_display = _CAT_DISPLAY.get(category, category)
    parts: list[str] = [
        f"  <details open><summary>"
        f'<span class="gate-badge gate-and">&and;</span>'
        f'<span class="cat-badge {category}">{_esc(cat_display)}</span>'
        f'<span class="tree-node-label">{_esc(label)}</span>'
        f"</summary>"
    ]
    children = branch.get("children", []) or []
    for child in children:
        parts.extend(_render_tree_child(child))
    parts.append("  </details>")
    return parts


def _render_tree_child(child: dict) -> list[str]:
    """Recursively render a tree child node."""
    parts: list[str] = []
    label = child.get("label", "")
    details = child.get("details", "")
    children = child.get("children", []) or []

    if children:
        parts.append(
            f"  <details open><summary>"
            f'<span class="tree-node-label">{_esc(label)}</span>'
            f"</summary>"
        )
        for sub in children:
            parts.extend(_render_tree_child(sub))
        parts.append("  </details>")
    else:
        details_html = ""
        if details:
            details_html = f'<div class="tree-node-details">{_esc(details)}</div>'
        parts.append(
            f'  <div class="tree-leaf">'
            f'<span class="gate-badge gate-leaf">&bull;</span>'
            f'<span class="tree-node-label">{_esc(label)}</span>'
            f"{details_html}</div>"
        )
    return parts


def _attr_list(obj: Any, name: str) -> list:
    """Get a list attribute from an object, defaulting to empty list."""
    return getattr(obj, name, []) or []


def _build_defender_bdi_block(defender: Any) -> str:
    """Build the defender BDI block HTML."""
    parts: list[str] = ['          <div class="bdi-block">']
    parts.append("            <h4>Defender BDI</h4>")
    for b in _attr_list(defender, "beliefs"):
        parts.append(
            f'            <div class="bdi-item"><strong>{_esc(b.pm_id)}</strong>: {_esc(b.content)}</div>'
        )
        if hasattr(b, "vulnerability") and b.vulnerability:
            parts.append(
                f'            <div class="bdi-item-vuln">Vulnerability: {_esc(b.vulnerability)}</div>'
            )
    for d in _attr_list(defender, "desires"):
        parts.append(
            f'            <div class="bdi-item"><strong>Desire</strong> ({_esc(d.resp_id)}): {_esc(d.content)}</div>'
        )
    for i in _attr_list(defender, "intentions"):
        parts.append(
            f'            <div class="bdi-item"><strong>Intention</strong> ({_esc(i.ca_id)}): {_esc(i.content)}</div>'
        )
    parts.append("          </div>")
    return "\n".join(parts)


def _build_attacker_bdi_block(attacker: Any) -> str:
    """Build the attacker BDI block HTML."""
    parts: list[str] = ['          <div class="bdi-block">']
    parts.append("            <h4>Attacker BDI</h4>")
    for b in _attr_list(attacker, "beliefs"):
        parts.append(
            f'            <div class="bdi-item"><strong>Belief</strong>: {_esc(b)}</div>'
        )
    for d in _attr_list(attacker, "desires"):
        parts.append(
            f'            <div class="bdi-item"><strong>Desire</strong>: {_esc(d)}</div>'
        )
    for i in _attr_list(attacker, "intentions"):
        parts.append(
            f'            <div class="bdi-item"><strong>Intention</strong>: {_esc(i)}</div>'
        )
    parts.append("          </div>")
    return "\n".join(parts)


def _build_bdi_section(scenario_spec: Any) -> str:
    """Build the BDI section for a scenario."""
    parts: list[str] = ['      <div class="scenario-section">']
    parts.append('        <div class="scenario-section-title">BDI Models</div>')
    parts.append('        <div class="bdi-grid">')

    defender = getattr(scenario_spec, "defender_bdi", None)
    if defender:
        parts.append(_build_defender_bdi_block(defender))
    else:
        parts.append(
            '          <div class="bdi-block"><h4>Defender BDI</h4><p class="bdi-item">No data</p></div>'
        )

    attacker = getattr(scenario_spec, "attacker_bdi", None)
    if attacker:
        parts.append(_build_attacker_bdi_block(attacker))
    else:
        parts.append(
            '          <div class="bdi-block"><h4>Attacker BDI</h4><p class="bdi-item">No data</p></div>'
        )

    parts.append("        </div>")
    parts.append("      </div>")
    return "\n".join(parts)


def _build_system_context_section(ctx: Any) -> list[str]:
    """Build the System Context enrichment section HTML parts."""
    parts: list[str] = []
    parts.append('      <div class="scenario-section">')
    parts.append('        <div class="scenario-section-title">System Context</div>')
    parts.append('        <div class="metadata-grid">')

    resp_desc = getattr(ctx, "target_responsibility_description", "") or ""
    ca_desc = getattr(ctx, "target_control_action_description", "") or ""
    tool_inventory = getattr(ctx, "tool_inventory", []) or []
    active_zones = getattr(ctx, "active_zones", []) or []
    multi_agent = getattr(ctx, "multi_agent", False)
    has_persistent_memory = getattr(ctx, "has_persistent_memory", False)

    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Target Responsibility</span><span class="metadata-value">{_esc(resp_desc)}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Target Control Action</span><span class="metadata-value">{_esc(ca_desc)}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Tool Inventory</span><span class="metadata-value">{_esc(", ".join(tool_inventory))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Active Zones</span><span class="metadata-value">{_esc(", ".join(active_zones))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Multi-Agent</span><span class="metadata-value">{_esc(str(multi_agent))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Persistent Memory</span><span class="metadata-value">{_esc(str(has_persistent_memory))}</span></div>'
    )

    parts.append("        </div>")
    parts.append("      </div>")
    return parts


def _build_consumer_hints_section(hints: Any) -> list[str]:
    """Build the Consumer Hints enrichment section HTML parts."""
    parts: list[str] = []
    parts.append('      <div class="scenario-section">')
    parts.append('        <div class="scenario-section-title">Consumer Hints</div>')
    parts.append('        <div class="metadata-grid">')

    primary_attack_zone = getattr(hints, "primary_attack_zone", "") or ""
    requires_tool_execution = getattr(hints, "requires_tool_execution", False)
    requires_multi_turn = getattr(hints, "requires_multi_turn", False)
    requires_multi_agent = getattr(hints, "requires_multi_agent", False)
    requires_persistent_state = getattr(hints, "requires_persistent_state", False)
    garak_testability = getattr(hints, "garak_testability", "") or ""
    midojo_testability = getattr(hints, "midojo_testability", "") or ""

    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Primary Attack Zone</span><span class="metadata-value">{_esc(primary_attack_zone)}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Requires Tool Execution</span><span class="metadata-value">{_esc(str(requires_tool_execution))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Requires Multi-Turn</span><span class="metadata-value">{_esc(str(requires_multi_turn))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Requires Multi-Agent</span><span class="metadata-value">{_esc(str(requires_multi_agent))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Requires Persistent State</span><span class="metadata-value">{_esc(str(requires_persistent_state))}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Garak Testability</span><span class="metadata-value">{_esc(garak_testability)}</span></div>'
    )
    parts.append(
        f'          <div class="metadata-item"><span class="metadata-label">Midojo Testability</span><span class="metadata-value">{_esc(midojo_testability)}</span></div>'
    )

    parts.append("        </div>")
    parts.append("      </div>")
    return parts


def _build_scenario_envelope_body(envelope: Any) -> list[str]:
    """Build the HTML body parts from a scenario envelope's attributes."""
    parts: list[str] = []
    spec = getattr(envelope, "scenario_spec", None)

    # BDI section (always visible above tabs)
    if spec is not None:
        parts.append(_build_bdi_section(spec))

    # Collect tab content
    tab_contents: list[tuple[str, str]] = []  # (tab_id, html_content)

    # Narrative tab
    narrative = getattr(envelope, "narrative", "") or ""
    if narrative:
        tab_contents.append(
            ("narrative", f'<div class="narrative-text">{_esc(narrative)}</div>')
        )

    # Attack tree tab
    attack_tree = getattr(envelope, "attack_tree", None)
    tab_contents.append(("attack_tree", _build_attack_tree_visual(attack_tree)))

    # Gherkin tab — prefer the structured spec's rendered feature text
    # (guaranteed valid Gherkin syntax); gherkin_raw is the raw LLM
    # response (often YAML), used only when the spec failed to parse.
    gherkin_text = ""
    gs = getattr(envelope, "gherkin_spec", None)
    if gs is not None and hasattr(gs, "to_feature_text") and getattr(gs, "feature", ""):
        gherkin_text = gs.to_feature_text()
    if not gherkin_text:
        gherkin_text = getattr(envelope, "gherkin_raw", None) or ""
    if gherkin_text:
        highlighted = _highlight_gherkin(gherkin_text)
        tab_contents.append(
            ("gherkin", f'<div class="gherkin-block">{highlighted}</div>')
        )

    # Build tab bar + content panels
    if tab_contents:
        tab_labels = {
            "narrative": "Narrative",
            "attack_tree": "Attack Tree",
            "gherkin": "Gherkin",
        }
        parts.append('      <div class="scenario-tabs-container">')
        parts.append('        <div class="scenario-tabs">')
        for i, (tab_id, _) in enumerate(tab_contents):
            active = " active" if i == 0 else ""
            parts.append(
                f'          <div class="scenario-tab{active}" data-tab="{tab_id}">{tab_labels.get(tab_id, tab_id)}</div>'
            )
        parts.append("        </div>")
        for i, (tab_id, content_html) in enumerate(tab_contents):
            active = " active" if i == 0 else ""
            parts.append(
                f'        <div class="scenario-tab-content{active}" data-tab-content="{tab_id}">{content_html}</div>'
            )
        parts.append("      </div>")

    # System Context section (enrichment, below tabs)
    system_context = getattr(envelope, "system_context", None)
    if system_context is not None:
        parts.extend(_build_system_context_section(system_context))

    # Consumer Hints section (enrichment, below tabs)
    consumer_hints = getattr(envelope, "consumer_hints", None)
    if consumer_hints is not None:
        parts.extend(_build_consumer_hints_section(consumer_hints))

    return parts


def _build_scenario_card(
    scenario_id: str,
    envelope: Any | None,
    feature_text: str | None,
) -> str:
    """Build a collapsible scenario card."""
    body_parts: list[str] = []

    if envelope is not None:
        body_parts.extend(_build_scenario_envelope_body(envelope))

    # If feature_text is provided separately (from .feature file on disk),
    # and the envelope didn't already include Gherkin in tabs, add it.
    if feature_text:
        has_gherkin_in_tabs = False
        if envelope is not None:
            has_gherkin_in_tabs = bool(
                getattr(envelope, "gherkin_raw", None)
                or (
                    hasattr(envelope, "gherkin_spec")
                    and envelope.gherkin_spec is not None
                )
            )
        if not has_gherkin_in_tabs:
            highlighted = _highlight_gherkin(feature_text)
            body_parts.append('      <div class="scenario-section">')
            body_parts.append(
                '        <div class="scenario-section-title">Gherkin Spec</div>'
            )
            body_parts.append(f'        <div class="gherkin-block">{highlighted}</div>')
            body_parts.append("      </div>")

    body = "\n".join(body_parts)
    return (
        f'    <details class="scenario-card" data-scenario-id="{_esc(scenario_id)}">\n'
        f"      <summary><span>{_esc(scenario_id)}</span></summary>\n"
        f'      <div class="scenario-card-body">\n{body}\n      </div>\n'
        f"    </details>"
    )


def _rate_field_values(metric_data: dict) -> list:
    """Extract all ``*_rate`` field values from a metric dict."""
    return [v for k, v in metric_data.items() if k.endswith("_rate")]


def _safe_floats(values: list) -> list[float]:
    """Convert values to floats, dropping any that fail."""
    return [r for r in (_safe_float(v) for v in values) if r is not None]


def _average_rate_fields(metric_data: dict) -> float | None:
    """Average all ``*_rate`` fields in a metric dict."""
    rate_fields = _rate_field_values(metric_data)
    if not rate_fields:
        return None
    floats = _safe_floats(rate_fields)
    if not floats:
        return None
    return sum(floats) / len(floats)


def extract_metric_rate(metric_data: dict) -> float | None:
    """Extract a single rate from a metric dict.

    Looks for 'rate' first, then averages all '*_rate' fields.
    """
    if not isinstance(metric_data, dict):
        return None
    if "rate" in metric_data:
        return _safe_float(metric_data["rate"])
    return _average_rate_fields(metric_data)


def _safe_float(val: Any) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _gauge_color(rate: float) -> str:
    """Return the gauge color class for a rate."""
    if rate >= 0.8:
        return "green"
    if rate >= 0.6:
        return "yellow"
    return "red"


def _build_eval_gauge(metric_name: str, rate: float) -> str:
    """Build a colored gauge/bar for a single metric."""
    color = _gauge_color(rate)
    pct = rate * 100
    pct_str = f"{pct:.0f}%"
    return (
        f'  <div class="eval-gauge-row" data-metric="{_esc(metric_name)}">\n'
        f'    <div class="eval-gauge-name">{_esc(metric_name)}</div>\n'
        f'    <div class="eval-gauge-track"><div class="eval-gauge-fill {color}" style="width:{pct_str}"></div></div>\n'
        f'    <div class="eval-gauge-pct">{pct_str}</div>\n'
        f'    <span class="scorecard-badge scorecard-badge-{color}">{color.upper()}</span>\n'
        f"  </div>"
    )


def _build_eval_scorecard(eval_data: dict | None) -> str:
    """Build the eval scorecard section with gauges."""
    if not eval_data:
        return '<div class="tree-empty">No eval scorecard available.</div>'

    metrics = eval_data.get("metrics", eval_data)
    if not isinstance(metrics, dict):
        return '<div class="tree-empty">No eval scorecard available.</div>'

    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Eval Scorecard</div>')
    for name, data in metrics.items():
        rate = extract_metric_rate(data)
        if rate is not None:
            parts.append(_build_eval_gauge(name, rate))
    parts.append("</div>")
    return "\n".join(parts)


def build_sp3_card(
    scenarios: list[tuple[str, Any, str | None]],
    eval_data: dict | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the SP3 flow card with scenario list and eval scorecard.

    Args:
        scenarios: List of (scenario_id, envelope, feature_text) tuples.
        eval_data: Parsed eval-scorecard dict.
        raw_texts: Raw YAML texts for collapsible sections.
    """
    body_parts: list[str] = []

    # Scenario list
    body_parts.append('<div class="subsection">')
    body_parts.append(
        f'  <div class="subsection-title">Scenarios ({len(scenarios)})</div>'
    )
    for scenario_id, envelope, feature_text in scenarios:
        body_parts.append(_build_scenario_card(scenario_id, envelope, feature_text))
    body_parts.append("</div>")

    # Eval scorecard
    body_parts.append(_build_eval_scorecard(eval_data))

    # Raw YAML for eval scorecard
    if raw_texts and "eval-scorecard.yaml" in raw_texts:
        body_parts.append(
            _build_raw_yaml_section(
                "eval-scorecard.yaml", raw_texts["eval-scorecard.yaml"]
            )
        )

    body = "\n".join(body_parts)
    return (
        f'<details id="sp3" class="flow-card sp3-section">\n'
        f"  <summary>SP3 — Scenario Production & Evaluation</summary>\n"
        f'  <div class="flow-card-body">\n{body}\n  </div>\n'
        f"</details>"
    )


def build_llm_call_inspector(calls: list[dict]) -> str:
    """Build the LLM call inspector section.

    Collapsible list of calls, no search. Each call expandable to show
    system prompt, user prompt, and response content.
    """
    total = len(calls)
    success = sum(1 for c in calls if c.get("success", True))
    failed = total - success

    parts: list[str] = ['<section id="calls" class="flow-card">']
    parts.append("  <summary>Calls</summary>")
    parts.append('  <div class="flow-card-body">')

    # Summary
    parts.append('    <div class="call-summary-bar">')
    parts.append(
        f'      <div class="call-summary-stat">Total: <strong>{total}</strong></div>'
    )
    parts.append(
        f'      <div class="call-summary-stat">Successful: <strong>{success}</strong></div>'
    )
    parts.append(
        f'      <div class="call-summary-stat">Failed: <strong>{failed}</strong></div>'
    )
    parts.append("    </div>")

    # Call entries
    for i, entry in enumerate(calls):
        parts.append(_build_call_entry_html(entry, i))

    parts.append("  </div>")
    parts.append("</section>")
    return "\n".join(parts)


def _build_call_entry_html(entry: dict, index: int) -> str:
    """Build a single collapsible call entry."""
    success = entry.get("success", True)
    stage = entry.get("stage", "")
    step = entry.get("step", "")
    model = entry.get("model", "")
    prompt_tokens = entry.get("prompt_tokens", 0)
    completion_tokens = entry.get("completion_tokens", 0)
    duration_ms = entry.get("duration_ms", 0)

    css_class = "call-entry failed" if not success else "call-entry"
    indicator = (
        '<span class="call-fail-indicator">FAILED</span>'
        if not success
        else '<span class="call-success-indicator">OK</span>'
    )

    # Collapsible sections for prompts and response
    sections: list[str] = []
    for label, key in (
        ("system_prompt", "system_prompt_text"),
        ("user_prompt", "user_prompt_text"),
        ("response_content", "response_content"),
    ):
        content = entry.get(key, "")
        if content:
            display = _pretty_print_if_json(content)
            sections.append(
                f'      <details class="raw-yaml"><summary>{_esc(label)}</summary>'
                f'<pre class="code-block">{display}</pre></details>'
            )

    sections_html = "\n".join(sections)
    return (
        f'    <details class="{css_class}" data-call-index="{index}">\n'
        f"      <summary>"
        f'<span class="call-meta-stage">{_esc(stage)}/{_esc(step)}</span>'
        f'<span class="call-meta">model={_esc(model)}</span>'
        f'<span class="call-meta">tokens={prompt_tokens}+{completion_tokens}</span>'
        f'<span class="call-meta">duration={duration_ms}ms</span>'
        f"{indicator}"
        f"</summary>\n"
        f'      <div class="call-entry-body">\n{sections_html}\n      </div>\n'
        f"    </details>"
    )


def _build_manifest_grid(
    run_id: Any, created_at: Any, model_name: Any, max_workers: Any
) -> str:
    """Build the manifest metadata grid."""
    return (
        '    <div class="manifest-grid">\n'
        f'      <div class="manifest-item"><div class="manifest-label">Run ID</div><div class="manifest-value">{_esc(str(run_id))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Created At</div><div class="manifest-value">{_esc(str(created_at))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Model</div><div class="manifest-value">{_esc(str(model_name))}</div></div>\n'
        f'      <div class="manifest-item"><div class="manifest-label">Max Workers</div><div class="manifest-value">{_esc(str(max_workers))}</div></div>\n'
        "    </div>"
    )


def _build_manifest_hashes_table(input_hashes: dict) -> str:
    """Build the input hashes table for the manifest section."""
    rows = "\n".join(
        f"        <tr><td>{_esc(str(name))}</td><td>{_esc(str(hash_val))}</td></tr>"
        for name, hash_val in input_hashes.items()
    )
    return (
        '    <div class="subsection">\n'
        '      <div class="subsection-title">Input Hashes</div>\n'
        '      <table class="data-table"><thead><tr><th>Artifact</th><th>Hash</th></tr></thead><tbody>\n'
        f"{rows}\n"
        "      </tbody></table>\n"
        "    </div>"
    )


def _resolve_model_name(manifest: dict) -> str:
    """Extract the model name from manifest model_config."""
    model_config = manifest.get("model_config", {}) or {}
    if isinstance(model_config, dict):
        return model_config.get("model", "N/A")
    return "N/A"


def _is_valid_hashes(input_hashes: Any) -> bool:
    """Check if input_hashes is a non-empty dict."""
    return bool(input_hashes and isinstance(input_hashes, dict))


def build_run_manifest(
    manifest: dict | None,
    raw_texts: dict[str, str] | None,
) -> str:
    """Build the run manifest section."""
    if not manifest:
        return '<section id="manifest" class="flow-card"><summary>Manifest</summary><div class="flow-card-body"><div class="tree-empty">No run manifest available.</div></div></section>'

    run_id = manifest.get("run_id", "N/A")
    created_at = manifest.get("created_at", "N/A")
    model_name = _resolve_model_name(manifest)
    max_workers = manifest.get("max_workers", "N/A")
    input_hashes = manifest.get("input_hashes", {}) or {}

    parts: list[str] = ['<section id="manifest" class="flow-card">']
    parts.append("  <summary>Manifest</summary>")
    parts.append('  <div class="flow-card-body">')
    parts.append(_build_manifest_grid(run_id, created_at, model_name, max_workers))

    if _is_valid_hashes(input_hashes):
        parts.append(_build_manifest_hashes_table(input_hashes))

    if raw_texts and "run-manifest.yaml" in raw_texts:
        parts.append(
            _build_raw_yaml_section("run-manifest.yaml", raw_texts["run-manifest.yaml"])
        )

    parts.append("  </div>")
    parts.append("</section>")
    return "\n".join(parts)


def _build_produces_arrow() -> str:
    """Build a produces arrow between flow cards."""
    return '<div class="produces-arrow" data-arrow="produces">&darr; produces</div>'


# ---------------------------------------------------------------------------
# Top-level assembler
# ---------------------------------------------------------------------------


def build_html(
    *,
    run_id: str | None = None,
    created_at: str | None = None,
    scenario_count: int | None = None,
    eval_metrics: dict[str, float] | None = None,
    sp1_html: str = "",
    sp2_html: str = "",
    sp3_html: str = "",
    calls_html: str = "",
    manifest_html: str = "",
    has_sp2: bool = True,
    has_sp3: bool = True,
) -> str:
    """Assemble all sections into a single self-contained HTML document."""
    hero = _build_hero_summary(run_id, created_at, scenario_count, eval_metrics)
    nav = _build_sticky_nav()

    sections: list[str] = [hero]

    # SP1 card
    sections.append(sp1_html)

    # SP1 → SP2 arrow + SP2 card
    if has_sp2 and sp2_html:
        sections.append(_build_produces_arrow())
        sections.append(sp2_html)

    # SP2 → SP3 arrow + SP3 card
    if has_sp3 and sp3_html:
        sections.append(_build_produces_arrow())
        sections.append(sp3_html)

    # Calls
    if calls_html:
        sections.append(calls_html)

    # Manifest
    sections.append(manifest_html)

    body = "\n".join(sections)
    css = _build_css()
    js = _build_js()

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>STPA-Sec Report</title>\n"
        f"{css}\n"
        "</head>\n"
        "<body>\n"
        f"{nav}\n"
        f'<div class="container">\n'
        f"{body}\n"
        f"</div>\n"
        f"{js}\n"
        "</body>\n"
        "</html>\n"
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T15:26:20Z","module_hash":"dc8b7fda106b959c606e7ff6637cb74c62ce4dc378e3257e86fb464dc122dc1c","functions":[{"id":"func/_esc","name":"_esc","line":40,"end_line":44,"hash":"89f3305e0e261839254081b13828a912588ad461ecb42e00259273287ba5384c"},{"id":"func/_highlight_yaml","name":"_highlight_yaml","line":47,"end_line":70,"hash":"b5663db782fb27bc050ba90311cd2cb25eb15ea97f93ff24d7fe168a287e5129"},{"id":"func/_is_quoted_string","name":"_is_quoted_string","line":73,"end_line":77,"hash":"5df5edbe94e4af26fb3582c9953526bcacd997866001dde7114326a923e76d2c"},{"id":"func/_yaml_value_class","name":"_yaml_value_class","line":80,"end_line":90,"hash":"1ccf18ac9ace062ae375a9a1a6da90a47c26449632fafe5bfacae56c2dd6a353"},{"id":"func/_highlight_yaml_value","name":"_highlight_yaml_value","line":93,"end_line":100,"hash":"6e88e41b54f2cd27563790a686d8cfd01326f63253dd28ec1eb8dad5e77e3dd7"},{"id":"func/_apply_gherkin_keyword_highlight","name":"_apply_gherkin_keyword_highlight","line":117,"end_line":129,"hash":"5d1e96c912a6119ad1829cd757212b7c23f770598f108432d32273210c328b88"},{"id":"func/_highlight_gherkin","name":"_highlight_gherkin","line":132,"end_line":155,"hash":"12ccc10e2fa98f2830e82b0edaa4236c94924b93d7f1b92acb34bdac63165c36"},{"id":"func/_gherkin_keyword_class","name":"_gherkin_keyword_class","line":158,"end_line":173,"hash":"5aaeaf64ec3bbcebeaa6083e88c9f406ad85e881456c5d3c842215f967dc646d"},{"id":"func/_build_css","name":"_build_css","line":181,"end_line":456,"hash":"1130ece99db9490acbd1db63ff3695e630ce816abcbadeb4648f17b627050e36"},{"id":"func/_build_js","name":"_build_js","line":464,"end_line":487,"hash":"5d98617200950dbd7db573acdf483e751e75694cc06848b0a2cf87dce90dd3a2"},{"id":"func/_build_sticky_nav","name":"_build_sticky_nav","line":495,"end_line":507,"hash":"709d8e28026d8203a29e3b823c9f6edda55d9d64b73de8c722099198b5fcc15e"},{"id":"func/_build_hero_summary","name":"_build_hero_summary","line":510,"end_line":546,"hash":"5c3206edffc1b9d8e330f5349de574c56d5ae23276c2be4b88f516d1fda26f39"},{"id":"func/_build_raw_yaml_section","name":"_build_raw_yaml_section","line":549,"end_line":558,"hash":"718da545110766fb610c7fdefaa1528706c79a6c2bf5e31be85f5159c8261110"},{"id":"func/_build_raw_yaml_sections","name":"_build_raw_yaml_sections","line":561,"end_line":571,"hash":"03e7a7384c7466378186e721d703fe43c090656d170ea42e757e2abed3f9a8de"},{"id":"func/_build_table_rows","name":"_build_table_rows","line":574,"end_line":579,"hash":"fe73ea95aa6d9c8153dc30ef58094d54f5d0616d83286a54273426d2c4c9d763"},{"id":"func/_build_data_table","name":"_build_data_table","line":582,"end_line":590,"hash":"0b4fbac3ae11bf6f43ee8bf5f683eea9e9ea04f975e67e72c0aeba074a40ae49"},{"id":"func/_build_losses_table","name":"_build_losses_table","line":593,"end_line":600,"hash":"04b8a53468df13cecf6cd12e1ddbc20f7c4e8db0b91f4755e927872374e47b26"},{"id":"func/_build_hazards_table","name":"_build_hazards_table","line":603,"end_line":610,"hash":"8e1831f0707955796db965612e1bdfc5c8a057eb6ac4f286c820526baeda55b4"},{"id":"func/_build_constraints_table","name":"_build_constraints_table","line":613,"end_line":620,"hash":"929d3e2eafa4e5b16378f018289386735a704934ce3ec169de32348515ae4521"},{"id":"func/_build_sp1_losses_section","name":"_build_sp1_losses_section","line":623,"end_line":637,"hash":"14867ef4374cd17aede264d1da596274480e36400d62251b4957fed2538f143b"},{"id":"func/_build_sp1_capability_section","name":"_build_sp1_capability_section","line":640,"end_line":655,"hash":"0227d7fd71d6bdef5ac619fc0ed488fffe98a062c4669966d0f794372ea55362"},{"id":"func/_build_sp1_control_section","name":"_build_sp1_control_section","line":658,"end_line":669,"hash":"1a11b550be2dd36e43d6b9f574ae8bb748b75c3b7626a45aa66b8f3dabb06969"},{"id":"func/build_sp1_card","name":"build_sp1_card","line":672,"end_line":701,"hash":"193829e4432e1678c177406c5d8b53fcb61b3f6143880845cebcdc5a84accd2a"},{"id":"func/_loss_to_dict","name":"_loss_to_dict","line":704,"end_line":713,"hash":"1999ae1438a3e9149c645588e8f6298c61beeb503dc02298676a71d50baf53d1"},{"id":"func/_loss_analysis_losses","name":"_loss_analysis_losses","line":716,"end_line":723,"hash":"019e7cab104a8c1070bb24241d2b6d3bdf5f930be663fb11d76a835c3fb627d4"},{"id":"func/_build_sp2_ica_section","name":"_build_sp2_ica_section","line":726,"end_line":741,"hash":"63d74939a0b5901f9b3eae7c885778674ccb9f258a929d013d49761d36f06731"},{"id":"func/_build_sp2_enrichment_section","name":"_build_sp2_enrichment_section","line":744,"end_line":758,"hash":"140d05f81dca089e440e1e360ee1e4865d835f2d3ab5e151105b299535e35ea7"},{"id":"func/_build_sp2_coverage_section","name":"_build_sp2_coverage_section","line":761,"end_line":773,"hash":"ca5bab3828de0f263883c3aafdf4f80e0e98c6b60e638179557931decf61a7bb"},{"id":"func/build_sp2_card","name":"build_sp2_card","line":776,"end_line":802,"hash":"a6d7ae8917fbeb31d404f88f26a4e39d84fe1e533336bb5f99991c6601c48093"},{"id":"func/_parse_tree_dict","name":"_parse_tree_dict","line":805,"end_line":810,"hash":"45e7595492eefa665c066ccc3ff042547dfc762b00b2e1dbdd59cdfeca0ed94b"},{"id":"func/_has_tree_content","name":"_has_tree_content","line":813,"end_line":815,"hash":"8a4672f74b4a22ad77fae2c289b77d24fbe953d69e7a1a16018bc89ed1df049b"},{"id":"func/_build_attack_tree_visual","name":"_build_attack_tree_visual","line":818,"end_line":854,"hash":"3d2b489ced29d177f286a5919dd68eba493a16f3cc8aa0356df8a882d9744442"},{"id":"func/_build_tree_branch_node","name":"_build_tree_branch_node","line":857,"end_line":872,"hash":"a2fe30d88efbe819032dd00eb1ca537edb7458204a06e02526c87d2296dec493"},{"id":"func/_render_tree_child","name":"_render_tree_child","line":875,"end_line":899,"hash":"f0a64c941171e4ec5bc9f40592c840502d820a2269ebd5d9c8bdc0cfa55e2efd"},{"id":"func/_attr_list","name":"_attr_list","line":902,"end_line":904,"hash":"36542a6e0976fdc143d98995b78dafa36eaf7bab486b8fe0d1cf6b2532388841"},{"id":"func/_build_defender_bdi_block","name":"_build_defender_bdi_block","line":907,"end_line":920,"hash":"c37bf751f898eaec74ec4778fa04a4239d90d9222674f199ecfdd7f22113ca80"},{"id":"func/_build_attacker_bdi_block","name":"_build_attacker_bdi_block","line":923,"end_line":934,"hash":"bf40c072fa30a85bb5935972ca81023cc286d11ed3763875fccdad4cf4762f6d"},{"id":"func/_build_bdi_section","name":"_build_bdi_section","line":937,"end_line":957,"hash":"568e6f81c40749bd01b27e82bfdaf4369d4903c8a35158b194edbcb5e27becdc"},{"id":"func/_build_system_context_section","name":"_build_system_context_section","line":960,"end_line":983,"hash":"e8798efd3d8d0ecb53cbc377e5baa9fd1d4dea9a4ec5653f47cee43c8b142c56"},{"id":"func/_build_consumer_hints_section","name":"_build_consumer_hints_section","line":986,"end_line":1011,"hash":"c8b51618123c697f461a3c883883d7fd1c3ecace93ca6343fd15a02165ea3aec"},{"id":"func/_build_scenario_envelope_body","name":"_build_scenario_envelope_body","line":1014,"end_line":1048,"hash":"14d207345ac77796e53d0887bfc4f6ff6ab2557d61dbad885095f8a0141446cd"},{"id":"func/_build_scenario_card","name":"_build_scenario_card","line":1051,"end_line":1084,"hash":"c4d00a8394287ca4c2d9333e7f3a86de81d7481c03f6ad66cb3aa2efb96c7d62"},{"id":"func/_rate_field_values","name":"_rate_field_values","line":1087,"end_line":1089,"hash":"d3ab9243cf2a705a7d046734e03f11dd440ab7363a09568b2744fbb759b78fc5"},{"id":"func/_safe_floats","name":"_safe_floats","line":1092,"end_line":1094,"hash":"ed6aa2972b0e52740ce4b35779392425e7ac13c9abd0fc1f9a997db6516b66f8"},{"id":"func/_average_rate_fields","name":"_average_rate_fields","line":1097,"end_line":1105,"hash":"a4f25d78a91a70483e2ad6c2622cdf6493862dc0f0663a6a5b8aed5c86293620"},{"id":"func/extract_metric_rate","name":"extract_metric_rate","line":1108,"end_line":1117,"hash":"5af0c886e4c30a1f8fcb4a41fc3df4ad5f5fb50a24ffcb45267ae0f73179a260"},{"id":"func/_safe_float","name":"_safe_float","line":1120,"end_line":1124,"hash":"22308d2541cf3256d477270074020e62b7b7c8591eadcc6e14c9039f654bc991"},{"id":"func/_gauge_color","name":"_gauge_color","line":1127,"end_line":1133,"hash":"ed6902603c6956c97b5f035b1e9508bd9a13f8854823c20601e1ef3a20992094"},{"id":"func/_build_eval_gauge","name":"_build_eval_gauge","line":1136,"end_line":1148,"hash":"ec1c3a398d21928f5e9919135d008e66de71c8d8d3425107b4ddbd6404c21d6f"},{"id":"func/_build_eval_scorecard","name":"_build_eval_scorecard","line":1151,"end_line":1167,"hash":"9e4003ce06938fed8c741b58d7e8e930c15eeff82e0957fc5b8093e650176852"},{"id":"func/build_sp3_card","name":"build_sp3_card","line":1170,"end_line":1204,"hash":"a896ec2f8f5bdae48634884ff1e9ef99cb3d1385af80bfcbb39b720c89dd6aee"},{"id":"func/build_llm_call_inspector","name":"build_llm_call_inspector","line":1207,"end_line":1234,"hash":"986b31f3f25d39dd7252887836e16b8dcc016bf794939e7257a9d0c0cdae0342"},{"id":"func/_build_call_entry_html","name":"_build_call_entry_html","line":1237,"end_line":1280,"hash":"2e6d411187d05a8e91cdbabaa50a79c8c0c265dd525819655d232f63f6646b89"},{"id":"func/_build_manifest_grid","name":"_build_manifest_grid","line":1283,"end_line":1292,"hash":"d1245764f3a92a3f1d36c4f297868d8562d79202b08a5b5ac4521c95fa42ade9"},{"id":"func/_build_manifest_hashes_table","name":"_build_manifest_hashes_table","line":1295,"end_line":1308,"hash":"0be64dbf0f62f7665279fe8bfccf927dc2ccd94ac4a413812767004cdb9ae2a3"},{"id":"func/_resolve_model_name","name":"_resolve_model_name","line":1311,"end_line":1316,"hash":"9443d6aba2ac7a48f850274f4bdc5f0248c2e6ca09652442ceeba7fc658dbdeb"},{"id":"func/_is_valid_hashes","name":"_is_valid_hashes","line":1319,"end_line":1321,"hash":"0bed58d7a17cd97873af407a9edcce64949b8a2ef6f3504e7cb7af77a392399e"},{"id":"func/build_run_manifest","name":"build_run_manifest","line":1324,"end_line":1351,"hash":"14c0bd8ff89e0cd4d7f38c0fb6b5002f563dbbefcf852168796a855459291a79"},{"id":"func/_build_produces_arrow","name":"_build_produces_arrow","line":1354,"end_line":1356,"hash":"f8fcf2efc935a684d43f2e0f3139fd30db9690114904d640eec8ef17be9ef42a"},{"id":"func/build_html","name":"build_html","line":1364,"end_line":1425,"hash":"32b32bc3bf61462fa80bc5ff26220a13d06606bd4cd3d58b17cd1f2e8c2e0311"}]}
# mutate4py-manifest-end
