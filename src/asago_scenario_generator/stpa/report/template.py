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


_GHERKIN_ROW_KEYWORDS: list[tuple[str, str]] = [
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
]

_GHERKIN_HEADER_KEYWORDS = frozenset(
    {"Feature", "Background", "Scenario", "Scenario Outline"}
)


def _docstring_opening(stripped: str) -> list[str] | None:
    """The first collected docstring line, or None when the line opens none."""
    if not stripped.startswith('"""'):
        return None
    remainder = stripped[3:]
    return [remainder] if remainder else []


def _docstring_row_html(stripped: str, docstring_lines: list[str]) -> str:
    """The closing docstring row for a completed Gherkin docstring."""
    remainder = stripped[:-3]
    if remainder:
        docstring_lines.append(remainder)
    ds_text = "\n".join(docstring_lines).strip()
    return f'<div class="step-docstring">"""\n{_esc(ds_text)}\n"""</div>'


def _gherkin_decorative_row(stripped: str) -> str | None:
    """HTML for tag or comment rows, or None for other lines."""
    if stripped.startswith("@"):
        return f'<div class="gherkin-tag-line">{_esc(stripped)}</div>'
    if stripped.startswith("#"):
        return f'<div class="gherkin-comment-line">{_esc(stripped)}</div>'
    return None


def _gherkin_keyword_row(stripped: str) -> tuple[str, str, str] | None:
    """Extract (keyword, step_text, step_class) for a keyword line, or None."""
    for kw, cls in _GHERKIN_ROW_KEYWORDS:
        if stripped.startswith(kw):
            return kw.strip().rstrip(":"), stripped[len(kw) :].strip(), cls
    return None


def _gherkin_header_row(keyword: str, step_text: str) -> str:
    """HTML for a section-header Gherkin line."""
    return (
        '<div style="padding:10px 0 6px;font-size:14px;font-weight:700;color:var(--text-primary);">'
        f'<span style="color:var(--accent);">{_esc(keyword)}:</span> {_esc(step_text)}</div>'
    )


def _gherkin_step_row(keyword: str, step_text: str, step_class: str) -> str:
    """HTML for a feature-step Gherkin line."""
    return (
        f'<div class="feature-step {step_class}">'
        f'<span class="step-keyword">{_esc(keyword)}</span> '
        f'<span class="step-text">{_esc(step_text)}</span>'
        f"</div>"
    )


def _gherkin_plain_row(stripped: str) -> str:
    """HTML for a Gherkin line without a recognized keyword."""
    return (
        '<div style="padding:4px 14px 4px 70px;font-size:13px;color:var(--text-secondary);">'
        f"{_esc(stripped)}</div>"
    )


def _gherkin_row_html(stripped: str) -> str | None:
    """Render one non-docstring Gherkin line, or None when the line is skipped."""
    if not stripped:
        return None
    decorative = _gherkin_decorative_row(stripped)
    if decorative is not None:
        return decorative
    keyword_row = _gherkin_keyword_row(stripped)
    if keyword_row is not None:
        keyword, step_text, step_class = keyword_row
        if keyword in _GHERKIN_HEADER_KEYWORDS:
            return _gherkin_header_row(keyword, step_text)
        return _gherkin_step_row(keyword, step_text, step_class)
    return _gherkin_plain_row(stripped)


def _advance_docstring_state(
    stripped: str,
    in_docstring: bool,
    docstring_lines: list[str],
    result: list[str],
) -> tuple[bool, list[str]]:
    """Consume one line against the docstring state, returning the new state."""
    if in_docstring:
        if stripped.endswith('"""'):
            result.append(_docstring_row_html(stripped, docstring_lines))
            return False, []
        docstring_lines.append(stripped)
        return True, docstring_lines
    opening = _docstring_opening(stripped)
    if opening is not None:
        return True, opening
    row = _gherkin_row_html(stripped)
    if row is not None:
        result.append(row)
    return False, []


def _highlight_gherkin(text: str) -> str:
    """Render Gherkin as structured HTML with styled step rows.

    Parses Gherkin text line-by-line and produces flexbox step rows
    with colored keyword labels (matching the non-STPA report style).
    """
    if not text:
        return ""
    result: list[str] = []
    in_docstring = False
    docstring_lines: list[str] = []

    for line in text.strip().split("\n"):
        stripped = line.strip()
        in_docstring, docstring_lines = _advance_docstring_state(
            stripped, in_docstring, docstring_lines, result
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


def _build_table_rows(rows_data: list[tuple]) -> str:
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
        ]
    )
    return _build_data_table(["ID", "Description", "Provenance"], rows)


def _build_hazards_table(hazards: list) -> str:
    """Build the hazards data table, or empty string if no hazards."""
    if not hazards:
        return ""
    rows = _build_table_rows([(h.hazard_id, h.description) for h in hazards])
    return _build_data_table(["Hazard ID", "Description"], rows)


def _build_constraints_table(constraints: list) -> str:
    """Build the constraints data table, or empty string if no constraints."""
    if not constraints:
        return ""
    rows = _build_table_rows([(sc.constraint_id, sc.description) for sc in constraints])
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


def _kc_item_html(kc: str, label: str) -> str:
    """One capability key-code row with its display label."""
    if label and label != kc:
        return (
            f'      <div class="kc-item" style="margin-bottom:4px;">'
            f'<code style="color:var(--accent);font-weight:600;">{_esc(kc)}</code>'
            f' — <span style="color:var(--text-secondary);font-size:12px;">{_esc(label)}</span>'
            f"</div>"
        )
    return (
        f'      <div class="kc-item" style="margin-bottom:4px;">'
        f'<code style="color:var(--accent);font-weight:600;">{_esc(kc)}</code>'
        f"</div>"
    )


def _kc_item_rows(kcs: list, kc_display: dict[str, str] | None) -> list[str]:
    """The capability key-code item rows."""
    return [_kc_item_html(kc, (kc_display or {}).get(kc, "")) for kc in kcs]


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
        parts.extend(_kc_item_rows(kcs, kc_display))
        parts.append("    </div>")
    parts.append("</div>")
    return "\n".join(parts)


def _build_sp1_control_section(control_structure: Any) -> str:
    """Build the control structure subsection of SP1."""
    parts: list[str] = ['<div class="subsection">']
    parts.append('  <div class="subsection-title">Control Structure</div>')
    if control_structure.responsibilities:
        rows = _build_table_rows(
            [(r.resp_id, r.description) for r in control_structure.responsibilities]
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


_EMPTY_TREE_HTML = '<div class="tree-empty">No attack tree data available.</div>'


def _tree_root_markup(root: str) -> tuple[str, str]:
    """(opening, closing) details markup for the expandable tree root."""
    return (
        "  <details open><summary>"
        f'<span class="gate-badge gate-or">&or;</span>'
        f'<span class="tree-node-label">{_esc(root)}</span>'
        f"</summary>",
        "  </details>",
    )


def _tree_leaf_markup(leaf: str) -> str:
    """One flat leaf row of the attack tree."""
    return (
        '  <div class="tree-leaf">'
        f'<span class="gate-badge gate-leaf">&bull;</span>'
        f'<span class="tree-node-label">{_esc(leaf)}</span></div>'
    )


def _tree_branch_rows(branches: list) -> list[str]:
    """HTML rows for every branch node, in order."""
    rows: list[str] = []
    for branch in branches:
        rows.extend(_build_tree_branch_node(branch))
    return rows


def _tree_leaf_rows(leaves: list) -> list[str]:
    """HTML rows for every flat leaf, in order."""
    return [_tree_leaf_markup(leaf) for leaf in leaves]


def _build_attack_tree_visual(tree_dict: dict | None) -> str:
    """Build a visual attack tree using expandable details nodes.

    The tree dict has:
      - root: str (the root goal)
      - branches: list of {category, label, children: [...]}
      - leaves: list of str
    """
    if not tree_dict:
        return _EMPTY_TREE_HTML

    root, branches, leaves = _parse_tree_dict(tree_dict)

    if not _has_tree_content(root, branches, leaves):
        return _EMPTY_TREE_HTML

    parts: list[str] = ['<div class="attack-tree">']

    if root:
        root_open, root_close = _tree_root_markup(root)
        parts.append(root_open)

    parts.extend(_tree_branch_rows(branches))
    parts.extend(_tree_leaf_rows(leaves))

    if root:
        parts.append(root_close)

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


_SCENARIO_TAB_LABELS: dict[str, str] = {
    "narrative": "Narrative",
    "attack_tree": "Attack Tree",
    "gherkin": "Gherkin",
}


def _tab_active(index: int) -> str:
    """The active CSS class for the first tab."""
    return " active" if index == 0 else ""


def _build_tab_bar(
    tab_contents: list[tuple[str, str]], labels: dict[str, str]
) -> list[str]:
    """The scenario tab bar rows."""
    rows: list[str] = []
    for i, (tab_id, _) in enumerate(tab_contents):
        rows.append(
            f'          <div class="scenario-tab{_tab_active(i)}" data-tab="{tab_id}">{labels.get(tab_id, tab_id)}</div>'
        )
    return rows


def _build_tab_panels(tab_contents: list[tuple[str, str]]) -> list[str]:
    """The scenario tab content panel rows."""
    rows: list[str] = []
    for i, (tab_id, content_html) in enumerate(tab_contents):
        rows.append(
            f'        <div class="scenario-tab-content{_tab_active(i)}" data-tab-content="{tab_id}">{content_html}</div>'
        )
    return rows


def _envelope_gherkin_text(envelope: Any) -> str:
    """The envelope's canonical Gherkin text, falling back to the raw response."""
    gs = getattr(envelope, "gherkin_spec", None)
    if gs is not None and hasattr(gs, "to_feature_text") and getattr(gs, "feature", ""):
        return gs.to_feature_text()
    return getattr(envelope, "gherkin_raw", None) or ""


def _scenario_tab_contents(envelope: Any) -> list[tuple[str, str]]:
    """Collect (tab_id, html) pairs in display order for one envelope."""
    tab_contents: list[tuple[str, str]] = []

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
    gherkin_text = _envelope_gherkin_text(envelope)
    if gherkin_text:
        highlighted = _highlight_gherkin(gherkin_text)
        tab_contents.append(
            ("gherkin", f'<div class="gherkin-block">{highlighted}</div>')
        )
    return tab_contents


def _build_scenario_envelope_body(envelope: Any) -> list[str]:
    """Build the HTML body parts from a scenario envelope's attributes."""
    parts: list[str] = []
    spec = getattr(envelope, "scenario_spec", None)

    # BDI section (always visible above tabs)
    if spec is not None:
        parts.append(_build_bdi_section(spec))

    # Collect tab content
    tab_contents = _scenario_tab_contents(envelope)

    # Build tab bar + content panels
    if tab_contents:
        parts.append('      <div class="scenario-tabs-container">')
        parts.append('        <div class="scenario-tabs">')
        parts.extend(_build_tab_bar(tab_contents, _SCENARIO_TAB_LABELS))
        parts.append("        </div>")
        parts.extend(_build_tab_panels(tab_contents))
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


def _envelope_has_gherkin(envelope: Any | None) -> bool:
    """Whether the envelope already carries Gherkin content in its tabs."""
    if envelope is None:
        return False
    return bool(
        getattr(envelope, "gherkin_raw", None)
        or (hasattr(envelope, "gherkin_spec") and envelope.gherkin_spec is not None)
    )


def _feature_text_section(feature_text: str) -> list[str]:
    """The standalone Gherkin Spec section rows for a scenario card."""
    highlighted = _highlight_gherkin(feature_text)
    return [
        '      <div class="scenario-section">',
        '        <div class="scenario-section-title">Gherkin Spec</div>',
        f'        <div class="gherkin-block">{highlighted}</div>',
        "      </div>",
    ]


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
    if feature_text and not _envelope_has_gherkin(envelope):
        body_parts.extend(_feature_text_section(feature_text))

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
# {"version":1,"tested_at":"2026-08-26T11:34:32Z","module_hash":"913022ff346f2fa50cbdaa138f8bc2f4a9627b4ac93877484013a3ec31205363","source_sha256":"12a2ccd2f27d3a608f258c075a98d1621beccac77e5aea0e332404845bc91186","functions":[{"id":"func/_esc","name":"_esc","line":36,"end_line":38,"hash":"d37ba6c20d2b01d1e7150eb0a4212cc9ab6762ced235556faebc461ef42bfc9c"},{"id":"func/_highlight_yaml","name":"_highlight_yaml","line":46,"end_line":69,"hash":"b5663db782fb27bc050ba90311cd2cb25eb15ea97f93ff24d7fe168a287e5129"},{"id":"func/_is_quoted_string","name":"_is_quoted_string","line":72,"end_line":76,"hash":"5df5edbe94e4af26fb3582c9953526bcacd997866001dde7114326a923e76d2c"},{"id":"func/_yaml_value_class","name":"_yaml_value_class","line":79,"end_line":89,"hash":"1ccf18ac9ace062ae375a9a1a6da90a47c26449632fafe5bfacae56c2dd6a353"},{"id":"func/_highlight_yaml_value","name":"_highlight_yaml_value","line":92,"end_line":99,"hash":"6e88e41b54f2cd27563790a686d8cfd01326f63253dd28ec1eb8dad5e77e3dd7"},{"id":"func/_pretty_print_if_json","name":"_pretty_print_if_json","line":102,"end_line":114,"hash":"7e2386acba92b58edfb89b220fc74d1d647fd13146d8b2f748974392de17adec"},{"id":"func/_apply_gherkin_keyword_highlight","name":"_apply_gherkin_keyword_highlight","line":131,"end_line":143,"hash":"5d1e96c912a6119ad1829cd757212b7c23f770598f108432d32273210c328b88"},{"id":"func/_docstring_opening","name":"_docstring_opening","line":164,"end_line":169,"hash":"d11a4f58bceec5745bc40672d93dba3797f44f5f3e7d1e9f7469e28fcc9492f0"},{"id":"func/_docstring_row_html","name":"_docstring_row_html","line":172,"end_line":178,"hash":"f95eec7ab2990e4148dadfa4936f9e44046cd509192d3062e31725303ce43365"},{"id":"func/_gherkin_decorative_row","name":"_gherkin_decorative_row","line":181,"end_line":187,"hash":"5ff6ac8c9b02ccb21b48fc0c0b32ca42e77a450187dc60ac935158c1e93c4b40"},{"id":"func/_gherkin_keyword_row","name":"_gherkin_keyword_row","line":190,"end_line":195,"hash":"fbacf7d5d5a920c2be6a8fdfc2d828b9c1509e552c68fc58280713f05f198958"},{"id":"func/_gherkin_header_row","name":"_gherkin_header_row","line":198,"end_line":203,"hash":"b32a9ba9f0c4d030e86557d6f21f3e7a0b54dc7074b6c0cbf2df45fbfcb9ef4b"},{"id":"func/_gherkin_step_row","name":"_gherkin_step_row","line":206,"end_line":213,"hash":"d885f2746847a59078033cabdd0a69fa2a894cf81db585a8cc47c54212d5afce"},{"id":"func/_gherkin_plain_row","name":"_gherkin_plain_row","line":216,"end_line":221,"hash":"08d2a83894834512fb5aab98dc884d24630dcdd88948625307d57568f4da1a48"},{"id":"func/_gherkin_row_html","name":"_gherkin_row_html","line":224,"end_line":237,"hash":"401cc23e23ee76f6df039fe92da8f58ae5935ee11a3e388f5062f01cc8cd5089"},{"id":"func/_advance_docstring_state","name":"_advance_docstring_state","line":240,"end_line":259,"hash":"83d010a1fba7389b5f67b31c83b2455035207b8cef8a30682bfde5429507f4bb"},{"id":"func/_highlight_gherkin","name":"_highlight_gherkin","line":262,"end_line":280,"hash":"ac2426dab3cf272eb3481420af585fce36941762f65132dbf5b7f094c07b7b3d"},{"id":"func/_gherkin_keyword_class","name":"_gherkin_keyword_class","line":283,"end_line":298,"hash":"5aaeaf64ec3bbcebeaa6083e88c9f406ad85e881456c5d3c842215f967dc646d"},{"id":"func/_build_css","name":"_build_css","line":306,"end_line":637,"hash":"d289afdf53b4e263a4155c391a9c006612083b22d34c72da2d93f17cfeb2ba20"},{"id":"func/_build_js","name":"_build_js","line":645,"end_line":683,"hash":"f4357fa70c40555b0acddf6cdea481427dc24b43bb70e0deef09745ca38a502d"},{"id":"func/_build_sticky_nav","name":"_build_sticky_nav","line":691,"end_line":701,"hash":"709d8e28026d8203a29e3b823c9f6edda55d9d64b73de8c722099198b5fcc15e"},{"id":"func/_build_hero_summary","name":"_build_hero_summary","line":704,"end_line":742,"hash":"5c3206edffc1b9d8e330f5349de574c56d5ae23276c2be4b88f516d1fda26f39"},{"id":"func/_build_raw_yaml_section","name":"_build_raw_yaml_section","line":745,"end_line":754,"hash":"718da545110766fb610c7fdefaa1528706c79a6c2bf5e31be85f5159c8261110"},{"id":"func/_build_raw_yaml_sections","name":"_build_raw_yaml_sections","line":757,"end_line":768,"hash":"03e7a7384c7466378186e721d703fe43c090656d170ea42e757e2abed3f9a8de"},{"id":"func/_build_table_rows","name":"_build_table_rows","line":771,"end_line":776,"hash":"c985f5612b1be6f232229900a6a467731b33e0f633cacd471d7a421d4d234151"},{"id":"func/_build_data_table","name":"_build_data_table","line":779,"end_line":789,"hash":"0b4fbac3ae11bf6f43ee8bf5f683eea9e9ea04f975e67e72c0aeba074a40ae49"},{"id":"func/_build_losses_table","name":"_build_losses_table","line":792,"end_line":802,"hash":"77627366739a7aa24154ebcfa8f78ac6561e95ea26e6154951c13699963d16b5"},{"id":"func/_build_hazards_table","name":"_build_hazards_table","line":805,"end_line":810,"hash":"8e8f1dee8514b6b455f05aa24e9821ee4442e0b223c2ebf96c58a87b21db3254"},{"id":"func/_build_constraints_table","name":"_build_constraints_table","line":813,"end_line":818,"hash":"a9e1d267c5246bde8e1239e8d07054cea07956369892d56e02be5b1716ecb718"},{"id":"func/_build_sp1_losses_section","name":"_build_sp1_losses_section","line":821,"end_line":835,"hash":"14867ef4374cd17aede264d1da596274480e36400d62251b4957fed2538f143b"},{"id":"func/_kc_item_html","name":"_kc_item_html","line":838,"end_line":851,"hash":"860fe8dc00c8c8ec3af98682f0c199d372be1e49ea82368698e7954d6ca31523"},{"id":"func/_kc_item_rows","name":"_kc_item_rows","line":854,"end_line":856,"hash":"9fe448004907966552dbe07bb50ca00db48d912c903cfa2ad6859298190aac33"},{"id":"func/_build_sp1_capability_section","name":"_build_sp1_capability_section","line":859,"end_line":875,"hash":"ce6f68b7f10563e197dd89c03479fcfc7028ba0c069cee28289bfd05bfffa86b"},{"id":"func/_build_sp1_control_section","name":"_build_sp1_control_section","line":878,"end_line":888,"hash":"0419b87badf6eeca30dbd348d803f5033047e7cc29b38bd8682d6c4556918da8"},{"id":"func/build_sp1_card","name":"build_sp1_card","line":891,"end_line":923,"hash":"0772939b72b8bf9922a3ec1cad92ced13e0b757d450e8e0d6da65899f3e72511"},{"id":"func/_loss_to_dict","name":"_loss_to_dict","line":926,"end_line":937,"hash":"1999ae1438a3e9149c645588e8f6298c61beeb503dc02298676a71d50baf53d1"},{"id":"func/_loss_analysis_losses","name":"_loss_analysis_losses","line":940,"end_line":947,"hash":"019e7cab104a8c1070bb24241d2b6d3bdf5f930be663fb11d76a835c3fb627d4"},{"id":"func/_build_sp2_ica_section","name":"_build_sp2_ica_section","line":950,"end_line":965,"hash":"3b0ad1f25ac674def3fcc8492f95ff67bd279f804fb982a811bad94887f3e290"},{"id":"func/_build_sp2_enrichment_section","name":"_build_sp2_enrichment_section","line":968,"end_line":984,"hash":"140d05f81dca089e440e1e360ee1e4865d835f2d3ab5e151105b299535e35ea7"},{"id":"func/_build_sp2_coverage_section","name":"_build_sp2_coverage_section","line":987,"end_line":999,"hash":"ca5bab3828de0f263883c3aafdf4f80e0e98c6b60e638179557931decf61a7bb"},{"id":"func/build_sp2_card","name":"build_sp2_card","line":1002,"end_line":1030,"hash":"a6d7ae8917fbeb31d404f88f26a4e39d84fe1e533336bb5f99991c6601c48093"},{"id":"func/_parse_tree_dict","name":"_parse_tree_dict","line":1033,"end_line":1038,"hash":"45e7595492eefa665c066ccc3ff042547dfc762b00b2e1dbdd59cdfeca0ed94b"},{"id":"func/_has_tree_content","name":"_has_tree_content","line":1041,"end_line":1043,"hash":"8a4672f74b4a22ad77fae2c289b77d24fbe953d69e7a1a16018bc89ed1df049b"},{"id":"func/_tree_root_markup","name":"_tree_root_markup","line":1049,"end_line":1057,"hash":"94fdf3d5259578c0107252216e14dc30c1793dcbd29eebda7bfaac8c883b6b31"},{"id":"func/_tree_leaf_markup","name":"_tree_leaf_markup","line":1060,"end_line":1066,"hash":"8f663545352ab5b2028f0d2a90b3a8eadd96464afc50dc77797d60c52548929b"},{"id":"func/_tree_branch_rows","name":"_tree_branch_rows","line":1069,"end_line":1074,"hash":"243f4b0ad36b3b4efd43fe889e3e02cad2b7da501c072a59662e61aa85922ae2"},{"id":"func/_tree_leaf_rows","name":"_tree_leaf_rows","line":1077,"end_line":1079,"hash":"764e01b82d2a177ab1ddfabd6c5f278b6eec112c948ff26290cf7452efca6fa3"},{"id":"func/_build_attack_tree_visual","name":"_build_attack_tree_visual","line":1082,"end_line":1111,"hash":"a7a98a812af3cadb27b4f8d1b11717c6dd428a2e4839beed794ee5ee19989160"},{"id":"func/_build_tree_branch_node","name":"_build_tree_branch_node","line":1121,"end_line":1137,"hash":"265898e20f9c36cf9f760663aeb9271eddded9d30c2ec7d66b6ea1ee4c096fd3"},{"id":"func/_render_tree_child","name":"_render_tree_child","line":1140,"end_line":1166,"hash":"ecb3919a2bc6f28e70a44812eefe16fa49622998df85fdfc7e966e015c2728a1"},{"id":"func/_attr_list","name":"_attr_list","line":1169,"end_line":1171,"hash":"36542a6e0976fdc143d98995b78dafa36eaf7bab486b8fe0d1cf6b2532388841"},{"id":"func/_build_defender_bdi_block","name":"_build_defender_bdi_block","line":1174,"end_line":1195,"hash":"c37bf751f898eaec74ec4778fa04a4239d90d9222674f199ecfdd7f22113ca80"},{"id":"func/_build_attacker_bdi_block","name":"_build_attacker_bdi_block","line":1198,"end_line":1215,"hash":"bf40c072fa30a85bb5935972ca81023cc286d11ed3763875fccdad4cf4762f6d"},{"id":"func/_build_bdi_section","name":"_build_bdi_section","line":1218,"end_line":1242,"hash":"568e6f81c40749bd01b27e82bfdaf4369d4903c8a35158b194edbcb5e27becdc"},{"id":"func/_build_system_context_section","name":"_build_system_context_section","line":1245,"end_line":1280,"hash":"e8798efd3d8d0ecb53cbc377e5baa9fd1d4dea9a4ec5653f47cee43c8b142c56"},{"id":"func/_build_consumer_hints_section","name":"_build_consumer_hints_section","line":1283,"end_line":1322,"hash":"c8b51618123c697f461a3c883883d7fd1c3ecace93ca6343fd15a02165ea3aec"},{"id":"func/_tab_active","name":"_tab_active","line":1332,"end_line":1334,"hash":"5de4191b65b521f05d35c0a987eaddc588e1f945d8652fc781555145ff58ebbb"},{"id":"func/_build_tab_bar","name":"_build_tab_bar","line":1337,"end_line":1346,"hash":"02d8ea9369b362af6bdb2d2613a3e9e93bd22f7bf6a4619025b06b99462e5fc8"},{"id":"func/_build_tab_panels","name":"_build_tab_panels","line":1349,"end_line":1356,"hash":"d4431da8c6a0b4593fb9feab2227d5e3072702644613b9188fbe159e3faf95cb"},{"id":"func/_envelope_gherkin_text","name":"_envelope_gherkin_text","line":1359,"end_line":1364,"hash":"55f9dbb4552d46ed30f041e9dbabf8b1f9ff051165b9adf65f96bdf914ce2cd3"},{"id":"func/_scenario_tab_contents","name":"_scenario_tab_contents","line":1367,"end_line":1391,"hash":"3cdec59c5fb83f933dc8dab83dec12be31f07ceaa8451553512c2d303c580c15"},{"id":"func/_build_scenario_envelope_body","name":"_build_scenario_envelope_body","line":1394,"end_line":1425,"hash":"b0a3f60447bc69bd12c9dbe4739d9837b1b668cbfeb1f6846f1dfe8e2518bebf"},{"id":"func/_envelope_has_gherkin","name":"_envelope_has_gherkin","line":1428,"end_line":1435,"hash":"eeb62ffa366acefbd328a78e428a154015f8fe491f4640bbadd4892ea3dc6208"},{"id":"func/_feature_text_section","name":"_feature_text_section","line":1438,"end_line":1446,"hash":"90d207d3f714219439332936d4ad968cdfedd94e0d96c3155c2d4d2c68f32864"},{"id":"func/_build_scenario_card","name":"_build_scenario_card","line":1449,"end_line":1471,"hash":"0daf1771e65f990040f6f835daf9f4505e5fec1efa4a21acc9584d225904ead5"},{"id":"func/_rate_field_values","name":"_rate_field_values","line":1474,"end_line":1476,"hash":"d3ab9243cf2a705a7d046734e03f11dd440ab7363a09568b2744fbb759b78fc5"},{"id":"func/_safe_floats","name":"_safe_floats","line":1479,"end_line":1481,"hash":"ed6aa2972b0e52740ce4b35779392425e7ac13c9abd0fc1f9a997db6516b66f8"},{"id":"func/_average_rate_fields","name":"_average_rate_fields","line":1484,"end_line":1492,"hash":"a4f25d78a91a70483e2ad6c2622cdf6493862dc0f0663a6a5b8aed5c86293620"},{"id":"func/extract_metric_rate","name":"extract_metric_rate","line":1495,"end_line":1504,"hash":"5af0c886e4c30a1f8fcb4a41fc3df4ad5f5fb50a24ffcb45267ae0f73179a260"},{"id":"func/_safe_float","name":"_safe_float","line":1507,"end_line":1511,"hash":"22308d2541cf3256d477270074020e62b7b7c8591eadcc6e14c9039f654bc991"},{"id":"func/_gauge_color","name":"_gauge_color","line":1514,"end_line":1520,"hash":"ed6902603c6956c97b5f035b1e9508bd9a13f8854823c20601e1ef3a20992094"},{"id":"func/_build_eval_gauge","name":"_build_eval_gauge","line":1523,"end_line":1535,"hash":"ec1c3a398d21928f5e9919135d008e66de71c8d8d3425107b4ddbd6404c21d6f"},{"id":"func/_build_eval_scorecard","name":"_build_eval_scorecard","line":1538,"end_line":1554,"hash":"9e4003ce06938fed8c741b58d7e8e930c15eeff82e0957fc5b8093e650176852"},{"id":"func/build_sp3_card","name":"build_sp3_card","line":1557,"end_line":1597,"hash":"65f8a774bf71054cb2a9c24345c9b768812e0ffb2c6e745c4186da6f4a0c0819"},{"id":"func/build_llm_call_inspector","name":"build_llm_call_inspector","line":1600,"end_line":1633,"hash":"986b31f3f25d39dd7252887836e16b8dcc016bf794939e7257a9d0c0cdae0342"},{"id":"func/_build_call_entry_html","name":"_build_call_entry_html","line":1636,"end_line":1680,"hash":"c476900fa166854ad921bd7240de4ac00637ec0aded19cee8f57227ebb239f34"},{"id":"func/_build_manifest_grid","name":"_build_manifest_grid","line":1683,"end_line":1694,"hash":"d1245764f3a92a3f1d36c4f297868d8562d79202b08a5b5ac4521c95fa42ade9"},{"id":"func/_build_manifest_hashes_table","name":"_build_manifest_hashes_table","line":1697,"end_line":1710,"hash":"0be64dbf0f62f7665279fe8bfccf927dc2ccd94ac4a413812767004cdb9ae2a3"},{"id":"func/_resolve_model_name","name":"_resolve_model_name","line":1713,"end_line":1718,"hash":"9443d6aba2ac7a48f850274f4bdc5f0248c2e6ca09652442ceeba7fc658dbdeb"},{"id":"func/_is_valid_hashes","name":"_is_valid_hashes","line":1721,"end_line":1723,"hash":"0bed58d7a17cd97873af407a9edcce64949b8a2ef6f3504e7cb7af77a392399e"},{"id":"func/build_run_manifest","name":"build_run_manifest","line":1726,"end_line":1755,"hash":"14c0bd8ff89e0cd4d7f38c0fb6b5002f563dbbefcf852168796a855459291a79"},{"id":"func/_build_produces_arrow","name":"_build_produces_arrow","line":1758,"end_line":1760,"hash":"f8fcf2efc935a684d43f2e0f3139fd30db9690114904d640eec8ef17be9ef42a"},{"id":"func/build_html","name":"build_html","line":1768,"end_line":1829,"hash":"32b32bc3bf61462fa80bc5ff26220a13d06606bd4cd3d58b17cd1f2e8c2e0311"}]}
# mutate4py-manifest-end
