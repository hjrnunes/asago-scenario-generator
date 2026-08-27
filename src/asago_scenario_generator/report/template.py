"""HTML template components for the asago-scenario-generator report.

CSS styles, JavaScript interactivity, and HTML section builders.
Each section builder is a function returning an HTML string.

The heavy section builders live in the ``sections_*`` modules; this module
re-exports them for callers that import from ``report.template`` and keeps
the static shell (CSS, JavaScript, glossary, and full-page assembly).
"""

from __future__ import annotations

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import THREAT_NAMES

from asago_scenario_generator.report.scenario_common import (
    _CALL_DISPLAY_NAMES,  # noqa: F401
    _SIGNAL_COLORS,  # noqa: F401
    _SIGNAL_NUMERIC,  # noqa: F401
    _SIGNAL_TOOLTIPS,  # noqa: F401
    _USAGE_METRIC_FIELDS,  # noqa: F401
    _hex_to_rgb_css,  # noqa: F401
    _is_valid_usage_metric,  # noqa: F401
    _priority_color,  # noqa: F401
    _priority_label,  # noqa: F401
    _usage_call_label,  # noqa: F401
    _usage_failure_suffix,  # noqa: F401
    _usage_metrics,  # noqa: F401
    _usage_summary,  # noqa: F401
    _usage_totals,  # noqa: F401
    _usage_warning_html,  # noqa: F401
)

from asago_scenario_generator.report.sections_scenarios import (
    build_scenarios_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_scenario_cards import (
    _build_priority_signals,  # noqa: F401
    _build_scenario_card,  # noqa: F401
)

from asago_scenario_generator.report.sections_attack_tree import (
    _GATE_TOOLTIPS,  # noqa: F401
    _STRUCTURAL_EXPOSURE_TOOLTIPS,  # noqa: F401
    _build_attack_tree_node,  # noqa: F401
)

from asago_scenario_generator.report.sections_behavior_spec import (
    _build_behavior_spec,  # noqa: F401
)

from asago_scenario_generator.report.sections_profile_block import (
    _CAPABILITY_COLORS,  # noqa: F401
    _CAPABILITY_TOOLTIPS,  # noqa: F401
    _build_actor_profile_block,  # noqa: F401
    _build_complexity_assessment_block,  # noqa: F401
)

from asago_scenario_generator.report.sections_generation_inputs import (
    _build_generation_inputs_block,  # noqa: F401
)

from asago_scenario_generator.report.sections_atlas import (
    _build_atlas_techniques_block,  # noqa: F401
    _collect_used_technique_ids,  # noqa: F401
)

from asago_scenario_generator.report.sections_pipeline_calls import (
    _build_pipeline_call_item,  # noqa: F401
    _semantic_stage_status_html,  # noqa: F401
    build_pipeline_calls_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_threats import (
    _node_tip,  # noqa: F401
    build_threat_surface_section,  # noqa: F401
    _build_sankey_svg,  # noqa: F401
    _sankey_link,  # noqa: F401
)

from asago_scenario_generator.report.sections_coverage import (
    _coverage_status,  # noqa: F401
    _GAP_REASON_LABELS,  # noqa: F401
    _attribution_span,  # noqa: F401
    build_coverage_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_techniques import (
    build_threat_technique_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_diversity import (
    _DIVERSITY_COLORS,  # noqa: F401
    build_attacker_diversity_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_profile import (
    _build_kc_descriptions,  # noqa: F401
    _kc_category,  # noqa: F401
    _corpus_applicability_label,  # noqa: F401
    build_capability_profile_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_summary import (
    build_run_summary_section,  # noqa: F401
)

from asago_scenario_generator.report.sections_raw import (
    build_raw_data_section,  # noqa: F401
    _highlight_yaml,  # noqa: F401
    _highlight_yaml_value,  # noqa: F401
    _highlight_gherkin,  # noqa: F401
)


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


def _nav_link(href: str, icon: str, label: str, present: str) -> str:
    """Return a sidebar navigation link, or empty when the section is absent."""
    if not present:
        return ""
    return f'<a href="{href}"><span class="nav-icon">{icon}</span> {label}</a>'


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
    run_summary_nav = _nav_link(
        "#sec-run-summary", "&#9654;", "Run Summary", run_summary_html
    )
    methodology_nav = _nav_link(
        "#sec-methodology", "&#9881;", "Methodology", methodology_html
    )
    use_case_nav = _nav_link("#sec-use-case", "&#9673;", "Use Case", use_case_html)
    coverage_nav = _nav_link(
        "#sec-coverage", "&#9635;", "Coverage Analysis", coverage_html
    )
    diversity_nav = _nav_link(
        "#sec-diversity", "&#9783;", "Actor Profiles", diversity_html
    )
    scorecard_nav = _nav_link(
        "#sec-scorecard", "&#9745;", "Eval Scorecard", scorecard_html
    )
    threat_technique_nav = _nav_link(
        "#sec-threat-matrix",
        "&#9638;",
        "Threat–Technique Matrix",
        threat_technique_html,
    )
    pipeline_calls_nav = _nav_link(
        "#sec-pipeline-calls", "&#9998;", "Pipeline LLM Calls", pipeline_calls_html
    )

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
