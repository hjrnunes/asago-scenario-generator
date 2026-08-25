"""Scenario card rendering and its per-card quality badges."""

from __future__ import annotations

import json
import re
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    ZONE_BG_COLORS,
    ZONE_COLORS,
    ZONE_DISPLAY_NAMES,
    _build_provenance_chain,
    _build_seed_metadata_block,
    _normalize_zone,
)
from asago_scenario_generator.report.scenario_common import (
    _CALL_DISPLAY_NAMES,
    _SIGNAL_TOOLTIPS,
    _hex_to_rgb_css,
    _priority_color,
    _priority_label,
    _usage_call_label,
    _usage_failure_suffix,
    _usage_metrics,
    _usage_summary,
    _usage_warning_html,
)
from asago_scenario_generator.report.sections_attack_tree import _build_attack_tree_node
from asago_scenario_generator.report.sections_atlas import _build_atlas_techniques_block
from asago_scenario_generator.report.sections_behavior_spec import _build_behavior_spec
from asago_scenario_generator.report.sections_generation_inputs import (
    _build_generation_inputs_block,
)
from asago_scenario_generator.report.sections_profile_block import (
    _build_actor_profile_block,
    _build_complexity_assessment_block,
)


def _zone_breadcrumb_html(zone_sequence: list[Any]) -> str:
    """Build the zone breadcrumb chips with arrows."""
    breadcrumb = ""
    for i, z in enumerate(zone_sequence):
        zn = _normalize_zone(z)
        color = ZONE_COLORS.get(zn, "#666")
        bg = ZONE_BG_COLORS.get(zn, "#333")
        display = ZONE_DISPLAY_NAMES.get(zn, zn)
        breadcrumb += f'<span class="zone-crumb" style="background:{bg};color:{color};" data-tooltip="{_esc(display)}">{_esc(zn)}</span>'
        if i < len(zone_sequence) - 1:
            breadcrumb += '<span class="zone-crumb-arrow">&rarr;</span>'
    return breadcrumb


def _above_threshold(value: float | None, mean: float, std: float) -> bool:
    """Return whether *value* exceeds mean + 2 std (anomaly threshold)."""
    return value is not None and std > 0 and value > mean + 2.0 * std


def _is_high_token_call(
    usage: dict[str, int | float | None], call_stats: dict[str, float]
) -> bool:
    """Return whether either token metric exceeds the anomaly threshold."""
    return _above_threshold(
        usage["prompt_tokens"], call_stats["pt_mean"], call_stats["pt_std"]
    ) or _above_threshold(
        usage["completion_tokens"], call_stats["ct_mean"], call_stats["ct_std"]
    )


def _anomaly_badges_html(
    usage: dict[str, int | float | None],
    call_stats: dict[str, float] | None,
) -> tuple[str, bool]:
    """Return (anomaly badge html, is_anomaly) for one call."""
    anomaly_badges = ""
    is_anomaly = False
    if call_stats is not None:
        if _above_threshold(
            usage["duration_ms"], call_stats["dur_mean"], call_stats["dur_std"]
        ):
            anomaly_badges += '<span class="call-anomaly-badge">⚠ slow</span>'
            is_anomaly = True
        if _is_high_token_call(usage, call_stats):
            anomaly_badges += '<span class="call-anomaly-badge">⚠ high tokens</span>'
            is_anomaly = True
    return anomaly_badges, is_anomaly


def _call_item_html(
    idx: int,
    entry: dict[str, Any],
    call_stats: dict[str, float] | None,
) -> str:
    """Render one LLM call-log details entry."""
    call_name = entry.get("call", "")
    display_name = _CALL_DISPLAY_NAMES.get(call_name, call_name)
    call_label = _usage_call_label(entry, idx)
    usage = _usage_metrics(entry, call_label=call_label)
    sys_prompt = _esc(entry.get("system_prompt", ""))
    usr_prompt = _esc(entry.get("user_prompt", ""))
    response_raw = entry.get("response", "")
    if isinstance(response_raw, (dict, list)):
        response_text = _esc(json.dumps(response_raw, indent=2, ensure_ascii=False))
    else:
        response_text = _esc(str(response_raw))

    anomaly_badges, is_anomaly = _anomaly_badges_html(usage, call_stats)
    detail_cls = "expandable call-anomaly" if is_anomaly else "expandable"
    failure_suffix = _usage_failure_suffix(entry)
    warning_html = _usage_warning_html(call_label, usage)
    return f"""
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


def _call_log_html(
    sid: str,
    call_logs: dict[str, list[dict]] | None,
    call_stats: dict[str, float] | None,
) -> str:
    """Render the LLM call log section (inner content only)."""
    _logs = (call_logs or {}).get(sid, [])
    if not _logs:
        return ""
    return "".join(
        _call_item_html(idx, entry, call_stats) for idx, entry in enumerate(_logs)
    )


def _behavior_spec_badge(feature_content: str) -> str:
    """Build the step-count quality badge for the Behavior Spec tab."""
    if not feature_content:
        return ""
    step_count = sum(
        1
        for line in feature_content.splitlines()
        if re.match(r"\s*(Given|When|Then|And|But)\b", line)
    )
    return f'<span class="tab-quality-badge">{step_count} steps</span>'


def _consistency_warning_part(metric: float | None, label: str) -> str:
    """Build a consistency warning badge when the metric is below 1.0."""
    if metric is not None and metric < 1.0:
        return f'<span class="tab-quality-badge tab-warn">{label}: {metric:.2f}</span>'
    return ""


def _tree_quality_badge(scorecard_data: dict[str, Any] | None, sid: str) -> str:
    """Build attack-tree consistency warning badges from the scorecard."""
    if not scorecard_data:
        return ""
    eval_block = scorecard_data.get("evaluation", {})

    # Attack Tree badge: consistency metrics below 1.0
    consistency = eval_block.get("consistency", {}).get("per_scenario", {}).get(sid, {})
    tree_badge = _consistency_warning_part(consistency.get("zone_alignment"), "zones")
    tree_badge += _consistency_warning_part(
        consistency.get("step_node_correspondence"), "step-node"
    )
    return tree_badge


def _narrative_quality_badge(scorecard_data: dict[str, Any] | None, sid: str) -> str:
    """Build the narrative plausibility-violation badge from the scorecard."""
    if not scorecard_data:
        return ""
    plausibility = (
        scorecard_data.get("evaluation", {})
        .get("plausibility", {})
        .get("per_scenario", {})
        .get(sid)
    )
    if not plausibility:
        return ""
    n_violations = len(plausibility)
    return (
        f'<span class="tab-quality-badge tab-fail">'
        f"{n_violations} violation{'s' if n_violations != 1 else ''}"
        f"</span>"
    )


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
    breadcrumb = _zone_breadcrumb_html(zone_sequence)

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

    # Scenario Seed block: renders only when seed metadata is present and
    # complete (attack pattern name and seed ID), so absent or partial
    # metadata degrades honestly.
    seed_metadata_html = _build_seed_metadata_block(scenario)

    # ATLAS techniques section
    atlas_techniques_html = _build_atlas_techniques_block(scenario, feature_content)

    # LLM call log section (inner content only, no <details> wrapper)
    call_log_html = _call_log_html(sid, call_logs, call_stats)

    # Sanitised scenario ID for unique radio input IDs
    safe_sid = re.sub(r"[^a-zA-Z0-9_-]", "_", sid)

    # ------------------------------------------------------------------
    # Quality badges for tab headers (from eval scorecard)
    # ------------------------------------------------------------------
    bspec_badge = _behavior_spec_badge(feature_content)
    tree_badge = _tree_quality_badge(scorecard_data, sid)
    narr_badge = _narrative_quality_badge(scorecard_data, sid)

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
            {seed_metadata_html}
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
