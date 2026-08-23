"""Eval scorecard rendering for the taxonomy/risk report."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc

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
        "Whether attack tree and behavior spec carry the same exact "
        "projected-step ATLAS mappings; scenario classifications are separate"
    ),
    "Mean Technique Agreement": (
        "Average Jaccard similarity of exact projected-step mapping sets in "
        "the attack tree and behavior spec. 1.0 means perfect agreement"
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
                (
                    sev,
                    sid,
                    "Projected-step Mapping Agreement",
                    "Mapping Agreement",
                    score,
                    css,
                )
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
                    "Projected-step Mapping Agreement",
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
                classifications = ", ".join(detail.get("scenario_classifications", []))
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
                    f"<td>{_esc(classifications) or '-'}</td>"
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
              <th>Scenario Classifications</th>
              <th data-tooltip="Exact projected-step mappings present in behavior spec but missing from attack tree">Missing from Tree</th>
              <th data-tooltip="Exact projected-step mappings present in attack tree but missing from behavior spec">Missing from Spec</th>
            </tr></thead>
            <tbody>{ta_rows}</tbody>
          </table>
        </details>"""

        ta_tip = _SCORECARD_METRIC_TOOLTIPS.get("Technique Agreement", "")
        technique_agreement_html = f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(ta_tip)}">Projected-step Mapping Agreement</div>
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
