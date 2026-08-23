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


def _join_strs(items: list[Any], sep: str = ", ") -> str:
    """Stringify and join *items* with *sep*."""
    return sep.join(str(item) for item in items)


def _display_or_dash(value: str) -> str:
    """Return *value* when non-empty, else '-'."""
    if value:
        return value
    return "-"


def _badge_css_class(value: float, invert: bool) -> str:
    """Return the badge CSS class for a metric value."""
    if invert:
        # For counts: 0 = green, >0 = red
        if value == 0:
            return "scorecard-badge-green"
        return "scorecard-badge-red"
    if value >= 0.9:
        return "scorecard-badge-green"
    if value >= 0.7:
        return "scorecard-badge-yellow"
    return "scorecard-badge-red"


def _badge_display_value(value: float) -> str:
    """Format a metric value for display (2 decimals for non-integer floats)."""
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.2f}"
    return str(int(value))


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
    css_cls = _badge_css_class(value, invert)
    display = _badge_display_value(value)
    tip = tooltip or _SCORECARD_METRIC_TOOLTIPS.get(label, "")
    tip_attr = f' data-tooltip="{_esc(tip)}"' if tip else ""
    return f'<span class="scorecard-badge {css_cls}"{tip_attr}>{_esc(label)}: {display}</span>'


def _low_value_rank(
    value: float, warn_below: float, red_below: float
) -> tuple[str, str] | None:
    """Classify a below-threshold value as an outlier.

    Returns ``(severity, css_cls)`` when *value* is below *warn_below*
    (``"red"`` below *red_below*, otherwise ``"yellow"``), or None when the
    value is within range.
    """
    if value >= warn_below:
        return None
    if value < red_below:
        return "red", "scorecard-badge-red"
    return "yellow", "scorecard-badge-yellow"


def _collect_consistency_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect per-scenario consistency outlier rows."""
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []
    per_scenario_c = ev.get("consistency", {}).get("per_scenario", {})
    for sid, metrics in per_scenario_c.items():
        za = metrics.get("zone_alignment", 1.0)
        za_rank = _low_value_rank(za, 0.9, 0.7)
        if za_rank:
            outliers.append(
                (za_rank[0], sid, "Consistency", "Zone Alignment", za, za_rank[1])
            )
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
        snc_rank = _low_value_rank(snc, 0.9, 0.7)
        if snc_rank:
            outliers.append(
                (
                    snc_rank[0],
                    sid,
                    "Consistency",
                    "Step-Node Correspondence",
                    snc,
                    snc_rank[1],
                )
            )
    return outliers


def _missing_parts(
    missing_narr: list[str], missing_tree: list[str], missing_spec: list[str]
) -> list[str]:
    """Build human-readable missing-technique parts."""
    parts = []
    for label, items in (
        ("narrative", missing_narr),
        ("tree", missing_tree),
        ("spec", missing_spec),
    ):
        if items:
            parts.append(f"{label}: {', '.join(items)}")
    return parts


def _mapping_row(
    sid: str, detail: dict[str, Any]
) -> tuple[str, str, str, str, float | int | str, str] | None:
    """Return the mapping-agreement outlier row for one scenario, or None."""
    score = detail.get("technique_agreement", 1.0)
    score_rank = _low_value_rank(score, 0.9, 0.7)
    if score_rank:
        return (
            score_rank[0],
            sid,
            "Projected-step Mapping Agreement",
            "Mapping Agreement",
            score,
            score_rank[1],
        )
    missing_narr = detail.get("missing_from_narrative", [])
    missing_tree = detail.get("missing_from_tree", [])
    missing_spec = detail.get("missing_from_spec", [])
    parts = _missing_parts(missing_narr, missing_tree, missing_spec)
    if parts:
        return (
            "yellow",
            sid,
            "Projected-step Mapping Agreement",
            "Missing Techniques",
            "; ".join(parts),
            "scorecard-badge-yellow",
        )
    return None


def _collect_technique_agreement_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect per-scenario projected-step mapping agreement outlier rows."""
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []
    ta = ev.get("technique_agreement", {})
    per_scenario_ta = ta.get("per_scenario", {})
    for sid, detail in per_scenario_ta.items():
        row = _mapping_row(sid, detail)
        if row:
            outliers.append(row)
    return outliers


def _plausibility_issue_rows(
    sid: str, issues: Any
) -> list[tuple[str, str, str, str, str, str]]:
    """Return one outlier row per capability violation issue."""
    rows: list[tuple[str, str, str, str, str, str]] = []
    if isinstance(issues, list):
        for issue in issues:
            rows.append(
                (
                    "red",
                    sid,
                    "Plausibility",
                    "Capability Violation",
                    str(issue),
                    "scorecard-badge-red",
                )
            )
    return rows


def _collect_plausibility_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect per-scenario and aggregate plausibility outlier rows."""
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []
    per_scenario_p = ev.get("plausibility", {}).get("per_scenario", {})
    for sid, issues in per_scenario_p.items():
        outliers.extend(_plausibility_issue_rows(sid, issues))
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
    return outliers


def _collect_title_outliers(
    diversity: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect the aggregate Title Uniqueness outlier row."""
    tu = diversity.get("title_uniqueness", 1.0)
    if not isinstance(tu, (int, float)):
        return []
    tu_rank = _low_value_rank(tu, 0.7, 0.5)
    if not tu_rank:
        return []
    return [
        (tu_rank[0], "(aggregate)", "Diversity", "Title Uniqueness", tu, tu_rank[1])
    ]


def _collect_ep_coverage_outliers(
    diversity: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect the aggregate EP Coverage outlier row."""
    ep_ent = diversity.get("entry_point_entropy", {})
    if not isinstance(ep_ent, dict):
        return []
    ep_cov = ep_ent.get("entry_point_coverage", 1.0)
    ep_rank = _low_value_rank(ep_cov, 0.7, 0.5)
    if not ep_rank:
        return []
    return [(ep_rank[0], "(aggregate)", "Diversity", "EP Coverage", ep_cov, ep_rank[1])]


def _collect_diversity_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Collect aggregate diversity outlier rows."""
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []
    diversity = ev.get("diversity", {})
    outliers.extend(_collect_title_outliers(diversity))
    outliers.extend(_collect_ep_coverage_outliers(diversity))
    return outliers


def _collect_scorecard_outliers(
    ev: dict[str, Any],
) -> list[tuple[str, str, str, str, float | int | str, str]]:
    """Scan scorecard evaluation data and return outlier rows.

    Each row is ``(severity, scenario_id, group, metric, value, css_cls)``
    where *severity* is ``"red"`` or ``"yellow"`` (for sort ordering) and
    *css_cls* is the badge CSS class.

    Returns:
        Sorted list: red items first, then yellow, each alphabetical by
        scenario ID within its severity tier.
    """
    outliers: list[tuple[str, str, str, str, float | int | str, str]] = []
    outliers.extend(_collect_consistency_outliers(ev))
    outliers.extend(_collect_technique_agreement_outliers(ev))
    outliers.extend(_collect_plausibility_outliers(ev))
    outliers.extend(_collect_diversity_outliers(ev))

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


def _metric_badge_class(value: float) -> str:
    """Return the scorecard badge class for a 0-1 metric value."""
    if value >= 0.9:
        return "scorecard-badge-green"
    if value >= 0.7:
        return "scorecard-badge-yellow"
    return "scorecard-badge-red"


def _build_consistency_detail(per_scenario_consistency: dict[str, Any]) -> str:
    """Render the per-scenario consistency breakdown table."""
    if not per_scenario_consistency:
        return ""
    rows = ""
    for sid, metrics in per_scenario_consistency.items():
        za = metrics.get("zone_alignment", 0)
        epa = metrics.get("entry_point_agreement", 0)
        snc = metrics.get("step_node_correspondence", 0)
        za_cls = _metric_badge_class(za)
        epa_cls = "scorecard-badge-green" if epa == 1 else "scorecard-badge-red"
        snc_cls = _metric_badge_class(snc)
        rows += (
            f"<tr>"
            f"<td>{_esc(sid)}</td>"
            f'<td><span class="scorecard-badge {za_cls}">{za:.2f}</span></td>'
            f'<td><span class="scorecard-badge {epa_cls}">{epa}</span></td>'
            f'<td><span class="scorecard-badge {snc_cls}">{snc:.2f}</span></td>'
            f"</tr>"
        )
    return f"""
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


def _build_consistency_group(ev: dict[str, Any]) -> str:
    """Render the Consistency metric group."""
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
    consistency_detail = _build_consistency_detail(per_scenario_consistency)

    consistency_tip = _SCORECARD_METRIC_TOOLTIPS.get("Consistency", "")
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(consistency_tip)}">Consistency</div>
      <div class="scorecard-metrics">{consistency_badges}</div>
      {consistency_detail}
    </div>"""


def _build_gherkin_group(ev: dict[str, Any]) -> str:
    """Render the Gherkin Quality metric group ('' when no Gherkin data)."""
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
    if not gherkin_badges:
        return ""
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(gherkin_tip)}">Gherkin Quality</div>
      <div class="scorecard-metrics">{gherkin_badges}</div>
    </div>"""


def _build_grounding_group(ev: dict[str, Any]) -> str:
    """Render the Grounding metric group ('' when no grounding data)."""
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
    if not grounding_badges:
        return ""
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(grounding_tip)}">Grounding</div>
      <div class="scorecard-metrics">{grounding_badges}</div>
    </div>"""


def _ta_row(sid: str, detail: dict[str, Any]) -> str:
    """Render one per-scenario mapping-agreement table row."""
    score = detail.get("technique_agreement", 0)
    score_cls = _metric_badge_class(score)
    classifications = _display_or_dash(
        _join_strs(detail.get("scenario_classifications", []))
    )
    missing_tree = _display_or_dash(_join_strs(detail.get("missing_from_tree", [])))
    missing_spec = _display_or_dash(_join_strs(detail.get("missing_from_spec", [])))
    return (
        f"<tr>"
        f"<td>{_esc(sid)}</td>"
        f'<td><span class="scorecard-badge {score_cls}">{score:.2f}</span></td>'
        f"<td>{_esc(classifications)}</td>"
        f"<td>{_esc(missing_tree)}</td>"
        f"<td>{_esc(missing_spec)}</td>"
        f"</tr>"
    )


def _build_ta_per_scenario(ta_per_scenario: dict[str, Any]) -> str:
    """Render the per-scenario mapping disagreement table."""
    if not ta_per_scenario:
        return ""
    ta_rows = ""
    for sid, detail in ta_per_scenario.items():
        ta_rows += _ta_row(sid, detail)
    return f"""
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


def _build_technique_agreement_group(ev: dict[str, Any]) -> str:
    """Render the Projected-step Mapping Agreement group ('' when absent)."""
    technique_agreement = ev.get("technique_agreement", {})
    if not technique_agreement:
        return ""
    mta = technique_agreement.get("mean_technique_agreement", 0)
    ta_badges = _scorecard_badge(mta, "Mean Technique Agreement")

    ta_per_scenario = technique_agreement.get("per_scenario", {})
    ta_detail = _build_ta_per_scenario(ta_per_scenario)

    ta_tip = _SCORECARD_METRIC_TOOLTIPS.get("Technique Agreement", "")
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(ta_tip)}">Projected-step Mapping Agreement</div>
      <div class="scorecard-metrics">{ta_badges}</div>
      {ta_detail}
    </div>"""


def _build_diversity_entropy_badges(ep_ent: Any) -> str:
    """Render the entry-point entropy/coverage badges ('' when absent)."""
    if not isinstance(ep_ent, dict):
        return ""
    entropy = ep_ent.get("entropy", 0)
    ep_cov = ep_ent.get("entry_point_coverage", 0)
    ep_ent_tip = _SCORECARD_METRIC_TOOLTIPS.get("EP Entropy", "")
    badges = (
        f'<span class="scorecard-badge scorecard-badge-green"'
        f' data-tooltip="{_esc(ep_ent_tip)}">'
        f"EP Entropy: {entropy:.2f}</span>"
    )
    return badges + _scorecard_badge(ep_cov, "EP Coverage")


def _build_diversity_zone_badges(zone_cov: Any) -> str:
    """Render the zone-coverage badges ('' when absent)."""
    if not isinstance(zone_cov, dict):
        return ""
    azc = zone_cov.get("active_zone_coverage", 0)
    badges = _scorecard_badge(azc, "Active Zone Coverage")
    violations = zone_cov.get("out_of_scope_zone_violations", [])
    if violations:
        badges += _scorecard_badge(len(violations), "Zone Violations", invert=True)
    return badges


def _scalar_scorecard_badge(diversity: dict[str, Any], key: str, label: str) -> str:
    """Render a scalar diversity metric badge ('' when not numeric)."""
    value = diversity.get(key, 0)
    if not isinstance(value, (int, float)):
        return ""
    return _scorecard_badge(value, label)


def _diversity_badges(diversity: dict[str, Any]) -> str:
    """Render all diversity badges for the diversity group."""
    badges = ""
    if diversity:
        badges += _build_diversity_entropy_badges(
            diversity.get("entry_point_entropy", {})
        )
        badges += _build_diversity_zone_badges(diversity.get("zone_coverage", {}))
        badges += _scalar_scorecard_badge(
            diversity, "actor_type_entropy", "Actor Type Entropy"
        )
        badges += _scalar_scorecard_badge(
            diversity, "capability_level_evenness", "Capability Evenness"
        )
        badges += _scalar_scorecard_badge(
            diversity, "title_uniqueness", "Title Uniqueness"
        )
    return badges


def _build_diversity_group(ev: dict[str, Any]) -> str:
    """Render the Diversity metric group ('' when no diversity data)."""
    diversity = ev.get("diversity", {})
    diversity_badges = _diversity_badges(diversity)

    diversity_tip = _SCORECARD_METRIC_TOOLTIPS.get("Diversity", "")
    if not diversity_badges:
        return ""
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(diversity_tip)}">Diversity</div>
      <div class="scorecard-metrics">{diversity_badges}</div>
    </div>"""


def _violation_rows(per_scenario_p: dict[str, Any]) -> str:
    """Render the per-scenario capability violation table rows."""
    violation_items = ""
    for sid, issues in per_scenario_p.items():
        if isinstance(issues, list):
            for issue in issues:
                violation_items += (
                    f"<tr><td>{_esc(sid)}</td><td>{_esc(str(issue))}</td></tr>"
                )
    return violation_items


def _build_violations_detail(per_scenario_p: dict[str, Any]) -> str:
    """Render the per-scenario capability violation details table."""
    violation_items = _violation_rows(per_scenario_p)
    if not violation_items:
        return ""
    return f"""
        <details class="expandable" style="margin-top:10px;">
          <summary>Violation Details</summary>
          <table class="scorecard-detail-table">
            <thead><tr><th>Scenario</th><th>Issue</th></tr></thead>
            <tbody>{violation_items}</tbody>
          </table>
        </details>"""


def _build_plausibility_group(ev: dict[str, Any]) -> str:
    """Render the Plausibility metric group ('' when absent)."""
    plausibility = ev.get("plausibility", {})
    if not plausibility:
        return ""
    violation_count = plausibility.get("capability_complexity_violation_count", 0)
    plausibility_badges = _scorecard_badge(
        violation_count, "Capability Violations", invert=True
    )

    per_scenario_p = plausibility.get("per_scenario", {})
    violations_detail = _build_violations_detail(per_scenario_p)

    plausibility_tip = _SCORECARD_METRIC_TOOLTIPS.get("Plausibility", "")
    return f"""
    <div class="scorecard-group">
      <div class="scorecard-group-title" data-tooltip="{_esc(plausibility_tip)}">Plausibility</div>
      <div class="scorecard-metrics">{plausibility_badges}</div>
      {violations_detail}
    </div>"""


def _build_legacy_summary_html(ev: dict[str, Any]) -> str:
    """Render the legacy scorecard summary stat blocks."""
    scenario_count = ev.get("scenario_count", 0)
    feature_file_count = ev.get("feature_file_count", 0)
    return f"""
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


_SCORECARD_VERSIONED_GROUPS: tuple[tuple[str, str], ...] = (
    ("presence_coverage", "Presence / Coverage"),
    ("validity_grounding", "Validity / Grounding"),
    ("cross_artifact_agreement", "Cross-artifact Agreement"),
    ("semantic_quality_diagnostics", "Semantic Quality / Diagnostics"),
    ("release_qualification", "Release Qualification"),
)


def _build_versioned_metric_row(metric_id: str, metric: dict[str, Any]) -> str:
    """Render one metric row of a versioned scorecard group."""
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
    evidence = _join_strs(metric.get("evidence", []), "; ")
    affected = _join_strs(metric.get("affected_ids", []))
    return (
        "<tr>"
        f"<td>{_esc(metric_id)}</td>"
        f'<td><span class="scorecard-badge {css}">{_esc(status)}</span></td>'
        f"<td>{_esc(fraction)}</td><td>{_esc(rendered_value)}</td>"
        f"<td>{_esc(evidence)}</td><td>{_esc(affected) or '—'}</td>"
        "</tr>"
    )


def _build_versioned_group(group_data: dict[str, Any], label: str) -> str:
    """Render one metric group of the versioned scorecard."""
    metrics = group_data.get("metrics", {})
    rows = ""
    for metric_id, metric in metrics.items():
        rows += _build_versioned_metric_row(metric_id, metric)
    return f"""
        <div class="scorecard-group">
          <div class="scorecard-group-title">{_esc(label)}</div>
          <table class="scorecard-detail-table">
            <thead><tr><th>Metric</th><th>Status</th><th>Numerator / Denominator</th>
            <th>Bounded Value</th><th>Evidence</th><th>Affected IDs</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""


def _build_versioned_scorecard_section(scorecard_data: dict[str, Any]) -> str:
    """Render strict typed metrics without inferring meaning from missing values."""
    groups = ""
    for key, label in _SCORECARD_VERSIONED_GROUPS:
        groups += _build_versioned_group(scorecard_data.get(key, {}), label)
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

    summary_html = _build_legacy_summary_html(ev)

    # --- Outliers panel (rendered after summary, before metric groups) ---
    outliers = _collect_scorecard_outliers(ev)
    outliers_html = _build_outliers_panel(outliers)

    consistency_html = _build_consistency_group(ev)
    gherkin_html = _build_gherkin_group(ev)
    grounding_html = _build_grounding_group(ev)
    technique_agreement_html = _build_technique_agreement_group(ev)
    diversity_html = _build_diversity_group(ev)
    plausibility_html = _build_plausibility_group(ev)

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
