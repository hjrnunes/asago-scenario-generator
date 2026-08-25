"""Threat-Technique Matrix section builder."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    THREAT_NAMES,
    ZONE_ABBREVS,
    ZONE_BG_COLORS,
    ZONE_COLORS,
    ZONE_DISPLAY_NAMES,
    _attack_pattern_tooltip,
    _normalize_zone,
    _technique_id_tooltip,
    _threat_id_tooltip,
)

_ALL_THREAT_IDS = [f"T{i}" for i in range(1, 18)]


def _sid_title_lookup(scenarios: list[dict[str, Any]]) -> dict[str, str]:
    """Build scenario ID -> narrative title lookup."""
    sid_titles: dict[str, str] = {}
    for s in scenarios:
        s_id = s.get("scenario_id", "")
        s_title = s.get("narrative", {}).get("title", "")
        if s_id and s_title:
            sid_titles[s_id] = s_title
    return sid_titles


def _pinned_technique_ids(candidate_filter: dict[str, Any]) -> list[str]:
    """Extract pinned technique IDs, falling back to the singular field."""
    pinned = candidate_filter.get("pinned_technique_ids") or []
    if not pinned:
        old_id = candidate_filter.get("pinned_technique_id", "")
        pinned = [old_id] if old_id else []
    return pinned


def _pinned_technique_names(candidate_filter: dict[str, Any]) -> list[str]:
    """Extract pinned technique names, falling back to the singular field."""
    pinned = candidate_filter.get("pinned_technique_names") or []
    if not pinned:
        old_name = candidate_filter.get("pinned_technique_name", "")
        pinned = [old_name] if old_name else []
    return pinned


def _parent_threat(scenario_seed: str, threat_ids: list[str]) -> str:
    """Derive the parent threat (e.g. 'AP-T10-01' -> 'T10') from the seed."""
    parent_threat = ""
    if scenario_seed:
        parts = scenario_seed.split("-")
        if len(parts) >= 2:
            parent_threat = parts[1]
    if not parent_threat and threat_ids:
        parent_threat = threat_ids[0]
    return parent_threat


def _base_threat_id(tid: str) -> str:
    """Strip technique scoping from a threat ID ('T6-AML.T0040' -> 'T6')."""
    return tid.split("-")[0] if "-" in tid else tid


def _record_cell(
    row: dict[str, list[str]],
    tech_id: str,
    sid: str,
    all_techniques: list[str],
) -> None:
    """Record one (sid, tech_id) pair in the matrix row and technique list."""
    if tech_id not in row:
        row[tech_id] = []
    if sid not in row[tech_id]:
        row[tech_id].append(sid)
    if tech_id not in all_techniques:
        all_techniques.append(tech_id)


def _record_technique_links(
    threat_tech_map: dict[str, dict[str, list[str]]],
    all_techniques: list[str],
    sid: str,
    threat_ids: list[str],
    technique_ids: list[str],
) -> None:
    """Populate threat -> technique -> scenario links for one scenario."""
    for tid in threat_ids:
        base_tid = _base_threat_id(tid)
        if base_tid not in threat_tech_map:
            threat_tech_map[base_tid] = {}
        for tech_id in technique_ids:
            _record_cell(threat_tech_map[base_tid], tech_id, sid, all_techniques)


def _collect_technique_data(
    scenarios: list[dict[str, Any]],
) -> tuple[
    dict[str, str], dict[str, dict[str, list[str]]], list[str], list[dict[str, Any]]
]:
    """Collect matrix links, technique columns, and roster rows from scenarios."""
    sid_titles = _sid_title_lookup(scenarios)
    threat_tech_map: dict[str, dict[str, list[str]]] = {}
    all_techniques: list[str] = []
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

        # Extract pinned technique(s) from candidate_filter.
        candidate_filter = s.get("candidate_filter", {}) or {}
        pinned_technique_ids = _pinned_technique_ids(candidate_filter)
        pinned_technique_names = _pinned_technique_names(candidate_filter)
        parent_threat = _parent_threat(scenario_seed, threat_ids)

        _record_technique_links(
            threat_tech_map, all_techniques, sid, threat_ids, technique_ids
        )

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

    # Sort techniques for consistent column order.
    all_techniques.sort()
    return sid_titles, threat_tech_map, all_techniques, roster_rows


def _matrix_headers_html(all_techniques: list[str]) -> str:
    """Build the rotated technique column headers."""
    tech_headers = ""
    for tech_id in all_techniques:
        tech_tip = _technique_id_tooltip(tech_id)
        tech_headers += (
            f'<th class="matrix-col-header"{tech_tip}>'
            f'<span class="matrix-col-header-text">{_esc(tech_id)}</span></th>'
        )
    return tech_headers


def _matrix_cell_html(
    scenario_ids: list[str],
    sid_titles: dict[str, str],
) -> str:
    """Render one matrix cell: scenario link with tooltip, or an empty cell."""
    if not scenario_ids:
        return '<td class="matrix-cell"></td>'
    count = len(scenario_ids)
    tooltip_lines = "&#10;".join(
        f"{_esc(s_id)}: {_esc(sid_titles.get(s_id, ''))}"
        if s_id in sid_titles
        else _esc(s_id)
        for s_id in scenario_ids
    )
    # Link to the first scenario for click convenience
    first_sid = scenario_ids[0]
    return (
        f'<td class="matrix-cell">'
        f'<a class="matrix-count-link" '
        f'href="#scenario-{_esc(first_sid)}" '
        f'data-tooltip="{tooltip_lines}">'
        f"{count}</a></td>"
    )


def _matrix_rows_html(
    threat_tech_map: dict[str, dict[str, list[str]]],
    all_techniques: list[str],
    sid_titles: dict[str, str],
) -> str:
    """Build the cross-reference matrix rows (one per threat T1-T17)."""
    matrix_rows = ""
    for tid in _ALL_THREAT_IDS:
        threat_name = THREAT_NAMES.get(tid, "")
        has_scenarios = tid in threat_tech_map
        row_cls = "" if has_scenarios else " matrix-row-greyed"
        tip = _threat_id_tooltip(tid)

        cells = ""
        for tech_id in all_techniques:
            scenario_ids = threat_tech_map.get(tid, {}).get(tech_id, [])
            cells += _matrix_cell_html(scenario_ids, sid_titles)

        matrix_rows += (
            f'<tr class="{row_cls.strip()}">'
            f'<td class="matrix-sticky-col matrix-sticky-col-0"{tip}>'
            f"<strong>{_esc(tid)}</strong></td>"
            f'<td class="matrix-sticky-col matrix-sticky-col-1">'
            f"{_esc(threat_name)}</td>"
            f"{cells}"
            f"</tr>"
        )
    return matrix_rows


def _roster_zone_badges(zones: list[str]) -> str:
    """Render the traversed-zone badge row for one roster entry."""
    zone_badges = ""
    for z in zones:
        zc = ZONE_COLORS.get(z, "#666")
        zbg = ZONE_BG_COLORS.get(z, "#333")
        zname = ZONE_DISPLAY_NAMES.get(z, z)
        zabbr = ZONE_ABBREVS.get(z, z)
        zone_badges += (
            f'<span class="zone-badge" style="background:{zbg};'
            f'color:{zc};" data-tooltip="{_esc(zname)}">{_esc(zabbr)}</span>'
        )
    return zone_badges


def _roster_threat_spans(row: dict[str, Any]) -> str:
    """Render the threat column for one roster entry."""
    parent_threat = row["threat"]
    if not parent_threat:
        # Fallback: show all threat IDs.
        return ", ".join(
            f"<span{_threat_id_tooltip(t)}>{_esc(t)}</span>" for t in row["threat_ids"]
        )
    if row["threat_ids"]:
        full_threats = "&#10;".join(row["threat_ids"])
        return f'<span data-tooltip="{_esc(full_threats)}">{_esc(parent_threat)}</span>'
    return f"<span{_threat_id_tooltip(parent_threat)}>{_esc(parent_threat)}</span>"


def _single_pinned_span(pinned_ids: list[str], pinned_names_list: list[str]) -> str:
    """Render a single pinned technique with its name tooltip."""
    pinned_name_display = pinned_names_list[0] if pinned_names_list else ""
    tech_tip = (
        f' data-tooltip="{_esc(pinned_name_display)}"' if pinned_name_display else ""
    )
    return f"<span{tech_tip}>{_esc(pinned_ids[0])}</span>"


def _multi_pinned_span(pinned_ids: list[str], pinned_names_list: list[str]) -> str:
    """Render a multi-technique count badge with tooltip of all IDs."""
    combo_display = " + ".join(pinned_ids)
    names_display = ", ".join(pinned_names_list) if pinned_names_list else combo_display
    tech_tip = f' data-tooltip="{_esc(names_display)}"'
    return f'<span class="count-badge"{tech_tip}>{len(pinned_ids)} techniques</span>'


def _roster_technique_spans(row: dict[str, Any]) -> str:
    """Render the technique column for one roster entry."""
    pinned_ids = row["pinned_technique_ids"]
    if not pinned_ids:
        # Fallback: show all technique IDs.
        return ", ".join(
            f"<span{_technique_id_tooltip(t)}>{_esc(t)}</span>"
            for t in row["technique_ids"]
        )
    pinned_names_list = row["pinned_technique_names"]
    if len(pinned_ids) == 1:
        return _single_pinned_span(pinned_ids, pinned_names_list)
    return _multi_pinned_span(pinned_ids, pinned_names_list)


def _roster_body_html(
    roster_rows: list[dict[str, Any]],
    sid_titles: dict[str, str],
) -> str:
    """Render the scenario roster body rows."""
    roster_body = ""
    for row in roster_rows:
        sid = row["scenario_id"]
        threat_spans = _roster_threat_spans(row)
        sub = row["attack_pattern"]
        tech_spans = _roster_technique_spans(row)
        actor_display = (
            row["actor_type"].replace("-", " ").replace("_", " ").title()
            if row["actor_type"]
            else ""
        )
        cap_display = row["capability_level"].title() if row["capability_level"] else ""
        zone_badges = _roster_zone_badges(row["zones_traversed"])

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
    return roster_body


def _matrix_html(tech_headers: str, matrix_rows: str) -> str:
    """Wrap the matrix table in its card container."""
    return f"""
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


def _roster_html(roster_body: str) -> str:
    """Wrap the scenario roster table in its card container."""
    return f"""
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

    sid_titles, threat_tech_map, all_techniques, roster_rows = _collect_technique_data(
        scenarios
    )

    tech_headers = _matrix_headers_html(all_techniques)
    matrix_rows = _matrix_rows_html(threat_tech_map, all_techniques, sid_titles)
    matrix_html = _matrix_html(tech_headers, matrix_rows)

    roster_rows.sort(key=lambda r: r["scenario_id"])
    roster_html = _roster_html(_roster_body_html(roster_rows, sid_titles))

    # Active threats count
    active_count = sum(1 for t in _ALL_THREAT_IDS if t in threat_tech_map)

    return f"""
    <div id="sec-threat-matrix" class="section">
      <div class="section-header">
        <h2>Threat&ndash;Technique Matrix</h2>
        <span class="badge">{active_count}/{len(_ALL_THREAT_IDS)} threats &middot; {len(all_techniques)} techniques &middot; {len(scenarios)} scenarios</span>
      </div>

      {matrix_html}
      {roster_html}
    </div>
    """
