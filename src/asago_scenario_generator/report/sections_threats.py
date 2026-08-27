"""Threat Surface section and Sankey-style flow diagram builders."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    THREAT_NAMES,
    _ATTACK_PATTERN_INFO,
    _OWASP_LLM_NAMES,
    _THREAT_DESCRIPTIONS,
    _attack_pattern_tooltip,
    _threat_id_tooltip,
    _truncate,
)
from asago_scenario_generator.report.scenario_common import _priority_label

# Sankey layout constants
_SANKEY_COL_X = [40, 240, 440, 640]
_SANKEY_NODE_W = 140
_SANKEY_NODE_H = 30
_SANKEY_NODE_GAP = 8
_SANKEY_TOP_PAD = 50
_SANKEY_COLORS = ["#3b82f6", "#8b5cf6", "#f97316", "#ef4444"]
_SANKEY_LABEL_NAMES = ["Risk Atlas", "LLM Top 10", "Agentic Threats", "Attack Patterns"]
_SANKEY_LINK_COLORS = ["#3b82f6", "#8b5cf6", "#f97316"]


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
        return _risk_node_tip(node_id, risk_tips)
    if col_idx == 1:
        return _llm_node_tip(node_id)
    if col_idx == 2:
        return _threat_node_tip(node_id)
    if col_idx == 3:
        return _pattern_node_tip(node_id)
    return node_id


def _risk_node_tip(node_id: str, risk_tips: dict[str, str] | None) -> str:
    """Tooltip for a Risk Atlas column node."""
    name = (risk_tips or {}).get(node_id, "")
    return f"{node_id}: {name}" if name else node_id


def _llm_node_tip(node_id: str) -> str:
    """Tooltip for an OWASP LLM Top 10 column node."""
    name = _OWASP_LLM_NAMES.get(node_id, "")
    return f"{node_id}: {name}" if name else node_id


def _named_node_tip(node_id: str, name: str, desc: str) -> str:
    """Tooltip for a named node: ID plus optional name and description."""
    parts = node_id
    if name:
        parts += f": {name}"
    if desc:
        parts += f" — {_truncate(desc, 150)}"
    return parts


def _threat_node_tip(node_id: str) -> str:
    """Tooltip for an Agentic Threats column node."""
    return _named_node_tip(
        node_id,
        THREAT_NAMES.get(node_id, ""),
        _THREAT_DESCRIPTIONS.get(node_id, ""),
    )


def _pattern_node_tip(node_id: str) -> str:
    """Tooltip for an Attack Patterns column node."""
    info = _ATTACK_PATTERN_INFO.get(node_id, {})
    return _named_node_tip(node_id, info.get("name", ""), info.get("description", ""))


def _tid_scenario_index(scenarios: list[dict]) -> dict[str, list[tuple[int, str]]]:
    """Build threat-ID -> [(scenario_idx, priority_label)] index."""
    tid_to_scenarios: dict[str, list[tuple[int, str]]] = {}
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
                tid_to_scenarios.setdefault(tid, []).append((idx, label))
    return tid_to_scenarios


def _llm_id_spans(raw_llm: list[str]) -> str:
    """Render the LLM Top 10 ID list with tooltips, or '-' when absent."""
    if raw_llm:
        return ", ".join(
            f'<span data-tooltip="OWASP Top 10 for LLM Applications '
            f'— standardized LLM vulnerability category">{_esc(lid)}</span>'
            for lid in raw_llm
        )
    return "-"


def _threat_id_spans(raw_tids: list[str]) -> str:
    """Render agentic threat IDs with tooltips (count badge for 3+)."""
    if not raw_tids:
        return "-"
    if len(raw_tids) <= 2:
        return ", ".join(
            f"<span{_threat_id_tooltip(tid)}>{_esc(tid)}</span>" for tid in raw_tids
        )
    tid_tooltip_lines = "&#10;".join(
        f"{_esc(tid)} — {_esc(THREAT_NAMES.get(tid, ''))}" for tid in raw_tids
    )
    return (
        f'<span class="count-badge" data-tooltip="{tid_tooltip_lines}">'
        f"{len(raw_tids)} threats</span>"
    )


def _attack_pattern_spans(raw_aps: list[str]) -> str:
    """Render attack pattern IDs with tooltips (count badge for 3+)."""
    if not raw_aps:
        return "-"
    if len(raw_aps) <= 2:
        ap_parts: list[str] = []
        for ap_id in raw_aps:
            ap_parts.append(
                f"<span{_attack_pattern_tooltip(ap_id)}>{_esc(ap_id)}</span>"
            )
        return ", ".join(ap_parts)
    ap_tooltip_lines = "&#10;".join(
        f"{_esc(ap_id)}: {_esc(_ATTACK_PATTERN_INFO.get(ap_id, {}).get('name', ''))}"
        for ap_id in raw_aps
    )
    return (
        f'<span class="count-badge" data-tooltip="{ap_tooltip_lines}">'
        f"{len(raw_aps)} patterns</span>"
    )


def _risk_id_tip(rc: dict[str, Any]) -> str:
    """Return a tooltip attribute for Risk Atlas risk IDs."""
    risk_id = rc.get("risk_id", "")
    if risk_id.startswith("atlas-"):
        return ' data-tooltip="IBM AI Risk Atlas — standardized AI risk identifier"'
    return ""


def _count_priority(seen: dict[int, str], label: str) -> int:
    """Count scenario indexes whose priority bucket equals *label*."""
    return sum(1 for lbl in seen.values() if lbl == label)


def _priority_badge_counts(seen: dict[int, str]) -> tuple[int, int, int]:
    """Count high/medium/low priorities among the seen scenario indexes."""
    return (
        _count_priority(seen, "high"),
        _count_priority(seen, "medium"),
        _count_priority(seen, "low"),
    )


def _priority_badge_html(h: int, m: int, lo: int) -> str:
    """Render colored priority count badges (only nonzero buckets)."""
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
    return " ".join(parts)


def _entry_outcomes_cell(
    raw_tids: list[str],
    tid_to_scenarios: dict[str, list[tuple[int, str]]],
) -> str:
    """Render the per-entry outcomes cell with unique scenario counts."""
    seen: dict[int, str] = {}  # scenario_idx -> priority label
    for tid in raw_tids:
        for idx, label in tid_to_scenarios.get(tid, []):
            if idx not in seen:
                seen[idx] = label
    total = len(seen)
    if total:
        h, m, lo = _priority_badge_counts(seen)
        badge_html = _priority_badge_html(h, m, lo)
        return (
            f"<td data-tooltip=\"Scenarios generated from this entry's"
            f' threat IDs">{total} scenarios {badge_html}</td>'
        )
    return (
        '<td style="color:var(--muted);">'
        '<span style="opacity:.5;">0 scenarios</span></td>'
    )


def _risk_tips_lookup(entries: list[dict[str, Any]]) -> dict[str, str]:
    """Build risk_id -> risk_name lookup for Sankey tooltips."""
    risk_tips: dict[str, str] = {}
    for entry in entries:
        rc = entry.get("risk_card", {})
        rid = rc.get("risk_id", "")
        rname = rc.get("risk_name", "")
        if rid and rname:
            risk_tips[rid] = rname
    return risk_tips


def _entry_status(gov: bool) -> tuple[str, str, str]:
    """Return (css_class, text, tooltip) for an entry's status badge."""
    status_cls = "status-governance" if gov else "status-actionable"
    status_text = "GOV" if gov else "ACT"
    status_tip = (
        "Governance: maps to organizational controls, not directly testable"
        if gov
        else "Actionable: maps to testable agentic threat scenarios"
    )
    return status_cls, status_text, status_tip


def _column_widths(
    has_outcomes: bool,
) -> tuple[list[str], str]:
    """Return table column widths plus the optional Outcomes header."""
    if has_outcomes:
        _rw = ["14%", "18%", "9%", "8%", "9%", "11%", "14%", "17%"]
        outcomes_th = f'<th style="width:{_rw[7]}">Outcomes</th>'
    else:
        _rw = ["15%", "21%", "10%", "9%", "10%", "13%", "22%"]
        outcomes_th = ""
    return _rw, outcomes_th


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
    tid_to_scenarios = _tid_scenario_index(scenarios)
    has_outcomes = bool(tid_to_scenarios)

    # Option A: Table
    table_rows = ""
    for entry in all_entries:
        rc = entry.get("risk_card", {})
        gov = entry.get("governance_only", False)
        status_cls, status_text, status_tip = _entry_status(gov)

        llm_spans = _llm_id_spans(entry.get("owasp_llm_ids", []))
        raw_tids = entry.get("agentic_threat_ids", [])
        tid_spans = _threat_id_spans(raw_tids)
        sub_spans = _attack_pattern_spans(entry.get("attack_pattern_ids", []))

        risk_id_tip = _risk_id_tip(rc)

        conf = rc.get("confidence", 0)
        conf_display = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)

        # Outcomes cell — unique scenarios across this entry's agentic threat IDs
        outcomes_cell = ""
        if has_outcomes:
            outcomes_cell = _entry_outcomes_cell(raw_tids, tid_to_scenarios)

        table_rows += f"""
        <tr>
          <td{risk_id_tip}>{_esc(rc.get("risk_id", ""))}</td>
          <td>{_esc(rc.get("risk_name", ""))}</td>
          <td><span class="status-badge {status_cls}" data-tooltip="{_esc(status_tip)}">{status_text}</span></td>
          <td data-tooltip="Upstream extraction confidence — how strongly the policy text maps to this risk">{conf_display}</td>
          <td>{llm_spans}</td>
          <td>{tid_spans}</td>
          <td>{sub_spans}</td>
          {outcomes_cell}
        </tr>"""

    # Option B: Sankey-style SVG
    risk_tips = _risk_tips_lookup(entries)
    sankey_svg = _build_sankey_svg(entries, risk_tips=risk_tips)

    # Column widths for fixed table layout — vary with/without Outcomes column
    _rw, outcomes_th = _column_widths(has_outcomes)

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


def _sankey_columns(entries: list[dict[str, Any]]) -> list[list[str]]:
    """Collect the unique node names for each Sankey column, in order."""
    risk_ids: list[str] = []
    llm_ids_set: list[str] = []
    threat_ids_set: list[str] = []
    scenario_ids_set: list[str] = []

    for e in entries:
        rc = e.get("risk_card", {})
        _unique_append(risk_ids, rc.get("risk_id", ""))
        for lid in e.get("owasp_llm_ids", []):
            _unique_append(llm_ids_set, lid)
        for tid in e.get("agentic_threat_ids", []):
            _unique_append(threat_ids_set, tid)
        for ap_id in e.get("attack_pattern_ids", []):
            _unique_append(scenario_ids_set, ap_id)

    return [risk_ids, llm_ids_set, threat_ids_set, scenario_ids_set]


def _unique_append(lst: list[str], item: str) -> None:
    """Append *item* to *lst* once unless already present."""
    if item and item not in lst:
        lst.append(item)


def _sankey_node_y(
    columns: list[list[str]], svg_h: int, col_idx: int, item_idx: int
) -> float:
    """Vertical center of a node within its column."""
    col = columns[col_idx]
    total_h = len(col) * _SANKEY_NODE_H + (len(col) - 1) * _SANKEY_NODE_GAP
    start_y = _SANKEY_TOP_PAD + (svg_h - _SANKEY_TOP_PAD - 20 - total_h) / 2
    return start_y + item_idx * (_SANKEY_NODE_H + _SANKEY_NODE_GAP)


def _sankey_nodes_html(
    columns: list[list[str]],
    svg_h: int,
    node_pos: dict[str, tuple[float, float, float, float]],
    risk_tips: dict[str, str],
) -> str:
    """Build the SVG node groups for all columns."""
    svg_nodes = ""
    for ci, col in enumerate(columns):
        for ni, name in enumerate(col):
            x = _SANKEY_COL_X[ci]
            y = _sankey_node_y(columns, svg_h, ci, ni)
            node_pos[f"{ci}:{name}"] = (x, y, x + _SANKEY_NODE_W, y + _SANKEY_NODE_H)

            truncated = name if len(name) <= 20 else name[:17] + "..."
            tip = _esc(_node_tip(ci, name, risk_tips))
            svg_nodes += f"""
            <g class="sankey-node" data-tip="{tip}">
              <rect x="{x}" y="{y}" width="{_SANKEY_NODE_W}" height="{_SANKEY_NODE_H}"
                    fill="{_SANKEY_COLORS[ci]}" opacity="0.8"/>
              <text x="{x + _SANKEY_NODE_W / 2}" y="{y + _SANKEY_NODE_H / 2 + 4}"
                    text-anchor="middle" font-size="10" fill="white" font-weight="600"
                    pointer-events="none">
                {_esc(truncated)}
              </text>
            </g>"""
    return svg_nodes


def _risk_llm_links(
    node_pos: dict[str, tuple[float, float, float, float]],
    rid: str,
    llm_ids: list[str],
) -> str:
    """Build Risk -> LLM links for one entry."""
    links = ""
    for lid in llm_ids:
        links += _sankey_link(node_pos, f"0:{rid}", f"1:{lid}", _SANKEY_LINK_COLORS[0])
    return links


def _llm_threat_links(
    node_pos: dict[str, tuple[float, float, float, float]],
    llm_ids: list[str],
    threat_ids: list[str],
) -> str:
    """Build LLM -> Threat links for one entry."""
    links = ""
    for lid in llm_ids:
        for tid in threat_ids:
            links += _sankey_link(
                node_pos, f"1:{lid}", f"2:{tid}", _SANKEY_LINK_COLORS[1]
            )
    return links


def _threat_pattern_links(
    node_pos: dict[str, tuple[float, float, float, float]],
    threat_ids: list[str],
    pattern_ids: list[str],
) -> str:
    """Build Threat -> Attack Pattern links for one entry."""
    links = ""
    for tid in threat_ids:
        for ap_id in pattern_ids:
            links += _sankey_link(
                node_pos, f"2:{tid}", f"3:{ap_id}", _SANKEY_LINK_COLORS[2]
            )
    return links


def _sankey_links_html(
    entries: list[dict[str, Any]],
    node_pos: dict[str, tuple[float, float, float, float]],
) -> str:
    """Build all SVG links between consecutive columns."""
    svg_links = ""
    for e in entries:
        rc = e.get("risk_card", {})
        rid = rc.get("risk_id", "")
        llm_ids = e.get("owasp_llm_ids", [])
        threat_ids = e.get("agentic_threat_ids", [])
        pattern_ids = e.get("attack_pattern_ids", [])

        svg_links += _risk_llm_links(node_pos, rid, llm_ids)
        svg_links += _llm_threat_links(node_pos, llm_ids, threat_ids)
        svg_links += _threat_pattern_links(node_pos, threat_ids, pattern_ids)
    return svg_links


def _sankey_headers_html() -> str:
    """Build the SVG column header labels."""
    svg_headers = ""
    for ci, label in enumerate(_SANKEY_LABEL_NAMES):
        svg_headers += f"""
        <text x="{_SANKEY_COL_X[ci] + _SANKEY_NODE_W / 2}" y="30" text-anchor="middle"
              fill="var(--text-muted)" font-size="11" font-weight="600"
              text-transform="uppercase" letter-spacing="0.5">{_esc(label)}</text>"""
    return svg_headers


def _build_sankey_svg(
    entries: list[dict[str, Any]],
    risk_tips: dict[str, str] | None = None,
) -> str:
    """Build a pure SVG Sankey-style flow diagram."""
    if not entries:
        return '<p style="color:var(--text-muted);text-align:center;padding:40px;">No actionable entries to visualize.</p>'

    # Collect unique nodes for each column
    columns = _sankey_columns(entries)

    # Calculate total height
    max_nodes = max(len(c) for c in columns) if columns else 1
    svg_h = max(
        _SANKEY_TOP_PAD + max_nodes * (_SANKEY_NODE_H + _SANKEY_NODE_GAP) + 40, 200
    )

    # Build node positions
    node_pos: dict[str, tuple[float, float, float, float]] = {}
    svg_nodes = _sankey_nodes_html(columns, svg_h, node_pos, risk_tips or {})

    # Build links
    svg_links = _sankey_links_html(entries, node_pos)

    # Column headers
    svg_headers = _sankey_headers_html()

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
