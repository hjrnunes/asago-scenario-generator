"""Generation-inputs sub-table builders for scenario cards."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    _technique_id_tooltip,
    _threat_id_tooltip,
)


def _gen_value_html(v: Any, join_sep: str = "; ") -> str:
    """Format a value for display. Lists are joined; None/empty -> em dash."""
    if v is None:
        return "—"
    if isinstance(v, list):
        if not v:
            return "—"
        return join_sep.join(str(item) for item in v)
    return str(v) if v else "—"


def _gen_row_html(
    label: str, value: str, *, hint: bool = False, tooltip: str = ""
) -> str:
    """Build a single generation-inputs table row (hint renders italic)."""
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


def _gen_threat_html(tid: str, tname: str) -> str:
    """Threat ID with tooltip and name."""
    if not tid:
        return "—"
    tip = _threat_id_tooltip(tid)
    label = f"{_esc(tid)} — {_esc(tname)}" if tname else _esc(tid)
    return f"<span{tip}>{label}</span>"


def _gen_techniques_html(ids: list[str] | None) -> str:
    """ATLAS technique IDs with tooltips."""
    if not ids:
        return "—"
    parts = []
    for tid in ids:
        tip = _technique_id_tooltip(tid)
        parts.append(f"<span{tip}>{_esc(tid)}</span>")
    return "; ".join(parts)


def _gen_call_header(idx: int, name: str) -> str:
    """Render a grouped sub-table header for one LLM call."""
    return (
        f'<div style="font-size:11px;font-weight:700;'
        f"color:var(--text-muted);text-transform:uppercase;"
        f"letter-spacing:0.5px;margin:14px 0 4px;"
        f'padding-bottom:3px;border-bottom:1px solid var(--border);">'
        f"Call {idx}: {_esc(name)}</div>"
    )


def _gen_table_html(rows: str) -> str:
    """Wrap generation-input rows in a collapsed table."""
    return (
        f'<table style="width:100%;border-collapse:collapse;'
        f'margin-bottom:4px;">{rows}</table>'
    )


def _gen_source_dict(scenario: dict[str, Any], key: str) -> dict[str, Any]:
    """Return the scenario sub-dict for *key*, or an empty dict."""
    return scenario.get(key) or {}


def _build_generation_inputs_block(scenario: dict[str, Any]) -> str:
    """Build a Generation Inputs expandable section showing every datum
    that participates in scenario generation, organized by LLM call.

    Returns an HTML block with four grouped sub-tables (one per LLM call)
    in vertical key-value layout.
    """
    meta = _gen_source_dict(scenario, "scenario_seed_metadata")
    actor = _gen_source_dict(scenario, "actor_profile")
    narrative = _gen_source_dict(scenario, "narrative")
    attack_tree = _gen_source_dict(scenario, "attack_tree")
    faceting = _gen_source_dict(scenario, "faceting")
    tc = _gen_source_dict(faceting, "taxonomy_chain")
    cp = _gen_source_dict(faceting, "capability_profile")

    # --- shared values ---
    attack_pattern = _gen_value_html(
        meta.get("attack_pattern_name") or meta.get("mechanism_name")
    )
    attack_pattern_desc = _gen_value_html(
        meta.get("attack_pattern_description") or meta.get("mechanism_description")
    )
    threat_html = _gen_threat_html(
        meta.get("threat_id", ""), meta.get("threat_name", "")
    )
    zones_html = _gen_value_html(cp.get("zones_traversed"))
    atlas_html = _gen_techniques_html(tc.get("atlas_technique_ids"))
    goal_cat = actor.get("goal_category", "")
    goal_name = actor.get("goal_category_name", "")
    goal_parent = actor.get("goal_category_parent", "")
    goal_display = (
        f"{_esc(goal_name)} ({_esc(goal_cat)})"
        if goal_name
        else _gen_value_html(goal_cat)
    )

    # ---- Call 0: Actor Profile ----
    call0_rows = "".join(
        [
            _gen_row_html("Attack pattern", attack_pattern),
            _gen_row_html("Attack pattern description", attack_pattern_desc),
            _gen_row_html("Threat", threat_html),
            _gen_row_html("System zones", zones_html),
            _gen_row_html("ATLAS techniques", atlas_html),
            _gen_row_html("Attack goal", goal_display),
            _gen_row_html("Attack goal category", _gen_value_html(goal_parent)),
            _gen_row_html(
                "Diversity hint: preferred actor type",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
            _gen_row_html(
                "Diversity hint: excluded actor types",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
        ]
    )

    # ---- Call 1: Narrative ----
    owasp_html = _gen_value_html(tc.get("owasp_llm_ids"))
    call1_rows = "".join(
        [
            _gen_row_html("Attack pattern", attack_pattern),
            _gen_row_html("Attack pattern description", attack_pattern_desc),
            _gen_row_html("Threat", threat_html),
            _gen_row_html("System zones", zones_html),
            _gen_row_html("Entry point", _gen_value_html(cp.get("entry_point"))),
            _gen_row_html("OWASP LLM IDs", owasp_html),
            _gen_row_html("ATLAS techniques", atlas_html),
            _gen_row_html("Actor type", _gen_value_html(actor.get("actor_type"))),
            _gen_row_html(
                "Capability level", _gen_value_html(actor.get("capability_level"))
            ),
            _gen_row_html("Beliefs", _gen_value_html(actor.get("beliefs"))),
            _gen_row_html("Desires", _gen_value_html(actor.get("desires"))),
            _gen_row_html("Intentions", _gen_value_html(actor.get("intentions"))),
            _gen_row_html("Resources", _gen_value_html(actor.get("resources"))),
            _gen_row_html("Attack goal", goal_display),
            _gen_row_html("Attack goal category", _gen_value_html(goal_parent)),
            _gen_row_html(
                "Diversity hint: preferred entry point",
                '<span style="color:var(--text-muted);font-style:italic;">'
                "not captured in output</span>",
                hint=True,
            ),
            _gen_row_html(
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
            _gen_row_html("Attack pattern", attack_pattern),
            _gen_row_html("Threat", threat_html),
            _gen_row_html("System zones", zones_html),
            _gen_row_html("ATLAS techniques", atlas_html),
            _gen_row_html("Actor type", _gen_value_html(actor.get("actor_type"))),
            _gen_row_html(
                "Capability level", _gen_value_html(actor.get("capability_level"))
            ),
            _gen_row_html("Narrative title", _gen_value_html(narrative.get("title"))),
            _gen_row_html(
                "Narrative summary", _gen_value_html(narrative.get("summary"))
            ),
            _gen_row_html("Entry point", _gen_value_html(narrative.get("entry_point"))),
            _gen_row_html(
                "Zone sequence", _gen_value_html(narrative.get("zone_sequence"))
            ),
        ]
    )

    # ---- Call 3: Behavior Spec ----
    call3_rows = "".join(
        [
            _gen_row_html("Narrative title", _gen_value_html(narrative.get("title"))),
            _gen_row_html("Entry point", _gen_value_html(narrative.get("entry_point"))),
            _gen_row_html(
                "Zone sequence", _gen_value_html(narrative.get("zone_sequence"))
            ),
            _gen_row_html("Attack tree goal", _gen_value_html(attack_tree.get("goal"))),
            _gen_row_html("Actor type", _gen_value_html(actor.get("actor_type"))),
            _gen_row_html(
                "Capability level", _gen_value_html(actor.get("capability_level"))
            ),
        ]
    )

    content = (
        _gen_call_header(0, "Actor Profile")
        + _gen_table_html(call0_rows)
        + _gen_call_header(1, "Narrative")
        + _gen_table_html(call1_rows)
        + _gen_call_header(2, "Attack Tree")
        + _gen_table_html(call2_rows)
        + _gen_call_header(3, "Behavior Spec")
        + _gen_table_html(call3_rows)
    )

    return f'<div style="padding:12px 0 4px;">{content}</div>'
