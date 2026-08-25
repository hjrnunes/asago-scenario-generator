"""ATLAS technique scoping block for scenario cards."""

from __future__ import annotations

import re
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.provenance import (
    _ATLAS_TECHNIQUE_NAMES,
    _technique_id_tooltip,
)


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
    """Build separately labelled scenario and projected-step ATLAS scopes."""
    evidence = scenario.get("technique_scope_evidence") or {}
    scenario_ids = list(
        dict.fromkeys(
            evidence.get("scenario_classification_ids")
            or scenario.get("faceting", {})
            .get("taxonomy_chain", {})
            .get("atlas_technique_ids", [])
        )
    )
    mapping_ids = list(
        dict.fromkeys(
            evidence.get("projected_step_mapping_ids")
            or sorted(_collect_used_technique_ids(scenario, ""))
        )
    )
    if not scenario_ids and not mapping_ids:
        return ""

    def _badges(technique_ids: list[str]) -> str:
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
        return badges or '<span class="prov-badge prov-badge-muted">none</span>'

    return f"""
            <div style="font-size:11px;font-weight:700;margin-bottom:4px;">
              Scenario classifications
            </div>
            <div style="display:flex;flex-wrap:wrap;margin-bottom:10px;">
              {_badges(scenario_ids)}
            </div>
            <div style="font-size:11px;font-weight:700;margin-bottom:4px;">
              Projected-step mappings
            </div>
            <div style="display:flex;flex-wrap:wrap;">
              {_badges(mapping_ids)}
            </div>"""
