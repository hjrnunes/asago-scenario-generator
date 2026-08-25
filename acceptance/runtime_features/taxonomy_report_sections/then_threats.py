"""Then step handlers asserting threat-surface table rows and badges."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _resolve


def _threats_region(world: World) -> str:
    return _section_region(_html(world), "sec-threats")


def _h_ts_entry_row_values(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the status badge "S" and the row values ... ."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)" '
        r"and the row values \"([^\"]+)\", \"([^\"]+)\", \"([^\"]+)\", \"([^\"]+)\", and \"([^\"]+)\"",
        text,
    )
    if not match:
        return False, f"Could not parse entry-row assertion: {text}"
    risk_id, status, value1, value2, value3, value4, value5 = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    badge = "status-actionable" if status == "ACT" else "status-governance"
    ok = f"status-badge {badge}" in row
    for value in (value1, value2, value3, value4, value5):
        ok = ok and f">{value}" in row
    return _resolve(
        ok,
        f"row {risk_id!r} status={status} values={value1} {value2} {value3} {value4} {value5}",
    )


def _h_ts_entry_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the status badge "S"."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse entry-status assertion: {text}"
    risk_id, status = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    badge = "status-actionable" if status == "ACT" else "status-governance"
    return _resolve(f"status-badge {badge}" in row, f"status={status}")


def _h_ts_governance_placeholder(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry shows the placeholder "-" for the OWASP LLM IDs, agentic threats, and attack patterns."""
    region = _threats_region(world)
    gov_start = region.find("status-governance")
    if gov_start == -1:
        return _resolve(False, "no governance-only row rendered")
    gov_row = region[gov_start : region.find("</tr>", gov_start)]
    return _resolve(
        gov_row.count("-") >= 3, f"governance row placeholders={gov_row.count('-')}"
    )


def _h_ts_message(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface shows the message "M"."""
    match = re.search(r'the threat surface shows the message "([^"]+)"', text)
    if not match:
        return False, f"Could not parse threat-surface message: {text}"
    return _resolve(
        match.group(1) in _threats_region(world), f"message={match.group(1)!r}"
    )


def _h_ts_outcomes_column(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface table shows the "Outcomes" column."""
    return _resolve(
        ">Outcomes</th>" in _threats_region(world), "Outcomes column missing"
    )


def _h_ts_outcomes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the outcomes "O" with the chip "C"."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the outcomes "([^"]+)" '
        r'with the chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse outcomes assertion: {text}"
    risk_id, outcomes, chip = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    ok = f">{outcomes}" in row and chip in row
    return _resolve(ok, f"outcomes={outcomes} chip={chip}")


def _h_ts_count_badge(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the count badge "N threats|patterns"."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the count badge '
        r'"(\d+) (threats|patterns)"',
        text,
    )
    if not match:
        return False, f"Could not parse count-badge assertion: {text}"
    risk_id, count, kind = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    ok = 'class="count-badge"' in row and f">{count} {kind}</span>" in row
    return _resolve(ok, f"count badge {count} {kind} missing for {risk_id!r}")


def _h_ts_sankey_node_tip(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface flow diagram node for "R" carries the tip "T"."""
    match = re.search(
        r'the threat surface flow diagram node for "([^"]+)" carries the '
        r'tip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse sankey-tip assertion: {text}"
    node_id, tip = match.groups()
    region = _threats_region(world)
    return _resolve(
        f'data-tip="{tip}"' in region,
        f"sankey node {node_id!r} tip {tip!r} missing",
    )


def register(api: Any) -> None:
    # --- Threat surface Then steps ---
    api.register(
        'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)" and the row values .+$',
        _h_ts_entry_row_values,
        source_order=8010,
    )
    api.register(
        'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)"$',
        _h_ts_entry_status,
        source_order=8011,
    )
    api.register(
        'the governance-only entry shows the placeholder "-" for the OWASP LLM IDs, agentic threats, and attack patterns',
        _h_ts_governance_placeholder,
        source_order=8012,
    )
    api.register(
        'the threat surface shows the message "([^"]+)"',
        _h_ts_message,
        source_order=8013,
    )
    api.register(
        'the threat surface table shows the "Outcomes" column',
        _h_ts_outcomes_column,
        source_order=8014,
    )
    api.register(
        'the threat surface entry for "([^"]+)" shows the outcomes "([^"]+)" with the chip "([^"]+)"',
        _h_ts_outcomes,
        source_order=8015,
    )
    api.register(
        'the threat surface entry for "([^"]+)" shows the count badge "\\d+ (?:threats|patterns)"',
        _h_ts_count_badge,
        source_order=8075,
    )
    api.register(
        'the threat surface flow diagram node for "([^"]+)" carries the tip "([^"]+)"',
        _h_ts_sankey_node_tip,
        source_order=8076,
    )
