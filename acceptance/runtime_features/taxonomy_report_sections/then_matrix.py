"""Then step handlers asserting the threat-technique matrix and scenario roster."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _visible, _resolve


def _h_ts_matrix_cell(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the matrix shows for threat "T" a count of N for technique "A" linking to scenario "S"."""
    match = re.search(
        r'the matrix shows for threat "([^"]+)" a count of (\d+) for technique '
        r'"([^"]+)" linking to scenario "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse matrix-cell assertion: {text}"
    threat, count, technique, scenario = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    ok = 'class="matrix-count-link"' in region
    ok = ok and f'href="#scenario-{scenario}"' in region
    ok = ok and f">{count}</a>" in region
    ok = ok and technique in region
    return _resolve(
        ok,
        f"cell threat={threat} count={count} technique={technique} scenario={scenario}",
    )


def _h_ts_no_tech_headers(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the matrix shows no technique column headers."""
    region = _section_region(_html(world), "sec-threat-matrix")
    return _resolve(
        "matrix-col-header" not in region, "technique headers still rendered"
    )


def _h_ts_roster_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the roster row for "S" shows threat "T", attack pattern "P", technique "A", actor type "AT", and capability "C"."""
    match = re.search(
        r'the roster row for "([^"]+)" shows threat "([^"]+)", attack pattern '
        r'"([^"]+)", technique "([^"]+)", actor type "([^"]+)", and capability "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse roster-row assertion: {text}"
    sid, threat, pattern, technique, actor_type, capability = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find(sid)
    if row_start == -1:
        return _resolve(False, f"roster row {sid!r} is not rendered")
    row = roster[row_start : roster.find("</tr>", row_start)]
    visible = _visible(row)
    ok = all(
        value in visible
        for value in (threat, pattern, technique, actor_type, capability)
    )
    return _resolve(ok, f"roster {sid} row={visible}")


def _h_ts_roster_no_technique(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the roster row for "S" shows the attack pattern "P" with no technique value."""
    match = re.search(
        r'the roster row for "([^"]+)" shows the attack pattern "([^"]+)" with '
        r"no technique value",
        text,
    )
    if not match:
        return False, f"Could not parse roster-no-technique assertion: {text}"
    sid, pattern = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find(sid)
    if row_start == -1:
        return _resolve(False, f"roster row {sid!r} is not rendered")
    row = roster[row_start : roster.find("</tr>", row_start)]
    ok = pattern in row and "AML." not in row
    return _resolve(ok, f"roster {sid} technique cell not empty")


def _h_ts_matrix_tech_headers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the matrix shows technique column headers for "A" and "B"."""
    match = re.search(
        r'the matrix shows technique column headers for "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse matrix-header assertion: {text}"
    region = _section_region(_html(world), "sec-threat-matrix")
    ok = "matrix-col-header" in region
    ok = ok and f'class="matrix-col-header-text">{match.group(1)}</span>' in region
    ok = ok and f'class="matrix-col-header-text">{match.group(2)}</span>' in region
    return _resolve(ok, f"matrix headers={match.groups()}")


def register(api: Any) -> None:
    # --- Matrix and roster Then steps ---
    api.register(
        'the matrix shows for threat "([^"]+)" a count of (\\d+) for technique "([^"]+)" linking to scenario "([^"]+)"',
        _h_ts_matrix_cell,
        source_order=8023,
    )
    api.register(
        "the matrix shows no technique column headers",
        _h_ts_no_tech_headers,
        source_order=8024,
    )
    api.register(
        'the roster row for "([^"]+)" shows threat "([^"]+)", attack pattern "([^"]+)", technique "([^"]+)", actor type "([^"]+)", and capability "([^"]+)"',
        _h_ts_roster_row,
        source_order=8025,
    )
    api.register(
        'the roster row for "([^"]+)" shows the attack pattern "([^"]+)" with no technique value',
        _h_ts_roster_no_technique,
        source_order=8026,
    )
    api.register(
        'the matrix shows technique column headers for "([^"]+)" and "([^"]+)"',
        _h_ts_matrix_tech_headers,
        source_order=8083,
    )
