"""Then step handlers asserting threat-surface rows, coverage cards, the matrix, roster, and actor distribution."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _visible, _resolve


def _threats_region(world: World) -> str:
    return _section_region(_html(world), "sec-threats")


def _coverage_card_statuses(region: str) -> dict[str, str]:
    """Return coverage-card title -> status label."""
    return {
        title: status
        for title, status in re.findall(
            r'<span class="coverage-card-title">([^<]+)</span>\s*'
            r'<span class="coverage-status [\w-]+">([^<]+)</span>',
            region,
        )
    }


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


def _h_ts_coverage_cards(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage cards "A", "B", "C", and "D" each show the status "S"."""
    match = re.search(
        r'the coverage cards "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)" '
        r'each show the status "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-cards assertion: {text}"
    cards = match.groups()[:4]
    status = match.group(5)
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    ok = all(statuses.get(card) == status for card in cards)
    return _resolve(ok, f"card statuses={statuses}")


def _h_ts_coverage_messages(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the messages "A", "B", "C", and "D"."""
    match = re.search(
        r'the coverage section shows the messages "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-messages assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = all(message in region for message in match.groups())
    return _resolve(ok, f"messages={match.groups()}")


def _h_ts_coverage_universe(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage universe card shows inventory completeness "C" with the evidence "E"."""
    match = re.search(
        r'the coverage universe card shows inventory completeness "([^"]+)" '
        r'with the evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-universe assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = match.group(1) in region and match.group(2) in region
    return _resolve(ok, f"universe={match.group(1)} evidence={match.group(2)}")


def _h_ts_sidebar_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the sidebar shows a link to the "Section" section."""
    match = re.search(r'the sidebar shows a link to the "([^"]+)" section', text)
    if not match:
        return False, f"Could not parse sidebar-link assertion: {text}"
    href = {
        "Coverage Analysis": "#sec-coverage",
        "Run Summary": "#sec-run-summary",
        "Eval Scorecard": "#sec-scorecard",
    }.get(match.group(1))
    if href is None:
        return False, f"Unknown sidebar section {match.group(1)!r}"
    return _resolve(href in _html(world), f"sidebar link {href} missing")


def _h_ts_coverage_card_attribution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage card "C" shows the status "S" and the uncovered entry point "E" with the attribution "A"."""
    match = re.search(
        r'the coverage card "([^"]+)" shows the status "([^"]+)" and the '
        r'uncovered entry point "([^"]+)" with the attribution "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-attribution assertion: {text}"
    card, status, entry_point, attribution = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    if statuses.get(card) != status:
        return _resolve(False, f"card {card} status={statuses.get(card)}")
    card_start = region.find(f">{card}</span>")
    card_body = region[card_start : card_start + 2000]
    ok = entry_point in card_body and attribution in card_body
    return _resolve(ok, f"entry point {entry_point} attribution={attribution}")


def _h_ts_coverage_card_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage card "C" shows the status "S" (single card)."""
    match = re.search(r'the coverage card "([^"]+)" shows the status "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse coverage-card assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    return _resolve(
        statuses.get(match.group(1)) == match.group(2), f"statuses={statuses}"
    )


def _h_ts_coverage_cards_pair(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the "A" and "B" cards."""
    match = re.search(
        r'the coverage section shows the "([^"]+)" and "([^"]+)" cards', text
    )
    if not match:
        return False, f"Could not parse coverage-card-pair assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = match.group(1) in region and match.group(2) in region
    return _resolve(ok, f"cards={match.group(1)} {match.group(2)}")


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


def _h_ts_diversity_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the distribution shows the actor type "T" with the count N and P percent."""
    match = re.search(
        r'the distribution shows the actor type "([^"]+)" with the count (\d+) '
        r"and (\d+) percent",
        text,
    )
    if not match:
        return False, f"Could not parse diversity-type assertion: {text}"
    actor_type, count, percent = match.groups()
    region = _section_region(_html(world), "sec-diversity")
    bars = re.findall(
        r'<span class="diversity-bar-label">([^<]+)</span>.*?'
        r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>.*?'
        r'<span class="diversity-bar-count">([^<]+)</span>',
        region,
        re.S,
    )
    matched = [bar for bar in bars if bar[0] == actor_type]
    ok = bool(matched) and matched[0][1] == count and percent in matched[0][2]
    return _resolve(ok, f"diversity bars={bars}")


def _h_ts_diversity_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the distribution shows the warning "W"."""
    match = re.search(r'the distribution shows the warning "([^"]+)"', text)
    if not match:
        return False, f"Could not parse diversity-warning assertion: {text}"
    region = _section_region(_html(world), "sec-diversity")
    return _resolve(match.group(1) in _visible(region), f"warning={match.group(1)!r}")


def _h_ts_diversity_goal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the distribution shows the goal category "G" with the count N."""
    match = re.search(
        r'the distribution shows the goal category "([^"]+)" with the count (\d+)',
        text,
    )
    if not match:
        return False, f"Could not parse diversity-goal assertion: {text}"
    goal, count = match.groups()
    region = _section_region(_html(world), "sec-diversity")
    goal_region = region[region.find("Goal Category Distribution") :]
    bars = re.findall(
        r'<span class="diversity-bar-label">([^<]+)</span>.*?'
        r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>',
        goal_region,
        re.S,
    )
    ok = (goal, count) in bars
    return _resolve(ok, f"goal bars={bars}")


def register(api: Any) -> None:
    # --- Threat surface / coverage / matrix / roster / diversity Then steps ---
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
        'the coverage cards "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)" each show the status "([^"]+)"',
        _h_ts_coverage_cards,
        source_order=8016,
    )
    api.register(
        'the coverage section shows the messages "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_coverage_messages,
        source_order=8017,
    )
    api.register(
        'the coverage universe card shows inventory completeness "([^"]+)" with the evidence "([^"]+)"',
        _h_ts_coverage_universe,
        source_order=8018,
    )
    api.register(
        'the sidebar shows a link to the "([^"]+)" section',
        _h_ts_sidebar_link,
        source_order=8019,
    )
    api.register(
        'the coverage card "([^"]+)" shows the status "([^"]+)" and the uncovered entry point "([^"]+)" with the attribution "([^"]+)"',
        _h_ts_coverage_card_attribution,
        source_order=8020,
    )
    api.register(
        'the coverage card "([^"]+)" shows the status "([^"]+)"$',
        _h_ts_coverage_card_status,
        source_order=8021,
    )
    api.register(
        'the coverage section shows the "([^"]+)" and "([^"]+)" cards',
        _h_ts_coverage_cards_pair,
        source_order=8022,
    )
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
        'the distribution shows the actor type "([^"]+)" with the count (\\d+) and (\\d+) percent',
        _h_ts_diversity_type,
        source_order=8027,
    )
    api.register(
        'the distribution shows the warning "([^"]+)"',
        _h_ts_diversity_warning,
        source_order=8028,
    )
    api.register(
        'the distribution shows the goal category "([^"]+)" with the count (\\d+)',
        _h_ts_diversity_goal,
        source_order=8029,
    )
