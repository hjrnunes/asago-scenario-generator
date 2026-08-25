"""Then step handlers asserting the coverage cards, plan, and universe."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _resolve


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


def _h_ts_coverage_card_containing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the "Card" card containing "Item"."""
    match = re.search(
        r'the coverage section shows the "([^"]+)" card containing "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-card-containing assertion: {text}"
    card, item = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    card_start = region.find(f">{card}</span>")
    if card_start == -1:
        return _resolve(False, f"coverage card {card!r} is not rendered")
    card_body = region[card_start : card_start + 4000]
    return _resolve(
        item in card_body, f"item {item!r} missing from coverage card {card!r}"
    )


def _h_ts_coverage_card_entry_detail(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the "Card" card with the entry "E", the reason "R", the detail "D", and the candidate "C"."""
    match = re.search(
        r'the coverage section shows the "([^"]+)" card with the entry '
        r'"([^"]+)", the reason "([^"]+)", the detail "([^"]+)", and the '
        r'candidate "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-card-entry detail: {text}"
    card, entry, reason, detail, candidate = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    card_start = region.find(f">{card}</span>")
    if card_start == -1:
        return _resolve(False, f"coverage card {card!r} is not rendered")
    card_body = region[card_start : card_start + 4000]
    ok = all(value in card_body for value in (entry, reason, detail, candidate))
    return _resolve(
        ok,
        f"coverage card {card!r} entry={entry} reason={reason} detail={detail} candidate={candidate}",
    )


def _h_ts_coverage_card_entry_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the "Card" card with the entry "E" and the reason "R"."""
    match = re.search(
        r'the coverage section shows the "([^"]+)" card with the entry '
        r'"([^"]+)" and the reason "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-card-entry reason: {text}"
    card, entry, reason = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    card_start = region.find(f">{card}</span>")
    if card_start == -1:
        return _resolve(False, f"coverage card {card!r} is not rendered")
    card_body = region[card_start : card_start + 4000]
    ok = entry in card_body and reason in card_body
    return _resolve(ok, f"coverage card {card!r} entry={entry} reason={reason}")


def _h_ts_coverage_plan_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows a "Coverage Plan" row for "E" with primary candidate "C" and state "S"."""
    match = re.search(
        r'the coverage section shows a "Coverage Plan" row for "([^"]+)" with '
        r'primary candidate "([^"]+)" and state "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-plan row assertion: {text}"
    entry, primary, state = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    plan_start = region.find("Coverage Plan (schema v1)")
    if plan_start == -1:
        return _resolve(False, "coverage plan table is not rendered")
    plan_body = region[plan_start : plan_start + 4000]
    ok = entry in plan_body and primary in plan_body and f">{state}</td>" in plan_body
    return _resolve(
        ok, f"coverage plan row entry={entry} primary={primary} state={state}"
    )


def _h_ts_coverage_universe_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage universe card shows inventory completeness "C" (no evidence clause)."""
    match = re.search(
        r'the coverage universe card shows inventory completeness "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse universe-completeness assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    return _resolve(
        match.group(1) in region, f"universe completeness={match.group(1)!r}"
    )


def _h_ts_coverage_universe_message(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage universe card shows the message "M"."""
    match = re.search(r'the coverage universe card shows the message "([^"]+)"', text)
    if not match:
        return False, f"Could not parse universe-message assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    return _resolve(match.group(1) in region, f"universe message={match.group(1)!r}")


def register(api: Any) -> None:
    # --- Coverage cards / plan / universe Then steps ---
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
        'the coverage section shows the "([^"]+)" card containing "([^"]+)"',
        _h_ts_coverage_card_containing,
        source_order=8077,
    )
    api.register(
        'the coverage section shows the "([^"]+)" card with the entry "([^"]+)", the reason "([^"]+)", the detail "([^"]+)", and the candidate "([^"]+)"',
        _h_ts_coverage_card_entry_detail,
        source_order=8078,
    )
    api.register(
        'the coverage section shows the "([^"]+)" card with the entry "([^"]+)" and the reason "([^"]+)"$',
        _h_ts_coverage_card_entry_reason,
        source_order=8079,
    )
    api.register(
        'the coverage section shows a "Coverage Plan" row for "([^"]+)" with primary candidate "([^"]+)" and state "([^"]+)"',
        _h_ts_coverage_plan_row,
        source_order=8080,
    )
    api.register(
        'the coverage universe card shows inventory completeness "([^"]+)"$',
        _h_ts_coverage_universe_completeness,
        source_order=8081,
    )
    api.register(
        'the coverage universe card shows the message "([^"]+)"',
        _h_ts_coverage_universe_message,
        source_order=8082,
    )
