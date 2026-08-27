"""Then step handlers asserting the capability profile and section badges."""

from __future__ import annotations

import re
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from runtime_world import World
from ._helpers import _html, _section_region, _resolve


def _profile_region(world: World) -> str:
    return _section_region(_html(world), "sec-profile")


def _h_ts_section_with_badge(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a "Section" section with the badge ... ."""
    match = re.search(
        r'the report contains an? "([^"]+)" section with the badge (.+)$', text
    )
    if not match:
        return False, f"Could not parse section-badge step: {text}"
    section_name, badges_phrase = match.groups()
    h2 = {
        "Threat–Technique Matrix": "Threat&ndash;Technique Matrix",
    }.get(section_name, section_name)
    html = _html(world)
    if f"<h2>{h2}</h2>" not in html:
        return _resolve(False, f"section {section_name!r} is not rendered")
    for badge in re.findall(r'"([^"]+)"', badges_phrase):
        if badge not in html:
            return _resolve(False, f"badge {badge!r} is not rendered")
    return _resolve(True, "")


def _h_ts_profile_zone_chips(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows an active zone chip "A" and an inactive zone chip "I"."""
    match = re.search(
        r'the capability profile shows an active zone chip "([^"]+)" and an '
        r'inactive zone chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse zone-chip step: {text}"
    active, inactive = match.groups()
    region = _profile_region(world)
    active_texts = re.findall(
        r'<span class="zone-chip active"[^>]*>(.*?)</span>', region, re.S
    )
    inactive_texts = re.findall(
        r'<span class="zone-chip inactive"[^>]*>(.*?)</span>', region, re.S
    )
    ok = _esc(active) in [t.strip() for t in active_texts]
    ok = ok and _esc(inactive) in [t.strip() for t in inactive_texts]
    return _resolve(ok, f"zone chips active={active_texts} inactive={inactive_texts}")


def _h_ts_profile_flags(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the flag "F1" <on|off>, the flag "F2" <on|off>, and confidence "C"."""
    match = re.search(
        r'the capability profile shows the flag "([^"]+)" (on|off), the flag '
        r'"([^"]+)" (on|off), and confidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse flag assertion: {text}"
    name1, state1, name2, state2, confidence = match.groups()
    region = _profile_region(world)
    flags = region[region.find("Capability Flags") :]
    chips = re.findall(
        r'<span class="flag-dot (on|off)"></span>\s*'
        r'<span class="flag-label">([^<]+)</span>',
        flags,
    )
    by_name = {name: state for state, name in chips}
    ok = by_name.get(name1) == state1 and by_name.get(name2) == state2
    ok = ok and "Confidence:" in flags and confidence.capitalize() in flags
    return _resolve(ok, f"flag chips={chips} confidence={confidence!r}")


def _h_ts_profile_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows entry point "E1" with input direction and entry point "E2" with bidirectional direction."""
    match = re.search(
        r"the capability profile shows entry point \"([^\"]+)\" with input "
        r'direction and entry point "([^"]+)" with bidirectional direction',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point assertion: {text}"
    ep_input, ep_bidi = match.groups()
    region = _profile_region(world)
    ok = (
        'class="ep-direction" title="input">←</span>' in region
        and ep_input in region
        and 'class="ep-direction" title="bidirectional">↔</span>' in region
        and ep_bidi in region
    )
    return _resolve(ok, f"entry points input={ep_input!r} bidirectional={ep_bidi!r}")


def _h_ts_profile_tools_integrations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows tool "T" with tool id "TI" and integration "I" with integration id "II"."""
    match = re.search(
        r'the capability profile shows tool "([^"]+)" with tool id "([^"]+)" '
        r'and integration "([^"]+)" with integration id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool/integration assertion: {text}"
    tool, tool_id, integration, integration_id = match.groups()
    region = _profile_region(world)
    ok = all(value in region for value in (tool, tool_id, integration, integration_id))
    return _resolve(
        ok, f"tools={tool} {tool_id} integrations={integration} {integration_id}"
    )


def _h_ts_profile_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows entry point completeness "C" with the evidence "E"."""
    match = re.search(
        r'the capability profile shows entry point completeness "([^"]+)" with '
        r'the evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse completeness assertion: {text}"
    completeness, evidence = match.groups()
    region = _profile_region(world)
    ok = f">{completeness}</span>" in region and evidence in region
    return _resolve(ok, f"completeness={completeness} evidence={evidence}")


def _h_ts_profile_tool_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows tool inventory completeness "C" and the message "M"."""
    match = re.search(
        r'the capability profile shows tool inventory completeness "([^"]+)" '
        r'and the message "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool-completeness assertion: {text}"
    completeness, message = match.groups()
    region = _profile_region(world)
    ok = f">{completeness}</span>" in region and message in region
    return _resolve(ok, f"tool completeness={completeness} message={message}")


def _h_ts_profile_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the KC sub-code badge "K"."""
    match = re.search(
        r'the capability profile shows the KC sub-code badge "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse KC badge assertion: {text}"
    region = _profile_region(world)
    ok = 'class="kc-badge' in region and match.group(1) in region
    return _resolve(ok, f"kc badge={match.group(1)!r}")


def _h_ts_profile_message(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the message "M"."""
    match = re.search(r'the capability profile shows the message "([^"]+)"', text)
    if not match:
        return False, f"Could not parse profile-message assertion: {text}"
    return _resolve(
        match.group(1) in _profile_region(world), f"message={match.group(1)!r}"
    )


def _h_ts_no_entry_point_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile renders no entry point row."""
    region = _profile_region(world)
    ok = "ep-direction" not in region and ">Entry Points</div>" not in region
    return _resolve(ok, "entry point row still rendered")


def register(api: Any) -> None:
    # --- Capability profile / section badge Then steps ---
    api.register(
        'the report contains an? "([^"]+)" section with the badge .+$',
        _h_ts_section_with_badge,
        source_order=8000,
    )
    api.register(
        'the capability profile shows an active zone chip "([^"]+)" and an inactive zone chip "([^"]+)"',
        _h_ts_profile_zone_chips,
        source_order=8001,
    )
    api.register(
        'the capability profile shows the flag "([^"]+)" (on|off), the flag "([^"]+)" (on|off), and confidence "([^"]+)"',
        _h_ts_profile_flags,
        source_order=8002,
    )
    api.register(
        'the capability profile shows entry point "([^"]+)" with input direction and entry point "([^"]+)" with bidirectional direction',
        _h_ts_profile_entry_points,
        source_order=8003,
    )
    api.register(
        'the capability profile shows tool "([^"]+)" with tool id "([^"]+)" and integration "([^"]+)" with integration id "([^"]+)"',
        _h_ts_profile_tools_integrations,
        source_order=8004,
    )
    api.register(
        'the capability profile shows entry point completeness "([^"]+)" with the evidence "([^"]+)"',
        _h_ts_profile_completeness,
        source_order=8005,
    )
    api.register(
        'the capability profile shows tool inventory completeness "([^"]+)" and the message "([^"]+)"',
        _h_ts_profile_tool_completeness,
        source_order=8006,
    )
    api.register(
        'the capability profile shows the KC sub-code badge "([^"]+)"',
        _h_ts_profile_kc,
        source_order=8007,
    )
    api.register(
        'the capability profile shows the message "([^"]+)"',
        _h_ts_profile_message,
        source_order=8008,
    )
    api.register(
        "the capability profile renders no entry point row",
        _h_ts_no_entry_point_row,
        source_order=8009,
    )
