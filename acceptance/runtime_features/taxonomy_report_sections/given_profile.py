"""Given step handlers that assemble capability-profile fixtures."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from runtime_features.taxonomy_report import _split_csv

# Profile key names for the boolean flag steps (feature vocabulary -> model key).
_PROFILE_FLAG_KEYS: dict[str, str] = {
    "memory": "has_persistent_memory",
    "multi-agent": "multi_agent",
    "hitl": "hitl",
}


def _h_profile_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile declares active zones "A,B"."""
    match = re.search(r'the capability profile declares active zones "([^"]+)"', text)
    if not match:
        return False, f"Could not parse active-zones step: {text}"
    world.trpt_profile_data["zones_active"] = _split_csv(match.group(1))
    return True, ""


def _h_profile_degraded_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... declares active zone "Z" with no tool inventory, no external integrations, and no evidence."""
    match = re.search(
        r'the capability profile declares active zone "([^"]+)" with no tool '
        r"inventory, no external integrations, and no evidence",
        text,
    )
    if not match:
        return False, f"Could not parse degraded-profile step: {text}"
    world.trpt_profile_data = {
        "zones_active": [match.group(1)],
        "entry_points": [],
        "tool_inventory": [],
        "external_integrations": [],
        "entry_point_evidence": [],
        "tool_inventory_evidence": [],
    }
    return True, ""


def _h_profile_flags(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... declares the flag "F1" <on|off> and the flag "F2" <on|off> with confidence "C"."""
    match = re.search(
        r'the capability profile declares the flag "([^"]+)" (on|off) and the '
        r'flag "([^"]+)" (on|off) with confidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse flag step: {text}"
    name1, state1, name2, state2, confidence = match.groups()
    world.trpt_profile_data[_PROFILE_FLAG_KEYS[name1.lower()]] = state1 == "on"
    world.trpt_profile_data[_PROFILE_FLAG_KEYS[name2.lower()]] = state2 == "on"
    world.trpt_profile_data["confidence"] = confidence
    return True, ""


def _h_profile_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... lists entry point "E1" with direction "D1" and entry point "E2" with direction "D2"."""
    match = re.search(
        r'the capability profile lists entry point "([^"]+)" with direction '
        r'"([^"]+)"(?: and entry point "([^"]+)" with direction "([^"]+)")?',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point step: {text}"
    entries: list[dict[str, str]] = []
    if match.group(1):
        entries.append({"name": match.group(1), "direction": match.group(2)})
    if match.group(3):
        entries.append({"name": match.group(3), "direction": match.group(4)})
    world.trpt_profile_data["entry_points"] = entries
    return True, ""


def _h_profile_tool(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the tool "T" with tool id "ID"."""
    match = re.search(
        r'the capability profile lists the tool "([^"]+)" with tool id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool step: {text}"
    world.trpt_profile_data["tool_inventory"] = [
        {"name": match.group(1), "tool_id": match.group(2)}
    ]
    return True, ""


def _h_profile_integration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the integration "I" with integration id "ID"."""
    match = re.search(
        r'the capability profile lists the integration "([^"]+)" with '
        r'integration id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse integration step: {text}"
    world.trpt_profile_data["external_integrations"] = [
        {"name": match.group(1), "integration_id": match.group(2)}
    ]
    return True, ""


def _h_profile_ep_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... records entry point completeness "C" with evidence "E"."""
    match = re.search(
        r'the capability profile records entry point completeness "([^"]+)" '
        r'with evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point completeness step: {text}"
    world.trpt_profile_data["entry_point_completeness"] = match.group(1)
    world.trpt_profile_data["entry_point_evidence"] = [match.group(2)]
    return True, ""


def _h_profile_tool_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... records tool inventory completeness "C" with no evidence."""
    match = re.search(
        r'the capability profile records tool inventory completeness "([^"]+)" '
        r"with no evidence",
        text,
    )
    if not match:
        return False, f"Could not parse tool-inventory completeness step: {text}"
    world.trpt_profile_data["tool_inventory_completeness"] = match.group(1)
    world.trpt_profile_data["tool_inventory_evidence"] = []
    return True, ""


def _h_profile_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... declares the KC sub-code "K"."""
    match = re.search(
        r'the capability profile declares the KC sub-code "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse KC sub-code step: {text}"
    world.trpt_profile_data.setdefault("kc_subcodes", []).append(match.group(1))
    return True, ""


def register(api: Any) -> None:
    # --- Capability profile Given steps ---
    api.register(
        'the capability profile declares active zones "([^"]+)"',
        _h_profile_zones,
        source_order=7000,
    )
    api.register(
        'the capability profile declares active zone \\"([^\\"]+)\\" with no tool inventory, no external integrations, and no evidence',
        _h_profile_degraded_zone,
        source_order=7001,
    )
    api.register(
        'the capability profile declares the flag "([^"]+)" (on|off) and the flag "([^"]+)" (on|off) with confidence "([^"]+)"',
        _h_profile_flags,
        source_order=7002,
    )
    api.register(
        'the capability profile lists entry point "([^"]+)" with direction "([^"]+)"(?: and entry point "([^"]+)" with direction "([^"]+)")?',
        _h_profile_entry_points,
        source_order=7003,
    )
    api.register(
        'the capability profile lists the tool "([^"]+)" with tool id "([^"]+)"',
        _h_profile_tool,
        source_order=7004,
    )
    api.register(
        'the capability profile lists the integration "([^"]+)" with integration id "([^"]+)"',
        _h_profile_integration,
        source_order=7005,
    )
    api.register(
        'the capability profile records entry point completeness "([^"]+)" with evidence "([^"]+)"',
        _h_profile_ep_completeness,
        source_order=7006,
    )
    api.register(
        'the capability profile records tool inventory completeness "([^"]+)" with no evidence',
        _h_profile_tool_completeness,
        source_order=7007,
    )
    api.register(
        'the capability profile declares the KC sub-code "([^"]+)"',
        _h_profile_kc,
        source_order=7008,
    )
