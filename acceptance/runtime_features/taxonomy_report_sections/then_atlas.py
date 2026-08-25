"""Then step handlers asserting the ATLAS Techniques and Actor Profile tab details."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _card_region, _section_region, _visible, _resolve


def _h_ts_atlas_classifications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab of scenario "S" shows the heading "Scenario classifications" with the badge "B"."""
    match = re.search(
        r'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading '
        r'"Scenario classifications" with the badge "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-classifications assertion: {text}"
    sid, badge = match.groups()
    region = _card_region(_html(world), sid)
    block = region[
        region.find("Scenario classifications") : region.find("Projected-step mappings")
    ]
    return _resolve(
        "Scenario classifications" in region and badge in block, f"badge={badge}"
    )


def _h_ts_atlas_none(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab shows the heading "Projected-step mappings" with the placeholder "none"."""
    match = re.search(
        r'the ATLAS Techniques tab shows the heading "([^"]+)" with the '
        r'placeholder "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-none assertion: {text}"
    heading, placeholder = match.groups()
    html = _html(world)
    ok = heading in html
    ok = ok and f'class="prov-badge prov-badge-muted">{placeholder}</span>' in html
    return _resolve(ok, f"heading={heading} placeholder={placeholder}")


def _h_ts_complexity_heading(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows the heading "ATTACK COMPLEXITY (RULE V3):"."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-heading assertion: {text}"
    sid, heading = match.groups()
    return _resolve(heading in _card_region(_html(world), sid), f"heading={heading}")


def _h_ts_complexity_levels(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows "Candidate lower bound" as "L" and "Final required level" as "F"."""
    match = re.search(
        r'the attack complexity block shows "Candidate lower bound" as '
        r'"([^"]+)" and "Final required level" as "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-levels assertion: {text}"
    lower, final = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    visible = _visible(region)
    ok = f"Candidate lower bound: {lower}" in visible
    ok = ok and f"Final required level: {final}" in visible
    return _resolve(ok, f"lower={lower} final={final}")


def _h_ts_complexity_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows the reason line "R"."""
    match = re.search(
        r'the attack complexity block shows the reason line "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse complexity-reason assertion: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    return _resolve(match.group(1) in _visible(region), f"reason={match.group(1)!r}")


def _h_ts_no_attack_complexity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows no attack complexity block."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        text,
    )
    if not match:
        return False, f"Could not parse no-complexity assertion: {text}"
    return _resolve(
        "ATTACK COMPLEXITY" not in _card_region(_html(world), match.group(1)),
        "attack complexity block rendered unexpectedly",
    )


def register(api: Any) -> None:
    # --- ATLAS Techniques / attack complexity Then steps ---
    api.register(
        'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading "Scenario classifications" with the badge "([^"]+)"',
        _h_ts_atlas_classifications,
        source_order=8066,
    )
    api.register(
        'the ATLAS Techniques tab shows the heading "([^"]+)" with the placeholder "([^"]+)"',
        _h_ts_atlas_none,
        source_order=8067,
    )
    api.register(
        'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        _h_ts_complexity_heading,
        source_order=8068,
    )
    api.register(
        'the attack complexity block shows "Candidate lower bound" as "([^"]+)" and "Final required level" as "([^"]+)"',
        _h_ts_complexity_levels,
        source_order=8069,
    )
    api.register(
        'the attack complexity block shows the reason line "([^"]+)"',
        _h_ts_complexity_reason,
        source_order=8070,
    )
    api.register(
        'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        _h_ts_no_attack_complexity,
        source_order=8071,
    )
