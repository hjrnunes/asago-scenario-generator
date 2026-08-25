"""Then step handlers asserting the actor profile distribution."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _visible, _resolve


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


def _h_ts_diversity_no_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the distribution shows no low-diversity warning."""
    region = _section_region(_html(world), "sec-diversity")
    return _resolve(
        "Low actor diversity" not in region, "low-diversity warning is present"
    )


def _h_ts_diversity_block_badge(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the distribution shows the "Block" block with the badge "B"."""
    match = re.search(
        r'the distribution shows the "([^"]+)" block with the badge "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse diversity-block badge: {text}"
    block, badge = match.groups()
    region = _section_region(_html(world), "sec-diversity")
    block_start = region.find(block)
    if block_start == -1:
        return _resolve(False, f"diversity block {block!r} is not rendered")
    block_body = region[block_start : block_start + 3000]
    return _resolve(badge in block_body, f"block {block!r} badge={badge}")


def register(api: Any) -> None:
    # --- Actor profile distribution Then steps ---
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
    api.register(
        "the distribution shows no low-diversity warning",
        _h_ts_diversity_no_warning,
        source_order=8084,
    )
    api.register(
        'the distribution shows the "([^"]+)" block with the badge "([^"]+)"',
        _h_ts_diversity_block_badge,
        source_order=8085,
    )
