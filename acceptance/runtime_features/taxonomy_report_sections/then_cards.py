"""Then step handlers asserting scenario cards (signals, actor, attack tree, dashboard)."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _card_region, _section_region, _resolve


def _h_ts_signals_grid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows a priority signals grid."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows a priority signals grid', text
    )
    if not match:
        return False, f"Could not parse signals-grid assertion: {text}"
    return _resolve(
        'class="signals-grid"' in _card_region(_html(world), match.group(1)),
        "signals grid missing",
    )


def _h_ts_signals_labels(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the priority signals grid shows the labels "L1", ..., and "L6"."""
    match = re.search(
        r'the priority signals grid shows the labels "([^"]+)", "([^"]+)", '
        r'"([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse signals-labels assertion: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    ok = all(f">{label}</div>" in region for label in match.groups())
    return _resolve(ok, f"signal labels={match.groups()}")


def _h_ts_signals_values(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the priority signals grid shows the value "V1" for "L1" and "V2" for "L2"."""
    match = re.search(
        r'the priority signals grid shows the value "([^"]+)" for "([^"]+)" '
        r'and "([^"]+)" for "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse signals-values assertion: {text}"
    value1, label1, value2, label2 = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    item = re.compile(
        r'<div class="signal-label">([^<]+)</div>\s*'
        r'<div class="signal-value">([^<]+)</div>'
    )
    pairs = dict(item.findall(region))
    ok = pairs.get(label1) == value1 and pairs.get(label2) == value2
    return _resolve(ok, f"signal pairs={pairs}")


def _h_ts_no_signals_grid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows no priority signals grid."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows no priority signals grid', text
    )
    if not match:
        return False, f"Could not parse no-signals assertion: {text}"
    return _resolve(
        'class="signals-grid"' not in _card_region(_html(world), match.group(1)),
        "signals grid rendered unexpectedly",
    )


def _h_ts_actor_chips(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows the actor type chip "AT", the capability chip "C", and the goal chip "G"."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows the actor type chip "([^"]+)", '
        r'the capability chip "([^"]+)", and the goal chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-chip assertion: {text}"
    sid, actor_type, capability, goal = match.groups()
    region = _card_region(_html(world), sid)
    ok = (
        f">{actor_type}</span>" in region
        and f">{capability}</span>" in region
        and f">{goal}</span>" in region
    )
    return _resolve(ok, f"chips actor={actor_type} capability={capability} goal={goal}")


def _h_ts_actor_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile block shows the belief "B", the desire "D", the intention "I", and the resource "R"."""
    match = re.search(
        r'the actor profile block shows the belief "([^"]+)", the desire '
        r'"([^"]+)", the intention "([^"]+)", and the resource "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-BDI assertion: {text}"
    values = match.groups()
    html = _html(world)
    ok = all(value in html for value in values)
    return _resolve(ok, f"BDI values={values}")


def _h_ts_actor_access(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile block shows the access provenance with ingress "I" and entry point "E"."""
    match = re.search(
        r"the actor profile block shows the access provenance with ingress "
        r'"([^"]+)" and entry point "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-access assertion: {text}"
    ingress, entry_point = match.groups()
    html = _html(world)
    ok = f"Ingress: <strong>{ingress}</strong>" in html
    ok = ok and f"Entry point ID: <code>{entry_point}</code>" in html
    return _resolve(ok, f"access ingress={ingress} entry_point={entry_point}")


def _h_ts_no_actor_block(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows no actor profile block."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows no actor profile block', text
    )
    if not match:
        return False, f"Could not parse no-actor-block assertion: {text}"
    region = _card_region(_html(world), match.group(1))
    ok = "BELIEFS:" not in region and "ACCESS PROVENANCE:" not in region
    return _resolve(ok, "actor profile block rendered unexpectedly")


def _h_ts_attack_tree_tab(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Attack Tree tab of scenario "S" <rendering>."""
    match = re.search(r'the Attack Tree tab of scenario "([^"]+)" (.*)$', text)
    if not match:
        return False, f"Could not parse attack-tree tab assertion: {text}"
    sid, rendering = match.groups()
    region = _card_region(_html(world), sid)
    if "renders an OR gate summary" in rendering:
        ok = (
            region.count('class="tree-leaf"') == 2
            and "gate-or" in region
            and "AML.T0015" in region
            and "AML.T0040" in region
        )
    elif "renders an AND gate summary" in rendering:
        ok = (
            region.count('class="tree-leaf"') == 2
            and "gate-and" in region
            and "AML.T0015" in region
            and "AML.T0040" in region
        )
    elif "renders exactly one leaf node and no gate summary" in rendering:
        ok = (
            region.count('class="tree-leaf"') == 1
            and "gate-or" not in region
            and "gate-and" not in region
        )
    else:  # renders no tree node markup
        ok = (
            region.count('class="tree-leaf"') == 0
            and "<details open" not in region
            and "gate-or" not in region
        )
    return _resolve(ok, f"attack tree rendering case: {rendering}")


def _h_ts_tree_meta(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Attack Tree tab shows the leaf node meta "M" with code "C"."""
    match = re.search(
        r'the Attack Tree tab shows the leaf node meta "([^"]+)" with code "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tree-meta assertion: {text}"
    meta, code = match.groups()
    html = _html(world)
    ok = meta in html and f"<code>{code}</code>" in html
    return _resolve(ok, f"tree meta={meta} code={code}")


def _h_ts_leaf_meta(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the leaf node meta shows "M" with code "C"."""
    match = re.search(r'the leaf node meta shows "([^"]+)" with code "([^"]+)"', text)
    if not match:
        return False, f"Could not parse leaf-meta assertion: {text}"
    meta, code = match.groups()
    html = _html(world)
    ok = meta in html and f"<code>{code}</code>" in html
    return _resolve(ok, f"leaf meta={meta} code={code}")


def _h_ts_scenario_card_title(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a scenario card for "S" with the title "T"."""
    match = re.search(
        r'the report contains a scenario card for "([^"]+)" with the title "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse card-title assertion: {text}"
    sid, title = match.groups()
    html = _html(world)
    ok = f'id="scenario-{sid}"' in html and title in html
    return _resolve(ok, f"card {sid} title={title}")


def _h_ts_scenario_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains a scenario card for "S"."""
    match = re.search(r'the report contains a scenario card for "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse card assertion: {text}"
    return _resolve(
        f'id="scenario-{match.group(1)}"' in _html(world),
        f"scenario card {match.group(1)!r} is not rendered",
    )


def _h_ts_card_badge_score(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows the priority badge "B" with the score "S"."""
    match = re.search(
        r'the card shows the priority badge "([^"]+)" with the score "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse badge-score assertion: {text}"
    badge, score = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = re.search(
        rf'class="priority-badge"[^>]*>\s*{re.escape(badge)}\s*</span>', region
    )
    ok = bool(ok) and f">{score}</span>" in region
    return _resolve(ok, f"badge={badge} score={score}")


def _h_ts_nine_tabs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows all nine tab labels ... ."""
    match = re.search(r"the card shows all nine tab labels (.*)$", text)
    if not match:
        return False, f"Could not parse tab-labels assertion: {text}"
    labels = re.findall(r'"([^"]+)"', match.group(1))
    region = _section_region(_html(world), "sec-scenarios")
    ok = all(f">{label}</label>" in region for label in labels)
    return _resolve(ok, f"tab labels={labels}")


def _h_ts_no_zone_crumbs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows no zone crumbs."""
    return _resolve(
        "zone-crumb" not in _section_region(_html(world), "sec-scenarios"),
        "zone crumbs rendered",
    )


def _h_ts_no_scenarios_placeholder(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a Scenarios section showing "No scenarios generated."."""
    html = _html(world)
    ok = 'id="sec-scenarios"' in html and "No scenarios generated." in html
    return _resolve(ok, "scenarios placeholder missing")


def _h_ts_zone_crumbs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows the zone crumbs "Z1" and "Z2"."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows the zone crumbs "([^"]+)" '
        r'and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse zone-crumbs assertion: {text}"
    sid, zone1, zone2 = match.groups()
    region = _card_region(_html(world), sid)
    ok = 'class="zone-crumb"' in region and f">{zone1}</span>" in region
    ok = ok and f">{zone2}</span>" in region
    return _resolve(ok, f"card {sid} zone crumbs {zone1} {zone2}")


def register(api: Any) -> None:
    # --- Scenario card Then steps ---
    api.register(
        'the scenario card for "([^"]+)" shows a priority signals grid',
        _h_ts_signals_grid,
        source_order=8030,
    )
    api.register(
        'the priority signals grid shows the labels "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_signals_labels,
        source_order=8031,
    )
    api.register(
        'the priority signals grid shows the value "([^"]+)" for "([^"]+)" and "([^"]+)" for "([^"]+)"',
        _h_ts_signals_values,
        source_order=8032,
    )
    api.register(
        'the scenario card for "([^"]+)" shows no priority signals grid',
        _h_ts_no_signals_grid,
        source_order=8033,
    )
    api.register(
        'the scenario card for "([^"]+)" shows the actor type chip "([^"]+)", the capability chip "([^"]+)", and the goal chip "([^"]+)"',
        _h_ts_actor_chips,
        source_order=8034,
    )
    api.register(
        'the actor profile block shows the belief "([^"]+)", the desire "([^"]+)", the intention "([^"]+)", and the resource "([^"]+)"',
        _h_ts_actor_bdi,
        source_order=8035,
    )
    api.register(
        'the actor profile block shows the access provenance with ingress "([^"]+)" and entry point "([^"]+)"',
        _h_ts_actor_access,
        source_order=8036,
    )
    api.register(
        'the scenario card for "([^"]+)" shows no actor profile block',
        _h_ts_no_actor_block,
        source_order=8037,
    )
    api.register(
        'the Attack Tree tab of scenario "([^"]+)" .+$',
        _h_ts_attack_tree_tab,
        source_order=8038,
    )
    api.register(
        'the Attack Tree tab shows the leaf node meta "([^"]+)" with code "([^"]+)"',
        _h_ts_tree_meta,
        source_order=8039,
    )
    api.register(
        'the leaf node meta shows "([^"]+)" with code "([^"]+)"',
        _h_ts_leaf_meta,
        source_order=8040,
    )
    api.register(
        'the report contains a scenario card for "([^"]+)" with the title "([^"]+)"',
        _h_ts_scenario_card_title,
        source_order=8043,
    )
    api.register(
        'the report contains a scenario card for "([^"]+)"$',
        _h_ts_scenario_card,
        source_order=8044,
    )
    api.register(
        'the card shows the priority badge "([^"]+)" with the score "([^"]+)"',
        _h_ts_card_badge_score,
        source_order=8045,
    )
    api.register(
        "the card shows all nine tab labels .+",
        _h_ts_nine_tabs,
        source_order=8046,
    )
    api.register(
        "the card shows no zone crumbs",
        _h_ts_no_zone_crumbs,
        source_order=8047,
    )
    api.register(
        'the report contains a Scenarios section showing "No scenarios generated."',
        _h_ts_no_scenarios_placeholder,
        source_order=8048,
    )
    api.register(
        'the scenario card for "([^"]+)" shows the zone crumbs "([^"]+)" and "([^"]+)"',
        _h_ts_zone_crumbs,
        source_order=8094,
    )
