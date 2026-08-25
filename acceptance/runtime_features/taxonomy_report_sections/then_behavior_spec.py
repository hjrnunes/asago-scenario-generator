"""Then step handlers asserting the Behavior Spec tab of scenario cards."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _card_region, _resolve


def _h_ts_behavior_spec_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the step keywords "Given", "When", and "Then" with the texts "A", "B", and "C"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords '
        r'"Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-spec assertion: {text}"
    sid, text1, text2, text3 = match.groups()
    region = _card_region(_html(world), sid)
    ok = (
        'class="step-keyword">Given</span>' in region
        and 'class="step-keyword">When</span>' in region
        and 'class="step-keyword">Then</span>' in region
    )
    ok = ok and f'class="step-text">{text1}</span>' in region
    ok = ok and f'class="step-text">{text2}</span>' in region
    ok = ok and f'class="step-text">{text3}</span>' in region
    return _resolve(ok, f"behavior steps texts={text1} {text2} {text3}")


def _h_ts_behavior_spec_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the message "M"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-absent assertion: {text}"
    sid, message = match.groups()
    return _resolve(message in _card_region(_html(world), sid), f"message={message}")


def _h_ts_behavior_spec_keyword_header(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" renders the keyword "K:" with the text "T"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" renders the keyword '
        r'"([^"]+)" with the text "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior header assertion: {text}"
    sid, keyword, header_text = match.groups()
    region = _card_region(_html(world), sid)
    ok = f">{keyword}</span>" in region
    ok = (
        ok
        and re.search(
            re.escape(keyword) + r"</span>\s*" + re.escape(header_text) + r"</div>",
            region,
        )
        is not None
    )
    return _resolve(ok, f"behavior header keyword={keyword} text={header_text}")


def _h_ts_behavior_spec_step(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab shows the step "K" with the text "T"."""
    match = re.search(
        r'the Behavior Spec tab shows the step "([^"]+)" with the text "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse behavior step assertion: {text}"
    keyword, step_text = match.groups()
    html = _html(world)
    ok = f'class="step-keyword">{keyword}</span>' in html
    ok = ok and f'class="step-text">{step_text}</span>' in html
    return _resolve(ok, f"behavior step keyword={keyword} text={step_text}")


def _h_ts_behavior_spec_step_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab shows the step "K" with the text "T" and the zone badge "Z"."""
    match = re.search(
        r'the Behavior Spec tab shows the step "([^"]+)" with the text '
        r'"([^"]+)" and the zone badge "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior step-zone assertion: {text}"
    keyword, step_text, zone = match.groups()
    html = _html(world)
    ok = f'class="step-keyword">{keyword}</span>' in html
    # The zone-bearing step wraps the badge inside the step-text span, so the
    # text is followed by the badge markup rather than a closing span.
    ok = ok and f'class="step-text">{step_text}' in html
    ok = ok and 'class="zone-badge"' in html and f">{zone}</span>" in html
    return _resolve(ok, f"behavior step keyword={keyword} zone={zone}")


def _h_ts_behavior_spec_docstring(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab shows the docstring "D"."""
    match = re.search(r'the Behavior Spec tab shows the docstring "([^"]+)"', text)
    if not match:
        return False, f"Could not parse behavior docstring assertion: {text}"
    html = _html(world)
    ok = "step-docstring" in html and match.group(1) in html
    return _resolve(ok, f"behavior docstring={match.group(1)!r}")


def _h_ts_behavior_spec_continuation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab shows the continuation line "L"."""
    match = re.search(
        r'the Behavior Spec tab shows the continuation line "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse behavior continuation assertion: {text}"
    html = _html(world)
    return _resolve(match.group(1) in html, f"continuation={match.group(1)!r}")


def _h_ts_behavior_spec_no_tag(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab does not render the tag "T"."""
    match = re.search(r'the Behavior Spec tab does not render the tag "([^"]+)"', text)
    if not match:
        return False, f"Could not parse behavior no-tag assertion: {text}"
    html = _html(world)
    return _resolve(f"@{match.group(1)}" not in html, f"tag @{match.group(1)} rendered")


def register(api: Any) -> None:
    # --- Behavior Spec tab Then steps ---
    api.register(
        'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords "Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_behavior_spec_steps,
        source_order=8064,
    )
    api.register(
        'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        _h_ts_behavior_spec_absent,
        source_order=8065,
    )
    api.register(
        'the Behavior Spec tab of scenario "([^"]+)" renders the keyword "([^"]+)" with the text "([^"]+)"',
        _h_ts_behavior_spec_keyword_header,
        source_order=8095,
    )
    api.register(
        'the Behavior Spec tab shows the step "([^"]+)" with the text "([^"]+)"$',
        _h_ts_behavior_spec_step,
        source_order=8096,
    )
    api.register(
        'the Behavior Spec tab shows the step "([^"]+)" with the text "([^"]+)" and the zone badge "([^"]+)"',
        _h_ts_behavior_spec_step_zone,
        source_order=8097,
    )
    api.register(
        'the Behavior Spec tab shows the docstring "([^"]+)"',
        _h_ts_behavior_spec_docstring,
        source_order=8098,
    )
    api.register(
        'the Behavior Spec tab shows the continuation line "([^"]+)"',
        _h_ts_behavior_spec_continuation,
        source_order=8099,
    )
    api.register(
        'the Behavior Spec tab does not render the tag "([^"]+)"',
        _h_ts_behavior_spec_no_tag,
        source_order=8100,
    )
