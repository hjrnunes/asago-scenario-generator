"""Shared extraction helpers for taxonomy report section handlers.

Pure world/HTML helpers used by multiple themed ``given_*`` and ``then_*``
handler modules.  They live in this private leaf module so submodules depend
on the helpers directly instead of on the package facade, leaving
``__init__`` with only the ``register`` entry and feature identity.
"""

from __future__ import annotations

import re

from runtime_world import World


def _html(world: World) -> str:
    """Return the generated report HTML, failing loudly if absent."""
    if not world.trpt_html:
        raise AssertionError("the HTML report has not been generated")
    return world.trpt_html


def _card_region(html: str, sid: str) -> str:
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"scenario card {sid} is not rendered")
    return html[idx:]


def _section_region(html: str, section_id: str) -> str:
    marker = f'id="{section_id}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"section {section_id!r} is not rendered")
    return html[idx : idx + 60000]


def _stats(region: str) -> dict[str, int]:
    """Return label -> count for every stat-number/stat-label pair."""
    return {
        label: int(count)
        for count, label in re.findall(
            r'<span class="stat-number">(\d+)</span>\s*'
            r'<span class="stat-label">([^<]+)</span>',
            region,
        )
    }


def _visible(fragment: str) -> str:
    """Strip markup and decode entities for text-content assertions."""
    text = re.sub(r"<[^>]+>", "", fragment)
    text = (
        text.replace("&rarr;", "→")
        .replace("&ndash;", "–")
        .replace("&middot;", "·")
        .replace("&mdash;", "—")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&nbsp;", " ")
        .replace("&#10;", " ")
        .replace("&and;", "∧")
        .replace("&or;", "∨")
        .replace("&bull;", "•")
    )
    return text.strip()


def _resolve(ok: bool, detail: str) -> tuple[bool, str]:
    return ok, detail
