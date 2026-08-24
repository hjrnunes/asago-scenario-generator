"""Acceptance step handlers for taxonomy/risk HTML report section rendering.

Covers the section builders that still live in ``report/template.py``: the
capability profile, threat surface, coverage analysis, threat-technique
matrix, actor profile distribution, scenario cards (priority signals,
actor profile, attack tree, generation inputs, behavior spec, ATLAS
techniques, attack complexity), the run summary, pipeline call logs, and
raw-data syntax highlighting.  Fixtures are assembled step-by-step on the
world reusing the ``taxonomy_report`` vocabulary; the When step drives the
public report entry ``generate_report`` so the pinned behavior is
verified on the real rendered document.  All fixtures are offline.

The module is split into themed submodules (``given_*`` fixture handlers
and ``then_*`` assertion handlers); this package keeps the shared
extraction helpers, the feature-scoped Background/When registration, and
the ``register`` entry that delegates registration in the original
source-order groups.
"""

from __future__ import annotations

import re
from typing import Any

from runtime_world import World
from runtime_features.taxonomy_report import (
    _h_background,
    _h_generate_report,
)

FEATURE_ID = "taxonomy_report_sections"


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


def _profile_region(world: World) -> str:
    return _section_region(_html(world), "sec-profile")


def _threats_region(world: World) -> str:
    return _section_region(_html(world), "sec-threats")


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


def _last_scenario(world: World) -> dict[str, Any]:
    if not world.trpt_scenarios:
        raise AssertionError("the fixture contains no scenarios yet")
    return world.trpt_scenarios[-1]


def _coverage_card_statuses(region: str) -> dict[str, str]:
    """Return coverage-card title -> status label."""
    return {
        title: status
        for title, _cls, status in re.findall(
            r'<span class="coverage-card-title">([^<]+)</span>\s*'
            r'<span class="coverage-status [\w-]+">([^<]+)</span>',
            region,
        )
    }


def _resolve(ok: bool, detail: str) -> tuple[bool, str]:
    return ok, detail


def register(api: Any) -> None:
    # Sibling themes are imported here (not at module level): they import
    # the shared helpers above, so the package must be fully initialized
    # before they load. Registration order preserves the original
    # source-order groups.
    from . import given_profile
    from . import given_threat_surface
    from . import given_scenarios
    from . import given_run
    from . import then_profile
    from . import then_threats
    from . import then_cards
    from . import then_summary
    from . import then_panels

    # Shared Background/When: register under this feature's scope so the
    # same public-report vocabulary drives the section-rendering scenarios.
    api.set_feature(FEATURE_ID)
    api.register_first(
        "an offline completed taxonomy-and-risk run fixture",
        _h_background,
        source_order=6000,
    )
    api.register_first(
        "the HTML report is generated",
        _h_generate_report,
        source_order=6100,
    )
    api.set_feature(None)

    given_profile.register(api)
    given_threat_surface.register(api)
    given_scenarios.register(api)
    given_run.register(api)
    then_profile.register(api)
    then_threats.register(api)
    then_cards.register(api)
    then_summary.register(api)
    then_panels.register(api)


__all__ = ["FEATURE_ID", "register"]
