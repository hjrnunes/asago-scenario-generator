"""Then step handlers asserting the run summary, funnel, and sidebar navigation."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _stats, _resolve

# Report section name -> sidebar anchor for navigation assertions.
_SIDEBAR_ANCHORS: dict[str, str] = {
    "Coverage Analysis": "#sec-coverage",
    "Run Summary": "#sec-run-summary",
    "Eval Scorecard": "#sec-scorecard",
    "Capability Profile": "#sec-profile",
    "Threat Surface": "#sec-threats",
    "Scenarios": "#sec-scenarios",
    "Raw Data": "#sec-raw",
    "Glossary & Methodology": "#glossary",
}


def _h_ts_run_summary_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a "Run Summary" section."""
    return _resolve("<h2>Run Summary</h2>" in _html(world), "Run Summary missing")


def _h_ts_run_summary_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains no "Run Summary" section."""
    return _resolve("<h2>Run Summary</h2>" not in _html(world), "Run Summary rendered")


def _h_ts_no_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains no "Section" section."""
    match = re.search(r'the report contains no "([^"]+)" section', text)
    if not match:
        return False, f"Could not parse no-section assertion: {text}"
    section_name = match.group(1)
    h2 = {
        "Threat–Technique Matrix": "Threat&ndash;Technique Matrix",
    }.get(section_name, section_name)
    return _resolve(
        f"<h2>{h2}</h2>" not in _html(world),
        f"section {section_name!r} rendered unexpectedly",
    )


def _h_ts_sidebar_no_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the sidebar shows no link to the "Run Summary" section."""
    return _resolve(
        '<a href="#sec-run-summary">' not in _html(world),
        "Run Summary sidebar link rendered",
    )


def _h_ts_sidebar_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the sidebar shows a link to the "Section" section."""
    match = re.search(r'the sidebar shows a link to the "([^"]+)" section', text)
    if not match:
        return False, f"Could not parse sidebar-link assertion: {text}"
    href = _SIDEBAR_ANCHORS.get(match.group(1))
    if href is None:
        return False, f"Unknown sidebar section {match.group(1)!r}"
    return _resolve(href in _html(world), f"sidebar link {href} missing")


def _h_ts_funnel_stats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the funnel shows "N" <Label>, ... ."""
    match = re.search(r"the funnel shows (.*)$", text)
    if not match:
        return False, f"Could not parse funnel assertion: {text}"
    pairs = re.findall(r'"(\d+)" ([^,]+?)(?:,| and |$)', match.group(1))
    expected = {label.strip(): int(count) for count, label in pairs}
    region = _section_region(_html(world), "sec-run-summary")
    stats = _stats(region)
    ok = all(stats.get(label) == count for label, count in expected.items())
    return _resolve(ok, f"funnel stats={stats}")


def _h_ts_run_summary_stats(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows "F" Failed, "R" Rejected, and the rejection rate "P"."""
    match = re.search(
        r'the run summary shows "(\d+)" Failed, "(\d+)" Rejected, and the '
        r'rejection rate "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse run-summary stats: {text}"
    failed, rejected, rate = match.groups()
    region = _section_region(_html(world), "sec-run-summary")
    stats = _stats(region)
    ok = stats.get("Failed") == int(failed) and stats.get("Rejected") == int(rejected)
    ok = ok and f">{rate}</span>" in region
    return _resolve(ok, f"stats={stats} rate={rate}")


def _h_ts_run_summary_duration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows the duration "D"."""
    match = re.search(r'the run summary shows the duration "([^"]+)"', text)
    if not match:
        return False, f"Could not parse duration assertion: {text}"
    return _resolve(
        match.group(1) in _section_region(_html(world), "sec-run-summary"),
        f"duration={match.group(1)!r}",
    )


def _h_ts_run_summary_config(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows model "M", temperature "T", start "S", and end "E"."""
    match = re.search(
        r'the run summary shows model "([^"]+)", temperature "([^"]+)", '
        r'start "([^"]+)", and end "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse run-summary config: {text}"
    model, temperature, start, end = match.groups()
    region = _section_region(_html(world), "sec-run-summary")
    ok = f">{model}</div>" in region and f">{temperature}</div>" in region
    ok = ok and start in region and end in region
    return _resolve(ok, f"config model={model} temperature={temperature}")


def _h_ts_rerun_summary_absent_values(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows model "unknown", temperature "N/A", start "N/A", and end "N/A"."""
    region = _section_region(_html(world), "sec-run-summary")
    ok = ">unknown</div>" in region
    ok = ok and region.count(">N/A</div>") >= 3
    return _resolve(
        ok, f"absent values region has {region.count('>N/A</div>')} N/A divs"
    )


def _h_ts_rejection_rate_na(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows the rejection rate "N/A"."""
    return _resolve(
        ">N/A</span>" in _section_region(_html(world), "sec-run-summary"),
        "rejection rate N/A missing",
    )


def _h_ts_outcome_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run summary outcome summary shows "H" High Priority, "M" Medium Priority, and "L" Low Priority."""
    match = re.search(
        r'the run summary outcome summary shows "(\d+)" High Priority, '
        r'"(\d+)" Medium Priority, and "(\d+)" Low Priority',
        text,
    )
    if not match:
        return False, f"Could not parse outcome-summary assertion: {text}"
    expected = {
        "High Priority": int(match.group(1)),
        "Medium Priority": int(match.group(2)),
        "Low Priority": int(match.group(3)),
    }
    region = _section_region(_html(world), "sec-run-summary")
    stats = _stats(region)
    ok = all(stats.get(label) == count for label, count in expected.items())
    return _resolve(ok, f"outcome summary stats={stats}")


def _h_ts_run_summary_coverage_card(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows the coverage card "N" Coverage Gaps."""
    match = re.search(
        r'the run summary shows the coverage card "(\d+)" Coverage Gaps', text
    )
    if not match:
        return False, f"Could not parse run-summary coverage-card: {text}"
    region = _section_region(_html(world), "sec-run-summary")
    ok = f">{match.group(1)}</span>" in region and "Coverage Gaps" in region
    return _resolve(ok, f"coverage card={match.group(1)}")


def register(api: Any) -> None:
    # --- Run summary Then steps ---
    api.register(
        'the run summary outcome summary shows "\\d+" High Priority, "\\d+" Medium Priority, and "\\d+" Low Priority',
        _h_ts_outcome_summary,
        source_order=8086,
    )
    api.register(
        'the run summary shows the coverage card "\\d+" Coverage Gaps',
        _h_ts_run_summary_coverage_card,
        source_order=8087,
    )
    api.register(
        'the report contains a "Run Summary" section',
        _h_ts_run_summary_present,
        source_order=8049,
    )
    api.register(
        'the report contains no "Run Summary" section',
        _h_ts_run_summary_absent,
        source_order=8050,
    )
    api.register(
        'the sidebar shows a link to the "([^"]+)" section',
        _h_ts_sidebar_link,
        source_order=8019,
    )
    api.register(
        'the report contains no "([^"]+)" section',
        _h_ts_no_section,
        source_order=8051,
    )
    api.register(
        'the sidebar shows no link to the "Run Summary" section',
        _h_ts_sidebar_no_link,
        source_order=8052,
    )
    api.register(
        "the funnel shows .+",
        _h_ts_funnel_stats,
        source_order=8053,
    )
    api.register(
        'the run summary shows "(\\d+)" Failed, "(\\d+)" Rejected, and the rejection rate "([^"]+)"',
        _h_ts_run_summary_stats,
        source_order=8054,
    )
    api.register(
        'the run summary shows the duration "([^"]+)"',
        _h_ts_run_summary_duration,
        source_order=8055,
    )
    api.register(
        'the run summary shows model "([^"]+)", temperature "([^"]+)", start "([^"]+)", and end "([^"]+)"',
        _h_ts_run_summary_config,
        source_order=8056,
    )
    api.register(
        'the run summary shows model "unknown", temperature "N/A", start "N/A", and end "N/A"',
        _h_ts_rerun_summary_absent_values,
        source_order=8057,
    )
    api.register(
        'the run summary shows the rejection rate "N/A"',
        _h_ts_rejection_rate_na,
        source_order=8058,
    )
