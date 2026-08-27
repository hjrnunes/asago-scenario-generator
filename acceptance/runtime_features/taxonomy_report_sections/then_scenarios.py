"""Then step handlers asserting the Scenarios-section dashboard, charts, and filters."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _section_region, _stats, _resolve


def _h_ts_dashboard_stats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the dashboard stats "N" In Report, "H" High Priority, "M" Medium Priority, and "L" Low Priority."""
    match = re.search(
        r'the Scenarios section shows the dashboard stats "(\d+)" In Report, '
        r'"(\d+)" High Priority, "(\d+)" Medium Priority, and "(\d+)" Low Priority',
        text,
    )
    if not match:
        return False, f"Could not parse dashboard assertion: {text}"
    expected = {
        "In Report": int(match.group(1)),
        "High Priority": int(match.group(2)),
        "Medium Priority": int(match.group(3)),
        "Low Priority": int(match.group(4)),
    }
    region = _section_region(_html(world), "sec-scenarios")
    stats = _stats(region)
    ok = all(stats.get(label) == count for label, count in expected.items())
    return _resolve(ok, f"dashboard stats={stats}")


def _h_ts_coverage_gaps_stat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Scenarios section shows "N" Coverage Gaps."""
    match = re.search(r'the Scenarios section shows "(\d+)" Coverage Gaps', text)
    if not match:
        return False, f"Could not parse coverage-gaps stat: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    stats = _stats(region)
    return _resolve(stats.get("Coverage Gaps") == int(match.group(1)), f"stats={stats}")


def _h_ts_scenarios_chart_segment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the "Chart" chart with the segment "S"."""
    match = re.search(
        r'the Scenarios section shows the "([^"]+)" chart with the segment "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse chart-segment assertion: {text}"
    chart, segment = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = chart in region and segment in region
    return _resolve(ok, f"chart {chart!r} segment={segment}")


def _h_ts_threat_zone_cell(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the "Threat x Zone Coverage" matrix with the cell "T" x "Z" counting "N"."""
    match = re.search(
        r'the Scenarios section shows the "([^"]+)" matrix with the cell '
        r'"([^"]+)" x "([^"]+)" counting "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse threat-zone cell assertion: {text}"
    matrix, threat, zone, count = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = matrix in region and f">{count}</div>" in region
    ok = ok and f"{threat} x {zone}: {count} scenario" in region
    return _resolve(
        ok,
        f"threat-zone cell threat={threat} zone={zone} count={count}",
    )


def _h_ts_threat_zone_empty_cell(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the "Threat x Zone Coverage" matrix with the empty cell "T" x "Z"."""
    match = re.search(
        r'the Scenarios section shows the "([^"]+)" matrix with the empty '
        r'cell "([^"]+)" x "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse empty matrix cell assertion: {text}"
    matrix, threat, zone = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = matrix in region and "matrix-cell empty" in region
    ok = ok and f"{threat} x {zone}: no scenarios" in region
    return _resolve(ok, f"empty cell threat={threat} zone={zone}")


def _h_ts_entry_point_distribution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the "Entry Point Distribution" listing "A" with count N and "B" with count M."""
    match = re.search(
        r'the Scenarios section shows the "Entry Point Distribution" listing '
        r'"([^"]+)" with count (\d+) and "([^"]+)" with count (\d+)',
        text,
    )
    if not match:
        return False, f"Could not parse ep-distribution assertion: {text}"
    first_name, first_count, second_name, second_count = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f'class="ep-dist-name" data-tooltip="{first_name}"' in region
    ok = ok and f'data-tooltip="{second_name}"' in region
    ok = (
        ok
        and f">{first_count}</span>" in region
        and f">{second_count}</span>" in region
    )
    return _resolve(
        ok,
        f"ep distribution {first_name}={first_count} {second_name}={second_count}",
    )


def _h_ts_filter_chips(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the filter chips "Threats" containing "T", "Zones" containing "Z1" and "Z2", and "Priority" containing "P1", "P2", and "P3"."""
    match = re.search(
        r'the Scenarios section shows the filter chips "([^"]+)" containing '
        r'"([^"]+)", "([^"]+)" containing "([^"]+)" and "([^"]+)", and '
        r'"([^"]+)" containing "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse filter-chips assertion: {text}"
    (
        threats_label,
        threat,
        zones_label,
        zone1,
        zone2,
        priority_label,
        priority1,
        priority2,
        priority3,
    ) = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = (
        threats_label in region
        and f'data-filter-type="threat" data-filter-value="{threat}"' in region
    )
    ok = ok and zones_label in region
    # Zone chips carry canonical keys in data-filter-value and display names
    # as their label; assert by the visible label.
    ok = ok and 'data-filter-type="zone"' in region and f">{zone1}</span>" in region
    ok = ok and 'data-filter-type="zone"' in region and f">{zone2}</span>" in region
    ok = ok and priority_label in region
    for priority in (priority1, priority2, priority3):
        ok = (
            ok
            and f'data-filter-type="priority" data-filter-value="{priority.lower()}"'
            in region
        )
    return _resolve(ok, f"filter chips threat={threat} zones={zone1} {zone2}")


def _h_ts_stat_sublabel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the stat "N" In Report with the sublabel "S"."""
    match = re.search(
        r'the Scenarios section shows the stat "(\d+)" In Report with the '
        r'sublabel "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse stat-sublabel assertion: {text}"
    count, sublabel = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f'<span class="stat-number">{count}</span>' in region
    ok = ok and 'class="stat-sublabel"' in region and sublabel in region
    return _resolve(ok, f"stat In Report={count} sublabel={sublabel}")


def register(api: Any) -> None:
    # --- Scenarios-section dashboard, charts, and filters Then steps ---
    api.register(
        'the Scenarios section shows the dashboard stats "(\\d+)" In Report, "(\\d+)" High Priority, "(\\d+)" Medium Priority, and "(\\d+)" Low Priority',
        _h_ts_dashboard_stats,
        source_order=8041,
    )
    api.register(
        'the Scenarios section shows "(\\d+)" Coverage Gaps',
        _h_ts_coverage_gaps_stat,
        source_order=8042,
    )
    api.register(
        'the Scenarios section shows the "([^"]+)" chart with the segment "([^"]+)"',
        _h_ts_scenarios_chart_segment,
        source_order=8088,
    )
    api.register(
        'the Scenarios section shows the "([^"]+)" matrix with the cell "([^"]+)" x "([^"]+)" counting "([^"]+)"',
        _h_ts_threat_zone_cell,
        source_order=8089,
    )
    api.register(
        'the Scenarios section shows the "([^"]+)" matrix with the empty cell "([^"]+)" x "([^"]+)"',
        _h_ts_threat_zone_empty_cell,
        source_order=8090,
    )
    api.register(
        'the Scenarios section shows the "Entry Point Distribution" listing "([^"]+)" with count (\\d+) and "([^"]+)" with count (\\d+)',
        _h_ts_entry_point_distribution,
        source_order=8091,
    )
    api.register(
        "the Scenarios section shows the filter chips .*",
        _h_ts_filter_chips,
        source_order=8092,
    )
    api.register(
        'the Scenarios section shows the stat "\\d+" In Report with the sublabel "([^"]+)"',
        _h_ts_stat_sublabel,
        source_order=8093,
    )
