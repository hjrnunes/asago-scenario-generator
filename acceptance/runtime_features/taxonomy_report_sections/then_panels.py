"""Then step handlers asserting raw-data panels and Generation Inputs tab rows."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _card_region, _section_region, _resolve


def _h_ts_yaml_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel shows a highlighted comment, key "K", number value N, boolean value B, and null value."""
    match = re.search(
        r'the YAML panel shows a highlighted comment, key "([^"]+)", number '
        r"value \d+, boolean value .*, and null value",
        text,
    )
    if not match:
        return False, f"Could not parse YAML panel assertion: {text}"
    key = match.group(1)
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="yaml-comment"' in region
    ok = ok and f'class="yaml-key">{key}</span>' in region
    ok = ok and 'class="yaml-number">3</span>' in region
    ok = ok and 'class="yaml-bool">true</span>' in region
    ok = ok and 'class="yaml-null">null</span>' in region
    return _resolve(ok, f"YAML panel key={key}")


def _h_ts_yaml_quoted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel renders the quoted string "S" without a highlight class."""
    match = re.search(
        r'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        text,
    )
    if not match:
        return False, f"Could not parse YAML quoted-string assertion: {text}"
    region = _section_region(_html(world), "sec-raw")
    ok = f"&quot;{match.group(1)}&quot;" in region
    ok = ok and "yaml-string" not in region
    return _resolve(ok, f"quoted string {match.group(1)!r}")


def _h_ts_gherkin_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Gherkin panel shows a highlighted comment, tag "T", and the keywords "A", "B", ... ."""
    match = re.search(
        r'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and '
        r"the keywords (.+)$",
        text,
    )
    if not match:
        return False, f"Could not parse Gherkin panel assertion: {text}"
    tag, keywords_phrase = match.groups()
    keywords = re.findall(r'"([^"]+)"', keywords_phrase)
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="gherkin-comment"' in region
    ok = ok and f'class="gherkin-tag">@{tag}</span>' in region
    for keyword in keywords:
        # Step keywords carry a trailing space inside the span; header
        # keywords ("Feature:", "Background:", ...) do not.
        ok = ok and (
            f'class="gherkin-keyword">{keyword}</span>' in region
            or f'class="gherkin-keyword">{keyword} </span>' in region
        )
    return _resolve(ok, f"gherkin tag={tag} keywords={keywords}")


def _h_ts_gen_inputs_headers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab of scenario "S" shows the call headers "H1" and "H2"."""
    match = re.search(
        r'the Generation Inputs tab of scenario "([^"]+)" shows the call '
        r'headers "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs headers: {text}"
    sid, header1, header2 = match.groups()
    region = _card_region(_html(world), sid)
    return _resolve(
        header1 in region and header2 in region, f"headers={header1} {header2}"
    )


def _h_ts_gen_inputs_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "L" with the value "V"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs row: {text}"
    label, value = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and value in region
    return _resolve(ok, f"row label={label} value={value}")


def _h_ts_gen_inputs_em_dash(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "Narrative summary" with the em dash "—"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs em-dash: {text}"
    label, dash = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and f">{dash}</td>" in region
    return _resolve(ok, f"em-dash row label={label}")


def register(api: Any) -> None:
    # --- Raw panels / Generation Inputs Then steps ---
    api.register(
        'the YAML panel shows a highlighted comment, key "([^"]+)", number value \\d+, boolean value .*, and null value',
        _h_ts_yaml_panel,
        source_order=8058,
    )
    api.register(
        'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        _h_ts_yaml_quoted,
        source_order=8059,
    )
    api.register(
        'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and the keywords .+',
        _h_ts_gherkin_panel,
        source_order=8060,
    )
    api.register(
        'the Generation Inputs tab of scenario "([^"]+)" shows the call headers "([^"]+)" and "([^"]+)"',
        _h_ts_gen_inputs_headers,
        source_order=8061,
    )
    api.register(
        'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        _h_ts_gen_inputs_row,
        source_order=8062,
    )
    api.register(
        'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        _h_ts_gen_inputs_em_dash,
        source_order=8063,
    )
