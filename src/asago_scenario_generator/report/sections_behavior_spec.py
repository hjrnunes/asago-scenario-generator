"""Gherkin behavior-spec and zone-badge rendering for scenario cards."""

from __future__ import annotations

import re

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    ZONE_NAMES as _ZONE_NAMES_TUPLE,
)
from asago_scenario_generator.report.provenance import (
    ZONE_BG_COLORS,
    ZONE_COLORS,
    _INT_TO_ZONE_NAME,
)

_ZONE_NAME_SET = set(_ZONE_NAMES_TUPLE)


def _process_docstring_line(
    stripped: str,
    in_docstring: bool,
    docstring_lines: list[str],
    result: list[str],
) -> tuple[bool, list[str], bool]:
    """Advance the docstring parser; appends closing HTML to *result*.

    Returns ``(in_docstring, docstring_lines, consumed)``; a consumed line
    is never parsed as a Gherkin step.
    """
    if in_docstring:
        if stripped.endswith('"""'):
            docstring_lines.append(stripped[:-3])
            ds_text = "\n".join(docstring_lines).strip()
            result.append(f'<div class="step-docstring">{_esc(ds_text)}</div>')
            return False, [], True
        return True, docstring_lines + [stripped], True
    if stripped.startswith('"""'):
        return True, [stripped[3:]], True
    return False, docstring_lines, False


def _continue_or_skip_html(stripped: str) -> str:
    """HTML for a non-keyword line: '' for @tags, blanks, and comments."""
    if stripped.startswith("@") or not stripped:
        return ""
    if stripped.startswith("#"):
        return ""
    return (
        '<div style="padding:4px 14px 4px 70px;font-size:13px;'
        f'color:var(--text-secondary);">{_esc(stripped)}</div>'
    )


def _gherkin_step_split(stripped: str) -> tuple[str | None, str, str]:
    """Split a Gherkin keyword from its text; keyword is None when unmatched."""
    for kw, cls in [
        ("Feature:", ""),
        ("Background:", ""),
        ("Scenario:", ""),
        ("Given ", "step-given"),
        ("When ", "step-when"),
        ("And ", "step-and"),
        ("Then ", "step-then"),
        ("But ", "step-but"),
        ("* ", "step-star"),
    ]:
        if stripped.startswith(kw):
            return kw.strip().rstrip(":"), stripped[len(kw) :], cls
    return None, stripped, ""


def _match_display_zone(zone_token: str) -> str | None:
    """Match a zone token against display names (case-insensitive)."""
    for name, display in ZONE_DISPLAY_NAMES.items():
        if zone_token.lower() in display.lower():
            return name
    return None


def _zone_token_name(zone_token: str) -> str | None:
    """Resolve a zone token to a canonical zone name, or None."""
    if zone_token.isdigit():
        return _INT_TO_ZONE_NAME.get(int(zone_token))
    if zone_token in _ZONE_NAME_SET:
        return zone_token
    return _match_display_zone(zone_token)


def _zone_badge_html(zn: str) -> str:
    """Render a colored zone badge for a canonical zone name."""
    zc = ZONE_COLORS.get(zn, "#666")
    zbg = ZONE_BG_COLORS.get(zn, "#333")
    zone_display_name = ZONE_DISPLAY_NAMES.get(zn, zn)
    return (
        f'<span class="zone-badge" style="background:{zbg};color:{zc};'
        f'margin-left:6px;">{_esc(zone_display_name)}</span>'
    )


def _extract_zone_badge(text: str) -> str:
    """Extract a zone badge from step text, supporting legacy formats."""
    zone_badge = ""
    zone_match = re.search(r"\(.*?[Zz]one\s+(\S+(?:\s+\S+)*).*?\)", text)
    if zone_match:
        zone_token = zone_match.group(1).rstrip(")")
        zn = _zone_token_name(zone_token)
        if zn:
            zone_badge = _zone_badge_html(zn)
    return zone_badge


def _step_or_header_html(keyword: str, text: str, step_class: str) -> str:
    """Render a Gherkin header line or a step row with its zone badge."""
    if keyword in ("Feature", "Background", "Scenario"):
        return (
            '<div style="padding:10px 0 6px;font-size:14px;font-weight:700;'
            'color:var(--text-primary);">'
            f'<span style="color:var(--accent);">{_esc(keyword)}:</span> '
            f"{_esc(text)}</div>"
        )
    zone_badge = _extract_zone_badge(text)
    return (
        f'<div class="feature-step {step_class}">'
        f'<span class="step-keyword">{_esc(keyword)}</span>'
        f'<span class="step-text">{_esc(text)}{zone_badge}</span>'
        f"</div>"
    )


def _build_behavior_spec(feature_content: str) -> str:
    if not feature_content:
        return '<p style="color:var(--text-muted);">No behavior specification available.</p>'

    lines = feature_content.strip().split("\n")
    result = []
    in_docstring = False
    docstring_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Handle docstrings (triple-quoted blocks)
        in_docstring, docstring_lines, is_docstring = _process_docstring_line(
            stripped, in_docstring, docstring_lines, result
        )
        if is_docstring:
            continue

        # Parse Gherkin keywords
        keyword, text, step_class = _gherkin_step_split(stripped)
        if keyword is None:
            # Skip @id/blank/comment lines; render continuation lines
            cont_html = _continue_or_skip_html(stripped)
            if cont_html:
                result.append(cont_html)
            continue

        result.append(_step_or_header_html(keyword, text, step_class))

    return "\n".join(result)
