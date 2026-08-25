"""Raw Data section and YAML / Gherkin syntax highlighters."""

from __future__ import annotations

import re

from asago_scenario_generator.html_utils import escape_html as _esc


def build_raw_data_section(raw_files: dict[str, str]) -> str:
    if not raw_files:
        return ""

    tabs_html = ""
    panels_html = ""

    for i, (filename, content) in enumerate(raw_files.items()):
        active = " active" if i == 0 else ""
        tab_id = f"raw-{i}"

        tabs_html += f'<button class="raw-tab{active}" onclick="switchRawTab(\'{tab_id}\', this)">{_esc(filename)}</button>'

        if filename.endswith((".yaml", ".yml")):
            highlighted = _highlight_yaml(content)
        elif filename.endswith(".feature"):
            highlighted = _highlight_gherkin(content)
        else:
            highlighted = _esc(content)

        panels_html += f"""
        <div id="{tab_id}" class="raw-panel{active}">
          <button class="copy-btn" onclick="copyToClipboard('{tab_id}-code')">Copy</button>
          <div class="code-block" id="{tab_id}-code">{highlighted}</div>
        </div>"""

    return f"""
    <div id="sec-raw" class="section">
      <div class="section-header">
        <h2>Raw Data</h2>
        <span class="badge">{len(raw_files)} files</span>
      </div>
      <div class="raw-tabs">{tabs_html}</div>
      {panels_html}
    </div>
    """


def _highlight_yaml(text: str) -> str:
    """Simple regex-based YAML syntax highlighting."""
    lines = text.split("\n")
    result = []
    for line in lines:
        escaped = _esc(line)

        # Comments
        if escaped.strip().startswith("#"):
            result.append(f'<span class="yaml-comment">{escaped}</span>')
            continue

        # Key-value pairs
        m = re.match(r"^(\s*)([\w_-]+)(\s*:\s*)(.*)", escaped)
        if m:
            indent, key, colon, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(
                f'{indent}<span class="yaml-key">{key}</span>{colon}{highlighted_value}'
            )
            continue

        # List items
        m = re.match(r"^(\s*-\s+)(.*)", escaped)
        if m:
            prefix, value = m.groups()
            highlighted_value = _highlight_yaml_value(value)
            result.append(f"{prefix}{highlighted_value}")
            continue

        result.append(escaped)

    return "\n".join(result)


_YAML_LITERAL_CLASSES: dict[str, str] = {
    "null": "yaml-null",
    "~": "yaml-null",
    "true": "yaml-bool",
    "false": "yaml-bool",
}

_GHERKIN_STEP_KEYWORDS: list[str] = [
    "Feature:",
    "Background:",
    "Scenario:",
    "Scenario Outline:",
    "Given ",
    "When ",
    "Then ",
    "And ",
    "But ",
    "* ",
]


def _is_quoted_literal(v: str) -> bool:
    """Return whether *v* is wrapped in matching single or double quotes."""
    return v[:1] == v[-1:] and v[:1] in ("'", '"')


def _highlight_yaml_value(value: str) -> str:
    v = value.strip()
    if not v:
        return value
    literal_class = _YAML_LITERAL_CLASSES.get(v)
    if literal_class:
        return f'<span class="{literal_class}">{value}</span>'
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return f'<span class="yaml-number">{value}</span>'
    if _is_quoted_literal(v):
        return f'<span class="yaml-string">{value}</span>'
    return value


def _gherkin_keyword_span(escaped: str) -> tuple[int, str, int] | None:
    """Return (index, span, tail_start) of the first Gherkin keyword, or None."""
    for kw in _GHERKIN_STEP_KEYWORDS:
        ekw = _esc(kw)
        if escaped.strip().startswith(ekw):
            idx = escaped.index(ekw)
            tail_start = idx + len(ekw)
            return (idx, f'<span class="gherkin-keyword">{ekw}</span>', tail_start)
    return None


def _highlight_gherkin_strings(escaped: str) -> str:
    """Wrap triple-quoted marker runs in a highlight span."""
    if "&quot;&quot;&quot;" not in escaped:
        return escaped
    return escaped.replace(
        "&quot;&quot;&quot;",
        '<span class="gherkin-string">&quot;&quot;&quot;</span>',
    )


def _highlight_gherkin_line(escaped: str) -> str:
    """Highlight one escaped Gherkin line, preserving unmatched lines."""
    if escaped.strip().startswith("#"):
        return f'<span class="gherkin-comment">{escaped}</span>'
    if escaped.strip().startswith("@"):
        return f'<span class="gherkin-tag">{escaped}</span>'

    keyword = _gherkin_keyword_span(escaped)
    if keyword is not None:
        idx, span, tail_start = keyword
        escaped = escaped[:idx] + span + escaped[tail_start:]
    return _highlight_gherkin_strings(escaped)


def _highlight_gherkin(text: str) -> str:
    """Simple regex-based Gherkin syntax highlighting."""
    return "\n".join(_highlight_gherkin_line(_esc(line)) for line in text.split("\n"))
