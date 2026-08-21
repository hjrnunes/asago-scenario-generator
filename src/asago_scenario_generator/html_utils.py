"""Shared HTML rendering helpers."""

from __future__ import annotations

import html
from typing import Any


def escape_html(value: Any | None) -> str:
    """Escape a value for safe insertion into HTML."""
    if value is None:
        return ""
    return html.escape(str(value))
