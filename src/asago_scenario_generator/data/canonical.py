"""Shared canonicalization primitives for pinned data artifacts."""

from __future__ import annotations

import json
import unicodedata
from typing import Any


def _nfc(value: str) -> str:
    """Normalize a string to Unicode NFC."""
    return unicodedata.normalize("NFC", value)


def _canonical_json(value: Any) -> str:
    """Serialize a value using the repository's canonical JSON profile."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
