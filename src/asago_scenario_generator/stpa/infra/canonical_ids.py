"""Deterministic canonical ID allocation for request-local handles."""

from __future__ import annotations

import re
from collections.abc import Iterable


def next_canonical_number(prefix: str, ids: Iterable[str]) -> int:
    """Return one past the highest ``<prefix><n>`` number among *ids*."""
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    numbers = (
        int(match.group(1)) for value in ids if (match := pattern.fullmatch(value))
    )
    return max(numbers, default=0) + 1


def allocate_canonical_ids(
    prefix: str, used: Iterable[str], handles: Iterable[str]
) -> dict[str, str]:
    """Map each handle, in the given order, to a fresh ``<prefix><n>``.

    Numbering starts after the highest ``<prefix><n>`` in *used*, so no
    allocated ID collides with one already in use.  A repeated handle
    consumes another number and keeps the last one.
    """
    start = next_canonical_number(prefix, used)
    mapping: dict[str, str] = {}
    for number, handle in enumerate(handles, start=start):
        mapping[handle] = f"{prefix}{number}"
    return mapping


__all__ = ["allocate_canonical_ids", "next_canonical_number"]
