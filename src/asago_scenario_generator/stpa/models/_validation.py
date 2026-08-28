"""Shared validation helpers for boundary schema cross-reference checks."""

from __future__ import annotations


def check_duplicate_ids(ids: list[str], field_name: str) -> None:
    """Raise ValueError if *ids* contains duplicates.

    Args:
        ids: List of identifier strings to check.
        field_name: Human-readable field name used in the error message.

    Raises:
        ValueError: If any ID appears more than once.
    """
    seen: set[str] = set()
    for id_val in ids:
        if id_val in seen:
            raise ValueError(f"Duplicate {field_name}: '{id_val}'.")
        seen.add(id_val)
