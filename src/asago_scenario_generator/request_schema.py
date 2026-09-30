"""Closed vocabularies for model-facing JSON Schemas.

Guided decoding samples only what the request schema allows, so a schema
enum is what keeps a guided response inside a vocabulary that code later
matches on.  These helpers are ``json_schema_extra`` callables: they change
the generated schema only.  Local Pydantic validation is unchanged, so the
existing validators still write the exact correction feedback when a
provider does not constrain its decoding.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

SchemaExtra = Callable[[dict[str, Any]], None]


def _choices(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def string_enum(values: Iterable[str]) -> SchemaExtra:
    """Restrict a string field to *values*, in the given order."""
    choices = _choices(values)

    def apply(schema: dict[str, Any]) -> None:
        if choices:
            schema["enum"] = list(choices)

    return apply


def string_items_enum(
    values: Iterable[str],
    *,
    min_items: int | None = None,
    max_items: int | None = None,
) -> SchemaExtra:
    """Restrict a string array's items to *values*.

    With no values the array must be empty: an empty enum would make any
    item unsatisfiable, and an absent enum would leave it open.
    """
    choices = _choices(values)

    def apply(schema: dict[str, Any]) -> None:
        if choices:
            schema["items"] = {**schema.get("items", {}), "enum": list(choices)}
        else:
            schema["maxItems"] = 0
        _apply_bounds(schema, min_items, max_items)

    return apply


def array_bounds(
    *, min_items: int | None = None, max_items: int | None = None
) -> SchemaExtra:
    """Set array length bounds in the schema only."""

    def apply(schema: dict[str, Any]) -> None:
        _apply_bounds(schema, min_items, max_items)

    return apply


def _apply_bounds(
    schema: dict[str, Any], min_items: int | None, max_items: int | None
) -> None:
    if min_items is not None:
        schema["minItems"] = min_items
    if max_items is not None:
        schema["maxItems"] = max_items


__all__ = ["array_bounds", "string_enum", "string_items_enum"]
