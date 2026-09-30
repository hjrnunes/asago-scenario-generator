"""Closed vocabularies for model-facing JSON Schemas.

Guided decoding samples only what the request schema allows, so a schema
enum is what keeps a guided response inside a vocabulary that code later
matches on.  These helpers change the generated schema only.  Local
Pydantic validation is unchanged, so the existing validators still write
the exact correction feedback when a provider does not constrain its
decoding.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable
from typing import Any, TypeVar

from pydantic import BaseModel

SchemaExtra = Callable[[dict[str, Any]], None]
_ModelT = TypeVar("_ModelT", bound=type[BaseModel])


def with_keyed_rows(
    model: _ModelT,
    *,
    array_field: str,
    key_field: str,
    keys: Iterable[str],
) -> _ModelT:
    """Return a subclass whose schema asks for one row per key, in order.

    An enum on the key plus a row count still lets a guided decoder repeat
    one key and skip another.  The schema instead lists one ``prefixItems``
    row per key, each with its key fixed, and allows no other items.  The
    subclass keeps the model's name and validation.
    """
    ordered = _choices(keys)

    def model_json_schema(cls: type[BaseModel], *args: Any, **kwargs: Any):
        schema = super(keyed, cls).model_json_schema(*args, **kwargs)
        _key_rows(schema, array_field, key_field, ordered)
        return schema

    keyed = type(
        model.__name__,
        (model,),
        {
            "__module__": model.__module__,
            "__qualname__": model.__qualname__,
            "model_json_schema": classmethod(model_json_schema),
        },
    )
    return keyed  # type: ignore[return-value]


def _key_rows(
    schema: dict[str, Any], array_field: str, key_field: str, keys: list[str]
) -> None:
    array = schema["properties"][array_field]
    row = array["items"]
    if "$ref" in row:
        row = schema["$defs"][row["$ref"].rsplit("/", 1)[-1]]
    rows = []
    for key in keys:
        keyed_row = copy.deepcopy(row)
        keyed_row["properties"] = {
            **keyed_row["properties"],
            key_field: {"type": "string", "enum": [key]},
        }
        rows.append(keyed_row)
    schema["properties"][array_field] = {
        **{
            name: value
            for name, value in array.items()
            if name not in {"items", "minItems", "maxItems"}
        },
        "type": "array",
        "prefixItems": rows,
        "items": False,
        "minItems": len(keys),
        "maxItems": len(keys),
    }


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


def require_schema_fields(*names: str) -> SchemaExtra:
    """Mark defaulted fields as required in the object schema only."""

    def extra(schema: dict[str, Any]) -> None:
        required = schema.setdefault("required", [])
        required.extend(name for name in names if name not in required)

    return extra


__all__ = [
    "array_bounds",
    "require_schema_fields",
    "string_enum",
    "string_items_enum",
    "with_keyed_rows",
]
