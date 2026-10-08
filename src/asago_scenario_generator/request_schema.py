"""Closed vocabularies for guided-decoding request schemas.

Guided decoding samples only what the request schema allows, so a schema
enum is what keeps a guided response inside a vocabulary that code later
matches on.  Call sites apply these helpers only when
:func:`uses_guided_decoding` is true; other clients keep the static schema.
The helpers change the generated schema only, so the existing validators
still write the exact correction feedback.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Iterable, Mapping
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


def _apply_bounds(
    schema: dict[str, Any], min_items: int | None, max_items: int | None
) -> None:
    if min_items is not None:
        schema["minItems"] = min_items
    if max_items is not None:
        schema["maxItems"] = max_items


def uses_guided_decoding(llm_client: object) -> bool:
    """Whether *llm_client*'s profile asks for guided decoding.

    Call sites send the tightened request schemas only to these clients;
    every other client receives the static wire's schema unchanged.
    """
    return getattr(llm_client, "use_guided_decoding", False) is True


def portable_request_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``schema`` that guided decoders can compile.

    vLLM's xgrammar backend rejects a string schema that combines ``pattern``
    with ``minLength`` or ``maxLength``.  When the pattern cannot match an
    empty string, ``minLength: 1`` adds nothing and is dropped here.  The
    response is still validated against the original Pydantic model.
    """

    def portable(node: Any) -> Any:
        if isinstance(node, Mapping):
            converted = {key: portable(value) for key, value in node.items()}
            pattern = converted.get("pattern")
            if (
                isinstance(pattern, str)
                and converted.get("minLength") == 1
                and _pattern_rejects_empty(pattern)
            ):
                del converted["minLength"]
            return converted
        if isinstance(node, list):
            return [portable(value) for value in node]
        return copy.deepcopy(node)

    return portable(schema)


def _pattern_rejects_empty(pattern: str) -> bool:
    try:
        return re.search(pattern, "") is None
    except re.error:
        return False


__all__ = [
    "portable_request_schema",
    "string_enum",
    "string_items_enum",
    "uses_guided_decoding",
    "with_keyed_rows",
]
