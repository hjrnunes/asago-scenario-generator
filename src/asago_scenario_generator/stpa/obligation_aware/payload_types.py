"""Build provider payload types whose list length equals one request's count."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, conlist, create_model


def require_positive_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def require_non_negative_count(value: int, name: str) -> None:
    """Reject booleans and negative dynamic-schema counts."""
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def exact_length_payload_type(
    name: str,
    base: type[BaseModel],
    field: str,
    element: Any,
    count: int,
    *,
    module: str,
) -> type[BaseModel]:
    """Subclass *base* with *field* required to hold exactly *count* elements.

    *module* is explicit because ``create_model`` would otherwise record this
    module, and the recorded module appears in the generated schema.
    """
    return create_model(
        name,
        __base__=base,
        __module__=module,
        **{field: (conlist(element, min_length=count, max_length=count), ...)},
    )
