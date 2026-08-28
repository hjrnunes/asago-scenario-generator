"""Shared raw traversal for tolerant STPA model boundaries."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from functools import singledispatch
from typing import Any

from pydantic import BaseModel


@singledispatch
def _raw_model_data(value: Any) -> Any:
    """Deep-copy values that need no structural conversion."""
    return copy.deepcopy(value)


def _raw_model_base_model(value: BaseModel) -> dict[str, Any]:
    """Read a Pydantic model graph without invoking its serializer."""
    return raw_model_data(value.__dict__)


def _raw_model_mapping(value: Mapping[Any, Any]) -> dict[Any, Any]:
    """Recursively copy mapping values while preserving their keys."""
    return {key: raw_model_data(field_value) for key, field_value in value.items()}


def _copy_raw_collection(
    value: list[Any] | tuple[Any, ...] | set[Any],
    factory: Callable[..., Any],
) -> Any:
    """Copy collection members and rebuild the requested built-in shape."""
    return factory(raw_model_data(item) for item in value)


@_raw_model_data.register(Mapping)
def _raw_model_mapping_dispatch(value: Mapping[Any, Any]) -> dict[Any, Any]:
    return _raw_model_mapping(value)


@_raw_model_data.register(list)
def _raw_model_list(value: list[Any]) -> list[Any]:
    return _copy_raw_collection(value, list)


@_raw_model_data.register(tuple)
def _raw_model_tuple(value: tuple[Any, ...]) -> tuple[Any, ...]:
    return _copy_raw_collection(value, tuple)


@_raw_model_data.register(set)
def _raw_model_set(value: set[Any]) -> set[Any]:
    return _copy_raw_collection(value, set)


def raw_model_data(value: Any) -> Any:
    """Copy a model graph without invoking Pydantic serialization.

    Tolerant ``model_construct`` boundaries can retain schema-adjacent values
    until a later normalization pass.  Reading ``__dict__`` recursively keeps
    those intermediate values available without serializer warnings while
    ensuring callers receive an independent copy.
    """
    if isinstance(value, BaseModel):
        return _raw_model_base_model(value)
    return _raw_model_data(value)
