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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T14:18:51Z","module_hash":"4c91ef537862d9841ea87e6d28094accd7090c63292a98be52e48c7b3a59a375","source_sha256":"b7ec4558e8c245ba552b3a611cb78805e9a0f3efe22eb4f3abe716fb95bb773d","functions":[{"id":"func/_raw_model_data","name":"_raw_model_data","line":14,"end_line":16,"hash":"d3ea2ab9e3450779be975c6899023837b3f1678b22c297701ad9bb735aa20627"},{"id":"func/_raw_model_base_model","name":"_raw_model_base_model","line":19,"end_line":21,"hash":"41f318b66c05e54145f5faeedc67d6455b335eec264860a8c04b10bccfec19d6"},{"id":"func/_raw_model_mapping","name":"_raw_model_mapping","line":24,"end_line":26,"hash":"5a3835b79a25e893712a2cb1b5b30012bec816c3f4ca724d3f658cbeffba1f0b"},{"id":"func/_copy_raw_collection","name":"_copy_raw_collection","line":29,"end_line":34,"hash":"f0c46cc8ed53e7af65fe9cd8b501f689ea4c2992ecf8708f7daee8171c58f3e9"},{"id":"func/_raw_model_mapping_dispatch","name":"_raw_model_mapping_dispatch","line":38,"end_line":39,"hash":"8054bd78bcae4c5cd3494085ac8f15959bc800961ebe232e5522c8b5a2968cd5"},{"id":"func/_raw_model_list","name":"_raw_model_list","line":43,"end_line":44,"hash":"92839135c3ee1368cc2c6cd372d0477e26475a1fd8453c799936b02901de364b"},{"id":"func/_raw_model_tuple","name":"_raw_model_tuple","line":48,"end_line":49,"hash":"cea1d39e3ec84328667ec7943293d1cb5e35379d11bd0d4e77e81a7666643258"},{"id":"func/_raw_model_set","name":"_raw_model_set","line":53,"end_line":54,"hash":"8c5d0e7ba44bfa9fdc61a03a09309dd1165545ba0cbb19067a3d695f84b09f0d"},{"id":"func/raw_model_data","name":"raw_model_data","line":57,"end_line":67,"hash":"d21d82560e3aac8c748ae9562527b122795116824a2225163cd953a8782f2a88"}]}
# mutate4py-manifest-end
