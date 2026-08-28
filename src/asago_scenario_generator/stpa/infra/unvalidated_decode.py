"""Policy-free unvalidated construction of Pydantic model graphs.

Omitted required fields receive type-appropriate sentinels so attribute
access is safe.  Declared defaults stay authoritative.  Required nested
models are not fabricated.  A generic input ``id`` may fill an omitted
required field whose name ends in ``_id``.  Other fields never read
``id``.  Content validity belongs to model validators.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, TypeVar, Union, get_args, get_origin

from pydantic import BaseModel

from asago_scenario_generator.stpa._model_data import raw_model_data as raw_model_data

_T = TypeVar("_T", bound=BaseModel)
_UNION_TYPE = type(int | str)
_EMPTY_COLLECTION_FACTORIES = {
    list: list,
    tuple: tuple,
    set: set,
    dict: dict,
}


def _construct_collection(
    value: Any,
    origin: Any,
    args: tuple[Any, ...],
) -> Any:
    """Construct a supported collection while preserving its element values."""
    item_type = args[0] if args else Any
    converted = [_construct_unvalidated(item, item_type) for item in value]
    if origin is tuple:
        return tuple(converted)
    if origin is set:
        return set(converted)
    return converted


def _construct_union(value: Any, candidates: tuple[Any, ...]) -> Any:
    """Construct the first union member that accepts *value*."""
    for candidate in candidates:
        if candidate is type(None):
            continue
        try:
            return _construct_unvalidated(value, candidate)
        except (TypeError, ValueError):
            continue
    return value


def _construct_enum(value: Any, annotation: type[Enum]) -> Any:
    """Convert an enum value, retaining malformed values for later validation."""
    try:
        return annotation(value)
    except ValueError:
        return value


def _required_union_sentinel(candidates: tuple[Any, ...]) -> Any:
    """Choose a sentinel from a required union annotation."""
    if type(None) in candidates:
        return None
    first_member = next(
        (member for member in candidates if member is not type(None)),
        None,
    )
    return _required_field_sentinel(first_member)


def _required_collection_sentinel(origin: Any, annotation: Any) -> Any:
    """Return a fresh empty value for a supported collection annotation."""
    factory = _EMPTY_COLLECTION_FACTORIES.get(origin or annotation)
    return factory() if factory else None


def _required_scalar_sentinel(annotation: Any) -> Any:
    """Return the scalar sentinel for an omitted required field."""
    if annotation is str:
        return ""
    if annotation is int:
        return 0
    if annotation is float:
        return 0.0
    if annotation is bool:
        return False
    return None


def _required_field_sentinel(annotation: Any) -> Any:
    """Return an attribute-safe sentinel for an omitted required field."""
    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (_UNION_TYPE, Union):
        return _required_union_sentinel(args)

    if origin is Annotated:
        return _required_field_sentinel(args[0]) if args else None

    collection_sentinel = _required_collection_sentinel(origin, annotation)
    if collection_sentinel is not None:
        return collection_sentinel
    return _required_scalar_sentinel(annotation)


def _id_alias(name: str, value: dict[str, Any]) -> bool:
    """Return True when a generic ``id`` may fill an omitted ``*_id`` field."""
    return name.endswith("_id") and "id" in value


def _omitted_value(
    name: str,
    field: Any,
    value: dict[str, Any],
) -> Any:
    """Fill one omitted required field from ``id`` or a type sentinel."""
    if _id_alias(name, value):
        return _construct_unvalidated(value["id"], field.annotation)
    return _required_field_sentinel(field.annotation)


def _construct_model_values(
    value: dict[str, Any],
    annotation: type[BaseModel],
) -> dict[str, Any]:
    """Construct supplied fields and sentinels for required omitted fields."""
    values: dict[str, Any] = {}
    for name, field in annotation.model_fields.items():
        if name in value:
            values[name] = _construct_unvalidated(value[name], field.annotation)
            continue
        if field.is_required():
            values[name] = _omitted_value(name, field, value)
    return values


def construct_model_unvalidated(
    value: dict[str, Any],
    model_class: type[_T],
) -> _T:
    """Build *model_class* from a mapping without running field validators."""
    values = _construct_model_values(value, model_class)
    return model_class.model_construct(**values)


def _construct_model(value: dict[str, Any], annotation: type[BaseModel]) -> Any:
    """Construct a nested model without running field validators."""
    return construct_model_unvalidated(value, annotation)


def _construct_typed_value(value: Any, annotation: type[Any]) -> Any:
    """Construct enum or model annotations without running validators."""
    if issubclass(annotation, Enum):
        return _construct_enum(value, annotation)
    if issubclass(annotation, BaseModel) and isinstance(value, dict):
        return _construct_model(value, annotation)
    return value


def _construct_unvalidated(value: Any, annotation: Any) -> Any:
    """Construct nested Pydantic models without running field validators."""
    if value is None:
        return None

    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (list, tuple, set):
        return _construct_collection(value, origin, args)
    if origin in (_UNION_TYPE, Union):
        return _construct_union(value, args)
    if isinstance(annotation, type):
        return _construct_typed_value(value, annotation)
    return value
