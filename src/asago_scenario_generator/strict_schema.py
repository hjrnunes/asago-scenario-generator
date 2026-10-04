"""Pure helpers for OpenAI Structured Outputs schemas.

OpenAI strict schemas differ from the JSON Schema emitted by Pydantic in two
important ways: every object property must be required, and optional values
must use ``null`` rather than omission.  The provider still returns the
original application model, so the decoder removes those synthetic nulls
before validating the response against the original Pydantic class.
"""

from __future__ import annotations

import re
from collections.abc import Mapping as ABCMapping
from collections.abc import Sequence as ABCSequence
from copy import deepcopy
from typing import Any, Mapping, get_args, get_origin

from pydantic import BaseModel

_SUPPORTED_KEYS = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "anyOf",
        "description",
        "enum",
        "items",
        "properties",
        "required",
        "title",
        "type",
    }
)
_UNSUPPORTED_COMPOSITION_KEYS = frozenset(
    {"allOf", "dependentRequired", "dependentSchemas", "else", "if", "not", "then"}
)


def _model_type(value: Any) -> type[BaseModel] | None:
    """Return a Pydantic model class when *value* is one."""
    if isinstance(value, type) and issubclass(value, BaseModel):
        return value
    return None


def _resolve_ref(root: Mapping[str, Any], reference: str) -> Any:
    """Resolve a local JSON pointer from a schema root."""
    if not reference.startswith("#/"):
        return None
    current: Any = root
    for component in reference[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    return current


def _is_nullable(schema: Mapping[str, Any]) -> bool:
    """Return whether a normalized schema already accepts JSON null."""
    if schema.get("type") == "null":
        return True
    schema_type = schema.get("type")
    if isinstance(schema_type, list) and "null" in schema_type:
        return True
    return any(
        isinstance(branch, Mapping) and branch.get("type") == "null"
        for branch in schema.get("anyOf", ())
    )


def _as_nullable(schema: dict[str, Any]) -> dict[str, Any]:
    """Represent an omitted Pydantic property as a required nullable value."""
    if _is_nullable(schema):
        return schema
    return {"anyOf": [schema, {"type": "null"}]}


def _merge_object_all_of(
    branches: list[dict[str, Any]], remainder: dict[str, Any]
) -> dict[str, Any] | None:
    """Flatten object-only ``allOf`` branches into one strict object."""
    if not branches or not all(branch.get("type") == "object" for branch in branches):
        return None
    merged = {key: value for key, value in remainder.items() if key != "allOf"}
    properties: dict[str, Any] = {}
    required: list[str] = []
    for branch in branches:
        properties.update(branch.get("properties", {}))
        for name in branch.get("required", ()):
            if name not in required:
                required.append(name)
    properties.update(merged.get("properties", {}))
    for name in merged.get("required", ()):
        if name not in required:
            required.append(name)
    merged["type"] = "object"
    merged["properties"] = properties
    merged["required"] = required
    merged["additionalProperties"] = False
    return merged


_Context = tuple[Mapping[str, Any], tuple[str, ...], frozenset[str]]


def _normalize_schema(
    source: Mapping[str, Any],
    *,
    root: Mapping[str, Any],
    path: tuple[str, ...] = (),
    resolving_refs: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Recursively convert one JSON Schema mapping into OpenAI strict form."""
    node = deepcopy(dict(source))

    # OpenAI accepts $defs/$ref, but a $ref cannot have sibling keywords.
    # Resolve local ref siblings when possible; recursive refs remain leaves.
    reference = node.get("$ref")
    if isinstance(reference, str) and len(node) > 1:
        expanded = _expand_ref_siblings(node, reference, root, resolving_refs)
        if expanded is not None:
            return _normalize_schema(
                expanded,
                root=root,
                path=path,
                resolving_refs=resolving_refs | {reference},
            )
        node = {"$ref": reference}

    context = (root, path, resolving_refs)
    node = _normalize_composition(node, context)
    _normalize_scalar_keywords(node)
    _normalize_defs(node, context)
    _normalize_properties(node, context)
    _normalize_items(node, context)
    _normalize_any_of(node, context)

    # Remove provider-unsupported metadata and any unknown Pydantic extension.
    return {
        key: value
        for key, value in node.items()
        if key in _SUPPORTED_KEYS or key == "$defs"
    }


def _normalize_child(
    schema: Mapping[str, Any], context: _Context, *segments: str
) -> dict[str, Any]:
    """Normalize a nested schema at ``path + segments``."""
    root, path, resolving_refs = context
    return _normalize_schema(
        schema,
        root=root,
        path=(*path, *segments),
        resolving_refs=resolving_refs,
    )


def _expand_ref_siblings(
    node: dict[str, Any],
    reference: str,
    root: Mapping[str, Any],
    resolving_refs: frozenset[str],
) -> dict[str, Any] | None:
    """Inline a resolvable, non-recursive local ``$ref`` under its siblings."""
    resolved = _resolve_ref(root, reference)
    if not isinstance(resolved, Mapping) or reference in resolving_refs:
        return None
    siblings = {key: value for key, value in node.items() if key != "$ref"}
    expanded = deepcopy(dict(resolved))
    expanded.update(siblings)
    return expanded


def _normalize_composition(node: dict[str, Any], context: _Context) -> dict[str, Any]:
    """Map ``oneOf`` to ``anyOf`` and flatten or convert ``allOf``."""
    # Pydantic emits oneOf for some discriminated unions. OpenAI's supported
    # composition primitive is anyOf, so preserve the branches under that
    # supported keyword. Object-only allOf can be flattened without changing
    # its intersection semantics.
    if "oneOf" in node and "anyOf" not in node:
        node["anyOf"] = node.pop("oneOf")
    if not isinstance(node.get("allOf"), list):
        return node
    normalized_branches = [
        _normalize_child(branch, context, "allOf", str(index))
        for index, branch in enumerate(node["allOf"])
        if isinstance(branch, Mapping)
    ]
    if len(normalized_branches) == 1:
        branch = normalized_branches[0]
        remainder = {key: value for key, value in node.items() if key != "allOf"}
        branch.update(remainder)
        return branch
    merged = _merge_object_all_of(normalized_branches, node)
    if merged is not None:
        return merged
    node["anyOf"] = normalized_branches
    node.pop("allOf", None)
    return node


def _normalize_scalar_keywords(node: dict[str, Any]) -> None:
    """Rewrite ``const`` and ``definitions``; drop unsupported keywords."""
    # ``const`` is equivalent to a one-value enum, and enum is the documented
    # strict-output primitive.
    if "const" in node and "enum" not in node:
        node["enum"] = [node.pop("const")]
    else:
        node.pop("const", None)

    # ``definitions`` is the older spelling; OpenAI supports the Pydantic v2
    # spelling only.
    if "definitions" in node and "$defs" not in node:
        node["$defs"] = node.pop("definitions")
    for key in _UNSUPPORTED_COMPOSITION_KEYS:
        node.pop(key, None)
    node.pop("discriminator", None)
    node.pop("default", None)


def _normalize_defs(node: dict[str, Any], context: _Context) -> None:
    defs = node.get("$defs")
    if isinstance(defs, Mapping):
        node["$defs"] = {
            str(name): _normalize_child(definition, context, "$defs", str(name))
            for name, definition in defs.items()
            if isinstance(definition, Mapping)
        }


def _normalize_properties(node: dict[str, Any], context: _Context) -> None:
    """Require every property, making originally optional ones nullable."""
    properties = node.get("properties")
    if isinstance(properties, Mapping):
        normalized_properties: dict[str, Any] = {}
        for name, property_schema in properties.items():
            if not isinstance(property_schema, Mapping):
                continue
            normalized = _normalize_child(
                property_schema, context, "properties", str(name)
            )
            original_required = set(node.get("required", ()))
            if name not in original_required:
                normalized = _as_nullable(normalized)
            normalized_properties[str(name)] = normalized
        node["type"] = "object"
        node["properties"] = normalized_properties
        node["required"] = list(normalized_properties)
        node["additionalProperties"] = False
    elif node.get("type") == "object":
        # OpenAI requires this even for an empty object or a mapping schema.
        node["additionalProperties"] = False


def _normalize_items(node: dict[str, Any], context: _Context) -> None:
    items = node.get("items")
    if isinstance(items, Mapping):
        node["items"] = _normalize_child(items, context, "items")


def _normalize_any_of(node: dict[str, Any], context: _Context) -> None:
    any_of = node.get("anyOf")
    if isinstance(any_of, list):
        node["anyOf"] = [
            _normalize_child(branch, context, "anyOf", str(index))
            for index, branch in enumerate(any_of)
            if isinstance(branch, Mapping)
        ]


def to_openai_strict_schema(
    model_or_schema: type[BaseModel] | Mapping[str, Any],
) -> dict[str, Any]:
    """Return a fresh OpenAI Structured Outputs schema.

    The input model/schema is never mutated. Every object has
    ``additionalProperties: false`` and every property appears in
    ``required``. Properties that were optional in the source schema accept
    ``null`` so the provider can satisfy the required-key rule.
    """
    model = _model_type(model_or_schema)
    if model is not None:
        source = model.model_json_schema()
    elif isinstance(model_or_schema, Mapping):
        source = dict(model_or_schema)
    else:
        raise TypeError("expected a Pydantic BaseModel class or JSON Schema mapping")
    return _normalize_schema(source, root=source)


def _unwrap_annotation(annotation: Any) -> Any:
    """Drop Annotated wrappers while retaining the underlying annotation."""
    while (
        get_origin(annotation) is not None
        and str(get_origin(annotation)) == "typing.Annotated"
    ):
        annotation = get_args(annotation)[0]
    return annotation


def _model_classes(annotation: Any) -> tuple[type[BaseModel], ...]:
    """Collect model classes nested in unions and containers."""
    annotation = _unwrap_annotation(annotation)
    model = _model_type(annotation)
    if model is not None:
        return (model,)
    result: list[type[BaseModel]] = []
    for argument in get_args(annotation):
        for candidate in _model_classes(argument):
            if candidate not in result:
                result.append(candidate)
    return tuple(result)


def _field_aliases(name: str, field: Any) -> tuple[str, ...]:
    """Return the names a Pydantic field can use in provider JSON."""
    aliases = [name]
    alias = getattr(field, "alias", None)
    if isinstance(alias, str) and alias not in aliases:
        aliases.append(alias)
    serialization_alias = getattr(field, "serialization_alias", None)
    if isinstance(serialization_alias, str) and serialization_alias not in aliases:
        aliases.append(serialization_alias)
    validation_alias = getattr(field, "validation_alias", None)
    choices = getattr(validation_alias, "choices", None)
    if choices:
        aliases.extend(
            choice
            for choice in choices
            if isinstance(choice, str) and choice not in aliases
        )
    elif isinstance(validation_alias, str) and validation_alias not in aliases:
        aliases.append(validation_alias)
    return tuple(aliases)


def _model_for_mapping(
    annotation: Any, value: Mapping[str, Any]
) -> type[BaseModel] | None:
    """Choose the model branch whose fields explain a mapping value."""
    candidates = _model_classes(annotation)
    if not candidates:
        return None
    keys = set(value)
    for candidate in candidates:
        aliases = {
            alias
            for name, field in candidate.model_fields.items()
            for alias in _field_aliases(name, field)
        }
        if keys & aliases:
            return candidate
    return candidates[0]


def _mapping_value_annotation(annotation: Any) -> Any:
    """Return a mapping value annotation, or None when one is unavailable."""
    annotation = _unwrap_annotation(annotation)
    origin = get_origin(annotation)
    if origin in (dict, Mapping, ABCMapping):
        args = get_args(annotation)
        return args[1] if len(args) == 2 else None
    for argument in get_args(annotation):
        nested = _mapping_value_annotation(argument)
        if nested is not None:
            return nested
    return None


def _sequence_item_annotation(annotation: Any) -> Any:
    """Return the item annotation for a list/tuple/set-like field."""
    annotation = _unwrap_annotation(annotation)
    origin = get_origin(annotation)
    if origin in (list, tuple, set, frozenset, ABCSequence):
        args = get_args(annotation)
        return args[0] if args else None
    for argument in get_args(annotation):
        nested = _sequence_item_annotation(argument)
        if nested is not None:
            return nested
    return None


def _strip_nulls(value: Any, annotation: Any) -> Any:
    """Copy *value* while dropping nulls for non-required model fields."""
    annotation = _unwrap_annotation(annotation)
    if isinstance(value, Mapping):
        return _strip_mapping_nulls(value, annotation)
    if isinstance(value, (list, tuple, set, frozenset)):
        return _strip_collection_nulls(value, annotation)
    return value


def _strip_mapping_nulls(value: Mapping[str, Any], annotation: Any) -> dict[str, Any]:
    """Copy a mapping as a typed dict, a model payload, or an untyped mapping."""
    mapping_annotation = _mapping_value_annotation(annotation)
    if mapping_annotation is not None:
        return {
            key: _strip_nulls(item, mapping_annotation) for key, item in value.items()
        }
    model = _model_for_mapping(annotation, value)
    if model is None:
        return {key: _strip_nulls(item, None) for key, item in value.items()}
    return _strip_model_nulls(value, model.model_fields)


def _strip_model_nulls(
    value: Mapping[str, Any], fields: Mapping[str, Any]
) -> dict[str, Any]:
    """Drop nulls for non-required fields of one model payload."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        field_name = _field_name_for_key(fields, key)
        if field_name is None:
            result[key] = _strip_nulls(item, None)
            continue
        field = fields[field_name]
        if item is None and not field.is_required():
            continue
        result[key] = _strip_nulls(item, field.annotation)
    return result


def _field_name_for_key(fields: Mapping[str, Any], key: str) -> str | None:
    """Return the model field whose name or alias is *key*."""
    return next(
        (name for name, field in fields.items() if key in _field_aliases(name, field)),
        None,
    )


def _strip_collection_nulls(value: Any, annotation: Any) -> Any:
    """Copy a list, tuple, set, or frozenset, keeping its collection type."""
    item_annotation = _sequence_item_annotation(annotation)
    converted = [_strip_nulls(item, item_annotation) for item in value]
    if isinstance(value, tuple):
        return tuple(converted)
    if isinstance(value, set):
        return set(converted)
    if isinstance(value, frozenset):
        return frozenset(converted)
    return converted


def strip_null_fields(
    value: Any,
    model: type[BaseModel],
) -> Any:
    """Drop provider-emitted nulls for fields with original model defaults."""
    if not _model_type(model):
        raise TypeError("model must be a Pydantic BaseModel class")
    return _strip_nulls(value, model)


def portable_request_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``schema`` that guided decoders can compile.

    vLLM's xgrammar backend rejects a string schema that combines ``pattern``
    with ``minLength`` or ``maxLength``.  When the pattern cannot match an
    empty string, ``minLength: 1`` adds nothing and is dropped here.  The
    response is still validated against the original Pydantic model.
    """

    def portable(node: Any) -> Any:
        if isinstance(node, ABCMapping):
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
        return deepcopy(node)

    return portable(schema)


def _pattern_rejects_empty(pattern: str) -> bool:
    try:
        return re.search(pattern, "") is None
    except re.error:
        return False


__all__ = ["portable_request_schema", "strip_null_fields", "to_openai_strict_schema"]
