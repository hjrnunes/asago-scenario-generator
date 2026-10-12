"""Flatten object unions in request schemas.

GLM's structured-output endpoint decodes a ``oneOf`` by always taking its last
branch, whatever the model chose.  The producer therefore sends every object
union as one object: the discriminator becomes one string enum of every
branch's values, and a property only some branches define becomes nullable
and required.  Replies are validated against the original Pydantic models.

A union is a ``oneOf``, or an ``anyOf`` with two or more object branches
after ``$ref`` resolution.  A nullable field (one schema and
``{"type": "null"}``) and a choice of scalars are not unions.

:func:`restore_flat_reply` undoes the flattening on a reply before it is
validated: it keeps only the keys the selected branch defines and drops a null
in one of the branch's own fields that the branch rejects.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from functools import lru_cache
from typing import Any

from pydantic import BaseModel

_NULL = {"type": "null"}
_DEF_PREFIX = "#/$defs/"
_LABELS = ("title", "description")


class UnionMergeError(ValueError):
    """Raised when a union's branches cannot merge into one object."""


def find_unions(schema: Mapping[str, Any]) -> list[str]:
    """Return the JSON pointer of every union in ``schema``."""
    defs = schema.get("$defs", {})
    found: list[str] = []
    _collect_unions(schema, "", defs, found)
    return found


def _collect_unions(node: Any, path: str, defs: Mapping, found: list[str]) -> None:
    if isinstance(node, Mapping):
        if _is_union(node, defs):
            found.append(path)
        for key, value in node.items():
            _collect_unions(value, f"{path}/{key}", defs, found)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _collect_unions(value, f"{path}/{index}", defs, found)


def _is_union(node: Mapping[str, Any], defs: Mapping) -> bool:
    if isinstance(node.get("oneOf"), list):
        return True
    branches = node.get("anyOf")
    if not isinstance(branches, list):
        return False
    objects = [b for b in branches if _is_object(_deref(b, defs))]
    return len(objects) >= 2


def _is_object(node: Any) -> bool:
    return isinstance(node, Mapping) and (
        node.get("type") == "object" or "properties" in node
    )


def _deref(node: Any, defs: Mapping) -> Any:
    ref = node.get("$ref") if isinstance(node, Mapping) else None
    if isinstance(ref, str) and ref.startswith(_DEF_PREFIX):
        return defs.get(ref[len(_DEF_PREFIX) :], node)
    return node


def flatten_unions(schema: Mapping[str, Any]) -> Any:
    """Return ``schema`` with every union merged into one object schema.

    A schema without a union is returned as it is, so its request stays
    byte-identical.  ``$defs`` entries left unreferenced are removed.
    """
    if not find_unions(schema):
        return schema
    flat = _Flattener(schema.get("$defs", {})).node(schema, "")
    return _prune_defs(flat)


class _Flattener:
    def __init__(self, defs: Mapping[str, Any]) -> None:
        self._defs = defs
        self._flat_defs: dict[str, Any] = {}

    def node(self, node: Any, path: str) -> Any:
        if isinstance(node, list):
            return [self.node(v, f"{path}/{i}") for i, v in enumerate(node)]
        if not isinstance(node, Mapping):
            return node
        if _is_union(node, self._defs):
            return self._union(node, path)
        return {key: self.node(value, f"{path}/{key}") for key, value in node.items()}

    def _union(self, node: Mapping[str, Any], path: str) -> dict[str, Any]:
        key = "oneOf" if isinstance(node.get("oneOf"), list) else "anyOf"
        options = node[key]
        branches = [self._branch(b, path) for b in options if b != _NULL]
        discriminator = node.get("discriminator", {}).get("propertyName")
        merged = _Merge(self, path, discriminator).objects(branches)
        meta = {k: v for k, v in node.items() if k not in (key, "discriminator")}
        merged = _with_description(
            merged, _union_description(meta, branches, discriminator)
        )
        meta.pop("description", None)
        if len(branches) < len(options):
            return {"anyOf": [merged, dict(_NULL)], **meta}
        return {**meta, **merged}

    def _branch(self, branch: Any, path: str) -> dict[str, Any]:
        resolved = self.resolve(branch, path)
        if not _is_object(resolved):
            raise UnionMergeError(
                f"union at {path}: branch {branch!r} is not an object"
            )
        return resolved

    def resolve(self, node: Any, path: str) -> Any:
        """Return ``node`` with a ``$defs`` reference replaced by its flat entry."""
        ref = node.get("$ref") if isinstance(node, Mapping) else None
        if not (isinstance(ref, str) and ref.startswith(_DEF_PREFIX)):
            return self.node(node, path)
        name = ref[len(_DEF_PREFIX) :]
        if name not in self._flat_defs:
            self._flat_defs[name] = self.node(self._defs[name], f"/$defs/{name}")
        extra = {k: v for k, v in node.items() if k != "$ref"}
        return {**self._flat_defs[name], **extra}


class _Merge:
    """Merge the object branches of one union, in branch order."""

    def __init__(self, flattener: _Flattener, path: str, discriminator: str | None):
        self._flattener = flattener
        self._path = path
        self._discriminator = discriminator

    def objects(self, branches: list[Mapping[str, Any]]) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        required: list[str] = []
        for name in _ordered_names(branches):
            defining = [b for b in branches if name in b.get("properties", {})]
            schema, always = self._property(name, defining)
            if len(defining) < len(branches):
                schema = _nullable(schema, self._applies_when(defining))
                always = True
            properties[name] = schema
            if always or all(name in b.get("required", ()) for b in branches):
                required.append(name)
        merged: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "required": required,
        }
        if all(b.get("additionalProperties") is False for b in branches):
            merged["additionalProperties"] = False
        return merged

    def _property(
        self, name: str, defining: list[Mapping[str, Any]]
    ) -> tuple[dict[str, Any], bool]:
        """Return the merged schema and whether merging made it required."""
        schemas = [b["properties"][name] for b in defining]
        first = schemas[0]
        if all(s == first for s in schemas):
            return first, False
        resolved = [self._flattener.resolve(s, self._path) for s in schemas]
        if all(_string_choices(s) is not None for s in resolved):
            return _merged_choices(schemas, resolved), False
        if all(_is_object(s) for s in resolved):
            return self._merged_objects(name, schemas, resolved), False
        nullable = _nullable_merge(schemas)
        if nullable is not None:
            return nullable, True
        raise UnionMergeError(
            f"union at {self._path}: property {name!r} differs between "
            f"branches: {_first_other(schemas)!r}"
        )

    def _merged_objects(
        self, name: str, schemas: list[Mapping], resolved: list[Mapping]
    ) -> dict[str, Any]:
        nested = _Merge(self._flattener, f"{self._path}/{name}", None)
        labels = _labels(schemas)
        description = _union_description(labels, resolved, None)
        title = {k: v for k, v in labels.items() if k == "title"}
        return _with_description({**title, **nested.objects(resolved)}, description)

    def _applies_when(self, defining: list[Mapping[str, Any]]) -> str:
        if self._discriminator is None:
            return "Applies to some forms of this object only; null otherwise."
        values = [v for b in defining for v in _branch_values(b, self._discriminator)]
        return (
            f"Applies when `{self._discriminator}` is {_spoken(values)}; "
            "null otherwise."
        )


def _ordered_names(branches: Iterable[Mapping[str, Any]]) -> list[str]:
    return list(dict.fromkeys(n for b in branches for n in b.get("properties", {})))


def _first_other(schemas: list[Any]) -> tuple[Any, Any]:
    return schemas[0], next(s for s in schemas if s != schemas[0])


def _string_choices(schema: Any) -> list[Any] | None:
    if not isinstance(schema, Mapping) or schema.get("type") != "string":
        return None
    if "const" in schema:
        return [schema["const"]]
    enum = schema.get("enum")
    return list(enum) if isinstance(enum, list) else None


def _merged_choices(schemas: list[Mapping], resolved: list[Mapping]) -> dict[str, Any]:
    values = [v for s in resolved for v in _string_choices(s) or ()]
    labels = _labels(schemas)
    # A ``$ref`` choice carries its description on the definition.
    described = [s["description"] for s in resolved if "description" in s]
    if described:
        labels.setdefault("description", described[0])
    return {**labels, "type": "string", "enum": list(dict.fromkeys(values))}


def _labels(schemas: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Return the title and description of the first schema that has each."""
    return {k: v for s in reversed(schemas) for k, v in s.items() if k in _LABELS}


def _branch_values(branch: Mapping[str, Any], discriminator: str) -> list[Any]:
    return _string_choices(branch.get("properties", {}).get(discriminator)) or []


def _spoken(values: list[Any]) -> str:
    quoted = [f"`{v}`" for v in dict.fromkeys(values)]
    if len(quoted) < 2:
        return "".join(quoted)
    return f"{', '.join(quoted[:-1])} or {quoted[-1]}"


def _split_nullable(schema: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    """Return ``schema`` without labels or default, and whether it was nullable."""
    core = {k: v for k, v in schema.items() if k not in (*_LABELS, "default")}
    options = core.get("anyOf")
    if set(core) == {"anyOf"} and isinstance(options, list) and _NULL in options:
        rest = [o for o in options if o != _NULL]
        if len(rest) == 1:
            return dict(rest[0]), True
        return {"anyOf": rest}, True
    return core, False


def _nullable(schema: Mapping[str, Any], sentence: str) -> dict[str, Any]:
    core, _ = _split_nullable(schema)
    labels = {k: schema[k] for k in _LABELS if k in schema}
    nullable: dict[str, Any] = {"anyOf": [core, dict(_NULL)], **labels}
    return _with_description(nullable, _joined(schema.get("description"), sentence))


def _nullable_merge(schemas: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Merge a schema with its nullable form into the nullable form, or decline."""
    cores = [_split_nullable(s)[0] for s in schemas]
    if any(c != cores[0] for c in cores):
        return None
    labels = _labels(schemas)
    return {"anyOf": [cores[0], dict(_NULL)], **labels}


def _union_description(
    meta: Mapping[str, Any],
    branches: list[Mapping[str, Any]],
    discriminator: str | None,
) -> str | None:
    parts = [meta.get("description")]
    for branch in branches:
        text = branch.get("description")
        if text and discriminator is not None:
            values = _spoken(_branch_values(branch, discriminator))
            text = f"When `{discriminator}` is {values}: {text}"
        parts.append(text)
    return "\n".join(dict.fromkeys(p for p in parts if p)) or None


def _joined(description: Any, sentence: str) -> str:
    return f"{description} {sentence}" if description else sentence


def _with_description(
    schema: dict[str, Any], description: str | None
) -> dict[str, Any]:
    without = {k: v for k, v in schema.items() if k != "description"}
    if description is None:
        return without
    return {**without, "description": description}


def _prune_defs(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.get("$defs")
    if not isinstance(defs, Mapping):
        return schema
    body = {k: v for k, v in schema.items() if k != "$defs"}
    kept = _reachable(body, defs)
    if not kept:
        return body
    return {**body, "$defs": {n: d for n, d in defs.items() if n in kept}}


def _reachable(body: Any, defs: Mapping[str, Any]) -> set[str]:
    kept: set[str] = set()
    pending = _refs(body)
    while pending:
        name = pending.pop()
        if name in kept or name not in defs:
            continue
        kept.add(name)
        pending |= _refs(defs[name])
    return kept


def _refs(node: Any) -> set[str]:
    if isinstance(node, list):
        return set().union(*(_refs(v) for v in node))
    if not isinstance(node, Mapping):
        return set()
    found = set().union(*(_refs(v) for v in node.values()))
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith(_DEF_PREFIX):
        found.add(ref[len(_DEF_PREFIX) :])
    return found


def restore_flat_reply(
    value: Any,
    schema: Mapping[str, Any],
    drops: list[dict[str, str]] | None = None,
) -> Any:
    """Return ``value`` with each flat union restored to its selected branch.

    ``schema`` is the original (unflattened) schema.  At each discriminated
    union, only the keys the selected branch defines are kept: every other
    key is dropped, whether its value is null or not.  A key the branch
    defines whose value is null is dropped too when the branch's schema for
    that key does not accept null, so the field's default applies; a required
    field without a default then fails validation as a missing field.  Nulls
    outside a union position stay.  ``value`` is not modified.

    When ``drops`` is given, each drop is appended to it as ``path`` (a JSON
    pointer to the dropped key), ``branch`` (the discriminator value), and
    ``reason``: ``foreign_value`` for a non-null value the branch does not
    define, ``null_to_default`` for a null its own field rejects.  A foreign
    null is the normal flat form and is not recorded.  The dropped values are
    not copied.
    """
    restorer = _Restorer(schema.get("$defs", {}), [] if drops is None else drops)
    return restorer.value(value, schema, "")


@lru_cache(maxsize=256)
def _restorable_schema(model: type) -> Mapping[str, Any] | None:
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        return None
    schema = model.model_json_schema()
    return schema if _has_discriminator(schema) else None


def restores_flat_replies(model: type) -> bool:
    """Whether replies to ``model`` can carry flat unions to restore."""
    return _restorable_schema(model) is not None


def restore_flat_reply_for(
    model: type, value: Any, drops: list[dict[str, str]] | None = None
) -> Any:
    """Restore a reply against ``model``'s schema; return it as is without unions.

    ``drops`` collects the drops as :func:`restore_flat_reply` records them.
    """
    schema = _restorable_schema(model)
    return value if schema is None else restore_flat_reply(value, schema, drops)


def flat_restore_drops(model: type, value: Any) -> list[dict[str, str]]:
    """Return the drops that restoring ``value`` against ``model`` makes."""
    drops: list[dict[str, str]] = []
    restore_flat_reply_for(model, value, drops)
    return drops


def _has_discriminator(node: Any) -> bool:
    if isinstance(node, list):
        return any(_has_discriminator(v) for v in node)
    if not isinstance(node, Mapping):
        return False
    return "discriminator" in node or any(_has_discriminator(v) for v in node.values())


class _Restorer:
    def __init__(self, defs: Mapping[str, Any], drops: list[dict[str, str]]) -> None:
        self._defs = defs
        self._drops = drops

    def value(self, value: Any, node: Any, path: str) -> Any:
        node = _deref(node, self._defs)
        if not isinstance(node, Mapping):
            return value
        options = node.get("oneOf", node.get("anyOf"))
        if isinstance(options, list):
            return self._union(value, node, options, path)
        if isinstance(value, dict):
            return self._object(value, node, path)
        if isinstance(value, list):
            return self._array(value, node, path)
        return value

    def _union(
        self, value: Any, node: Mapping[str, Any], options: list, path: str
    ) -> Any:
        branch = _selected_branch(value, node, options)
        if branch is None:
            return value
        if "discriminator" in node:
            tag = value[node["discriminator"]["propertyName"]]
            value = self._within_branch(value, branch, tag, path)
        return self.value(value, branch, path)

    def _within_branch(
        self, value: dict[str, Any], branch: Any, tag: str, path: str
    ) -> dict[str, Any]:
        properties = _deref(branch, self._defs).get("properties", {})
        kept = {}
        for key, item in value.items():
            fate = self._fate(key, item, properties)
            if fate == "keep":
                kept[key] = item
            elif fate != "foreign_null":
                self._drops.append(
                    {"path": _pointer(path, key), "branch": tag, "reason": fate}
                )
        return kept

    def _fate(self, key: str, item: Any, properties: Mapping[str, Any]) -> str:
        if key not in properties:
            return "foreign_null" if item is None else "foreign_value"
        if item is None and not _accepts_null(properties[key], self._defs):
            return "null_to_default"
        return "keep"

    def _object(
        self, value: dict[str, Any], node: Mapping[str, Any], path: str
    ) -> dict:
        properties = node.get("properties", {})
        return {
            key: self.value(item, properties[key], _pointer(path, key))
            if key in properties
            else item
            for key, item in value.items()
        }

    def _array(self, value: list[Any], node: Mapping[str, Any], path: str) -> list[Any]:
        prefix = node.get("prefixItems") or []
        items = node.get("items")
        return [
            self.value(item, prefix[i] if i < len(prefix) else items, f"{path}/{i}")
            for i, item in enumerate(value)
        ]


def _pointer(path: str, key: str) -> str:
    return f"{path}/{key.replace('~', '~0').replace('/', '~1')}"


def _selected_branch(value: Any, node: Mapping[str, Any], options: list) -> Any:
    """Return the branch ``value`` takes, or ``None`` when no single one does."""
    if value is None:
        return None
    discriminator = node.get("discriminator")
    if isinstance(discriminator, Mapping):
        return _mapped_branch(value, discriminator)
    rest = [o for o in options if o != _NULL]
    return rest[0] if len(rest) == 1 else None


def _accepts_null(schema: Any, defs: Mapping[str, Any]) -> bool:
    """Whether ``schema`` allows null; a schema it cannot read counts as allowing it."""
    schema = _deref(schema, defs)
    if not isinstance(schema, Mapping):
        return True
    for key in ("anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            return any(_accepts_null(option, defs) for option in schema[key])
    return _literal_accepts_null(schema)


def _literal_accepts_null(schema: Mapping[str, Any]) -> bool:
    if "const" in schema:
        return schema["const"] is None
    if "enum" in schema:
        return None in schema["enum"]
    kind = schema.get("type")
    if kind is None:
        return True
    return kind == "null" or (isinstance(kind, list) and "null" in kind)


def _mapped_branch(value: Any, discriminator: Mapping[str, Any]) -> Any:
    if not isinstance(value, dict):
        return None
    tag = value.get(discriminator.get("propertyName"))
    mapping = discriminator.get("mapping", {})
    target = mapping.get(tag) if isinstance(tag, str) else None
    return {"$ref": target} if target else None


def flat_reply(value: Any, flat_schema: Mapping[str, Any]) -> Any:
    """Return ``value`` written as a reply to the flattened ``flat_schema``.

    Each required property ``value`` lacks is added as null, which is how a
    flat union says "this branch does not use the property".
    """
    return _fill(value, flat_schema, flat_schema.get("$defs", {}))


def _fill(value: Any, node: Any, defs: Mapping[str, Any]) -> Any:
    node = _deref(node, defs)
    if value is None or not isinstance(node, Mapping):
        return value
    if isinstance(node.get("anyOf"), list):
        return _fill_nullable(value, node["anyOf"], defs)
    if isinstance(value, list):
        return [_fill(item, node.get("items"), defs) for item in value]
    if isinstance(value, dict):
        return _fill_object(value, node, defs)
    return value


def _fill_nullable(value: Any, options: list, defs: Mapping[str, Any]) -> Any:
    rest = [o for o in options if o != _NULL]
    return _fill(value, rest[0], defs) if len(rest) == 1 else value


def _fill_object(
    value: dict[str, Any], node: Mapping[str, Any], defs: Mapping[str, Any]
) -> dict[str, Any]:
    properties = node.get("properties", {})
    filled = {
        key: _fill(item, properties.get(key), defs) for key, item in value.items()
    }
    missing = [k for k in node.get("required", ()) if k not in filled]
    return {**filled, **dict.fromkeys(missing)}


__all__ = [
    "UnionMergeError",
    "flat_reply",
    "flat_restore_drops",
    "find_unions",
    "flatten_unions",
    "restore_flat_reply",
    "restore_flat_reply_for",
    "restores_flat_replies",
]
