"""Closed setup binding resolution for frozen artifact packages."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CLOSED_TYPES = frozenset({"array", "boolean", "integer", "number", "object", "string"})
SOURCE_KINDS = frozenset({"supplied_input", "setup_output"})
MISSING_POLICIES = frozenset({"inconclusive", "stop"})
_SLOT_RE = re.compile(r"\{\{([^{}]*)\}\}")


class BindingError(ValueError):
    """Raised when an authored binding cannot be resolved exactly."""


@dataclass(frozen=True)
class RuntimeBinding:
    name: str
    expected_type: str
    source_kind: str
    source_ref: str
    selector: str
    consumers: tuple[str, ...]
    on_missing: str

    @classmethod
    def from_dict(cls, value: Any) -> RuntimeBinding:
        if not isinstance(value, dict):
            raise BindingError("binding must be an object")
        required = {
            "name",
            "expected_type",
            "source_kind",
            "source_ref",
            "selector",
            "consumers",
            "on_missing",
        }
        missing, unknown = required - set(value), set(value) - required
        if missing or unknown:
            raise BindingError(
                f"binding fields invalid (missing={sorted(missing)}, unknown={sorted(unknown)})"
            )
        consumers = value["consumers"]
        if not isinstance(consumers, list) or not all(
            isinstance(item, str) and item.strip() for item in consumers
        ):
            raise BindingError("binding consumers must be non-empty strings")
        if any(
            not isinstance(value[field], str)
            for field in (
                "name",
                "expected_type",
                "source_kind",
                "source_ref",
                "selector",
                "on_missing",
            )
        ):
            raise BindingError("binding scalar fields must be strings")
        return cls(
            name=value["name"],
            expected_type=value["expected_type"],
            source_kind=value["source_kind"],
            source_ref=value["source_ref"],
            selector=value["selector"],
            consumers=tuple(consumers),
            on_missing=value["on_missing"],
        )


def validate_binding_declarations(
    declarations: Any,
    *,
    inventory: dict[str, Any],
    runtime_contract: dict[str, Any],
    setup_operations: set[str] | None = None,
) -> tuple[RuntimeBinding, ...]:
    if not isinstance(declarations, list):
        raise BindingError("runtime_bindings must be a list")
    result: list[RuntimeBinding] = []
    names: set[str] = set()
    for raw in declarations:
        binding = RuntimeBinding.from_dict(raw)
        if (
            not isinstance(binding.name, str)
            or not binding.name
            or binding.name in names
        ):
            raise BindingError(f"duplicate or blank binding: {binding.name!r}")
        if binding.expected_type not in CLOSED_TYPES:
            raise BindingError(f"binding expected_type is not closed: {binding.name}")
        if binding.source_kind not in SOURCE_KINDS:
            raise BindingError(f"binding source_kind is not closed: {binding.name}")
        if binding.on_missing not in MISSING_POLICIES:
            raise BindingError(f"binding on_missing is not closed: {binding.name}")
        if binding.source_kind == "setup_output" and setup_operations is not None:
            operation = _setup_operation(binding.source_ref)
            if operation not in setup_operations:
                raise BindingError(
                    f"binding setup operation is not declared: {binding.name}"
                )
        schema = _source_schema(binding, inventory, runtime_contract)
        actual = _schema_at_selector(schema, binding.selector)
        if actual is None:
            raise BindingError(
                f"undocumented selector for binding {binding.name}: {binding.selector}"
            )
        if not _types_compatible(actual, binding.expected_type):
            raise BindingError(
                f"binding type mismatch for {binding.name}: expected {binding.expected_type}, source is {actual}"
            )
        names.add(binding.name)
        result.append(binding)
    return tuple(result)


def resolve_bindings(
    declarations: tuple[RuntimeBinding, ...] | list[RuntimeBinding],
    *,
    setup_outputs: dict[str, Any],
    supplied_inputs: dict[str, Any] | None = None,
    allow_null_bindings: set[str] | frozenset[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    values: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    supplied_inputs = supplied_inputs or {}
    allow_null_bindings = allow_null_bindings or set()
    for binding in declarations:
        if binding.source_kind == "setup_output":
            operation = _setup_operation(binding.source_ref)
            source = {"result": setup_outputs.get(operation)}
            provenance_source = f"setup:{operation}"
        else:
            fact = binding.source_ref.removeprefix("facts:")
            source = {"value": supplied_inputs.get(fact)}
            provenance_source = f"facts:{fact}"
        try:
            value = select_value(source, binding.selector)
        except BindingError as exc:
            raise BindingError(f"binding_missing:{binding.name}:{exc}") from exc
        if not _value_matches_type(value, binding.expected_type) and not (
            value is None and binding.name in allow_null_bindings
        ):
            raise BindingError(f"binding_mistyped:{binding.name}")
        values[binding.name] = value
        provenance[binding.name] = {
            "source_kind": binding.source_kind,
            "source_ref": binding.source_ref,
            "selector": binding.selector,
            "provenance": provenance_source,
        }
    return values, provenance


def substitute_slots(
    template: str,
    values: dict[str, Any],
    declarations: tuple[RuntimeBinding, ...] | list[RuntimeBinding],
) -> str:
    by_name = {item.name: item for item in declarations}
    tokens = [match.group(1) for match in _SLOT_RE.finditer(template)]
    for token in tokens:
        _validate_slot_name(token, by_name)
        _validate_scalar_slot(by_name[token])
        if token not in values:
            raise BindingError(f"missing bound value: {token}")
        if not _value_matches_type(values[token], by_name[token].expected_type):
            raise BindingError(f"mistyped bound value: {token}")
        if isinstance(values[token], (dict, list)):
            raise BindingError(f"non-scalar slot value: {token}")
    return _SLOT_RE.sub(lambda match: str(values[match.group(1)]), template)


def validate_slot_references(
    template: str,
    declarations: tuple[RuntimeBinding, ...] | list[RuntimeBinding],
) -> None:
    """Reject invalid or undeclared slots without resolving their values."""

    by_name = {item.name: item for item in declarations}
    for match in _SLOT_RE.finditer(template):
        token = match.group(1)
        _validate_slot_name(token, by_name)
        _validate_scalar_slot(by_name[token])


def _validate_scalar_slot(binding: RuntimeBinding) -> None:
    if binding.expected_type in {"array", "object"}:
        raise BindingError(f"non-scalar slot value: {binding.name}")


def _validate_slot_name(token: str, by_name: dict[str, Any] | set[str]) -> None:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) or token not in by_name:
        raise BindingError(f"undeclared slot: {token}")


def select_value(source: Any, selector: str) -> Any:
    parts = _selector_parts(selector)
    current = source
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise BindingError(f"selector not found: {selector}")
    return current


def _source_schema(
    binding: RuntimeBinding, inventory: dict[str, Any], runtime_contract: dict[str, Any]
) -> dict[str, Any]:
    setup_permissions = runtime_contract.get("setup_permissions", [])
    if not isinstance(setup_permissions, list):
        raise BindingError("runtime setup_permissions must be a list")
    if binding.source_kind == "setup_output":
        operation = _setup_operation(binding.source_ref)
        operations = inventory.get("operations", [])
        if not isinstance(operations, list):
            raise BindingError("inventory operations must be a list")
        record = next(
            (
                item
                for item in operations
                if isinstance(item, dict) and item.get("name") == operation
            ),
            None,
        )
        if record is None:
            raise BindingError(f"unknown setup operation: {operation}")
        if operation not in setup_permissions:
            raise BindingError(f"setup operation is not permitted: {operation}")
        schema = record.get("result_schema")
    else:
        fact_name = binding.source_ref.removeprefix("facts:")
        facts = inventory.get("facts", [])
        if not isinstance(facts, list):
            raise BindingError("inventory facts must be a list")
        record = next(
            (
                item
                for item in facts
                if isinstance(item, dict) and item.get("ref") == fact_name
            ),
            None,
        )
        schema = record.get("schema") if record else None
    if not isinstance(schema, dict):
        raise BindingError(f"missing source schema for binding: {binding.name}")
    return schema


def _schema_at_selector(schema: dict[str, Any], selector: str) -> str | None:
    selected = _schema_node_at_selector(schema, selector)
    return selected.get("type") if selected is not None else None


def _schema_node_at_selector(
    schema: dict[str, Any], selector: str
) -> dict[str, Any] | None:
    try:
        parts = _selector_parts(selector)
    except BindingError:
        return None
    if not parts or parts[0] not in {"result", "value"}:
        return None
    current: Any = schema
    for part in parts[1:]:
        if not isinstance(current, dict):
            return None
        if current.get("type") == "object":
            properties = current.get("properties")
            if not isinstance(properties, dict) or part not in properties:
                return None
            current = properties[part]
        else:
            return None
    return current if isinstance(current, dict) else None


def _selector_parts(selector: str) -> list[str]:
    parts = selector.split(".")
    if not parts or any(not part for part in parts):
        raise BindingError(f"invalid selector: {selector}")
    return parts


def _binding_value_schema(
    binding: RuntimeBinding,
    *,
    inventory: dict[str, Any],
    runtime_contract: dict[str, Any],
) -> dict[str, Any] | None:
    source = _source_schema(binding, inventory, runtime_contract)
    return _schema_node_at_selector(source, binding.selector)


def _schema_at_path(schema: dict[str, Any], path: list[str]) -> dict[str, Any] | None:
    try:
        path = _selector_parts(".".join(path))
    except BindingError:
        return None
    current: Any = schema
    for part in path:
        if not isinstance(current, dict) or current.get("type") != "object":
            return None
        properties = current.get("properties")
        if not isinstance(properties, dict) or part not in properties:
            return None
        current = properties[part]
    return current if isinstance(current, dict) else None


def _setup_operation(source_ref: str) -> str:
    prefix, _, operation = source_ref.partition(":")
    if prefix != "setup" or not operation:
        raise BindingError(
            f"setup binding source_ref must be setup:<operation>: {source_ref}"
        )
    return operation


def _types_compatible(actual: str, expected: str) -> bool:
    return actual == expected or (actual == "integer" and expected == "number")


def _value_matches_type(value: Any, expected: str) -> bool:
    return {
        "boolean": lambda: isinstance(value, bool),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: (
            isinstance(value, (int, float)) and not isinstance(value, bool)
        ),
        "string": lambda: isinstance(value, str),
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
    }.get(expected, lambda: False)()


__all__ = [
    "BindingError",
    "CLOSED_TYPES",
    "RuntimeBinding",
    "resolve_bindings",
    "select_value",
    "substitute_slots",
    "validate_slot_references",
    "validate_binding_declarations",
]
