"""Secret redaction for observed MCP tool metadata.

The policy runs on canonical tool fields before they reach a model, a
prompt, or a persisted profile.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_REDACTED = "[REDACTED]"
_SCHEMA_VALUE_KEYS = frozenset({"default", "example", "examples"})
_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|passwd|credential|authorization|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|default|examples?|sample)",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = re.compile(
    r"(\b(?:secret|token|password|passwd|credential|authorization|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|default|examples?|sample)"
    r"\b\s*[:=]\s*)"
    r"([^\s,;\]}]+)",
    re.IGNORECASE,
)


def sanitize_tool_fields(source: Mapping[str, Any]) -> dict[str, Any]:
    """Redact secret-like observed values before model/prompt publication."""
    sanitized: dict[str, Any] = {}
    for key, value in source.items():
        if key in {"description", "title"} and isinstance(value, str):
            sanitized[key] = _sanitize_text(value)
        elif key in {"input_schema", "output_schema", "annotations"}:
            # JSON Schema defaults/examples are interface semantics, not
            # runtime credentials by themselves.  Preserve their exact type
            # and value unless they belong to an explicitly secret-looking
            # property; annotations remain ordinary metadata and keep the
            # stricter key-based redaction below.
            sanitized[key] = sanitize_json(
                value, schema_context=key in {"input_schema", "output_schema"}
            )
        else:
            sanitized[key] = value
    return sanitized


def sanitize_json(
    value: Any,
    *,
    parent_key: str | None = None,
    schema_context: bool = False,
    schema_property: str | None = None,
) -> Any:
    """Redact secrets without changing JSON Schema semantic values.

    ``default`` and ``examples`` are schema keywords whose values can carry
    meaningful numbers, enums, or object shapes.  The old blanket key regex
    replaced all of them with ``[REDACTED]``.  We now preserve those keywords
    in schema context while still redacting values under an explicitly
    credential-like property name.  Runtime URLs, headers, and credentials do
    not enter this function: they are excluded at the transport boundary.
    """
    if isinstance(value, Mapping):
        return _sanitize_mapping(
            value,
            parent_key,
            schema_context=schema_context,
            schema_property=schema_property,
        )
    if isinstance(value, list):
        return _sanitize_sequence(
            value,
            parent_key,
            schema_context=schema_context,
            schema_property=schema_property,
        )
    if isinstance(value, tuple):
        return tuple(
            _sanitize_sequence(
                value,
                parent_key,
                schema_context=schema_context,
                schema_property=schema_property,
            )
        )
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _sanitize_mapping(
    value: Mapping[Any, Any],
    parent_key: str | None,
    *,
    schema_context: bool,
    schema_property: str | None,
) -> dict[str, Any]:
    """Redact sensitive mapping values while preserving non-sensitive fields."""
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if schema_context and key_text in _SCHEMA_VALUE_KEYS:
            if _secret_schema_property(schema_property):
                sanitized[key_text] = _redacted_json_value(item)
            else:
                # Recurse through example objects so nested secret-looking
                # keys are still protected, but retain scalar/schema value
                # types exactly.
                sanitized[key_text] = sanitize_json(
                    item,
                    parent_key=key_text,
                    schema_context=schema_context,
                    schema_property=None,
                )
            continue
        if _is_sensitive_key(key_text, parent_key):
            sanitized[key_text] = _redacted_json_value(item)
            continue
        child_property = (
            key_text
            if schema_context and parent_key == "properties"
            else schema_property
        )
        sanitized[key_text] = sanitize_json(
            item,
            parent_key=key_text,
            schema_context=schema_context,
            schema_property=child_property,
        )
    return sanitized


def _sanitize_sequence(
    value: Sequence[Any],
    parent_key: str | None,
    *,
    schema_context: bool,
    schema_property: str | None,
) -> list[Any]:
    """Sanitize each member of a JSON list/tuple."""
    return [
        sanitize_json(
            item,
            parent_key=parent_key,
            schema_context=schema_context,
            schema_property=schema_property,
        )
        for item in value
    ]


def _is_sensitive_key(key: str, parent_key: str | None) -> bool:
    """Identify secret-bearing fields without redacting schema property names."""
    if key in _SCHEMA_VALUE_KEYS:
        return False
    return parent_key != "properties" and bool(_SENSITIVE_KEY.search(key))


def _secret_schema_property(property_name: str | None) -> bool:
    """Return whether a schema property's defaults/examples may be secret."""
    return bool(property_name and _SENSITIVE_KEY.search(property_name))


def _redacted_json_value(value: Any) -> Any:
    """Redact one sensitive value while retaining list shape for schema keywords."""
    if isinstance(value, (list, tuple)):
        return [_REDACTED]
    return _REDACTED


def _sanitize_text(value: str) -> str:
    """Redact credential-like key/value fragments embedded in prose."""
    return _SENSITIVE_TEXT.sub(rf"\1{_REDACTED}", value)


__all__ = ["sanitize_json", "sanitize_tool_fields"]
