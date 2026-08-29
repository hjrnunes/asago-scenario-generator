"""Neutral canonical encoding and version-framed digest primitives.

The frame is exactly ``UTF-8(domain) + NUL + canonical-json(payload)``.  The
canonical JSON contract recursively NFC-normalizes strings and mapping keys,
rejects key collisions after normalization, sorts mapping keys, emits compact
UTF-8 JSON, and rejects non-finite numbers.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from pydantic import BaseModel


class FrozenDict(dict[str, Any]):
    """A JSON-serializable mapping whose mutation methods fail closed.

    Pydantic's ``frozen`` model option protects attribute assignment but does
    not protect a nested ``dict``.  This small ``dict`` subclass keeps normal
    JSON/YAML serialization while closing every mutating mapping operation.
    """

    __slots__ = ()

    def _reject_mutation(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError("mapping is immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation

    def __ior__(self, other: object) -> "FrozenDict":
        del other
        raise TypeError("mapping is immutable")

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenDict":
        del memo
        return self


class FrozenList(list[Any]):
    """A JSON-serializable list whose mutation methods fail closed."""

    __slots__ = ()

    def _reject_mutation(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError("list is immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    __iadd__ = _reject_mutation
    __imul__ = _reject_mutation
    append = _reject_mutation
    clear = _reject_mutation
    extend = _reject_mutation
    insert = _reject_mutation
    pop = _reject_mutation
    remove = _reject_mutation
    reverse = _reject_mutation
    sort = _reject_mutation

    def __copy__(self) -> "FrozenList":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenList":
        del memo
        return self


def normalize_unicode(value: Any) -> Any:
    """Recursively NFC-normalize supported canonical values."""
    if isinstance(value, BaseModel):
        return normalize_unicode(value.model_dump(mode="json"))
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return _normalize_mapping(value)
    if isinstance(value, (list, tuple)):
        return [normalize_unicode(item) for item in value]
    return value


def _normalize_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    """Normalize one mapping while preserving unique canonical key identity."""
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("canonical JSON mapping keys must be strings")
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ValueError("canonical mapping keys collide after NFC normalization")
        normalized[normalized_key] = normalize_unicode(item)
    return normalized


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one value under the neutral canonical JSON contract."""
    return json.dumps(
        normalize_unicode(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    """Encode diagnostic JSON with the repository's stable readable layout."""
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def compute_framed_digest(domain: str, value: Any) -> str:
    """Hash one payload with an explicit versioned NUL-separated domain frame."""
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_bytes(value)
    ).hexdigest()


__all__ = [
    "FrozenDict",
    "FrozenList",
    "canonical_json_bytes",
    "canonical_json_text",
    "compute_framed_digest",
    "normalize_unicode",
]
