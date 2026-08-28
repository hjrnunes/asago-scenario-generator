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


def compute_framed_digest(domain: str, value: Any) -> str:
    """Hash one payload with an explicit versioned NUL-separated domain frame."""
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_bytes(value)
    ).hexdigest()


__all__ = [
    "FrozenDict",
    "FrozenList",
    "canonical_json_bytes",
    "compute_framed_digest",
    "normalize_unicode",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T16:49:02Z","module_hash":"2433751a99f9ba58654cf7db2a7aa201ead4522fb5760e738a97f59a2f0993f0","source_sha256":"52fac04a25655c4b4896a5e9bebb65cc5eb5d94a70c8f92aa758ee302481de72","functions":[{"id":"func/FrozenDict._reject_mutation","name":"_reject_mutation","line":29,"end_line":31,"hash":"bf308f05b4c0fb40aeac77bb0a5e35f83dddee960f69becfaba7872a83427b54"},{"id":"func/FrozenDict.__ior__","name":"__ior__","line":41,"end_line":43,"hash":"c3f56d6e8daa040b18600cd548b1dd69cfea0318f2b2f2c149757b0ac11e5372"},{"id":"func/FrozenDict.__copy__","name":"__copy__","line":45,"end_line":46,"hash":"b9fb3cba0906893f2aa5598f57fa80de0ccf607268273009ac2c96c4e1a02d53"},{"id":"func/FrozenDict.__deepcopy__","name":"__deepcopy__","line":48,"end_line":50,"hash":"1d48f21c66d542039bb87292d376c195f8e6ebff8690de1a8b1356fea93ef7b6"},{"id":"func/FrozenList._reject_mutation","name":"_reject_mutation","line":58,"end_line":60,"hash":"6af222a5ad9ae8be94b1cddb9991518573b13e86aeb4c54d718556264cd120b6"},{"id":"func/FrozenList.__copy__","name":"__copy__","line":75,"end_line":76,"hash":"a2d19af42cc9a4733254d32af3091b053fad9c5e50f4d620f60d3d2a0b74dde7"},{"id":"func/FrozenList.__deepcopy__","name":"__deepcopy__","line":78,"end_line":80,"hash":"5da169bb1e402c8ae344846f8c8adeaf835ad3d1524831f56650184857c2893f"},{"id":"func/normalize_unicode","name":"normalize_unicode","line":83,"end_line":93,"hash":"84a0ac8901097adb93c2b249259ec54741279f26fb2a8f9e183ff754cd1a5bae"},{"id":"func/_normalize_mapping","name":"_normalize_mapping","line":96,"end_line":106,"hash":"70eb0a643da9307fa156d6fbfceed6365cb0908563973555ab0edc87c802d654"},{"id":"func/canonical_json_bytes","name":"canonical_json_bytes","line":109,"end_line":117,"hash":"350332d5e93e2fa4591001ae45d7da5c0b7926b6268ab73861b023fdc4c94c32"},{"id":"func/compute_framed_digest","name":"compute_framed_digest","line":120,"end_line":124,"hash":"373b6ab10cd152379326df9568f98fdfd558f5b7b5fdf0118aa60583b43c403e"}]}
# mutate4py-manifest-end
