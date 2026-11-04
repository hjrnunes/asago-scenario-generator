"""Canonical JSON and framed digests, with both persisted encodings named.

Two Asago components persisted canonical-JSON digests before this package
existed. They differ in exactly two policies, and both are pinned here:

- The producer encoding NFC-normalizes strings and mapping keys, refuses a key
  that collides after normalization, and rejects non-finite numbers.
- The consumer encoding leaves strings as written and accepts non-finite
  numbers, as the consumer wrote its package manifests before normalization.

Both encodings sort mapping keys, use compact separators and keep non-ASCII
text in UTF-8. A digest that this module records carries its encoding name, so
a reader can say which policy produced it.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Encoding:
    """One named canonical-JSON policy."""

    name: str
    nfc: bool
    allow_nan: bool


PRODUCER_ENCODING = Encoding("canonical-json-nfc-v1", nfc=True, allow_nan=False)
CONSUMER_ENCODING = Encoding("canonical-json-v1", nfc=False, allow_nan=True)
NFC_ALLOW_NAN_ENCODING = Encoding(
    "canonical-json-nfc-allow-nan-v1", nfc=True, allow_nan=True
)
NO_NAN_ENCODING = Encoding("canonical-json-no-nan-v1", nfc=False, allow_nan=False)

_ENCODINGS = {
    (encoding.nfc, encoding.allow_nan): encoding
    for encoding in (
        PRODUCER_ENCODING,
        CONSUMER_ENCODING,
        NFC_ALLOW_NAN_ENCODING,
        NO_NAN_ENCODING,
    )
}


def encoding_for(*, nfc: bool, allow_nan: bool) -> Encoding:
    """Return the named encoding for a normalization and NaN policy."""

    return _ENCODINGS[(bool(nfc), bool(allow_nan))]


def normalize_unicode(value: Any) -> Any:
    """Recursively NFC-normalize strings, mapping keys included.

    A non-string mapping key is refused, because JSON cannot tell it from its
    text; two keys that collide after normalization are refused, because one
    would silently replace the other.
    """

    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return _normalize_mapping(value)
    if isinstance(value, (list, tuple)):
        return [normalize_unicode(item) for item in value]
    return value


def canonical_json(value: Any, *, encoding: Encoding = PRODUCER_ENCODING) -> str:
    """Encode one value under ``encoding`` as text."""

    return canonical_json_bytes(value, encoding=encoding).decode("utf-8")


def canonical_json_bytes(
    value: Any, *, encoding: Encoding = PRODUCER_ENCODING
) -> bytes:
    """Encode one value under ``encoding`` as UTF-8 bytes."""

    if not isinstance(encoding, Encoding):
        raise TypeError("encoding must be an Encoding")
    if encoding.nfc:
        value = normalize_unicode(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=encoding.allow_nan,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex sha256 of raw bytes."""

    if not isinstance(data, bytes):
        raise TypeError("sha256_hex hashes bytes")
    return hashlib.sha256(data).hexdigest()


def framed_digest(
    domain: str, value: Any, *, encoding: Encoding = PRODUCER_ENCODING
) -> str:
    """Hash a payload under ``UTF-8(domain) + NUL + canonical-json(payload)``."""

    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_bytes(value, encoding=encoding)
    ).hexdigest()


def digest_record(
    domain: str, value: Any, *, encoding: Encoding = PRODUCER_ENCODING
) -> dict[str, str]:
    """Return a framed digest together with the encoding that produced it."""

    return {
        "encoding": encoding.name,
        "domain": domain,
        "sha256": framed_digest(domain, value, encoding=encoding),
    }


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


__all__ = [
    "CONSUMER_ENCODING",
    "NFC_ALLOW_NAN_ENCODING",
    "NO_NAN_ENCODING",
    "PRODUCER_ENCODING",
    "Encoding",
    "canonical_json",
    "canonical_json_bytes",
    "digest_record",
    "encoding_for",
    "framed_digest",
    "normalize_unicode",
    "sha256_hex",
]
