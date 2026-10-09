"""Neutral canonical encoding and version-framed digest primitives.

The frame is exactly ``UTF-8(domain) + NUL + canonical-json(payload)``.  The
canonical JSON contract recursively NFC-normalizes strings and mapping keys,
rejects key collisions after normalization, sorts mapping keys, emits compact
UTF-8 JSON, and rejects non-finite numbers.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from typing import Any, ClassVar, Self

import yaml
from pydantic import BaseModel, ConfigDict, model_validator


class ClosedCanonicalModel(BaseModel):
    """Closed immutable model whose inputs use the canonical Unicode form."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Normalize Unicode before validating identities or digests."""
        return normalize_unicode(value)


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


def normalize_unicode(value: Any, *, keep_models: bool = False) -> Any:
    """Recursively NFC-normalize supported canonical values.

    With ``keep_models``, validated models pass through unchanged, so raw input
    can be normalized before typed validation without dumping nested models.
    """
    if isinstance(value, BaseModel):
        if keep_models:
            return value
        return normalize_unicode(value.model_dump(mode="json"))
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return _normalize_mapping(value, keep_models)
    if isinstance(value, (list, tuple)):
        return [normalize_unicode(item, keep_models=keep_models) for item in value]
    return value


def freeze_json(value: Any) -> Any:
    """Recursively close JSON data into ``FrozenDict`` and ``FrozenList``.

    A ``FrozenDict`` or ``FrozenList`` passes through unchanged and unchecked,
    because an earlier call already closed it. Scalars pass through; a NaN or
    infinite float raises ``ValueError``, and any other non-JSON value or
    non-string mapping key raises ``TypeError``.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return _checked_json_scalar(value)
    if isinstance(value, FrozenDict | FrozenList):
        return value
    if isinstance(value, Mapping):
        return _freeze_json_mapping(value)
    if isinstance(value, (list, tuple)):
        return FrozenList(freeze_json(item) for item in value)
    raise TypeError("JSON data must contain only JSON values")


def _checked_json_scalar(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON data cannot contain NaN or infinity")
    return value


def _freeze_json_mapping(value: Mapping[Any, Any]) -> FrozenDict:
    if any(not isinstance(key, str) for key in value):
        raise TypeError("JSON mapping keys must be strings")
    return FrozenDict({key: freeze_json(item) for key, item in value.items()})


def unique_sorted_strings(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    """Return non-empty unique strings in their canonical order."""
    if any(not value for value in values):
        raise ValueError(f"{label} must contain non-empty values")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must contain unique values")
    return tuple(sorted(values))


def _normalize_mapping(value: dict[Any, Any], keep_models: bool) -> dict[str, Any]:
    """Normalize one mapping while preserving unique canonical key identity."""
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("canonical JSON mapping keys must be strings")
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ValueError("canonical mapping keys collide after NFC normalization")
        normalized[normalized_key] = normalize_unicode(item, keep_models=keep_models)
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


def canonical_yaml(model: BaseModel) -> str:
    """Dump one model's JSON form as sorted block-style Unicode YAML."""
    return yaml.dump(
        model.model_dump(mode="json"),
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )


def load_yaml_mapping(value: str | bytes) -> dict[str, Any]:
    """Parse YAML text that must hold one mapping."""
    data = yaml.safe_load(value)
    if not isinstance(data, dict):
        raise ValueError("YAML data must be a dictionary")
    return data


class SemanticDigestMixin:
    """Content addressing for a model with a ``semantic_digest`` field.

    The digest frames every other field's JSON form under the subclass's
    ``_digest_domain``.
    """

    _digest_domain: ClassVar[str]

    def compute_semantic_digest(self) -> str:
        """Compute the version-framed digest of the content."""
        return compute_framed_digest(
            self._digest_domain,
            self.model_dump(mode="json", exclude={"semantic_digest"}),
        )

    def _attest_semantic_digest(self, mismatch: str) -> None:
        """Record the content digest, rejecting a different recorded one."""
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError(mismatch)
        object.__setattr__(self, "semantic_digest", expected)


class CanonicalYamlMixin:
    """Canonical YAML I/O for a closed artifact.

    Subclasses provide ``assert_integrity`` and ``_load_checked``.
    """

    def to_yaml(self) -> str:
        """Serialize the integrity-checked artifact as canonical YAML."""
        self.assert_integrity()
        return canonical_yaml(self)

    @classmethod
    def from_yaml(cls, value: str | bytes) -> Self:
        """Load and integrity-check one YAML artifact."""
        return cls._load_checked(load_yaml_mapping(value))


__all__ = [
    "CanonicalYamlMixin",
    "ClosedCanonicalModel",
    "FrozenDict",
    "FrozenList",
    "SemanticDigestMixin",
    "canonical_json_bytes",
    "canonical_yaml",
    "compute_framed_digest",
    "freeze_json",
    "load_yaml_mapping",
    "normalize_unicode",
    "unique_sorted_strings",
]
