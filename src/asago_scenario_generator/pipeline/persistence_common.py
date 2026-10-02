"""Shared constants and canonical persistence primitives."""

from __future__ import annotations

import hashlib
from typing import Any


SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_TARGET_CHOICES = 3


def canonical_json_bytes(value: Any) -> bytes:
    """Use the projection encoder without importing the projection module eagerly."""
    from asago_scenario_generator.pipeline.projection_contracts import (
        canonical_json_bytes as encode,
    )

    return encode(value)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _event_key(kind: str, identity: Any) -> str:
    return canonical_sha256({"kind": kind, "identity": identity})


def _verify_event(item: Any, kind: str, identity: Any, payload: Any) -> None:
    if item.event_id != _event_key(kind, identity):
        raise ValueError(f"{kind} event ID mismatch")
    if item.payload_sha256 != canonical_sha256(payload):
        raise ValueError(f"{kind} payload digest mismatch")
