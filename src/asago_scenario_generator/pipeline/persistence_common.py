"""Shared constants and canonical persistence primitives."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel

COVERAGE_PLAN_VERSION = "2"
FINALIZATION_INVENTORY_VERSION = "1"
QUARANTINE_BUNDLE_VERSION = "1"
PLANNING_CHECKPOINT_VERSION = "1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_TARGET_CHOICES = 3


def canonical_json_bytes(value: Any) -> bytes:
    """Use the projection encoder without importing the projection module eagerly."""
    from asago_scenario_generator.pipeline.projection_contracts import (
        canonical_json_bytes as encode,
    )

    return encode(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, tuple):
        value = list(value)
    # Round-trip only through the one public canonical encoder.  This both
    # normalizes NFC and rejects unsupported/non-finite values.
    return json.loads(canonical_json_bytes(value))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _event_key(kind: str, identity: Any) -> str:
    return canonical_sha256({"kind": kind, "identity": identity})


def _verify_event(item: Any, kind: str, identity: Any, payload: Any) -> None:
    if item.event_id != _event_key(kind, identity):
        raise ValueError(f"{kind} event ID mismatch")
    if item.payload_sha256 != canonical_sha256(payload):
        raise ValueError(f"{kind} payload digest mismatch")
