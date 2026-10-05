"""Atomic persistence for the standalone target-discovery artifacts."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any


from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.canonical import canonical_json_bytes

from .contracts import TargetDiscoveryResult


TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION = "target-discovery-manifest-v1"
INVENTORY_FILENAME = "mcp-inventory.json"
PROFILE_FILENAME = "execution-target-profile.json"
MANIFEST_FILENAME = "target-discovery-manifest.json"
CALLS_FILENAME = "calls.jsonl"


def write_target_discovery(
    output_dir: Path,
    result: TargetDiscoveryResult,
) -> dict[str, Path]:
    """Publish scanner artifacts with canonical bytes and atomic replacement.

    A failed inventory still publishes its diagnostic manifest and call log;
    inventory/profile files are emitted only when their verified models exist.
    The returned mapping contains exactly the files written.
    """
    if not isinstance(result, TargetDiscoveryResult):
        raise TypeError("result must be a TargetDiscoveryResult")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: dict[str, Path] = {}
    if result.inventory is not None:
        result.inventory.assert_integrity()
        inventory_path = output_dir / INVENTORY_FILENAME
        atomic_write_text(
            inventory_path, _json_text(result.inventory.model_dump(mode="json"))
        )
        written[INVENTORY_FILENAME] = inventory_path
    if result.profile is not None:
        result.profile.assert_integrity()
        profile_path = output_dir / PROFILE_FILENAME
        atomic_write_text(
            profile_path, _json_text(result.profile.model_dump(mode="json"))
        )
        written[PROFILE_FILENAME] = profile_path

    calls_path = output_dir / CALLS_FILENAME
    calls_text = "".join(
        json.dumps(call, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        + "\n"
        for call in result.calls
    )
    atomic_write_text(calls_path, calls_text)
    written[CALLS_FILENAME] = calls_path

    manifest = _manifest_payload(result, written)
    manifest_path = output_dir / MANIFEST_FILENAME
    atomic_write_text(manifest_path, _json_text(manifest))
    written[MANIFEST_FILENAME] = manifest_path
    return written


def _manifest_payload(
    result: TargetDiscoveryResult,
    written: dict[str, Path],
) -> dict[str, Any]:
    """Build a non-secret manifest from verified result identities."""
    profile = result.profile
    inventory = result.inventory
    files = {
        name: {
            "sha256": _file_sha256(path),
            "size": path.stat().st_size,
        }
        for name, path in sorted(written.items())
        if name != MANIFEST_FILENAME
    }
    payload: dict[str, Any] = {
        "schema_version": TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION,
        "target_id": _attribute_or_none(profile, "target_id"),
        "authorization_scope_id": _attribute_or_none(profile, "authorization_scope_id"),
        "mode": _enum_value(result.mode),
        "controls": dict(result.controls),
        "inventory_digest": _attribute_or_none(inventory, "semantic_digest"),
        "profile_digest": _attribute_or_none(profile, "semantic_digest"),
        "diagnostic_count": len(result.diagnostics),
        "diagnostics": [item.model_dump(mode="json") for item in result.diagnostics],
        "call_count": len(result.calls),
        "calls_digest": _digest_json(list(result.calls)),
        "files": files,
    }
    if profile is not None:
        payload.update(
            {
                "inventory_authority": _enum_value(profile.inventory_authority),
                "semantic_authority": profile.semantic_authority.value,
                "inventory_completeness": profile.inventory_completeness.value,
                "source_protocol": profile.source_protocol.value,
            }
        )
    return payload


def _attribute_or_none(item: Any, attribute: str) -> Any:
    return None if item is None else getattr(item, attribute)


def _enum_value(value: Enum | None) -> Any:
    return None if value is None else value.value


def _json_text(value: Any) -> str:
    """Encode readable canonical JSON while preserving semantic bytes."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _file_sha256(path: Path) -> str:
    """Hash exact published file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest_json(value: Any) -> str:
    """Hash canonical JSON accounting values."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "CALLS_FILENAME",
    "INVENTORY_FILENAME",
    "MANIFEST_FILENAME",
    "PROFILE_FILENAME",
    "TARGET_DISCOVERY_MANIFEST_SCHEMA_VERSION",
    "write_target_discovery",
]
