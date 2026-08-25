"""Source-catalog snapshot pinning for the catalog-lineage artifact.

The lineage artifact records the historical attack-pattern catalog that
informed its decisions.  This module owns the canonicalization and explicit
source-snapshot audit for that pin.  Normal lineage validation deliberately
does not consult the mutable live catalog.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator

from asago_scenario_generator.data.canonical import _canonical_json, _nfc

_SOURCE_CATALOG_DOMAIN = "asago-scenario-generator:attack-pattern-catalog:v1"
SOURCE_CATALOG_CANONICALIZATION = "asago-scenario-generator:attack-pattern-records:v1"


def _normalize_dict(value: dict[Any, Any]) -> dict[str, Any]:
    return {str(k): _normalize_record(v) for k, v in value.items()}


def _normalize_list(value: list[Any]) -> list[Any]:
    return [_normalize_record(item) for item in value]


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return _nfc(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return str(value)


def _normalize_record(value: Any) -> Any:
    """Canonicalize a loader record while preserving array order.

    Kill-chain step order is semantic, so arrays remain ordered.  Object key
    order is normalized by canonical JSON, strings use NFC normalization, and
    non-JSON scalar values are stringified deterministically.
    """
    if isinstance(value, dict):
        return _normalize_dict(value)
    if isinstance(value, list):
        return _normalize_list(value)
    return _normalize_scalar(value)


def _records_for_file(
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    filename: str,
) -> list[list[Any]]:
    records = sorted(
        (pid, _canonical_json(_normalize_record(patterns[pid])))
        for pid, owner in owners.items()
        if owner == filename
    )
    return [[pid, blob] for pid, blob in records]


def _source_catalog_files(
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    manifest: list[str],
) -> list[dict[str, Any]]:
    return [
        {"file": filename, "records": _records_for_file(patterns, owners, filename)}
        for filename in manifest
    ]


def compute_source_catalog_digest(
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    manifest: list[str],
) -> str:
    """Deterministic content pin over production source-catalog records.

    ``patterns`` is the production catalog, ``owners`` maps each catalog id
    to its declaring file, and ``manifest`` is the expected ordered file
    list.  Each record is framed with its id under its declaring file.
    """
    unowned = sorted(set(patterns) - set(owners))
    if unowned:
        raise ValueError(f"source catalog ids without a declaring file: {unowned}")
    undeclared = sorted(set(owners.values()) - set(manifest))
    if undeclared:
        raise ValueError(f"owners reference files outside the manifest: {undeclared}")
    framed = {
        "canonicalization": SOURCE_CATALOG_CANONICALIZATION,
        "files": _source_catalog_files(patterns, owners, manifest),
    }
    payload = (
        _SOURCE_CATALOG_DOMAIN.encode()
        + b"\0"
        + _canonical_json(framed).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def _evidence_tier(pattern: Mapping[str, Any]) -> str:
    """Return the mutually exclusive evidence tier for a loader record."""
    evidence = pattern.get("evidence") or []
    if any(e.get("type") == "direct_demonstration" for e in evidence):
        return "direct_demonstration"
    if evidence:
        return "enrichment"
    if pattern.get("kill_chain"):
        return "kill_chain_only"
    return "none"


def _verify_pin_canonicalization(pin: Mapping[str, Any]) -> None:
    if pin["canonicalization"] != SOURCE_CATALOG_CANONICALIZATION:
        raise ValueError(
            "catalog lineage source catalog canonicalization "
            f"{pin['canonicalization']!r} is not {SOURCE_CATALOG_CANONICALIZATION!r}"
        )


def _verify_pinned_manifest(
    pin: Mapping[str, Any],
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
) -> None:
    """The pinned manifest and record count must match the supplied catalog."""
    manifest = pin["file_manifest"]
    actual_files = sorted({owners[pid] for pid in patterns})
    if sorted(manifest) != actual_files:
        raise ValueError(
            f"catalog lineage source catalog manifest {sorted(manifest)} does "
            f"not match the supplied declaring files {actual_files}"
        )
    if pin["record_count"] != len(patterns):
        raise ValueError(
            f"catalog lineage source catalog record_count {pin['record_count']} "
            f"does not match the supplied catalog size {len(patterns)}"
        )


def _verify_source_ids_match(
    sources: list[Any], patterns: Mapping[str, Mapping[str, Any]]
) -> None:
    """Exactly the supplied catalog ids must appear as sources, once each."""
    source_ids = [entry["source_pattern_id"] for entry in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("duplicate source_pattern_id in catalog lineage sources")
    if set(source_ids) != set(patterns):
        missing = sorted(set(patterns) - set(source_ids))
        extra = sorted(set(source_ids) - set(patterns))
        raise ValueError(
            f"catalog lineage sources diverge from the supplied catalog; "
            f"missing={missing} extra={extra}"
        )


def _verify_entry_facts_match(
    entry: Mapping[str, Any],
    pid: str,
    pattern: Mapping[str, Any],
    owners: Mapping[str, str],
) -> None:
    """One source entry's recorded facts must match the supplied record."""
    mismatches = {
        "threat_id": (entry["threat_id"], pattern["threat_id"]),
        "evidence_tier": (entry["evidence_tier"], _evidence_tier(pattern)),
        "evidence_count": (
            entry["evidence_count"],
            len(pattern.get("evidence") or []),
        ),
        "legacy_kill_chain_steps": (
            entry["legacy_kill_chain_steps"],
            len(pattern.get("kill_chain") or []),
        ),
    }
    for field, (claimed, actual) in mismatches.items():
        if claimed != actual:
            raise ValueError(
                f"catalog lineage entry {pid} {field}={claimed!r} "
                f"does not match the supplied catalog value {actual!r}"
            )
    if entry["source_file"] != owners[pid]:
        raise ValueError(
            f"catalog lineage entry {pid} source_file={entry['source_file']!r} "
            f"does not match the declaring file {owners[pid]!r}"
        )


def _verify_supplied_entries(
    by_id: Mapping[str, Any],
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
) -> None:
    """Source-entry facts must match the supplied historical loader records."""
    for pid, pattern in patterns.items():
        _verify_entry_facts_match(by_id[pid], pid, pattern, owners)


def verify_catalog_lineage_source_snapshot(
    artifact: dict[str, Any],
    *,
    patterns: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, str],
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Verify the lineage artifact against its historical catalog snapshot.

    The caller supplies the schema so this implementation remains independent
    from the public lineage loader.  The public wrapper resolves the default
    schema and preserves the original interface.
    """
    Draft202012Validator(schema).validate(artifact)

    pin = artifact["source_catalog_context"]
    _verify_pin_canonicalization(pin)
    _verify_pinned_manifest(pin, patterns, owners)
    recomputed_pin = compute_source_catalog_digest(
        patterns, owners, pin["file_manifest"]
    )
    if pin["digest"] != recomputed_pin:
        raise ValueError(
            "catalog lineage source catalog digest mismatch: recorded "
            f"{pin['digest']} != recomputed {recomputed_pin} (supplied records "
            "must come from the pinned source_git_revision "
            f"{pin['source_git_revision']})"
        )

    sources = artifact["sources"]
    _verify_source_ids_match(sources, patterns)

    # Source-entry facts must match the supplied historical loader records.
    by_id = {entry["source_pattern_id"]: entry for entry in sources}
    _verify_supplied_entries(by_id, patterns, owners)
    return artifact
