"""Atomic publication and standalone verification of execution bundles."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    BUNDLE_SCHEMA_VERSION,
    BundleProjectionReference,
    BundleScenarioReference,
    BundleValidationResult,
    ExecutionBundleEntry,
    ExecutionBundleIndex,
    ExecutionRunIdentity,
    ProducerIdentity,
    ProjectionValidationCode,
    ProjectionValidationViolation,
)
from asago_scenario_generator.stpa.models.execution_projection_v3 import (
    BUNDLE_V2_SCHEMA_VERSION,
    PROJECTION_V3_SCHEMA_VERSION,
    BundleProjectionReferenceV3,
    ExecutionBundleEntryV3,
    ExecutionBundleIndexV2,
    ExecutionProjectionV3,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope

from .execution_projection import (
    ValidatedExecutionProjection,
    validate_execution_projection,
    validate_execution_projection_v3,
)


INDEX_JSON_NAME = "execution-bundle.json"
INDEX_YAML_NAME = "execution-bundle.yaml"
EXECUTION_TARGET_PROFILE_NAME = "execution-target-profile.json"

# A published bundle is homogeneous: every entry references projections of
# exactly one schema version.  Bundle v1 indexes carry v2 projections only;
# bundle v2 indexes carry v3 projections only.
_BUNDLE_INDEX_TYPES = {
    BUNDLE_SCHEMA_VERSION: ExecutionBundleIndex,
    BUNDLE_V2_SCHEMA_VERSION: ExecutionBundleIndexV2,
}
_BundleIndex = ExecutionBundleIndex | ExecutionBundleIndexV2
_BundleEntry = ExecutionBundleEntry | ExecutionBundleEntryV3


@dataclass(frozen=True)
class ExecutionBundlePublication:
    """One validated scenario paired with its final relative output names."""

    scenario_envelope: ScenarioEnvelope
    validated_projection: ValidatedExecutionProjection
    scenario_path: str
    projection_path: str


class ExecutionBundlePublicationError(ValueError):
    """Raised when publication preflight or atomic persistence fails."""


def publish_execution_target_profile(
    destination: Path,
    profile: ExecutionTargetProfile,
) -> Path:
    """Publish one verified target profile through the shared atomic writer.

    The profile is written as canonical JSON beside the execution bundle.  The
    function is intentionally separate from bundle-index publication so the
    run orchestrator can publish the profile first and refuse to publish an
    index whose classifications point at unavailable profile bytes.
    """
    if not isinstance(destination, Path):
        raise ExecutionBundlePublicationError("destination must be a pathlib.Path")
    if not isinstance(profile, ExecutionTargetProfile):
        raise ExecutionBundlePublicationError(
            "profile must be an ExecutionTargetProfile"
        )
    profile.assert_integrity()
    profile_path = destination.resolve() / EXECUTION_TARGET_PROFILE_NAME
    _atomic_write(profile_path, profile.canonical_json_bytes())
    return profile_path


@dataclass(frozen=True)
class _IndexDocument:
    """Raw index bytes and decoded object retained for exact verification."""

    content: bytes
    payload: Mapping[str, Any]


def publish_execution_bundle(
    destination: Path,
    run_identity: ExecutionRunIdentity,
    entries: Sequence[ExecutionBundlePublication],
) -> _BundleIndex:
    """Publish validated canonical scenario/projection pairs and index last.

    The published index version is homogeneous: a set of v2 projections
    publishes the bundle-v1 index exactly as before, a set of v3 projections
    publishes the bundle-v2 index, and a mixed set fails closed.
    """
    if not isinstance(destination, Path):
        raise ExecutionBundlePublicationError("destination must be a pathlib.Path")
    if not isinstance(run_identity, ExecutionRunIdentity):
        raise ExecutionBundlePublicationError(
            "run_identity must be an ExecutionRunIdentity"
        )
    if isinstance(entries, (str, bytes, bytearray)):
        raise ExecutionBundlePublicationError(
            "entries must be a sequence of publications"
        )
    publications = tuple(entries)
    base = destination.resolve()
    prepared = _prepare_publications(base, run_identity, publications)
    if (base / INDEX_JSON_NAME).is_file():
        prepared = _stage_update_generation(base, run_identity, prepared)
    index = _build_bundle_index(base, run_identity, prepared)
    _publish_transaction(_publication_writes(base, prepared, index))
    return index


def _build_bundle_index(
    base: Path,
    run_identity: ExecutionRunIdentity,
    prepared: tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...],
) -> _BundleIndex:
    """Build the closed index for one homogeneous projection version set."""
    versions = {
        publication.validated_projection.projection.schema_version
        for publication, _scenario_bytes, _projection_bytes, _scenario_path, _projection_path in prepared
    }
    if len(versions) > 1:
        raise ExecutionBundlePublicationError(
            "bundle entries must share one projection schema version"
        )
    producer = ProducerIdentity(
        name=run_identity.producer_name,
        version=run_identity.producer_version,
    )
    if versions == {PROJECTION_V3_SCHEMA_VERSION}:
        return ExecutionBundleIndexV2(
            run_id=run_identity.run_id,
            producer=producer,
            entries=tuple(_bundle_entry_v3(base, item) for item in prepared),
        )
    return ExecutionBundleIndex(
        run_id=run_identity.run_id,
        producer=producer,
        entries=tuple(_bundle_entry(base, item) for item in prepared),
    )


def _bundle_entry(
    base: Path,
    prepared: tuple[ExecutionBundlePublication, bytes, bytes, Path, Path],
) -> ExecutionBundleEntry:
    """Build one bundle-v1 index entry from preflighted canonical bytes."""
    publication, scenario_bytes, projection_bytes, scenario_path, projection_path = (
        prepared
    )
    projection = publication.validated_projection.projection
    return ExecutionBundleEntry(
        scenario_id=projection.scenario_id,
        candidate_id=projection.candidate_id,
        ica_slot_id=projection.ica_slot_id,
        ica_id=projection.ica_id,
        scenario=BundleScenarioReference(
            path=_relative_posix(base, scenario_path),
            content_sha256=_sha256(scenario_bytes),
        ),
        projection=BundleProjectionReference(
            path=_relative_posix(base, projection_path),
            content_sha256=_sha256(projection_bytes),
            semantic_digest=projection.semantic_digest
            or projection.compute_semantic_digest(),
        ),
    )


def _bundle_entry_v3(
    base: Path,
    prepared: tuple[ExecutionBundlePublication, bytes, bytes, Path, Path],
) -> ExecutionBundleEntryV3:
    """Build one bundle-v2 index entry referencing its v3 projection."""
    publication, scenario_bytes, projection_bytes, scenario_path, projection_path = (
        prepared
    )
    projection = publication.validated_projection.projection
    return ExecutionBundleEntryV3(
        scenario_id=projection.scenario_id,
        candidate_id=projection.candidate_id,
        ica_slot_id=projection.ica_slot_id,
        ica_id=projection.ica_id,
        scenario=BundleScenarioReference(
            path=_relative_posix(base, scenario_path),
            content_sha256=_sha256(scenario_bytes),
        ),
        projection=BundleProjectionReferenceV3(
            path=_relative_posix(base, projection_path),
            content_sha256=_sha256(projection_bytes),
            semantic_digest=projection.semantic_digest
            or projection.compute_semantic_digest(),
        ),
    )


def _stage_update_generation(
    base: Path,
    run_identity: ExecutionRunIdentity,
    prepared: tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...],
) -> tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...]:
    """Move update entries into a deterministic immutable generation namespace."""
    generation = _generation_key(base, run_identity, prepared)
    generation_root = base / ".generations" / generation
    return tuple(
        (
            publication,
            scenario_bytes,
            projection_bytes,
            generation_root
            / Path(*PurePosixPath(_relative_posix(base, scenario_path)).parts),
            generation_root
            / Path(*PurePosixPath(_relative_posix(base, projection_path)).parts),
        )
        for publication, scenario_bytes, projection_bytes, scenario_path, projection_path in prepared
    )


def _generation_key(
    base: Path,
    run_identity: ExecutionRunIdentity,
    prepared: tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...],
) -> str:
    """Derive a stable key from the complete prepared generation, not a clock."""
    material = [run_identity.run_id.encode("utf-8")]
    for (
        publication,
        scenario_bytes,
        projection_bytes,
        scenario_path,
        projection_path,
    ) in sorted(
        prepared,
        key=lambda item: _projection_identity(item[0].validated_projection.projection),
    ):
        material.extend(
            (
                _relative_posix(base, scenario_path).encode("utf-8"),
                scenario_bytes,
                _relative_posix(base, projection_path).encode("utf-8"),
                projection_bytes,
            )
        )
    return _sha256(b"\0".join(material))


def _publication_writes(
    base: Path,
    prepared: tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...],
    index: _BundleIndex,
) -> tuple[tuple[Path, bytes], ...]:
    """Materialize the complete generation before touching final paths."""
    writes: list[tuple[Path, bytes]] = []
    for (
        _publication,
        scenario_bytes,
        projection_bytes,
        scenario_path,
        projection_path,
    ) in prepared:
        writes.extend(
            (
                (scenario_path, scenario_bytes),
                (projection_path, projection_bytes),
            )
        )
    writes.extend(
        (
            (
                base / INDEX_YAML_NAME,
                yaml.safe_dump(
                    index.model_dump(mode="json"),
                    sort_keys=False,
                    allow_unicode=True,
                ).encode("utf-8"),
            ),
            (base / INDEX_JSON_NAME, index.canonical_json_bytes()),
        )
    )
    return tuple(writes)


@dataclass(frozen=True)
class _FileBackup:
    """Original bytes for one final path in a publication transaction."""

    path: Path
    content: bytes | None


def _publish_transaction(writes: tuple[tuple[Path, bytes], ...]) -> None:
    """Replace a complete generation and restore the prior one on failure."""
    backups = _capture_backups(path for path, _content in writes)
    try:
        for path, content in writes:
            _atomic_write(path, content)
    except BaseException:
        try:
            _restore_backups(backups)
        except BaseException as rollback_error:
            raise ExecutionBundlePublicationError(
                "bundle publication failed and rollback could not restore the prior bundle"
            ) from rollback_error
        raise


def _capture_backups(paths) -> tuple[_FileBackup, ...]:
    """Read each touched final path before a publication transaction starts."""
    return tuple(
        _FileBackup(path, path.read_bytes() if path.is_file() else None)
        for path in paths
    )


def _restore_backups(backups: tuple[_FileBackup, ...]) -> None:
    """Restore exact prior bytes or remove files created by a failed update."""
    for backup in backups:
        if backup.content is None:
            backup.path.unlink(missing_ok=True)
        else:
            _replace_bytes(backup.path, backup.content)


def verify_execution_bundle(destination: Path) -> BundleValidationResult:
    """Verify index, paths, exact bytes, projection digests and pair identity."""
    if not isinstance(destination, Path):
        return _bundle_invalid(
            ProjectionValidationCode.bundle_path_invalid,
            "$",
            "bundle destination must be a pathlib.Path",
        )
    base = destination.resolve()
    document = _read_index_document(base)
    if isinstance(document, BundleValidationResult):
        return document
    index, violations = _validate_index_document(document)
    if index is None:
        return BundleValidationResult(valid=False, violations=tuple(violations))
    violations.extend(_verify_index_entries(base, index))
    if violations:
        return BundleValidationResult(valid=False, violations=tuple(violations))
    return BundleValidationResult(valid=True, index=index)


def _read_index_document(base: Path) -> _IndexDocument | BundleValidationResult:
    index_path = base / INDEX_JSON_NAME
    if not index_path.is_file():
        return _bundle_invalid(
            ProjectionValidationCode.required_field_missing,
            INDEX_JSON_NAME,
            "execution-bundle.json is the publication-completion marker",
        )
    index_bytes = _read_index_bytes(index_path)
    if isinstance(index_bytes, BundleValidationResult):
        return index_bytes
    payload = _decode_index_payload(index_bytes)
    if isinstance(payload, BundleValidationResult):
        return payload
    if "bundle_digest" not in payload:
        return _bundle_invalid(
            ProjectionValidationCode.required_field_missing,
            "bundle_digest",
            "persisted bundle indexes require bundle_digest",
        )
    return _IndexDocument(content=index_bytes, payload=payload)


def _read_index_bytes(path: Path) -> bytes | BundleValidationResult:
    try:
        return path.read_bytes()
    except OSError as exc:
        return _bundle_invalid(
            ProjectionValidationCode.content_digest_mismatch,
            INDEX_JSON_NAME,
            f"index is unreadable: {exc}",
        )


def _decode_index_payload(
    content: bytes,
) -> Mapping[str, Any] | BundleValidationResult:
    try:
        payload = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        return _bundle_invalid(
            ProjectionValidationCode.container_type_mismatch,
            INDEX_JSON_NAME,
            f"index is not valid JSON: {exc}",
        )
    if not isinstance(payload, Mapping):
        return _bundle_invalid(
            ProjectionValidationCode.container_type_mismatch,
            INDEX_JSON_NAME,
            "bundle index must be a JSON object",
        )
    return payload


def _validate_index_document(
    document: _IndexDocument,
) -> tuple[_BundleIndex | None, list[ProjectionValidationViolation]]:
    violations = _index_header_violations(document.payload)
    index_type = _BUNDLE_INDEX_TYPES.get(document.payload.get("schema_version"))
    if index_type is None:
        return None, violations
    try:
        index = index_type.model_validate(document.payload)
    except ValidationError as exc:
        violations.extend(_index_validation_errors(exc))
        return None, violations
    if canonical_json_bytes(index.model_dump(mode="json")) != document.content:
        violations.append(
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                INDEX_JSON_NAME,
                "bundle index is not the exact canonical JSON encoding",
            )
        )
    if violations:
        return None, violations
    violations.extend(_entry_order_violations(document.payload))
    return index, violations


def _index_header_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    unknown = sorted(
        set(payload)
        - {"schema_version", "run_id", "producer", "entries", "bundle_digest"}
    )
    if unknown:
        violations.append(
            _violation(
                ProjectionValidationCode.unexpected_field,
                str(unknown[0]),
                f"unknown bundle index field {unknown[0]!r}",
            )
        )
    if payload.get("schema_version") not in _BUNDLE_INDEX_TYPES:
        violations.append(
            _violation(
                ProjectionValidationCode.schema_version_mismatch,
                "schema_version",
                "schema_version must be stpa-execution-bundle-v1 or "
                "stpa-execution-bundle-v2",
            )
        )
    return violations


def _entry_order_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return []
    raw_order = tuple(_entry_identity(item) for item in entries)
    if raw_order == tuple(sorted(raw_order)):
        return []
    return [
        _violation(
            ProjectionValidationCode.identity_mismatch,
            "entries",
            "bundle entries must be in canonical identity order",
        )
    ]


def _verify_index_entries(
    base: Path,
    index: _BundleIndex,
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    seen_paths: set[str] = set()
    for entry_index, entry in enumerate(index.entries):
        violations.extend(_verify_entry(base, index, entry_index, entry, seen_paths))
    return violations


def _verify_entry(
    base: Path,
    index: _BundleIndex,
    entry_index: int,
    entry: _BundleEntry,
    seen_paths: set[str],
) -> list[ProjectionValidationViolation]:
    prefix = f"entries[{entry_index}]"
    path_violations = _entry_path_violations(base, entry, prefix, seen_paths)
    paths = _entry_paths(base, entry)
    if paths is None:
        return path_violations
    scenario_file, projection_file = paths
    content = _read_entry_content(scenario_file, projection_file, prefix)
    if content is None:
        return path_violations + [
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                prefix,
                "referenced canonical file is unreadable",
            )
        ]
    scenario_bytes, projection_bytes = content
    violations = path_violations + _entry_digest_violations(
        entry, prefix, scenario_bytes, projection_bytes
    )
    scenario, scenario_violations = _load_scenario_entry(entry, prefix, scenario_bytes)
    violations.extend(scenario_violations)
    projection, projection_violations = _load_projection_entry(
        index, entry, prefix, projection_bytes
    )
    violations.extend(projection_violations)
    if projection is not None and scenario is not None:
        violations.extend(
            _pair_identity_violations(scenario, projection, entry, prefix)
        )
    return violations


def _entry_paths(
    base: Path,
    entry: _BundleEntry,
) -> tuple[Path, Path] | None:
    scenario_file = _safe_resolved_path(base, entry.scenario.path)
    projection_file = _safe_resolved_path(base, entry.projection.path)
    if scenario_file is None or projection_file is None:
        return None
    return scenario_file, projection_file


def _entry_path_violations(
    base: Path,
    entry: _BundleEntry,
    prefix: str,
    seen_paths: set[str],
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    for field_name, relative in (
        ("scenario", entry.scenario.path),
        ("projection", entry.projection.path),
    ):
        if _safe_resolved_path(base, relative) is None:
            violations.append(
                _violation(
                    ProjectionValidationCode.bundle_path_invalid,
                    f"{prefix}.{field_name}.path",
                    "path is not a safe relative POSIX path",
                )
            )
        elif relative in seen_paths:
            violations.append(
                _violation(
                    ProjectionValidationCode.bundle_path_invalid,
                    prefix,
                    f"duplicate bundle path {relative!r}",
                )
            )
        seen_paths.add(relative)
    if entry.scenario.path == entry.projection.path:
        violations.append(
            _violation(
                ProjectionValidationCode.bundle_path_invalid,
                prefix,
                "scenario and projection must use distinct bundle paths",
            )
        )
    return violations


def _read_entry_content(
    scenario_file: Path,
    projection_file: Path,
    prefix: str,
) -> tuple[bytes, bytes] | None:
    try:
        return scenario_file.read_bytes(), projection_file.read_bytes()
    except OSError:
        del prefix
        return None


def _entry_digest_violations(
    entry: _BundleEntry,
    prefix: str,
    scenario_bytes: bytes,
    projection_bytes: bytes,
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    if _sha256(scenario_bytes) != entry.scenario.content_sha256:
        violations.append(
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                f"{prefix}.scenario.content_sha256",
                "scenario content digest does not match exact persisted bytes",
            )
        )
    if _sha256(projection_bytes) != entry.projection.content_sha256:
        violations.append(
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                f"{prefix}.projection.content_sha256",
                "projection content digest does not match exact persisted bytes",
            )
        )
    return violations


def _load_scenario_entry(
    entry: _BundleEntry,
    prefix: str,
    content: bytes,
) -> tuple[ScenarioEnvelope | None, list[ProjectionValidationViolation]]:
    try:
        payload = json.loads(content)
        scenario = ScenarioEnvelope.model_validate(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        return None, [
            _violation(
                ProjectionValidationCode.container_type_mismatch,
                f"{prefix}.scenario",
                f"scenario canonical JSON is invalid: {exc}",
            )
        ]
    except ValidationError as exc:
        return None, [
            _violation(
                ProjectionValidationCode.pair_identity_mismatch,
                f"{prefix}.scenario",
                f"scenario envelope is invalid: {exc}",
            )
        ]
    violations: list[ProjectionValidationViolation] = []
    if (
        canonical_json_bytes(scenario.model_dump(mode="json", exclude_unset=True))
        != content
    ):
        violations.append(
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                f"{prefix}.scenario",
                "scenario bytes are not the exact canonical JSON encoding",
            )
        )
    if scenario.scenario_id != entry.scenario_id:
        violations.append(
            _violation(
                ProjectionValidationCode.pair_identity_mismatch,
                f"{prefix}.scenario_id",
                "scenario envelope ID does not match index entry",
            )
        )
    return scenario, violations


def _load_projection_entry(
    index: _BundleIndex,
    entry: _BundleEntry,
    prefix: str,
    content: bytes,
) -> tuple[Any | None, list[ProjectionValidationViolation]]:
    payload, decode_violations = _decode_projection_entry(content, prefix)
    if decode_violations:
        return None, decode_violations
    projection, violations = _validate_projection_entry_payload(index, entry, payload)
    if projection is None:
        return None, [
            _prefix_violation(item, prefix + ".projection") for item in violations
        ]
    integrity_violations = _projection_entry_integrity(
        entry, prefix, projection, content
    )
    return projection, violations + integrity_violations


def _validate_projection_entry_payload(
    index: _BundleIndex,
    entry: _BundleEntry,
    payload: Any,
) -> tuple[Any | None, list[ProjectionValidationViolation]]:
    """Validate one referenced projection through its own schema version."""
    document_version = (
        payload.get("schema_version") if isinstance(payload, Mapping) else None
    )
    if document_version == PROJECTION_V3_SCHEMA_VERSION:
        codes = validate_execution_projection_v3(
            payload,
            expected_run_id=index.run_id,
            expected_scenario_id=entry.scenario_id,
        )
        if codes:
            return None, [
                _violation(
                    code,
                    "projection",
                    f"projection-v3 validation failed: {code.value}",
                )
                for code in codes
            ]
        return ExecutionProjectionV3.model_validate(payload), []
    result = validate_execution_projection(
        payload,
        expected_run_id=index.run_id,
        expected_scenario_id=entry.scenario_id,
    )
    if not result.valid or result.projection is None:
        return None, list(result.violations)
    return result.projection, []


def _decode_projection_entry(
    content: bytes,
    prefix: str,
) -> tuple[Any | None, list[ProjectionValidationViolation]]:
    try:
        return json.loads(content), []
    except (UnicodeError, json.JSONDecodeError) as exc:
        return None, [
            _violation(
                ProjectionValidationCode.container_type_mismatch,
                f"{prefix}.projection",
                f"projection canonical JSON is invalid: {exc}",
            )
        ]


def _projection_entry_integrity(
    entry: _BundleEntry,
    prefix: str,
    projection: Any,
    content: bytes,
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    if canonical_json_bytes(projection.model_dump(mode="json")) != content:
        violations.append(
            _violation(
                ProjectionValidationCode.content_digest_mismatch,
                f"{prefix}.projection",
                "projection bytes are not the exact canonical JSON encoding",
            )
        )
    if entry.projection.semantic_digest != projection.semantic_digest:
        violations.append(
            _violation(
                ProjectionValidationCode.semantic_digest_mismatch,
                f"{prefix}.projection.semantic_digest",
                "index semantic digest does not match projection",
            )
        )
    return violations


def read_execution_bundle(destination: Path) -> BundleValidationResult:
    """Read and verify a published bundle through the standalone verifier."""
    return verify_execution_bundle(destination)


def _prepare_publications(
    base: Path,
    run_identity: ExecutionRunIdentity,
    entries: Sequence[ExecutionBundlePublication],
) -> tuple[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path], ...]:
    prepared: list[tuple[ExecutionBundlePublication, bytes, bytes, Path, Path]] = []
    identities: set[tuple[str, str, str, str]] = set()
    paths: set[str] = set()
    for index, publication in enumerate(entries):
        prepared_item = _prepare_publication(base, run_identity, publication, index)
        projection = prepared_item[0].validated_projection.projection
        identity = _projection_identity(projection)
        _reject_duplicate_identity(identity, identities, index)
        identities.add(identity)
        scenario_relative = _relative_posix(base, prepared_item[3])
        projection_relative = _relative_posix(base, prepared_item[4])
        _reject_duplicate_paths(scenario_relative, projection_relative, paths, index)
        paths.update((scenario_relative, projection_relative))
        prepared.append(prepared_item)
    return tuple(prepared)


def _prepare_publication(
    base: Path,
    run_identity: ExecutionRunIdentity,
    publication: ExecutionBundlePublication,
    index: int,
) -> tuple[ExecutionBundlePublication, bytes, bytes, Path, Path]:
    _validate_publication_types(publication, index)
    envelope = publication.scenario_envelope
    validated = publication.validated_projection
    projection = validated.projection
    _validate_publication_pair(envelope, projection, run_identity, index)
    scenario_path = _require_safe_path(base, publication.scenario_path, index)
    projection_path = _require_safe_path(base, publication.projection_path, index)
    scenario_bytes = canonical_json_bytes(envelope.model_dump(mode="json"))
    projection_bytes = _validated_projection_bytes(validated, projection, index)
    return publication, scenario_bytes, projection_bytes, scenario_path, projection_path


def _validate_publication_types(
    publication: ExecutionBundlePublication,
    index: int,
) -> None:
    if not isinstance(publication, ExecutionBundlePublication):
        raise ExecutionBundlePublicationError(
            f"entries[{index}] must be an ExecutionBundlePublication"
        )
    if not isinstance(publication.scenario_envelope, ScenarioEnvelope):
        raise ExecutionBundlePublicationError(
            f"entries[{index}].scenario_envelope is not a ScenarioEnvelope"
        )
    if not isinstance(publication.validated_projection, ValidatedExecutionProjection):
        raise ExecutionBundlePublicationError(
            f"entries[{index}].validated_projection is not a validated projection"
        )


def _validate_publication_pair(
    envelope: ScenarioEnvelope,
    projection: Any,
    run_identity: ExecutionRunIdentity,
    index: int,
) -> None:
    if projection.run_id != run_identity.run_id:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] projection run_id does not match enclosing run"
        )
    if envelope.scenario_id != projection.scenario_id:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] scenario_id does not match projection"
        )
    identity_violations = _envelope_projection_identity_violations(
        envelope, projection, f"entries[{index}]"
    )
    if identity_violations:
        raise ExecutionBundlePublicationError(
            "; ".join(item.detail for item in identity_violations)
        )


def _validated_projection_bytes(
    validated: ValidatedExecutionProjection,
    projection: Any,
    index: int,
) -> bytes:
    content = validated.canonical_json_bytes
    if not isinstance(content, bytes):
        raise ExecutionBundlePublicationError(
            f"entries[{index}] canonical projection bytes are not immutable bytes"
        )
    if content != projection.canonical_json_bytes():
        raise ExecutionBundlePublicationError(
            f"entries[{index}] canonical projection bytes do not match projection"
        )
    if validated.semantic_digest != projection.semantic_digest:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] validated semantic digest does not match projection"
        )
    return content


def _projection_identity(projection: Any) -> tuple[str, str, str, str]:
    return (
        projection.scenario_id,
        projection.candidate_id,
        projection.ica_slot_id,
        projection.ica_id,
    )


def _reject_duplicate_identity(
    identity: tuple[str, str, str, str],
    identities: set[tuple[str, str, str, str]],
    index: int,
) -> None:
    if identity in identities:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] duplicates an existing scenario identity"
        )


def _reject_duplicate_paths(
    scenario_path: str,
    projection_path: str,
    paths: set[str],
    index: int,
) -> None:
    if scenario_path in paths or projection_path in paths:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] reuses a persisted bundle path"
        )


def _require_safe_path(base: Path, value: str, index: int) -> Path:
    path = _safe_resolved_path(base, value)
    if path is None:
        raise ExecutionBundlePublicationError(
            f"entries[{index}] contains an unsafe relative POSIX path"
        )
    return path


def _safe_resolved_path(base: Path, value: str) -> Path | None:
    if _invalid_path_spelling(value):
        return None
    relative = PurePosixPath(value)
    if _invalid_relative_path(relative):
        return None
    return _resolve_under_bundle(base, relative)


def _invalid_path_spelling(value: Any) -> bool:
    return (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    )


def _invalid_relative_path(relative: PurePosixPath) -> bool:
    return relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    )


def _resolve_under_bundle(base: Path, relative: PurePosixPath) -> Path | None:
    candidate = (base / Path(*relative.parts)).resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate


def _relative_posix(base: Path, path: Path) -> str:
    return path.relative_to(base).as_posix()


def _atomic_write(path: Path, content: bytes) -> None:
    """Atomically replace one final path with durable bytes."""
    _replace_bytes(path, content)


def _replace_bytes(path: Path, content: bytes) -> None:
    """Replace one path without the transaction hook used for fault injection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _entry_identity(value: Any) -> tuple[str, str, str, str]:
    if isinstance(value, Mapping):
        return tuple(
            str(value.get(key, ""))
            for key in ("scenario_id", "candidate_id", "ica_slot_id", "ica_id")
        )  # type: ignore[return-value]
    if all(
        hasattr(value, key)
        for key in ("scenario_id", "candidate_id", "ica_slot_id", "ica_id")
    ):
        return (
            str(value.scenario_id),
            str(value.candidate_id),
            str(value.ica_slot_id),
            str(value.ica_id),
        )
    return (
        "",
        "",
        "",
        "",
    )


def _envelope_projection_identity_violations(
    envelope: ScenarioEnvelope,
    projection: Any,
    prefix: str,
) -> list[ProjectionValidationViolation]:
    """Compare the envelope's authoritative STPA tuple to a projection."""
    scenario_spec = envelope.scenario_spec
    expected = {
        "scenario_id": scenario_spec.scenario_id,
        "controller_id": scenario_spec.target_controller,
        "control_action_id": scenario_spec.target_control_action,
        "uca_type": scenario_spec.ica_type,
        "ica_slot_id": scenario_spec.threat_source.ica_slot_id,
        "ica_id": scenario_spec.threat_source.ica_id,
    }
    actual = {
        "scenario_id": projection.scenario_id,
        "controller_id": projection.controller_id,
        "control_action_id": projection.control_action_id,
        "uca_type": projection.uca_type,
        "ica_slot_id": projection.ica_slot_id,
        "ica_id": projection.ica_id,
    }
    violations: list[ProjectionValidationViolation] = []
    for field_name in expected:
        if expected[field_name] != actual[field_name]:
            violations.append(
                _violation(
                    ProjectionValidationCode.pair_identity_mismatch,
                    f"{prefix}.{field_name}",
                    f"scenario envelope {field_name} does not match projection",
                )
            )
    if envelope.ica_type != projection.uca_type:
        violations.append(
            _violation(
                ProjectionValidationCode.pair_identity_mismatch,
                f"{prefix}.ica_type",
                "scenario envelope ica_type does not match projection UCA type",
            )
        )
    if envelope.target_responsibility != projection.controller_id:
        violations.append(
            _violation(
                ProjectionValidationCode.pair_identity_mismatch,
                f"{prefix}.target_responsibility",
                "scenario envelope target_responsibility does not match projection",
            )
        )
    context = scenario_spec.scenario_context
    if context is not None:
        expected_hazards = tuple(sorted(item.hazard_id for item in context.hazards))
        expected_constraints = tuple(
            sorted(item.constraint_id for item in context.constraints)
        )
        expected_losses = tuple(sorted(item.loss_id for item in context.losses))
        lineage_pairs = (
            (
                "unsafe_outcome.hazard_refs",
                tuple(projection.unsafe_outcome.hazard_refs),
                expected_hazards,
            ),
            (
                "unsafe_outcome.constraint_refs",
                tuple(projection.unsafe_outcome.constraint_refs),
                expected_constraints,
            ),
            (
                "trace_refs.hazard_ids",
                tuple(projection.trace_refs.hazard_ids),
                expected_hazards,
            ),
            (
                "trace_refs.constraint_ids",
                tuple(projection.trace_refs.constraint_ids),
                expected_constraints,
            ),
            (
                "trace_refs.loss_ids",
                tuple(projection.trace_refs.loss_ids),
                expected_losses,
            ),
        )
        for field_name, actual_value, expected_value in lineage_pairs:
            if actual_value != expected_value:
                violations.append(
                    _violation(
                        ProjectionValidationCode.pair_identity_mismatch,
                        f"{prefix}.{field_name}",
                        f"scenario context lineage does not match projection {field_name}",
                    )
                )
        if (
            projection.unsafe_outcome.semantic_proposition
            != scenario_spec.unsafe_outcome_semantic_proposition
        ):
            violations.append(
                _violation(
                    ProjectionValidationCode.pair_identity_mismatch,
                    f"{prefix}.unsafe_outcome.semantic_proposition",
                    "scenario semantic proposition does not match projection",
                )
            )
    return violations


def _pair_identity_violations(
    envelope: ScenarioEnvelope,
    projection: Any,
    entry: _BundleEntry,
    prefix: str,
) -> list[ProjectionValidationViolation]:
    violations = _envelope_projection_identity_violations(
        envelope,
        projection,
        f"{prefix}.scenario",
    )
    if (
        projection.scenario_id,
        projection.candidate_id,
        projection.ica_slot_id,
        projection.ica_id,
    ) != _entry_identity(entry):
        violations.append(
            _violation(
                ProjectionValidationCode.pair_identity_mismatch,
                prefix,
                "projection identity does not match index entry",
            )
        )
    return violations


def _index_validation_errors(
    exc: ValidationError,
) -> list[ProjectionValidationViolation]:
    return [
        _index_error_violation(error)
        for error in sorted(exc.errors(), key=lambda item: str(item["loc"]))
    ]


def _index_error_violation(error: Mapping[str, Any]) -> ProjectionValidationViolation:
    path = ".".join(str(part) for part in error["loc"]) or "$"
    message = str(error.get("msg", "invalid bundle index"))
    return _violation(_index_validation_code(path, message), path, message)


def _index_validation_code(path: str, message: str) -> ProjectionValidationCode:
    lowered = f"{path} {message}".lower()
    if "digest" in lowered:
        return ProjectionValidationCode.semantic_digest_mismatch
    if "path" in lowered:
        return ProjectionValidationCode.bundle_path_invalid
    if "schema_version" in lowered:
        return ProjectionValidationCode.schema_version_mismatch
    return ProjectionValidationCode.pair_identity_mismatch


def _prefix_violation(
    violation: ProjectionValidationViolation,
    prefix: str,
) -> ProjectionValidationViolation:
    return ProjectionValidationViolation(
        code=violation.code,
        path=f"{prefix}.{violation.path}",
        detail=violation.detail,
    )


def _violation(
    code: ProjectionValidationCode,
    path: str,
    detail: str,
) -> ProjectionValidationViolation:
    return ProjectionValidationViolation(code=code, path=path, detail=detail)


def _bundle_invalid(
    code: ProjectionValidationCode,
    path: str,
    detail: str,
) -> BundleValidationResult:
    return BundleValidationResult(
        valid=False,
        violations=(_violation(code, path, detail),),
    )


__all__ = [
    "ExecutionBundlePublication",
    "ExecutionBundlePublicationError",
    "INDEX_JSON_NAME",
    "INDEX_YAML_NAME",
    "EXECUTION_TARGET_PROFILE_NAME",
    "publish_execution_bundle",
    "publish_execution_target_profile",
    "read_execution_bundle",
    "verify_execution_bundle",
]
