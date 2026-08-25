"""Strict, hash-verified access to manifest inventory artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from asago_scenario_generator.manifest_errors import ManifestIntegrityError
from asago_scenario_generator.manifest_models import (
    MANIFEST_FILENAME,
    MANIFEST_V3,
    LEGACY_MANIFEST_VERSION,
    ArtifactEntry,
    ArtifactRole,
    RunManifest,
    RunStatus,
    SINGLETON_ROLES,
    _ROLE_METADATA,
    _SHA256_RE,
)


def _default_leaf_open_hook() -> None:
    """Default no-op hook used before opening an artifact leaf."""


class ManifestInventoryResolver:
    """Strict manifest inventory resolver and validator.

    Loads a manifest (from disk or in-memory), validates every inventory
    entry (path, hash, role, duplicates, orphans, singletons, pairing),
    and provides typed access to artifacts by role.

    This is the **single shared resolver** used by both eval and report
    readers.  It never globs the filesystem — it consumes only manifest
    inventory entries.
    """

    def __init__(
        self,
        run_dir: Path,
        manifest: RunManifest,
        check_orphans: bool = True,
        *,
        leaf_open_hook: Callable[[], None] | None = None,
    ) -> None:
        self.run_dir = Path(run_dir).absolute()
        self.manifest = manifest
        self.check_orphans = check_orphans
        self._leaf_open_hook = leaf_open_hook or _default_leaf_open_hook
        self._by_role: dict[ArtifactRole, list[ArtifactEntry]] = {}
        # Cache of fd-read, hash-verified content bytes keyed by entry
        # path.  read_text/read_bytes serve from this cache so consumers
        # always receive the exact bytes that were validated.
        self._content_cache: dict[str, bytes] = {}
        self._validated_entries: dict[str, ArtifactEntry] = {}
        try:
            self._validation_root_fd: int | None = os.open(
                self.run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
        except OSError as exc:
            raise ManifestIntegrityError(
                f"Cannot safely open run directory {self.run_dir}: {exc}"
            ) from exc
        try:
            self._validate()
        finally:
            os.close(self._validation_root_fd)
            self._validation_root_fd = None

    # --- Validation ---

    def _validate(self) -> None:
        """Validate the full inventory integrity globally.

        For non-authoritative manifests (failed, completed_with_errors),
        YAML/feature pairing is relaxed — a partial scenario (YAML without
        feature or vice versa) is tolerated as evidence, not rejected.
        """
        requires_complete_inventory = self.manifest.status.requires_complete_inventory
        seen_canonical: set[str] = set()
        seen_physical: set[tuple[int, int]] = set()
        singleton_counts: dict[ArtifactRole, int] = {}
        scenario_ids: set[tuple[ArtifactRole, str]] = set()
        # Track (scenario_id -> candidate_id) to reject duplicate candidate
        # IDs across *different* scenario pairs.  Within one pair (YAML +
        # feature) the candidate_id is shared and valid.
        scenario_to_candidate: dict[str, str] = {}
        yaml_stems: set[str] = set()
        feature_stems: set[str] = set()
        yaml_scenario_ids: dict[
            str, dict[str, str | None]
        ] = {}  # stem -> {inventory, serialized}
        feature_scenario_ids_map: dict[str, str] = {}  # stem -> scenario_id

        for entry in self.manifest.inventory:
            role = self._entry_role(entry)
            _validate_legacy_role_support(self.manifest.manifest_version, role)
            self._validate_entry_path(entry)
            self._track_canonical_path(entry, seen_canonical)
            self._validate_sha256_field(entry)
            # Safe open and hash verification: traverse from the run directory
            # one component at a time; each parent and the leaf is opened
            # without following symlinks, so pathname replacement cannot
            # redirect the verified read.
            content_bytes = self._verify_artifact_content(entry, seen_physical)
            self._validate_role_metadata(entry, role)
            self._validate_scenario_identity(entry, role)
            self._track_singleton(role, singleton_counts)
            self._track_scenario_ids(entry, role, scenario_ids, scenario_to_candidate)
            # Scenario YAML/feature collection (pairing done post-loop).
            if role in (
                ArtifactRole.SCENARIO_YAML,
                ArtifactRole.SCENARIO_FEATURE,
            ):
                self._collect_scenario_entry(
                    role,
                    entry,
                    content_bytes,
                    yaml_stems,
                    yaml_scenario_ids,
                    feature_stems,
                    feature_scenario_ids_map,
                )
            # Index by role
            self._by_role.setdefault(role, []).append(entry)
            self._validated_entries[entry.path] = entry

        # --- 11. Post-index global YAML/feature pairing and identity checks ---
        _check_duplicate_candidate_ids(scenario_to_candidate)
        _check_yaml_feature_pairing(
            yaml_stems, feature_stems, requires_complete_inventory
        )
        _check_paired_stems(yaml_stems, yaml_scenario_ids, feature_scenario_ids_map)
        _validate_v3_legacy_authority(self.manifest)
        if _is_v3_completed_status(self.manifest):
            _validate_v3_required_artifacts(singleton_counts, self.manifest.status)
            self._validate_v3_inventory_integrity()

        # --- 12. Orphan detection ---
        if self.check_orphans:
            self._check_orphans(seen_canonical)

    def _entry_role(self, entry: ArtifactEntry) -> ArtifactRole:
        """Return the entry role, rejecting unknown values."""
        try:
            return entry.role
        except (ValueError, TypeError):
            # Do not re-read entry.role here: a raising accessor must not
            # mask the integrity error while formatting its message.
            raise ManifestIntegrityError("Invalid or unknown artifact role") from None

    def _validate_path_form(self, entry_path: Path, path_str: str) -> None:
        """Reject absolute, backslash, and non-canonical artifact paths."""
        if entry_path.is_absolute():
            raise ManifestIntegrityError(f"Artifact path is absolute: {path_str}")
        # Reject backslashes — PurePosixPath does not treat them as
        # separators, so they would silently survive canonicalisation.
        if "\\" in path_str:
            raise ManifestIntegrityError(
                f"Artifact path contains backslash: {path_str}"
            )
        # Reject non-normalized paths: compare original string to canonical
        # PurePosixPath rendering so ./, //, and . fail.
        canonical = PurePosixPath(path_str).as_posix()
        if canonical != path_str:
            raise ManifestIntegrityError(
                f"Artifact path is not canonical: '{path_str}' (expected '{canonical}')"
            )

    def _validate_path_components(self, entry_path: Path, path_str: str) -> None:
        """Reject dot and dot-dot components in an artifact path."""
        if ".." in entry_path.parts:
            raise ManifestIntegrityError(f"Artifact path contains '..': {path_str}")
        if path_str == "." or "." in entry_path.parts:
            raise ManifestIntegrityError(
                f"Artifact path contains a dot component: {path_str}"
            )

    def _validate_entry_path(self, entry: ArtifactEntry) -> None:
        """Reject unsafe or non-canonical artifact paths."""
        entry_path = Path(entry.path)
        self._validate_path_form(entry_path, entry.path)
        self._validate_path_components(entry_path, entry.path)

    def _track_canonical_path(
        self, entry: ArtifactEntry, seen_canonical: set[str]
    ) -> None:
        """Reject duplicate canonical artifact paths."""
        if entry.path in seen_canonical:
            raise ManifestIntegrityError(
                f"Duplicate artifact canonical path: {entry.path}"
            )
        seen_canonical.add(entry.path)

    def _validate_sha256_field(self, entry: ArtifactEntry) -> None:
        """Require a well-formed SHA-256 field on the entry."""
        if not entry.sha256:
            raise ManifestIntegrityError(f"Missing SHA-256 for artifact: {entry.path}")
        if not _SHA256_RE.match(entry.sha256):
            raise ManifestIntegrityError(
                f"Malformed SHA-256 for artifact {entry.path}: {entry.sha256}"
            )

    def _verify_artifact_content(
        self,
        entry: ArtifactEntry,
        seen_physical: set[tuple[int, int]],
    ) -> bytes:
        """Open once through O_NOFOLLOW and hash-verify against the manifest.

        Read all content through a single fd so that hash and YAML
        identity checks use the exact same bytes, eliminating TOCTOU
        between separate reads.  Cache the verified bytes so
        read_text/read_bytes serve exactly what was validated.
        """
        content_bytes, physical_id = self._open_artifact(entry.path)
        if physical_id in seen_physical:
            raise ManifestIntegrityError(
                f"Duplicate artifact physical file (device/inode): {entry.path}"
            )
        seen_physical.add(physical_id)
        actual_hash = hashlib.sha256(content_bytes).hexdigest()
        if actual_hash != entry.sha256:
            raise ManifestIntegrityError(
                f"Hash mismatch for {entry.path}: "
                f"manifest={entry.sha256}, actual={actual_hash}"
            )
        self._content_cache[entry.path] = content_bytes
        return content_bytes

    def _validate_role_schema_version(
        self, entry: ArtifactEntry, role: ArtifactRole, meta: dict[str, Any]
    ) -> None:
        """Require a supported schema_version for a role's metadata."""
        supported_versions = meta.get("schema_versions", [])
        if not entry.schema_version:
            raise ManifestIntegrityError(
                f"Missing schema_version for artifact: {entry.path}"
            )
        if supported_versions and entry.schema_version not in supported_versions:
            raise ManifestIntegrityError(
                f"Role {role.value} expects schema_version "
                f"in {supported_versions}, got '{entry.schema_version}' "
                f"for {entry.path}"
            )

    def _validate_singleton_path(
        self, entry: ArtifactEntry, role: ArtifactRole, meta: dict[str, Any]
    ) -> None:
        """Require a singleton artifact to live at its exact expected path."""
        singleton_path = meta.get("singleton_path")
        if singleton_path is not None and entry.path != singleton_path:
            raise ManifestIntegrityError(
                f"Role {role.value} must be at '{singleton_path}', got: {entry.path}"
            )

    def _validate_role_metadata(self, entry: ArtifactEntry, role: ArtifactRole) -> None:
        """Validate extension, media type, schema version, and singleton path."""
        meta = _ROLE_METADATA.get(role)
        if meta is None:
            if not entry.schema_version:
                raise ManifestIntegrityError(
                    f"Missing schema_version for artifact: {entry.path}"
                )
            return
        expected_ext = meta["extension"]
        if not entry.path.endswith(expected_ext):
            raise ManifestIntegrityError(
                f"Role {role.value} expects extension {expected_ext}, got: {entry.path}"
            )
        expected_media = meta["media_type"]
        if entry.media_type != expected_media:
            raise ManifestIntegrityError(
                f"Role {role.value} expects media_type "
                f"'{expected_media}', got '{entry.media_type}' "
                f"for {entry.path}"
            )
        self._validate_role_schema_version(entry, role, meta)
        self._validate_singleton_path(entry, role, meta)

    def _validate_quarantine_entry(
        self, entry: ArtifactEntry, role: ArtifactRole
    ) -> None:
        """Require quarantine bundles to carry candidate context only."""
        if role is not ArtifactRole.QUARANTINE_BUNDLE:
            return
        if entry.scenario_id is not None:
            raise ManifestIntegrityError(
                f"Quarantine bundle must not carry scenario_id: {entry.path}"
            )
        if not entry.candidate_id:
            raise ManifestIntegrityError(
                f"Role {role.value} requires candidate_id: {entry.path}"
            )
        expected_prefix = "quarantine/"
        if not entry.path.startswith(expected_prefix):
            raise ManifestIntegrityError(
                f"Quarantine bundle must be below '{expected_prefix}': {entry.path}"
            )

    def _validate_scenario_identity(
        self, entry: ArtifactEntry, role: ArtifactRole
    ) -> None:
        """Require scenario/candidate IDs on scenario and quarantine entries."""
        if role in (
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
        ):
            if not entry.scenario_id:
                raise ManifestIntegrityError(
                    f"Role {role.value} requires scenario_id: {entry.path}"
                )
            if not entry.candidate_id:
                raise ManifestIntegrityError(
                    f"Role {role.value} requires candidate_id: {entry.path}"
                )
        self._validate_quarantine_entry(entry, role)

    def _track_singleton(
        self, role: ArtifactRole, singleton_counts: dict[ArtifactRole, int]
    ) -> None:
        """Count singleton roles, rejecting any duplicate."""
        if role in SINGLETON_ROLES:
            singleton_counts[role] = singleton_counts.get(role, 0) + 1
            if singleton_counts[role] > 1:
                raise ManifestIntegrityError(
                    f"Duplicate singleton role {role.value}: "
                    f"{singleton_counts[role]} entries"
                )

    def _register_scenario_id(
        self,
        entry: ArtifactEntry,
        role: ArtifactRole,
        scenario_ids: set[tuple[ArtifactRole, str]],
    ) -> None:
        """Register one (role, scenario_id) pair, rejecting duplicates."""
        sid_key = (role, entry.scenario_id)
        if sid_key in scenario_ids:
            raise ManifestIntegrityError(
                f"Duplicate scenario_id for role {role.value}: {entry.scenario_id}"
            )
        scenario_ids.add(sid_key)

    def _register_scenario_candidate(
        self,
        entry: ArtifactEntry,
        scenario_to_candidate: dict[str, str],
    ) -> None:
        """Track scenario_id → candidate_id, rejecting conflicts."""
        prev_cid = scenario_to_candidate.get(entry.scenario_id)
        if prev_cid is not None and prev_cid != entry.candidate_id:
            raise ManifestIntegrityError(
                f"Conflicting candidate_id for scenario "
                f"{entry.scenario_id}: {prev_cid} vs {entry.candidate_id}"
            )
        scenario_to_candidate[entry.scenario_id] = entry.candidate_id

    def _track_scenario_ids(
        self,
        entry: ArtifactEntry,
        role: ArtifactRole,
        scenario_ids: set[tuple[ArtifactRole, str]],
        scenario_to_candidate: dict[str, str],
    ) -> None:
        """Track scenario/candidate IDs for post-loop duplicate checks."""
        if not entry.scenario_id:
            return
        self._register_scenario_id(entry, role, scenario_ids)
        if entry.candidate_id:
            self._register_scenario_candidate(entry, scenario_to_candidate)

    def _collect_scenario_yaml(
        self,
        entry: ArtifactEntry,
        content_bytes: bytes,
        yaml_stems: set[str],
        yaml_scenario_ids: dict[str, dict[str, str | None]],
    ) -> None:
        """Collect a scenario YAML stem and its serialized identity."""
        stem = Path(entry.path).stem
        yaml_stems.add(stem)
        expected_yaml_path = f"scenarios/{entry.scenario_id}.yaml"
        if entry.path != expected_yaml_path:
            raise ManifestIntegrityError(
                f"Scenario YAML must be at canonical path "
                f"'{expected_yaml_path}', got '{entry.path}'"
            )
        _data, serialized_sid, serialized_cid = _parse_scenario_yaml(
            entry, content_bytes
        )
        _require_serialized_ids(entry, serialized_sid, serialized_cid)
        yaml_scenario_ids[stem] = {
            "inventory": entry.scenario_id or "",
            "serialized": serialized_sid,
            "serialized_cid": serialized_cid,
            "inventory_cid": entry.candidate_id or "",
        }

    def _collect_scenario_feature(
        self,
        entry: ArtifactEntry,
        feature_stems: set[str],
        feature_scenario_ids_map: dict[str, str],
    ) -> None:
        """Collect a scenario feature stem and its scenario_id."""
        stem = Path(entry.path).stem
        feature_stems.add(stem)
        feature_scenario_ids_map[stem] = entry.scenario_id or ""
        expected_feat_path = f"scenarios/{entry.scenario_id}.feature"
        if entry.path != expected_feat_path:
            raise ManifestIntegrityError(
                f"Scenario feature must be at canonical path "
                f"'{expected_feat_path}', got '{entry.path}'"
            )

    def _collect_scenario_entry(
        self,
        role: ArtifactRole,
        entry: ArtifactEntry,
        content_bytes: bytes,
        yaml_stems: set[str],
        yaml_scenario_ids: dict[str, dict[str, str | None]],
        feature_stems: set[str],
        feature_scenario_ids_map: dict[str, str],
    ) -> None:
        """Collect scenario YAML or feature pairing state for one entry."""
        if role == ArtifactRole.SCENARIO_YAML:
            self._collect_scenario_yaml(
                entry, content_bytes, yaml_stems, yaml_scenario_ids
            )
        else:
            self._collect_scenario_feature(
                entry, feature_stems, feature_scenario_ids_map
            )

    def _validate_v3_inventory_integrity(self) -> None:
        """Run v3 inventory-level integrity checks against the fully validated
        inventory: quarantine rules, lifecycle completeness, scorecard
        binding, and semantic-generation consistency with the finalization
        inventory.

        Imports from ``pipeline.persistence`` are deferred so the resolver
        module has no load-time dependency on higher-level modules.
        """
        from asago_scenario_generator.pipeline.persistence import (
            FinalizationInventoryV1,
            build_semantic_generation_summary,
            validate_v3_inventories,
        )

        validate_v3_inventories(self)
        if self.manifest.semantic_generation:
            finalization_entry = self.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
            assert finalization_entry is not None
            authoritative_inventory = FinalizationInventoryV1.model_validate(
                self.read_json(finalization_entry)
            )
            expected_semantic_generation = build_semantic_generation_summary(
                authoritative_inventory
            )
            if self.manifest.semantic_generation != expected_semantic_generation:
                raise ManifestIntegrityError(
                    "semantic_generation does not match finalization inventory"
                )
        _validate_v3_scorecard_binding(self.manifest, self)

    def _check_orphans(self, manifested_paths: set[str]) -> None:
        """Detect unmanifested files inside the run directory.

        The manifest container file (``run-manifest.yaml``) is the sole
        orphan exception — it is the inventory container, not an artifact.
        """
        actual_files: set[str] = set()
        for root, _dirs, files in os.walk(self.run_dir):
            for fname in files:
                full = Path(root) / fname
                rel = full.relative_to(self.run_dir).as_posix()
                actual_files.add(rel)

        allowed_unmanifested = {MANIFEST_FILENAME}
        orphans = actual_files - manifested_paths - allowed_unmanifested
        if orphans:
            raise ManifestIntegrityError(
                f"Unmanifested orphan files in run directory: {sorted(orphans)}"
            )

    # --- Typed accessors ---

    def entries_by_role(self, role: ArtifactRole) -> list[ArtifactEntry]:
        """Return all inventory entries with the given role."""
        return list(self._by_role.get(role, []))

    def entry_by_role(self, role: ArtifactRole) -> ArtifactEntry | None:
        """Return the single entry with the given role, or None."""
        entries = self.entries_by_role(role)
        if len(entries) > 1:
            raise ManifestIntegrityError(
                f"Expected at most 1 entry for role {role}, got {len(entries)}"
            )
        return entries[0] if entries else None

    def resolve_path(self, entry: ArtifactEntry) -> Path:
        """Return the lexical absolute path without following components."""
        return self.run_dir / entry.path

    def read_bytes(self, entry: ArtifactEntry) -> bytes:
        """Read the content of an inventory entry as bytes.

        Serves from the immutable cache of fd-read, hash-verified bytes
        populated during ``_validate`` — consumers always receive the
        exact bytes that were validated, never a fresh read that could
        be affected by post-validation file replacement.
        """
        return self._verified_read(entry)

    def read_text(self, entry: ArtifactEntry, encoding: str = "utf-8") -> str:
        """Read the content of an inventory entry as text.

        Serves from the immutable cache of fd-read, hash-verified bytes.
        """
        return self.read_bytes(entry).decode(encoding)

    def read_yaml(self, entry: ArtifactEntry) -> Any:
        """Read and parse a YAML inventory entry from verified bytes."""
        return yaml.safe_load(self.read_text(entry))

    def read_json(self, entry: ArtifactEntry) -> Any:
        """Read and parse a JSON inventory entry from verified bytes."""
        return json.loads(self.read_text(entry))

    def _verified_read(self, entry: ArtifactEntry) -> bytes:
        """Return only bytes cached for an exact validated inventory entry."""
        validated = self._validated_entries.get(entry.path)
        content = self._content_cache.get(entry.path)
        if validated != entry or content is None:
            raise ManifestIntegrityError(
                f"Artifact was not validated and cached by this resolver: {entry.path}"
            )
        return content

    def _open_validation_root(self) -> int:
        """Open the run directory root fd, duplicating the cached one if any."""
        if self._validation_root_fd is not None:
            return os.dup(self._validation_root_fd)
        return os.open(self.run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def _open_component_dirs(
        self,
        parts: tuple[str, ...],
        current_fd: int,
        opened_dirs: list[int],
    ) -> int:
        """Open each parent component dirfd without following symlinks."""
        for part in parts[:-1]:
            current_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            opened_dirs.append(current_fd)
        return current_fd

    def _read_artifact_leaf(
        self, leaf_fd: int, relative_path: str
    ) -> tuple[bytes, os.stat_result]:
        """Read the leaf fd to EOF and return content plus its stat."""
        file_stat = os.fstat(leaf_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ManifestIntegrityError(
                f"Artifact is not a regular file: {relative_path}"
            )
        chunks: list[bytes] = []
        while chunk := os.read(leaf_fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks), file_stat

    def _open_artifact(self, relative_path: str) -> tuple[bytes, tuple[int, int]]:
        """Open a regular artifact by component-wise dirfd traversal."""
        opened_dirs: list[int] = []
        leaf_fd: int | None = None
        try:
            current_fd = self._open_validation_root()
            opened_dirs.append(current_fd)
            parts = PurePosixPath(relative_path).parts
            current_fd = self._open_component_dirs(parts, current_fd, opened_dirs)
            self._leaf_open_hook()
            leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
            content_bytes, file_stat = self._read_artifact_leaf(leaf_fd, relative_path)
            return content_bytes, (file_stat.st_dev, file_stat.st_ino)
        except OSError as exc:
            raise ManifestIntegrityError(
                f"Cannot safely read artifact {relative_path} (symlink, does not exist, "
                f"or unsafe path): {exc}"
            ) from exc
        finally:
            if leaf_fd is not None:
                os.close(leaf_fd)
            for directory_fd in reversed(opened_dirs):
                os.close(directory_fd)

    def scenario_yaml_entries(self) -> list[ArtifactEntry]:
        """Return all scenario YAML entries, sorted by scenario_id."""
        return sorted(
            self.entries_by_role(ArtifactRole.SCENARIO_YAML),
            key=lambda e: e.scenario_id or e.path,
        )

    def scenario_feature_entries(self) -> list[ArtifactEntry]:
        """Return all scenario feature entries, sorted by scenario_id."""
        return sorted(
            self.entries_by_role(ArtifactRole.SCENARIO_FEATURE),
            key=lambda e: e.scenario_id or e.path,
        )

    def feature_for_scenario(self, scenario_id: str) -> ArtifactEntry | None:
        """Return the feature entry for a given scenario_id, if any."""
        for e in self.entries_by_role(ArtifactRole.SCENARIO_FEATURE):
            if e.scenario_id == scenario_id:
                return e
        return None


def _is_v3_completed_status(manifest: RunManifest) -> bool:
    """True for v3 manifests in a final completed-like status."""
    return manifest.manifest_version == MANIFEST_V3 and manifest.status in {
        RunStatus.COMPLETED,
        RunStatus.COMPLETED_WITH_WARNINGS,
        RunStatus.COMPLETED_WITH_ERRORS,
    }


def _validate_v3_legacy_authority(manifest: RunManifest) -> None:
    """Require v3 lifecycle authority to live in the finalization inventory."""
    if manifest.manifest_version != MANIFEST_V3:
        return
    legacy_authorities = {
        "attempts": manifest.attempts,
        "funnel": manifest.funnel,
        "stage_records": manifest.stage_records,
        "rule_verdicts": manifest.rule_verdicts,
        "artifacts": manifest.artifacts,
        "phantom_validation": manifest.phantom_validation,
        "structural_validation": manifest.structural_validation,
        "semantic_validation": manifest.semantic_validation,
        "leaf_technique_provenance": manifest.leaf_technique_provenance,
        "parsimony": manifest.parsimony,
        "scenarios_generated": manifest.scenarios_generated,
        "scenarios_failed": manifest.scenarios_failed,
    }
    populated = sorted(name for name, value in legacy_authorities.items() if value)
    if populated:
        raise ManifestIntegrityError(
            "Manifest v3 lifecycle authority is finalization_inventory; "
            f"legacy lifecycle fields must be empty: {populated}"
        )


def _validate_v3_required_artifacts(
    singleton_counts: dict[ArtifactRole, int],
    status: RunStatus,
) -> None:
    """Require the three v3 planning artifacts exactly once for final statuses."""
    for role in (
        ArtifactRole.PLANNING_CHECKPOINT,
        ArtifactRole.COVERAGE_PLAN,
        ArtifactRole.FINALIZATION_INVENTORY,
    ):
        if singleton_counts.get(role, 0) != 1:
            raise ManifestIntegrityError(
                f"Manifest v3 status {status.value} requires "
                f"exactly one {role.value} artifact"
            )


def _validate_legacy_role_support(manifest_version: str, role: ArtifactRole) -> None:
    """Reject v3-only roles in legacy v2 manifests."""
    if manifest_version == LEGACY_MANIFEST_VERSION and role in {
        ArtifactRole.PLANNING_CHECKPOINT,
        ArtifactRole.COVERAGE_PLAN,
        ArtifactRole.FINALIZATION_INVENTORY,
        ArtifactRole.QUARANTINE_BUNDLE,
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
    }:
        raise ManifestIntegrityError(
            f"Manifest v2 does not support v3-only role {role.value}"
        )


def _parse_scenario_yaml(
    entry: ArtifactEntry, content_bytes: bytes
) -> tuple[dict[str, Any], str | None, str | None]:
    """Parse a scenario YAML from verified bytes; require a dict body."""
    try:
        data = yaml.safe_load(content_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            raise ManifestIntegrityError(f"Scenario YAML {entry.path} is not a dict")
        return data, data.get("scenario_id"), data.get("candidate_id")
    except ManifestIntegrityError:
        raise
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Failed to read scenario YAML {entry.path}: {exc}"
        ) from exc


def _require_serialized_ids(
    entry: ArtifactEntry,
    serialized_sid: str | None,
    serialized_cid: str | None,
) -> None:
    """Require serialized scenario/candidate IDs in a scenario YAML."""
    if not serialized_sid:
        raise ManifestIntegrityError(
            f"Scenario YAML {entry.path} missing serialized scenario_id"
        )
    if not serialized_cid:
        raise ManifestIntegrityError(
            f"Scenario YAML {entry.path} missing serialized candidate_id"
        )


def _check_duplicate_candidate_ids(
    scenario_to_candidate: dict[str, str],
) -> None:
    """Reject duplicate candidate IDs across different scenario pairs."""
    cid_to_scenarios: dict[str, set[str]] = {}
    for sid, cid in scenario_to_candidate.items():
        cid_to_scenarios.setdefault(cid, set()).add(sid)
    for cid, sids in cid_to_scenarios.items():
        if len(sids) > 1:
            raise ManifestIntegrityError(
                f"Duplicate candidate_id {cid} across different "
                f"scenarios: {sorted(sids)}"
            )


def _pairing_parts(yaml_only: set[str], feature_only: set[str]) -> list[str]:
    """Describe unpaired scenario stems as human-readable parts."""
    parts: list[str] = []
    if yaml_only:
        parts.append(f"YAML without feature: {sorted(yaml_only)}")
    if feature_only:
        parts.append(f"feature without YAML: {sorted(feature_only)}")
    return parts


def _check_yaml_feature_pairing(
    yaml_stems: set[str],
    feature_stems: set[str],
    requires_complete_inventory: bool,
) -> None:
    """Require exact YAML/feature stem pairing for completed manifests."""
    if not requires_complete_inventory:
        return
    yaml_only = yaml_stems - feature_stems
    feature_only = feature_stems - yaml_stems
    if yaml_only or feature_only:
        parts = _pairing_parts(yaml_only, feature_only)
        raise ManifestIntegrityError(
            f"Incomplete scenario YAML/feature pairs: {'; '.join(parts)}"
        )


def _check_paired_stems(
    yaml_stems: set[str],
    yaml_scenario_ids: dict[str, dict[str, str | None]],
    feature_scenario_ids_map: dict[str, str],
) -> None:
    """Run order-independent identity checks for each paired stem."""
    for stem in yaml_stems:
        yaml_info = yaml_scenario_ids.get(stem)
        if yaml_info is None:
            continue
        _check_paired_stem(stem, yaml_info, feature_scenario_ids_map)


def _check_paired_stem(
    stem: str,
    yaml_info: dict[str, str | None],
    feature_scenario_ids_map: dict[str, str],
) -> None:
    """Check inventory/serialized/feature identity for one scenario stem."""
    inv_sid = yaml_info.get("inventory") or ""
    ser_sid = yaml_info.get("serialized")
    ser_cid = yaml_info.get("serialized_cid")
    inv_cid = yaml_info.get("inventory_cid") or ""
    _validate_stem_inventory_ids(stem, inv_sid, ser_sid)
    _validate_stem_filename(stem, ser_sid)
    _validate_stem_candidate_id(stem, ser_cid, inv_cid)
    feat_sid = feature_scenario_ids_map.get(stem, "")
    _validate_stem_feature_pair(stem, feat_sid, inv_sid)


def _validate_stem_inventory_ids(stem: str, inv_sid: str, ser_sid: str | None) -> None:
    """Require the inventory scenario_id and its serialized match."""
    if not inv_sid:
        raise ManifestIntegrityError(
            f"Scenario YAML {stem}.yaml missing inventory scenario_id"
        )
    if ser_sid and inv_sid and ser_sid != inv_sid:
        raise ManifestIntegrityError(
            f"Scenario ID mismatch for {stem}.yaml: "
            f"inventory={inv_sid}, serialized={ser_sid}"
        )


def _validate_stem_filename(stem: str, ser_sid: str | None) -> None:
    """Require the filename stem to match the serialized scenario_id."""
    if ser_sid and ser_sid != stem:
        raise ManifestIntegrityError(
            f"Filename stem '{stem}' does not match "
            f"serialized scenario_id '{ser_sid}' in {stem}.yaml"
        )


def _validate_stem_candidate_id(stem: str, ser_cid: str | None, inv_cid: str) -> None:
    """Require serialized candidate_id to match the inventory value."""
    if ser_cid and inv_cid and ser_cid != inv_cid:
        raise ManifestIntegrityError(
            f"Candidate ID mismatch for {stem}.yaml: "
            f"inventory={inv_cid}, serialized={ser_cid}"
        )


def _validate_stem_feature_pair(stem: str, feat_sid: str, inv_sid: str) -> None:
    """Require the paired feature scenario_id to match the YAML value."""
    if feat_sid and inv_sid and feat_sid != inv_sid:
        raise ManifestIntegrityError(
            f"Feature scenario_id mismatch for {stem}.feature: "
            f"feature={feat_sid}, yaml={inv_sid}"
        )


# --------------------------------------------------------------------------- #
# Scorecard binding validation (cross-artifact integrity, no pipeline dep)
# --------------------------------------------------------------------------- #


def _load_v3_scorecard(
    resolver: ManifestInventoryResolver, entry: ArtifactEntry
) -> Any:
    """Parse a persisted v3 scorecard against the strict v1 schema."""
    from asago_scenario_generator.eval.scorecard import ScorecardV1

    try:
        return ScorecardV1.model_validate(resolver.read_yaml(entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Scorecard violates strict v1 schema: {exc}"
        ) from exc


def _validate_scorecard_counts(
    scorecard: Any, resolver: ManifestInventoryResolver
) -> None:
    """Require the scorecard scenario/feature counts to match the inventory."""
    scenario_count = len(resolver.entries_by_role(ArtifactRole.SCENARIO_YAML))
    feature_count = len(resolver.entries_by_role(ArtifactRole.SCENARIO_FEATURE))
    if scorecard.scenario_count != scenario_count:
        raise ManifestIntegrityError(
            f"Scorecard scenario_count={scorecard.scenario_count} "
            f"does not match inventory count={scenario_count}"
        )
    if scorecard.feature_file_count != feature_count:
        raise ManifestIntegrityError(
            f"Scorecard feature_file_count={scorecard.feature_file_count} "
            f"does not match inventory count={feature_count}"
        )


def _validate_scorecard_qualification(scorecard: Any, status: RunStatus) -> None:
    """Require a passing qualification for complete-status manifests."""
    if (
        status.requires_complete_inventory
        and scorecard.qualification.status.value != "pass"
    ):
        raise ManifestIntegrityError(
            "completed manifest requires passing scorecard qualification"
        )


def _validate_v3_scorecard_binding(
    manifest: RunManifest, resolver: ManifestInventoryResolver
) -> None:
    """Validate any persisted final v3 scorecard at the resolver boundary."""
    entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
    if entry is None:
        return
    scorecard = _load_v3_scorecard(resolver, entry)
    if scorecard.run_id != manifest.run_id:
        raise ManifestIntegrityError(
            f"Scorecard run_id={scorecard.run_id!r} does not match "
            f"manifest run_id={manifest.run_id!r}"
        )
    _validate_scorecard_counts(scorecard, resolver)
    _validate_scorecard_qualification(scorecard, manifest.status)
