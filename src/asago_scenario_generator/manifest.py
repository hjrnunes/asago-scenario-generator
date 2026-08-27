"""Immutable run identity, versioned manifest, artifact inventory, and provenance.

This module is the single ownership boundary for:

* Run collection → run directory resolution (sortable, collision-safe)
* Versioned manifest sentinel lifecycle (``started`` → final status)
* Typed artifact inventory with SHA-256 verification and global integrity
* Comprehensive provenance capture (Git, config, inputs, model, prompts)
* Strict manifest inventory resolver shared by eval and report readers

Every invocation creates a new ``<collection>/<run_id>/`` child directory.
Existing run directories are never reused, cleaned, or overwritten.
"""

# This module re-exports the split implementation as the compatibility façade
# for the long-standing ``asago_scenario_generator.manifest`` API.
# ruff: noqa: F401

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.manifest_completion import (
    _admitted_attempt_keys,
    _check_completed_attempt_equations,
    _check_completed_duplicate_singletons,
    _check_completed_inventory_identity,
    _check_completed_scenario_pairing,
    _check_completed_scorecard_counts,
    _check_completed_scorecard_entry,
    _check_completed_singleton_roles,
    _check_scorecard_count_equality,
    _scenario_role_counts,
    _scorecard_entry_verifiable,
    _strict_resolver_for_completed,
    _unique_scenario_ids,
    _v2_scorecard_counts,
    _v3_scorecard_counts,
    _yaml_inventory_keys,
    _quarantined_attempt_keys,
    validate_completed_inventory,
    validate_v3_resolver_policy,
)
from asago_scenario_generator.manifest_errors import ManifestIntegrityError
from asago_scenario_generator.manifest_funnel import (
    _attempt_tallies,
    _check_funnel_aggregate_equations,
    _check_main_funnel_equations,
    _check_qualified_capacity,
    _check_remediation_funnel_equations,
    _check_total_failed_equation,
    _disposition_tally,
    _duplicate_attempt_keys,
    _phase_attempted,
    _require_funnel_lifecycle_keys,
    _resolve_persisted_artifacts,
    _resolve_qualified_count,
    _validate_attempt_evidence,
    _validate_zero_attempt_funnel,
    derive_funnel_from_attempts,
    validate_attempt_equations,
)
from asago_scenario_generator.manifest_models import (
    ARTIFACT_SCHEMA_VERSION,
    LEGACY_MANIFEST_VERSION,
    MANIFEST_FILENAME,
    MANIFEST_VERSION,
    MANIFEST_V3,
    ArtifactEntry,
    ArtifactRole,
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    CommandProvenance,
    GitProvenance,
    InputHashes,
    ModelConfig,
    Provenance,
    RunManifest,
    RunStatus,
    SINGLETON_ROLES,
    _ROLE_METADATA,
    _RUN_ID_HEX_LEN,
    _RUN_ID_RE,
    _RUN_ID_SEPARATOR,
    _RUN_ID_TIMESTAMP_LEN,
    _RUN_ID_TOTAL_LEN,
    _SHA256_RE,
    _DECLARED_AUTHORITATIVE_WARNING_PREFIXES,
    required_singleton_roles,
    select_final_run_status,
)
from asago_scenario_generator.manifest_resolver import (
    ManifestInventoryResolver as _ManifestInventoryResolver,
    _check_duplicate_candidate_ids,
    _check_paired_stem,
    _check_paired_stems,
    _check_yaml_feature_pairing,
    _is_v3_completed_status,
    _load_v3_scorecard,
    _pairing_parts,
    _parse_scenario_yaml,
    _require_serialized_ids,
    _validate_legacy_role_support,
    _validate_scorecard_counts,
    _validate_scorecard_qualification,
    _validate_stem_candidate_id,
    _validate_stem_feature_pair,
    _validate_stem_filename,
    _validate_stem_inventory_ids,
    _validate_v3_legacy_authority,
    _validate_v3_required_artifacts,
    _validate_v3_scorecard_binding,
)


def _before_artifact_leaf_open() -> None:
    """Test seam invoked before opening an artifact leaf."""


_LEGACY_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class ManifestInventoryResolver(_ManifestInventoryResolver):
    """Compatibility façade for the strict inventory resolver."""

    def __init__(
        self,
        run_dir: Path,
        manifest: RunManifest,
        check_orphans: bool = True,
    ) -> None:
        super().__init__(
            run_dir,
            manifest,
            check_orphans,
            leaf_open_hook=_before_artifact_leaf_open,
        )


# --------------------------------------------------------------------------- #
# Run ID generation and validation
# --------------------------------------------------------------------------- #


def generate_sortable_run_id() -> str:
    """Generate a sortable, collision-safe run ID.

    Format: ``YYYYMMDDTHHMMSS_<32 hex chars>`` (48 chars total).
    The timestamp prefix makes directories sortable by lexical order.
    The 128-bit random suffix prevents collisions within the same second.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    suffix = secrets.token_hex(16)  # 32 hex chars = 128 bits
    return f"{ts}_{suffix}"


def validate_run_id(run_id: str) -> None:
    """Validate that *run_id* is acceptable for manifest forensic loading.

    Accepts:
    - The canonical sortable format: ``YYYYMMDDTHHMMSS_<32hex>``
    - The legacy 32-char lowercase hex format (UUID4) — forensic read only.

    Raises:
        ValueError: If the run_id is invalid.
    """
    if not run_id:
        raise ValueError("run_id must not be empty")

    # Canonical sortable format or legacy 32-character lowercase hex
    # (UUID4 without dashes, forensic read only).
    if _RUN_ID_RE.match(run_id) or _LEGACY_RUN_ID_RE.fullmatch(run_id):
        return

    raise ValueError(
        f"run_id must be a sortable format (YYYYMMDDTHHMMSS_<32hex>) "
        f"or a 32-char hex string, got: '{run_id}' (length {len(run_id)})"
    )


def validate_generation_run_id(run_id: str) -> None:
    """Validate that *run_id* uses the canonical sortable format for new generation.

    Unlike :func:`validate_run_id`, this **rejects** the legacy 32-char hex
    format — new scenario generation must use ``YYYYMMDDTHHMMSS_<32hex>``.

    Raises:
        ValueError: If the run_id is not the canonical sortable format.
    """
    if not run_id:
        raise ValueError("run_id must not be empty")
    if not _RUN_ID_RE.match(run_id):
        raise ValueError(
            f"Generation run_id must be canonical sortable format "
            f"(YYYYMMDDTHHMMSS_<32hex>), got: '{run_id}' (length {len(run_id)})"
        )


def is_sortable_run_id(run_id: str) -> bool:
    """Check whether *run_id* uses the canonical sortable format."""
    return bool(_RUN_ID_RE.match(run_id))


# --------------------------------------------------------------------------- #
# Collection → run directory resolution
# --------------------------------------------------------------------------- #


def resolve_run_dir(
    collection_dir: Path, run_id: str | None = None
) -> tuple[Path, str]:
    """Resolve and exclusively create a new run directory under *collection_dir*.

    This is the **single ownership boundary** for collection-to-run
    resolution.  No other code should create run directories.

    Raises:
        FileExistsError: If the run directory already exists (collision).
        ValueError: If run_id is invalid.
    """
    if run_id is None:
        run_id = generate_sortable_run_id()
    validate_generation_run_id(run_id)

    collection_dir = Path(collection_dir)
    collection_dir.mkdir(parents=True, exist_ok=True)
    run_dir = collection_dir / run_id

    run_dir.mkdir(exist_ok=False)
    return run_dir, run_id


# --------------------------------------------------------------------------- #
# File hashing
# --------------------------------------------------------------------------- #


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file's exact bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of exact bytes."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Atomic file writing
# --------------------------------------------------------------------------- #


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> Path:
    """Write text to *path* atomically using temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, suffix=".tmp", prefix=path.name
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        # Persist the directory entry as well as file contents.  Without this
        # fsync, a power loss after replace can lose the rename despite a
        # fully flushed temporary file.
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path


def atomic_write_yaml(path: Path, data: Any) -> Path:
    """Write YAML atomically."""
    content = yaml.dump(
        data, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
    return atomic_write_text(path, content)


# --------------------------------------------------------------------------- #
# Manifest sentinel and finalization
# --------------------------------------------------------------------------- #


def _get_package_version() -> str:
    try:
        return importlib.metadata.version("asago-scenario-generator")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def write_manifest_sentinel(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    package_version: str | None = None,
    manifest_version: str = MANIFEST_VERSION,
) -> Path:
    """Write the initial manifest sentinel before any pipeline work begins.

    The sentinel has status ``started`` and survives every exit path.
    It is later replaced by the final manifest via :func:`finalize_manifest`.
    """
    if package_version is None:
        package_version = _get_package_version()

    sentinel = {
        "manifest_version": manifest_version,
        "status": RunStatus.STARTED.value,
        "run_id": run_id,
        "timestamp_start": timestamp_start,
        "package_version": package_version,
    }
    manifest_path = run_dir / MANIFEST_FILENAME
    return atomic_write_yaml(manifest_path, sentinel)


def write_started_manifest(run_dir: Path, manifest: RunManifest) -> Path:
    """Atomically checkpoint a resumable, non-final run manifest."""
    if manifest.status is not RunStatus.STARTED:
        raise ValueError(
            f"Cannot checkpoint manifest with non-started status: {manifest.status}"
        )
    manifest_path = run_dir / MANIFEST_FILENAME
    data = manifest.model_dump(mode="json", exclude_none=True)
    return atomic_write_yaml(manifest_path, data)


def finalize_manifest(
    run_dir: Path,
    manifest: RunManifest,
) -> Path:
    """Write the final manifest atomically, replacing the sentinel.

    The manifest must have a final status.
    """
    if not manifest.status.is_final:
        raise ValueError(
            f"Cannot finalize manifest with non-final status: {manifest.status}"
        )
    manifest_path = run_dir / MANIFEST_FILENAME
    data = manifest.model_dump(mode="json", exclude_none=True)
    return atomic_write_yaml(manifest_path, data)


def write_failed_manifest(
    run_dir: Path,
    manifest: RunManifest,
) -> Path:
    """Best-effort write of a ``failed`` manifest with accumulated evidence.

    Called when a fatal error prevents normal finalization.  Updates the
    *existing* manifest in-place with ``status=failed`` and an error
    field, preserving whatever attempts/artifacts/provenance were
    accumulated.  Does **not** replace it with an empty manifest.
    """
    manifest.status = RunStatus.FAILED
    manifest.timestamp_end = manifest.timestamp_end or datetime.now(UTC).isoformat()
    if manifest.provenance is not None:
        manifest.provenance.timestamp_end = manifest.timestamp_end
    data = manifest.model_dump(mode="json", exclude_none=True)
    manifest_path = run_dir / MANIFEST_FILENAME
    try:
        return atomic_write_yaml(manifest_path, data)
    except Exception:
        try:
            manifest_path.write_text(
                yaml.dump(data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )
        except Exception:
            pass
        return manifest_path


# --------------------------------------------------------------------------- #
# Git provenance
# --------------------------------------------------------------------------- #


def _find_source_repo_root() -> Path | None:
    """Find the Git repository root for the asago_scenario_generator source package."""
    # Walk up from the package directory to find a .git directory.
    pkg_dir = Path(__file__).resolve().parent
    for parent in [pkg_dir, *pkg_dir.parents]:
        if (parent / ".git").is_dir():
            return parent
    return None


def _run_git(repo_root: Path, *args: str) -> str | None:
    """Run one read-only git command and return trimmed stdout, or None."""
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            timeout=10,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return None


def _untracked_files(untracked_output: str | None) -> list[str]:
    """Return sorted untracked file paths from ``git ls-files`` output."""
    if not untracked_output:
        return []
    return sorted([f for f in untracked_output.splitlines() if f])


def _hashed_untracked_content(repo_root: Path, relative_path: str) -> bytes:
    """Return digest bytes for one untracked file, or an unreadable sentinel."""
    fpath = repo_root / relative_path
    if not fpath.is_file():
        return b""
    try:
        return hashlib.sha256(fpath.read_bytes()).hexdigest().encode() + b"\n"
    except OSError:
        return b"<unreadable>\n"


def _source_diff_digest(
    repo_root: Path, diff: str | None, untracked_files: list[str]
) -> str:
    """SHA-256 of the tracked diff plus deterministic untracked hashes."""
    hasher = hashlib.sha256()
    if diff is not None:
        hasher.update(b"--- diff ---\n")
        hasher.update(diff.encode("utf-8"))
    hasher.update(b"\n--- untracked ---\n")
    for f in untracked_files:
        hasher.update(f.encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(_hashed_untracked_content(repo_root, f))
    return hasher.hexdigest()


def capture_git_provenance(repo_root: Path | None = None) -> GitProvenance:
    """Capture Git commit, dirty state, and source-diff digest.

    Args:
        repo_root: Path to the Git repository root.  If None, finds the
            source repository root for the asago_scenario_generator package.

    Returns:
        GitProvenance with commit hash, dirty flag, source-diff digest
        (including untracked file content), and untracked file list.
        If Git is unavailable or not a repo, all fields are None.
    """
    if repo_root is None:
        repo_root = _find_source_repo_root()
    if repo_root is None:
        return GitProvenance()

    commit = _run_git(repo_root, "rev-parse", "HEAD")
    if commit is None:
        # Git is not available or not a repo — return all None
        return GitProvenance()
    branch = _run_git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")

    # Dirty state: check if working tree has modifications or untracked files
    status = _run_git(repo_root, "status", "--porcelain")
    dirty = bool(status) if status is not None else None

    # Source-diff digest: SHA-256 of tracked diff + deterministic untracked
    # file paths and content hashes.
    diff = _run_git(repo_root, "diff", "HEAD")
    untracked_files = _untracked_files(
        _run_git(repo_root, "ls-files", "--others", "--exclude-standard")
    )

    return GitProvenance(
        commit=commit,
        dirty=dirty,
        source_diff_digest=_source_diff_digest(repo_root, diff, untracked_files),
        branch=branch,
        untracked_files=untracked_files,
    )


# --------------------------------------------------------------------------- #
# Provenance capture
# --------------------------------------------------------------------------- #


def capture_provenance(
    run_id: str,
    timestamp_start: str,
    command: str = "generate",
    options: dict[str, Any] | None = None,
    model_config: ModelConfig | None = None,
    prompt_template_hashes: dict[str, str] | None = None,
    input_hashes: InputHashes | None = None,
    config_digest: str | None = None,
    repo_root: Path | None = None,
    timestamp_end: str | None = None,
) -> Provenance:
    """Capture comprehensive provenance for a run."""
    pkg_version = _get_package_version()
    git_prov = capture_git_provenance(repo_root)

    return Provenance(
        run_id=run_id,
        command=CommandProvenance(
            command=command,
            options=options or {},
        ),
        package_version=pkg_version,
        manifest_version=MANIFEST_VERSION,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        model_config_provenance=model_config,
        prompt_template_hashes=prompt_template_hashes or {},
        input_hashes=input_hashes or InputHashes(),
        config_digest=config_digest,
        git=git_prov,
    )


def compute_config_digest(options: dict[str, Any]) -> str:
    """Compute a canonical SHA-256 digest of the run configuration."""
    canonical = json.dumps(options, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Manifest loading and strict inventory validation
# --------------------------------------------------------------------------- #


def _read_manifest_dict(manifest_path: Path) -> dict[str, Any]:
    """Read and parse a manifest YAML file as a dict."""
    if not manifest_path.exists():
        raise ManifestIntegrityError(
            f"No manifest found in run directory: {manifest_path.parent}"
        )
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not data or not isinstance(data, dict):
        raise ManifestIntegrityError(f"Invalid manifest in {manifest_path}: not a dict")
    return data


def _validate_manifest_version(
    actual_version: str, requested_version: str | None
) -> None:
    """Require the manifest version to satisfy any request and supported set."""
    if requested_version is not None and actual_version != requested_version:
        raise ManifestIntegrityError(
            f"Unsupported manifest version {actual_version!r}; "
            f"version {requested_version!r} was explicitly requested"
        )
    if actual_version not in {LEGACY_MANIFEST_VERSION, MANIFEST_V3}:
        raise ManifestIntegrityError(
            f"Unsupported manifest version {actual_version!r}; supported versions are "
            f"{LEGACY_MANIFEST_VERSION!r} and {MANIFEST_V3!r}"
        )


def load_manifest(
    run_dir: Path, *, requested_version: str | None = None
) -> RunManifest:
    """Load and parse a manifest from a run directory.

    Does not validate inventory — use :func:`load_strict_resolver` for that.
    """
    run_dir = Path(run_dir)
    manifest_path = run_dir / MANIFEST_FILENAME
    data = _read_manifest_dict(manifest_path)
    actual_version = str(data.get("manifest_version", ""))
    _validate_manifest_version(actual_version, requested_version)
    return RunManifest.model_validate(data)


def _require_final_status(
    manifest: RunManifest, run_dir: Path, require_final: bool
) -> None:
    """Require a final manifest status when requested."""
    if require_final and not manifest.status.is_final:
        raise ManifestIntegrityError(
            f"Manifest status is not final: {manifest.status} in {run_dir}"
        )


def _require_authoritative_status(
    manifest: RunManifest, run_dir: Path, require_authoritative: bool
) -> None:
    """Require an authoritative manifest status when requested."""
    if require_authoritative and not manifest.status.is_authoritative:
        raise ManifestIntegrityError(
            f"Manifest is not authoritative (status={manifest.status}) in {run_dir}"
        )


def load_strict_resolver(
    run_dir: Path,
    require_final: bool = True,
    require_authoritative: bool = False,
    manifest_version: str | None = None,
) -> ManifestInventoryResolver:
    """Load a manifest from disk and build a strict inventory resolver.

    Args:
        run_dir: Path to a run directory (not a collection).
        require_final: If True, manifest status must be final.
        require_authoritative: If True, manifest status must be ``completed``.

    Raises:
        ManifestIntegrityError: If the manifest is missing, invalid,
            not final (when required), or not authoritative (when required).
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise ManifestIntegrityError(
            f"Run directory does not exist or is not a directory: {run_dir}"
        )

    manifest = load_manifest(run_dir, requested_version=manifest_version)
    _require_final_status(manifest, run_dir, require_final)
    _require_authoritative_status(manifest, run_dir, require_authoritative)

    check_orphans = require_final
    return ManifestInventoryResolver(run_dir, manifest, check_orphans=check_orphans)


def build_in_memory_resolver(
    run_dir: Path,
    manifest: RunManifest,
) -> ManifestInventoryResolver:
    """Build a resolver from an in-memory manifest for internal pipeline use.

    Validates inventory entries (paths, hashes, roles) but does **not**
    check for orphans — the run is still in progress and may have files
    not yet inventoried.
    """
    return ManifestInventoryResolver(run_dir, manifest, check_orphans=False)


def is_run_dir(path: Path) -> bool:
    """Check whether *path* is a run directory (contains a manifest)."""
    return (Path(path) / MANIFEST_FILENAME).exists()


def _runs_in_collection(collection: Path) -> list[Path]:
    """Return sorted run directories directly inside a collection."""
    return sorted(
        [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)],
        key=lambda d: d.name,
    )


def _single_run_in_collection(collection: Path, run_dirs: list[Path]) -> Path:
    """Resolve a collection containing exactly one run directory."""
    if len(run_dirs) == 1:
        return run_dirs[0]
    if not run_dirs:
        raise ManifestIntegrityError(
            f"No run directory found in collection: {collection}"
        )
    raise ManifestIntegrityError(
        f"Collection {collection} contains {len(run_dirs)} runs; "
        f"pass a specific run directory to disambiguate. "
        f"Runs: {[d.name for d in run_dirs]}"
    )


def find_run_dir(path: Path) -> Path:
    """Given a path, resolve it to a single unambiguous run directory.

    If *path* is a run directory (contains run-manifest.yaml), return it.
    If *path* is a collection containing **exactly one** run, return that run.
    If the collection contains zero or multiple runs, raise.
    """
    path = Path(path)
    if is_run_dir(path):
        return path

    if path.is_dir():
        return _single_run_in_collection(path, _runs_in_collection(path))

    raise ManifestIntegrityError(
        f"Path is neither a run directory nor a collection: {path}"
    )


# --------------------------------------------------------------------------- #
# Inventory builder helpers
# --------------------------------------------------------------------------- #


def build_artifact_entry(
    role: ArtifactRole,
    run_dir: Path,
    rel_path: str,
    scenario_id: str | None = None,
    candidate_id: str | None = None,
    schema_version: str = ARTIFACT_SCHEMA_VERSION,
) -> ArtifactEntry:
    """Build an ArtifactEntry from a file in the run directory.

    The file must exist — this function raises if it does not, so that
    ``_build_run_inventory`` fails for expected-but-missing outputs
    rather than silently omitting them.
    """
    full_path = run_dir / rel_path
    if not full_path.exists():
        raise ManifestIntegrityError(
            f"Expected artifact missing for role {role.value}: {rel_path}"
        )
    meta = _ROLE_METADATA.get(role, {})
    return ArtifactEntry(
        role=role,
        path=rel_path,
        sha256=compute_file_sha256(full_path),
        scenario_id=scenario_id,
        candidate_id=candidate_id,
        media_type=meta.get("media_type", "application/octet-stream"),
        schema_version=schema_version,
    )
