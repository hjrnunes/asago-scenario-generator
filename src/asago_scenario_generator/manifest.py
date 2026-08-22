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

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from collections.abc import Iterable
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

# --------------------------------------------------------------------------- #
# Constants and versions
# --------------------------------------------------------------------------- #

LEGACY_MANIFEST_VERSION = "2"
# Compatibility constant retained for callers that historically used this as
# the v2 reader/default sentinel version.  Production opts into v3 explicitly.
MANIFEST_VERSION = LEGACY_MANIFEST_VERSION
MANIFEST_V3 = "3"
ARTIFACT_SCHEMA_VERSION = "1"
_RUN_ID_TIMESTAMP_LEN = 15  # YYYYMMDDTHHMMSS
_RUN_ID_SEPARATOR = "_"
_RUN_ID_HEX_LEN = 32  # 128 bits of collision-safe entropy
_RUN_ID_TOTAL_LEN = _RUN_ID_TIMESTAMP_LEN + 1 + _RUN_ID_HEX_LEN  # 48
_RUN_ID_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})_([0-9a-f]{32})$")
MANIFEST_FILENAME = "run-manifest.yaml"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class RunStatus(str, Enum):
    """Lifecycle status of a run."""

    STARTED = "started"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"

    @classmethod
    def final_statuses(cls) -> set[RunStatus]:
        return {
            cls.COMPLETED,
            cls.COMPLETED_WITH_WARNINGS,
            cls.COMPLETED_WITH_ERRORS,
            cls.FAILED,
        }

    @property
    def is_final(self) -> bool:
        return self in self.final_statuses()

    @property
    def is_authoritative(self) -> bool:
        """Whether a run satisfied all ordinary completion gates."""
        return self.requires_complete_inventory

    @property
    def requires_complete_inventory(self) -> bool:
        """Whether the final run must satisfy completed inventory invariants."""
        return self in {self.COMPLETED, self.COMPLETED_WITH_WARNINGS}


_DECLARED_AUTHORITATIVE_WARNING_PREFIXES = (
    "candidate_filter_unavailable:",
    "presentation_fallback:",
)


def select_final_run_status(
    ordinary_completion_succeeded: bool,
    generation_notes: Iterable[str],
) -> RunStatus:
    """Select the final status without promoting undeclared warning classes."""
    if not ordinary_completion_succeeded:
        return RunStatus.COMPLETED_WITH_ERRORS
    if any(
        note.startswith(_DECLARED_AUTHORITATIVE_WARNING_PREFIXES)
        for note in generation_notes
    ):
        return RunStatus.COMPLETED_WITH_WARNINGS
    return RunStatus.COMPLETED


class ArtifactRole(str, Enum):
    """Typed role for every persisted artifact in a run.

    The manifest container file (``run-manifest.yaml``) is **not** an
    artifact entry — it is the sole orphan exception.
    """

    USE_CASE = "use_case"
    CAPABILITY_PROFILE = "capability_profile"
    THREAT_SURFACE = "threat_surface"
    SCENARIO_YAML = "scenario_yaml"
    SCENARIO_FEATURE = "scenario_feature"
    SCENARIO_CALL_LOG = "scenario_call_log"
    PIPELINE_CALL_LOG = "pipeline_call_log"
    COVERAGE_REPORT = "coverage_report"
    EVAL_SCORECARD = "eval_scorecard"
    REPORT = "report"
    PIPELINE_LOG = "pipeline_log"
    PLANNING_CHECKPOINT = "planning_checkpoint"
    COVERAGE_PLAN = "coverage_plan"
    FINALIZATION_INVENTORY = "finalization_inventory"
    QUARANTINE_BUNDLE = "quarantine_bundle"
    CANDIDATE_FILTER_QUARANTINE = "candidate_filter_quarantine"


class AttemptDisposition(str, Enum):
    """Disposition of a generation attempt."""

    ADMITTED = "admitted"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class AttemptPhase(str, Enum):
    """Phase of a generation attempt — main or remediation pass."""

    MAIN = "main"
    REMEDIATION = "remediation"


# --------------------------------------------------------------------------- #
# Role metadata
# --------------------------------------------------------------------------- #

# Expected file extension, media type, supported schema versions, and
# (for singleton roles) the exact canonical path for each role.
_ROLE_METADATA: dict[ArtifactRole, dict[str, Any]] = {
    ArtifactRole.USE_CASE: {
        "extension": ".txt",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": "use-case.txt",
    },
    ArtifactRole.CAPABILITY_PROFILE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "capability-profile.yaml",
    },
    ArtifactRole.THREAT_SURFACE: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "threat-surface.yaml",
    },
    ArtifactRole.SCENARIO_YAML: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.SCENARIO_FEATURE: {
        "extension": ".feature",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.SCENARIO_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
        "schema_versions": ["1"],
        "singleton_path": "scenarios/calls.jsonl",
    },
    ArtifactRole.PIPELINE_CALL_LOG: {
        "extension": ".jsonl",
        "media_type": "application/jsonl",
        "schema_versions": ["1"],
        "singleton_path": "calls.jsonl",
    },
    ArtifactRole.COVERAGE_REPORT: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "coverage-gaps.json",
    },
    ArtifactRole.EVAL_SCORECARD: {
        "extension": ".yaml",
        "media_type": "application/yaml",
        "schema_versions": ["1"],
        "singleton_path": "eval-scorecard.yaml",
    },
    ArtifactRole.REPORT: {
        "extension": ".html",
        "media_type": "text/html",
        "schema_versions": ["1"],
        "singleton_path": "report.html",
    },
    ArtifactRole.PIPELINE_LOG: {
        "extension": ".log",
        "media_type": "text/plain",
        "schema_versions": ["1"],
        "singleton_path": "pipeline.log",
    },
    ArtifactRole.PLANNING_CHECKPOINT: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "planning-checkpoint.json",
    },
    ArtifactRole.COVERAGE_PLAN: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["2"],
        "singleton_path": "coverage-plan.json",
    },
    ArtifactRole.FINALIZATION_INVENTORY: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "finalization-inventory.json",
    },
    ArtifactRole.QUARANTINE_BUNDLE: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": None,
    },
    ArtifactRole.CANDIDATE_FILTER_QUARANTINE: {
        "extension": ".json",
        "media_type": "application/json",
        "schema_versions": ["1"],
        "singleton_path": "candidate-filter-quarantine.json",
    },
}

# Roles that must appear at most once in the inventory.
SINGLETON_ROLES: frozenset[ArtifactRole] = frozenset(
    {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.EVAL_SCORECARD,
        ArtifactRole.REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.PIPELINE_CALL_LOG,
        ArtifactRole.SCENARIO_CALL_LOG,
        ArtifactRole.PLANNING_CHECKPOINT,
        ArtifactRole.COVERAGE_PLAN,
        ArtifactRole.FINALIZATION_INVENTORY,
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
    }
)


def required_singleton_roles(
    *, eval_enabled: bool, manifest_version: str = LEGACY_MANIFEST_VERSION
) -> set[ArtifactRole]:
    """Return the set of singleton roles required for ``completed`` status.

    *report* is always required.  *eval_scorecard* is required only when
    eval is enabled.
    """
    roles: set[ArtifactRole] = {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.COVERAGE_REPORT,
        ArtifactRole.PIPELINE_LOG,
        ArtifactRole.REPORT,
    }
    if eval_enabled:
        roles.add(ArtifactRole.EVAL_SCORECARD)
    if manifest_version == MANIFEST_V3:
        roles.update(
            {
                ArtifactRole.PLANNING_CHECKPOINT,
                ArtifactRole.COVERAGE_PLAN,
                ArtifactRole.FINALIZATION_INVENTORY,
            }
        )
    return roles


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #


class ArtifactEntry(BaseModel):
    """A single persisted artifact in the run inventory.

    Every entry requires a valid SHA-256 hash, media_type, schema_version,
    canonical role/path, and applicable scenario_id/candidate_id.
    """

    role: ArtifactRole
    path: str  # canonical relative path from run root
    sha256: str
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    media_type: str
    scenario_id: str | None = None
    candidate_id: str | None = None

    model_config = {"use_enum_values": False}


class AttemptRecord(BaseModel):
    """Typed record of a generation attempt keyed by candidate/scenario.

    Every attempt requires a deterministic ``scenario_id`` and
    ``candidate_id``.  Failed and quarantined attempts require typed
    ``failure_evidence``.
    """

    candidate_id: str
    scenario_id: str
    disposition: AttemptDisposition
    failure_evidence: str | None = None
    phase: AttemptPhase = AttemptPhase.MAIN

    model_config = {"use_enum_values": False}

    @model_validator(mode="after")
    def _validate_evidence(self) -> AttemptRecord:
        """Failed and quarantined attempts require nonempty evidence."""
        if self.disposition in (
            AttemptDisposition.FAILED,
            AttemptDisposition.QUARANTINED,
        ):
            if not self.failure_evidence or not self.failure_evidence.strip():
                raise ValueError(
                    f"AttemptRecord with disposition={self.disposition.value} "
                    f"requires nonempty failure_evidence"
                )
        return self


class GitProvenance(BaseModel):
    """Git source provenance for reproducibility."""

    commit: str | None = None
    dirty: bool | None = None
    source_diff_digest: str | None = None
    branch: str | None = None
    untracked_files: list[str] = Field(default_factory=list)


class InputHashes(BaseModel):
    """SHA-256 hashes of all effective inputs."""

    use_case_hash: str | None = None
    risk_extraction_hash: str | None = None
    sssom_hash: str | None = None
    cross_taxonomy_hash: str | None = None
    threats_hash: str | None = None
    source_profile_hash: str | None = None
    qualification_facts_hash: str | None = None
    effective_profile_hash: str | None = None
    attack_patterns_hash: str | None = None
    attack_patterns_sssom_hash: str | None = None
    attack_goals_taxonomy_hash: str | None = None
    threat_goal_affinity_hash: str | None = None
    # Deterministic sorted path→hash maps for all files actually loaded
    # by the attack-patterns*.yaml and attack-patterns*.sssom.tsv globs.
    attack_patterns_yaml_map: dict[str, str] = Field(default_factory=dict)
    attack_patterns_sssom_map: dict[str, str] = Field(default_factory=dict)


class ModelConfig(BaseModel):
    """Resolved LLM model configuration (effective values, not raw None args)."""

    model: str
    base_url: str | None = None
    temperature: float
    max_completion_tokens: int | None = None
    timeout: float | None = None
    top_p: float | None = None
    top_k: int | None = None
    use_guided_decoding: bool = False
    profile_name: str | None = None
    profiles_file: str | None = None
    header_names: list[str] = Field(default_factory=list)
    sources: dict[str, str] = Field(default_factory=dict)


class CommandProvenance(BaseModel):
    """Normalized command and options that invoked the run."""

    command: str = "generate"
    options: dict[str, Any] = Field(default_factory=dict)


class Provenance(BaseModel):
    """Full provenance for a run."""

    run_id: str
    command: CommandProvenance = Field(default_factory=CommandProvenance)
    package_version: str = "0.0.0"
    manifest_version: str = MANIFEST_VERSION
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION
    timestamp_start: str
    timestamp_end: str | None = None
    model_config_provenance: ModelConfig | None = None
    prompt_template_hashes: dict[str, str] = Field(default_factory=dict)
    input_hashes: InputHashes = Field(default_factory=InputHashes)
    config_digest: str | None = None
    git: GitProvenance = Field(default_factory=GitProvenance)


class RunManifest(BaseModel):
    """The complete versioned run manifest — sentinel and final inventory.

    ``run-manifest.yaml`` is the inventory **container**, not an
    :class:`ArtifactEntry`.  It is the sole orphan exception.
    """

    manifest_version: str = MANIFEST_VERSION
    status: RunStatus = RunStatus.STARTED
    run_id: str
    timestamp_start: str
    timestamp_end: str | None = None
    package_version: str = "0.0.0"
    provenance: Provenance | None = None
    inventory: list[ArtifactEntry] = Field(default_factory=list)
    attempts: list[AttemptRecord] = Field(default_factory=list)
    error: str | None = None

    # Legacy/extension fields from the pipeline manifest
    inputs: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    seeds_generated: int = 0
    funnel: dict[str, Any] = Field(default_factory=dict)
    stage_records: list[dict[str, Any]] = Field(default_factory=list)
    rule_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    scenarios_generated: int = 0
    scenarios_failed: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    phantom_validation: dict[str, Any] = Field(default_factory=dict)
    structural_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_validation: dict[str, Any] = Field(default_factory=dict)
    semantic_generation: dict[str, Any] = Field(default_factory=dict)
    leaf_technique_provenance: dict[str, Any] = Field(default_factory=dict)
    parsimony: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": False}


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

    # Canonical sortable format: YYYYMMDDTHHMMSS_<32hex>
    if _RUN_ID_RE.match(run_id):
        return

    # Legacy format: 32-char lowercase hex (UUID4 without dashes) — forensic read only
    if len(run_id) == 32 and run_id == run_id.lower():
        try:
            int(run_id, 16)
            return
        except ValueError:
            pass

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

    run_dir.mkdir(parents=True, exist_ok=False)
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
    cwd = str(repo_root)

    def _run_git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args],
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return None

    commit = _run_git("rev-parse", "HEAD")
    if commit is None:
        # Git is not available or not a repo — return all None
        return GitProvenance()
    branch = _run_git("rev-parse", "--abbrev-ref", "HEAD")

    # Dirty state: check if working tree has modifications or untracked files
    status = _run_git("status", "--porcelain")
    dirty = bool(status) if status is not None else None

    # Source-diff digest: SHA-256 of tracked diff + deterministic untracked
    # file paths and content hashes.
    diff = _run_git("diff", "HEAD")
    untracked_str = _run_git("ls-files", "--others", "--exclude-standard")
    untracked_files = sorted(
        [f for f in untracked_str.splitlines() if f] if untracked_str else []
    )

    hasher = hashlib.sha256()
    if diff is not None:
        hasher.update(b"--- diff ---\n")
        hasher.update(diff.encode("utf-8"))
    hasher.update(b"\n--- untracked ---\n")
    for f in untracked_files:
        hasher.update(f.encode("utf-8"))
        hasher.update(b"\n")
        fpath = repo_root / f
        if fpath.is_file():
            try:
                hasher.update(hashlib.sha256(fpath.read_bytes()).hexdigest().encode())
                hasher.update(b"\n")
            except OSError:
                hasher.update(b"<unreadable>\n")
    source_diff_digest = hasher.hexdigest()

    return GitProvenance(
        commit=commit,
        dirty=dirty,
        source_diff_digest=source_diff_digest,
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


class ManifestIntegrityError(Exception):
    """Raised when manifest inventory validation fails."""


def _before_artifact_leaf_open() -> None:
    """Test seam invoked after parent traversal and before artifact open."""


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
    ) -> None:
        self.run_dir = Path(run_dir).absolute()
        self.manifest = manifest
        self.check_orphans = check_orphans
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
            # --- 1. Role validity ---
            try:
                role = entry.role
            except (ValueError, TypeError):
                raise ManifestIntegrityError(
                    f"Invalid or unknown artifact role: {entry.role!r}"
                ) from None

            if self.manifest.manifest_version == LEGACY_MANIFEST_VERSION and role in {
                ArtifactRole.PLANNING_CHECKPOINT,
                ArtifactRole.COVERAGE_PLAN,
                ArtifactRole.FINALIZATION_INVENTORY,
                ArtifactRole.QUARANTINE_BUNDLE,
                ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
            }:
                raise ManifestIntegrityError(
                    f"Manifest v2 does not support v3-only role {role.value}"
                )

            # --- 2. Path validation ---
            entry_path = Path(entry.path)
            if entry_path.is_absolute():
                raise ManifestIntegrityError(f"Artifact path is absolute: {entry.path}")
            # Reject backslashes — PurePosixPath does not treat them as
            # separators, so they would silently survive canonicalisation.
            if "\\" in entry.path:
                raise ManifestIntegrityError(
                    f"Artifact path contains backslash: {entry.path}"
                )
            # Reject non-normalized paths: compare original string to
            # canonical PurePosixPath rendering so ./, //, and . fail.
            canonical = PurePosixPath(entry.path).as_posix()
            if canonical != entry.path:
                raise ManifestIntegrityError(
                    f"Artifact path is not canonical: '{entry.path}' "
                    f"(expected '{canonical}')"
                )
            # Reject dot and dot-dot path components.
            if ".." in entry_path.parts:
                raise ManifestIntegrityError(
                    f"Artifact path contains '..': {entry.path}"
                )
            if entry.path == "." or "." in entry_path.parts:
                raise ManifestIntegrityError(
                    f"Artifact path contains a dot component: {entry.path}"
                )
            # --- 3. No duplicate canonical paths ---
            if entry.path in seen_canonical:
                raise ManifestIntegrityError(
                    f"Duplicate artifact canonical path: {entry.path}"
                )
            seen_canonical.add(entry.path)

            # --- 4. Safe open and hash verification ---
            # Traverse from the run directory one component at a time. Each
            # parent and the leaf is opened without following symlinks, so
            # pathname replacement cannot redirect the verified read.
            # Read all content through a single fd so that
            # hash and YAML identity checks use the exact same bytes,
            # eliminating TOCTOU between separate reads.
            if not entry.sha256:
                raise ManifestIntegrityError(
                    f"Missing SHA-256 for artifact: {entry.path}"
                )
            if not _SHA256_RE.match(entry.sha256):
                raise ManifestIntegrityError(
                    f"Malformed SHA-256 for artifact {entry.path}: {entry.sha256}"
                )
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
            # Cache the verified bytes so read_text/read_bytes serve
            # exactly the bytes that were hash-validated.
            self._content_cache[entry.path] = content_bytes

            # --- 7. Role-extension-media-schema validation ---
            meta = _ROLE_METADATA.get(role)
            if meta is not None:
                expected_ext = meta["extension"]
                if not entry.path.endswith(expected_ext):
                    raise ManifestIntegrityError(
                        f"Role {role.value} expects extension {expected_ext}, "
                        f"got: {entry.path}"
                    )
                expected_media = meta["media_type"]
                if entry.media_type != expected_media:
                    raise ManifestIntegrityError(
                        f"Role {role.value} expects media_type "
                        f"'{expected_media}', got '{entry.media_type}' "
                        f"for {entry.path}"
                    )
                # Validate schema_version against supported versions
                supported_versions = meta.get("schema_versions", [])
                if not entry.schema_version:
                    raise ManifestIntegrityError(
                        f"Missing schema_version for artifact: {entry.path}"
                    )
                if (
                    supported_versions
                    and entry.schema_version not in supported_versions
                ):
                    raise ManifestIntegrityError(
                        f"Role {role.value} expects schema_version "
                        f"in {supported_versions}, got '{entry.schema_version}' "
                        f"for {entry.path}"
                    )
                # Validate singleton path matches exact expected path
                singleton_path = meta.get("singleton_path")
                if singleton_path is not None and entry.path != singleton_path:
                    raise ManifestIntegrityError(
                        f"Role {role.value} must be at '{singleton_path}', "
                        f"got: {entry.path}"
                    )
            else:
                if not entry.schema_version:
                    raise ManifestIntegrityError(
                        f"Missing schema_version for artifact: {entry.path}"
                    )

            # --- 7b. Scenario entries require scenario_id and candidate_id ---
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
            if role is ArtifactRole.QUARANTINE_BUNDLE:
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

            # --- 8. Singleton cardinality ---
            if role in SINGLETON_ROLES:
                singleton_counts[role] = singleton_counts.get(role, 0) + 1
                if singleton_counts[role] > 1:
                    raise ManifestIntegrityError(
                        f"Duplicate singleton role {role.value}: "
                        f"{singleton_counts[role]} entries"
                    )

            # --- 9. Scenario/candidate ID tracking ---
            # Track scenario IDs per role to allow YAML/feature pairs
            # with the same scenario_id while rejecting duplicates
            # within the same role.
            if entry.scenario_id:
                sid_key = (role, entry.scenario_id)
                if sid_key in scenario_ids:
                    raise ManifestIntegrityError(
                        f"Duplicate scenario_id for role {role.value}: "
                        f"{entry.scenario_id}"
                    )
                scenario_ids.add(sid_key)
                # Track scenario_id → candidate_id for post-loop duplicate
                # check.  Within one YAML+feature pair the candidate_id
                # is shared and valid; across different scenarios it must
                # be unique.
                if entry.candidate_id:
                    prev_cid = scenario_to_candidate.get(entry.scenario_id)
                    if prev_cid is not None and prev_cid != entry.candidate_id:
                        raise ManifestIntegrityError(
                            f"Conflicting candidate_id for scenario "
                            f"{entry.scenario_id}: {prev_cid} vs {entry.candidate_id}"
                        )
                    scenario_to_candidate[entry.scenario_id] = entry.candidate_id

            # --- 10. Scenario YAML/feature collection (pairing done post-loop) ---
            if role == ArtifactRole.SCENARIO_YAML:
                stem = Path(entry.path).stem
                yaml_stems.add(stem)
                # Require canonical path: scenarios/<scenario_id>.yaml
                expected_yaml_path = f"scenarios/{entry.scenario_id}.yaml"
                if entry.path != expected_yaml_path:
                    raise ManifestIntegrityError(
                        f"Scenario YAML must be at canonical path "
                        f"'{expected_yaml_path}', got '{entry.path}'"
                    )
                # Parse YAML from the same content_bytes read through the
                # safe O_NOFOLLOW fd — no separate read_text() that could
                # be TOCTOU-replaced.  Require serialized scenario_id AND
                # candidate_id.
                try:
                    data = yaml.safe_load(content_bytes.decode("utf-8"))
                    if isinstance(data, dict):
                        serialized_sid = data.get("scenario_id")
                        serialized_cid = data.get("candidate_id")
                        yaml_scenario_ids[stem] = {
                            "inventory": entry.scenario_id or "",
                            "serialized": serialized_sid,
                            "serialized_cid": serialized_cid,
                            "inventory_cid": entry.candidate_id or "",
                        }
                    else:
                        raise ManifestIntegrityError(
                            f"Scenario YAML {entry.path} is not a dict"
                        )
                except ManifestIntegrityError:
                    raise
                except Exception as exc:
                    raise ManifestIntegrityError(
                        f"Failed to read scenario YAML {entry.path}: {exc}"
                    ) from exc
                # Serialized scenario_id is required and must match inventory
                if not serialized_sid:
                    raise ManifestIntegrityError(
                        f"Scenario YAML {entry.path} missing serialized scenario_id"
                    )
                # Serialized candidate_id is required and must match inventory
                if not serialized_cid:
                    raise ManifestIntegrityError(
                        f"Scenario YAML {entry.path} missing serialized candidate_id"
                    )

            if role == ArtifactRole.SCENARIO_FEATURE:
                stem = Path(entry.path).stem
                feature_stems.add(stem)
                feature_scenario_ids_map[stem] = entry.scenario_id or ""
                # Require canonical path: scenarios/<scenario_id>.feature
                expected_feat_path = f"scenarios/{entry.scenario_id}.feature"
                if entry.path != expected_feat_path:
                    raise ManifestIntegrityError(
                        f"Scenario feature must be at canonical path "
                        f"'{expected_feat_path}', got '{entry.path}'"
                    )

            # Index by role
            self._by_role.setdefault(role, []).append(entry)
            self._validated_entries[entry.path] = entry

        # --- 11. Post-index global YAML/feature pairing and identity checks ---
        # Duplicate candidate_id across different scenarios (post-loop).
        cid_to_scenarios: dict[str, set[str]] = {}
        for sid, cid in scenario_to_candidate.items():
            cid_to_scenarios.setdefault(cid, set()).add(sid)
        for cid, sids in cid_to_scenarios.items():
            if len(sids) > 1:
                raise ManifestIntegrityError(
                    f"Duplicate candidate_id {cid} across different "
                    f"scenarios: {sorted(sids)}"
                )

        # Exact stem pairing — relaxed for non-completed manifests so
        # failed runs can retain partial evidence (YAML without feature
        # or vice versa) without being rejected.
        if requires_complete_inventory:
            yaml_only = yaml_stems - feature_stems
            feature_only = feature_stems - yaml_stems
            if yaml_only or feature_only:
                parts: list[str] = []
                if yaml_only:
                    parts.append(f"YAML without feature: {sorted(yaml_only)}")
                if feature_only:
                    parts.append(f"feature without YAML: {sorted(feature_only)}")
                raise ManifestIntegrityError(
                    f"Incomplete scenario YAML/feature pairs: {'; '.join(parts)}"
                )

        # Order-independent identity checks for each paired stem
        for stem in yaml_stems:
            yaml_info = yaml_scenario_ids.get(stem)
            if yaml_info is None:
                continue
            inv_sid = yaml_info.get("inventory") or ""
            ser_sid = yaml_info.get("serialized")
            ser_cid = yaml_info.get("serialized_cid")
            inv_cid = yaml_info.get("inventory_cid") or ""

            # Inventory scenario_id must be present
            if not inv_sid:
                raise ManifestIntegrityError(
                    f"Scenario YAML {stem}.yaml missing inventory scenario_id"
                )

            # Serialized scenario_id must match inventory scenario_id
            if ser_sid and inv_sid and ser_sid != inv_sid:
                raise ManifestIntegrityError(
                    f"Scenario ID mismatch for {stem}.yaml: "
                    f"inventory={inv_sid}, serialized={ser_sid}"
                )

            # Filename stem must match serialized scenario_id
            if ser_sid and ser_sid != stem:
                raise ManifestIntegrityError(
                    f"Filename stem '{stem}' does not match "
                    f"serialized scenario_id '{ser_sid}' in {stem}.yaml"
                )

            # Serialized candidate_id must match inventory candidate_id
            if ser_cid and inv_cid and ser_cid != inv_cid:
                raise ManifestIntegrityError(
                    f"Candidate ID mismatch for {stem}.yaml: "
                    f"inventory={inv_cid}, serialized={ser_cid}"
                )

            # Feature scenario_id must match paired YAML scenario_id
            feat_sid = feature_scenario_ids_map.get(stem, "")
            if feat_sid and inv_sid and feat_sid != inv_sid:
                raise ManifestIntegrityError(
                    f"Feature scenario_id mismatch for {stem}.feature: "
                    f"feature={feat_sid}, yaml={inv_sid}"
                )

        if self.manifest.manifest_version == MANIFEST_V3:
            legacy_authorities = {
                "attempts": self.manifest.attempts,
                "funnel": self.manifest.funnel,
                "stage_records": self.manifest.stage_records,
                "rule_verdicts": self.manifest.rule_verdicts,
                "artifacts": self.manifest.artifacts,
                "phantom_validation": self.manifest.phantom_validation,
                "structural_validation": self.manifest.structural_validation,
                "semantic_validation": self.manifest.semantic_validation,
                "leaf_technique_provenance": self.manifest.leaf_technique_provenance,
                "parsimony": self.manifest.parsimony,
                "scenarios_generated": self.manifest.scenarios_generated,
                "scenarios_failed": self.manifest.scenarios_failed,
            }
            populated = sorted(
                name for name, value in legacy_authorities.items() if value
            )
            if populated:
                raise ManifestIntegrityError(
                    "Manifest v3 lifecycle authority is finalization_inventory; "
                    f"legacy lifecycle fields must be empty: {populated}"
                )

        if self.manifest.manifest_version == MANIFEST_V3 and self.manifest.status in {
            RunStatus.COMPLETED,
            RunStatus.COMPLETED_WITH_WARNINGS,
            RunStatus.COMPLETED_WITH_ERRORS,
        }:
            for role in (
                ArtifactRole.PLANNING_CHECKPOINT,
                ArtifactRole.COVERAGE_PLAN,
                ArtifactRole.FINALIZATION_INVENTORY,
            ):
                if singleton_counts.get(role, 0) != 1:
                    raise ManifestIntegrityError(
                        f"Manifest v3 status {self.manifest.status.value} requires "
                        f"exactly one {role.value} artifact"
                    )

            # Keep v3-only policy out of current production v2 reads.
            from asago_scenario_generator.pipeline.persistence import (
                FinalizationInventoryV1,
                build_semantic_generation_summary,
                validate_v3_inventories,
            )

            validate_v3_inventories(self)
            if self.manifest.semantic_generation:
                finalization_entry = self.entry_by_role(
                    ArtifactRole.FINALIZATION_INVENTORY
                )
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

        # --- 12. Orphan detection ---
        if self.check_orphans:
            self._check_orphans(seen_canonical)

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

    def _open_artifact(self, relative_path: str) -> tuple[bytes, tuple[int, int]]:
        """Open a regular artifact by component-wise dirfd traversal."""
        opened_dirs: list[int] = []
        leaf_fd: int | None = None
        try:
            current_fd = (
                os.dup(self._validation_root_fd)
                if self._validation_root_fd is not None
                else os.open(self.run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            )
            opened_dirs.append(current_fd)
            parts = PurePosixPath(relative_path).parts
            for part in parts[:-1]:
                current_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
                opened_dirs.append(current_fd)
            _before_artifact_leaf_open()
            leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
            file_stat = os.fstat(leaf_fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ManifestIntegrityError(
                    f"Artifact is not a regular file: {relative_path}"
                )
            chunks: list[bytes] = []
            while chunk := os.read(leaf_fd, 65536):
                chunks.append(chunk)
            return b"".join(chunks), (file_stat.st_dev, file_stat.st_ino)
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


def _validate_v3_scorecard_binding(
    manifest: RunManifest, resolver: ManifestInventoryResolver
) -> None:
    """Validate any persisted final v3 scorecard at the resolver boundary."""
    entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
    if entry is None:
        return

    from asago_scenario_generator.eval.scorecard import ScorecardV1

    try:
        scorecard = ScorecardV1.model_validate(resolver.read_yaml(entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Scorecard violates strict v1 schema: {exc}"
        ) from exc
    if scorecard.run_id != manifest.run_id:
        raise ManifestIntegrityError(
            f"Scorecard run_id={scorecard.run_id!r} does not match "
            f"manifest run_id={manifest.run_id!r}"
        )

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
    if (
        manifest.status.requires_complete_inventory
        and scorecard.qualification.status.value != "pass"
    ):
        raise ManifestIntegrityError(
            "completed manifest requires passing scorecard qualification"
        )


def load_manifest(
    run_dir: Path, *, requested_version: str | None = None
) -> RunManifest:
    """Load and parse a manifest from a run directory.

    Does not validate inventory — use :func:`load_strict_resolver` for that.
    """
    run_dir = Path(run_dir)
    manifest_path = run_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise ManifestIntegrityError(f"No manifest found in run directory: {run_dir}")
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not data or not isinstance(data, dict):
        raise ManifestIntegrityError(f"Invalid manifest in {manifest_path}: not a dict")
    actual_version = str(data.get("manifest_version", ""))
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
    return RunManifest.model_validate(data)


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

    if require_final and not manifest.status.is_final:
        raise ManifestIntegrityError(
            f"Manifest status is not final: {manifest.status} in {run_dir}"
        )

    if require_authoritative and not manifest.status.is_authoritative:
        raise ManifestIntegrityError(
            f"Manifest is not authoritative (status={manifest.status}) in {run_dir}"
        )

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
        run_dirs = sorted(
            [d for d in path.iterdir() if d.is_dir() and is_run_dir(d)],
            key=lambda d: d.name,
        )
        if len(run_dirs) == 1:
            return run_dirs[0]
        if not run_dirs:
            raise ManifestIntegrityError(
                f"No run directory found in collection: {path}"
            )
        raise ManifestIntegrityError(
            f"Collection {path} contains {len(run_dirs)} runs; "
            f"pass a specific run directory to disambiguate. "
            f"Runs: {[d.name for d in run_dirs]}"
        )

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


def derive_funnel_from_attempts(
    attempts: list[AttemptRecord],
    *,
    expanded_instances: int = 0,
    unique_pre_rule_identities: int = 0,
    rule_rejected: int = 0,
    rule_transformed: int = 0,
    post_rule_collapsed: int = 0,
    filter_submitted: int = 0,
    filter_accepted: int = 0,
    selected: int = 0,
    qualified: int = 0,
    projection_rejected: int = 0,
    persisted_artifacts: int = 0,
    seeds_generated: int = 0,
) -> dict[str, Any]:
    """Derive a status-aware funnel lifecycle snapshot from accumulated attempts.

    Used before writing a failed manifest so that terminal equation
    validation can run even when the normal funnel construction was
    never reached.  The caller may pass zero for pre-attempt funnel
    stages that were not reached.

    ``selected`` and ``persisted_artifacts`` are derived from attempts
    when the caller does not supply nonzero values, so the returned dict
    is internally consistent with :class:`CandidateFunnel` equations.

    ``qualified`` and ``projection_rejected`` are preserved through
    failed-run reconstruction (cmps.4 blocker 5).
    """
    main_attempts = [a for a in attempts if a.phase == AttemptPhase.MAIN]
    rem_attempts = [a for a in attempts if a.phase == AttemptPhase.REMEDIATION]

    main_admitted = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.ADMITTED
    )
    main_quarantined = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.QUARANTINED
    )
    main_failed = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.FAILED
    )
    rem_admitted = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.ADMITTED
    )
    rem_quarantined = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.QUARANTINED
    )
    rem_failed = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.FAILED
    )

    total_admitted = main_admitted + rem_admitted
    total_quarantined = main_quarantined + rem_quarantined

    # Failed-run lifecycle counts must be reconstructed from actual reserved
    # attempts, never from the pre-generation plan.  In particular, a fatal
    # error after reserving the first of two planned candidates has selected
    # == main_attempted == 1, not the planned count of two.
    selected = len(main_attempts)
    # cmps.4 blocker 5: qualified must be >= selected.  When the caller
    # supplies an actual qualified value (> 0), preserve it — do NOT
    # default qualified=selected when actual context exists.  Only
    # derive from selected when the caller truly has no qualification
    # data (qualified == 0 AND projection_rejected == 0, meaning the
    # qualification stage was never reached).
    if qualified == 0 and selected > 0 and projection_rejected == 0:
        qualified = selected
    if selected > qualified:
        raise ManifestIntegrityError(
            f"failed funnel selected={selected} exceeds qualified={qualified}"
        )
    if persisted_artifacts == 0:
        persisted_artifacts = total_admitted + total_quarantined

    return {
        "expanded_instances": expanded_instances,
        "unique_pre_rule_identities": unique_pre_rule_identities,
        "rule_rejected": rule_rejected,
        "rule_transformed": rule_transformed,
        "post_rule_collapsed": post_rule_collapsed,
        "filter_submitted": filter_submitted,
        "filter_accepted": filter_accepted,
        "selected": selected,
        "qualified": qualified,
        "projection_rejected": projection_rejected,
        "main_attempted": len(main_attempts),
        "main_admitted": main_admitted + main_quarantined,
        "generation_failed": main_failed,
        "remediation_attempted": len(rem_attempts),
        "remediation_admitted": rem_admitted + rem_quarantined,
        "remediation_failed": rem_failed,
        "attempted": len(attempts),
        "admitted": total_admitted + total_quarantined,
        "quarantined": total_quarantined,
        "persisted_artifacts": persisted_artifacts,
        "seeds_generated": seeds_generated,
    }


def validate_attempt_equations(manifest: RunManifest) -> None:
    """Validate attempt keys, funnel equations, and disposition counts.

    Enforced for **every** final status (completed, completed_with_errors,
    failed), not only when attempts are nonempty.

    When attempts exist, the funnel must carry the relevant lifecycle keys.
    Uses :class:`AttemptPhase` to enforce phase-specific counts:
    ``main_attempted``/``main_admitted``/``generation_failed`` against MAIN
    records and ``remediation_attempted``/``remediation_admitted``/
    ``remediation_failed`` against REMEDIATION records, plus aggregate
    ``attempted``/``admitted``/``quarantined``.

    * Unique attempt keys (candidate_id, scenario_id)
    * ``funnel.attempted == len(attempts)``
    * ``funnel.admitted == admitted-disposition + quarantined-disposition``
      (quarantine is an admitted subset)
    * ``funnel.quarantined == quarantined-disposition``
    * main/remediation failed totals match failed records

    Early failures with zero attempts may omit candidate funnel fields,
    but must still have an internally valid zero-attempt lifecycle.

    Raises:
        ManifestIntegrityError: If any invariant is violated.
    """
    attempt_keys: set[tuple[str, str]] = set()
    for a in manifest.attempts:
        key = (a.candidate_id, a.scenario_id)
        if key in attempt_keys:
            raise ManifestIntegrityError(
                f"Duplicate attempt key: candidate={a.candidate_id}, "
                f"scenario={a.scenario_id}"
            )
        attempt_keys.add(key)

    # Recheck nonempty evidence for every FAILED/QUARANTINED record.
    # _finalize_attempt mutates in-place and may bypass the Pydantic
    # model validator; terminal validation must catch blank evidence.
    for a in manifest.attempts:
        if a.disposition in (AttemptDisposition.FAILED, AttemptDisposition.QUARANTINED):
            if not a.failure_evidence or not a.failure_evidence.strip():
                raise ManifestIntegrityError(
                    f"AttemptRecord (candidate={a.candidate_id}, "
                    f"scenario={a.scenario_id}) has disposition="
                    f"{a.disposition.value} but blank failure_evidence"
                )

    main_attempts = [a for a in manifest.attempts if a.phase == AttemptPhase.MAIN]
    rem_attempts = [a for a in manifest.attempts if a.phase == AttemptPhase.REMEDIATION]

    main_admitted = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.ADMITTED
    )
    main_quarantined = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.QUARANTINED
    )
    main_failed = sum(
        1 for a in main_attempts if a.disposition == AttemptDisposition.FAILED
    )
    rem_admitted = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.ADMITTED
    )
    rem_quarantined = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.QUARANTINED
    )
    rem_failed = sum(
        1 for a in rem_attempts if a.disposition == AttemptDisposition.FAILED
    )

    total_admitted = main_admitted + rem_admitted
    total_quarantined = main_quarantined + rem_quarantined
    total_failed = main_failed + rem_failed

    funnel = manifest.funnel
    if not manifest.attempts:
        # Zero-attempt lifecycle: a valid run may have nonzero pre-attempt
        # funnel stages (expanded_instances, unique_pre_rule_identities,
        # rule_rejected, etc.) but select zero candidates and have zero
        # generation attempts.  Only lifecycle fields must be zero.
        _zero_attempt_lifecycle_keys = (
            "selected",
            "main_attempted",
            "main_admitted",
            "generation_failed",
            "remediation_attempted",
            "remediation_admitted",
            "remediation_failed",
            "attempted",
            "admitted",
            "quarantined",
            "persisted_artifacts",
        )
        if funnel:
            for key in _zero_attempt_lifecycle_keys:
                if key in funnel and funnel[key] != 0:
                    raise ManifestIntegrityError(
                        f"Funnel {key}={funnel[key]} but zero attempts exist"
                    )
        return

    # When attempts exist, funnel must carry the relevant lifecycle keys.
    if not funnel:
        raise ManifestIntegrityError(
            "Manifest has attempts but no funnel lifecycle data"
        )

    required_keys = (
        "attempted",
        "admitted",
        "quarantined",
        "main_attempted",
        "main_admitted",
        "generation_failed",
        "remediation_attempted",
        "remediation_admitted",
        "remediation_failed",
    )
    missing_keys = [k for k in required_keys if k not in funnel]
    if missing_keys:
        raise ManifestIntegrityError(
            f"Funnel missing required lifecycle keys: {missing_keys}"
        )

    funnel_attempted = funnel["attempted"]
    funnel_admitted = funnel["admitted"]
    funnel_quarantined = funnel["quarantined"]

    # Aggregate equations
    if len(manifest.attempts) != funnel_attempted:
        raise ManifestIntegrityError(
            f"Funnel attempted mismatch: len(attempts)="
            f"{len(manifest.attempts)}, funnel={funnel_attempted}"
        )

    if total_admitted + total_quarantined != funnel_admitted:
        raise ManifestIntegrityError(
            f"Funnel admitted mismatch: attempts(admitted={total_admitted}"
            f"+quarantined={total_quarantined})={total_admitted + total_quarantined}, "
            f"funnel={funnel_admitted}"
        )

    if total_quarantined != funnel_quarantined:
        raise ManifestIntegrityError(
            f"Funnel quarantined mismatch: attempts={total_quarantined}, "
            f"funnel={funnel_quarantined}"
        )

    # Phase-specific equations
    funnel_main_attempted = funnel["main_attempted"]
    funnel_main_admitted = funnel["main_admitted"]
    funnel_gen_failed = funnel["generation_failed"]

    if len(main_attempts) != funnel_main_attempted:
        raise ManifestIntegrityError(
            f"Funnel main_attempted mismatch: "
            f"len(main_attempts)={len(main_attempts)}, "
            f"funnel={funnel_main_attempted}"
        )

    if main_admitted + main_quarantined != funnel_main_admitted:
        raise ManifestIntegrityError(
            f"Funnel main_admitted mismatch: "
            f"attempts(main_admitted={main_admitted}"
            f"+main_quarantined={main_quarantined})"
            f"={main_admitted + main_quarantined}, "
            f"funnel={funnel_main_admitted}"
        )

    if main_failed != funnel_gen_failed:
        raise ManifestIntegrityError(
            f"Funnel generation_failed mismatch: "
            f"attempts(main_failed={main_failed}), "
            f"funnel={funnel_gen_failed}"
        )

    funnel_rem_attempted = funnel["remediation_attempted"]
    funnel_rem_admitted = funnel["remediation_admitted"]
    funnel_rem_failed = funnel["remediation_failed"]

    if len(rem_attempts) != funnel_rem_attempted:
        raise ManifestIntegrityError(
            f"Funnel remediation_attempted mismatch: "
            f"len(rem_attempts)={len(rem_attempts)}, "
            f"funnel={funnel_rem_attempted}"
        )

    if rem_admitted + rem_quarantined != funnel_rem_admitted:
        raise ManifestIntegrityError(
            f"Funnel remediation_admitted mismatch: "
            f"attempts(rem_admitted={rem_admitted}"
            f"+rem_quarantined={rem_quarantined})"
            f"={rem_admitted + rem_quarantined}, "
            f"funnel={funnel_rem_admitted}"
        )

    if rem_failed != funnel_rem_failed:
        raise ManifestIntegrityError(
            f"Funnel remediation_failed mismatch: "
            f"attempts(rem_failed={rem_failed}), "
            f"funnel={funnel_rem_failed}"
        )

    # Total failed must equal generation_failed + remediation_failed
    if total_failed != funnel_gen_failed + funnel_rem_failed:
        raise ManifestIntegrityError(
            f"Funnel total failed mismatch: "
            f"attempts(failed={total_failed}), "
            f"funnel(generation_failed={funnel_gen_failed}"
            f"+remediation_failed={funnel_rem_failed})"
            f"={funnel_gen_failed + funnel_rem_failed}"
        )


def validate_completed_inventory(
    manifest: RunManifest,
    *,
    eval_enabled: bool,
    run_dir: Path | None = None,
) -> None:
    """Globally validate role cardinality, singleton requirements, funnel
    equations, attempt equations, and full inventory before atomically
    committing ``completed``.

    When *run_dir* is provided, also runs the full strict
    :class:`ManifestInventoryResolver` (including orphan checks) against
    the exact final manifest and run directory.

    Raises:
        ManifestIntegrityError: If any invariant is violated.
    """
    # --- Full strict resolver validation against the final manifest ---
    # Store the resolver for later use in scorecard verified-byte reads.
    _resolver: ManifestInventoryResolver | None = None
    if run_dir is not None:
        _resolver = ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    # Check required singleton roles
    required = required_singleton_roles(
        eval_enabled=eval_enabled, manifest_version=manifest.manifest_version
    )
    present_roles: set[ArtifactRole] = set()
    for entry in manifest.inventory:
        try:
            present_roles.add(entry.role)
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role in inventory: {entry.role!r}"
            ) from None

    missing = required - present_roles
    if missing:
        raise ManifestIntegrityError(
            f"Missing required singleton roles for completed status: "
            f"{sorted(r.value for r in missing)}"
        )

    # Check duplicate singleton roles
    role_counts: dict[ArtifactRole, int] = {}
    for entry in manifest.inventory:
        try:
            role = entry.role
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role: {entry.role!r}"
            ) from None
        if role in SINGLETON_ROLES:
            role_counts[role] = role_counts.get(role, 0) + 1
            if role_counts[role] > 1:
                raise ManifestIntegrityError(
                    f"Duplicate singleton role {role.value}: "
                    f"{role_counts[role]} entries"
                )

    # --- Scenario ID uniqueness: role-aware/pair-aware ---
    # YAML and feature entries for the same scenario legitimately share
    # the same scenario_id.  Duplicates within the same role are rejected.
    yaml_scenario_ids: set[str] = set()
    feature_scenario_ids: set[str] = set()
    for entry in manifest.inventory:
        if entry.role == ArtifactRole.SCENARIO_YAML:
            if entry.scenario_id:
                if entry.scenario_id in yaml_scenario_ids:
                    raise ManifestIntegrityError(
                        f"Duplicate scenario_id in YAML role: {entry.scenario_id}"
                    )
                yaml_scenario_ids.add(entry.scenario_id)
        elif entry.role == ArtifactRole.SCENARIO_FEATURE:
            if entry.scenario_id:
                if entry.scenario_id in feature_scenario_ids:
                    raise ManifestIntegrityError(
                        f"Duplicate scenario_id in feature role: {entry.scenario_id}"
                    )
                feature_scenario_ids.add(entry.scenario_id)

    # YAML and feature scenario ID sets must be identical (paired)
    if yaml_scenario_ids != feature_scenario_ids:
        yaml_only = yaml_scenario_ids - feature_scenario_ids
        feat_only = feature_scenario_ids - yaml_scenario_ids
        parts: list[str] = []
        if yaml_only:
            parts.append(f"YAML without feature: {sorted(yaml_only)}")
        if feat_only:
            parts.append(f"feature without YAML: {sorted(feat_only)}")
        raise ManifestIntegrityError(
            f"Scenario YAML/feature ID set mismatch: {'; '.join(parts)}"
        )

    # Manifest-v3's durable FinalizationInventory is the attempt authority.
    # Keep the generic role/pair/count checks here, but do not reconcile its
    # lifecycle against the legacy manifest.attempts projection.
    if manifest.manifest_version == MANIFEST_V3:
        admitted_attempt_keys: set[tuple[str, str]] = set()
        quarantined_attempt_keys: set[tuple[str, str]] = set()
    else:
        validate_attempt_equations(manifest)

    # --- Admitted/quarantined scenario inventory identities == attempts ---
    # Reconcile by exact (scenario_id, candidate_id), not scenario_id only.
    if manifest.manifest_version != MANIFEST_V3:
        admitted_attempt_keys = {
            (a.scenario_id, a.candidate_id)
            for a in manifest.attempts
            if a.disposition == AttemptDisposition.ADMITTED
        }
        quarantined_attempt_keys = {
            (a.scenario_id, a.candidate_id)
            for a in manifest.attempts
            if a.disposition == AttemptDisposition.QUARANTINED
        }
    # Build inventory scenario (scenario_id, candidate_id) sets
    yaml_inventory_keys: set[tuple[str, str]] = set()
    for entry in manifest.inventory:
        if (
            entry.role == ArtifactRole.SCENARIO_YAML
            and entry.scenario_id
            and entry.candidate_id
        ):
            yaml_inventory_keys.add((entry.scenario_id, entry.candidate_id))

    # Admitted (non-quarantined) inventory keys must equal admitted attempt keys
    inventory_non_quarantined_keys = yaml_inventory_keys - quarantined_attempt_keys
    if (
        manifest.manifest_version != MANIFEST_V3
        and inventory_non_quarantined_keys != admitted_attempt_keys
    ):
        raise ManifestIntegrityError(
            f"Admitted scenario identity mismatch: "
            f"inventory(non-quarantined)={sorted(inventory_non_quarantined_keys)}, "
            f"attempts(admitted)={sorted(admitted_attempt_keys)}"
        )
    # Quarantined inventory keys must equal quarantined attempt keys
    quarantined_in_inventory = yaml_inventory_keys & quarantined_attempt_keys
    if (
        manifest.manifest_version != MANIFEST_V3
        and quarantined_in_inventory != quarantined_attempt_keys
    ):
        raise ManifestIntegrityError(
            f"Quarantined scenario identity mismatch: "
            f"inventory(quarantined)={sorted(quarantined_in_inventory)}, "
            f"attempts(quarantined)={sorted(quarantined_attempt_keys)}"
        )

    # --- Scorecard counts validate against unique typed inventory ---
    if eval_enabled:
        yaml_count = sum(
            1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        feature_count = sum(
            1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_FEATURE
        )
        if yaml_count != feature_count:
            raise ManifestIntegrityError(
                f"Scenario YAML/feature count mismatch: "
                f"yaml={yaml_count}, feature={feature_count}"
            )
        # If a scorecard entry exists, require both scenario_count and
        # feature_file_count and exact inventory equality.  Use
        # resolver-verified bytes (via the resolver constructed above
        # when run_dir is provided).
        sc_entry = next(
            (e for e in manifest.inventory if e.role == ArtifactRole.EVAL_SCORECARD),
            None,
        )
        if sc_entry is not None and _resolver is not None:
            # Use the resolver's verified read instead of direct file I/O.
            # Reuse the resolver constructed at the top of this function
            # so we serve from its verified byte cache.
            try:
                sc_data = _resolver.read_yaml(sc_entry)
                if not isinstance(sc_data, dict):
                    raise ManifestIntegrityError("Scorecard root is not a dict")
                if manifest.manifest_version == MANIFEST_V3:
                    from asago_scenario_generator.eval.scorecard import ScorecardV1

                    try:
                        scorecard = ScorecardV1.model_validate(sc_data)
                    except Exception as exc:
                        raise ManifestIntegrityError(
                            f"Scorecard violates strict v1 schema: {exc}"
                        ) from exc
                    if scorecard.run_id != manifest.run_id:
                        raise ManifestIntegrityError(
                            f"Scorecard run_id={scorecard.run_id!r} does not match "
                            f"manifest run_id={manifest.run_id!r}"
                        )
                    if (
                        manifest.status.requires_complete_inventory
                        and scorecard.qualification.status.value != "pass"
                    ):
                        raise ManifestIntegrityError(
                            "completed manifest requires passing scorecard qualification"
                        )
                    sc_scenario_count = scorecard.scenario_count
                    sc_feature_count = scorecard.feature_file_count
                else:
                    eval_data = sc_data.get("evaluation")
                    if not isinstance(eval_data, dict):
                        raise ManifestIntegrityError(
                            "Scorecard 'evaluation' section is not a dict"
                        )
                    sc_scenario_count = eval_data.get("scenario_count")
                    sc_feature_count = eval_data.get("feature_file_count")
                # Require both counts
                if sc_scenario_count is None:
                    raise ManifestIntegrityError("Scorecard missing scenario_count")
                if sc_feature_count is None:
                    raise ManifestIntegrityError("Scorecard missing feature_file_count")
                if sc_scenario_count != yaml_count:
                    raise ManifestIntegrityError(
                        f"Scorecard scenario_count={sc_scenario_count} "
                        f"!= inventory YAML count={yaml_count}"
                    )
                if sc_feature_count != feature_count:
                    raise ManifestIntegrityError(
                        f"Scorecard feature_file_count={sc_feature_count} "
                        f"!= inventory feature count={feature_count}"
                    )
            except ManifestIntegrityError:
                raise
            except Exception as exc:
                raise ManifestIntegrityError(
                    f"Failed to read scorecard for count validation: {exc}"
                ) from exc
