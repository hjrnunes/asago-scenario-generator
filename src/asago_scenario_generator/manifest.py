"""Versioned run manifest, artifact inventory, and atomic artifact writes.

This module is the single ownership boundary for:

* Typed artifact inventory with SHA-256 verification and global integrity
* Strict manifest inventory resolver shared by eval and report readers
* Atomic text writes for persisted artifacts
"""

# This module re-exports the split implementation as the compatibility façade
# for the long-standing ``asago_scenario_generator.manifest`` API.
# ruff: noqa: F401

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from asago_scenario_generator.manifest_errors import ManifestIntegrityError
from asago_scenario_generator.manifest_models import (
    MANIFEST_FILENAME,
    ArtifactEntry,
    ArtifactRole,
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    ModelConfig,
    RunManifest,
    RunStatus,
    SINGLETON_ROLES,
    _SHA256_RE,
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
