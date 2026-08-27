"""Safe filesystem persistence and artifact loading operations."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    atomic_write_text,
    build_artifact_entry,
)
from .persistence_common import (
    COVERAGE_PLAN_VERSION,
    FINALIZATION_INVENTORY_VERSION,
    QUARANTINE_BUNDLE_VERSION,
    canonical_json_bytes,
)
from .persistence_journal import (
    AdmittedArtifactPublication,
    FinalizationInventoryV1,
    PersistenceJournalV1,
    QuarantineBundleV1,
)
from .persistence_plan import CoveragePlanV2, StrictModel
from .persistence_journal import _publication_receipts


def _write_model(run_dir: Path, rel_path: str, model: BaseModel) -> Path:
    # Revalidate after any adapter-side list mutation so an invalid in-memory
    # object can never replace the last valid on-disk document.
    model = type(model).model_validate(model.model_dump(mode="python"))
    content = canonical_json_bytes(model)
    return atomic_write_text(run_dir / rel_path, content.decode("utf-8"))


def _canonical_path_mismatch(rel_path: str, path: PurePosixPath) -> bool:
    return path.is_absolute() or path.as_posix() != rel_path or "\\" in rel_path


def _unsafe_path_parts(parts: tuple[str, ...]) -> bool:
    return any(part in {"", ".", ".."} for part in parts)


def _canonical_parts(rel_path: str) -> tuple[str, ...]:
    path = PurePosixPath(rel_path)
    if (
        not rel_path
        or _canonical_path_mismatch(rel_path, path)
        or _unsafe_path_parts(path.parts)
    ):
        raise ManifestIntegrityError(f"Persistence path is not canonical: {rel_path}")
    return path.parts


def _open_parent(
    run_dir: Path, rel_path: str, *, create: bool = False
) -> tuple[int, str]:
    parts = _canonical_parts(rel_path)
    fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, dir_fd=fd)
                os.fsync(fd)
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def _safe_read(run_dir: Path, rel_path: str) -> bytes:
    data = b""
    try:
        parent_fd, name = _open_parent(run_dir, rel_path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ManifestIntegrityError(
                        f"Persistence artifact is not a file: {rel_path}"
                    )
                while chunk := os.read(fd, 65536):
                    data += chunk
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise ManifestIntegrityError(
            f"Cannot safely read {run_dir / rel_path}: {exc}"
        ) from exc
    return data


def _exclusive_create(run_dir: Path, rel_path: str, content: bytes) -> None:
    parent_fd, name = _open_parent(run_dir, rel_path, create=True)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _safe_read(run_dir, rel_path) != content:
                raise ManifestIntegrityError(
                    f"Immutable evidence collision at {name}"
                ) from None
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def write_coverage_plan(run_dir: Path, plan: CoveragePlanV2) -> ArtifactEntry:
    _write_model(run_dir, "coverage-plan.json", plan)
    return build_artifact_entry(
        ArtifactRole.COVERAGE_PLAN,
        run_dir,
        "coverage-plan.json",
        schema_version=COVERAGE_PLAN_VERSION,
    )


def read_coverage_plan(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> CoveragePlanV2:
    return _read_model(
        run_dir, entry, ArtifactRole.COVERAGE_PLAN, "coverage-plan.json", CoveragePlanV2
    )


def write_finalization_inventory(
    run_dir: Path, inventory: FinalizationInventoryV1
) -> ArtifactEntry:
    _write_model(run_dir, "finalization-inventory.json", inventory)
    return build_artifact_entry(
        ArtifactRole.FINALIZATION_INVENTORY,
        run_dir,
        "finalization-inventory.json",
        schema_version=FINALIZATION_INVENTORY_VERSION,
    )


def read_finalization_inventory(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> FinalizationInventoryV1:
    return _read_model(
        run_dir,
        entry,
        ArtifactRole.FINALIZATION_INVENTORY,
        "finalization-inventory.json",
        FinalizationInventoryV1,
    )


def write_quarantine_bundle(run_dir: Path, bundle: QuarantineBundleV1) -> ArtifactEntry:
    rel_path = f"quarantine/{bundle.attempt_id}.json"
    bundle = QuarantineBundleV1.model_validate(bundle.model_dump(mode="python"))
    _exclusive_create(run_dir, rel_path, canonical_json_bytes(bundle))
    return build_artifact_entry(
        ArtifactRole.QUARANTINE_BUNDLE,
        run_dir,
        rel_path,
        schema_version=QUARANTINE_BUNDLE_VERSION,
        candidate_id=bundle.candidate_id,
    )


def _quarantine_path_valid(entry: ArtifactEntry) -> bool:
    expected = PurePosixPath(entry.path)
    return not (
        expected.as_posix() != entry.path
        or ".." in expected.parts
        or len(expected.parts) != 2
        or expected.parts[0] != "quarantine"
    )


def read_quarantine_bundle(run_dir: Path, entry: ArtifactEntry) -> QuarantineBundleV1:
    if not _quarantine_path_valid(entry):
        raise ManifestIntegrityError(f"Invalid quarantine bundle path: {entry.path}")
    return _read_model(
        run_dir, entry, ArtifactRole.QUARANTINE_BUNDLE, entry.path, QuarantineBundleV1
    )


def _read_journal(run_dir: Path) -> PersistenceJournalV1 | None:
    journal_path = run_dir / ".finalization-state.json"
    if not journal_path.exists():
        return None
    try:
        journal = PersistenceJournalV1.model_validate_json(
            _safe_read(run_dir, journal_path.name)
        )
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid finalization state journal: {exc}"
        ) from exc

    return journal


def _publish_journal(run_dir: Path, journal: PersistenceJournalV1) -> CoveragePlanV2:
    """Complete one already-validated synchronized state replacement."""

    journal_path = run_dir / ".finalization-state.json"
    if journal.quarantine_bundle is not None:
        write_quarantine_bundle(run_dir, journal.quarantine_bundle)
    if journal.admitted_publication is not None:
        _write_admitted_publication(run_dir, journal.admitted_publication)
    write_finalization_inventory(run_dir, journal.finalization_inventory)
    write_coverage_plan(run_dir, journal.coverage_plan)
    journal_path.unlink()
    dir_fd = os.open(run_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return journal.coverage_plan


def recover_finalization_journal(
    run_dir: Path, *, expected_run_id: str
) -> CoveragePlanV2 | None:
    """Complete an interrupted v3 state publication before forensic loading."""
    run_dir = Path(run_dir)
    journal = _read_journal(run_dir)
    if journal is None:
        return None
    if journal.finalization_inventory.run_id != expected_run_id:
        raise ManifestIntegrityError(
            "finalization state journal run_id does not match resumed run"
        )
    return _publish_journal(run_dir, journal)


def _verified_expected_entry(
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
) -> None:
    if entry is not None:
        if entry.role is not role or entry.path != expected_path:
            raise ManifestIntegrityError(
                f"{role.value} role/path mismatch: {entry.role.value} {entry.path}"
            )


def _read_verified_content(
    run_dir: Path, entry: ArtifactEntry | None, expected_path: str
) -> bytes:
    if entry is None:
        return _safe_read(run_dir, expected_path)
    content = _safe_read(run_dir, expected_path)
    if hashlib.sha256(content).hexdigest() != entry.sha256:
        raise ManifestIntegrityError(f"Hash mismatch for {entry.path}")
    return content


def _read_model(
    run_dir: Path,
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
    model_type: type[StrictModel],
) -> Any:
    _verified_expected_entry(entry, role, expected_path)
    try:
        return model_type.model_validate_json(
            _read_verified_content(run_dir, entry, expected_path)
        )
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid {role.value}: {exc}") from exc


def _write_admitted_publication(
    run_dir: Path, publication: AdmittedArtifactPublication
) -> None:
    for receipt, content in zip(
        _publication_receipts(publication),
        (publication.yaml_text, publication.feature_text),
        strict=True,
    ):
        _exclusive_create(run_dir, receipt.path, content.encode("utf-8"))
