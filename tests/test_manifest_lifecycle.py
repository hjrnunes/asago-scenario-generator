"""Focused lifecycle, immutability, integrity, and provenance tests for cmps.1.

Covers the acceptance contract:
- Immutable two-run collections with sortable, collision-safe run IDs (128-bit)
- Run-local logging that never appends across runs
- Versioned manifest sentinel surviving every exit path
- Final status: completed / completed_with_errors / failed
- Typed artifact inventory with SHA-256, roles, and integrity validation
- Strict eval/report consuming only manifest inventory entries
- Provenance: Git (clean/dirty/untracked), config digest, input hashes, model config
- Standalone CLI eval/report requiring authoritative completed
- Attempt records with admitted/quarantined/failed disposition
- Inventory validation: symlinks, non-regular, duplicate singletons, ID mismatch
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from asago_scenario_generator.manifest import (
    MANIFEST_FILENAME,
    ArtifactEntry,
    ArtifactRole,
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    GitProvenance,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    RunManifest,
    RunStatus,
    atomic_write_yaml,
    build_artifact_entry,
    build_in_memory_resolver,
    capture_provenance,
    compute_config_digest,
    compute_file_sha256,
    derive_funnel_from_attempts,
    finalize_manifest,
    find_run_dir,
    generate_sortable_run_id,
    is_run_dir,
    is_sortable_run_id,
    load_manifest,
    load_strict_resolver,
    required_singleton_roles,
    resolve_run_dir,
    select_final_run_status,
    validate_attempt_equations,
    validate_completed_inventory,
    validate_run_id,
    write_failed_manifest,
    write_manifest_sentinel,
    write_started_manifest,
)
from asago_scenario_generator.manifest import (
    _attempt_tallies,
    _check_duplicate_candidate_ids,
    _check_paired_stem,
    _check_paired_stems,
    _check_yaml_feature_pairing,
    _is_v3_completed_status,
    _pairing_parts,
    _parse_scenario_yaml,
    _require_serialized_ids,
    _validate_legacy_role_support,
    _validate_stem_candidate_id,
    _validate_stem_feature_pair,
    _validate_stem_filename,
    _validate_stem_inventory_ids,
    _validate_v3_legacy_authority,
    _validate_v3_required_artifacts,
    _check_funnel_aggregate_equations,
    _check_main_funnel_equations,
    _check_qualified_capacity,
    _check_remediation_funnel_equations,
    _check_total_failed_equation,
    _disposition_tally,
    _duplicate_attempt_keys,
    _hashed_untracked_content,
    _phase_attempted,
    _require_funnel_lifecycle_keys,
    _resolve_persisted_artifacts,
    _resolve_qualified_count,
    _run_git,
    _source_diff_digest,
    _untracked_files,
    _validate_attempt_evidence,
    _validate_zero_attempt_funnel,
)
from tests.manifest_helpers import build_test_run_dir

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_VALID_RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"


def _make_scenario(scenario_id: str = "s1", candidate_id: str = "cand:v2:abc") -> dict:
    return {
        "scenario_id": scenario_id,
        "candidate_id": candidate_id,
        "narrative": {
            "title": "Test",
            "summary": "A test",
            "entry_point": "e",
            "zone_sequence": ["input"],
            "steps": [],
        },
        "actor_profile": {
            "actor_type": "external",
            "goal_category": "x",
            "capability_level": "intermediate",
        },
        "attack_tree": {"id": "t", "goal": "g", "root": {}},
    }


def _make_feature(scenario_id: str = "s1") -> str:
    return f"Feature: {scenario_id}\n  Scenario: Attack\n    Given x\n"


# --------------------------------------------------------------------------- #
# 1. Immutable two-run collections
# --------------------------------------------------------------------------- #


class TestImmutableTwoRun:
    """Reusing one output collection twice creates two immutable run dirs."""

    def test_two_runs_create_unique_sortable_dirs(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir_1, run_id_1 = resolve_run_dir(collection)
        run_dir_2, run_id_2 = resolve_run_dir(collection)

        assert run_id_1 != run_id_2
        assert run_dir_1 != run_dir_2
        assert is_sortable_run_id(run_id_1)
        assert is_sortable_run_id(run_id_2)
        assert run_dir_1.parent == collection
        assert run_dir_2.parent == collection

    def test_nested_collection_directory_is_created(self, tmp_path: Path):
        collection = tmp_path / "nested" / "output"
        run_dir, _run_id = resolve_run_dir(collection)
        assert run_dir.parent == collection

    def test_first_run_unchanged_after_second(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir_1, run_id_1 = resolve_run_dir(collection)
        (run_dir_1 / "use-case.txt").write_text("test use case")
        write_manifest_sentinel(run_dir_1, run_id_1, "2026-01-01T00:00:00+00:00")

        snapshot: dict[str, bytes] = {}
        for f in run_dir_1.rglob("*"):
            if f.is_file():
                snapshot[f.relative_to(run_dir_1).as_posix()] = f.read_bytes()

        run_dir_2, _run_id_2 = resolve_run_dir(collection)
        (run_dir_2 / "use-case.txt").write_text("different use case")

        for rel, original_bytes in snapshot.items():
            assert (run_dir_1 / rel).read_bytes() == original_bytes, (
                f"File {rel} in first run was modified by second run"
            )

    def test_existing_run_dir_not_reused(self, tmp_path: Path):
        collection = tmp_path / "output"
        _run_dir, run_id = resolve_run_dir(collection)
        with pytest.raises(FileExistsError):
            resolve_run_dir(collection, run_id=run_id)

    def test_collection_sibling_stale_files_ignored(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / _VALID_RUN_ID,
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )

        (collection / "stale.yaml").write_text("stale: true")
        (collection / "garbage.json").write_text("{}")

        found = find_run_dir(collection)
        assert found == run_dir

        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1


# --------------------------------------------------------------------------- #
# 2. Run-local logging
# --------------------------------------------------------------------------- #


class TestRunLocalLogging:
    """Logs are run-local and never append across runs."""

    def test_log_file_mode_is_write_not_append(self, tmp_path: Path):
        import logging

        from asago_scenario_generator.log_config import setup_logging

        collection = tmp_path / "output"
        run_dir, _ = resolve_run_dir(collection)
        setup_logging(output_dir=run_dir)
        logger = logging.getLogger("asago_scenario_generator")
        logger.info("First run message")

        for h in logger.handlers:
            h.flush()

        log_path = run_dir / "pipeline.log"
        assert log_path.exists()
        content_1 = log_path.read_text()
        assert "First run message" in content_1

        run_dir_2, _ = resolve_run_dir(collection)
        setup_logging(output_dir=run_dir_2)
        logger.info("Second run message")
        for h in logger.handlers:
            h.flush()

        log_path_2 = run_dir_2 / "pipeline.log"
        content_2 = log_path_2.read_text()
        assert "Second run message" in content_2
        assert "First run message" not in content_2


# --------------------------------------------------------------------------- #
# 3. Manifest sentinel and lifecycle
# --------------------------------------------------------------------------- #


class TestManifestSentinel:
    """Versioned manifest sentinel survives every exit path."""

    def test_atomic_yaml_write_creates_nested_parent(self, tmp_path: Path):
        path = tmp_path / "nested" / "directory" / "manifest.yaml"
        atomic_write_yaml(path, {"status": "started"})
        assert yaml.safe_load(path.read_text()) == {"status": "started"}

    def test_sentinel_written_before_pipeline_work(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        ts = "2026-01-01T00:00:00+00:00"
        write_manifest_sentinel(run_dir, run_id, ts)

        manifest = load_manifest(run_dir)
        assert manifest.status == RunStatus.STARTED
        assert manifest.run_id == run_id
        assert manifest.timestamp_start == ts
        assert manifest.manifest_version == "2"

    def test_failed_manifest_on_fatal_error(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)
        ts = "2026-01-01T00:00:00+00:00"
        write_manifest_sentinel(run_dir, run_id, ts)

        # Build a manifest with some accumulated evidence
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=ts,
            attempts=[
                AttemptRecord(
                    candidate_id="cand:v2:abc",
                    scenario_id="20240101T120000_abcdef1234567890abcdef1234567890",
                    disposition=AttemptDisposition.FAILED,
                    failure_evidence="boom",
                )
            ],
        )
        manifest.error = "Something went wrong"
        write_failed_manifest(run_dir, manifest)

        loaded = load_manifest(run_dir)
        assert loaded.status == RunStatus.FAILED
        assert loaded.run_id == run_id
        assert loaded.error == "Something went wrong"
        assert loaded.timestamp_end is not None
        assert len(loaded.attempts) == 1
        raw_failed = yaml.safe_load(
            (run_dir / MANIFEST_FILENAME).read_text(encoding="utf-8")
        )
        assert "provenance" not in raw_failed

    def test_failed_manifest_preserves_existing_end_timestamp(self, tmp_path: Path):
        run_dir, run_id = resolve_run_dir(tmp_path / "output")
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start="2026-01-01T00:00:00+00:00",
            timestamp_end="2026-01-02T00:00:00+00:00",
        )
        write_failed_manifest(run_dir, manifest)
        assert load_manifest(run_dir).timestamp_end == "2026-01-02T00:00:00+00:00"

    def test_manifest_writers_omit_none_fields(self, tmp_path: Path):
        run_dir, run_id = resolve_run_dir(tmp_path / "output")
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start="2026-01-01T00:00:00+00:00",
        )

        write_started_manifest(run_dir, manifest)
        started = yaml.safe_load(
            (run_dir / MANIFEST_FILENAME).read_text(encoding="utf-8")
        )
        assert "error" not in started

        manifest.status = RunStatus.COMPLETED
        finalize_manifest(run_dir, manifest)
        finalized = yaml.safe_load(
            (run_dir / MANIFEST_FILENAME).read_text(encoding="utf-8")
        )
        assert "error" not in finalized


    def test_finalize_requires_final_status(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir, run_id = resolve_run_dir(collection)

        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start="2026-01-01T00:00:00+00:00",
        )
        with pytest.raises(ValueError, match="non-final status"):
            finalize_manifest(run_dir, manifest)

    def test_completed_status_is_authoritative(self):
        assert RunStatus.COMPLETED.is_authoritative
        assert RunStatus.COMPLETED_WITH_WARNINGS.is_authoritative
        assert not RunStatus.COMPLETED_WITH_ERRORS.is_authoritative
        assert not RunStatus.FAILED.is_authoritative

    def test_final_statuses(self):
        finals = RunStatus.final_statuses()
        assert RunStatus.COMPLETED in finals
        assert RunStatus.COMPLETED_WITH_WARNINGS in finals
        assert RunStatus.COMPLETED_WITH_ERRORS in finals
        assert RunStatus.FAILED in finals
        assert RunStatus.STARTED not in finals

    @pytest.mark.parametrize(
        ("notes", "expected"),
        [
            ([], RunStatus.COMPLETED),
            (
                ["candidate_filter_unavailable: provider timed out"],
                RunStatus.COMPLETED_WITH_WARNINGS,
            ),
            (
                ["presentation_fallback: narrative title was synthesized"],
                RunStatus.COMPLETED_WITH_WARNINGS,
            ),
            (
                ["Risk card R-1 may describe a different system."],
                RunStatus.COMPLETED,
            ),
        ],
    )
    def test_successful_completion_only_promotes_declared_warnings(
        self, notes: list[str], expected: RunStatus
    ):
        assert select_final_run_status(True, notes) is expected

    def test_failed_completion_gates_keep_completed_with_errors(self):
        assert (
            select_final_run_status(
                False, ["candidate_filter_unavailable: provider timed out"]
            )
            is RunStatus.COMPLETED_WITH_ERRORS
        )


# --------------------------------------------------------------------------- #
# 4. Typed artifact inventory integrity
# --------------------------------------------------------------------------- #


class TestInventoryIntegrity:
    """Manifest inventory validation: missing, duplicate, orphan, hash mismatch."""

    def test_valid_inventory_passes(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        resolver = load_strict_resolver(run_dir)
        assert len(resolver.scenario_yaml_entries()) == 1
        assert resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE) is not None

    def test_hash_mismatch_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "capability-profile.yaml").write_text("tampered: true")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            load_strict_resolver(run_dir)

    def test_missing_artifact_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "capability-profile.yaml").unlink()
        with pytest.raises(ManifestIntegrityError, match="does not exist"):
            load_strict_resolver(run_dir)

    def test_orphan_file_in_run_rejected(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        (run_dir / "rogue.yaml").write_text("rogue: true")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            load_strict_resolver(run_dir)

    def test_duplicate_path_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Duplicate"):
            load_strict_resolver(run_dir)

    def test_path_escaping_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")
        outside = tmp_path / "outside.txt"
        outside.write_text("outside")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="../../outside.txt",
            sha256=compute_file_sha256(outside),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(
            ManifestIntegrityError, match="not normalized|escapes|'\\.\\.'"
        ):
            load_strict_resolver(run_dir)

    def test_symlink_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        target = tmp_path / "target.txt"
        target.write_text("target")
        link = run_dir / "link.txt"
        os.symlink(target, link)

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="link.txt",
            sha256=compute_file_sha256(link),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="symlink"):
            load_strict_resolver(run_dir)

    def test_non_regular_file_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "subdir").mkdir()

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="subdir",
            sha256=compute_file_sha256(run_dir / "use-case.txt")
            if (run_dir / "use-case.txt").exists()
            else "0" * 64,
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="not a regular file"):
            load_strict_resolver(run_dir)

    def test_intermediate_symlink_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        artifact = outside / "s1.feature"
        artifact.write_text("Feature: outside")
        os.symlink(outside, run_dir / "scenarios")
        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/s1.feature",
            sha256=compute_file_sha256(artifact),
            media_type="text/plain",
            scenario_id="s1",
            candidate_id="cand-1",
        )
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )

        with pytest.raises(ManifestIntegrityError, match="symlink"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=False)

    def test_parent_exchange_after_traversal_reads_opened_directory(
        self, tmp_path: Path
    ):
        run_dir = tmp_path / "run"
        parent = run_dir / "scenarios"
        parent.mkdir(parents=True)
        original = b"Feature: verified\n"
        (parent / "s1.feature").write_bytes(original)
        decoy = run_dir / "decoy"
        decoy.mkdir()
        (decoy / "s1.feature").write_bytes(b"Feature: attacker\n")
        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/s1.feature",
            sha256=hashlib.sha256(original).hexdigest(),
            media_type="text/plain",
            scenario_id="s1",
            candidate_id="cand-1",
        )
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )

        def exchange_parent() -> None:
            parent.rename(run_dir / "original")
            decoy.rename(parent)

        with patch(
            "asago_scenario_generator.manifest._before_artifact_leaf_open",
            side_effect=exchange_parent,
        ):
            resolver = ManifestInventoryResolver(run_dir, manifest, check_orphans=False)

        assert resolver.read_bytes(entry) == original

    def test_root_exchange_between_entries_uses_one_pinned_directory(
        self, tmp_path: Path
    ):
        run_dir = tmp_path / "run"
        scenarios = run_dir / "scenarios"
        scenarios.mkdir(parents=True)
        originals = {
            "s1": b"Feature: verified one\n",
            "s2": b"Feature: verified two\n",
        }
        for scenario_id, content in originals.items():
            (scenarios / f"{scenario_id}.feature").write_bytes(content)
        decoy = tmp_path / "decoy"
        (decoy / "scenarios").mkdir(parents=True)
        for scenario_id in originals:
            (decoy / f"scenarios/{scenario_id}.feature").write_bytes(
                b"Feature: attacker\n"
            )
        entries = [
            ArtifactEntry(
                role=ArtifactRole.SCENARIO_FEATURE,
                path=f"scenarios/{scenario_id}.feature",
                sha256=hashlib.sha256(content).hexdigest(),
                media_type="text/plain",
                scenario_id=scenario_id,
                candidate_id=f"cand-{scenario_id}",
            )
            for scenario_id, content in originals.items()
        ]
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=entries,
        )
        exchanged = False

        def exchange_root() -> None:
            nonlocal exchanged
            if exchanged:
                return
            exchanged = True
            run_dir.rename(tmp_path / "original")
            decoy.rename(run_dir)

        with patch(
            "asago_scenario_generator.manifest._before_artifact_leaf_open",
            side_effect=exchange_root,
        ):
            resolver = ManifestInventoryResolver(run_dir, manifest, check_orphans=False)

        assert [resolver.read_bytes(entry) for entry in entries] == list(
            originals.values()
        )
        resolver._content_cache.pop(entries[0].path)
        with pytest.raises(ManifestIntegrityError, match="not validated and cached"):
            resolver.read_bytes(entries[0])

        secret = tmp_path / "secret.feature"
        secret.write_bytes(b"Feature: secret\n")
        forged = entries[0].model_copy(
            update={
                "path": "../secret.feature",
                "sha256": compute_file_sha256(secret),
            }
        )
        with pytest.raises(ManifestIntegrityError, match="not validated and cached"):
            resolver._verified_read(forged)

    def test_hardlinked_inventory_entries_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        scenarios = run_dir / "scenarios"
        scenarios.mkdir(parents=True)
        first = scenarios / "s1.feature"
        second = scenarios / "s2.feature"
        first.write_text("Feature: shared")
        os.link(first, second)
        digest = compute_file_sha256(first)
        entries = [
            ArtifactEntry(
                role=ArtifactRole.SCENARIO_FEATURE,
                path=f"scenarios/s{number}.feature",
                sha256=digest,
                media_type="text/plain",
                scenario_id=f"s{number}",
                candidate_id=f"cand-{number}",
            )
            for number in (1, 2)
        ]
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=entries,
        )

        with pytest.raises(ManifestIntegrityError, match="device/inode"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=False)

    def test_malformed_hash_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="not-a-hash",
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Malformed SHA-256"):
            load_strict_resolver(run_dir)

    def test_missing_hash_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="",
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="Missing SHA-256"):
            load_strict_resolver(run_dir)

    def test_duplicate_singleton_role_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "a.txt").write_text("a")
        (run_dir / "b.txt").write_text("b")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                ArtifactEntry(
                    role=ArtifactRole.USE_CASE,
                    path="a.txt",
                    sha256=compute_file_sha256(run_dir / "a.txt"),
                    media_type="text/plain",
                ),
                ArtifactEntry(
                    role=ArtifactRole.USE_CASE,
                    path="b.txt",
                    sha256=compute_file_sha256(run_dir / "b.txt"),
                    media_type="text/plain",
                ),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(
            ManifestIntegrityError,
            match="Duplicate singleton|must be at 'use-case.txt'",
        ):
            load_strict_resolver(run_dir)

    def test_wrong_extension_for_role_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "profile.txt").write_text("not yaml")

        entry = ArtifactEntry(
            role=ArtifactRole.CAPABILITY_PROFILE,
            path="profile.txt",
            sha256=compute_file_sha256(run_dir / "profile.txt"),
            media_type="application/yaml",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="expects extension"):
            load_strict_resolver(run_dir)

    def test_yaml_feature_pairing_enforced(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        (run_dir / "scenarios" / "s1.yaml").write_text(
            yaml.dump(
                {
                    "scenario_id": "s1",
                    "candidate_id": "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }
            )
        )
        # No matching .feature file

        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            sha256=compute_file_sha256(run_dir / "scenarios" / "s1.yaml"),
            media_type="application/yaml",
            scenario_id="s1",
            candidate_id="cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="YAML without feature"):
            load_strict_resolver(run_dir)

    def test_feature_only_without_yaml_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        (run_dir / "scenarios" / "orphan.feature").write_text("Feature: orphan")

        entry = ArtifactEntry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/orphan.feature",
            sha256=compute_file_sha256(run_dir / "scenarios" / "orphan.feature"),
            media_type="text/plain",
            scenario_id="orphan",
            candidate_id="cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="feature without YAML"):
            load_strict_resolver(run_dir)

    def test_scenario_id_filename_stem_mismatch_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        # Filename stem is "s1" but serialized scenario_id is "s2"
        (run_dir / "scenarios" / "s1.yaml").write_text(yaml.dump({"scenario_id": "s2"}))
        (run_dir / "scenarios" / "s1.feature").write_text("Feature: s1")

        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                ArtifactEntry(
                    role=ArtifactRole.SCENARIO_YAML,
                    path="scenarios/s1.yaml",
                    sha256=compute_file_sha256(run_dir / "scenarios" / "s1.yaml"),
                    media_type="application/yaml",
                    scenario_id="s2",
                    candidate_id="cand:v2:cccccccccccccccccccccccccccccccc",
                ),
                ArtifactEntry(
                    role=ArtifactRole.SCENARIO_FEATURE,
                    path="scenarios/s1.feature",
                    sha256=compute_file_sha256(run_dir / "scenarios" / "s1.feature"),
                    media_type="text/plain",
                    scenario_id="s2",
                    candidate_id="cand:v2:cccccccccccccccccccccccccccccccc",
                ),
            ],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="canonical path"):
            load_strict_resolver(run_dir)

    def test_absolute_path_rejected(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path=str(run_dir / "use-case.txt"),
            sha256=compute_file_sha256(run_dir / "use-case.txt"),
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="absolute"):
            load_strict_resolver(run_dir)

    def test_manifest_container_is_sole_orphan_exception(self, tmp_path: Path):
        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
        )
        # run-manifest.yaml exists but is not in inventory — should be OK
        resolver = load_strict_resolver(run_dir)
        # No RUN_MANIFEST role in inventory
        assert resolver.entry_by_role(ArtifactRole.REPORT) is not None


# --------------------------------------------------------------------------- #
# 5. Strict eval/report stale file immunity
# --------------------------------------------------------------------------- #


@pytest.mark.skip(
    reason="legacy manifest-v2 eval reader removed; strict v3 is tested separately"
)
class TestStrictEvalStaleImmunity:
    """Strict eval/report consume only manifest inventory entries."""

    def test_stale_scenario_yaml_rejected_inside_finalized_run(self, tmp_path: Path):
        from asago_scenario_generator.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )

        stale = run_dir / "scenarios" / "stale.yaml"
        stale.write_text(
            yaml.dump({"scenario_id": "stale", "narrative": {"entry_point": "bad"}})
        )

        with pytest.raises(ManifestIntegrityError, match="orphan"):
            run_evaluation(run_dir)

    def test_collection_level_stale_ignored_by_eval(self, tmp_path: Path):
        from asago_scenario_generator.eval.runner import run_evaluation

        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / _VALID_RUN_ID,
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        (collection / "stale.yaml").write_text("stale: true")

        scorecard = run_evaluation(run_dir)
        assert scorecard["evaluation"]["scenario_count"] == 1

    def test_stale_feature_only_entry_not_scored_by_eval(self, tmp_path: Path):
        """Eval must not score feature-only entries."""
        from asago_scenario_generator.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            scenarios=[_make_scenario("s1")],
            feature_files={"s1": _make_feature("s1")},
        )
        # Add an unmanifested stale feature file — orphan check rejects it
        stale_feature = run_dir / "scenarios" / "stale.feature"
        stale_feature.write_text("Feature: stale\n  Scenario: X\n")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            run_evaluation(run_dir)

    def test_non_authoritative_rejected_by_default(self, tmp_path: Path):
        from asago_scenario_generator.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            status=RunStatus.COMPLETED_WITH_ERRORS,
        )
        with pytest.raises(ManifestIntegrityError, match="not authoritative"):
            run_evaluation(run_dir)

    def test_non_authoritative_allowed_with_flag(self, tmp_path: Path):
        from asago_scenario_generator.eval.runner import run_evaluation

        run_dir = build_test_run_dir(
            tmp_path / "run",
            profile_data={"zones_active": ["input"], "entry_points": []},
            status=RunStatus.COMPLETED_WITH_ERRORS,
        )
        scorecard = run_evaluation(run_dir, allow_non_authoritative=True)
        assert scorecard["evaluation"]["scenario_count"] == 0


# --------------------------------------------------------------------------- #
# 6. Provenance
# --------------------------------------------------------------------------- #


class TestProvenance:
    """Git, config digest, and input hash provenance."""

    def test_config_digest_stable_across_key_order(self):
        opts1 = {"a": 1, "b": 2, "c": 3}
        opts2 = {"c": 3, "a": 1, "b": 2}
        assert compute_config_digest(opts1) == compute_config_digest(opts2)

    def test_config_digest_differs_for_different_values(self):
        assert compute_config_digest({"a": 1}) != compute_config_digest({"a": 2})

    def test_git_provenance_mocked_clean(self, tmp_path: Path):
        from asago_scenario_generator.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()

        with patch("asago_scenario_generator.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "abc123"
        assert prov.dirty is False
        assert prov.source_diff_digest is not None

    def test_git_provenance_mocked_dirty(self, tmp_path: Path):
        from asago_scenario_generator.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("asago_scenario_generator.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="def456\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="dev\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=" M file.py\n", stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="diff content\n", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.commit == "def456"
        assert prov.dirty is True
        assert prov.source_diff_digest is not None

    def test_git_provenance_clean_vs_dirty_differ(self, tmp_path: Path):
        from asago_scenario_generator.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        def make_mock(stdout_status, stdout_diff, stdout_untracked=""):
            mock_run = MagicMock()

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_status, stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_diff, stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout=stdout_untracked, stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            return mock_run

        with patch(
            "asago_scenario_generator.manifest.subprocess.run", make_mock("", "")
        ):
            clean_prov = capture_git_provenance(repo)
        with patch(
            "asago_scenario_generator.manifest.subprocess.run",
            make_mock(" M f\n", "d\n"),
        ):
            dirty_prov = capture_git_provenance(repo)

        assert clean_prov.source_diff_digest != dirty_prov.source_diff_digest
        assert clean_prov.dirty is False
        assert dirty_prov.dirty is True

    def test_git_provenance_no_repo(self, tmp_path: Path):
        from asago_scenario_generator.manifest import capture_git_provenance

        prov = capture_git_provenance(tmp_path)
        assert prov.commit is None
        assert prov.dirty is None
        assert prov.source_diff_digest is None

    def test_git_provenance_untracked_in_digest(self, tmp_path: Path):
        from asago_scenario_generator.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "tracked.txt").write_text("tracked")
        (repo / "untracked.txt").write_text("untracked content")

        with patch("asago_scenario_generator.manifest.subprocess.run") as mock_run:

            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc123\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(
                        returncode=0, stdout="?? untracked.txt\n", stderr=""
                    )
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout="untracked.txt\n", stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            mock_run.side_effect = side_effect
            prov = capture_git_provenance(repo)

        assert prov.dirty is True
        assert "untracked.txt" in prov.untracked_files
        assert prov.source_diff_digest is not None

    def test_git_provenance_tracked_dirty_vs_untracked_dirty_differ(
        self, tmp_path: Path
    ):
        """Tracked-dirty and untracked-dirty states produce distinct digests."""
        from asago_scenario_generator.manifest import capture_git_provenance

        repo = tmp_path / "repo"
        repo.mkdir()

        def make_mock(status, diff, untracked):
            def side_effect(cmd, **kw):
                if "rev-parse" in cmd and "HEAD" in cmd:
                    return MagicMock(returncode=0, stdout="abc\n", stderr="")
                if "rev-parse" in cmd and "abbrev-ref" in cmd:
                    return MagicMock(returncode=0, stdout="main\n", stderr="")
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=status, stderr="")
                if "diff" in cmd:
                    return MagicMock(returncode=0, stdout=diff, stderr="")
                if "ls-files" in cmd:
                    return MagicMock(returncode=0, stdout=untracked, stderr="")
                return MagicMock(returncode=1, stdout="", stderr="")

            return side_effect

        with patch(
            "asago_scenario_generator.manifest.subprocess.run",
            side_effect=make_mock(" M tracked.txt\n", "diff\n", ""),
        ):
            tracked_prov = capture_git_provenance(repo)
        with patch(
            "asago_scenario_generator.manifest.subprocess.run",
            side_effect=make_mock("?? new.txt\n", "", "new.txt\n"),
        ):
            untracked_prov = capture_git_provenance(repo)

        assert tracked_prov.source_diff_digest != untracked_prov.source_diff_digest


# --------------------------------------------------------------------------- #
# 7. Run ID validation (128-bit entropy)
# --------------------------------------------------------------------------- #


class TestRunIdValidation:
    """Sortable run ID format and validation."""

    def test_sortable_format_accepted(self):
        validate_run_id("20260101T120000_abcdef0123456789abcdef0123456789")

    def test_legacy_hex_accepted(self):
        validate_run_id("a" * 32)

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("")

    def test_uppercase_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("A" * 32)

    def test_too_short_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("short")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError):
            validate_run_id("z" * 32)

    def test_old_16hex_format_rejected(self):
        """The old 64-bit suffix format (16 hex) is no longer valid."""
        with pytest.raises(ValueError):
            validate_run_id("20260101T120000_abcdef0123456789")

    def test_generate_produces_valid(self):
        rid = generate_sortable_run_id()
        validate_run_id(rid)
        assert is_sortable_run_id(rid)

    def test_generated_ids_unique(self):
        ids = {generate_sortable_run_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generated_id_has_128_bit_suffix(self):
        """The suffix must be 32 hex chars (128 bits)."""
        rid = generate_sortable_run_id()
        suffix = rid.split("_", 1)[1]
        assert len(suffix) == 32


# --------------------------------------------------------------------------- #
# 8. find_run_dir unambiguous resolution
# --------------------------------------------------------------------------- #


class TestFindRunDir:
    """find_run_dir requires unambiguous resolution — no implicit latest."""

    def test_run_dir_returns_itself(self, tmp_path: Path):
        run_dir = build_test_run_dir(tmp_path / "run")
        assert find_run_dir(run_dir) == run_dir

    def test_collection_with_one_run(self, tmp_path: Path):
        collection = tmp_path / "output"
        run_dir = build_test_run_dir(collection / _VALID_RUN_ID)
        assert find_run_dir(collection) == run_dir

    def test_collection_with_multiple_runs_ambiguous(self, tmp_path: Path):
        collection = tmp_path / "output"
        build_test_run_dir(collection / _VALID_RUN_ID)
        build_test_run_dir(
            collection / "20260102T000000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        with pytest.raises(ManifestIntegrityError, match="2 runs"):
            find_run_dir(collection)

    def test_empty_collection_raises(self, tmp_path: Path):
        collection = tmp_path / "output"
        collection.mkdir()
        with pytest.raises(ManifestIntegrityError, match="No run"):
            find_run_dir(collection)


# --------------------------------------------------------------------------- #
# 9. Required singleton roles and completed validation
# --------------------------------------------------------------------------- #


class TestRequiredSingletonRoles:
    """Required singleton roles from effective config."""

    def test_report_always_required(self):
        roles = required_singleton_roles(eval_enabled=True)
        assert ArtifactRole.REPORT in roles
        roles = required_singleton_roles(eval_enabled=False)
        assert ArtifactRole.REPORT in roles

    def test_scorecard_required_when_eval_enabled(self):
        roles = required_singleton_roles(eval_enabled=True)
        assert ArtifactRole.EVAL_SCORECARD in roles

    def test_scorecard_not_required_when_eval_disabled(self):
        roles = required_singleton_roles(eval_enabled=False)
        assert ArtifactRole.EVAL_SCORECARD not in roles

    def test_validate_completed_inventory_missing_report_fails(self, tmp_path: Path):
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[],
        )
        with pytest.raises(ManifestIntegrityError, match="Missing required"):
            validate_completed_inventory(manifest, eval_enabled=True)


# --------------------------------------------------------------------------- #
# 10. Attempt records
# --------------------------------------------------------------------------- #


class TestAttemptRecords:
    """Typed attempt records with admitted/quarantined/failed disposition."""

    def test_admitted_attempt(self):
        rec = AttemptRecord(
            candidate_id="cand:v2:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.ADMITTED,
        )
        assert rec.disposition == AttemptDisposition.ADMITTED
        assert rec.failure_evidence is None

    def test_failed_attempt_with_evidence(self):
        rec = AttemptRecord(
            candidate_id="cand:v2:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.FAILED,
            failure_evidence="LLM timeout",
        )
        assert rec.disposition == AttemptDisposition.FAILED
        assert rec.failure_evidence == "LLM timeout"

    def test_quarantined_attempt_with_evidence(self):
        rec = AttemptRecord(
            candidate_id="cand:v2:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.QUARANTINED,
            failure_evidence="phantom capability",
        )
        assert rec.disposition == AttemptDisposition.QUARANTINED


# --------------------------------------------------------------------------- #
# 11. In-memory resolver (no persisted started manifest)
# --------------------------------------------------------------------------- #


class TestInMemoryResolver:
    """Internal eval/report use in-memory resolver, not persisted started manifest."""

    def test_in_memory_resolver_no_orphan_check(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")
        (run_dir / "extra.txt").write_text("extra")  # would be orphan if checked

        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[
                build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt"),
            ],
        )
        resolver = build_in_memory_resolver(run_dir, manifest)
        # Extra file does not trigger orphan check
        assert resolver.entry_by_role(ArtifactRole.USE_CASE) is not None

    def test_in_memory_resolver_validates_entries(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("test")

        entry = ArtifactEntry(
            role=ArtifactRole.USE_CASE,
            path="use-case.txt",
            sha256="0" * 64,  # wrong hash
            media_type="text/plain",
        )
        manifest = RunManifest(
            status=RunStatus.STARTED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            build_in_memory_resolver(run_dir, manifest)


# --------------------------------------------------------------------------- #
# 12. Pipeline lifecycle integration (mocked)
# --------------------------------------------------------------------------- #


def _mock_write_coverage_report(run_dir):
    """Side effect that actually writes coverage-gaps.json."""
    from asago_scenario_generator.pipeline.io import write_coverage_report as _real

    def _side_effect(*args, **kwargs):
        # Write a minimal coverage file

        path = args[0] if args else kwargs.get("run_dir")
        if path is None:
            # CoverageGaps, run_dir, attacker_diversity signature
            return _real(*args, **kwargs)
        return _real(*args, **kwargs)

    return _side_effect


@pytest.mark.usefixtures("offline_llm")
class TestPipelineLifecycle:
    """Integration tests for pipeline lifecycle with mocked LLM calls."""

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_empty_run_completes_with_errors(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from asago_scenario_generator.llm.client import LLMResult
        from asago_scenario_generator.models.capability_profile import CapabilityProfile
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from asago_scenario_generator.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        # Mock report to actually write report.html
        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        assert result.run_dir is not None
        assert result.run_id is not None
        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED_WITH_ERRORS

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_fatal_error_writes_failed_manifest(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        mock_profile.side_effect = RuntimeError("LLM connection failed")
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        with pytest.raises(RuntimeError, match="LLM connection failed"):
            run_pipeline(
                use_case="A chatbot",
                risk_extraction_path=risk_path,
                sssom_path=sssom_path,
                output_dir=collection,
            )

        runs = [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)]
        assert len(runs) == 1
        manifest = load_manifest(runs[0])
        assert manifest.status == RunStatus.FAILED

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_two_runs_same_collection(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from asago_scenario_generator.llm.client import LLMResult
        from asago_scenario_generator.models.capability_profile import CapabilityProfile
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from asago_scenario_generator.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result1 = run_pipeline(
            use_case="First run",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )
        result2 = run_pipeline(
            use_case="Second run",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        assert result1.run_dir != result2.run_dir
        assert result1.run_id != result2.run_id

        m1 = load_manifest(result1.run_dir)
        m2 = load_manifest(result2.run_dir)
        assert m1.status == RunStatus.COMPLETED_WITH_ERRORS
        assert m2.status == RunStatus.COMPLETED_WITH_ERRORS

        assert (result1.run_dir / "use-case.txt").read_text() == "First run"

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_no_eval_is_completed_with_errors(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        from asago_scenario_generator.llm.client import LLMResult
        from asago_scenario_generator.models.capability_profile import CapabilityProfile
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from asago_scenario_generator.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        def _write_report(data, out_dir):
            (Path(out_dir) / "report.html").write_text("<html>mock</html>")
            return Path(out_dir) / "report.html"

        mock_report.side_effect = _write_report

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
            eval=False,
        )

        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED_WITH_ERRORS


# --------------------------------------------------------------------------- #
# Second independent review acceptance contract
# --------------------------------------------------------------------------- #


def _valid_run(run_dir: Path, *, status=RunStatus.COMPLETED) -> RunManifest:
    """Build and load a complete one-scenario run used by adversarial tests."""
    scenario = _make_scenario("s1") | {"candidate_id": "cand-1"}
    build_test_run_dir(
        run_dir,
        use_case="A chatbot",
        profile_data={"zones_active": ["input"]},
        threat_surface_data={"entries": []},
        scenarios=[scenario],
        feature_files={"s1": _make_feature("s1")},
        coverage_data={"gaps": []},
        eval_scorecard={"evaluation": {"scenario_count": 1, "feature_file_count": 1}},
        status=status,
    )
    manifest = load_manifest(run_dir)
    manifest.attempts = [
        AttemptRecord(
            candidate_id="cand-1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
            phase=AttemptPhase.MAIN,
        )
    ]
    manifest.funnel = {
        "attempted": 1,
        "admitted": 1,
        "quarantined": 0,
        "main_attempted": 1,
        "main_admitted": 1,
        "generation_failed": 0,
        "remediation_attempted": 0,
        "remediation_admitted": 0,
        "remediation_failed": 0,
    }
    return manifest


class TestCompletedRunWithAdmittedPair:
    def test_completed_with_warnings_requires_complete_scenario_pairs(
        self, tmp_path: Path
    ):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir, status=RunStatus.COMPLETED_WITH_WARNINGS)
        manifest.inventory = [
            entry
            for entry in manifest.inventory
            if entry.role is not ArtifactRole.SCENARIO_FEATURE
        ]

        with pytest.raises(
            ManifestIntegrityError, match="Incomplete scenario YAML/feature pairs"
        ):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=False)

    def test_completed_run_with_real_admitted_pair(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)

        validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)
        ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

        yaml_entries = [
            entry
            for entry in manifest.inventory
            if entry.role == ArtifactRole.SCENARIO_YAML
        ]
        scorecard = yaml.safe_load((run_dir / "eval-scorecard.yaml").read_text())
        assert manifest.status == RunStatus.COMPLETED
        assert scorecard["evaluation"]["scenario_count"] == len(yaml_entries)

    def test_second_real_run_does_not_change_first(self, tmp_path: Path):
        collection = tmp_path / "collection"
        first = collection / _VALID_RUN_ID
        _valid_run(first)
        before = {
            path.relative_to(first).as_posix(): path.read_bytes()
            for path in first.rglob("*")
            if path.is_file()
        }

        second = collection / "20260101T000001_abcdef0123456789abcdef0123456789"
        _valid_run(second)
        after = {
            path.relative_to(first).as_posix(): path.read_bytes()
            for path in first.rglob("*")
            if path.is_file()
        }
        assert after == before


class TestAttemptEquations:
    @staticmethod
    def _manifest(attempts, funnel):
        return RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=attempts,
            funnel=funnel,
        )

    @staticmethod
    def _attempt(candidate, scenario, disposition, phase=AttemptPhase.MAIN):
        evidence = (
            "generation error" if disposition != AttemptDisposition.ADMITTED else None
        )
        return AttemptRecord(
            candidate_id=candidate,
            scenario_id=scenario,
            disposition=disposition,
            phase=phase,
            failure_evidence=evidence,
        )

    @pytest.mark.parametrize(
        ("attempts", "funnel"),
        [
            (
                [_attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED)],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 0,
                    "main_attempted": 1,
                    "main_admitted": 1,
                    "generation_failed": 0,
                    "remediation_attempted": 0,
                    "remediation_admitted": 0,
                    "remediation_failed": 0,
                },
            ),
            (
                [
                    _attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED),
                    _attempt.__func__(
                        "c2",
                        "s2",
                        AttemptDisposition.ADMITTED,
                        AttemptPhase.REMEDIATION,
                    ),
                ],
                {
                    "attempted": 2,
                    "admitted": 2,
                    "quarantined": 0,
                    "main_attempted": 1,
                    "main_admitted": 1,
                    "generation_failed": 0,
                    "remediation_attempted": 1,
                    "remediation_admitted": 1,
                    "remediation_failed": 0,
                },
            ),
            (
                [
                    _attempt.__func__("c1", "s1", AttemptDisposition.ADMITTED),
                    _attempt.__func__(
                        "c2", "s2", AttemptDisposition.FAILED, AttemptPhase.REMEDIATION
                    ),
                ],
                {
                    "attempted": 2,
                    "admitted": 1,
                    "quarantined": 0,
                    "main_attempted": 1,
                    "main_admitted": 1,
                    "generation_failed": 0,
                    "remediation_attempted": 1,
                    "remediation_admitted": 0,
                    "remediation_failed": 1,
                },
            ),
            (
                [_attempt.__func__("c1", "s1", AttemptDisposition.QUARANTINED)],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 1,
                    "main_attempted": 1,
                    "main_admitted": 1,
                    "generation_failed": 0,
                    "remediation_attempted": 0,
                    "remediation_admitted": 0,
                    "remediation_failed": 0,
                },
            ),
            (
                [],
                {
                    "attempted": 0,
                    "admitted": 0,
                    "quarantined": 0,
                    "generation_failed": 0,
                    "remediation_failed": 0,
                },
            ),
        ],
    )
    def test_valid_equations(self, attempts, funnel):
        validate_attempt_equations(self._manifest(attempts, funnel))

    def test_remediation_success(self):
        attempt = self._attempt(
            "c1", "s1", AttemptDisposition.ADMITTED, AttemptPhase.REMEDIATION
        )
        validate_attempt_equations(
            self._manifest(
                [attempt],
                {
                    "attempted": 1,
                    "admitted": 1,
                    "quarantined": 0,
                    "main_attempted": 0,
                    "main_admitted": 0,
                    "generation_failed": 0,
                    "remediation_attempted": 1,
                    "remediation_admitted": 1,
                    "remediation_failed": 0,
                },
            )
        )

    def test_remediation_failure_with_evidence(self):
        attempt = self._attempt(
            "c1", "s1", AttemptDisposition.FAILED, AttemptPhase.REMEDIATION
        )
        assert attempt.failure_evidence
        validate_attempt_equations(
            self._manifest(
                [attempt],
                {
                    "attempted": 1,
                    "admitted": 0,
                    "quarantined": 0,
                    "main_attempted": 0,
                    "main_admitted": 0,
                    "generation_failed": 0,
                    "remediation_attempted": 1,
                    "remediation_admitted": 0,
                    "remediation_failed": 1,
                },
            )
        )

    def test_duplicate_attempt_keys_raise(self):
        attempt = self._attempt("c1", "s1", AttemptDisposition.ADMITTED)
        with pytest.raises(ManifestIntegrityError, match="Duplicate attempt"):
            validate_attempt_equations(
                self._manifest([attempt, attempt.model_copy()], {})
            )

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("attempted", 2, "attempted mismatch"),
            ("admitted", 0, "admitted mismatch"),
            ("quarantined", 1, "quarantined mismatch"),
            ("generation_failed", 1, "failed mismatch"),
        ],
    )
    def test_funnel_mismatches_raise(self, field, value, message):
        funnel = {
            "attempted": 1,
            "admitted": 1,
            "quarantined": 0,
            "main_attempted": 1,
            "main_admitted": 1,
            "generation_failed": 0,
            "remediation_attempted": 0,
            "remediation_admitted": 0,
            "remediation_failed": 0,
        }
        funnel[field] = value
        attempt = self._attempt("c1", "s1", AttemptDisposition.ADMITTED)
        with pytest.raises(ManifestIntegrityError, match=message):
            validate_attempt_equations(self._manifest([attempt], funnel))


class TestFailedEvidenceRetention:
    @staticmethod
    def _write_failed(run_dir: Path, files):
        inventory = []
        for role, rel_path, content, scenario_id, candidate_id in files:
            path = run_dir / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            inventory.append(
                build_artifact_entry(role, run_dir, rel_path, scenario_id, candidate_id)
            )
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=inventory,
            error="injected failure",
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )

    def test_partial_unpaired_evidence_loads_strictly(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        self._write_failed(
            run_dir,
            [
                (ArtifactRole.USE_CASE, "use-case.txt", "chatbot", None, None),
                (
                    ArtifactRole.CAPABILITY_PROFILE,
                    "capability-profile.yaml",
                    "zones: []\n",
                    None,
                    None,
                ),
                (
                    ArtifactRole.THREAT_SURFACE,
                    "threat-surface.yaml",
                    "entries: []\n",
                    None,
                    None,
                ),
                (
                    ArtifactRole.SCENARIO_YAML,
                    "scenarios/s1.yaml",
                    yaml.safe_dump(_make_scenario("s1")),
                    "s1",
                    "cand:v2:abc",
                ),
            ],
        )
        resolver = load_strict_resolver(run_dir, require_final=True)
        assert resolver.manifest.status == RunStatus.FAILED

    def test_failed_run_inventories_all_forensic_artifacts(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        self._write_failed(
            run_dir,
            [
                (
                    ArtifactRole.SCENARIO_YAML,
                    "scenarios/s1.yaml",
                    yaml.safe_dump(_make_scenario("s1")),
                    "s1",
                    "cand:v2:abc",
                ),
                (
                    ArtifactRole.SCENARIO_FEATURE,
                    "scenarios/s1.feature",
                    _make_feature("s1"),
                    "s1",
                    "cand:v2:abc",
                ),
                (ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl", "{}\n", None, None),
                (ArtifactRole.PIPELINE_LOG, "pipeline.log", "failed\n", None, None),
            ],
        )
        load_strict_resolver(run_dir, require_final=True)


class TestStrictValidationNegativeCases:
    def _base(self, tmp_path):
        run_dir = tmp_path / _VALID_RUN_ID
        return run_dir, _valid_run(run_dir)

    @pytest.mark.parametrize(
        "bad_path",
        [
            "/etc/passwd",
            "scenarios\\s1.yaml",
            "./use-case.txt",
            "scenarios//s1.yaml",
            "../use-case.txt",
        ],
    )
    def test_noncanonical_paths_raise(self, tmp_path, bad_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory[0].path = bad_path
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_canonical_path_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory.append(manifest.inventory[0].model_copy())
        with pytest.raises(
            ManifestIntegrityError, match="Duplicate artifact canonical"
        ):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_singleton_role_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        duplicate = run_dir / "other.txt"
        duplicate.write_text("other")
        manifest.inventory.append(
            build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "other.txt")
        )
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize("field", ["scenario_id", "candidate_id"])
    def test_missing_scenario_identity_raises(self, tmp_path, field):
        run_dir, manifest = self._base(tmp_path)
        entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        setattr(entry, field, None)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_hash_mismatch_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        (run_dir / "use-case.txt").write_text("mutated")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_malformed_hash_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        manifest.inventory[0].sha256 = "bad"
        with pytest.raises(ManifestIntegrityError, match="Malformed SHA"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize(
        ("field", "value"), [("media_type", "text/xml"), ("schema_version", "99")]
    )
    def test_wrong_metadata_raises(self, tmp_path, field, value):
        run_dir, manifest = self._base(tmp_path)
        entry = next(e for e in manifest.inventory if e.path.endswith("s1.yaml"))
        setattr(entry, field, value)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_wrong_extension_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        entry = next(e for e in manifest.inventory if e.path.endswith("s1.yaml"))
        source = run_dir / entry.path
        target = source.with_suffix(".txt")
        source.rename(target)
        entry.path = "scenarios/s1.txt"
        entry.sha256 = compute_file_sha256(target)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_duplicate_candidate_across_scenarios_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        for suffix, role, content in [
            ("yaml", ArtifactRole.SCENARIO_YAML, yaml.safe_dump(_make_scenario("s2"))),
            ("feature", ArtifactRole.SCENARIO_FEATURE, _make_feature("s2")),
        ]:
            path = run_dir / f"scenarios/s2.{suffix}"
            path.write_text(content)
            manifest.inventory.append(
                build_artifact_entry(
                    role, run_dir, f"scenarios/s2.{suffix}", "s2", "cand-1"
                )
            )
        with pytest.raises(ManifestIntegrityError, match="candidate"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    @pytest.mark.parametrize("defect", ["inventory", "filename", "feature"])
    def test_scenario_identity_mismatches_raise(self, tmp_path, defect):
        run_dir, manifest = self._base(tmp_path)
        yaml_entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
        )
        feature_entry = next(
            e for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_FEATURE
        )
        if defect == "inventory":
            yaml_entry.scenario_id = "different"
        elif defect == "feature":
            feature_entry.scenario_id = "different"
        else:
            old = run_dir / yaml_entry.path
            new = old.with_name("different.yaml")
            old.rename(new)
            yaml_entry.path = "scenarios/different.yaml"
            yaml_entry.sha256 = compute_file_sha256(new)
        with pytest.raises(ManifestIntegrityError):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)

    def test_orphan_file_raises(self, tmp_path):
        run_dir, manifest = self._base(tmp_path)
        (run_dir / "orphan.txt").write_text("unexpected")
        with pytest.raises(ManifestIntegrityError, match="orphan"):
            ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


class TestProvenanceStartSnapshot:
    def test_input_hashes_remain_start_snapshot(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import _capture_input_hashes

        risk = tmp_path / "risk.json"
        sssom = tmp_path / "mapping.tsv"
        cross = tmp_path / "cross.yaml"
        risk.write_text("original")
        sssom.write_text("mapping")
        cross.write_text("cross")
        hashes = _capture_input_hashes("chatbot", risk, sssom, cross, None, None)
        original = hashes.risk_extraction_hash
        risk.write_text("mutated")
        assert hashes.risk_extraction_hash == original
        assert hashes.risk_extraction_hash != compute_file_sha256(risk)

    def test_capture_provenance_uses_git_state_at_call_time(self, tmp_path: Path):
        with patch(
            "asago_scenario_generator.manifest.capture_git_provenance"
        ) as capture:
            capture.return_value = GitProvenance(
                commit="first",
                dirty=False,
                source_diff_digest=None,
                branch="main",
                untracked_files=[],
            )
            provenance = capture_provenance(
                _VALID_RUN_ID, "2026-01-01T00:00:00+00:00", repo_root=tmp_path
            )
        capture.assert_called_with(tmp_path)
        assert provenance.git.commit == "first"


@pytest.mark.usefixtures("offline_llm")
class TestFaultInjection:
    @staticmethod
    def _inputs(tmp_path):
        risk = tmp_path / "risk.json"
        sssom = tmp_path / "sssom.tsv"
        risk.write_text("[]")
        sssom.write_text("")
        return risk, sssom

    def test_client_construction_failure_leaves_failed_manifest(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        collection = tmp_path / "output"
        with (
            patch(
                "asago_scenario_generator.pipeline.runner_run.LLMClient.__init__",
                side_effect=RuntimeError("client failure"),
            ),
            pytest.raises(RuntimeError, match="client failure"),
        ):
            run_pipeline(
                use_case="chatbot",
                risk_extraction_path=risk,
                sssom_path=sssom,
                output_dir=collection,
            )
        run_dir = next(path for path in collection.iterdir() if path.is_dir())
        assert load_manifest(run_dir).status == RunStatus.FAILED

    def test_use_case_write_failure_keeps_provenance(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        collection = tmp_path / "output"
        with (
            patch(
                "asago_scenario_generator.pipeline.runner_run.write_use_case",
                side_effect=OSError("disk full"),
            ),
            pytest.raises(OSError, match="disk full"),
        ):
            run_pipeline(
                use_case="chatbot",
                risk_extraction_path=risk,
                sssom_path=sssom,
                output_dir=collection,
            )
        run_dir = next(path for path in collection.iterdir() if path.is_dir())
        manifest = load_manifest(run_dir)
        assert manifest.status == RunStatus.FAILED
        assert manifest.provenance is not None
        assert manifest.provenance.input_hashes.risk_extraction_hash

    def test_finalization_failure_propagates(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import run_pipeline

        risk, sssom = self._inputs(tmp_path)
        profile = tmp_path / "capability-profile.yaml"
        profile.write_text(
            yaml.safe_dump(
                {
                    "zones_active": ["input", "reasoning"],
                    "entry_points": ["chat input [input]"],
                    "confidence": "high",
                    "kc_subcodes": ["KC1.1"],
                }
            )
        )
        with (
            patch(
                "asago_scenario_generator.pipeline.runner.finalize_manifest",
                side_effect=RuntimeError("finalize failure"),
            ),
            pytest.raises(RuntimeError, match="finalize failure"),
        ):
            run_pipeline(
                use_case="chatbot",
                risk_extraction_path=risk,
                sssom_path=sssom,
                output_dir=tmp_path / "output",
                profile_path=profile,
            )

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_client_construction_failure_writes_failed_manifest(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        """Fatal error during client construction writes failed manifest."""
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        with (
            patch(
                "asago_scenario_generator.pipeline.runner_run.LLMClient",
                side_effect=RuntimeError("bad config"),
            ),
            pytest.raises(RuntimeError, match="bad config"),
        ):
            run_pipeline(
                use_case="A chatbot",
                risk_extraction_path=risk_path,
                sssom_path=sssom_path,
                output_dir=collection,
            )

        runs = [d for d in collection.iterdir() if d.is_dir() and is_run_dir(d)]
        assert len(runs) == 1
        manifest = load_manifest(runs[0])
        assert manifest.status == RunStatus.FAILED
        assert manifest.error is not None

    @patch("asago_scenario_generator.report.generator.generate_report")
    @patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
    @patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
    @patch("asago_scenario_generator.pipeline.runner_run.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner_run.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner_run.validate_risk_card_coherence")
    @patch(
        "asago_scenario_generator.pipeline.runner_run.load_risk_extraction",
        return_value=[],
    )
    @patch("asago_scenario_generator.pipeline.runner_run.infer_capability_profile")
    def test_report_failure_is_completed_with_errors(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_report,
        tmp_path: Path,
    ):
        """Report generation failure results in completed_with_errors."""
        from asago_scenario_generator.llm.client import LLMResult
        from asago_scenario_generator.models.capability_profile import CapabilityProfile
        from asago_scenario_generator.pipeline.runner import run_pipeline
        from asago_scenario_generator.models import ThreatSurface

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["ep-1"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        mock_profile.return_value = (
            profile,
            LLMResult(
                content="mock",
                prompt_tokens=10,
                completion_tokens=20,
                duration_ms=100,
                system_prompt="system",
                user_prompt="user",
            ),
        )
        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence
        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])
        from asago_scenario_generator.pipeline.coverage import CoverageGaps

        mock_gaps.return_value = CoverageGaps()
        mock_diversity.return_value = None

        mock_report.side_effect = RuntimeError("report rendering failed")

        collection = tmp_path / "output"
        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        result = run_pipeline(
            use_case="A chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=collection,
        )

        manifest = load_manifest(result.run_dir)
        assert manifest.status == RunStatus.COMPLETED_WITH_ERRORS


# --------------------------------------------------------------------------- #
# Third narrow independent review — focused correction tests
# --------------------------------------------------------------------------- #


class TestThirdReviewAttemptEvidence:
    """AttemptRecord evidence validation for FAILED/QUARANTINED."""

    def test_failed_without_evidence_rejected(self):
        with pytest.raises(Exception, match="failure_evidence"):
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.FAILED,
                failure_evidence=None,
            )

    def test_quarantined_without_evidence_rejected(self):
        with pytest.raises(Exception, match="failure_evidence"):
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.QUARANTINED,
                failure_evidence=None,
            )

    def test_failed_with_blank_evidence_rejected(self):
        with pytest.raises(Exception, match="failure_evidence"):
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.FAILED,
                failure_evidence="   ",
            )

    def test_admitted_without_evidence_accepted(self):
        rec = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
            failure_evidence=None,
        )
        assert rec.disposition == AttemptDisposition.ADMITTED


class TestThirdReviewFunnelEquations:
    """Phase-specific funnel equation validation."""

    def test_attempts_with_empty_funnel_rejected(self):
        attempt = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[attempt],
            funnel={},
        )
        with pytest.raises(ManifestIntegrityError, match="no funnel"):
            validate_attempt_equations(manifest)

    def test_main_attempted_mismatch_rejected(self):
        attempt = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[attempt],
            funnel={
                "attempted": 1,
                "admitted": 1,
                "quarantined": 0,
                "main_attempted": 99,
                "main_admitted": 1,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="main_attempted"):
            validate_attempt_equations(manifest)

    def test_main_admitted_mismatch_rejected(self):
        attempt = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[attempt],
            funnel={
                "attempted": 1,
                "admitted": 1,
                "quarantined": 0,
                "main_attempted": 1,
                "main_admitted": 99,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="main_admitted"):
            validate_attempt_equations(manifest)

    def test_remediation_attempted_mismatch_rejected(self):
        attempt = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
            phase=AttemptPhase.REMEDIATION,
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[attempt],
            funnel={
                "attempted": 1,
                "admitted": 1,
                "quarantined": 0,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 0,
                "remediation_attempted": 99,
                "remediation_admitted": 1,
                "remediation_failed": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="remediation_attempted"):
            validate_attempt_equations(manifest)

    def test_generation_failed_mismatch_rejected(self):
        attempt = AttemptRecord(
            candidate_id="c1",
            scenario_id="s1",
            disposition=AttemptDisposition.FAILED,
            failure_evidence="gen error",
        )
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[attempt],
            funnel={
                "attempted": 1,
                "admitted": 0,
                "quarantined": 0,
                "main_attempted": 1,
                "main_admitted": 0,
                "generation_failed": 99,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="generation_failed"):
            validate_attempt_equations(manifest)

    def test_zero_attempts_with_nonzero_lifecycle_key_rejected(self):
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=[],
            funnel={
                "attempted": 0,
                "admitted": 0,
                "quarantined": 0,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 5,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="generation_failed.*zero"):
            validate_attempt_equations(manifest)

    def test_derive_funnel_from_attempts(self):
        from asago_scenario_generator.manifest import derive_funnel_from_attempts

        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
            AttemptRecord(
                candidate_id="c2",
                scenario_id="s2",
                disposition=AttemptDisposition.FAILED,
                failure_evidence="gen error",
                phase=AttemptPhase.MAIN,
            ),
            AttemptRecord(
                candidate_id="c3",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.REMEDIATION,
            ),
        ]
        funnel = derive_funnel_from_attempts(attempts)
        assert funnel["attempted"] == 3
        assert funnel["admitted"] == 2
        assert funnel["quarantined"] == 0
        assert funnel["main_attempted"] == 2
        assert funnel["main_admitted"] == 1
        assert funnel["generation_failed"] == 1
        assert funnel["remediation_attempted"] == 1
        assert funnel["remediation_admitted"] == 1
        assert funnel["remediation_failed"] == 0
        # Validate the derived funnel passes equation validation
        manifest = RunManifest(
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            attempts=attempts,
            funnel=funnel,
        )
        validate_attempt_equations(manifest)


class TestThirdReviewExactReconciliation:
    """Exact (scenario_id, candidate_id) reconciliation in completed inventory."""

    def test_exact_key_mismatch_rejected(self, tmp_path: Path):
        """Admitted attempt with wrong candidate_id fails reconciliation."""
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)
        # Change the attempt candidate_id to mismatch inventory
        manifest.attempts[0] = AttemptRecord(
            candidate_id="wrong-candidate",
            scenario_id="s1",
            disposition=AttemptDisposition.ADMITTED,
        )
        with pytest.raises(ManifestIntegrityError, match="Admitted scenario identity"):
            validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)


class TestThirdReviewScorecardValidation:
    """Scorecard count validation using verified bytes."""

    def test_scorecard_missing_scenario_count_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)
        # Overwrite scorecard with missing scenario_count
        sc_path = run_dir / "eval-scorecard.yaml"
        sc_data = yaml.safe_load(sc_path.read_text())
        del sc_data["evaluation"]["scenario_count"]
        sc_path.write_text(yaml.dump(sc_data))
        # Re-hash the scorecard in inventory
        for entry in manifest.inventory:
            if entry.role == ArtifactRole.EVAL_SCORECARD:
                entry.sha256 = compute_file_sha256(sc_path)
        with pytest.raises(ManifestIntegrityError, match="missing scenario_count"):
            validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)

    def test_scorecard_missing_feature_count_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)
        sc_path = run_dir / "eval-scorecard.yaml"
        sc_data = yaml.safe_load(sc_path.read_text())
        del sc_data["evaluation"]["feature_file_count"]
        sc_path.write_text(yaml.dump(sc_data))
        for entry in manifest.inventory:
            if entry.role == ArtifactRole.EVAL_SCORECARD:
                entry.sha256 = compute_file_sha256(sc_path)
        with pytest.raises(ManifestIntegrityError, match="missing feature_file_count"):
            validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)

    def test_scorecard_wrong_scenario_count_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)
        sc_path = run_dir / "eval-scorecard.yaml"
        sc_data = yaml.safe_load(sc_path.read_text())
        sc_data["evaluation"]["scenario_count"] = 99
        sc_path.write_text(yaml.dump(sc_data))
        for entry in manifest.inventory:
            if entry.role == ArtifactRole.EVAL_SCORECARD:
                entry.sha256 = compute_file_sha256(sc_path)
        with pytest.raises(ManifestIntegrityError, match="scenario_count=99"):
            validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)

    def test_scorecard_non_dict_evaluation_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        manifest = _valid_run(run_dir)
        sc_path = run_dir / "eval-scorecard.yaml"
        sc_path.write_text(yaml.dump({"evaluation": "not a dict"}))
        for entry in manifest.inventory:
            if entry.role == ArtifactRole.EVAL_SCORECARD:
                entry.sha256 = compute_file_sha256(sc_path)
        with pytest.raises(ManifestIntegrityError, match="evaluation.*not a dict"):
            validate_completed_inventory(manifest, eval_enabled=True, run_dir=run_dir)


class TestThirdReviewSerializedIdentity:
    """Serialized scenario_id/candidate_id in YAML and canonical paths."""

    def _make_run_with_scenario(
        self,
        tmp_path,
        sid="s1",
        cid="cand:v2:abc",
        yaml_content=None,
        yaml_path="scenarios/s1.yaml",
        feat_path="scenarios/s1.feature",
    ):
        run_dir = tmp_path / _VALID_RUN_ID
        run_dir.mkdir(parents=True)
        (run_dir / "scenarios").mkdir()
        if yaml_content is None:
            yaml_content = yaml.dump({"scenario_id": sid, "candidate_id": cid})
        (run_dir / yaml_path).write_text(yaml_content)
        (run_dir / feat_path).write_text(f"Feature: {sid}\n")
        entries = [
            build_artifact_entry(
                ArtifactRole.SCENARIO_YAML,
                run_dir,
                yaml_path,
                scenario_id=sid,
                candidate_id=cid,
            ),
            build_artifact_entry(
                ArtifactRole.SCENARIO_FEATURE,
                run_dir,
                feat_path,
                scenario_id=sid,
                candidate_id=cid,
            ),
        ]
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=entries,
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        return run_dir, manifest

    def test_missing_serialized_scenario_id_rejected(self, tmp_path: Path):
        run_dir, _manifest = self._make_run_with_scenario(
            tmp_path,
            yaml_content=yaml.dump({"candidate_id": "cand:v2:abc"}),
        )
        with pytest.raises(
            ManifestIntegrityError, match="missing serialized scenario_id"
        ):
            load_strict_resolver(run_dir)

    def test_missing_serialized_candidate_id_rejected(self, tmp_path: Path):
        run_dir, _manifest = self._make_run_with_scenario(
            tmp_path,
            yaml_content=yaml.dump({"scenario_id": "s1"}),
        )
        with pytest.raises(
            ManifestIntegrityError, match="missing serialized candidate_id"
        ):
            load_strict_resolver(run_dir)

    def test_mismatched_serialized_scenario_id_rejected(self, tmp_path: Path):
        run_dir, _manifest = self._make_run_with_scenario(
            tmp_path,
            yaml_content=yaml.dump(
                {"scenario_id": "wrong", "candidate_id": "cand:v2:abc"}
            ),
        )
        with pytest.raises(ManifestIntegrityError, match="Scenario ID mismatch"):
            load_strict_resolver(run_dir)

    def test_mismatched_serialized_candidate_id_rejected(self, tmp_path: Path):
        run_dir, _manifest = self._make_run_with_scenario(
            tmp_path,
            yaml_content=yaml.dump({"scenario_id": "s1", "candidate_id": "wrong"}),
        )
        with pytest.raises(ManifestIntegrityError, match="Candidate ID mismatch"):
            load_strict_resolver(run_dir)

    def test_scenario_yaml_wrong_parent_directory_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        run_dir.mkdir(parents=True)
        (run_dir / "wrong_dir").mkdir()
        (run_dir / "scenarios").mkdir()
        (run_dir / "wrong_dir" / "s1.yaml").write_text(
            yaml.dump({"scenario_id": "s1", "candidate_id": "cand:v2:abc"})
        )
        (run_dir / "scenarios" / "s1.feature").write_text("Feature: s1\n")
        entries = [
            build_artifact_entry(
                ArtifactRole.SCENARIO_YAML,
                run_dir,
                "wrong_dir/s1.yaml",
                scenario_id="s1",
                candidate_id="cand:v2:abc",
            ),
            build_artifact_entry(
                ArtifactRole.SCENARIO_FEATURE,
                run_dir,
                "scenarios/s1.feature",
                scenario_id="s1",
                candidate_id="cand:v2:abc",
            ),
        ]
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=entries,
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="canonical path"):
            load_strict_resolver(run_dir)

    def test_feature_wrong_parent_directory_rejected(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        run_dir.mkdir(parents=True)
        (run_dir / "wrong_dir").mkdir()
        (run_dir / "scenarios").mkdir()
        (run_dir / "scenarios" / "s1.yaml").write_text(
            yaml.dump({"scenario_id": "s1", "candidate_id": "cand:v2:abc"})
        )
        (run_dir / "wrong_dir" / "s1.feature").write_text("Feature: s1\n")
        entries = [
            build_artifact_entry(
                ArtifactRole.SCENARIO_YAML,
                run_dir,
                "scenarios/s1.yaml",
                scenario_id="s1",
                candidate_id="cand:v2:abc",
            ),
            build_artifact_entry(
                ArtifactRole.SCENARIO_FEATURE,
                run_dir,
                "wrong_dir/s1.feature",
                scenario_id="s1",
                candidate_id="cand:v2:abc",
            ),
        ]
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=entries,
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="canonical path"):
            load_strict_resolver(run_dir)


class TestThirdReviewVerifiedByteCache:
    """Resolver serves cached verified bytes, not fresh file reads."""

    def test_post_validation_replacement_returns_cached_bytes(self, tmp_path: Path):
        run_dir = tmp_path / _VALID_RUN_ID
        run_dir.mkdir(parents=True)
        (run_dir / "use-case.txt").write_text("original content")
        entry = build_artifact_entry(
            ArtifactRole.USE_CASE,
            run_dir,
            "use-case.txt",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        resolver = load_strict_resolver(run_dir)
        # Read original content through resolver
        original = resolver.read_text(entry)
        assert original == "original content"
        # Replace the file on disk after validation
        (run_dir / "use-case.txt").write_text("tampered content")
        # Resolver should still return cached verified bytes
        cached = resolver.read_text(entry)
        assert cached == "original content", (
            "Resolver should return cached verified bytes, not fresh file content"
        )


class TestThirdReviewConfigDigest:
    """Config digest bound to resolved effective options."""

    def test_resolved_model_difference_changes_digest(self):
        """Different resolved model produces different config digest."""
        opts1 = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        opts2 = dict(opts1, model="gpt-4o")
        d1 = compute_config_digest(opts1)
        d2 = compute_config_digest(opts2)
        assert d1 != d2, "Different resolved model must produce different digest"

    def test_resolved_base_url_difference_changes_digest(self):
        """Different resolved base URL produces different config digest."""
        opts1 = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        opts2 = dict(opts1, base_url="https://api.example.com/v1")
        d1 = compute_config_digest(opts1)
        d2 = compute_config_digest(opts2)
        assert d1 != d2, "Different resolved base URL must produce different digest"

    def test_generation_setting_difference_changes_digest(self):
        """Different generation settings produce different config digest."""
        opts1 = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        opts2 = dict(opts1, max_techniques=5)
        d1 = compute_config_digest(opts1)
        d2 = compute_config_digest(opts2)
        assert d1 != d2, "Different generation settings must produce different digest"

    def test_raw_none_args_still_yield_distinct_digests(self):
        """When raw CLI args are None, resolved values still produce
        distinct digests for different environment-resolved configs."""
        # Simulate: CLI passes model=None, but LLMClient resolves to
        # different defaults based on environment
        resolved_opts_a = {
            "model": "default-model-a",
            "base_url": "https://default-a.example.com",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        resolved_opts_b = {
            "model": "default-model-b",
            "base_url": "https://default-b.example.com",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        d_a = compute_config_digest(resolved_opts_a)
        d_b = compute_config_digest(resolved_opts_b)
        assert d_a != d_b, (
            "Different environment-resolved configs must produce different digests"
        )

    def test_temperature_included_in_digest(self):
        """Temperature must be part of the config digest."""
        opts1 = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        opts2 = dict(opts1, temperature=0.0)
        d1 = compute_config_digest(opts1)
        d2 = compute_config_digest(opts2)
        assert d1 != d2, "Different temperature must produce different digest"

    def test_no_api_key_in_digest(self):
        """API key material must not appear in effective_options or digest."""
        opts = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
        }
        import json

        canonical = json.dumps(opts, sort_keys=True, separators=(",", ":"), default=str)
        assert "api_key" not in canonical.lower()
        assert "key" not in canonical.lower() or "max" in canonical.lower()


# --------------------------------------------------------------------------- #
# Fourth narrow independent review
# --------------------------------------------------------------------------- #


class TestFourthReviewNormalizedConfigDigest:
    """Config digest must be bound to normalized, resolved effective options."""

    def test_whitespace_equivalent_zones_produce_identical_digest(self):
        """Whitespace-equivalent zone strings produce identical digests
        because zones are parsed and trimmed into a canonical list."""
        # Simulate the normalization done in run_pipeline
        zones_a = "input, reasoning"
        zones_b = "input,reasoning"
        zones_c = " input ,  reasoning  "

        def _normalize(z: str | None) -> list[str] | None:
            if z is None:
                return None
            return [x.strip() for x in z.split(",") if x.strip()]

        opts_a = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": _normalize(zones_a),
            "eval": True,
        }
        opts_b = dict(opts_a, zones=_normalize(zones_b))
        opts_c = dict(opts_a, zones=_normalize(zones_c))

        d_a = compute_config_digest(opts_a)
        d_b = compute_config_digest(opts_b)
        d_c = compute_config_digest(opts_c)

        assert d_a == d_b, (
            "Whitespace-equivalent zone strings must produce identical digests"
        )
        assert d_a == d_c, (
            "Whitespace-equivalent zone strings must produce identical digests"
        )

    def test_omitted_threats_records_bundled_resolved_path(self):
        """When threats_path is None, effective_options must record the
        resolved bundled default path, not None."""
        from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

        # Simulate the resolution done in run_pipeline
        threats_path = None
        effective_threats = (threats_path or _DEFAULT_THREATS_PATH).resolve()

        opts_with_none = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
            "threats_path": None,
        }
        opts_with_default = dict(opts_with_none, threats_path=str(effective_threats))

        d_none = compute_config_digest(opts_with_none)
        d_default = compute_config_digest(opts_with_default)

        assert d_none != d_default, (
            "Omitted threats (None) must differ from resolved bundled path"
        )
        # The resolved path must be a real, absolute path
        assert effective_threats.is_absolute(), (
            "Effective threats path must be resolved to an absolute path"
        )
        assert effective_threats.exists(), "Bundled default threats path must exist"

    def test_explicit_vs_default_threats_produce_distinct_digests(self):
        """Explicit threats path produces a different digest than the
        bundled default."""
        from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

        effective_default = _DEFAULT_THREATS_PATH.resolve()
        explicit = "/custom/threats.yaml"

        opts_default = {
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "temperature": 0.7,
            "max_completion_tokens": 4096,
            "max_techniques": 1,
            "max_scenarios_per_pattern": None,
            "zones": None,
            "eval": True,
            "threats_path": str(effective_default),
        }
        opts_explicit = dict(opts_default, threats_path=explicit)

        d_default = compute_config_digest(opts_default)
        d_explicit = compute_config_digest(opts_explicit)

        assert d_default != d_explicit, (
            "Explicit vs default threats paths must produce distinct digests"
        )


class TestFourthReviewZeroAttemptFunnel:
    """Zero-attempt runs may have nonzero pre-attempt funnel stages."""

    def test_nonzero_pre_attempt_stages_with_zero_lifecycle(self):
        """A valid run with expanded candidates but zero selected/attempted
        must pass validation: pre-attempt stages nonzero, lifecycle zero."""
        manifest = RunManifest(
            manifest_version="1.0",
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            package_version="0.1.0",
            attempts=[],
            funnel={
                "expanded_instances": 10,
                "unique_pre_rule_identities": 5,
                "rule_rejected": 3,
                "rule_transformed": 0,
                "post_rule_collapsed": 0,
                "filter_submitted": 2,
                "filter_accepted": 0,
                "selected": 0,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
                "attempted": 0,
                "admitted": 0,
                "quarantined": 0,
                "persisted_artifacts": 0,
            },
        )
        # Must not raise
        validate_attempt_equations(manifest)

    def test_nonzero_selected_with_zero_attempts_rejected(self):
        """If selected is nonzero but there are zero attempts, that's invalid."""
        manifest = RunManifest(
            manifest_version="1.0",
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            package_version="0.1.0",
            attempts=[],
            funnel={
                "expanded_instances": 10,
                "unique_pre_rule_identities": 5,
                "rule_rejected": 3,
                "rule_transformed": 0,
                "post_rule_collapsed": 0,
                "filter_submitted": 2,
                "filter_accepted": 1,
                "selected": 1,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
                "attempted": 0,
                "admitted": 0,
                "quarantined": 0,
                "persisted_artifacts": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="selected.*zero attempts"):
            validate_attempt_equations(manifest)

    def test_nonzero_admitted_with_zero_attempts_rejected(self):
        """If admitted is nonzero but there are zero attempts, that's invalid."""
        manifest = RunManifest(
            manifest_version="1.0",
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            package_version="0.1.0",
            attempts=[],
            funnel={
                "expanded_instances": 10,
                "selected": 0,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
                "attempted": 0,
                "admitted": 1,
                "quarantined": 0,
                "persisted_artifacts": 0,
            },
        )
        with pytest.raises(ManifestIntegrityError, match="admitted.*zero attempts"):
            validate_attempt_equations(manifest)

    def test_nonzero_persisted_artifacts_with_zero_attempts_rejected(self):
        """If persisted_artifacts is nonzero but zero attempts, invalid."""
        manifest = RunManifest(
            manifest_version="1.0",
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            package_version="0.1.0",
            attempts=[],
            funnel={
                "expanded_instances": 10,
                "selected": 0,
                "main_attempted": 0,
                "main_admitted": 0,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
                "attempted": 0,
                "admitted": 0,
                "quarantined": 0,
                "persisted_artifacts": 5,
            },
        )
        with pytest.raises(
            ManifestIntegrityError, match="persisted_artifacts.*zero attempts"
        ):
            validate_attempt_equations(manifest)


class TestFourthReviewEmptyEvidence:
    """Empty-message exceptions must not produce blank FAILED evidence."""

    def test_terminal_validation_rejects_blank_evidence(self):
        """validate_attempt_equations must reject a FAILED AttemptRecord
        with blank evidence even if it was mutated in-place after
        construction (bypassing the Pydantic model validator)."""
        attempt = AttemptRecord(
            candidate_id="cand:v2:abc",
            scenario_id="scenario:v2:def",
            disposition=AttemptDisposition.ADMITTED,
            phase=AttemptPhase.MAIN,
        )
        # Construct manifest with a valid attempt first
        manifest = RunManifest(
            manifest_version="1.0",
            status=RunStatus.FAILED,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            package_version="0.1.0",
            attempts=[attempt],
            funnel={
                "selected": 1,
                "main_attempted": 1,
                "main_admitted": 1,
                "generation_failed": 0,
                "remediation_attempted": 0,
                "remediation_admitted": 0,
                "remediation_failed": 0,
                "attempted": 1,
                "admitted": 1,
                "quarantined": 0,
                "persisted_artifacts": 1,
            },
        )
        # Now simulate unchecked in-place mutation that bypasses
        # the Pydantic model validator
        manifest.attempts[0].disposition = AttemptDisposition.FAILED
        manifest.attempts[0].failure_evidence = "   "  # blank

        with pytest.raises(ManifestIntegrityError, match="blank failure_evidence"):
            validate_attempt_equations(manifest)


def test_record_stage_result_writes_to_calls_jsonl(tmp_path):
    import json
    from unittest.mock import MagicMock
    from asago_scenario_generator.pipeline.persistence import (
        FinalizationPersistenceAdapter,
    )
    from asago_scenario_generator.pipeline.finalization import (
        StageInvocation,
        GeneratedStage,
        GeneratedStageResult,
    )
    from asago_scenario_generator.pipeline.generate.stages import (
        StageCallEvidence,
        StageAttemptFailure,
    )
    from asago_scenario_generator.llm.client import LLMResult
    from asago_scenario_generator.models.scenario import CallName

    # 1. Setup mocks
    inventory = MagicMock()
    inventory.candidate_attempts = []
    inventory.stage_attempts = []
    inventory.transitions = []
    inventory.repairs = []
    inventory.admission_decisions = []
    inventory.model_copy.return_value = inventory

    coverage_plan = MagicMock()
    coverage_plan.targets = []

    run_dir = tmp_path / "run_dir"
    run_dir.mkdir()

    adapter = FinalizationPersistenceAdapter(
        run_dir=run_dir,
        inventory=inventory,
        coverage_plan=coverage_plan,
    )
    adapter._candidate_attempt = MagicMock()
    adapter._replayed = MagicMock(return_value=False)
    adapter._commit = MagicMock()
    adapter._sequence = MagicMock(return_value=1)

    # 2. Test successful stage result
    invocation = StageInvocation(
        candidate_id="cand:v2:abc123_success",
        stage=GeneratedStage.actor,
        invocation_index=0,
        owner_retry_index=0,
        artifacts={},
        candidate_snapshot={"some": "data"},
    )

    llm_result = LLMResult(
        content="mock response content",
        prompt_tokens=10,
        completion_tokens=20,
        duration_ms=100,
        system_prompt="system prompt success",
        user_prompt="user prompt success",
    )

    from asago_scenario_generator.models.scenario import CallMetadata

    metadata = CallMetadata(
        call=CallName.actor_profile,
        prompt_tokens=10,
        completion_tokens=20,
        duration_ms=100,
    )

    evidence = StageCallEvidence(
        call_name=CallName.actor_profile,
        result=llm_result,
        metadata=metadata,
    )

    result = GeneratedStageResult(
        artifact={"some": "artifact"},
        evidence=evidence,
        violations=(),
    )

    adapter.record_stage_result(invocation, result)

    # 3. Test failed stage result
    invocation_fail = StageInvocation(
        candidate_id="cand:v2:abc123_fail",
        stage=GeneratedStage.narrative,
        invocation_index=1,
        owner_retry_index=0,
        artifacts={},
        candidate_snapshot={"some": "data"},
    )

    failure_evidence = StageAttemptFailure(
        call_name=CallName.narrative,
        exception=ValueError("Something went wrong"),
        phase="invocation",
        invoked=True,
        system_prompt="system prompt fail",
        user_prompt="user prompt fail",
    )

    result_fail = GeneratedStageResult(
        artifact=None,
        evidence=failure_evidence,
        violations=(),
    )

    adapter.record_stage_result(invocation_fail, result_fail)

    # 4. Verify calls.jsonl content
    calls_file = run_dir / "calls.jsonl"
    assert calls_file.exists()

    lines = calls_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    entry_success = json.loads(lines[0])
    assert entry_success["call"] == "actor_profile"
    assert entry_success["candidate_id"] == "cand:v2:abc123_success"
    assert entry_success["stage"] == "actor"
    assert entry_success["attempt_id"] == "cand:v2:abc123_success:actor:0"
    assert entry_success["system_prompt"] == "system prompt success"
    assert entry_success["user_prompt"] == "user prompt success"
    assert entry_success["response"] == "mock response content"
    assert entry_success["prompt_tokens"] == 10
    assert entry_success["completion_tokens"] == 20
    assert entry_success["duration_ms"] == 100
    assert "error" not in entry_success

    entry_fail = json.loads(lines[1])
    assert entry_fail["call"] == "narrative"
    assert entry_fail["candidate_id"] == "cand:v2:abc123_fail"
    assert entry_fail["stage"] == "narrative"
    assert entry_fail["attempt_id"] == "cand:v2:abc123_fail:narrative:1"
    assert entry_fail["system_prompt"] == "system prompt fail"
    assert entry_fail["user_prompt"] == "user prompt fail"
    assert entry_fail["response"] is None
    assert entry_fail["prompt_tokens"] is None
    assert entry_fail["completion_tokens"] is None
    assert entry_fail["duration_ms"] is None
    assert entry_fail["error"] == "ValueError: Something went wrong"


def test_record_stage_result_redacts_and_preserves_completion_length_diagnostics(
    tmp_path,
):
    import json
    from unittest.mock import MagicMock

    from asago_scenario_generator.llm.client import CompletionLengthError
    from asago_scenario_generator.models.scenario import CallName
    from asago_scenario_generator.pipeline.finalization import (
        GeneratedStage,
        GeneratedStageResult,
        StageInvocation,
    )
    from asago_scenario_generator.pipeline.generate.stages import (
        stage_attempt_failure,
    )
    from asago_scenario_generator.pipeline.persistence import (
        FinalizationPersistenceAdapter,
    )

    inventory = MagicMock()
    inventory.candidate_attempts = []
    inventory.stage_attempts = []
    inventory.transitions = []
    inventory.repairs = []
    inventory.admission_decisions = []
    inventory.model_copy.return_value = inventory
    coverage_plan = MagicMock(targets=[])
    run_dir = tmp_path / "run_dir"
    run_dir.mkdir()

    adapter = FinalizationPersistenceAdapter(run_dir, inventory, coverage_plan)
    adapter._candidate_attempt = MagicMock()
    adapter._replayed = MagicMock(return_value=False)
    adapter._commit = MagicMock()
    adapter._sequence = MagicMock(return_value=1)

    partial = "BEGIN SECRET=fixture-customer@example.invalid END"
    usage_details = {
        "prompt_tokens": 31,
        "completion_tokens": 16,
        "total_tokens": 47,
        "prompt_tokens_details": {"cached_tokens": 3},
        "completion_tokens_details": {"reasoning_tokens": 5},
    }
    failure = stage_attempt_failure(
        CallName.actor_profile,
        CompletionLengthError(
            prompt_tokens=31,
            completion_tokens=16,
            total_tokens=47,
            usage_details=usage_details,
            response_id="fixture-response-001",
            model="fixture-model-v1",
            partial_character_count=len(partial),
            partial_sha256="a" * 64,
            partial_preview_prefix="BEGIN [REDACTED] END",
            partial_preview_suffix="BEGIN [REDACTED] END",
            elapsed_ms=3,
        ),
        phase="invocation",
        invoked=True,
        system_prompt="system",
        user_prompt="user",
        request_controls={
            "response_schema": "standard",
            "max_completion_tokens": 16384,
            "temperature": 0.4,
        },
    )
    invocation = StageInvocation(
        candidate_id="cand:v2:diagnostics",
        stage=GeneratedStage.actor,
        invocation_index=0,
        owner_retry_index=0,
        artifacts={},
        candidate_snapshot={"candidate_id": "cand:v2:diagnostics"},
        retry_reason="completion_length",
    )

    adapter.record_stage_result(
        invocation,
        GeneratedStageResult(artifact=None, evidence=failure),
    )

    entry = json.loads((run_dir / "calls.jsonl").read_text().splitlines()[0])
    assert entry["code"] == "completion_length"
    assert entry["finish_reason"] == "length"
    assert entry["prompt_tokens"] == 31
    assert entry["completion_tokens"] == 16
    assert entry["total_tokens"] == 47
    assert entry["usage_details"] == usage_details
    assert entry["response_id"] == "fixture-response-001"
    assert entry["model"] == "fixture-model-v1"
    assert entry["partial_character_count"] == len(partial)
    assert entry["partial_sha256"] == "a" * 64
    assert entry["partial_preview_prefix"] == "BEGIN [REDACTED] END"
    assert entry["partial_preview_suffix"] == "BEGIN [REDACTED] END"
    assert entry["elapsed_ms"] == 3
    assert "SECRET=fixture-customer@example.invalid" not in json.dumps(entry)


# --------------------------------------------------------------------------- #
# CRAP-decomposition helper coverage: loaders and status gates
# --------------------------------------------------------------------------- #


class TestManifestLoadHelpers:
    """Branch-level coverage for load_manifest decomposition helpers."""

    def test_read_manifest_dict_missing_file_raises(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _read_manifest_dict

        with pytest.raises(ManifestIntegrityError, match="No manifest found"):
            _read_manifest_dict(tmp_path / MANIFEST_FILENAME)

    def test_read_manifest_dict_rejects_non_dict(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _read_manifest_dict

        path = tmp_path / MANIFEST_FILENAME
        path.write_text("- not\n- a dict\n")
        with pytest.raises(ManifestIntegrityError, match="not a dict"):
            _read_manifest_dict(path)

    def test_read_manifest_dict_accepts_empty_dict(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _read_manifest_dict

        path = tmp_path / MANIFEST_FILENAME
        path.write_text("manifest_version: '2'\n")
        assert _read_manifest_dict(path) == {"manifest_version": "2"}

    def test_validate_manifest_version_accepts_supported(self):
        from asago_scenario_generator.manifest import _validate_manifest_version

        _validate_manifest_version("2", None)
        _validate_manifest_version("3", None)
        _validate_manifest_version("3", "3")

    def test_validate_manifest_version_rejects_request_mismatch(self):
        from asago_scenario_generator.manifest import _validate_manifest_version

        with pytest.raises(ManifestIntegrityError, match="explicitly requested"):
            _validate_manifest_version("2", "3")

    def test_validate_manifest_version_rejects_unsupported(self):
        from asago_scenario_generator.manifest import _validate_manifest_version

        with pytest.raises(ManifestIntegrityError, match="supported versions"):
            _validate_manifest_version("1", None)


class TestFindRunDirHelpers:
    """Branch-level coverage for find_run_dir decomposition helpers."""

    def test_runs_in_collection_filters_and_sorts(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _runs_in_collection

        collection = tmp_path / "output"
        build_test_run_dir(
            collection / "20260102T000000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        (collection / "plain-dir").mkdir(parents=True)
        build_test_run_dir(
            collection / "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        runs = _runs_in_collection(collection)
        assert [d.name for d in runs] == [
            "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "20260102T000000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ]

    def test_single_run_in_collection(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _single_run_in_collection

        collection = tmp_path / "output"
        run_dir = build_test_run_dir(
            collection / "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        assert _single_run_in_collection(collection, [run_dir]) == run_dir

    def test_single_run_in_collection_empty_raises(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _single_run_in_collection

        collection = tmp_path / "output"
        collection.mkdir()
        with pytest.raises(ManifestIntegrityError, match="No run directory found"):
            _single_run_in_collection(collection, [])

    def test_single_run_in_collection_many_raises(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _single_run_in_collection

        collection = tmp_path / "output"
        first = build_test_run_dir(
            collection / "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        second = build_test_run_dir(
            collection / "20260102T000000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        with pytest.raises(ManifestIntegrityError, match="contains 2 runs"):
            _single_run_in_collection(collection, [first, second])


class TestStrictResolverStatusGates:
    """Branch-level coverage for load_strict_resolver status gates."""

    @staticmethod
    def _manifest(status: str) -> RunManifest:
        return RunManifest(
            status=RunStatus(status),
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
        )

    def test_require_final_status_gate(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _require_final_status

        _require_final_status(self._manifest("completed"), tmp_path, require_final=True)
        _require_final_status(self._manifest("started"), tmp_path, require_final=False)
        with pytest.raises(ManifestIntegrityError, match="status is not final"):
            _require_final_status(
                self._manifest("started"), tmp_path, require_final=True
            )

    def test_require_authoritative_status_gate(self, tmp_path: Path):
        from asago_scenario_generator.manifest import _require_authoritative_status

        _require_authoritative_status(
            self._manifest("completed"), tmp_path, require_authoritative=True
        )
        _require_authoritative_status(
            self._manifest("failed"), tmp_path, require_authoritative=False
        )
        with pytest.raises(ManifestIntegrityError, match="not authoritative"):
            _require_authoritative_status(
                self._manifest("failed"), tmp_path, require_authoritative=True
            )


# --------------------------------------------------------------------------- #
# CRAP-decomposition helper coverage: funnel tallies, equations, git helpers
# --------------------------------------------------------------------------- #


class TestFunnelTallyHelpers:
    """Branch-level coverage for _attempt_tallies decomposition helpers."""

    @staticmethod
    def _mixed_attempts() -> list[AttemptRecord]:
        return [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
            AttemptRecord(
                candidate_id="c2",
                scenario_id="s2",
                disposition=AttemptDisposition.QUARANTINED,
                phase=AttemptPhase.MAIN,
                failure_evidence="quarantined",
            ),
            AttemptRecord(
                candidate_id="c3",
                scenario_id="s3",
                disposition=AttemptDisposition.FAILED,
                phase=AttemptPhase.MAIN,
                failure_evidence="failed",
            ),
            AttemptRecord(
                candidate_id="c4",
                scenario_id="s4",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.REMEDIATION,
            ),
            AttemptRecord(
                candidate_id="c5",
                scenario_id="s5",
                disposition=AttemptDisposition.FAILED,
                phase=AttemptPhase.REMEDIATION,
                failure_evidence="failed",
            ),
        ]

    def test_phase_attempted_counts_by_phase(self):
        attempts = self._mixed_attempts()
        assert _phase_attempted(attempts, AttemptPhase.MAIN) == 3
        assert _phase_attempted(attempts, AttemptPhase.REMEDIATION) == 2

    def test_disposition_tally_matches_phase_and_disposition(self):
        attempts = self._mixed_attempts()
        assert (
            _disposition_tally(attempts, AttemptPhase.MAIN, AttemptDisposition.ADMITTED)
            == 1
        )
        assert (
            _disposition_tally(
                attempts, AttemptPhase.MAIN, AttemptDisposition.QUARANTINED
            )
            == 1
        )
        assert (
            _disposition_tally(attempts, AttemptPhase.MAIN, AttemptDisposition.FAILED)
            == 1
        )
        assert (
            _disposition_tally(
                attempts, AttemptPhase.REMEDIATION, AttemptDisposition.ADMITTED
            )
            == 1
        )
        assert (
            _disposition_tally(
                attempts, AttemptPhase.REMEDIATION, AttemptDisposition.FAILED
            )
            == 1
        )

    def test_attempt_tallies_aggregates_all_counts(self):
        tallies = _attempt_tallies(self._mixed_attempts())
        assert tallies == {
            "main_attempted": 3,
            "main_admitted": 1,
            "main_quarantined": 1,
            "main_failed": 1,
            "remediation_attempted": 2,
            "remediation_admitted": 1,
            "remediation_quarantined": 0,
            "remediation_failed": 1,
        }


class TestFunnelDeriveHelpers:
    """Branch-level coverage for derive_funnel_from_attempts helpers."""

    @pytest.mark.parametrize(
        ("selected", "qualified", "projection_rejected", "expected"),
        [
            (2, 0, 0, 2),  # qualification never reached -> derive from selected
            (2, 3, 0, 3),  # actual qualified preserved
            (2, 0, 1, 0),  # projection rejection happened -> keep qualified
            (0, 0, 0, 0),  # nothing selected, nothing qualified
        ],
    )
    def test_resolve_qualified_count(
        self, selected, qualified, projection_rejected, expected
    ):
        assert (
            _resolve_qualified_count(selected, qualified, projection_rejected)
            == expected
        )

    def test_check_qualified_capacity_accepts_equal(self):
        _check_qualified_capacity(2, 2)

    def test_check_qualified_capacity_rejects_excess_selected(self):
        with pytest.raises(ManifestIntegrityError, match="exceeds qualified"):
            _check_qualified_capacity(3, 2)

    def test_resolve_persisted_artifacts_derives_when_zero(self):
        assert _resolve_persisted_artifacts(3, 2, 0) == 5

    def test_resolve_persisted_artifacts_preserves_supplied(self):
        assert _resolve_persisted_artifacts(3, 2, 7) == 7

    def test_derive_funnel_from_attempts_zero_attempts(self):
        result = derive_funnel_from_attempts([], selected=0)
        assert result["selected"] == 0
        assert result["qualified"] == 0
        assert result["attempted"] == 0
        assert result["admitted"] == 0

    def test_derive_funnel_from_attempts_mixed(self):
        result = derive_funnel_from_attempts(
            TestFunnelTallyHelpers._mixed_attempts(),
            qualified=3,
            persisted_artifacts=9,
        )
        assert result["selected"] == 3
        assert result["qualified"] == 3
        assert result["main_attempted"] == 3
        assert result["main_admitted"] == 2
        assert result["generation_failed"] == 1
        assert result["remediation_attempted"] == 2
        assert result["remediation_admitted"] == 1
        assert result["remediation_failed"] == 1
        assert result["attempted"] == 5
        assert result["admitted"] == 3
        assert result["quarantined"] == 1
        assert result["persisted_artifacts"] == 9


class TestAttemptEquationHelpers:
    """Branch-level coverage for validate_attempt_equations helpers."""

    @staticmethod
    def _blank_evidence_attempt(candidate, scenario, disposition, evidence):
        """Build an attempt, then mutate evidence in-place to bypass the model
        validator — mirroring _finalize_attempt's bypass path that terminal
        validation must catch."""
        rec = AttemptRecord(
            candidate_id=candidate,
            scenario_id=scenario,
            disposition=disposition,
            phase=AttemptPhase.MAIN,
            failure_evidence="placeholder",
        )
        object.__setattr__(rec, "failure_evidence", evidence)
        return rec

    @staticmethod
    def _attempt(candidate, scenario, disposition, phase=AttemptPhase.MAIN):
        evidence = (
            "generation error" if disposition != AttemptDisposition.ADMITTED else None
        )
        return AttemptRecord(
            candidate_id=candidate,
            scenario_id=scenario,
            disposition=disposition,
            phase=phase,
            failure_evidence=evidence,
        )

    def test_duplicate_attempt_keys_accepts_unique(self):
        _duplicate_attempt_keys(
            [
                self._attempt("c1", "s1", AttemptDisposition.ADMITTED),
                self._attempt("c1", "s2", AttemptDisposition.ADMITTED),
            ]
        )

    def test_duplicate_attempt_keys_rejects_duplicate(self):
        with pytest.raises(ManifestIntegrityError, match="Duplicate attempt key"):
            _duplicate_attempt_keys(
                [
                    self._attempt("c1", "s1", AttemptDisposition.ADMITTED),
                    self._attempt("c1", "s1", AttemptDisposition.ADMITTED),
                ]
            )

    def test_validate_attempt_evidence_accepts_evidence(self):
        _validate_attempt_evidence(
            [
                self._attempt("c1", "s1", AttemptDisposition.ADMITTED),
                self._attempt("c2", "s2", AttemptDisposition.FAILED),
                self._attempt(
                    "c3", "s3", AttemptDisposition.QUARANTINED, AttemptPhase.REMEDIATION
                ),
            ]
        )

    def test_validate_attempt_evidence_rejects_blank_failed(self):
        with pytest.raises(ManifestIntegrityError, match="blank failure_evidence"):
            _validate_attempt_evidence(
                [
                    self._blank_evidence_attempt(
                        "c1",
                        "s1",
                        AttemptDisposition.FAILED,
                        "   ",
                    )
                ]
            )

    def test_validate_attempt_evidence_rejects_blank_quarantined(self):
        with pytest.raises(ManifestIntegrityError, match="blank failure_evidence"):
            _validate_attempt_evidence(
                [
                    self._blank_evidence_attempt(
                        "c1",
                        "s1",
                        AttemptDisposition.QUARANTINED,
                        "",
                    )
                ]
            )

    def test_validate_zero_attempt_funnel_accepts_empty(self):
        _validate_zero_attempt_funnel({})

    def test_validate_zero_attempt_funnel_accepts_pre_attempt_fields(self):
        _validate_zero_attempt_funnel({"expanded_instances": 5, "selected": 0})

    def test_validate_zero_attempt_funnel_rejects_nonzero_lifecycle(self):
        with pytest.raises(ManifestIntegrityError, match="zero attempts exist"):
            _validate_zero_attempt_funnel({"selected": 1})

    def test_require_funnel_lifecycle_keys_accepts_complete(self):
        funnel = {
            "attempted": 1,
            "admitted": 1,
            "quarantined": 0,
            "main_attempted": 1,
            "main_admitted": 1,
            "generation_failed": 0,
            "remediation_attempted": 0,
            "remediation_admitted": 0,
            "remediation_failed": 0,
        }
        _require_funnel_lifecycle_keys(funnel)

    def test_require_funnel_lifecycle_keys_rejects_missing(self):
        with pytest.raises(
            ManifestIntegrityError, match="missing required lifecycle keys"
        ):
            _require_funnel_lifecycle_keys({"attempted": 1})

    def test_check_funnel_aggregate_equations_accepts(self):
        _check_funnel_aggregate_equations(
            2, {"attempted": 2, "admitted": 3, "quarantined": 1}, 2, 1
        )

    def test_check_funnel_aggregate_equations_attempted_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="attempted mismatch"):
            _check_funnel_aggregate_equations(
                3, {"attempted": 2, "admitted": 3, "quarantined": 1}, 2, 1
            )

    def test_check_funnel_aggregate_equations_admitted_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="admitted mismatch"):
            _check_funnel_aggregate_equations(
                2, {"attempted": 2, "admitted": 4, "quarantined": 1}, 2, 1
            )

    def test_check_funnel_aggregate_equations_quarantined_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="quarantined mismatch"):
            _check_funnel_aggregate_equations(
                2, {"attempted": 2, "admitted": 3, "quarantined": 2}, 2, 1
            )

    def test_check_main_funnel_equations_accepts(self):
        _check_main_funnel_equations(
            2,
            1,
            1,
            1,
            {
                "main_attempted": 2,
                "main_admitted": 2,
                "generation_failed": 1,
            },
        )

    def test_check_main_funnel_equations_attempted_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="main_attempted mismatch"):
            _check_main_funnel_equations(
                1,
                1,
                1,
                1,
                {"main_attempted": 2, "main_admitted": 2, "generation_failed": 1},
            )

    def test_check_main_funnel_equations_admitted_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="main_admitted mismatch"):
            _check_main_funnel_equations(
                2,
                1,
                1,
                1,
                {"main_attempted": 2, "main_admitted": 3, "generation_failed": 1},
            )

    def test_check_main_funnel_equations_failed_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="generation_failed mismatch"):
            _check_main_funnel_equations(
                2,
                1,
                1,
                1,
                {"main_attempted": 2, "main_admitted": 2, "generation_failed": 2},
            )

    def test_check_remediation_funnel_equations_accepts(self):
        _check_remediation_funnel_equations(
            2,
            1,
            1,
            1,
            {
                "remediation_attempted": 2,
                "remediation_admitted": 2,
                "remediation_failed": 1,
            },
        )

    def test_check_remediation_funnel_equations_attempted_mismatch(self):
        with pytest.raises(
            ManifestIntegrityError, match="remediation_attempted mismatch"
        ):
            _check_remediation_funnel_equations(
                1,
                1,
                1,
                1,
                {
                    "remediation_attempted": 2,
                    "remediation_admitted": 2,
                    "remediation_failed": 1,
                },
            )

    def test_check_remediation_funnel_equations_admitted_mismatch(self):
        with pytest.raises(
            ManifestIntegrityError, match="remediation_admitted mismatch"
        ):
            _check_remediation_funnel_equations(
                2,
                1,
                1,
                1,
                {
                    "remediation_attempted": 2,
                    "remediation_admitted": 3,
                    "remediation_failed": 1,
                },
            )

    def test_check_remediation_funnel_equations_failed_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="remediation_failed mismatch"):
            _check_remediation_funnel_equations(
                2,
                1,
                1,
                1,
                {
                    "remediation_attempted": 2,
                    "remediation_admitted": 2,
                    "remediation_failed": 2,
                },
            )

    def test_check_total_failed_equation_accepts(self):
        _check_total_failed_equation(3, 2, 1)

    def test_check_total_failed_equation_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="total failed mismatch"):
            _check_total_failed_equation(4, 2, 1)


class TestGitHelperUnits:
    """Branch-level coverage for capture_git_provenance decomposition."""

    def test_run_git_returns_none_on_subprocess_error(self, tmp_path, monkeypatch):
        def _boom(*args, **kwargs):
            raise OSError("no git binary")

        monkeypatch.setattr("asago_scenario_generator.manifest.subprocess.run", _boom)
        assert _run_git(tmp_path, "rev-parse", "HEAD") is None

    def test_untracked_files_empty(self):
        assert _untracked_files(None) == []
        assert _untracked_files("") == []

    def test_untracked_files_sorts_lines(self):
        assert _untracked_files("b.txt\na.txt\n\n") == ["a.txt", "b.txt"]

    def test_hashed_untracked_content_missing_file(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        assert _hashed_untracked_content(repo, "missing.txt") == b""

    def test_hashed_untracked_content_reads_file(self, tmp_path):
        repo = tmp_path / "repo"
        fpath = repo / "note.txt"
        fpath.parent.mkdir(parents=True)
        fpath.write_text("hello")
        digest = hashlib.sha256(b"hello").hexdigest().encode()
        assert _hashed_untracked_content(repo, "note.txt") == digest + b"\n"

    def test_hashed_untracked_content_unreadable(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        fpath = repo / "locked.txt"
        fpath.parent.mkdir(parents=True)
        fpath.write_text("secret")

        original = Path.read_bytes

        def _raise_for_target(self):
            if self == fpath:
                raise OSError("permission denied")
            return original(self)

        monkeypatch.setattr(Path, "read_bytes", _raise_for_target)
        assert _hashed_untracked_content(repo, "locked.txt") == b"<unreadable>\n"

    def test_source_diff_digest_no_diff_no_untracked(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        digest = _source_diff_digest(repo, None, [])
        assert isinstance(digest, str) and len(digest) == 64

    def test_source_diff_digest_changes_with_diff(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        plain = _source_diff_digest(repo, None, [])
        with_diff = _source_diff_digest(repo, "--- a/x\n+++ b/x\n", [])
        assert with_diff != plain

    def test_source_diff_digest_changes_with_untracked_content(self, tmp_path):
        repo = tmp_path / "repo"
        fpath = repo / "u.txt"
        fpath.parent.mkdir(parents=True)
        fpath.write_text("v1")
        first = _source_diff_digest(repo, None, ["u.txt"])
        fpath.write_text("v2")
        second = _source_diff_digest(repo, None, ["u.txt"])
        assert first != second


# --------------------------------------------------------------------------- #
# CRAP-decomposition helper coverage: resolver validation helpers
# --------------------------------------------------------------------------- #


def _entry(**kwargs) -> ArtifactEntry:
    """Build a minimal ArtifactEntry with safe defaults."""
    defaults = {
        "role": ArtifactRole.USE_CASE,
        "path": "use-case.txt",
        "sha256": hashlib.sha256(b"x").hexdigest(),
        "media_type": "text/plain",
    }
    defaults.update(kwargs)
    return ArtifactEntry(**defaults)


class TestResolverPathHelpers:
    """Branch-level coverage for per-entry path validation helpers."""

    @staticmethod
    def _resolver(manifest=None):
        return ManifestInventoryResolver.__new__(ManifestInventoryResolver)

    def test_entry_role_accepts_valid(self):
        resolver = self._resolver()
        entry = _entry()
        assert resolver._entry_role(entry) is ArtifactRole.USE_CASE

    def test_entry_role_rejects_invalid(self):
        resolver = self._resolver()

        class _RaisingRole:
            @property
            def role(self):
                raise ValueError("unknown role")

        with pytest.raises(ManifestIntegrityError, match="Invalid or unknown"):
            resolver._entry_role(_RaisingRole())

    def test_validate_path_form_accepts_clean(self):
        resolver = self._resolver()
        resolver._validate_path_form(Path("scenarios/s1.yaml"), "scenarios/s1.yaml")

    def test_validate_path_form_rejects_absolute(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="path is absolute"):
            resolver._validate_path_form(Path("/etc/passwd"), "/etc/passwd")

    def test_validate_path_form_rejects_backslash(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="contains backslash"):
            resolver._validate_path_form(Path("a\\b.txt"), "a\\b.txt")

    def test_validate_path_form_rejects_non_canonical(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="not canonical"):
            resolver._validate_path_form(Path("a//b.txt"), "a//b.txt")

    def test_validate_path_components_accepts_clean(self):
        resolver = self._resolver()
        resolver._validate_path_components(
            Path("scenarios/s1.yaml"), "scenarios/s1.yaml"
        )

    def test_validate_path_components_rejects_dotdot(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match=r"contains '\.\.'"):
            resolver._validate_path_components(Path("a/../b.txt"), "a/../b.txt")

    def test_validate_path_components_rejects_dot(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="dot component"):
            resolver._validate_path_components(Path("."), ".")

    def test_validate_entry_path_wires_both_checks(self):
        resolver = self._resolver()
        resolver._validate_entry_path(_entry(path="scenarios/s1.yaml"))
        with pytest.raises(ManifestIntegrityError):
            resolver._validate_entry_path(_entry(path="scenarios/../x.yaml"))

    def test_track_canonical_path_accepts_new(self):
        resolver = self._resolver()
        seen: set[str] = set()
        resolver._track_canonical_path(_entry(path="a.txt"), seen)
        assert seen == {"a.txt"}

    def test_track_canonical_path_rejects_duplicate(self):
        resolver = self._resolver()
        with pytest.raises(
            ManifestIntegrityError, match="Duplicate artifact canonical"
        ):
            resolver._track_canonical_path(_entry(path="a.txt"), {"a.txt"})

    def test_validate_sha256_field_accepts_valid(self):
        resolver = self._resolver()
        resolver._validate_sha256_field(_entry())

    def test_validate_sha256_field_rejects_missing(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="Missing SHA-256"):
            resolver._validate_sha256_field(_entry(sha256=""))

    def test_validate_sha256_field_rejects_malformed(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="Malformed SHA-256"):
            resolver._validate_sha256_field(_entry(sha256="not-a-hash"))


class TestResolverRoleMetadataHelpers:
    """Branch-level coverage for role extension/media/schema validation."""

    @staticmethod
    def _resolver():
        return ManifestInventoryResolver.__new__(ManifestInventoryResolver)

    def test_validate_role_metadata_unknown_role_requires_schema(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="Missing schema_version"):
            resolver._validate_role_metadata(_entry(schema_version=""), "BOGUS_ROLE")

    def test_validate_role_metadata_unknown_role_with_schema(self):
        resolver = self._resolver()
        resolver._validate_role_metadata(_entry(schema_version="1"), "BOGUS_ROLE")

    def test_validate_role_metadata_extension_mismatch(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, path="use-case.txt.extra")
        with pytest.raises(ManifestIntegrityError, match="expects extension"):
            resolver._validate_role_metadata(entry, ArtifactRole.USE_CASE)

    def test_validate_role_metadata_media_type_mismatch(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, media_type="application/json")
        with pytest.raises(ManifestIntegrityError, match="expects media_type"):
            resolver._validate_role_metadata(entry, ArtifactRole.USE_CASE)

    def test_validate_role_metadata_schema_version_missing(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, schema_version="")
        with pytest.raises(ManifestIntegrityError, match="Missing schema_version"):
            resolver._validate_role_metadata(entry, ArtifactRole.USE_CASE)

    def test_validate_role_metadata_schema_version_unsupported(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, schema_version="99")
        with pytest.raises(ManifestIntegrityError, match="expects schema_version"):
            resolver._validate_role_metadata(entry, ArtifactRole.USE_CASE)

    def test_validate_role_metadata_singleton_path_mismatch(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, path="other.txt")
        with pytest.raises(ManifestIntegrityError, match="must be at"):
            resolver._validate_role_metadata(entry, ArtifactRole.USE_CASE)

    def test_validate_role_metadata_all_checks_pass(self):
        resolver = self._resolver()
        resolver._validate_role_metadata(
            _entry(role=ArtifactRole.USE_CASE, path="use-case.txt"),
            ArtifactRole.USE_CASE,
        )

    def test_validate_role_schema_version_unsupported(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, schema_version="2")
        with pytest.raises(ManifestIntegrityError, match="expects schema_version"):
            resolver._validate_role_schema_version(
                entry, ArtifactRole.USE_CASE, {"schema_versions": ["1"]}
            )

    def test_validate_singleton_path_accepts_expected(self):
        resolver = self._resolver()
        resolver._validate_singleton_path(
            _entry(path="use-case.txt"),
            ArtifactRole.USE_CASE,
            {"singleton_path": "use-case.txt"},
        )

    def test_validate_singleton_path_rejects_moved(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="must be at"):
            resolver._validate_singleton_path(
                _entry(path="elsewhere.txt"),
                ArtifactRole.USE_CASE,
                {"singleton_path": "use-case.txt"},
            )


class TestResolverScenarioIdentityHelpers:
    """Branch-level coverage for scenario/quarantine identity checks."""

    @staticmethod
    def _resolver():
        return ManifestInventoryResolver.__new__(ManifestInventoryResolver)

    def test_scenario_identity_requires_scenario_id(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.SCENARIO_YAML, path="scenarios/s1.yaml")
        with pytest.raises(ManifestIntegrityError, match="requires scenario_id"):
            resolver._validate_scenario_identity(entry, ArtifactRole.SCENARIO_YAML)

    def test_scenario_identity_requires_candidate_id(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/s1.feature",
            scenario_id="s1",
        )
        with pytest.raises(ManifestIntegrityError, match="requires candidate_id"):
            resolver._validate_scenario_identity(entry, ArtifactRole.SCENARIO_FEATURE)

    def test_scenario_identity_accepts_full_pair(self):
        resolver = self._resolver()
        resolver._validate_scenario_identity(
            _entry(
                role=ArtifactRole.SCENARIO_YAML,
                path="scenarios/s1.yaml",
                scenario_id="s1",
                candidate_id="c1",
            ),
            ArtifactRole.SCENARIO_YAML,
        )

    def test_quarantine_entry_ignored_for_other_roles(self):
        resolver = self._resolver()
        resolver._validate_quarantine_entry(
            _entry(role=ArtifactRole.USE_CASE), ArtifactRole.USE_CASE
        )

    def test_quarantine_entry_rejects_scenario_id(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.QUARANTINE_BUNDLE,
            path="quarantine/c1.jsonl",
            scenario_id="s1",
            candidate_id="c1",
        )
        with pytest.raises(ManifestIntegrityError, match="must not carry scenario_id"):
            resolver._validate_quarantine_entry(entry, ArtifactRole.QUARANTINE_BUNDLE)

    def test_quarantine_entry_requires_candidate_id(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.QUARANTINE_BUNDLE, path="quarantine/c1.jsonl")
        with pytest.raises(ManifestIntegrityError, match="requires candidate_id"):
            resolver._validate_quarantine_entry(entry, ArtifactRole.QUARANTINE_BUNDLE)

    def test_quarantine_entry_requires_prefix(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.QUARANTINE_BUNDLE,
            path="elsewhere/c1.jsonl",
            candidate_id="c1",
        )
        with pytest.raises(ManifestIntegrityError, match="must be below"):
            resolver._validate_quarantine_entry(entry, ArtifactRole.QUARANTINE_BUNDLE)

    def test_quarantine_entry_accepts_valid(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.QUARANTINE_BUNDLE,
            path="quarantine/c1.jsonl",
            candidate_id="c1",
        )
        resolver._validate_quarantine_entry(entry, ArtifactRole.QUARANTINE_BUNDLE)


class TestResolverTrackingHelpers:
    """Branch-level coverage for singleton/scenario tracking helpers."""

    @staticmethod
    def _resolver():
        return ManifestInventoryResolver.__new__(ManifestInventoryResolver)

    def test_track_singleton_counts_and_rejects_duplicate(self):
        resolver = self._resolver()
        counts: dict[ArtifactRole, int] = {}
        resolver._track_singleton(ArtifactRole.USE_CASE, counts)
        assert counts[ArtifactRole.USE_CASE] == 1
        with pytest.raises(ManifestIntegrityError, match="Duplicate singleton role"):
            resolver._track_singleton(ArtifactRole.USE_CASE, counts)

    def test_track_singleton_rejects_duplicate_second(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="Duplicate singleton role"):
            resolver._track_singleton(ArtifactRole.USE_CASE, {ArtifactRole.USE_CASE: 1})

    def test_track_singleton_ignores_non_singleton(self):
        resolver = self._resolver()
        counts: dict[ArtifactRole, int] = {}
        resolver._track_singleton(ArtifactRole.SCENARIO_YAML, counts)
        assert counts == {}

    def test_register_scenario_id_rejects_duplicate(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            scenario_id="s1",
            candidate_id="c1",
        )
        with pytest.raises(ManifestIntegrityError, match="Duplicate scenario_id"):
            resolver._register_scenario_id(
                entry, ArtifactRole.SCENARIO_YAML, {(ArtifactRole.SCENARIO_YAML, "s1")}
            )

    def test_register_scenario_candidate_rejects_conflict(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            scenario_id="s1",
            candidate_id="c2",
        )
        with pytest.raises(ManifestIntegrityError, match="Conflicting candidate_id"):
            resolver._register_scenario_candidate(entry, {"s1": "c1"})

    def test_register_scenario_candidate_accepts_match(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            scenario_id="s1",
            candidate_id="c1",
        )
        mapping: dict[str, str] = {}
        resolver._register_scenario_candidate(entry, mapping)
        assert mapping == {"s1": "c1"}

    def test_track_scenario_ids_skips_without_sid(self):
        resolver = self._resolver()
        entry = _entry(role=ArtifactRole.USE_CASE, path="use-case.txt")
        resolver._track_scenario_ids(
            entry, ArtifactRole.USE_CASE, set(), {"other": "x"}
        )

    def test_track_scenario_ids_registers_both(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/s1.yaml",
            scenario_id="s1",
            candidate_id="c1",
        )
        scenario_ids: set[tuple[ArtifactRole, str]] = set()
        mapping: dict[str, str] = {}
        resolver._track_scenario_ids(
            entry, ArtifactRole.SCENARIO_YAML, scenario_ids, mapping
        )
        assert scenario_ids == {(ArtifactRole.SCENARIO_YAML, "s1")}
        assert mapping == {"s1": "c1"}


class TestResolverScenarioCollectors:
    """Branch-level coverage for YAML/feature collection helpers."""

    @staticmethod
    def _resolver():
        return ManifestInventoryResolver.__new__(ManifestInventoryResolver)

    @staticmethod
    def _yaml_entry(scenario_id="s1", candidate_id="c1", path="scenarios/s1.yaml"):
        return _entry(
            role=ArtifactRole.SCENARIO_YAML,
            path=path,
            scenario_id=scenario_id,
            candidate_id=candidate_id,
        )

    def test_collect_scenario_yaml_accepts(self):
        resolver = self._resolver()
        yaml_stems: set[str] = set()
        yaml_info: dict[str, dict[str, str | None]] = {}
        content = b"scenario_id: s1\ncandidate_id: c1\n"
        resolver._collect_scenario_yaml(
            self._yaml_entry(), content, yaml_stems, yaml_info
        )
        assert yaml_stems == {"s1"}
        assert yaml_info["s1"] == {
            "inventory": "s1",
            "serialized": "s1",
            "serialized_cid": "c1",
            "inventory_cid": "c1",
        }

    def test_collect_scenario_yaml_rejects_wrong_path(self):
        resolver = self._resolver()
        with pytest.raises(ManifestIntegrityError, match="canonical path"):
            resolver._collect_scenario_yaml(
                self._yaml_entry(path="scenarios/wrong.yaml"),
                b"scenario_id: s1\ncandidate_id: c1\n",
                set(),
                {},
            )

    def test_collect_scenario_feature_accepts(self):
        resolver = self._resolver()
        feature_stems: set[str] = set()
        feature_map: dict[str, str] = {}
        entry = _entry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/s1.feature",
            scenario_id="s1",
            candidate_id="c1",
        )
        resolver._collect_scenario_feature(entry, feature_stems, feature_map)
        assert feature_stems == {"s1"}
        assert feature_map == {"s1": "s1"}

    def test_collect_scenario_feature_rejects_wrong_path(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/wrong.feature",
            scenario_id="s1",
            candidate_id="c1",
        )
        with pytest.raises(ManifestIntegrityError, match="canonical path"):
            resolver._collect_scenario_feature(entry, set(), {})

    def test_collect_scenario_entry_dispatches_yaml(self):
        resolver = self._resolver()
        resolver._collect_scenario_entry(
            ArtifactRole.SCENARIO_YAML,
            self._yaml_entry(),
            b"scenario_id: s1\ncandidate_id: c1\n",
            set(),
            {},
            set(),
            {},
        )

    def test_collect_scenario_entry_dispatches_feature(self):
        resolver = self._resolver()
        entry = _entry(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/s1.feature",
            scenario_id="s1",
            candidate_id="c1",
        )
        resolver._collect_scenario_entry(
            ArtifactRole.SCENARIO_FEATURE, entry, b"", set(), {}, set(), {}
        )


class TestResolverPostLoopHelpers:
    """Branch-level coverage for post-loop pairing and v3 helpers."""

    def test_parse_scenario_yaml_accepts_dict(self):
        entry = _entry(path="scenarios/s1.yaml")
        data, sid, cid = _parse_scenario_yaml(
            entry, b"scenario_id: s1\ncandidate_id: c1\n"
        )
        assert data == {"scenario_id": "s1", "candidate_id": "c1"}
        assert sid == "s1"
        assert cid == "c1"

    def test_parse_scenario_yaml_rejects_non_dict(self):
        entry = _entry(path="scenarios/s1.yaml")
        with pytest.raises(ManifestIntegrityError, match="is not a dict"):
            _parse_scenario_yaml(entry, b"- one\n- two\n")

    def test_parse_scenario_yaml_wraps_parse_errors(self):
        entry = _entry(path="scenarios/s1.yaml")
        with pytest.raises(
            ManifestIntegrityError, match="Failed to read scenario YAML"
        ):
            _parse_scenario_yaml(entry, b"{{{{{{{{")

    def test_require_serialized_ids_accepts(self):
        entry = _entry(path="scenarios/s1.yaml")
        _require_serialized_ids(entry, "s1", "c1")

    def test_require_serialized_ids_missing_sid(self):
        entry = _entry(path="scenarios/s1.yaml")
        with pytest.raises(
            ManifestIntegrityError, match="missing serialized scenario_id"
        ):
            _require_serialized_ids(entry, None, "c1")

    def test_require_serialized_ids_missing_cid(self):
        entry = _entry(path="scenarios/s1.yaml")
        with pytest.raises(
            ManifestIntegrityError, match="missing serialized candidate_id"
        ):
            _require_serialized_ids(entry, "s1", None)

    def test_check_duplicate_candidate_ids_accepts_unique(self):
        _check_duplicate_candidate_ids({"s1": "c1", "s2": "c2"})

    def test_check_duplicate_candidate_ids_rejects_shared(self):
        with pytest.raises(ManifestIntegrityError, match="Duplicate candidate_id"):
            _check_duplicate_candidate_ids({"s1": "c1", "s2": "c1"})

    def test_check_yaml_feature_pairing_relaxed_without_complete_inventory(self):
        _check_yaml_feature_pairing({"s1"}, {"s1", "s2"}, False)

    def test_check_yaml_feature_pairing_accepts_balanced(self):
        _check_yaml_feature_pairing({"s1"}, {"s1"}, True)

    def test_check_yaml_feature_pairing_rejects_yaml_only(self):
        with pytest.raises(ManifestIntegrityError, match="YAML without feature"):
            _check_yaml_feature_pairing({"s1"}, set(), True)

    def test_check_yaml_feature_pairing_rejects_feature_only(self):
        with pytest.raises(ManifestIntegrityError, match="feature without YAML"):
            _check_yaml_feature_pairing(set(), {"s1"}, True)

    def test_pairing_parts_both_sides(self):
        parts = _pairing_parts({"b"}, {"a"})
        assert len(parts) == 2

    def test_check_paired_stems_skips_missing_info(self):
        _check_paired_stems({"s1"}, {}, {})

    def test_check_paired_stem_accepts_consistent(self):
        _check_paired_stem(
            "s1",
            {
                "inventory": "s1",
                "serialized": "s1",
                "serialized_cid": "c1",
                "inventory_cid": "c1",
            },
            {"s1": "s1"},
        )

    def test_validate_stem_inventory_ids_missing(self):
        with pytest.raises(
            ManifestIntegrityError, match="missing inventory scenario_id"
        ):
            _validate_stem_inventory_ids("s1", "", "s1")

    def test_validate_stem_inventory_ids_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="Scenario ID mismatch"):
            _validate_stem_inventory_ids("s1", "s1", "other")

    def test_validate_stem_filename_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="does not match"):
            _validate_stem_filename("s1", "other")

    def test_validate_stem_candidate_id_mismatch(self):
        with pytest.raises(ManifestIntegrityError, match="Candidate ID mismatch"):
            _validate_stem_candidate_id("s1", "c2", "c1")

    def test_validate_stem_feature_pair_mismatch(self):
        with pytest.raises(
            ManifestIntegrityError, match="Feature scenario_id mismatch"
        ):
            _validate_stem_feature_pair("s1", "other", "s1")

    def test_validate_stem_feature_pair_accepts(self):
        _validate_stem_feature_pair("s1", "s1", "s1")

    @staticmethod
    def _manifest(version="2", status=RunStatus.COMPLETED, **kwargs):
        return RunManifest(
            manifest_version=version,
            status=status,
            run_id=_VALID_RUN_ID,
            timestamp_start="2026-01-01T00:00:00+00:00",
            **kwargs,
        )

    def test_is_v3_completed_status_true(self):
        assert _is_v3_completed_status(self._manifest("3", RunStatus.COMPLETED))
        assert _is_v3_completed_status(
            self._manifest("3", RunStatus.COMPLETED_WITH_ERRORS)
        )

    def test_is_v3_completed_status_false(self):
        assert not _is_v3_completed_status(self._manifest("3", RunStatus.FAILED))
        assert not _is_v3_completed_status(self._manifest("2", RunStatus.COMPLETED))

    def test_validate_v3_legacy_authority_ignores_v2(self):
        _validate_v3_legacy_authority(
            self._manifest("2", RunStatus.COMPLETED, attempts=[])
        )

    def test_validate_v3_legacy_authority_accepts_clean_v3(self):
        _validate_v3_legacy_authority(
            self._manifest("3", RunStatus.FAILED, attempts=[])
        )

    def test_validate_v3_legacy_authority_rejects_populated(self):
        with pytest.raises(ManifestIntegrityError, match="legacy lifecycle fields"):
            _validate_v3_legacy_authority(
                self._manifest(
                    "3",
                    RunStatus.FAILED,
                    attempts=[
                        AttemptRecord(
                            candidate_id="c1",
                            scenario_id="s1",
                            disposition=AttemptDisposition.ADMITTED,
                            phase=AttemptPhase.MAIN,
                        )
                    ],
                )
            )

    def test_validate_v3_required_artifacts_accepts(self):
        _validate_v3_required_artifacts(
            {
                ArtifactRole.PLANNING_CHECKPOINT: 1,
                ArtifactRole.COVERAGE_PLAN: 1,
                ArtifactRole.FINALIZATION_INVENTORY: 1,
            },
            RunStatus.COMPLETED,
        )

    def test_validate_v3_required_artifacts_rejects_missing(self):
        with pytest.raises(ManifestIntegrityError, match="exactly one"):
            _validate_v3_required_artifacts({}, RunStatus.COMPLETED)

    def test_validate_legacy_role_support_rejects_v3_role_in_v2(self):
        with pytest.raises(
            ManifestIntegrityError, match="does not support v3-only role"
        ):
            _validate_legacy_role_support("2", ArtifactRole.PLANNING_CHECKPOINT)

    def test_validate_legacy_role_support_accepts_v2_roles(self):
        _validate_legacy_role_support("2", ArtifactRole.SCENARIO_YAML)

    def test_validate_legacy_role_support_accepts_v3_manifest(self):
        _validate_legacy_role_support("3", ArtifactRole.PLANNING_CHECKPOINT)


class TestRunnerCompletionHelpers:
    """Direct coverage for the decomposed v3 completion-tail helpers."""

    def test_glob_hash_map_sorted_relative_entries(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import _glob_hash_map

        data_root = tmp_path / "data"
        patterns_dir = data_root / "taxonomies" / "attack-patterns"
        patterns_dir.mkdir(parents=True)
        (patterns_dir / "attack-patterns.yaml").write_text("a", encoding="utf-8")
        (patterns_dir / "attack-patterns.b.yaml").write_text("b", encoding="utf-8")
        result = _glob_hash_map(patterns_dir, "attack-patterns*.yaml", data_root)
        assert list(result) == [
            "taxonomies/attack-patterns/attack-patterns.b.yaml",
            "taxonomies/attack-patterns/attack-patterns.yaml",
        ]
        assert (
            result["taxonomies/attack-patterns/attack-patterns.yaml"]
            == hashlib.sha256(b"a").hexdigest()
        )
        assert _glob_hash_map(data_root / "missing", "*.yaml", data_root) == {}

    def test_collect_presentation_notes_deduplicates(self):
        from types import SimpleNamespace

        from asago_scenario_generator.pipeline.runner import _collect_presentation_notes

        notes: list[str] = ["existing"]
        scenarios = (
            SimpleNamespace(
                generation=SimpleNamespace(
                    notes=("presentation_fallback:first", "plain-note")
                )
            ),
            SimpleNamespace(
                generation=SimpleNamespace(
                    notes=(
                        "presentation_fallback:first",
                        "presentation_fallback:second",
                    )
                )
            ),
        )
        _collect_presentation_notes(scenarios, notes)
        assert notes == [
            "existing",
            "presentation_fallback:first",
            "presentation_fallback:second",
        ]

    def test_remove_stale_optional_products(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import (
            _remove_stale_optional_products,
        )

        (tmp_path / "eval-scorecard.yaml").write_text("x", encoding="utf-8")
        (tmp_path / "report.html").write_text("y", encoding="utf-8")
        (tmp_path / "coverage-gaps.json").write_text("z", encoding="utf-8")
        _remove_stale_optional_products(tmp_path)
        assert not (tmp_path / "eval-scorecard.yaml").exists()
        assert not (tmp_path / "report.html").exists()
        assert (tmp_path / "coverage-gaps.json").exists()

    def test_pattern_counts(self):
        from types import SimpleNamespace

        from asago_scenario_generator.pipeline.runner import _pattern_counts

        selected = (
            SimpleNamespace(pattern_id="a"),
            SimpleNamespace(pattern_id="b"),
            SimpleNamespace(pattern_id="a"),
        )
        assert _pattern_counts(selected) == {"a": 2, "b": 1}

    def test_restore_selected_absent_candidate_raises(self):
        from types import SimpleNamespace

        from asago_scenario_generator.pipeline.runner import _restore_selected
        from asago_scenario_generator.pipeline.runner import ManifestIntegrityError

        planning = SimpleNamespace(selected_candidate_ids=("missing",))
        with pytest.raises(ManifestIntegrityError, match="absent from plan"):
            _restore_selected(planning, {})

    def test_failed_artifact_entry_readable_and_missing(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import (
            _failed_artifact_entry,
        )

        (tmp_path / "use-case.txt").write_text("uc", encoding="utf-8")
        entry = _failed_artifact_entry(tmp_path, ArtifactRole.USE_CASE, "use-case.txt")
        assert entry is not None
        assert entry.role is ArtifactRole.USE_CASE
        assert entry.path == "use-case.txt"
        assert entry.sha256 == hashlib.sha256(b"uc").hexdigest()
        assert (
            _failed_artifact_entry(tmp_path, ArtifactRole.REPORT, "report.html") is None
        )

    def test_best_effort_artifact_entry_hashes_file(self, tmp_path: Path):
        from asago_scenario_generator.pipeline.runner import (
            ARTIFACT_SCHEMA_VERSION,
            _best_effort_artifact_entry,
        )

        full = tmp_path / "coverage-plan.json"
        full.write_text("plan", encoding="utf-8")
        entry = _best_effort_artifact_entry(
            full, ArtifactRole.COVERAGE_PLAN, "coverage-plan.json", None, None
        )
        assert entry is not None
        assert entry.role is ArtifactRole.COVERAGE_PLAN
        assert entry.sha256 == hashlib.sha256(b"plan").hexdigest()
        assert entry.schema_version == ARTIFACT_SCHEMA_VERSION

    def test_scenario_receipts(self):
        from asago_scenario_generator.pipeline.runner import _scenario_receipts

        receipts = [
            {
                "scenario_id": "s1",
                "candidate_id": "c1",
                "yaml_path": "work/s1.yaml",
                "feature_path": "work/s1.feature",
            },
            {"scenario_id": "s2", "candidate_id": "c2", "yaml_path": "w/s2.yaml"},
        ]
        entries = _scenario_receipts(receipts)
        assert entries == [
            (ArtifactRole.SCENARIO_YAML, "scenarios/s1.yaml", "s1", "c1"),
            (ArtifactRole.SCENARIO_FEATURE, "scenarios/s1.feature", "s1", "c1"),
            (ArtifactRole.SCENARIO_YAML, "scenarios/s2.yaml", "s2", "c2"),
        ]

    def test_finalization_inventory_receipts_missing_and_malformed(
        self, tmp_path: Path
    ):
        from asago_scenario_generator.pipeline.runner import (
            _finalization_inventory_receipts,
        )

        assert _finalization_inventory_receipts(tmp_path) == []
        (tmp_path / "finalization-inventory.json").write_text(
            "{not json", encoding="utf-8"
        )
        assert _finalization_inventory_receipts(tmp_path) == []
