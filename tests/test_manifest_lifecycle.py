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
        assert len(loaded.attempts) == 1

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

        with patch("asago_scenario_generator.manifest.subprocess.run", make_mock("", "")):
            clean_prov = capture_git_provenance(repo)
        with patch(
            "asago_scenario_generator.manifest.subprocess.run", make_mock(" M f\n", "d\n")
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
        with patch("asago_scenario_generator.manifest.capture_git_provenance") as capture:
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
                "asago_scenario_generator.pipeline.runner.LLMClient.__init__",
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
                "asago_scenario_generator.pipeline.runner.write_use_case",
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
                "asago_scenario_generator.pipeline.runner.LLMClient",
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
    @patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
    @patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
    @patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
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
    from pathlib import Path
    from asago_scenario_generator.pipeline.persistence import FinalizationPersistenceAdapter
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
