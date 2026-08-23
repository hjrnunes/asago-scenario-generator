"""Tests for the pipeline I/O boundary and manifest lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.eval.versioned_metrics import evaluate_v3_scorecard
from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    finalize_manifest,
    generate_sortable_run_id,
    load_manifest,
    load_strict_resolver,
    resolve_run_dir,
    write_manifest_sentinel,
)
from asago_scenario_generator.pipeline.io import (
    get_scenarios_dir,
    write_capability_profile,
    write_eval_scorecard,
    write_pipeline_call_log,
    write_threat_surface,
    write_use_case,
)


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    path = tmp_path / "pipeline-output"
    path.mkdir()
    return path


@pytest.fixture
def minimal_profile():
    """Return a minimal valid CapabilityProfile."""
    from asago_scenario_generator.models.capability_profile import CapabilityProfile

    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["chat input"],
        confidence="high",
        kc_subcodes=["KC1.1"],
    )


@pytest.fixture
def minimal_threat_surface():
    """Return a minimal ThreatSurface with no entries."""
    from asago_scenario_generator.models import ThreatSurface

    return ThreatSurface(entries=[], governance_only=[])


class TestRunSetup:
    def test_resolves_run_and_writes_sentinel_and_use_case(
        self, tmp_path: Path
    ) -> None:
        collection_dir = tmp_path / "collection"
        timestamp_start = datetime.now(UTC).isoformat()

        run_dir, run_id = resolve_run_dir(collection_dir)
        manifest_path = write_manifest_sentinel(run_dir, run_id, timestamp_start)
        use_case_path = write_use_case(run_dir, "An AI chatbot")

        assert run_dir.parent == collection_dir
        assert run_dir.name == run_id
        assert use_case_path.read_text(encoding="utf-8") == "An AI chatbot"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        assert manifest["status"] == "started"
        assert manifest["run_id"] == run_id
        assert manifest["timestamp_start"] == timestamp_start
        assert manifest["manifest_version"] == "2"

    def test_generated_run_id_is_sortable(self) -> None:
        run_id = generate_sortable_run_id()

        assert len(run_id) == 48
        assert run_id[8] == "T"
        assert run_id[15] == "_"
        int(run_id[16:], 16)

    def test_run_directory_collision_raises(self, tmp_path: Path) -> None:
        collection_dir = tmp_path / "collection"
        run_id = generate_sortable_run_id()
        resolve_run_dir(collection_dir, run_id)

        with pytest.raises(FileExistsError):
            resolve_run_dir(collection_dir, run_id)


class TestWriteCapabilityProfile:
    def test_writes_yaml_file(self, run_dir: Path, minimal_profile) -> None:
        path = write_capability_profile(minimal_profile, run_dir)

        assert path == run_dir / "capability-profile.yaml"
        written = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert written["zones_active"] == ["input", "reasoning"]
        assert written["confidence"] == "high"


class TestWriteThreatSurface:
    def test_writes_yaml_file(self, run_dir: Path, minimal_threat_surface) -> None:
        path = write_threat_surface(minimal_threat_surface, run_dir)

        assert path == run_dir / "threat-surface.yaml"
        written = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert written["entries"] == []
        assert written["governance_only"] == []


class TestWritePipelineCallLog:
    def test_writes_and_appends_jsonl(self, run_dir: Path) -> None:
        write_pipeline_call_log([{"call": "first"}], run_dir)
        write_pipeline_call_log([{"call": "second"}], run_dir)

        lines = (run_dir / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2

    def test_noop_on_empty_entries(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "missing-run"

        write_pipeline_call_log([], run_dir)

        assert not run_dir.exists()

    def test_creates_dir_if_missing(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "missing-run"

        write_pipeline_call_log([{"call": "test"}], run_dir)

        assert run_dir.is_dir()


class TestGetScenariosDir:
    def test_returns_scenarios_subdirectory(self, run_dir: Path) -> None:
        result = get_scenarios_dir(run_dir)

        assert result == run_dir / "scenarios"
        assert not result.exists()


class TestFinalizeManifest:
    def test_overwrites_sentinel_with_final_manifest(self, run_dir: Path) -> None:
        run_id = generate_sortable_run_id()
        timestamp_start = "2025-01-01T00:00:00+00:00"
        write_manifest_sentinel(run_dir, run_id, timestamp_start)
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            timestamp_end="2025-01-01T00:01:00+00:00",
            scenarios_generated=5,
        )

        path = finalize_manifest(run_dir, manifest)

        assert path == run_dir / "run-manifest.yaml"
        loaded = load_manifest(run_dir)
        assert loaded.status == RunStatus.COMPLETED
        assert loaded.scenarios_generated == 5
        assert loaded.timestamp_end == "2025-01-01T00:01:00+00:00"

    def test_rejects_non_final_status(self, run_dir: Path) -> None:
        manifest = RunManifest(
            run_id=generate_sortable_run_id(),
            timestamp_start="2025-01-01T00:00:00+00:00",
        )

        with pytest.raises(ValueError, match="non-final status"):
            finalize_manifest(run_dir, manifest)


class TestStrictManifestResolver:
    def _finalize_with_use_case(self, run_dir: Path) -> None:
        run_id = generate_sortable_run_id()
        timestamp_start = "2025-01-01T00:00:00+00:00"
        write_use_case(run_dir, "test use case")
        entry = build_artifact_entry(ArtifactRole.USE_CASE, run_dir, "use-case.txt")
        finalize_manifest(
            run_dir,
            RunManifest(
                status=RunStatus.COMPLETED,
                run_id=run_id,
                timestamp_start=timestamp_start,
                timestamp_end="2025-01-01T00:01:00+00:00",
                inventory=[entry],
            ),
        )

    def test_verifies_inventory_hashes(self, run_dir: Path) -> None:
        self._finalize_with_use_case(run_dir)

        resolver = load_strict_resolver(run_dir)
        entry = resolver.entry_by_role(ArtifactRole.USE_CASE)

        assert entry is not None
        assert resolver.read_text(entry) == "test use case"

        (run_dir / "use-case.txt").write_text("tampered", encoding="utf-8")
        with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
            load_strict_resolver(run_dir)

    def test_detects_orphan_files(self, run_dir: Path) -> None:
        self._finalize_with_use_case(run_dir)
        (run_dir / "orphan.txt").write_text("not inventoried", encoding="utf-8")

        with pytest.raises(ManifestIntegrityError, match="orphan.txt"):
            load_strict_resolver(run_dir)


class TestWriteEvalScorecard:
    def test_writes_yaml_file(self, run_dir: Path) -> None:
        from tests.test_versioned_scorecard import _Resolver

        scorecard = evaluate_v3_scorecard(_Resolver()).model_dump(mode="json")  # type: ignore[arg-type]

        path = write_eval_scorecard(scorecard, run_dir)

        assert path == run_dir / "eval-scorecard.yaml"
        assert yaml.safe_load(path.read_text(encoding="utf-8")) == scorecard
