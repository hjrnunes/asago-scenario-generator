"""Behavior of the strict manifest inventory resolver."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator import manifest_resolver
from asago_scenario_generator.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    RunManifest,
    RunStatus,
)
from asago_scenario_generator.manifest_models import _ROLE_METADATA
from asago_scenario_generator.manifest_resolver import (
    ManifestInventoryResolver,
    _parse_scenario_yaml,
    _validate_stem_inventory_ids,
)
from asago_scenario_generator.pipeline.persistence_journal import (
    FinalizationInventoryV1,
)
from asago_scenario_generator.pipeline.persistence_plan import (
    CoveragePlanV2,
    PlanningCheckpointV1,
)
from asago_scenario_generator.pipeline.persistence_summary import (
    build_semantic_generation_summary,
)

RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(
    role: ArtifactRole, path: str, data: bytes, **overrides: Any
) -> tuple[ArtifactEntry, bytes]:
    meta = _ROLE_METADATA[role]
    fields: dict[str, Any] = {
        "role": role,
        "path": path,
        "sha256": _sha(data),
        "media_type": meta["media_type"],
        "schema_version": meta["schema_versions"][0],
    }
    fields.update(overrides)
    return ArtifactEntry(**fields), data


def _resolve(
    run_dir: Path,
    entries: list[tuple[ArtifactEntry, bytes]],
    **manifest_fields: Any,
) -> ManifestInventoryResolver:
    for entry, data in entries:
        target = run_dir / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    fields: dict[str, Any] = {
        "run_id": RUN_ID,
        "timestamp_start": "2026-01-01T00:00:00Z",
        "inventory": [entry for entry, _ in entries],
    }
    fields.update(manifest_fields)
    return ManifestInventoryResolver(run_dir, RunManifest(**fields))


def _use_case() -> tuple[ArtifactEntry, bytes]:
    return _entry(ArtifactRole.USE_CASE, "use-case.txt", b"use case")


def _scenario_pair(
    scenario_id: str = "s1", yaml_text: str | None = None
) -> list[tuple[ArtifactEntry, bytes]]:
    body = yaml_text or f"scenario_id: {scenario_id}\ncandidate_id: c1\n"
    return [
        _entry(
            ArtifactRole.SCENARIO_YAML,
            f"scenarios/{scenario_id}.yaml",
            body.encode(),
            scenario_id=scenario_id,
            candidate_id="c1",
        ),
        _entry(
            ArtifactRole.SCENARIO_FEATURE,
            f"scenarios/{scenario_id}.feature",
            b"Feature: x\n",
            scenario_id=scenario_id,
            candidate_id="c1",
        ),
    ]


# --- _validate_role_metadata ---------------------------------------------------


def test_resolver_accepts_a_well_formed_inventory(tmp_path: Path) -> None:
    resolver = _resolve(tmp_path, [_use_case(), *_scenario_pair()])
    assert [e.scenario_id for e in resolver.scenario_yaml_entries()] == ["s1"]
    assert [e.scenario_id for e in resolver.scenario_feature_entries()] == ["s1"]


def test_resolver_rejects_a_path_with_the_wrong_extension(tmp_path: Path) -> None:
    entry = _entry(ArtifactRole.USE_CASE, "use-case.md", b"x")
    with pytest.raises(ManifestIntegrityError, match="expects extension .txt"):
        _resolve(tmp_path, [entry])


def test_resolver_rejects_the_wrong_media_type(tmp_path: Path) -> None:
    entry = _entry(
        ArtifactRole.USE_CASE, "use-case.txt", b"x", media_type="application/json"
    )
    with pytest.raises(ManifestIntegrityError, match="expects media_type"):
        _resolve(tmp_path, [entry])


def test_resolver_rejects_a_missing_schema_version(tmp_path: Path) -> None:
    entry = _entry(ArtifactRole.USE_CASE, "use-case.txt", b"x", schema_version="")
    with pytest.raises(ManifestIntegrityError, match="Missing schema_version"):
        _resolve(tmp_path, [entry])


def test_resolver_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    entry = _entry(ArtifactRole.USE_CASE, "use-case.txt", b"x", schema_version="9")
    with pytest.raises(ManifestIntegrityError, match="expects schema_version"):
        _resolve(tmp_path, [entry])


def test_resolver_rejects_a_singleton_outside_its_canonical_path(
    tmp_path: Path,
) -> None:
    entry = _entry(ArtifactRole.CAPABILITY_PROFILE, "other.yaml", b"a: 1\n")
    with pytest.raises(
        ManifestIntegrityError, match="must be at 'capability-profile.yaml'"
    ):
        _resolve(tmp_path, [entry])


def test_resolver_requires_a_schema_version_for_roles_without_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ok = _entry(ArtifactRole.USE_CASE, "use-case.txt", b"x")
    bad = _entry(ArtifactRole.USE_CASE, "use-case.txt", b"x", schema_version="")
    monkeypatch.delitem(manifest_resolver._ROLE_METADATA, ArtifactRole.USE_CASE)
    assert _resolve(tmp_path, [ok]).entry_by_role(ArtifactRole.USE_CASE) is not None
    with pytest.raises(ManifestIntegrityError, match="Missing schema_version"):
        _resolve(tmp_path / "bad", [bad])


# --- _validate_quarantine_entry ------------------------------------------------


def _bundle(path: str = "quarantine/a1.json", **overrides: Any) -> tuple[Any, bytes]:
    fields = {"candidate_id": "c1", **overrides}
    return _entry(ArtifactRole.QUARANTINE_BUNDLE, path, b"{}", **fields)


def test_resolver_accepts_a_quarantine_bundle_with_candidate_context(
    tmp_path: Path,
) -> None:
    resolver = _resolve(tmp_path, [_bundle()], manifest_version="3")
    assert len(resolver.entries_by_role(ArtifactRole.QUARANTINE_BUNDLE)) == 1


def test_resolver_rejects_a_quarantine_bundle_with_a_scenario_id(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManifestIntegrityError, match="must not carry scenario_id"):
        _resolve(tmp_path, [_bundle(scenario_id="s1")], manifest_version="3")


def test_resolver_requires_a_candidate_id_on_quarantine_bundles(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManifestIntegrityError, match="requires candidate_id"):
        _resolve(tmp_path, [_bundle(candidate_id=None)], manifest_version="3")


def test_resolver_requires_quarantine_bundles_below_the_quarantine_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManifestIntegrityError, match="must be below 'quarantine/'"):
        _resolve(tmp_path, [_bundle(path="bundle.json")], manifest_version="3")


# --- scenario YAML collection and parsing --------------------------------------


def test_resolver_requires_scenario_yaml_at_its_canonical_path(
    tmp_path: Path,
) -> None:
    yaml_entry, data = _entry(
        ArtifactRole.SCENARIO_YAML,
        "scenarios/other.yaml",
        b"scenario_id: s1\ncandidate_id: c1\n",
        scenario_id="s1",
        candidate_id="c1",
    )
    with pytest.raises(
        ManifestIntegrityError, match="Scenario YAML must be at canonical"
    ):
        _resolve(tmp_path, [(yaml_entry, data)])


def test_resolver_requires_serialized_ids_in_scenario_yaml(tmp_path: Path) -> None:
    entries = _scenario_pair(yaml_text="scenario_id: s1\n")
    with pytest.raises(ManifestIntegrityError, match="missing serialized candidate_id"):
        _resolve(tmp_path, entries)


def test_resolver_rejects_scenario_yaml_that_is_not_a_mapping(tmp_path: Path) -> None:
    entries = _scenario_pair(yaml_text="- just\n- a list\n")
    with pytest.raises(ManifestIntegrityError, match="is not a dict"):
        _resolve(tmp_path, entries)


def _yaml_entry() -> ArtifactEntry:
    return _entry(
        ArtifactRole.SCENARIO_YAML,
        "scenarios/s1.yaml",
        b"",
        scenario_id="s1",
        candidate_id="c1",
    )[0]


def test_parse_scenario_yaml_returns_the_mapping_and_serialized_ids() -> None:
    data, scenario_id, candidate_id = _parse_scenario_yaml(
        _yaml_entry(), b"scenario_id: s1\ncandidate_id: c1\nother: 2\n"
    )
    assert data == {"scenario_id": "s1", "candidate_id": "c1", "other": 2}
    assert (scenario_id, candidate_id) == ("s1", "c1")


def test_parse_scenario_yaml_returns_none_for_absent_ids() -> None:
    assert _parse_scenario_yaml(_yaml_entry(), b"other: 1\n")[1:] == (None, None)


def test_parse_scenario_yaml_rejects_a_non_mapping_body() -> None:
    with pytest.raises(ManifestIntegrityError, match="scenarios/s1.yaml is not a dict"):
        _parse_scenario_yaml(_yaml_entry(), b"42\n")


@pytest.mark.parametrize(
    "content", [b"a: [unclosed\n", b"\xff\xfe"], ids=["bad-yaml", "bad-utf8"]
)
def test_parse_scenario_yaml_wraps_read_failures(content: bytes) -> None:
    with pytest.raises(
        ManifestIntegrityError, match="Failed to read scenario YAML scenarios/s1.yaml"
    ):
        _parse_scenario_yaml(_yaml_entry(), content)


# --- _validate_stem_inventory_ids -----------------------------------------------


def test_stem_inventory_ids_accept_matching_or_unserialized_ids() -> None:
    _validate_stem_inventory_ids("s1", "s1", "s1")
    _validate_stem_inventory_ids("s1", "s1", None)


def test_stem_inventory_ids_require_an_inventory_scenario_id() -> None:
    with pytest.raises(ManifestIntegrityError, match="missing inventory scenario_id"):
        _validate_stem_inventory_ids("s1", "", "s1")


def test_stem_inventory_ids_reject_a_serialized_mismatch() -> None:
    with pytest.raises(ManifestIntegrityError, match="inventory=s1, serialized=other"):
        _validate_stem_inventory_ids("s1", "s1", "other")


# --- _open_artifact --------------------------------------------------------------


def test_open_artifact_returns_content_and_physical_identity(tmp_path: Path) -> None:
    resolver = _resolve(tmp_path, [_use_case(), *_scenario_pair()])
    content, (device, inode) = resolver._open_artifact("scenarios/s1.feature")
    stat = os.stat(tmp_path / "scenarios/s1.feature")
    assert content == b"Feature: x\n"
    assert (device, inode) == (stat.st_dev, stat.st_ino)


def test_open_artifact_runs_the_leaf_hook_before_opening_the_leaf(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.txt").write_bytes(b"x")
    events: list[str] = []
    resolver = manifest_resolver.ManifestInventoryResolver(
        tmp_path,
        RunManifest(run_id=RUN_ID, timestamp_start="2026-01-01T00:00:00Z"),
        check_orphans=False,
        leaf_open_hook=lambda: events.append("hook"),
    )
    assert resolver._open_artifact("a.txt")[0] == b"x"
    assert events == ["hook"]


def test_open_artifact_wraps_a_missing_file(tmp_path: Path) -> None:
    resolver = _resolve(tmp_path, [_use_case()])
    with pytest.raises(
        ManifestIntegrityError, match="Cannot safely read artifact gone"
    ):
        resolver._open_artifact("gone.txt")


def test_open_artifact_refuses_to_follow_a_symlink_leaf(tmp_path: Path) -> None:
    resolver = _resolve(tmp_path, [_use_case()])
    os.symlink(tmp_path / "use-case.txt", tmp_path / "link.txt")
    with pytest.raises(
        ManifestIntegrityError, match="Cannot safely read artifact link"
    ):
        resolver._open_artifact("link.txt")


def test_open_artifact_refuses_to_traverse_a_symlinked_directory(
    tmp_path: Path,
) -> None:
    resolver = _resolve(tmp_path, [_use_case(), *_scenario_pair()])
    os.symlink(tmp_path / "scenarios", tmp_path / "alias")
    with pytest.raises(ManifestIntegrityError, match="Cannot safely read artifact"):
        resolver._open_artifact("alias/s1.feature")


def test_open_artifact_rejects_a_directory_leaf(tmp_path: Path) -> None:
    resolver = _resolve(tmp_path, [_use_case()])
    (tmp_path / "folder").mkdir()
    with pytest.raises(ManifestIntegrityError, match="not a regular file"):
        resolver._open_artifact("folder")


def test_resolver_reports_a_manifested_file_that_does_not_exist(tmp_path: Path) -> None:
    entry, _ = _use_case()
    manifest = RunManifest(
        run_id=RUN_ID, timestamp_start="2026-01-01T00:00:00Z", inventory=[entry]
    )
    with pytest.raises(ManifestIntegrityError, match="Cannot safely read artifact"):
        ManifestInventoryResolver(tmp_path, manifest)


# --- _validate_v3_inventory_integrity --------------------------------------------


def _v3_entries() -> list[tuple[ArtifactEntry, bytes]]:
    checkpoint = PlanningCheckpointV1(
        stage_events=[],
        projection_limitation_target_ids=[],
        selected_candidate_ids=[],
        capped_count=0,
        uncovered_target_ids=[],
        per_pattern_counts={},
        primary_candidate_ids={},
        attempted_candidate_ids=[],
        selection_limitation_target_ids=[],
        fallback_candidate_ids={},
    )
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[],
        selection_limitation_target_ids=[],
    )
    plan_bytes = plan.model_dump_json().encode()
    final = FinalizationInventoryV1(
        schema_version="1",
        run_id=RUN_ID,
        coverage_plan_sha256=_sha(plan_bytes),
        candidate_attempts=[],
        stage_attempts=[],
        transitions=[],
        repairs=[],
        admission_decisions=[],
        admitted_inventory=[],
        quarantine_inventory=[],
    )
    return [
        _entry(
            ArtifactRole.PLANNING_CHECKPOINT,
            "planning-checkpoint.json",
            checkpoint.model_dump_json().encode(),
        ),
        _entry(ArtifactRole.COVERAGE_PLAN, "coverage-plan.json", plan_bytes),
        _entry(
            ArtifactRole.FINALIZATION_INVENTORY,
            "finalization-inventory.json",
            final.model_dump_json().encode(),
        ),
    ]


def _empty_final() -> FinalizationInventoryV1:
    return FinalizationInventoryV1.model_validate_json(_v3_entries()[2][1])


def test_v3_inventory_integrity_accepts_a_consistent_completed_run(
    tmp_path: Path,
) -> None:
    resolver = _resolve(
        tmp_path, _v3_entries(), manifest_version="3", status=RunStatus.COMPLETED
    )
    assert resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY) is not None


def test_v3_inventory_integrity_accepts_a_matching_semantic_generation(
    tmp_path: Path,
) -> None:
    summary = build_semantic_generation_summary(_empty_final())
    _resolve(
        tmp_path,
        _v3_entries(),
        manifest_version="3",
        status=RunStatus.COMPLETED,
        semantic_generation=summary,
    )


def test_v3_inventory_integrity_rejects_a_diverging_semantic_generation(
    tmp_path: Path,
) -> None:
    summary = build_semantic_generation_summary(_empty_final())
    summary["required_stages"] = ["actor"]
    with pytest.raises(
        ManifestIntegrityError,
        match="semantic_generation does not match finalization inventory",
    ):
        _resolve(
            tmp_path,
            _v3_entries(),
            manifest_version="3",
            status=RunStatus.COMPLETED,
            semantic_generation=summary,
        )


def test_v3_inventory_integrity_requires_the_planning_artifacts(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManifestIntegrityError, match="requires exactly one"):
        _resolve(
            tmp_path,
            _v3_entries()[:2],
            manifest_version="3",
            status=RunStatus.COMPLETED,
        )


def test_v3_inventory_integrity_runs_the_persistence_reconciliation(
    tmp_path: Path,
) -> None:
    entries = _v3_entries()
    wrong_run = FinalizationInventoryV1.model_validate_json(entries[2][1]).model_copy(
        update={"run_id": "another-run"}
    )
    entries[2] = _entry(
        ArtifactRole.FINALIZATION_INVENTORY,
        "finalization-inventory.json",
        wrong_run.model_dump_json().encode(),
    )
    with pytest.raises(ManifestIntegrityError, match="run_id mismatch"):
        _resolve(tmp_path, entries, manifest_version="3", status=RunStatus.COMPLETED)
