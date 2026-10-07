"""Snapshot contract for the committed acceptance suite.

Seam: acceptance/snapshot.py public mapping helpers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from generate_entrypoints import generate  # noqa: E402
from refresh_snapshot import refresh_snapshot  # noqa: E402
from snapshot import (  # noqa: E402
    SnapshotError,
    artifact_paths,
    discover_features,
    find_step_data_tables,
    metadata_name,
    snapshot_layout,
    validate_committed_snapshot,
    validate_snapshot,
)


def _configure_fake_aps(tmp_path: Path, monkeypatch) -> None:
    """Give mocked snapshot refreshes a structurally valid external APS root."""
    aps_root = tmp_path / "external-aps"
    aps_root.mkdir()
    (aps_root / "bb.edn").write_text("{}\n")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_APS_ROOT", str(aps_root))


def test_artifact_paths_preserve_feature_subdir():
    paths = artifact_paths("features/critic-revision-fix/critic-gap-detection.feature")

    assert (
        paths.feature_path
        == "features/critic-revision-fix/critic-gap-detection.feature"
    )
    assert (
        paths.ir_path
        == "build/acceptance/ir/critic-revision-fix/critic-gap-detection.json"
    )
    assert (
        paths.test_path
        == "build/acceptance/generated/critic-gap-detection_acceptance_test.py"
    )
    assert paths.metadata_path == (
        "build/acceptance/generated/metadata/critic-gap-detection.json"
    )
    assert (
        paths.dry_path
        == "build/acceptance/dry/critic-revision-fix/critic-gap-detection.txt"
    )


def test_snapshot_layout_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_IR_DIR", "tmp/custom-ir")
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_GENERATED_DIR", "tmp/custom-generated")
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_DRY_DIR", "tmp/custom-dry")

    layout = snapshot_layout()

    assert layout.ir_dir == "tmp/custom-ir"
    assert layout.generated_dir == "tmp/custom-generated"
    assert layout.metadata_dir == "tmp/custom-generated/metadata"
    assert layout.dry_dir == "tmp/custom-dry"
    assert (
        artifact_paths("features/example.feature").ir_path
        == "tmp/custom-ir/example.json"
    )


def test_metadata_name_slugifies_feature_stem():
    assert metadata_name("features/sp1_revision.feature") == "sp1-revision.json"


def test_discover_features_returns_sorted_repo_relative_paths(tmp_path: Path):
    (tmp_path / "features" / "group").mkdir(parents=True)
    (tmp_path / "features" / "zeta.feature").write_text("Feature: Z\n")
    (tmp_path / "features" / "group" / "alpha.feature").write_text("Feature: A\n")
    (tmp_path / "features" / "notes.md").write_text("ignore me\n")

    found = discover_features(tmp_path)

    assert found == [
        "features/group/alpha.feature",
        "features/zeta.feature",
    ]


def test_discover_features_rejects_duplicate_stems(tmp_path: Path):
    (tmp_path / "features" / "a").mkdir(parents=True)
    (tmp_path / "features" / "b").mkdir(parents=True)
    (tmp_path / "features" / "a" / "same.feature").write_text("Feature: A\n")
    (tmp_path / "features" / "b" / "same.feature").write_text("Feature: B\n")

    try:
        discover_features(tmp_path)
    except SnapshotError as exc:
        assert "same" in str(exc)
    else:
        raise AssertionError("expected SnapshotError for duplicate stems")


def test_generate_writes_repo_relative_paths_and_feature_hash(tmp_path: Path):
    feature = tmp_path / "features" / "group" / "example.feature"
    ir = tmp_path / "build" / "acceptance" / "ir" / "group" / "example.json"
    generated = tmp_path / "build" / "acceptance" / "generated"
    feature.parent.mkdir(parents=True)
    ir.parent.mkdir(parents=True)
    generated.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tmp"\n')
    feature.write_text("Feature: Example\n")
    ir.write_text('{"name": "Example", "scenarios": []}\n')

    generate(str(ir), str(generated), feature_path="features/group/example.feature")

    test_file = generated / "example_acceptance_test.py"
    meta_file = generated / "metadata" / "example.json"
    body = test_file.read_text()
    meta = json.loads(meta_file.read_text())

    assert "build/acceptance/ir/group/example.json" in body
    assert '_PROJECT_ROOT / "acceptance"' in body
    assert "_GENERATED_DIR.parent" not in body
    assert "/Users/" not in body
    assert body.count("print(output)") == 2
    assert meta["feature_path"] == "features/group/example.feature"
    assert meta["ir_path"] == "build/acceptance/ir/group/example.json"
    assert meta["generated_files"] == ["example_acceptance_test.py"]
    assert meta["feature_hash"].startswith("sha256:")
    assert meta["implementation_hash"].startswith("sha256:")


def test_refresh_snapshot_writes_mapped_artifacts_and_removes_orphans(
    tmp_path: Path, monkeypatch
):
    _configure_fake_aps(tmp_path, monkeypatch)
    feature = tmp_path / "features" / "group" / "kept.feature"
    feature.parent.mkdir(parents=True)
    feature.write_text("Feature: Kept\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tmp"\n')

    orphan_ir = tmp_path / "build" / "acceptance" / "ir" / "gone.json"
    orphan_test = (
        tmp_path / "build" / "acceptance" / "generated" / "gone_acceptance_test.py"
    )
    orphan_meta = (
        tmp_path / "build" / "acceptance" / "generated" / "metadata" / "gone.json"
    )
    orphan_ir.parent.mkdir(parents=True)
    orphan_test.parent.mkdir(parents=True)
    orphan_meta.parent.mkdir(parents=True)
    orphan_ir.write_text("{}\n")
    orphan_test.write_text("pass\n")
    orphan_meta.write_text("{}\n")

    def fake_run(command, **_kwargs):
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        if "gherkin-parser" in command:
            output.write_text('{"name": "Kept", "scenarios": []}\n')
        else:
            output.write_text("dry ok\n")
        return 0

    monkeypatch.setattr("refresh_snapshot.run_tool", fake_run)

    refresh_snapshot(tmp_path)

    assert (tmp_path / "build" / "acceptance" / "ir" / "group" / "kept.json").is_file()
    assert (tmp_path / "build" / "acceptance" / "dry" / "group" / "kept.txt").is_file()
    assert (
        tmp_path / "build" / "acceptance" / "generated" / "kept_acceptance_test.py"
    ).is_file()
    assert (
        tmp_path / "build" / "acceptance" / "generated" / "metadata" / "kept.json"
    ).is_file()
    assert not orphan_ir.exists()
    assert not orphan_test.exists()
    assert not orphan_meta.exists()


def test_refresh_snapshot_is_ordered_deterministic_and_keeps_unrelated_files(
    tmp_path: Path, monkeypatch
):
    _configure_fake_aps(tmp_path, monkeypatch)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tmp"\n')
    features = tmp_path / "features"
    (features / "group").mkdir(parents=True)
    # Created out of order: refresh must still process alpha before zeta.
    (features / "zeta.feature").write_text("Feature: Zeta\n")
    (features / "group" / "alpha.feature").write_text("Feature: Alpha\n")
    build = tmp_path / "build" / "acceptance"
    (build / "generated").mkdir(parents=True)
    unrelated = build / "generated" / "unrelated.txt"
    unrelated.write_text("preserve me\n")
    processed: list[str] = []

    def fake_run(command, **_kwargs):
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        if "gherkin-parser" in command:
            processed.append(Path(command[1]).relative_to(tmp_path).as_posix())
            output.write_text('{"name": "Feature", "scenarios": []}\n')
        else:
            output.write_text("dry ok\n")
        return 0

    monkeypatch.setattr("refresh_snapshot.run_tool", fake_run)

    def snapshot() -> dict[str, bytes]:
        return {
            path.relative_to(build).as_posix(): path.read_bytes()
            for path in sorted(build.rglob("*"))
            if path.is_file() and path != unrelated
        }

    refresh_snapshot(tmp_path)
    first = snapshot()
    refresh_snapshot(tmp_path)

    assert processed[:2] == ["features/group/alpha.feature", "features/zeta.feature"]
    assert snapshot() == first
    assert unrelated.read_text() == "preserve me\n"
    for name in ("group/alpha", "zeta"):
        stem = name.rsplit("/", 1)[-1]
        meta = json.loads(
            (build / "generated" / "metadata" / f"{stem}.json").read_text()
        )
        assert meta["feature_path"] == f"features/{name}.feature"
        assert meta["ir_path"] == f"build/acceptance/ir/{name}.json"


def test_refresh_snapshot_honors_env_output_dirs(tmp_path: Path, monkeypatch):
    _configure_fake_aps(tmp_path, monkeypatch)
    feature = tmp_path / "features" / "kept.feature"
    feature.parent.mkdir(parents=True)
    feature.write_text("Feature: Kept\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tmp"\n')
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_IR_DIR", "tmp/custom-ir")
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_GENERATED_DIR", "tmp/custom-generated")
    monkeypatch.setenv("SWARMFORGE_ACCEPTANCE_DRY_DIR", "tmp/custom-dry")

    def fake_run(command, **_kwargs):
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        if "gherkin-parser" in command:
            output.write_text('{"name": "Kept", "scenarios": []}\n')
        else:
            output.write_text("dry ok\n")
        return 0

    monkeypatch.setattr("refresh_snapshot.run_tool", fake_run)

    refresh_snapshot(tmp_path)

    assert (tmp_path / "tmp" / "custom-ir" / "kept.json").is_file()
    assert (tmp_path / "tmp" / "custom-generated" / "kept_acceptance_test.py").is_file()
    assert (tmp_path / "tmp" / "custom-dry" / "kept.txt").is_file()


def test_refresh_snapshot_reconstructs_from_empty_build(tmp_path: Path, monkeypatch):
    _configure_fake_aps(tmp_path, monkeypatch)
    feature = tmp_path / "features" / "kept.feature"
    feature.parent.mkdir(parents=True)
    feature.write_text("Feature: Kept\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tmp"\n')

    def fake_run(command, **_kwargs):
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        if "gherkin-parser" in command:
            output.write_text('{"name": "Kept", "scenarios": []}\n')
        else:
            output.write_text("dry ok\n")
        return 0

    monkeypatch.setattr("refresh_snapshot.run_tool", fake_run)

    refresh_snapshot(tmp_path)

    assert (tmp_path / "build" / "acceptance" / "ir" / "kept.json").is_file()
    assert (
        tmp_path / "build" / "acceptance" / "generated" / "kept_acceptance_test.py"
    ).is_file()


def _write_valid_snapshot(root: Path) -> None:
    feature = root / "features" / "group" / "kept.feature"
    feature.parent.mkdir(parents=True)
    feature.write_text("Feature: Kept\n")
    (root / "pyproject.toml").write_text('[project]\nname = "tmp"\n')
    ir = root / "build" / "acceptance" / "ir" / "group" / "kept.json"
    ir.parent.mkdir(parents=True)
    ir.write_text('{"name": "Kept", "scenarios": []}\n')
    generate(
        str(ir),
        str(root / "build" / "acceptance" / "generated"),
        feature_path="features/group/kept.feature",
    )


def test_validate_snapshot_reports_absolute_paths_and_orphans(tmp_path: Path):
    _write_valid_snapshot(tmp_path)
    generated = (
        tmp_path / "build" / "acceptance" / "generated" / "kept_acceptance_test.py"
    )
    generated.write_text(generated.read_text() + 'ABS = "/Users/someone/repo"\n')
    (
        tmp_path / "build" / "acceptance" / "generated" / "metadata" / "gone.json"
    ).write_text("{}\n")

    problems = validate_snapshot(tmp_path)

    assert any("absolute" in problem for problem in problems)
    assert any("orphan" in problem for problem in problems)


def test_validate_snapshot_accepts_complete_relative_tree(tmp_path: Path):
    _write_valid_snapshot(tmp_path)

    assert validate_snapshot(tmp_path) == []


def test_committed_snapshot_has_no_contract_problems():
    problems = validate_committed_snapshot(_PROJECT_ROOT)
    assert problems == []


def test_find_step_data_tables_ignores_examples_blocks(tmp_path: Path):
    feature = tmp_path / "ok.feature"
    feature.write_text(
        "Feature: Ok\n"
        "  Scenario Outline: uses examples\n"
        "    Then the column is <column>\n"
        "    Examples:\n"
        "      | column |\n"
        "      | model  |\n"
    )

    assert find_step_data_tables(feature) == []


def test_find_step_data_tables_reports_step_tables(tmp_path: Path):
    feature = tmp_path / "table.feature"
    feature.write_text(
        "Feature: Table\n"
        "  Background:\n"
        "    Given a table:\n"
        "      | a | b |\n"
        "      | 1 | 2 |\n"
    )

    found = find_step_data_tables(feature)

    assert found
    assert "table.feature" in found[0]


def test_committed_features_have_no_step_data_tables():
    problems = []
    for feature_path in discover_features(_PROJECT_ROOT):
        problems.extend(find_step_data_tables(_PROJECT_ROOT / feature_path))
    assert problems == []
