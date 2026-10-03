"""Focused contracts for the acceptance hygiene entry points."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
ACCEPTANCE = ROOT / "acceptance"
sys.path.insert(0, str(ACCEPTANCE))

from snapshot import artifact_paths, snapshot_layout  # noqa: E402


class TestGate:
    def test_quality_script_checks_and_formats_source_trees(self):
        body = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")

        assert "set -euo pipefail" in body
        assert "uv run ruff check src acceptance" in body
        assert "uv run ruff format --check src acceptance" in body

    def test_test_mode_runs_quality_before_generated_tests(self):
        body = (ROOT / "scripts" / "acceptance.sh").read_text(encoding="utf-8")

        gate = body.index('"$root/scripts/quality.sh"')
        pytest = body.index("exec uv run pytest")
        assert "set -euo pipefail" in body
        assert (
            "${SWARMFORGE_ACCEPTANCE_GENERATED_DIR:-build/acceptance/generated}" in body
        )
        assert 'exec uv run pytest "$root/$generated/" -q -s' in body
        assert gate < pytest

    def test_test_mode_stops_when_quality_fails(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        entry = scripts / "acceptance.sh"
        entry.write_text(
            (ROOT / "scripts" / "acceptance.sh").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        entry.chmod(0o755)
        gate = scripts / "quality.sh"
        gate.write_text("#!/usr/bin/env bash\nexit 17\n", encoding="utf-8")
        gate.chmod(0o755)

        result = subprocess.run(
            [str(entry), "--test"],
            cwd=tmp_path,
            check=False,
        )

        assert result.returncode == 17


class TestRuntime:
    def test_manifest_loads_through_acceptance_namespace(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import acceptance.runtime_manifest as manifest; "
                    "assert len(manifest.load_modules()) == len(manifest.MODULES)"
                ),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr

    def test_manifest_loads_valid_step_patterns(self):
        import acceptance_runtime
        import runtime_manifest

        modules = runtime_manifest.load_modules()

        assert (
            tuple(module.FEATURE_ID for module in modules) == runtime_manifest.MODULES
        )
        assert acceptance_runtime.STEP_PATTERNS
        assert all(
            pattern.pattern for pattern, _, _ in acceptance_runtime.STEP_PATTERNS
        )


class TestMapping:
    def test_generated_output_layout(self):
        layout = snapshot_layout()
        paths = artifact_paths("features/group/example.feature")

        assert layout.features_dir == "features"
        assert layout.ir_dir == "build/acceptance/ir"
        assert layout.generated_dir == "build/acceptance/generated"
        assert layout.metadata_dir == "build/acceptance/generated/metadata"
        assert paths.ir_path == "build/acceptance/ir/group/example.json"
        assert (
            paths.test_path == "build/acceptance/generated/example_acceptance_test.py"
        )
