#!/usr/bin/env python3
"""External artifact QA for the normative system-resource-map sidecar."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPO_ROOT / "src/asago_scenario_generator/stpa/fixtures"
MAP = FIXTURE_ROOT / "system_resource_map_klarna.yaml"
SNAPSHOT = FIXTURE_ROOT / "capability_fact_snapshot_klarna.yaml"
CONTROL = FIXTURE_ROOT / "control_structure_klarna.yaml"


def _command() -> list[str]:
    search_path = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
    uv = shutil.which("uv", path=search_path)
    if uv:
        return [uv, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv/bin/asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _run(output_dir: Path) -> None:
    environment = os.environ.copy()
    environment.pop("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", None)
    environment.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    command = [
        *_command(),
        "validate-system-resource-map",
        "--map",
        str(MAP),
        "--capability-snapshot",
        str(SNAPSHOT),
        "--control-structure",
        str(CONTROL),
        "--output-dir",
        str(output_dir),
        "--format",
        "both",
    ]
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(completed.stderr or completed.stdout)


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="asago-system-resource-map-artifact-"
    ) as directory:
        output = Path(directory)
        _run(output)
        yaml_bytes = (output / "system-resource-map-validation.yaml").read_bytes()
        json_bytes = (output / "system-resource-map-validation.json").read_bytes()
        if not yaml_bytes or not json_bytes:
            raise AssertionError("diagnostic artifacts are empty")
        artifact = yaml.safe_load((output / "system-resource-map.yaml").read_text())
        if artifact["schema_version"] != "system-resource-map-v1":
            raise AssertionError("wrong persisted schema version")
        if not (output / "system-resource-map.yaml").is_file():
            raise AssertionError("normative artifact is missing")
    print("system-resource-map artifact QA: 3/3 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"system-resource-map artifact QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
