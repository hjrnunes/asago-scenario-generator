#!/usr/bin/env python3
"""Executable external QA for the normative system-resource-map adapter.

This script deliberately imports no project modules. It drives the optional
CLI with committed, sanitized fixtures and inspects only standard YAML and
filesystem results. It never enables the live-model QA path.
"""

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
QA_ENV = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"


def _command() -> list[str]:
    search_path = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
    uv = shutil.which("uv", path=search_path)
    if uv:
        return [uv, "run", "asago-scenario-generator"]
    executable = REPO_ROOT / ".venv/bin/asago-scenario-generator"
    if executable.is_file():
        return [str(executable)]
    raise RuntimeError("neither uv nor .venv/bin/asago-scenario-generator is available")


def _run(output_dir: Path, map_path: Path = MAP) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop(QA_ENV, None)
    env.pop("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", None)
    return subprocess.run(
        [
            *_command(),
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(SNAPSHOT),
            "--control-structure",
            str(CONTROL),
            "--output-dir",
            str(output_dir),
            "--format",
            "yaml",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _valid_case(root: Path) -> None:
    output = root / "valid"
    completed = _run(output)
    _assert(completed.returncode == 0, completed.stderr or completed.stdout)
    diagnostic = output / "system-resource-map-validation.yaml"
    artifact = output / "system-resource-map.yaml"
    _assert(diagnostic.is_file(), "validation diagnostic was not published")
    _assert(artifact.is_file(), "normative system-resource-map.yaml was not published")
    result = yaml.safe_load(diagnostic.read_text(encoding="utf-8"))
    persisted = yaml.safe_load(artifact.read_text(encoding="utf-8"))
    snapshot = yaml.safe_load(SNAPSHOT.read_text(encoding="utf-8"))
    _assert(result["is_valid"] is True, "valid fixture did not validate")
    _assert(result["violations"] == [], "valid fixture emitted violations")
    _assert(
        result["entry_point_completeness"]
        == snapshot["profile"]["entry_point_completeness"],
        "entry-point inventory completeness was not attested exactly",
    )
    _assert(
        result["tool_inventory_completeness"]
        == snapshot["profile"]["tool_inventory_completeness"],
        "tool inventory completeness was not attested exactly",
    )
    _assert(result["network_calls"] == 0, "validation made network calls")
    _assert(result["model_calls"] == 0, "validation made model calls")
    _assert(persisted["schema_version"] == "system-resource-map-v1", "wrong schema")
    _assert(len(persisted["links"]) == 1, "representative link was lost")


def _tampered_case(root: Path, field: str) -> None:
    payload = yaml.safe_load(MAP.read_text(encoding="utf-8"))
    value = payload[field]
    payload[field] = ("f" if value[0] != "f" else "e") + value[1:]
    tampered = root / f"tampered-{field}.yaml"
    tampered.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    completed = _run(root / f"out-{field}", tampered)
    _assert(completed.returncode != 0, f"tampered {field} unexpectedly passed")


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="asago-system-resource-map-qa-"
    ) as directory:
        root = Path(directory)
        _valid_case(root)
        _tampered_case(root, "semantic_digest")
        _tampered_case(root, "capability_snapshot_digest")
        _tampered_case(root, "control_structure_digest")
    print("system-resource-map external QA: 4/4 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"system-resource-map external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
