"""The built wheels carry every contract, and an install from them loads each one.

The test builds the application and every workspace member into wheels from this
checkout, installs them into a fresh environment and runs a probe from a directory
outside the checkout in isolated mode. The probe reads each contract through the package
that ships it. The test then compares what the probe found, file by file, with
``data/contracts``, which stays the only maintained source.

A wheel built from the checkout proves what the checkout packages. It does not prove what
a published wheel carries.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "data" / "contracts"
PROJECTS = (
    ROOT,
    *sorted(
        path
        for path in (ROOT / "packages").iterdir()
        if (path / "pyproject.toml").is_file()
    ),
)

# Runs inside the installed environment and prints what the wheels carry.
PROBE = """
import hashlib
import json
from pathlib import Path

import asago_contracts_core
from asago_contracts_core.contract import installed_specs
from asago_scenario_generator.data.paths import DATA_ROOT


def tree(root):
    root = Path(root)
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


print(
    json.dumps(
        {
            "origins": {
                "asago_contracts_core": asago_contracts_core.__file__,
                "asago_scenario_generator data root": str(DATA_ROOT),
            },
            "scenario-handoff": tree(asago_contracts_core.CONTRACT_DIR),
            "contracts": tree(DATA_ROOT / "contracts"),
            "specs": sorted(f"{s.contract} {s.version}" for s in installed_specs().specs),
        }
    )
)
"""


def _tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _drift(source: dict[str, str], installed: dict[str, str]) -> list[str]:
    """Name every file the installed tree lacks, adds or changes against its source."""

    return sorted(
        [
            f"{name} is missing from the wheel"
            for name in source.keys() - installed.keys()
        ]
        + [f"{name} is not in the source" for name in installed.keys() - source.keys()]
        + [
            f"{name} differs"
            for name in source.keys() & installed.keys()
            if source[name] != installed[name]
        ]
    )


def _assert_carries(
    label: str, source: dict[str, str], installed: dict[str, str]
) -> None:
    drift = _drift(source, installed)

    assert not drift, (
        f"{label}: {len(drift)} files differ, among them {'; '.join(drift[:5])}"
    )


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    result = subprocess.run(
        command, cwd=cwd, env=environment, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        pytest.fail(f"{' '.join(command)} exited {result.returncode}:\n{result.stderr}")
    return result.stdout


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    uv = shutil.which("uv")
    assert uv, "uv builds and installs the wheels; put it on PATH"
    work = tmp_path_factory.mktemp("wheels")
    wheels, venv, outside = work / "wheels", work / "venv", work / "outside"
    outside.mkdir()
    for project in PROJECTS:
        _run([uv, "build", "--wheel", "--out-dir", str(wheels), str(project)])
    _run([uv, "venv", "--python", sys.executable, str(venv)])
    python = venv / "bin" / "python"
    _run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            *map(str, sorted(wheels.glob("*.whl"))),
        ]
    )
    return json.loads(_run([str(python), "-I", "-c", PROBE], cwd=outside))


def test_the_install_reads_every_contract_from_outside_the_checkout(
    installed: dict[str, Any],
) -> None:
    for label, origin in installed["origins"].items():
        assert not Path(origin).resolve().is_relative_to(ROOT.resolve()), (
            f"{label} was read from the checkout: {origin}"
        )


def test_the_core_wheel_carries_the_scenario_handoff_contract_byte_for_byte(
    installed: dict[str, Any],
) -> None:
    _assert_carries(
        "asago-contracts-core wheel, scenario-handoff",
        _tree(AUTHORITY / "scenario-handoff"),
        installed["scenario-handoff"],
    )


def test_the_application_wheel_carries_every_contract_byte_for_byte(
    installed: dict[str, Any],
) -> None:
    _assert_carries(
        "asago-scenario-generator wheel, contracts",
        _tree(AUTHORITY),
        installed["contracts"],
    )


def test_the_installed_core_loads_the_scenario_handoff_specs(
    installed: dict[str, Any],
) -> None:
    assert installed["specs"] == ["scenario-handoff scenario-handoff-v1"]


def test_a_missing_data_file_is_named() -> None:
    source = {"a/spec.json": "1", "a/schema.json": "2", "a/README.md": "3"}
    installed = {"a/spec.json": "1", "a/schema.json": "9", "a/extra.json": "4"}

    assert _drift(source, installed) == [
        "a/README.md is missing from the wheel",
        "a/extra.json is not in the source",
        "a/schema.json differs",
    ]
