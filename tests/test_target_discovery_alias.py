"""The old package path still reaches the target-discovery scanner.

The scanner moved into the ``asago-target-discovery`` workspace member
(``asago_target_discovery``). ``asago_scenario_generator.target_discovery``
keeps the package-root names and every pre-move child module path importable
for one cycle; M9 removes it. A child path loads lazily and resolves to the
same module object in the member, so private names, ``monkeypatch`` targets and
the Typer ``app`` keep working. New code imports ``asago_target_discovery``
only.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import asago_target_discovery
from asago_scenario_generator.target_discovery.cli import app
from asago_target_discovery.cli import app as moved_app

LEGACY = "asago_scenario_generator.target_discovery"
MOVED = "asago_target_discovery"

# The child modules of the pre-move package, in the order of the move.
LEGACY_CHILDREN = (
    "cli",
    "contracts",
    "discovery",
    "llm_interpreter",
    "model_adapter",
    "persistence",
    "prompts",
    "redaction",
    "runtime_contract",
    "transport",
)
MODEL_FACING = frozenset({"llm_interpreter", "prompts", "transport"})

ROOT = Path(__file__).resolve().parents[1]
APP_SRC = ROOT / "src"
MEMBER_SRC = ROOT / "packages" / "asago-target-discovery" / "src"

# Import the old root alone, then the old runtime-contract path. Both must stay
# clear of the model-facing modules, or the pure builder stops being pure.
_PROBE = f"""\
import json, sys
sys.path[:0] = [{str(APP_SRC)!r}, {str(MEMBER_SRC)!r}]
import {LEGACY}
root_only = sorted(sys.modules)
import {LEGACY}.runtime_contract
print(json.dumps({{"root_only": root_only, "with_builder": sorted(sys.modules)}}))
"""


@pytest.fixture(scope="module")
def probe() -> dict[str, list[str]]:
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout)


def test_the_legacy_path_lists_the_same_names() -> None:
    legacy = importlib.import_module(LEGACY)

    assert sorted(legacy.__all__) == sorted(asago_target_discovery.__all__)


@pytest.mark.parametrize("name", sorted(asago_target_discovery.__all__))
def test_the_legacy_path_reaches_the_same_object(name: str) -> None:
    legacy = importlib.import_module(LEGACY)

    assert getattr(legacy, name) is getattr(asago_target_discovery, name)


def test_the_legacy_path_is_not_the_implementation() -> None:
    legacy = importlib.import_module(LEGACY)

    assert legacy is not asago_target_discovery


@pytest.mark.parametrize("child", LEGACY_CHILDREN)
def test_every_legacy_child_module_is_the_moved_module(child: str) -> None:
    legacy = importlib.import_module(f"{LEGACY}.{child}")
    moved = importlib.import_module(f"{MOVED}.{child}")

    assert sys.modules[f"{LEGACY}.{child}"] is moved
    assert legacy is moved
    assert legacy.__name__ == f"{MOVED}.{child}"


def test_the_legacy_cli_module_exposes_the_moved_typer_app() -> None:
    assert app is moved_app


def test_the_legacy_root_loads_no_child_module(probe: dict[str, list[str]]) -> None:
    loaded = probe["root_only"]

    assert LEGACY in loaded
    assert [name for name in loaded if name.startswith(f"{MOVED}.")] == []


@pytest.mark.parametrize("stage", ["root_only", "with_builder"])
def test_the_legacy_paths_load_no_model_facing_module(
    probe: dict[str, list[str]], stage: str
) -> None:
    loaded = probe[stage]

    assert [name for name in loaded if name.rpartition(".")[2] in MODEL_FACING] == []


@pytest.mark.parametrize("stage", ["root_only", "with_builder"])
def test_the_legacy_paths_load_no_stpa_module(
    probe: dict[str, list[str]], stage: str
) -> None:
    loaded = probe[stage]

    assert [
        name for name in loaded if name.startswith("asago_scenario_generator.stpa")
    ] == []


def test_the_legacy_runtime_contract_path_is_the_moved_builder(
    probe: dict[str, list[str]],
) -> None:
    assert f"{LEGACY}.runtime_contract" in probe["with_builder"]
    assert f"{MOVED}.runtime_contract" in probe["with_builder"]
