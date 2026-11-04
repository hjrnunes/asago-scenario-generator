"""The extraction-ready core carries copies of the producer's contract data."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _sync_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sync_handoff_package_data_under_test",
        ROOT / "scripts" / "sync_handoff_package_data.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_core_carries_the_producer_contract_data() -> None:
    assert _sync_script().main(["--check"]) == 0
