"""The package's test kit carries the same documents the package reads."""

from __future__ import annotations

from pathlib import Path

from asago_contracts_core.contract import DATA_DIR

KIT_DIR = Path(__file__).resolve().parent / "data" / "scenario-handoff"
INSTALLED_DIR = DATA_DIR / "scenario-handoff"


def test_the_test_kit_carries_the_packaged_contract_without_a_difference() -> None:
    installed = sorted(
        path.relative_to(INSTALLED_DIR)
        for path in INSTALLED_DIR.rglob("*")
        if path.is_file()
    )
    kit = sorted(
        path.relative_to(KIT_DIR) for path in KIT_DIR.rglob("*") if path.is_file()
    )
    assert installed
    assert installed == kit
    for relative in installed:
        assert (INSTALLED_DIR / relative).read_bytes() == (
            KIT_DIR / relative
        ).read_bytes(), relative
