"""The package's test kit carries the same documents the package reads."""

from __future__ import annotations

from pathlib import Path

from asago_contracts_core.contract import DATA_DIR

KIT_DIR = Path(__file__).resolve().parent / "data" / "scenario-handoff"
DOCUMENTS = ("ownership-rules.json", "handoff-v5/schema.json")


def test_the_test_kit_carries_the_packaged_documents() -> None:
    for relative in DOCUMENTS:
        assert (DATA_DIR / relative).read_bytes() == (
            KIT_DIR / relative
        ).read_bytes(), relative
