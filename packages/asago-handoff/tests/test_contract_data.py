"""The package's copies of the contract documents match the producer's authority."""

from __future__ import annotations

from pathlib import Path

from asago_handoff.contract import DATA_DIR

CONTRACT_DIR = (
    Path(__file__).resolve().parents[3] / "data" / "contracts" / "scenario-handoff"
)
DOCUMENTS = ("ownership-rules.json", "handoff-v5/schema.json")


def test_the_package_copies_match_the_producer_contract() -> None:
    for relative in DOCUMENTS:
        assert (DATA_DIR / relative).read_bytes() == (
            CONTRACT_DIR / relative
        ).read_bytes(), relative
