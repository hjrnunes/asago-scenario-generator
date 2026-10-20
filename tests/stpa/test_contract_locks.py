"""Each producer-owned contract lock pins every file of its contract directory.

Mirrors copy a contract directory byte for byte and check it against this
lock, so a file the lock omits or a stale digest would pass unnoticed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_DIGEST_DOMAIN_V5,
    HANDOFF_SCHEMA_VERSION_V5,
)

DATA = Path(__file__).resolve().parents[2] / "data/contracts"
AUTHORITY = "asago-scenario-generator"

LOCKS = {
    "scenario-handoff": {
        "handoff_schema_version": HANDOFF_SCHEMA_VERSION_V5,
        "digest_domain": HANDOFF_DIGEST_DOMAIN_V5,
    },
    "target-profile": {
        "schema_version": "execution-target-profile-v1",
        "digest_domain": "execution-target-profile-v1",
    },
    "tool-call-condition": {"version": "tool-call-condition-v1"},
    "policy-coverage": {"schema_version": "policy-coverage-v2"},
    "attack-flow": {"schema_version": "attack-flow-2.0.0"},
    "model-profile": {"version": "model-profile-v1"},
}


@pytest.mark.parametrize("contract", sorted(LOCKS))
def test_lock_names_its_contract_and_pins_every_file(contract: str) -> None:
    root = DATA / contract
    lock = json.loads((root / "CONTRACT.lock").read_text(encoding="utf-8"))
    on_disk = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != "CONTRACT.lock"
    }

    assert lock["contract"] == contract
    assert lock["authority"] == AUTHORITY
    assert {key: lock.get(key) for key in LOCKS[contract]} == LOCKS[contract]
    assert lock["files"] == on_disk


def test_every_producer_contract_directory_has_a_lock_row() -> None:
    locked = {path.parent.name for path in DATA.glob("*/CONTRACT.lock")}

    assert locked == set(LOCKS)
