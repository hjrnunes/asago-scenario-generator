"""Atomic YAML persistence for the offline Phase 3 challenge ledger."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.challenge_ledger import StpaChallengeLedger

STPA_CHALLENGE_LEDGER_FILENAME = "stpa-obligation-challenge-ledger.yaml"


def write_stpa_challenge_ledger(output_dir: Path, ledger: StpaChallengeLedger) -> Path:
    """Validate, atomically publish, reload, and compare one ledger."""
    ledger.assert_integrity()
    target = Path(output_dir) / STPA_CHALLENGE_LEDGER_FILENAME
    atomic_write_text(target, ledger.to_yaml())
    loaded = StpaChallengeLedger.from_yaml(target.read_bytes())
    if loaded != ledger:
        raise ValueError("persisted STPA challenge ledger changed on round-trip")
    return target


def read_stpa_challenge_ledger(path: Path) -> StpaChallengeLedger:
    """Read and integrity-check the normative challenge-ledger artifact."""
    candidate = Path(path)
    if candidate.name != STPA_CHALLENGE_LEDGER_FILENAME:
        raise ValueError(
            f"expected {STPA_CHALLENGE_LEDGER_FILENAME}, got {candidate.name}"
        )
    return StpaChallengeLedger.from_yaml(candidate.read_bytes())


persist_stpa_challenge_ledger = write_stpa_challenge_ledger

__all__ = [
    "STPA_CHALLENGE_LEDGER_FILENAME",
    "persist_stpa_challenge_ledger",
    "read_stpa_challenge_ledger",
    "write_stpa_challenge_ledger",
]
