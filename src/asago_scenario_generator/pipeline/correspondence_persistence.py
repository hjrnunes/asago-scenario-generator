"""Atomic YAML persistence adapters for Task 3 correspondence artifacts."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.correspondence import (
    ProposalSet,
    ReconciliationResult,
)

CORRESPONDENCE_PROPOSALS_FILENAME = "correspondence-proposals.yaml"
CORRESPONDENCE_RECONCILIATION_FILENAME = "correspondence-reconciliation.yaml"


def write_correspondence_proposals(output_dir: Path, proposals: ProposalSet) -> Path:
    """Atomically publish and reload a canonical proposal artifact."""
    proposals.assert_integrity()
    target = Path(output_dir) / CORRESPONDENCE_PROPOSALS_FILENAME
    atomic_write_text(target, proposals.to_yaml())
    loaded = ProposalSet.from_yaml(target.read_bytes())
    if loaded != proposals:
        raise ValueError(
            "persisted correspondence proposals failed round-trip equality"
        )
    return target


def read_correspondence_proposals(path: Path) -> ProposalSet:
    """Read one canonical proposal artifact."""
    candidate = Path(path)
    if candidate.name != CORRESPONDENCE_PROPOSALS_FILENAME:
        raise ValueError(
            f"expected {CORRESPONDENCE_PROPOSALS_FILENAME}, got {candidate.name}"
        )
    return ProposalSet.from_yaml(candidate.read_bytes())


def write_correspondence_reconciliation(
    output_dir: Path, result: ReconciliationResult
) -> Path:
    """Atomically publish and reload a canonical reconciliation artifact."""
    result.assert_integrity()
    target = Path(output_dir) / CORRESPONDENCE_RECONCILIATION_FILENAME
    atomic_write_text(target, result.to_yaml())
    loaded = ReconciliationResult.from_yaml(target.read_bytes())
    if loaded != result:
        raise ValueError("persisted reconciliation failed round-trip equality")
    return target


def read_correspondence_reconciliation(path: Path) -> ReconciliationResult:
    """Read one canonical reconciliation artifact."""
    candidate = Path(path)
    if candidate.name != CORRESPONDENCE_RECONCILIATION_FILENAME:
        raise ValueError(
            f"expected {CORRESPONDENCE_RECONCILIATION_FILENAME}, got {candidate.name}"
        )
    return ReconciliationResult.from_yaml(candidate.read_bytes())


__all__ = [
    "CORRESPONDENCE_PROPOSALS_FILENAME",
    "CORRESPONDENCE_RECONCILIATION_FILENAME",
    "read_correspondence_proposals",
    "read_correspondence_reconciliation",
    "write_correspondence_proposals",
    "write_correspondence_reconciliation",
]
