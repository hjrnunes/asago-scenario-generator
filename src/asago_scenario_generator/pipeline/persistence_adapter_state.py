"""Target and event state derivation for the persistence adapter."""

from __future__ import annotations

import os
from pathlib import Path

from .persistence_journal import FinalizationInventoryV1
from .persistence_plan import (
    CoveragePlanV2,
    CoverageTargetEntry,
    QualifiedCandidateRef,
    TargetState,
)


def _violations(values: object) -> list[object]:
    from asago_scenario_generator.pipeline import persistence_validation as validation

    return validation._violations(values)


def _attempted_ids_for(target_id: str, attempts: list[object]) -> list[str]:
    return [
        item.candidate_id
        for item in sorted(attempts, key=lambda item: item.sequence)
        if item.target_entry_point_id == target_id
    ]


def _admitted_id_for(attempted: list[str], decisions: dict[str, object]) -> str | None:
    return next(
        (
            candidate_id
            for candidate_id in attempted
            if candidate_id in decisions and decisions[candidate_id].admitted
        ),
        None,
    )


def _target_terminal(attempted: list[str], decisions: dict[str, object]) -> bool:
    return bool(attempted) and all(
        candidate_id in decisions for candidate_id in attempted
    )


def _target_state_and_fallback(
    attempted: list[str],
    choice_ids: list[str],
    target: CoverageTargetEntry,
    terminal: bool,
    admitted: str | None,
) -> tuple[TargetState, list[QualifiedCandidateRef]]:
    if admitted is not None:
        return TargetState.admitted, []
    if (attempted == choice_ids and terminal) or not choice_ids:
        return TargetState.exhausted, []
    return TargetState.selected, target.ordered_choices[len(attempted) :]


def _fsync_dir(run_dir: Path) -> None:
    dir_fd = os.open(run_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _next_transition_index(transitions: list[object]) -> int:
    return max(item.index for item in transitions) + 1


def _refresh_state(
    adapter: object, next_inventory: FinalizationInventoryV1, next_plan: CoveragePlanV2
) -> None:
    adapter.inventory = next_inventory
    adapter.coverage_plan = next_plan
    adapter._events = {
        item.event_id: item.payload_sha256
        for item in [
            *next_inventory.candidate_attempts,
            *next_inventory.stage_attempts,
            *next_inventory.transitions,
            *next_inventory.repairs,
            *next_inventory.admission_decisions,
        ]
    }
