"""Core journaling mechanics for the finalization persistence adapter."""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from asago_scenario_generator.manifest import ManifestIntegrityError
from asago_scenario_generator.pipeline.finalization_contracts import (
    FinalizationPersistenceError,
)
from .persistence_files import (
    _write_admitted_publication,
    _write_model,
    write_coverage_plan,
    write_finalization_inventory,
    write_quarantine_bundle,
)
from .persistence_common import canonical_json_bytes
from .persistence_journal import (
    AdmittedArtifactPublication,
    FinalizationInventoryV1,
    PersistenceJournalV1,
    QuarantineBundleV1,
)
from .persistence_plan import CoveragePlanV2, CoverageTargetEntry
from .persistence_adapter_state import (
    _admitted_id_for,
    _attempted_ids_for,
    _refresh_state,
    _target_state_and_fallback,
    _target_terminal,
)


@dataclass(frozen=True, slots=True)
class _PersistenceHooks:
    write_model: Callable[..., Any]
    write_quarantine_bundle: Callable[..., Any]
    write_admitted_publication: Callable[..., Any]
    write_finalization_inventory: Callable[..., Any]
    write_coverage_plan: Callable[..., Any]


def _default_persistence_hooks() -> _PersistenceHooks:
    return _PersistenceHooks(
        write_model=_write_model,
        write_quarantine_bundle=write_quarantine_bundle,
        write_admitted_publication=_write_admitted_publication,
        write_finalization_inventory=write_finalization_inventory,
        write_coverage_plan=write_coverage_plan,
    )


class _PersistenceAdapterCore:
    def __init__(
        self,
        run_dir: Path,
        inventory: FinalizationInventoryV1,
        coverage_plan: CoveragePlanV2,
        hooks: _PersistenceHooks | None = None,
    ) -> None:
        self._hooks = hooks or _default_persistence_hooks()
        self.run_dir = Path(run_dir)
        self.inventory = inventory
        self.coverage_plan = coverage_plan
        self._lock = threading.Lock()
        self._candidate_plan = {
            choice.candidate_id: (target.effective_target_id, choice.rank)
            for target in coverage_plan.targets
            for choice in target.ordered_choices
        }
        self._events = {
            item.event_id: item.payload_sha256
            for item in [
                *inventory.candidate_attempts,
                *inventory.stage_attempts,
                *inventory.transitions,
                *inventory.repairs,
                *inventory.admission_decisions,
            ]
        }
        self._failed = False

    def _sequence(self, inventory: FinalizationInventoryV1) -> int:
        return sum(
            len(items)
            for items in (
                inventory.candidate_attempts,
                inventory.stage_attempts,
                inventory.transitions,
                inventory.repairs,
                inventory.admission_decisions,
            )
        )

    def _replayed(self, event_id: str, payload_sha256: str) -> bool:
        existing = self._events.get(event_id)
        if existing is None:
            return False
        if existing != payload_sha256:
            raise ManifestIntegrityError(
                f"Conflicting duplicate persistence event {event_id}"
            )
        return True

    def _derive_plan(self, inventory: FinalizationInventoryV1) -> CoveragePlanV2:
        decisions = {item.candidate_id: item for item in inventory.admission_decisions}
        attempts = sorted(inventory.candidate_attempts, key=lambda item: item.sequence)
        next_targets: list[CoverageTargetEntry] = []
        for target in self.coverage_plan.targets:
            attempted = _attempted_ids_for(target.effective_target_id, attempts)
            admitted = _admitted_id_for(attempted, decisions)
            choice_ids = [item.candidate_id for item in target.ordered_choices]
            terminal = _target_terminal(attempted, decisions)
            state, fallback = _target_state_and_fallback(
                attempted, choice_ids, target, terminal, admitted
            )
            next_targets.append(
                target.model_copy(
                    update={
                        "attempted_candidate_ids": attempted,
                        "admitted_candidate_id": admitted,
                        "target_state": state,
                        "fallback_available": fallback,
                    }
                )
            )
        return CoveragePlanV2.model_validate(
            self.coverage_plan.model_copy(update={"targets": next_targets}).model_dump(
                mode="python"
            )
        )

    def _commit(
        self,
        next_inventory: FinalizationInventoryV1,
        *,
        quarantine_bundle: QuarantineBundleV1 | None = None,
        admitted_publication: AdmittedArtifactPublication | None = None,
    ) -> None:
        if self._failed:
            raise FinalizationPersistenceError(
                "Persistence adapter requires journal recovery before reuse"
            )
        if (self.run_dir / ".finalization-state.json").exists():
            self._failed = True
            raise FinalizationPersistenceError(
                "Unresolved finalization journal must be recovered before another event"
            )
        next_plan = self._derive_plan(next_inventory)
        plan_sha256 = hashlib.sha256(canonical_json_bytes(next_plan)).hexdigest()
        next_inventory = FinalizationInventoryV1.model_validate(
            next_inventory.model_copy(
                update={"coverage_plan_sha256": plan_sha256}
            ).model_dump(mode="python")
        )
        journal = PersistenceJournalV1(
            schema_version="1",
            coverage_plan=next_plan,
            finalization_inventory=next_inventory,
            quarantine_bundle=quarantine_bundle,
            admitted_publication=admitted_publication,
        )
        try:
            self._hooks.write_model(self.run_dir, ".finalization-state.json", journal)
            if quarantine_bundle is not None:
                self._hooks.write_quarantine_bundle(self.run_dir, quarantine_bundle)
            if admitted_publication is not None:
                self._hooks.write_admitted_publication(
                    self.run_dir, admitted_publication
                )
            self._hooks.write_finalization_inventory(self.run_dir, next_inventory)
            self._hooks.write_coverage_plan(self.run_dir, next_plan)
            journal_path = self.run_dir / ".finalization-state.json"
            journal_path.unlink()
            dir_fd = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception as exc:
            self._failed = True
            raise FinalizationPersistenceError(
                f"Finalization state commit failed: {exc}"
            ) from exc
        _refresh_state(self, next_inventory, next_plan)
