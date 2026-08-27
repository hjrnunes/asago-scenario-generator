"""Compatibility façade for the Phase 4 persistence contracts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from asago_scenario_generator.manifest import ManifestIntegrityError

from . import (
    persistence_adapter,
    persistence_adapter_admission,
    persistence_adapter_core,
    persistence_adapter_evidence,
    persistence_adapter_events,
    persistence_adapter_state,
    persistence_adapter_terminal,
    persistence_adapter_terminal_methods,
    persistence_artifacts,
    persistence_checkpoint,
    persistence_common,
    persistence_decisions,
    persistence_evidence,
    persistence_files,
    persistence_journal,
    persistence_models,
    persistence_plan,
    persistence_summary,
)
from .persistence_adapter import FinalizationPersistenceAdapter
from .persistence_adapter_core import _PersistenceHooks
from .persistence_adapter_state import _fsync_dir
from .persistence_common import canonical_json_bytes
from .persistence_files import (
    _write_admitted_publication,
    _write_model,
    read_coverage_plan,
    read_finalization_inventory,
    recover_finalization_journal,
    write_coverage_plan,
    write_finalization_inventory,
    write_quarantine_bundle,
)
from .persistence_journal import (
    FinalizationInventoryV1,
    PersistenceJournalV1,
)
from .persistence_plan import CoveragePlanV2


def _facade_hooks() -> _PersistenceHooks:
    """Resolve façade callables at commit time, preserving test seams."""
    return _PersistenceHooks(
        write_model=lambda *args, **kwargs: _write_model(*args, **kwargs),
        write_quarantine_bundle=lambda *args, **kwargs: write_quarantine_bundle(
            *args, **kwargs
        ),
        write_admitted_publication=lambda *args, **kwargs: _write_admitted_publication(
            *args, **kwargs
        ),
        write_finalization_inventory=lambda *args, **kwargs: (
            write_finalization_inventory(*args, **kwargs)
        ),
        write_coverage_plan=lambda *args, **kwargs: write_coverage_plan(
            *args, **kwargs
        ),
    )


def _empty_inventory(run_id: str, coverage_plan_sha256: str) -> FinalizationInventoryV1:
    return FinalizationInventoryV1(
        schema_version="1",
        run_id=run_id,
        coverage_plan_sha256=coverage_plan_sha256,
        candidate_attempts=[],
        stage_attempts=[],
        transitions=[],
        repairs=[],
        admission_decisions=[],
        admitted_inventory=[],
        quarantine_inventory=[],
    )


def _bootstrap_fresh(run_dir: Path, run_id: str, coverage_plan: CoveragePlanV2) -> None:
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    inventory = _empty_inventory(run_id, coverage_plan_sha256)
    journal = PersistenceJournalV1(
        schema_version="1",
        coverage_plan=coverage_plan,
        finalization_inventory=inventory,
    )
    _write_model(run_dir, ".finalization-state.json", journal)
    write_finalization_inventory(run_dir, inventory)
    write_coverage_plan(run_dir, coverage_plan)
    (run_dir / ".finalization-state.json").unlink()
    _fsync_dir(run_dir)


def _recovered_or_validated_plan(
    run_dir: Path, run_id: str, coverage_plan: CoveragePlanV2
) -> CoveragePlanV2:
    recovered_plan = recover_finalization_journal(run_dir, expected_run_id=run_id)
    if recovered_plan is not None:
        coverage_plan = recovered_plan
    return CoveragePlanV2.model_validate(coverage_plan.model_dump(mode="python"))


def _persisted_plan_check(run_dir: Path, coverage_plan: CoveragePlanV2) -> None:
    persisted_plan = read_coverage_plan(run_dir)
    if persisted_plan != coverage_plan:
        raise ManifestIntegrityError(
            "Supplied coverage plan differs from persisted plan"
        )


def _persisted_inventory_check(
    run_dir: Path, run_id: str, coverage_plan_sha256: str
) -> FinalizationInventoryV1:
    inventory = read_finalization_inventory(Path(run_dir))
    if (
        inventory.run_id != run_id
        or inventory.coverage_plan_sha256 != coverage_plan_sha256
    ):
        raise ManifestIntegrityError(
            "Existing finalization inventory identity mismatch"
        )
    return inventory


def make_finalization_persistence_adapter(
    run_dir: Path,
    *,
    run_id: str,
    coverage_plan: CoveragePlanV2,
) -> FinalizationPersistenceAdapter:
    """Phase 5 factory; creates no runner coupling and activates no manifest version."""

    run_dir = Path(run_dir)
    coverage_plan = _recovered_or_validated_plan(run_dir, run_id, coverage_plan)
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    plan_path = run_dir / "coverage-plan.json"
    inventory_path = run_dir / "finalization-inventory.json"
    if not plan_path.exists() and not inventory_path.exists():
        _bootstrap_fresh(run_dir, run_id, coverage_plan)
    if plan_path.exists():
        _persisted_plan_check(run_dir, coverage_plan)
    else:
        write_coverage_plan(run_dir, coverage_plan)
    if inventory_path.exists():
        inventory = _persisted_inventory_check(run_dir, run_id, coverage_plan_sha256)
    else:
        inventory = _empty_inventory(run_id, coverage_plan_sha256)
        write_finalization_inventory(run_dir, inventory)
    return FinalizationPersistenceAdapter(
        run_dir, inventory, coverage_plan, hooks=_facade_hooks()
    )


_COMPATIBILITY_MODULES = (
    persistence_adapter,
    persistence_adapter_admission,
    persistence_adapter_core,
    persistence_adapter_evidence,
    persistence_adapter_events,
    persistence_adapter_state,
    persistence_adapter_terminal,
    persistence_adapter_terminal_methods,
    persistence_artifacts,
    persistence_checkpoint,
    persistence_common,
    persistence_decisions,
    persistence_evidence,
    persistence_files,
    persistence_journal,
    persistence_models,
    persistence_plan,
    persistence_summary,
)


# Inventory-validation predicates remain available through this façade without
# importing the projection-heavy validator during façade initialization.
def _validation_export(name: str) -> Any:
    from asago_scenario_generator.pipeline import persistence_validation as validation

    value = getattr(validation, name)
    globals()[name] = value
    return value


def __getattr__(name: str) -> Any:
    """Resolve legacy helpers from extracted modules or validation lazily."""
    for module in _COMPATIBILITY_MODULES:
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    try:
        return _validation_export(name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
