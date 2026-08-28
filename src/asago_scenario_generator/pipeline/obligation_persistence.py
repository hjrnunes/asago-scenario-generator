"""Atomic persistence for the Phase 1 taxonomy-obligation artifact."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan


PLAN_FILENAME = "taxonomy-obligation-plan.yaml"


def write_taxonomy_obligation_plan(
    output_dir: Path,
    plan: TaxonomyObligationPlan,
) -> Path:
    """Validate, atomically write, reload, and equality-check one plan."""
    plan.assert_integrity()
    target = Path(output_dir) / PLAN_FILENAME
    atomic_write_text(target, plan.to_yaml())
    loaded = TaxonomyObligationPlan.from_yaml(target.read_text(encoding="utf-8"))
    if loaded != plan:
        raise ValueError(
            "persisted taxonomy obligation plan failed round-trip equality"
        )
    return target


def read_taxonomy_obligation_plan(path: Path) -> TaxonomyObligationPlan:
    """Read and integrity-check a previously persisted YAML plan."""
    candidate = Path(path)
    if candidate.name != PLAN_FILENAME:
        raise ValueError(f"expected {PLAN_FILENAME}, got {candidate.name}")
    return TaxonomyObligationPlan.from_yaml(candidate.read_text(encoding="utf-8"))


# Keep a descriptive alias for adapters that name the operation "persist".
persist_taxonomy_obligation_plan = write_taxonomy_obligation_plan


__all__ = [
    "PLAN_FILENAME",
    "persist_taxonomy_obligation_plan",
    "read_taxonomy_obligation_plan",
    "write_taxonomy_obligation_plan",
]
