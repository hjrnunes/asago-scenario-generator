"""Atomic persistence for the Phase 1 taxonomy-obligation artifact."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import write_text_atomically
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan


PLAN_FILENAME = "taxonomy-obligation-plan.yaml"


def write_taxonomy_obligation_plan(
    output_dir: Path,
    plan: TaxonomyObligationPlan,
) -> Path:
    """Validate, atomically write, reload, and equality-check one plan."""
    plan.assert_integrity()
    target = Path(output_dir) / PLAN_FILENAME
    write_text_atomically(target, plan.to_yaml())
    loaded = TaxonomyObligationPlan.from_yaml(target.read_text(encoding="utf-8"))
    if loaded != plan:
        raise ValueError(
            "persisted taxonomy obligation plan failed round-trip equality"
        )
    return target


__all__ = [
    "PLAN_FILENAME",
    "write_taxonomy_obligation_plan",
]
