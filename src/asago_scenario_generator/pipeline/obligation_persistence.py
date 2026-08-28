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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T14:18:11Z","module_hash":"02808daf7576310ac518d6774aa2f2701aef5074e9a40fe6b83d0277d3833043","source_sha256":"fc8c45a55f721f4f6f70477800b58adb36c67059aa8f9f63f08d3c9ad6e4a3cd","functions":[{"id":"func/write_taxonomy_obligation_plan","name":"write_taxonomy_obligation_plan","line":14,"end_line":27,"hash":"799c331cb00a875db6def23756a6cbd9f3871fd9c4609cb1f1233e98d923b136"},{"id":"func/read_taxonomy_obligation_plan","name":"read_taxonomy_obligation_plan","line":30,"end_line":35,"hash":"64ef8aa85cf281a966469ca942a9b22933a6304e1d8df159d090d0ae5748435a"}]}
# mutate4py-manifest-end
