"""SP2 run orchestration — Stage 3 → Stage 4.

Orchestrates the full SP2 pipeline:
  Stage 3: Deterministic slot creation → LLM slot-filling → N/A quality gates
  Stage 4: Deterministic catalog enrichment + coverage analysis

All LLM calls are logged to ``calls.jsonl``. A run manifest is written
at run end with stage summary, N/A quality flags, coverage analysis,
input hashes, and prompt hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE as LLM_DEFAULT_TEMPERATURE,
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.manifest_helpers import (
    count_calls_by_stage,
    hash_model,
)
from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

from ._constants import PROMPTS_DIR
from .catalog_enrichment import enrich_threats
from .na_quality import check_all_na_quality
from .slot_creation import create_slots
from .slot_filling import fill_all_slots

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE

__all__ = ["SP2RunResult", "run_sp2"]


@dataclass
class SP2RunResult:
    """Result of a full SP2 run.

    Attributes:
        ica_enumeration: The ICA enumeration from Stage 3 (or None on failure).
        enriched_threat_set: The enriched threat set from Stage 4 (or None).
        na_quality_result: N/A quality check results.
        stage_errors: List of stage failure messages.
    """

    ica_enumeration: ICAEnumeration | None = None
    enriched_threat_set: EnrichedThreatSet | None = None
    na_quality_result: Any = None
    stage_errors: list[str] = field(default_factory=list)


def run_sp2(
    *,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    capability_profile: CapabilityProfile,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    max_workers: int = 1,
    temperature: float | None = None,
) -> SP2RunResult:
    """Run the full SP2 pipeline: Stage 3 → Stage 4.

    Args:
        llm_client: LLM client for slot-filling calls.
        control_structure: SP1 control structure.
        capability_profile: SP1 capability profile.
        loss_analysis: SP1 loss analysis.
        run_dir: Directory for output artifacts.
        max_workers: Maximum parallel workers for LLM calls.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).

    Returns:
        An :class:`SP2RunResult` with artifacts and diagnostics.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)
    temperature = effective_temperature(llm_client, temperature)

    stage_errors: list[str] = []

    # --- Stage 3 Phase 1: Deterministic slot creation ---
    slots = create_slots(control_structure)

    # --- Stage 3 Phase 2: LLM slot-filling ---
    filled_slots = fill_all_slots(
        llm_client=llm_client,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        capability_profile=capability_profile,
        slots=slots,
        run_dir=run_dir,
        max_workers=max_workers,
        temperature=temperature,
        loader=loader,
    )

    ica_enumeration = ICAEnumeration(slots=filled_slots)

    # --- N/A quality gates ---
    na_quality_result = check_all_na_quality(filled_slots)

    # --- Stage 4: Catalog enrichment + coverage analysis ---
    enriched_threat_set = enrich_threats(ica_enumeration, control_structure)

    # --- Write output artifacts ---
    write_yaml(ica_enumeration, run_dir / "ica-enumeration.yaml")
    write_yaml(enriched_threat_set, run_dir / "enriched-threats.yaml")

    # --- Write run manifest ---
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        control_structure=control_structure,
        capability_profile=capability_profile,
        loss_analysis=loss_analysis,
        loader=loader,
        ica_enumeration=ica_enumeration,
        enriched_threat_set=enriched_threat_set,
        na_quality_result=na_quality_result,
        max_workers=max_workers,
        temperature=temperature,
        stage_errors=stage_errors,
    )

    return SP2RunResult(
        ica_enumeration=ica_enumeration,
        enriched_threat_set=enriched_threat_set,
        na_quality_result=na_quality_result,
        stage_errors=stage_errors,
    )


def _write_manifest(
    run_dir: Path,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    capability_profile: CapabilityProfile,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    ica_enumeration: ICAEnumeration,
    enriched_threat_set: EnrichedThreatSet,
    na_quality_result: Any,
    max_workers: int,
    temperature: float,
    stage_errors: list[str],
) -> None:
    """Write the run manifest YAML."""
    input_hashes = {
        "control_structure": hash_model(control_structure),
        "capability_profile": hash_model(capability_profile),
        "loss_analysis": hash_model(loss_analysis),
    }
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)

    # Count calls by stage from calls.jsonl
    stage_summary = count_calls_by_stage(run_dir)

    na_count = sum(1 for s in ica_enumeration.slots if s.is_na)
    total_slots = len(ica_enumeration.slots)

    manifest = {
        "run_id": f"sp2-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "run_dir": str(run_dir),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_config": effective_model_config(
            llm_client,
            temperature=temperature,
        ),
        "input_hashes": input_hashes,
        "prompt_hashes": prompt_hashes,
        "stage_summary": stage_summary,
        "slot_count": total_slots,
        "na_count": na_count,
        "fill_rate": (total_slots - na_count) / total_slots if total_slots else 0.0,
        "na_quality_flags": {
            "flagged_slots": na_quality_result.flagged_slots,
            "ratio_flags": na_quality_result.ratio_flags,
        },
        "coverage_analysis": enriched_threat_set.coverage_analysis.model_dump(
            mode="json"
        ),
        "max_workers": max_workers,
        "stage_errors": stage_errors,
    }

    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(
            manifest, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T00:44:00Z","module_hash":"946c4646245bb7f299945b9148f6613f1f13dd108f8831cefd6400c9797e01eb","functions":[{"id":"func/run_sp2","name":"run_sp2","line":59,"end_line":136,"hash":"7b560f6ff5237937d80854a127e7ecee9c5f87b007f1ae342c9907cbcf687c91"},{"id":"func/_write_manifest","name":"_write_manifest","line":139,"end_line":196,"hash":"82039d629a7a1c766f3394db8996fe3e44bb127b4664961398067e922a198c30"}]}
# mutate4py-manifest-end
