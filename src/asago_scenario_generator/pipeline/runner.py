"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import importlib.metadata
from collections.abc import Sequence
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from asago_scenario_generator.data.loaders import (
    _THREAT_GOAL_AFFINITY_PATH,
    load_attack_patterns,
    load_yaml_strict,
)
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.manifest import (
    _ROLE_METADATA,
    ARTIFACT_SCHEMA_VERSION,
    ArtifactEntry,
    ArtifactRole,
    InputHashes,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    Provenance,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    build_in_memory_resolver,
    compute_bytes_sha256,
    compute_file_sha256,
    finalize_manifest,
    load_manifest,
    select_final_run_status,
    validate_completed_inventory,
)
from asago_scenario_generator.manifest import (
    MANIFEST_V3 as MANIFEST_VERSION,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.candidate_models import (
    FilteredSeed,
    FilterSeedQuarantine,
    RemovalDecision,
)
from asago_scenario_generator.pipeline.coverage import (
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    STAGE_ADMISSION,
    STAGE_GENERATION,
    STAGE_QUARANTINE,
    GenerationMode,
    StageLedger,
    build_coverage_universe,
    emit_quality_gaps,
)
from asago_scenario_generator.pipeline.io import (
    write_eval_scorecard,
)
from asago_scenario_generator.pipeline.profile import infer_capability_profile
from asago_scenario_generator.pipeline.projection import (
    canonical_json_bytes,
    capture_capability_snapshot,
)
from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

logger = logging.getLogger(__name__)

_DEFAULT_CROSS_TAXONOMY_PATH = (
    DATA_ROOT / "taxonomies" / "mappings" / "cross-taxonomy-mappings.yaml"
)


def _removal_decision_summary(decision: RemovalDecision) -> str:
    """Render the typed rule and reason carried by a removal decision."""
    return f"{decision.rule}: {decision.reason}"


class PipelineResult(BaseModel):
    capability_profile: CapabilityProfile
    threat_surface: ThreatSurface
    seeds: list[ScenarioSeed]
    filtered_seeds: list[FilteredSeed] | None = None
    scenarios: list[ScenarioEnvelope]
    governance_only_count: int
    generation_notes: list[str]
    run_dir: Path | None = None
    run_id: str | None = None
    manifest_status: RunStatus = RunStatus.COMPLETED
    admitted_count: int = 0
    quarantined_count: int = 0
    failed_count: int = 0


class QualificationFactsV1(BaseModel):
    """Explicit authoritative fact readings supplied for qualification runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    facts: tuple[EvaluatedFactEvidence, ...]

    @model_validator(mode="after")
    def canonical_facts(self) -> QualificationFactsV1:
        keys = [canonical_json_bytes(item.fact) for item in self.facts]
        if keys != sorted(set(keys)):
            raise ValueError("qualification facts must be sorted and unique")
        return self


def _parse_qualification_facts(content: bytes) -> QualificationFactsV1:
    """Parse exact UTF-8 source bytes through the strict typed boundary."""
    try:
        text = content.decode("utf-8")
        return QualificationFactsV1.model_validate(load_yaml_strict(text))
    except Exception as exc:
        raise ValueError(f"invalid qualification facts input: {exc}") from exc


def _load_admitted_scenarios(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    finalization_inventory: object,
) -> list[ScenarioEnvelope]:
    """Load admitted YAML only from one hash-verified resolver snapshot."""
    from asago_scenario_generator.pipeline.runner_finalization import build_v3_inventory

    manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("asago-scenario-generator"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir,
            finalization_inventory,
            include_coverage=False,
            include_quarantine=False,
        ),
    )
    resolver = ManifestInventoryResolver(run_dir, manifest, check_orphans=False)
    return [
        ScenarioEnvelope.model_validate(resolver.read_yaml(entry))
        for entry in resolver.entries_by_role(ArtifactRole.SCENARIO_YAML)
    ]


def _scorecard_qualification_passed(scorecard: dict) -> bool:
    """True when the eval scorecard records an authoritative qualification pass."""
    return scorecard["qualification"]["status"] == "pass"


def _authoritative_products_ready(eval_success: bool, report_success: bool) -> bool:
    """True when both eval and report products succeeded before finalization."""
    return eval_success and report_success


def _ordinary_completion_succeeded(
    *,
    terminal_processing_succeeded: bool,
    had_quarantine: bool,
    eval_enabled: bool,
    eval_success: bool,
    report_success: bool,
    qualification_passed: bool,
) -> bool:
    """True when the v3 run completed without quarantine or product failure."""
    return (
        terminal_processing_succeeded
        and not had_quarantine
        and eval_enabled
        and eval_success
        and report_success
        and qualification_passed
    )


def _readable_evidence_file(path: Path) -> bool:
    """True when the path is a real file the inventory can read."""
    return path.exists() and path.is_file()


def _load_finalization_tail_inputs(
    run_dir: Path, run_id: str, timestamp_start: str, provenance: Provenance | None
) -> tuple[object, object, list[object]]:
    """Load and verify the STARTED manifest, inventory, and admitted scenarios."""
    from asago_scenario_generator.pipeline.persistence import (
        build_semantic_generation_summary,
        read_finalization_inventory,
    )

    started_manifest = load_manifest(run_dir, requested_version=MANIFEST_VERSION)
    if started_manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("v3 completion tail requires STARTED manifest")
    ManifestInventoryResolver(run_dir, started_manifest, check_orphans=False)
    final_inventory_doc = read_finalization_inventory(run_dir)
    semantic_generation = build_semantic_generation_summary(final_inventory_doc)
    admitted_scenarios = _load_admitted_scenarios(
        run_dir, run_id, timestamp_start, provenance, final_inventory_doc
    )
    return final_inventory_doc, semantic_generation, admitted_scenarios


def _collect_presentation_notes(
    admitted_scenarios: Sequence[object], generation_notes: list[str]
) -> None:
    for scenario in admitted_scenarios:
        for note in scenario.generation.notes or ():
            if (
                note.startswith("presentation_fallback:")
                and note not in generation_notes
            ):
                generation_notes.append(note)


def _target_to_ingress(finalization: object) -> dict[str, str]:
    return {
        target.effective_target_id: target.entry_point_id
        for target in finalization.coverage_plan.targets
    }


def _finalization_target_outcomes(
    final_inventory_doc: object,
    decisions: dict[str, object],
    target_to_ingress: dict[str, str],
    stage_ledger: object,
) -> tuple[set[str], set[str]]:
    generated_target_ids: set[str] = set()
    quarantined_target_ids: set[str] = set()
    for candidate_attempt in final_inventory_doc.candidate_attempts:
        decision = decisions[candidate_attempt.candidate_id]
        entry_point_id = target_to_ingress[candidate_attempt.target_entry_point_id]
        if decision.admitted:
            generated_target_ids.add(entry_point_id)
            stage_ledger.record(
                entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_GENERATION,
                "generated",
                "Candidate completed all generated stages.",
            )
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_ADMISSION,
                "admitted",
                "Candidate passed postbehavior admission.",
            )
        else:
            quarantined_target_ids.add(entry_point_id)
            stage_ledger.record(
                entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_QUARANTINE,
                decision.status.value,
                "; ".join(item.detail for item in decision.violations),
            )
    return generated_target_ids, quarantined_target_ids


def _coverage_gap_analysis(
    *,
    profile: object,
    threat_surface: object,
    admitted_scenarios: Sequence[object],
    finalization: object,
    coverage_universe: object,
    stage_ledger: object,
    selection_result: object,
    fallback_queues: dict,
    projection_limitation_target_ids: set[str],
    run_dir: Path,
    final_inventory_doc: object,
) -> tuple[set[str], set[str], object, object]:
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, admitted_scenarios)
    decisions = {
        item.candidate_id: item for item in final_inventory_doc.admission_decisions
    }
    target_to_ingress = _target_to_ingress(finalization)
    generated_target_ids, quarantined_target_ids = _finalization_target_outcomes(
        final_inventory_doc, decisions, target_to_ingress, stage_ledger
    )
    quality_gaps, coverage_summary = emit_quality_gaps(
        coverage_universe,
        stage_ledger,
        selection_result,
        fallback_queues,
        generated_target_ids=generated_target_ids,
        quarantined_target_ids=quarantined_target_ids - generated_target_ids,
        projection_limitation_target_ids=projection_limitation_target_ids,
    )
    write_coverage_report(
        coverage_gaps,
        run_dir,
        analyze_attacker_diversity(admitted_scenarios),
        coverage_universe=coverage_universe,
        quality_gaps=quality_gaps,
        coverage_plan=finalization.coverage_plan,
        coverage_summary=coverage_summary,
        stage_ledger=stage_ledger,
        finalization_inventory=final_inventory_doc,
    )
    return generated_target_ids, quarantined_target_ids, quality_gaps, coverage_summary


def _remove_stale_optional_products(run_dir: Path) -> None:
    # A prior interrupted completion tail is non-authoritative. Reconcile its
    # optional products before regeneration so failed/disabled retries cannot
    # leave unmanifested stale files behind.
    for stale_name in ("eval-scorecard.yaml", "report.html"):
        (run_dir / stale_name).unlink(missing_ok=True)


def _provisional_manifest(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
    *,
    include_eval: bool = False,
) -> RunManifest:
    from asago_scenario_generator.pipeline.runner_finalization import (
        build_v3_inventory,
    )

    return RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("asago-scenario-generator"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir,
            final_inventory_doc,
            include_quarantine=False,
            include_eval=include_eval,
        ),
    )


def _provisional_eval_product(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
    eval_enabled: bool,
    threats_path: Path | None,
) -> tuple[bool, bool]:
    if not eval_enabled:
        logger.info("[Eval] Skipped (--no-eval) — non-authoritative.")
        return False, False
    try:
        from asago_scenario_generator.eval.runner import run_evaluation

        eval_manifest = _provisional_manifest(
            run_dir, run_id, timestamp_start, provenance, final_inventory_doc
        )
        scorecard = run_evaluation(
            resolver=build_in_memory_resolver(run_dir, eval_manifest),
            threats_path=threats_path,
        )
        write_eval_scorecard(scorecard, run_dir)
        return True, _scorecard_qualification_passed(scorecard)
    except Exception as exc:  # noqa: BLE001 - non-authoritative output
        (run_dir / "eval-scorecard.yaml").unlink(missing_ok=True)
        logger.warning("Eval scorecard generation failed: %s", exc)
        return False, False


def _terminal_completion_flags(
    final_inventory_doc: object,
    filter_quarantines: list[object] | None,
    finalization: object,
) -> tuple[bool, bool]:
    had_quarantine = bool(
        final_inventory_doc.quarantine_inventory or filter_quarantines
    )
    terminal_processing_succeeded = all(
        target.target_state.value in {"admitted", "exhausted"}
        for target in finalization.coverage_plan.targets
    )
    return had_quarantine, terminal_processing_succeeded


def _provisional_report_product(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
    eval_success: bool,
) -> bool:
    try:
        from asago_scenario_generator.report.data import load_report_data
        from asago_scenario_generator.report.generator import generate_report

        report_manifest = _provisional_manifest(
            run_dir,
            run_id,
            timestamp_start,
            provenance,
            final_inventory_doc,
            include_eval=eval_success,
        )
        report_data = load_report_data(
            resolver=build_in_memory_resolver(run_dir, report_manifest)
        )
        generate_report(report_data, run_dir)
        return True
    except Exception as exc:  # noqa: BLE001 - non-authoritative output
        (run_dir / "report.html").unlink(missing_ok=True)
        logger.warning("Report generation failed: %s", exc)
        return False


def _close_pipeline_log() -> None:
    # Close the pipeline log before hashing the complete candidate inventory.
    # The first eval/report products above are deliberately provisional: they
    # break the scorecard/report inventory cycle but cannot authorize a run.
    sf_logger = logging.getLogger("asago_scenario_generator")
    for handler in sf_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.flush()
            handler.close()
            sf_logger.removeHandler(handler)


def _strict_authoritative_manifest(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
) -> RunManifest:
    from asago_scenario_generator.pipeline.runner_finalization import (
        build_v3_inventory,
    )

    return RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("asago-scenario-generator"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir,
            final_inventory_doc,
            include_eval=True,
            include_report=True,
            include_log=True,
        ),
    )


def _authoritative_second_pass(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
    threats_path: Path | None,
) -> tuple[bool, bool, bool]:
    """Recompute eval and report from a strict orphan-checked resolver."""
    try:
        from asago_scenario_generator.eval.runner import run_evaluation
        from asago_scenario_generator.report.data import load_report_data
        from asago_scenario_generator.report.generator import generate_report

        candidate_manifest = _strict_authoritative_manifest(
            run_dir, run_id, timestamp_start, provenance, final_inventory_doc
        )
        strict_eval_resolver = ManifestInventoryResolver(
            run_dir, candidate_manifest, check_orphans=True
        )
        scorecard = run_evaluation(
            resolver=strict_eval_resolver,
            threats_path=threats_path,
        )
        write_eval_scorecard(scorecard, run_dir)
        qualification_passed = _scorecard_qualification_passed(scorecard)

        report_manifest = _strict_authoritative_manifest(
            run_dir, run_id, timestamp_start, provenance, final_inventory_doc
        )
        strict_report_resolver = ManifestInventoryResolver(
            run_dir, report_manifest, check_orphans=True
        )
        report_data = load_report_data(resolver=strict_report_resolver)
        generate_report(report_data, run_dir)
        return True, True, qualification_passed
    except Exception as exc:  # noqa: BLE001 - run remains non-authoritative
        eval_success = False
        report_success = False
        qualification_passed = False
        (run_dir / "eval-scorecard.yaml").unlink(missing_ok=True)
        (run_dir / "report.html").unlink(missing_ok=True)
        logger.warning("Authoritative eval/report finalization failed: %s", exc)
        return eval_success, report_success, qualification_passed


def _finalize_run_manifest(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    final_inventory_doc: object,
    generation_notes: list[str],
    semantic_generation: object,
    eval_enabled: bool,
    eval_success: bool,
    report_success: bool,
    ordinary_completion_succeeded: bool,
) -> RunManifest:
    from asago_scenario_generator.pipeline.runner_finalization import (
        build_v3_inventory,
    )

    final_status = select_final_run_status(
        ordinary_completion_succeeded, generation_notes
    )
    inventory = build_v3_inventory(
        run_dir,
        final_inventory_doc,
        include_eval=eval_success,
        include_report=report_success,
        include_log=True,
    )
    timestamp_end = datetime.now(UTC).isoformat()
    if provenance is not None:
        provenance.timestamp_end = timestamp_end
        provenance.input_hashes.effective_profile_hash = compute_file_sha256(
            run_dir / "capability-profile.yaml"
        )
    final_manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=final_status,
        run_id=run_id,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        package_version=importlib.metadata.version("asago-scenario-generator"),
        provenance=provenance,
        inventory=inventory,
        semantic_generation=semantic_generation,
    )
    if final_status.requires_complete_inventory:
        validate_completed_inventory(
            final_manifest, eval_enabled=eval_enabled, run_dir=run_dir
        )
    else:
        ManifestInventoryResolver(run_dir, final_manifest, check_orphans=True)
    finalize_manifest(run_dir, final_manifest)
    return final_manifest


def _result_counts(
    final_inventory_doc: object, filter_quarantines: list[object] | None
) -> tuple[int, int, int]:
    admitted_count = sum(
        decision.admitted for decision in final_inventory_doc.admission_decisions
    )
    finalization_quarantine_count = len(final_inventory_doc.quarantine_inventory)
    failed_count = sum(
        decision.status.value == "generation_or_finalization_failed"
        for decision in final_inventory_doc.admission_decisions
    )
    filter_quarantine_count = len(filter_quarantines or [])
    return (
        admitted_count,
        finalization_quarantine_count + filter_quarantine_count,
        failed_count,
    )


def _complete_v3_run(
    *,
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    profile: CapabilityProfile,
    threat_surface: ThreatSurface,
    finalization: object,
    coverage_universe: object,
    stage_ledger: StageLedger,
    selection_result: object,
    fallback_queues: dict,
    projection_limitation_target_ids: set[str],
    threats_path: Path | None,
    eval_enabled: bool,
    seeds: list[ScenarioSeed],
    filtered_seeds: list[FilteredSeed] | None,
    governance_count: int,
    generation_notes: list[str],
    filter_quarantines: list[FilterSeedQuarantine] | None = None,
) -> PipelineResult:
    """Run the single shared v3 coverage, eval, report, and manifest tail."""
    (
        final_inventory_doc,
        semantic_generation,
        admitted_scenarios,
    ) = _load_finalization_tail_inputs(run_dir, run_id, timestamp_start, provenance)
    _collect_presentation_notes(admitted_scenarios, generation_notes)
    (
        generated_target_ids,
        quarantined_target_ids,
        quality_gaps,
        coverage_summary,
    ) = _coverage_gap_analysis(
        profile=profile,
        threat_surface=threat_surface,
        admitted_scenarios=admitted_scenarios,
        finalization=finalization,
        coverage_universe=coverage_universe,
        stage_ledger=stage_ledger,
        selection_result=selection_result,
        fallback_queues=fallback_queues,
        projection_limitation_target_ids=projection_limitation_target_ids,
        run_dir=run_dir,
        final_inventory_doc=final_inventory_doc,
    )
    _remove_stale_optional_products(run_dir)
    eval_success, qualification_passed = _provisional_eval_product(
        run_dir,
        run_id,
        timestamp_start,
        provenance,
        final_inventory_doc,
        eval_enabled,
        threats_path,
    )
    had_quarantine, terminal_processing_succeeded = _terminal_completion_flags(
        final_inventory_doc, filter_quarantines, finalization
    )
    report_success = _provisional_report_product(
        run_dir,
        run_id,
        timestamp_start,
        provenance,
        final_inventory_doc,
        eval_success,
    )
    _close_pipeline_log()

    # Authoritative second pass. The complete provisional inventory is first
    # reconciled with orphan checking enabled. Evaluation is then recomputed
    # from that strict resolver, the scorecard hash is rebuilt, and the report
    # is regenerated from the final scorecard before final hashes/validation.
    if _authoritative_products_ready(eval_success, report_success):
        eval_success, report_success, qualification_passed = _authoritative_second_pass(
            run_dir,
            run_id,
            timestamp_start,
            provenance,
            final_inventory_doc,
            threats_path,
        )
    ordinary_completion_succeeded = _ordinary_completion_succeeded(
        terminal_processing_succeeded=terminal_processing_succeeded,
        had_quarantine=had_quarantine,
        eval_enabled=eval_enabled,
        eval_success=eval_success,
        report_success=report_success,
        qualification_passed=qualification_passed,
    )
    final_manifest = _finalize_run_manifest(
        run_dir,
        run_id,
        timestamp_start,
        provenance,
        final_inventory_doc,
        generation_notes,
        semantic_generation,
        eval_enabled,
        eval_success,
        report_success,
        ordinary_completion_succeeded,
    )
    admitted_count, quarantined_count, failed_count = _result_counts(
        final_inventory_doc, filter_quarantines
    )
    return PipelineResult(
        capability_profile=profile,
        threat_surface=threat_surface,
        seeds=seeds,
        filtered_seeds=filtered_seeds,
        scenarios=admitted_scenarios,
        governance_only_count=governance_count,
        generation_notes=generation_notes,
        run_dir=run_dir,
        run_id=run_id,
        manifest_status=final_manifest.status,
        admitted_count=admitted_count,
        quarantined_count=quarantined_count,
        failed_count=failed_count,
    )


def _repackage_candidate(candidate: object, rank: int) -> object:
    """Rebuild a qualified candidate with a new selection rank."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        QualifiedCandidate,
    )

    return QualifiedCandidate(
        projected=candidate.projected,
        accepted_filters=candidate.accepted_filters,
        rank=rank,
    )


def _restore_qualified_candidate(ref: object) -> object:
    """Deserialize one persisted choice reference back to a candidate."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        deserialize_qualified_candidate,
    )

    hydrated = deserialize_qualified_candidate(ref.model_dump(mode="json"))
    return _repackage_candidate(hydrated, hydrated.rank)


def _restore_selected(
    planning: object, hydrated_by_id: dict[str, object]
) -> list[object]:
    """Rebuild the typed selected list in persisted rank order."""
    try:
        return [
            _repackage_candidate(hydrated_by_id[item], rank)
            for rank, item in enumerate(planning.selected_candidate_ids)
        ]
    except KeyError as exc:
        raise ManifestIntegrityError(
            "planning checkpoint selected candidate is absent from plan"
        ) from exc


def _pattern_counts(selected: Sequence[object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in selected:
        counts[candidate.pattern_id] = counts.get(candidate.pattern_id, 0) + 1
    return counts


def _coverage_queues_for(
    coverage_universe: object, coverage_candidates: dict[str, list[object]]
) -> dict[str, object]:
    from asago_scenario_generator.pipeline.coverage_planning import (
        TargetFallbackQueue,
    )

    return {
        target.entry_point_id: TargetFallbackQueue(
            entry_point_id=target.entry_point_id,
            choices=[
                _repackage_candidate(candidate, rank)
                for rank, candidate in enumerate(
                    sorted(
                        coverage_candidates.get(target.entry_point_id, []),
                        key=lambda item: (item.pattern_id, item.candidate_id),
                    )[:3]
                )
            ],
        )
        for target in coverage_universe.feasible_targets
    }


def _hydrate_planning_inputs(
    planning: object, durable_plan: object, coverage_universe: object
) -> tuple[object, dict, dict]:
    """Rebuild the exact typed selection inputs persisted before finalization."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        QualifiedCandidate,
        SelectionResult,
        TargetFallbackQueue,
    )

    hydrated_by_id: dict[str, QualifiedCandidate] = {}
    target_queues: dict[str, TargetFallbackQueue] = {}
    coverage_candidates: dict[str, list[QualifiedCandidate]] = {}
    for target in durable_plan.targets:
        choices = [_restore_qualified_candidate(ref) for ref in target.ordered_choices]
        for candidate in choices:
            hydrated_by_id[candidate.candidate_id] = candidate
            coverage_candidates.setdefault(target.entry_point_id, []).append(candidate)
        target_queues[target.effective_target_id] = TargetFallbackQueue(
            entry_point_id=target.effective_target_id,
            choices=choices,
        )
    selected = _restore_selected(planning, hydrated_by_id)
    if _pattern_counts(selected) != planning.per_pattern_counts:
        raise ManifestIntegrityError("planning checkpoint pattern counts mismatch")

    selection_result = SelectionResult(
        selected=selected,
        capped_count=planning.capped_count,
        uncovered_target_ids=list(planning.uncovered_target_ids),
        per_pattern_counts=dict(planning.per_pattern_counts),
        primary_candidate_ids=dict(planning.primary_candidate_ids),
        attempted_candidate_ids=set(planning.attempted_candidate_ids),
        selection_limitation_target_ids=list(planning.selection_limitation_target_ids),
    )
    coverage_queues = _coverage_queues_for(coverage_universe, coverage_candidates)
    return selection_result, target_queues, coverage_queues


def resume_pipeline(
    run_dir: Path,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    eval: bool | None = None,
    log_level: str = "INFO",
    structured: bool = False,
) -> PipelineResult:
    """Resume exactly one interrupted manifest-v3 run in place."""
    from asago_scenario_generator.pipeline.coverage_planning import CoveragePlan
    from asago_scenario_generator.pipeline.persistence import (
        read_coverage_plan,
        validate_planning_checkpoint,
    )
    from asago_scenario_generator.pipeline.runner_finalization import (
        run_target_finalization,
    )

    supplied = _resolve_resume_directory(run_dir)
    manifest = _load_resumable_manifest(supplied)
    _validate_resume_manifest_identity(supplied, manifest)
    support = ManifestInventoryResolver(supplied, manifest, check_orphans=False)
    use_case, profile, threat_surface, planning = _load_resume_support_artifacts(
        supplied, manifest, support
    )
    provenance = manifest.provenance
    options, persisted_eval = _resume_command_options(provenance)
    _validate_resume_provenance_inputs(manifest, use_case)
    _validate_resume_eval_override(eval, persisted_eval)
    current_hashes = _capture_input_hashes(use_case, *_resume_input_paths(options))
    _validate_resume_input_hash_drift(current_hashes, provenance.input_hashes)

    taxonomy_resolver = load_taxonomy_resolver()
    qualification_facts = _resume_qualification_facts(
        planning, provenance.input_hashes, options
    )
    capability_snapshot = capture_capability_snapshot(profile, qualification_facts)
    trusted_catalog = list(load_attack_patterns().values())
    durable_plan = read_coverage_plan(supplied)
    validate_planning_checkpoint(planning, durable_plan)
    _revalidate_resume_candidates(
        durable_plan, taxonomy_resolver, capability_snapshot, trusted_catalog
    )
    coverage_universe = build_coverage_universe(profile)
    selection_result, _target_queues, coverage_queues = _hydrate_planning_inputs(
        planning, durable_plan, coverage_universe
    )

    _setup_resume_logging(log_level, supplied, structured)
    persisted_model = provenance.model_config_provenance
    _validate_resume_model_config(model, base_url, persisted_model)
    client = _resume_llm_client(base_url, api_key, model, persisted_model)
    finalization = run_target_finalization(
        run_dir=supplied,
        run_id=manifest.run_id,
        plan=CoveragePlan(
            schema_version="1",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[],
        ),
        profile=profile,
        client=client,
        use_case=use_case,
        taxonomy_resolver=taxonomy_resolver,
        capability_snapshot=capability_snapshot,
        trusted_catalog=trusted_catalog,
        presentation_fallback=persisted_presentation_fallback(options),
    )
    durable_plan = finalization.coverage_plan
    return _complete_v3_run(
        run_dir=supplied,
        run_id=manifest.run_id,
        timestamp_start=manifest.timestamp_start,
        provenance=manifest.provenance,
        profile=profile,
        threat_surface=threat_surface,
        finalization=finalization,
        coverage_universe=coverage_universe,
        stage_ledger=_resume_stage_ledger(planning),
        selection_result=selection_result,
        fallback_queues=coverage_queues,
        projection_limitation_target_ids=set(planning.projection_limitation_target_ids),
        threats_path=Path(options["threats_path"]),
        eval_enabled=persisted_eval,
        seeds=[],
        filtered_seeds=None,
        governance_count=len(threat_surface.governance_only),
        generation_notes=[],
    )


def run_profile_only(
    use_case: str,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> tuple[CapabilityProfile, LLMResult]:
    """Run Stage 1 only: infer a capability profile from a use-case description."""
    client = LLMClient(base_url=base_url, api_key=api_key, model=model)
    return infer_capability_profile(use_case, client)


def _glob_hash_map(directory: Path, pattern: str, data_root: Path) -> dict[str, str]:
    """Hash every file matched by ``pattern`` as a sorted path→hash map."""
    if not directory.exists():
        return {}
    return {
        str(yaml_file.relative_to(data_root)): compute_file_sha256(yaml_file)
        for yaml_file in sorted(directory.glob(pattern))
    }


def _source_profile_hash(hashes: InputHashes, profile_path: Path | None) -> None:
    if profile_path is not None:
        hashes.source_profile_hash = compute_file_sha256(profile_path)


def _qualification_facts_hash(
    hashes: InputHashes,
    qualification_facts_bytes: bytes | None,
    qualification_facts_path: Path | None,
) -> None:
    if qualification_facts_bytes is not None:
        hashes.qualification_facts_hash = compute_bytes_sha256(
            qualification_facts_bytes
        )
    elif qualification_facts_path is not None:
        hashes.qualification_facts_hash = compute_file_sha256(qualification_facts_path)


def _optional_bundled_hashes(hashes: InputHashes, data_root: Path) -> None:
    for path, attribute in (
        (
            data_root / "attack-patterns" / "attack-patterns.yaml",
            "attack_patterns_hash",
        ),
        (
            data_root / "attack-patterns" / "attack-patterns.sssom.tsv",
            "attack_patterns_sssom_hash",
        ),
        (
            data_root / "attack-goals" / "attack-goals.json",
            "attack_goals_taxonomy_hash",
        ),
        (_THREAT_GOAL_AFFINITY_PATH, "threat_goal_affinity_hash"),
    ):
        if path.exists():
            setattr(hashes, attribute, compute_file_sha256(path))


def _capture_input_hashes(
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    ct_path: Path,
    threats_path: Path | None,
    profile_path: Path | None,
    qualification_facts_path: Path | None = None,
    *,
    qualification_facts_bytes: bytes | None = None,
) -> InputHashes:
    """Capture SHA-256 hashes of all effective inputs at run start.

    Hashes every effective input before any processing can change them:
    use case, risk extraction, SSSOM, explicit/default cross taxonomy,
    explicit/default threats, optional source profile, and bundled
    taxonomies (attack patterns, attack goals, threat-goal affinity).
    """
    from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

    effective_threats = threats_path or _DEFAULT_THREATS_PATH

    # Bundled data paths
    data_root = DATA_ROOT / "taxonomies"
    attack_patterns_dir = data_root / "attack-patterns"

    # Hash every file actually loaded by the attack-patterns*.yaml and
    # attack-patterns*.sssom.tsv globs as deterministic sorted path→hash maps.
    attack_patterns_yaml_map = _glob_hash_map(
        attack_patterns_dir, "attack-patterns*.yaml", data_root
    )
    attack_patterns_sssom_map = _glob_hash_map(
        attack_patterns_dir, "attack-patterns*.sssom.tsv", data_root
    )

    hashes = InputHashes(
        use_case_hash=compute_bytes_sha256(use_case.encode("utf-8")),
        risk_extraction_hash=compute_file_sha256(risk_extraction_path),
        sssom_hash=compute_file_sha256(sssom_path),
        cross_taxonomy_hash=compute_file_sha256(ct_path),
        threats_hash=compute_file_sha256(effective_threats),
        attack_patterns_yaml_map=attack_patterns_yaml_map,
        attack_patterns_sssom_map=attack_patterns_sssom_map,
    )
    _source_profile_hash(hashes, profile_path)
    _qualification_facts_hash(
        hashes, qualification_facts_bytes, qualification_facts_path
    )
    _optional_bundled_hashes(hashes, data_root)
    return hashes


_SINGLETON_FAILED_ARTIFACTS: tuple[tuple[ArtifactRole, str], ...] = (
    (ArtifactRole.USE_CASE, "use-case.txt"),
    (ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"),
    (ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"),
    (ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json"),
    (ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json"),
    (ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl"),
    (ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml"),
    (ArtifactRole.REPORT, "report.html"),
    (ArtifactRole.PIPELINE_LOG, "pipeline.log"),
    (ArtifactRole.COVERAGE_PLAN, "coverage-plan.json"),
    (ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json"),
    (ArtifactRole.CANDIDATE_FILTER_QUARANTINE, "candidate-filter-quarantine.json"),
)


def _best_effort_artifact_entry(
    full: Path,
    role: ArtifactRole,
    rel_path: str,
    scenario_id: str | None,
    candidate_id: str | None,
) -> ArtifactEntry | None:
    """Record a file with a best-effort hash when canonical entry fails."""
    try:
        return ArtifactEntry(
            role=role,
            path=rel_path,
            sha256=compute_file_sha256(full),
            scenario_id=scenario_id,
            candidate_id=candidate_id,
            media_type=_ROLE_METADATA.get(role, {}).get(
                "media_type", "application/octet-stream"
            ),
            schema_version=ARTIFACT_SCHEMA_VERSION,
        )
    except Exception:  # noqa: BLE001, S110 - orphan check will flag unreadable files
        return None  # truly unreadable — orphan check will flag it


def _failed_artifact_entry(
    run_dir: Path,
    role: ArtifactRole,
    rel_path: str,
    scenario_id: str | None = None,
    candidate_id: str | None = None,
) -> ArtifactEntry | None:
    """Independently inventory one existing recognized artifact, if readable."""
    full = run_dir / rel_path
    if not _readable_evidence_file(full):
        return None
    try:
        return build_artifact_entry(
            role=role,
            run_dir=run_dir,
            rel_path=rel_path,
            scenario_id=scenario_id,
            candidate_id=candidate_id,
            schema_version="2" if role is ArtifactRole.COVERAGE_PLAN else "1",
        )
    except ManifestIntegrityError:
        # If we cannot build a valid entry (e.g. hash computation failure),
        # still record the file with a best-effort hash so orphan checks
        # don't flag it.  This is evidence, not authoritative inventory.
        return _best_effort_artifact_entry(
            full, role, rel_path, scenario_id, candidate_id
        )


def _finalization_inventory_receipts(run_dir: Path) -> list[tuple]:
    """V3 terminal files discovered only through the durable inventory."""
    finalization_path = run_dir / "finalization-inventory.json"
    if not finalization_path.is_file():
        return []
    try:
        from asago_scenario_generator.pipeline.persistence import (
            FinalizationInventoryV1,
        )

        finalization_inventory = FinalizationInventoryV1.model_validate_json(
            finalization_path.read_text(encoding="utf-8")
        )
        return [
            (receipt.role, receipt.path, receipt.scenario_id, receipt.candidate_id)
            for receipt in [
                *finalization_inventory.admitted_inventory,
                *finalization_inventory.quarantine_inventory,
            ]
        ]
    except Exception:  # noqa: BLE001, S110 - failed-manifest evidence is best effort
        return []


def _scenario_receipts(write_receipts: list[dict]) -> list[tuple]:
    """Scenario artifacts from write receipts."""
    entries: list[tuple] = []
    for receipt in write_receipts:
        sid = receipt.get("scenario_id")
        cid = receipt.get("candidate_id")
        yaml_name = Path(receipt["yaml_path"]).name
        entries.append((ArtifactRole.SCENARIO_YAML, f"scenarios/{yaml_name}", sid, cid))
        feat_path = receipt.get("feature_path")
        if feat_path:
            feat_name = Path(feat_path).name
            entries.append(
                (ArtifactRole.SCENARIO_FEATURE, f"scenarios/{feat_name}", sid, cid)
            )
    return entries


def _collect_failed_entries(
    run_dir: Path, inventory: list[ArtifactEntry], candidates: list[tuple]
) -> None:
    for role, rel_path, scenario_id, candidate_id in candidates:
        entry = _failed_artifact_entry(
            run_dir, role, rel_path, scenario_id, candidate_id
        )
        if entry is not None:
            inventory.append(entry)


def _build_failed_evidence_inventory(
    run_dir: Path,
    write_receipts: list[dict],
) -> list[ArtifactEntry]:
    """Tolerantly inventory each existing recognized artifact independently.

    This recovery builder does **not** require any late-stage artifact
    (coverage, scorecard, report, pipeline.log). Each known path is checked
    independently and added only if it exists. This ensures failed runs retain
    evidence for every artifact that was actually written before the failure.
    """
    inventory: list[ArtifactEntry] = []
    _collect_failed_entries(
        run_dir,
        inventory,
        [
            (role, rel_path, None, None)
            for role, rel_path in _SINGLETON_FAILED_ARTIFACTS
        ],
    )
    _collect_failed_entries(
        run_dir, inventory, _finalization_inventory_receipts(run_dir)
    )
    _collect_failed_entries(run_dir, inventory, _scenario_receipts(write_receipts))
    _collect_failed_entries(
        run_dir,
        inventory,
        [(ArtifactRole.SCENARIO_CALL_LOG, "scenarios/calls.jsonl", None, None)],
    )
    return inventory


def run_pipeline(
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    output_dir: Path,
    cross_taxonomy_path: Path | None = None,
    threats_path: Path | None = None,
    profile_path: Path | None = None,
    qualification_facts_path: Path | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    model_profile: str | None = None,
    profiles_file: Path = Path("config/model-profiles.yaml"),
    presentation_fallback: str = "allow",
    max_techniques: int = 1,
    max_scenarios_per_pattern: int | None = None,
    generation_mode: str = GenerationMode.EXHAUSTIVE.value,
    zones: str | None = None,
    eval: bool = True,
    log_level: str = "INFO",
    structured: bool = False,
) -> PipelineResult:
    """Run the full asago-scenario-generator pipeline (stages 1-4).

    Args:
        use_case: Free-text description of the AI system under assessment.
        risk_extraction_path: Path to policy-mapper risk-extraction.json.
        sssom_path: Path to SSSOM TSV mapping file.
        output_dir: **Collection** directory for pipeline outputs.  Each
            invocation creates a new immutable ``<run_id>`` child directory.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml (defaults to bundled).
        threats_path: Path to OWASP agentic threats YAML (defaults to bundled).
        profile_path: Path to a pre-built capability-profile.yaml (skips Stage 1 inference).
        qualification_facts_path: Optional explicit authoritative fact readings YAML.
        base_url: LLM endpoint URL override.
        api_key: LLM API key override.
        model: LLM model name override.
        max_scenarios_per_pattern: Cap on scenarios per attack pattern (None = no cap).
        generation_mode: ``exhaustive`` (default) or the bounded ``coverage`` smoke mode.
        eval: Whether to run deterministic eval metrics after generation (default True).
        log_level: Logging level for the console handler.
        structured: Whether the run-local file log uses JSON-lines format.

    The v3 lifecycle persists the immutable plan and inventory, runs
    entirely inside the guarded body: it builds the coverage universe
    (``build_coverage_universe(...)``), qualifies candidates
    (``build_qualified_candidates(...)``), plans generation
    (``plan_generation(...)``), drives every target through
    ``run_target_finalization(...)``, and returns the completed run with
    ``return _complete_v3_run(...)`` — no legacy v2 generation or mutation
    lifecycle remains.

    Returns:
        PipelineResult with all artifacts from the pipeline run.
    """
    return _run_pipeline_guarded(
        use_case=use_case,
        risk_extraction_path=risk_extraction_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
        cross_taxonomy_path=cross_taxonomy_path,
        threats_path=threats_path,
        profile_path=profile_path,
        qualification_facts_path=qualification_facts_path,
        base_url=base_url,
        api_key=api_key,
        model=model,
        model_profile=model_profile,
        profiles_file=profiles_file,
        presentation_fallback=presentation_fallback,
        max_techniques=max_techniques,
        max_scenarios_per_pattern=max_scenarios_per_pattern,
        generation_mode=generation_mode,
        zones=zones,
        eval=eval,
        log_level=log_level,
        structured=structured,
    )


# Resume and run orchestration helpers live in the sibling modules
# pipeline.runner_resume and pipeline.runner_run; re-export them here
# so every existing import path (including private helpers used by
# tests) keeps working.
from asago_scenario_generator.pipeline.runner_resume import (  # noqa: E402
    _resolve_resume_directory as _resolve_resume_directory,
    _load_resumable_manifest as _load_resumable_manifest,
    _validate_resume_manifest_identity as _validate_resume_manifest_identity,
    _load_resume_support_artifacts as _load_resume_support_artifacts,
    _resume_command_options as _resume_command_options,
    _validate_resume_presentation_fallback as _validate_resume_presentation_fallback,
    _validate_resume_generation_mode as _validate_resume_generation_mode,
    _validate_resume_provenance_inputs as _validate_resume_provenance_inputs,
    _validate_resume_eval_override as _validate_resume_eval_override,
    _resume_input_paths as _resume_input_paths,
    _validate_resume_input_hash_drift as _validate_resume_input_hash_drift,
    _validate_resume_facts_absent as _validate_resume_facts_absent,
    _parse_resume_facts as _parse_resume_facts,
    _resume_qualification_facts as _resume_qualification_facts,
    _revalidate_resume_candidates as _revalidate_resume_candidates,
    _setup_resume_logging as _setup_resume_logging,
    _validate_resume_model_config as _validate_resume_model_config,
    _validate_resume_model_override as _validate_resume_model_override,
    _validate_resume_endpoint_override as _validate_resume_endpoint_override,
    _resolved_resume_base_url as _resolved_resume_base_url,
    _resolved_resume_model as _resolved_resume_model,
    _persisted_temperature as _persisted_temperature,
    _persisted_max_completion_tokens as _persisted_max_completion_tokens,
    _resume_llm_client as _resume_llm_client,
    persisted_presentation_fallback as persisted_presentation_fallback,
    _resume_stage_ledger as _resume_stage_ledger,
)
from asago_scenario_generator.pipeline.runner_run import (  # noqa: E402
    _run_pipeline_guarded as _run_pipeline_guarded,
    _validate_run_pipeline_options as _validate_run_pipeline_options,
    _resolve_cross_taxonomy_path as _resolve_cross_taxonomy_path,
    _recover_and_reraise_failed_run as _recover_and_reraise_failed_run,
    _run_failure_log_flush as _run_failure_log_flush,
    _failed_manifest_for as _failed_manifest_for,
    _mark_failed_manifest as _mark_failed_manifest,
    _started_support_manifest as _started_support_manifest,
    _immutable_roles_by_role as _immutable_roles_by_role,
    _support_published as _support_published,
    _support_validation_result as _support_validation_result,
    _write_failed_manifest_evidence as _write_failed_manifest_evidence,
    _ingest_qualification_facts as _ingest_qualification_facts,
    _qualification_facts_mode_label as _qualification_facts_mode_label,
    _resolve_effective_threats_path as _resolve_effective_threats_path,
    _parse_effective_zones as _parse_effective_zones,
    _model_control_sources as _model_control_sources,
    _sorted_header_names as _sorted_header_names,
    _effective_pipeline_options as _effective_pipeline_options,
    _load_or_infer_profile as _load_or_infer_profile,
    _log_profile_inference_call as _log_profile_inference_call,
    _zone_tag_pattern as _zone_tag_pattern,
    _validate_requested_zones as _validate_requested_zones,
    _strip_zone_kc_codes as _strip_zone_kc_codes,
    _strip_memory_kc_codes as _strip_memory_kc_codes,
    _strip_inter_agent_kc_codes as _strip_inter_agent_kc_codes,
    _zone_kc_filter as _zone_kc_filter,
    _strip_entry_point_zone_tags as _strip_entry_point_zone_tags,
    _apply_zone_filter as _apply_zone_filter,
    _stage2_threat_surface as _stage2_threat_surface,
    _expansion_record as _expansion_record,
    _run_candidate_filter as _run_candidate_filter,
    _record_filter_unavailability_note as _record_filter_unavailability_note,
    _log_filter_quarantines as _log_filter_quarantines,
    _selected_authoritative_patterns as _selected_authoritative_patterns,
    _run_projection_readiness_gate as _run_projection_readiness_gate,
    _projected_by_pattern_lookup as _projected_by_pattern_lookup,
    _project_authoritative_run as _project_authoritative_run,
    _removal_decision_summaries as _removal_decision_summaries,
    _rule_rejection_reasons as _rule_rejection_reasons,
    _record_rule_rejections as _record_rule_rejections,
    _filter_rejection_rationale as _filter_rejection_rationale,
    _verdict_payload as _verdict_payload,
    _accepted_filter_ids as _accepted_filter_ids,
    _filter_rejection_by_id as _filter_rejection_by_id,
    _record_filter_rejections as _record_filter_rejections,
    _matching_projected_candidates as _matching_projected_candidates,
    _record_no_projection as _record_no_projection,
    _record_no_ingress_match as _record_no_ingress_match,
    _record_projected_match as _record_projected_match,
    _projection_event_for_fseed as _projection_event_for_fseed,
    _record_projection_events as _record_projection_events,
    _log_projection_rejections as _log_projection_rejections,
    _record_projection_limitation_events as _record_projection_limitation_events,
    _record_selection_events as _record_selection_events,
    _log_cap_summary as _log_cap_summary,
    _log_uncovered_targets as _log_uncovered_targets,
    _build_planning_checkpoint as _build_planning_checkpoint,
    _resume_support_inventory as _resume_support_inventory,
    _log_rule_filter_summary as _log_rule_filter_summary,
    _run_pipeline_body as _run_pipeline_body,
)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T19:41:59Z","module_hash":"a495f71e5ecebec6b4a9959bbf0e618b52a098210283d08bdb1b8238dd5fdd3c","source_sha256":"b7170e78418322e217fd49ecc2c6661d1988412e7ea1e4dcbf5cbd2cfeb6ca86","functions":[{"id":"func/_removal_decision_summary","name":"_removal_decision_summary","line":92,"end_line":94,"hash":"d667aee752da438147a4ec70db0a961fe233f2bd85b43f17d5093cf8955ea8d6"},{"id":"func/QualificationFactsV1.canonical_facts","name":"canonical_facts","line":122,"end_line":126,"hash":"e79433cdcf258ae6db4935554e1b3d4e3a7faf7ac00d4bd3add93c9b5d711334"},{"id":"func/_parse_qualification_facts","name":"_parse_qualification_facts","line":129,"end_line":135,"hash":"03ee223c05a0311e8801a378b3c2b2c71b1e99452d41287b46091bbbfe4fc732"},{"id":"func/_load_admitted_scenarios","name":"_load_admitted_scenarios","line":138,"end_line":166,"hash":"730b459ef988526f49fb7b63d6c106b2c717bed87d7f2af071c92051d462e9be"},{"id":"func/_scorecard_qualification_passed","name":"_scorecard_qualification_passed","line":169,"end_line":171,"hash":"9f4709e9478cce1a1455d62578da227705ff09f47854d2e2ac3b6670da3ee3b1"},{"id":"func/_authoritative_products_ready","name":"_authoritative_products_ready","line":174,"end_line":176,"hash":"7f1eb164932cbacbba712867f8071c667eaa60313cbc845dff3e6b47e16d861c"},{"id":"func/_ordinary_completion_succeeded","name":"_ordinary_completion_succeeded","line":179,"end_line":196,"hash":"b88e76347d673d088e57883fd9901eb4eacb3c29f3c250625207d8b73b8c290e"},{"id":"func/_readable_evidence_file","name":"_readable_evidence_file","line":199,"end_line":201,"hash":"4230982093fccad3d46ac9c3fb43f2a408b42e8b0a188ff7a4f8966fffa19f29"},{"id":"func/_load_finalization_tail_inputs","name":"_load_finalization_tail_inputs","line":204,"end_line":222,"hash":"e43d029f16acd7b23abfefc758399769a1df11a9f13fcc0d1e128070a0d57f89"},{"id":"func/_collect_presentation_notes","name":"_collect_presentation_notes","line":225,"end_line":234,"hash":"b5f706b3ad72924d1868a58e6e2c0eb8b6996ac538150173ebae426b09ca51e7"},{"id":"func/_target_to_ingress","name":"_target_to_ingress","line":237,"end_line":241,"hash":"eeecbc8c9a6be3952745a50e34004b25bece6985a4b8c0ffbff16ae7ed410854"},{"id":"func/_finalization_target_outcomes","name":"_finalization_target_outcomes","line":244,"end_line":280,"hash":"1a46ed78b41bf119083f7172f1945bfd9c8b2de037216c124d6028aa6f39577c"},{"id":"func/_coverage_gap_analysis","name":"_coverage_gap_analysis","line":283,"end_line":325,"hash":"3675acefac4afd2d07871bc8bc3609210f6f0e849665e05518768f9cc5c0ee30"},{"id":"func/_remove_stale_optional_products","name":"_remove_stale_optional_products","line":328,"end_line":333,"hash":"4883d28e916fe5e6eb4c62401d2b663dd694f8d945c2ad13e917f95796381fce"},{"id":"func/_provisional_manifest","name":"_provisional_manifest","line":336,"end_line":362,"hash":"7341b6caa99c9c9e64cb0821e63deb96aa381d93fc345158c0332174c4d1efc0"},{"id":"func/_provisional_eval_product","name":"_provisional_eval_product","line":365,"end_line":392,"hash":"1e38b925a306d8a635f5797ed7dcd63d0b79ea96c71707c018f807180f98f83d"},{"id":"func/_terminal_completion_flags","name":"_terminal_completion_flags","line":395,"end_line":407,"hash":"aafec80dede8bd4cd054600bcdd797abd31a80ddd8a48da56abfde791b599f1b"},{"id":"func/_provisional_report_product","name":"_provisional_report_product","line":410,"end_line":438,"hash":"7d24ddb03a3888b6f87737987323f9089fedce0c9a5d08328252c3a4d149f376"},{"id":"func/_close_pipeline_log","name":"_close_pipeline_log","line":441,"end_line":450,"hash":"466a86e12e7b7a5b5e20dc3c4f2a78d484baada225ee24b8d07d73b009d242b6"},{"id":"func/_strict_authoritative_manifest","name":"_strict_authoritative_manifest","line":453,"end_line":478,"hash":"98e65c52b0512ce42bb7aa2b2b56c4ae87479c203b42394f936e80a768b5bbfb"},{"id":"func/_authoritative_second_pass","name":"_authoritative_second_pass","line":481,"end_line":524,"hash":"f947a03163da48fc928f53657f1db18e6703ea87554f0cfd05d89ffcd123d1c5"},{"id":"func/_finalize_run_manifest","name":"_finalize_run_manifest","line":527,"end_line":578,"hash":"ad4960bca2ac6b958d13a4ecadd695115e1638288a641565340eccf818988fe2"},{"id":"func/_result_counts","name":"_result_counts","line":581,"end_line":597,"hash":"c61bb0957c245e8b959b562a1759a1f98b14bb684ec6713ab185af353f1d8f7d"},{"id":"func/_complete_v3_run","name":"_complete_v3_run","line":600,"end_line":721,"hash":"4976227ffb19d32e3424d83b73b12cafb689d4798f70572b7ce108b118b2ef8f"},{"id":"func/_repackage_candidate","name":"_repackage_candidate","line":724,"end_line":734,"hash":"2747d341b8ede075a3b848484e957c9944c11d993846a262d96cee4448a4c081"},{"id":"func/_restore_qualified_candidate","name":"_restore_qualified_candidate","line":737,"end_line":744,"hash":"f5a49c5746dc48050d09f4229c4895cb804d66ccbfc10ab91d9e6f1254d75573"},{"id":"func/_restore_selected","name":"_restore_selected","line":747,"end_line":759,"hash":"32a0348ffef38dd6b7371ef5e584acd3abebdbd5d353f8f36c9ced6151af945b"},{"id":"func/_pattern_counts","name":"_pattern_counts","line":762,"end_line":766,"hash":"13bfd8ee86e94285bbf676cc48ab73e9b77c1d1f5cccce540707b59acf6cb741"},{"id":"func/_coverage_queues_for","name":"_coverage_queues_for","line":769,"end_line":790,"hash":"b275564e6b732e4b6d2a724da1ad9d1a66e0e073055144b58df4104d8019ec6e"},{"id":"func/_hydrate_planning_inputs","name":"_hydrate_planning_inputs","line":793,"end_line":829,"hash":"3bae4a7f8bb9e07197116bfb9d0c263028ca63e5acbca674643d70c70413d1c7"},{"id":"func/resume_pipeline","name":"resume_pipeline","line":832,"end_line":923,"hash":"3afaeaa3ef1f0d34e8460bc6f13b6bbb445dc9051a5ee24e5d440c389815e443"},{"id":"func/run_profile_only","name":"run_profile_only","line":926,"end_line":934,"hash":"655c624fc6fe51e431b1ef1532fcc6302d1a09c38946e58b22195f7b43c1d35f"},{"id":"func/_glob_hash_map","name":"_glob_hash_map","line":937,"end_line":944,"hash":"fc2fa9b251f3442283f01717e77f54e3a1c053717ac0484dc4c23ad1e6005205"},{"id":"func/_source_profile_hash","name":"_source_profile_hash","line":947,"end_line":949,"hash":"b9e8decefc60e478a9ef75cad90921214dae1db1249a3159d2a4a393073027e7"},{"id":"func/_qualification_facts_hash","name":"_qualification_facts_hash","line":952,"end_line":962,"hash":"1b5781f9d5426333b89459c8025ccbe450956c9a639fcad08e5b4502e2c27d82"},{"id":"func/_optional_bundled_hashes","name":"_optional_bundled_hashes","line":965,"end_line":982,"hash":"4a7ff8e16ca8bab575baf946e3bf732788c3f805c5c400f561424945f471a1e4"},{"id":"func/_capture_input_hashes","name":"_capture_input_hashes","line":985,"end_line":1034,"hash":"4ff362185b758cd22521c0a5b6a02e109135542cbf6104865010e0b1148265dd"},{"id":"func/_best_effort_artifact_entry","name":"_best_effort_artifact_entry","line":1053,"end_line":1074,"hash":"5537be912d6b9b11d27caf189421318a896e4aba4b9d1b3954aa489cc1f5aa7b"},{"id":"func/_failed_artifact_entry","name":"_failed_artifact_entry","line":1077,"end_line":1103,"hash":"0db8993aadcb197aa88b167290271fce6f0ac30fb7cf4515a3565acd92325d36"},{"id":"func/_finalization_inventory_receipts","name":"_finalization_inventory_receipts","line":1106,"end_line":1127,"hash":"e592295c4f5c649216f6110e1b9f0c791df3030c5ce9299a207d271d818cbb03"},{"id":"func/_scenario_receipts","name":"_scenario_receipts","line":1130,"end_line":1144,"hash":"7f82719be5f16d58f7991fb6f6ac13d07695a41b0fdb51fa88662f84c5f0c53c"},{"id":"func/_collect_failed_entries","name":"_collect_failed_entries","line":1147,"end_line":1155,"hash":"6eeaeac378f4e136aaf8d51f40c90349ef9909a24eb3486a2f6b98fe63bb5448"},{"id":"func/_build_failed_evidence_inventory","name":"_build_failed_evidence_inventory","line":1158,"end_line":1187,"hash":"998503c8aba825cee225dc5665ec40496678c54ed57de73b65d5f8c231e5994f"},{"id":"func/run_pipeline","name":"run_pipeline","line":1190,"end_line":1268,"hash":"ca83a93d276a7c70cfbd538bfec6835ace3a39257461642e95c09af56c33c688"}]}
# mutate4py-manifest-end
