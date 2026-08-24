"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import importlib.metadata
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from asago_scenario_generator.data.loaders import (
    load_attack_patterns,
    load_risk_extraction,
    load_yaml_strict,
)
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.data.validation import validate_risk_card_coherence
from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.manifest import (
    _ROLE_METADATA,
    ARTIFACT_SCHEMA_VERSION,
    ArtifactEntry,
    ArtifactRole,
    InputHashes,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    ModelConfig,
    Provenance,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    build_in_memory_resolver,
    capture_provenance,
    compute_bytes_sha256,
    compute_config_digest,
    compute_file_sha256,
    finalize_manifest,
    load_manifest,
    resolve_run_dir,
    select_final_run_status,
    validate_completed_inventory,
    validate_generation_run_id,
    write_failed_manifest,
    write_manifest_sentinel,
    write_started_manifest,
)
from asago_scenario_generator.manifest import (
    MANIFEST_V3 as MANIFEST_VERSION,
)
from asago_scenario_generator.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
)
from asago_scenario_generator.models.attack_pattern import (
    EvaluatedFactEvidence,
    validate_attack_pattern,
)
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.candidates import (
    FilteredSeed,
    FilterProtocolError,
    FilterSeedQuarantine,
    RemovalDecision,
    StageRecord,
    apply_rule_based_filter,
    expand_candidates,
    filter_candidates,
)
from asago_scenario_generator.pipeline.coverage import (
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    STAGE_ADMISSION,
    STAGE_FILTER,
    STAGE_GENERATION,
    STAGE_PROJECTION,
    STAGE_QUARANTINE,
    STAGE_RULES,
    STAGE_SELECTION,
    GenerationMode,
    StageLedger,
    build_coverage_universe,
    build_qualified_candidates,
    emit_quality_gaps,
    plan_generation,
)
from asago_scenario_generator.pipeline.generate import generate_run_id
from asago_scenario_generator.pipeline.io import (
    write_filter_quarantine_evidence,
    write_capability_profile,
    write_eval_scorecard,
    write_pipeline_call_log,
    write_threat_surface,
    write_use_case,
)
from asago_scenario_generator.pipeline.profile import infer_capability_profile
from asago_scenario_generator.pipeline.model_configuration import (
    resolve_effective_model_config,
)
from asago_scenario_generator.pipeline.projection import (
    ProjectionReadinessError,
    ProjectionBudget,
    canonical_json_bytes,
    capture_capability_snapshot,
    ensure_projection_readiness,
    project_authoritative_candidates,
)
from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.pipeline.seeds import ScenarioSeed, expand_seeds
from asago_scenario_generator.pipeline.threats import determine_threat_surface
from asago_scenario_generator.prompts import hash_prompt_templates

logger = logging.getLogger(__name__)

_DEFAULT_CROSS_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "mappings"
    / "cross-taxonomy-mappings.yaml"
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
    from asago_scenario_generator.pipeline.persistence import (
        build_semantic_generation_summary,
        read_finalization_inventory,
    )
    from asago_scenario_generator.pipeline.runner_finalization import build_v3_inventory

    started_manifest = load_manifest(run_dir, requested_version=MANIFEST_VERSION)
    if started_manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("v3 completion tail requires STARTED manifest")
    ManifestInventoryResolver(run_dir, started_manifest, check_orphans=False)
    final_inventory_doc = read_finalization_inventory(run_dir)
    semantic_generation = build_semantic_generation_summary(final_inventory_doc)
    admitted_scenarios = _load_admitted_scenarios(
        run_dir, run_id, timestamp_start, provenance, final_inventory_doc
    )
    for scenario in admitted_scenarios:
        for note in scenario.generation.notes or ():
            if (
                note.startswith("presentation_fallback:")
                and note not in generation_notes
            ):
                generation_notes.append(note)
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, admitted_scenarios)
    decisions = {
        item.candidate_id: item for item in final_inventory_doc.admission_decisions
    }
    target_to_ingress = {
        target.effective_target_id: target.entry_point_id
        for target in finalization.coverage_plan.targets
    }
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

    # A prior interrupted completion tail is non-authoritative. Reconcile its
    # optional products before regeneration so failed/disabled retries cannot
    # leave unmanifested stale files behind.
    for stale_name in ("eval-scorecard.yaml", "report.html"):
        (run_dir / stale_name).unlink(missing_ok=True)

    eval_success = False
    qualification_passed = False
    eval_manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("asago-scenario-generator"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir, final_inventory_doc, include_quarantine=False
        ),
    )
    if eval_enabled:
        try:
            from asago_scenario_generator.eval.runner import run_evaluation

            scorecard = run_evaluation(
                resolver=build_in_memory_resolver(run_dir, eval_manifest),
                threats_path=threats_path,
            )
            write_eval_scorecard(scorecard, run_dir)
            eval_success = True
            qualification_passed = scorecard["qualification"]["status"] == "pass"
        except Exception as exc:  # noqa: BLE001 - non-authoritative output
            (run_dir / "eval-scorecard.yaml").unlink(missing_ok=True)
            logger.warning("Eval scorecard generation failed: %s", exc)
    else:
        logger.info("[Eval] Skipped (--no-eval) — non-authoritative.")

    had_quarantine = bool(
        final_inventory_doc.quarantine_inventory or filter_quarantines
    )
    terminal_processing_succeeded = all(
        target.target_state.value in {"admitted", "exhausted"}
        for target in finalization.coverage_plan.targets
    )
    report_success = False
    try:
        from asago_scenario_generator.report.data import load_report_data
        from asago_scenario_generator.report.generator import generate_report

        report_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("asago-scenario-generator"),
            provenance=provenance,
            inventory=build_v3_inventory(
                run_dir, final_inventory_doc, include_eval=eval_success
            ),
        )
        report_data = load_report_data(
            resolver=build_in_memory_resolver(run_dir, report_manifest)
        )
        generate_report(report_data, run_dir)
        report_success = True
    except Exception as exc:  # noqa: BLE001 - non-authoritative output
        (run_dir / "report.html").unlink(missing_ok=True)
        logger.warning("Report generation failed: %s", exc)

    # Close the pipeline log before hashing the complete candidate inventory.
    # The first eval/report products above are deliberately provisional: they
    # break the scorecard/report inventory cycle but cannot authorize a run.
    sf_logger = logging.getLogger("asago_scenario_generator")
    for handler in sf_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.flush()
            handler.close()
            sf_logger.removeHandler(handler)

    # Authoritative second pass. The complete provisional inventory is first
    # reconciled with orphan checking enabled. Evaluation is then recomputed
    # from that strict resolver, the scorecard hash is rebuilt, and the report
    # is regenerated from the final scorecard before final hashes/validation.
    if eval_success and report_success:
        try:
            from asago_scenario_generator.eval.runner import run_evaluation
            from asago_scenario_generator.report.data import load_report_data
            from asago_scenario_generator.report.generator import generate_report

            candidate_manifest = RunManifest(
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
            strict_eval_resolver = ManifestInventoryResolver(
                run_dir, candidate_manifest, check_orphans=True
            )
            scorecard = run_evaluation(
                resolver=strict_eval_resolver,
                threats_path=threats_path,
            )
            write_eval_scorecard(scorecard, run_dir)
            qualification_passed = scorecard["qualification"]["status"] == "pass"

            report_manifest = RunManifest(
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
            strict_report_resolver = ManifestInventoryResolver(
                run_dir, report_manifest, check_orphans=True
            )
            report_data = load_report_data(resolver=strict_report_resolver)
            generate_report(report_data, run_dir)
        except Exception as exc:  # noqa: BLE001 - run remains non-authoritative
            eval_success = False
            report_success = False
            qualification_passed = False
            (run_dir / "eval-scorecard.yaml").unlink(missing_ok=True)
            (run_dir / "report.html").unlink(missing_ok=True)
            logger.warning("Authoritative eval/report finalization failed: %s", exc)

    ordinary_completion_succeeded = (
        terminal_processing_succeeded
        and not had_quarantine
        and eval_enabled
        and eval_success
        and report_success
        and qualification_passed
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
    filter_quarantine_count = len(filter_quarantines or [])
    admitted_count = sum(
        decision.admitted for decision in final_inventory_doc.admission_decisions
    )
    finalization_quarantine_count = len(final_inventory_doc.quarantine_inventory)
    failed_count = sum(
        decision.status.value == "generation_or_finalization_failed"
        for decision in final_inventory_doc.admission_decisions
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
        manifest_status=final_status,
        admitted_count=admitted_count,
        quarantined_count=finalization_quarantine_count + filter_quarantine_count,
        failed_count=failed_count,
    )


def _hydrate_planning_inputs(
    planning: object, durable_plan: object, coverage_universe: object
) -> tuple[object, dict, dict]:
    """Rebuild the exact typed selection inputs persisted before finalization."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        QualifiedCandidate,
        SelectionResult,
        TargetFallbackQueue,
        deserialize_qualified_candidate,
    )

    hydrated_by_id: dict[str, QualifiedCandidate] = {}
    target_queues: dict[str, TargetFallbackQueue] = {}
    coverage_candidates: dict[str, list[QualifiedCandidate]] = {}
    for target in durable_plan.targets:
        choices: list[QualifiedCandidate] = []
        for ref in target.ordered_choices:
            hydrated = deserialize_qualified_candidate(ref.model_dump(mode="json"))
            candidate = QualifiedCandidate(
                projected=hydrated.projected,
                accepted_filters=hydrated.accepted_filters,
                rank=hydrated.rank,
            )
            choices.append(candidate)
            hydrated_by_id[candidate.candidate_id] = candidate
            coverage_candidates.setdefault(target.entry_point_id, []).append(candidate)
        target_queues[target.effective_target_id] = TargetFallbackQueue(
            entry_point_id=target.effective_target_id,
            choices=choices,
        )
    try:
        selected = [
            QualifiedCandidate(
                projected=hydrated_by_id[item].projected,
                accepted_filters=hydrated_by_id[item].accepted_filters,
                rank=rank,
            )
            for rank, item in enumerate(planning.selected_candidate_ids)
        ]
    except KeyError as exc:
        raise ManifestIntegrityError(
            "planning checkpoint selected candidate is absent from plan"
        ) from exc
    actual_pattern_counts: dict[str, int] = {}
    for candidate in selected:
        actual_pattern_counts[candidate.pattern_id] = (
            actual_pattern_counts.get(candidate.pattern_id, 0) + 1
        )
    if actual_pattern_counts != planning.per_pattern_counts:
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
    coverage_queues = {
        target.entry_point_id: TargetFallbackQueue(
            entry_point_id=target.entry_point_id,
            choices=[
                QualifiedCandidate(
                    projected=candidate.projected,
                    accepted_filters=candidate.accepted_filters,
                    rank=rank,
                )
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


def _resolve_resume_directory(run_dir: Path) -> Path:
    """Resolve the run directory strictly, or reject the resume."""
    try:
        supplied = Path(run_dir).resolve(strict=True)
    except OSError as exc:
        raise ManifestIntegrityError(
            "resume requires an existing run directory"
        ) from exc
    if not supplied.is_dir():
        raise ManifestIntegrityError("resume requires an existing run directory")
    return supplied


def _load_resumable_manifest(supplied: Path) -> Any:
    """Load the manifest and require a v3 STARTED status."""
    manifest = load_manifest(supplied, requested_version=MANIFEST_VERSION)
    if manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("only a v3 STARTED run can be resumed")
    return manifest


def _validate_resume_manifest_identity(supplied: Path, manifest: Any) -> None:
    """Require canonical run_id, matching directory name, and provenance."""
    try:
        validate_generation_run_id(manifest.run_id)
    except ValueError as exc:
        raise ManifestIntegrityError("resume manifest has noncanonical run_id") from exc
    if supplied.name != manifest.run_id:
        raise ManifestIntegrityError("manifest run_id does not match run directory")
    if manifest.provenance is None or manifest.provenance.run_id != manifest.run_id:
        raise ManifestIntegrityError("manifest provenance run_id mismatch")


def _load_resume_support_artifacts(
    supplied: Path,
    manifest: Any,
    support: Any,
) -> tuple[str, CapabilityProfile, ThreatSurface, Any]:
    """Read and validate the immutable resume support inventory."""
    from asago_scenario_generator.pipeline.persistence import (
        read_finalization_inventory,
        read_planning_checkpoint_bytes,
        recover_finalization_journal,
    )

    use_entry = support.entry_by_role(ArtifactRole.USE_CASE)
    profile_entry = support.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    threat_entry = support.entry_by_role(ArtifactRole.THREAT_SURFACE)
    planning_entry = support.entry_by_role(ArtifactRole.PLANNING_CHECKPOINT)
    if not all((use_entry, profile_entry, threat_entry, planning_entry)):
        raise ManifestIntegrityError("started manifest support inventory is incomplete")
    use_case = support.read_text(use_entry)
    profile = CapabilityProfile.model_validate(support.read_yaml(profile_entry))
    threat_surface = ThreatSurface.model_validate(support.read_yaml(threat_entry))
    planning = read_planning_checkpoint_bytes(support.read_bytes(planning_entry))
    recover_finalization_journal(supplied, expected_run_id=manifest.run_id)
    inventory = read_finalization_inventory(supplied)
    if inventory.run_id != manifest.run_id:
        raise ManifestIntegrityError("finalization inventory run_id mismatch")
    return use_case, profile, threat_surface, planning


def _resume_command_options(
    provenance: Any,
) -> tuple[dict[str, Any], bool]:
    """Extract and validate the persisted command options."""
    options = provenance.command.options
    required_paths = {
        "risk_extraction_path",
        "sssom_path",
        "cross_taxonomy_path",
        "threats_path",
    }
    if not required_paths.issubset(options):
        raise ManifestIntegrityError("resume command provenance is incomplete")
    persisted_eval = options.get("eval")
    if not isinstance(persisted_eval, bool):
        raise ManifestIntegrityError("resume eval provenance must be boolean")
    _validate_resume_presentation_fallback(
        options.get("presentation_fallback", "allow")
    )
    _validate_resume_generation_mode(
        options.get("generation_mode", GenerationMode.COVERAGE.value)
    )
    return options, persisted_eval


def _validate_resume_presentation_fallback(value: Any) -> None:
    """Require a valid persisted presentation fallback mode."""
    if value not in {"allow", "forbid"}:
        raise ManifestIntegrityError(
            "resume presentation fallback provenance is invalid"
        )


def _validate_resume_generation_mode(value: Any) -> None:
    """Require a valid persisted generation mode."""
    try:
        GenerationMode(value)
    except ValueError as exc:
        raise ManifestIntegrityError(
            "resume generation mode provenance is invalid"
        ) from exc


def _validate_resume_provenance_inputs(manifest: Any, use_case: str) -> None:
    """Require config, prompt-template, and use-case provenance stability."""
    provenance = manifest.provenance
    if provenance.config_digest != compute_config_digest(provenance.command.options):
        raise ManifestIntegrityError("resume configuration provenance drift")
    if provenance.prompt_template_hashes != hash_prompt_templates():
        raise ManifestIntegrityError("resume prompt template provenance drift")
    if provenance.input_hashes.use_case_hash != compute_bytes_sha256(
        use_case.encode("utf-8")
    ):
        raise ManifestIntegrityError("resume use-case provenance drift")


def _validate_resume_eval_override(eval: bool | None, persisted_eval: bool) -> None:
    """Reject eval overrides that contradict the persisted run option."""
    if eval is not None and eval is not persisted_eval:
        raise ManifestIntegrityError("resume eval override conflicts with provenance")


def _resume_input_paths(options: dict[str, Any]) -> list[Path | None]:
    """Return the six canonical input paths from persisted options."""
    return [
        Path(options["risk_extraction_path"]),
        Path(options["sssom_path"]),
        Path(options["cross_taxonomy_path"]),
        Path(options["threats_path"]),
        Path(options["profile_path"]) if options.get("profile_path") else None,
        (
            Path(options["qualification_facts_path"])
            if options.get("qualification_facts_path")
            else None
        ),
    ]


def _validate_resume_input_hash_drift(
    current_hashes: Any, persisted_hashes: Any
) -> None:
    """Require every canonical input hash to match the persisted hashes."""
    for field in (
        "risk_extraction_hash",
        "sssom_hash",
        "cross_taxonomy_hash",
        "threats_hash",
        "source_profile_hash",
        "qualification_facts_hash",
        "attack_patterns_hash",
        "attack_patterns_sssom_hash",
        "attack_goals_taxonomy_hash",
        "threat_goal_affinity_hash",
        "attack_patterns_yaml_map",
        "attack_patterns_sssom_map",
    ):
        if getattr(current_hashes, field) != getattr(persisted_hashes, field):
            raise ManifestIntegrityError(f"resume input provenance drift: {field}")


def _validate_resume_facts_absent(planning: Any, persisted_hashes: Any) -> None:
    """Reject a missing facts path when any fact provenance claims exist."""
    if (
        planning.qualification_facts_source is not None
        or planning.qualification_facts_sha256 is not None
        or persisted_hashes.qualification_facts_hash is not None
    ):
        raise ManifestIntegrityError(
            "resume qualification facts provenance is inconsistent"
        )


def _parse_resume_facts(planning: Any, persisted_hashes: Any) -> tuple[Any, ...]:
    """Verify and parse persisted qualification facts when present."""
    source_bytes = planning.qualification_facts_source.encode("utf-8")
    if compute_bytes_sha256(source_bytes) != persisted_hashes.qualification_facts_hash:
        raise ManifestIntegrityError("resume qualification facts provenance drift")
    try:
        return _parse_qualification_facts(source_bytes).facts
    except ValueError as exc:
        raise ManifestIntegrityError(str(exc)) from exc


def _resume_qualification_facts(
    planning: Any,
    persisted_hashes: Any,
    options: dict[str, Any],
) -> tuple[Any, ...]:
    """Return parsed qualification facts consistent with persisted provenance."""
    facts_path = options.get("qualification_facts_path")
    if facts_path is None:
        _validate_resume_facts_absent(planning, persisted_hashes)
        return ()
    if planning.qualification_facts_source is None:
        raise ManifestIntegrityError(
            "resume planning checkpoint lacks qualification facts source"
        )
    return _parse_resume_facts(planning, persisted_hashes)


def _revalidate_resume_candidates(
    durable_plan: Any,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: list[dict[str, Any]],
) -> None:
    """Revalidate every durable plan choice against its qualified source."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        revalidate_qualified_candidate,
    )

    try:
        for target in durable_plan.targets:
            for choice in target.ordered_choices:
                revalidate_qualified_candidate(
                    choice.model_dump(mode="json"),
                    taxonomy_resolver,
                    capability_snapshot,
                    trusted_catalog,
                )
    except Exception as exc:
        raise ManifestIntegrityError(
            f"resume durable candidate provenance drift: {exc}"
        ) from exc


def _setup_resume_logging(
    log_level: str,
    supplied: Path,
    structured: bool,
) -> None:
    """Configure run-local logging for the resumed run."""
    from asago_scenario_generator.log_config import setup_logging

    setup_logging(log_level=log_level, output_dir=supplied, structured=structured)


def _validate_resume_model_config(
    model: str | None,
    base_url: str | None,
    persisted_model: Any,
) -> None:
    """Require persisted model configuration and consistent overrides."""
    if persisted_model is None:
        raise ManifestIntegrityError(
            "resumable v3 run requires persisted model configuration"
        )
    _validate_resume_model_override(model, persisted_model)
    _validate_resume_endpoint_override(base_url, persisted_model)


def _validate_resume_model_override(model: str | None, persisted_model: Any) -> None:
    """Reject model overrides that contradict the persisted model."""
    if model is not None and model != persisted_model.model:
        raise ManifestIntegrityError("resume model override conflicts with provenance")


def _validate_resume_endpoint_override(
    base_url: str | None,
    persisted_model: Any,
) -> None:
    """Reject endpoint overrides that contradict the persisted model."""
    if base_url is not None and base_url != persisted_model.base_url:
        raise ManifestIntegrityError(
            "resume endpoint override conflicts with provenance"
        )


def _resolved_resume_base_url(base_url: str | None, persisted_model: Any) -> str | None:
    """Return the override base URL, or the persisted base URL."""
    return base_url or (persisted_model.base_url if persisted_model else None)


def _resolved_resume_model(model: str | None, persisted_model: Any) -> str | None:
    """Return the override model, or the persisted model."""
    return model or (persisted_model.model if persisted_model else None)


def _persisted_temperature(persisted_model: Any) -> float | None:
    """Return the persisted temperature, if any."""
    return persisted_model.temperature if persisted_model else None


def _persisted_max_completion_tokens(persisted_model: Any) -> int | None:
    """Return the persisted max completion tokens, if any."""
    return persisted_model.max_completion_tokens if persisted_model else None


def _resume_llm_client(
    base_url: str | None,
    api_key: str | None,
    model: str | None,
    persisted_model: Any,
) -> Any:
    """Build the resume LLM client from persisted model configuration."""
    return LLMClient(
        base_url=_resolved_resume_base_url(base_url, persisted_model),
        api_key=api_key,
        model=_resolved_resume_model(model, persisted_model),
        temperature=_persisted_temperature(persisted_model),
        max_completion_tokens=_persisted_max_completion_tokens(persisted_model),
    )


def persisted_presentation_fallback(options: dict[str, Any]) -> str:
    """Return the persisted presentation fallback mode."""
    return options.get("presentation_fallback", "allow")


def _resume_stage_ledger(planning: Any) -> Any:
    """Rebuild the stage ledger from persisted stage events."""
    from asago_scenario_generator.pipeline.coverage_planning import StageEvent

    return StageLedger(
        events=[
            StageEvent(**item.model_dump(mode="python"))
            for item in planning.stage_events
        ]
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
    from asago_scenario_generator.data.loaders import (
        _THREAT_GOAL_AFFINITY_PATH,
    )
    from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

    effective_threats = threats_path or _DEFAULT_THREATS_PATH

    # Bundled data paths
    data_root = Path(__file__).resolve().parents[3] / "data" / "taxonomies"
    attack_patterns_dir = data_root / "attack-patterns"
    attack_patterns_yaml = attack_patterns_dir / "attack-patterns.yaml"
    attack_patterns_sssom = attack_patterns_dir / "attack-patterns.sssom.tsv"
    attack_goals_json = data_root / "attack-goals" / "attack-goals.json"

    # Hash every file actually loaded by the attack-patterns*.yaml and
    # attack-patterns*.sssom.tsv globs as deterministic sorted path→hash maps.
    attack_patterns_yaml_map: dict[str, str] = {}
    attack_patterns_sssom_map: dict[str, str] = {}
    if attack_patterns_dir.exists():
        for yaml_file in sorted(attack_patterns_dir.glob("attack-patterns*.yaml")):
            rel = str(yaml_file.relative_to(data_root))
            attack_patterns_yaml_map[rel] = compute_file_sha256(yaml_file)
        for sssom_file in sorted(
            attack_patterns_dir.glob("attack-patterns*.sssom.tsv")
        ):
            rel = str(sssom_file.relative_to(data_root))
            attack_patterns_sssom_map[rel] = compute_file_sha256(sssom_file)

    hashes = InputHashes(
        use_case_hash=compute_bytes_sha256(use_case.encode("utf-8")),
        risk_extraction_hash=compute_file_sha256(risk_extraction_path),
        sssom_hash=compute_file_sha256(sssom_path),
        cross_taxonomy_hash=compute_file_sha256(ct_path),
        threats_hash=compute_file_sha256(effective_threats),
        attack_patterns_yaml_map=attack_patterns_yaml_map,
        attack_patterns_sssom_map=attack_patterns_sssom_map,
    )
    if profile_path is not None:
        hashes.source_profile_hash = compute_file_sha256(profile_path)
    if qualification_facts_bytes is not None:
        hashes.qualification_facts_hash = compute_bytes_sha256(
            qualification_facts_bytes
        )
    elif qualification_facts_path is not None:
        hashes.qualification_facts_hash = compute_file_sha256(qualification_facts_path)
    if attack_patterns_yaml.exists():
        hashes.attack_patterns_hash = compute_file_sha256(attack_patterns_yaml)
    if attack_patterns_sssom.exists():
        hashes.attack_patterns_sssom_hash = compute_file_sha256(attack_patterns_sssom)
    if attack_goals_json.exists():
        hashes.attack_goals_taxonomy_hash = compute_file_sha256(attack_goals_json)
    if _THREAT_GOAL_AFFINITY_PATH.exists():
        hashes.threat_goal_affinity_hash = compute_file_sha256(
            _THREAT_GOAL_AFFINITY_PATH
        )
    return hashes


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

    def _add_if_exists(
        role: ArtifactRole,
        rel_path: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        full = run_dir / rel_path
        if full.exists() and full.is_file():
            try:
                inventory.append(
                    build_artifact_entry(
                        role=role,
                        run_dir=run_dir,
                        rel_path=rel_path,
                        scenario_id=scenario_id,
                        candidate_id=candidate_id,
                        schema_version=(
                            "2" if role is ArtifactRole.COVERAGE_PLAN else "1"
                        ),
                    )
                )
            except ManifestIntegrityError:
                # If we cannot build a valid entry (e.g. hash computation
                # failure), still record the file with a best-effort hash
                # so orphan checks don't flag it.  This is evidence, not
                # authoritative inventory.
                try:
                    inventory.append(
                        ArtifactEntry(
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
                    )
                except Exception:  # noqa: BLE001, S110 - orphan check will flag unreadable files
                    pass  # truly unreadable — orphan check will flag it

    # Top-level singleton artifacts
    _add_if_exists(ArtifactRole.USE_CASE, "use-case.txt")
    _add_if_exists(ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml")
    _add_if_exists(ArtifactRole.THREAT_SURFACE, "threat-surface.yaml")
    _add_if_exists(ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json")
    _add_if_exists(ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json")
    _add_if_exists(ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl")
    _add_if_exists(ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml")
    _add_if_exists(ArtifactRole.REPORT, "report.html")
    _add_if_exists(ArtifactRole.PIPELINE_LOG, "pipeline.log")
    _add_if_exists(ArtifactRole.COVERAGE_PLAN, "coverage-plan.json")
    _add_if_exists(ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json")
    _add_if_exists(
        ArtifactRole.CANDIDATE_FILTER_QUARANTINE,
        "candidate-filter-quarantine.json",
    )

    # V3 terminal files are discovered only through the durable inventory,
    # never by globbing scenario/quarantine directories.
    finalization_path = run_dir / "finalization-inventory.json"
    if finalization_path.is_file():
        try:
            from asago_scenario_generator.pipeline.persistence import (
                FinalizationInventoryV1,
            )

            finalization_inventory = FinalizationInventoryV1.model_validate_json(
                finalization_path.read_text(encoding="utf-8")
            )
            for receipt in [
                *finalization_inventory.admitted_inventory,
                *finalization_inventory.quarantine_inventory,
            ]:
                _add_if_exists(
                    receipt.role,
                    receipt.path,
                    scenario_id=receipt.scenario_id,
                    candidate_id=receipt.candidate_id,
                )
        except Exception:  # noqa: BLE001, S110 - failed-manifest evidence is best effort
            pass

    # Scenario artifacts from write receipts
    for receipt in write_receipts:
        sid = receipt.get("scenario_id")
        cid = receipt.get("candidate_id")
        yaml_name = Path(receipt["yaml_path"]).name
        _add_if_exists(
            ArtifactRole.SCENARIO_YAML,
            f"scenarios/{yaml_name}",
            scenario_id=sid,
            candidate_id=cid,
        )
        feat_path = receipt.get("feature_path")
        if feat_path:
            feat_name = Path(feat_path).name
            _add_if_exists(
                ArtifactRole.SCENARIO_FEATURE,
                f"scenarios/{feat_name}",
                scenario_id=sid,
                candidate_id=cid,
            )

    # Optional scenario call log
    _add_if_exists(ArtifactRole.SCENARIO_CALL_LOG, "scenarios/calls.jsonl")

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


def _run_pipeline_guarded(
    *,
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    output_dir: Path,
    cross_taxonomy_path: Path | None,
    threats_path: Path | None,
    profile_path: Path | None,
    qualification_facts_path: Path | None,
    base_url: str | None,
    api_key: str | None,
    model: str | None,
    model_profile: str | None,
    profiles_file: Path,
    presentation_fallback: str,
    max_techniques: int,
    max_scenarios_per_pattern: int | None,
    generation_mode: str,
    zones: str | None,
    eval: bool,
    log_level: str,
    structured: bool,
) -> PipelineResult:
    """Run the guarded lifecycle with persistent failed-manifest recovery."""
    resolved_generation_mode = _validate_run_pipeline_options(
        presentation_fallback, max_scenarios_per_pattern, generation_mode
    )
    generation_notes: list[str] = []

    # --- Per-invocation run identity (cmps.1 sortable format) ---
    run_id = generate_run_id()

    # --- Collection → run directory resolution (single ownership boundary) ---
    # This happens BEFORE any fallible setup (LLMClient, logging, etc.)
    # so the immutable run directory and sentinel exist for every exit path.
    run_dir, run_id = resolve_run_dir(output_dir, run_id)

    # --- Manifest sentinel before any pipeline work ---
    timestamp_start = datetime.now(UTC).isoformat()
    write_manifest_sentinel(
        run_dir, run_id, timestamp_start, manifest_version=MANIFEST_VERSION
    )

    # --- Initialize state needed by the v3 failed-manifest recovery path ---
    provenance: Provenance | None = None
    partial_manifest: RunManifest | None = None

    return _run_pipeline_body(
        use_case=use_case,
        risk_extraction_path=risk_extraction_path,
        sssom_path=sssom_path,
        run_dir=run_dir,
        cross_taxonomy_path=_resolve_cross_taxonomy_path(cross_taxonomy_path),
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
        resolved_generation_mode=resolved_generation_mode,
        zones=zones,
        eval=eval,
        log_level=log_level,
        structured=structured,
        run_id=run_id,
        timestamp_start=timestamp_start,
        provenance=provenance,
        partial_manifest=partial_manifest,
        generation_notes=generation_notes,
    )


def _validate_run_pipeline_options(
    presentation_fallback: str,
    max_scenarios_per_pattern: int | None,
    generation_mode: str,
) -> GenerationMode:
    """Validate CLI-level option contracts up front."""
    if presentation_fallback not in {"allow", "forbid"}:
        raise ValueError("presentation_fallback must be 'allow' or 'forbid'")
    if max_scenarios_per_pattern is not None and max_scenarios_per_pattern < 1:
        raise ValueError("max_scenarios_per_pattern must be a positive integer")
    try:
        return GenerationMode(generation_mode)
    except ValueError as exc:
        raise ValueError("generation_mode must be 'exhaustive' or 'coverage'") from exc


def _resolve_cross_taxonomy_path(
    cross_taxonomy_path: Path | None,
) -> Path:
    """Return the explicit cross-taxonomy path, or the bundled default."""
    return cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH


def _recover_and_reraise_failed_run(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    partial_manifest: RunManifest | None,
    exc: Exception,
) -> None:
    """Flush run-local handlers, write a best-effort failed manifest, and
    re-raise the original pipeline failure."""
    _run_failure_log_flush()
    logging.getLogger("asago_scenario_generator").error("Pipeline failed: %s", exc)
    try:
        failed_manifest = _failed_manifest_for(
            run_dir, run_id, timestamp_start, provenance, partial_manifest, exc
        )
        _mark_failed_manifest(failed_manifest, exc)
        _write_failed_manifest_evidence(run_dir, run_id, failed_manifest, exc)
        raise
    except Exception:  # noqa: BLE001, S110 - best-effort write during error path
        pass
    raise


def _run_failure_log_flush() -> None:
    """Flush and remove run-local file handlers before writing failure
    evidence."""
    sf_logger = logging.getLogger("asago_scenario_generator")
    for handler in sf_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            try:
                handler.flush()
                handler.close()
            except Exception:  # noqa: BLE001, S110 - handler cleanup must not fail
                pass
            sf_logger.removeHandler(handler)


def _failed_manifest_for(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    partial_manifest: RunManifest | None,
    exc: Exception,
) -> RunManifest:
    """Return the partial manifest, or a sentinel-based fallback manifest."""
    if partial_manifest is not None:
        return partial_manifest
    try:
        return load_manifest(run_dir)
    except Exception:  # noqa: BLE001 - create fallback manifest if load fails
        return RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("asago-scenario-generator"),
            provenance=Provenance(
                run_id=run_id,
                timestamp_start=timestamp_start,
            )
            if provenance is not None
            else None,
        )


def _mark_failed_manifest(failed_manifest: RunManifest, exc: Exception) -> None:
    """Record the failure status, end time, and error description."""
    failed_manifest.status = RunStatus.FAILED
    failed_manifest.timestamp_end = datetime.now(UTC).isoformat()
    failure_code = getattr(exc, "failure_code", None)
    failed_manifest.error = f"{failure_code}: {exc}" if failure_code else str(exc)
    if failed_manifest.provenance:
        failed_manifest.provenance.timestamp_end = failed_manifest.timestamp_end


def _started_support_manifest(run_dir: Path) -> Any:
    """Load the started manifest, tolerating very early failures."""
    try:
        return load_manifest(run_dir, requested_version=MANIFEST_VERSION)
    except Exception:  # noqa: BLE001 - early failures may predate sentinel
        return None


def _immutable_roles_by_role(
    started_manifest: Any, immutable_roles: set[Any]
) -> dict[Any, Any]:
    """Map immutable support artifact roles to their entries, if published."""
    if started_manifest is None:
        return {}
    return {
        item.role: item
        for item in started_manifest.inventory
        if item.role in immutable_roles
    }


def _support_published(started_manifest: Any, immutable_roles: set[Any]) -> bool:
    """True when every immutable support role is published."""
    if started_manifest is None:
        return False
    return set(_immutable_roles_by_role(started_manifest, immutable_roles)) == (
        immutable_roles
    )


def _support_validation_result(
    run_dir: Path,
    started_manifest: Any,
    immutable_roles: set[Any],
    exc: Exception,
) -> tuple[bool, str | None]:
    """Validate immutable support resolution; returns (valid, error)."""
    if not _support_published(started_manifest, immutable_roles):
        return False, None
    try:
        ManifestInventoryResolver(run_dir, started_manifest, check_orphans=False)
    except ManifestIntegrityError as support_exc:
        return (
            False,
            f"{exc}; immutable support validation failed: {support_exc}",
        )
    return True, None


def _write_failed_manifest_evidence(
    run_dir: Path,
    run_id: str,
    failed_manifest: RunManifest,
    exc: Exception,
) -> None:
    """Recover the journal and publish the failed manifest inventory."""
    immutable_roles = {
        ArtifactRole.USE_CASE,
        ArtifactRole.CAPABILITY_PROFILE,
        ArtifactRole.THREAT_SURFACE,
        ArtifactRole.PLANNING_CHECKPOINT,
    }
    started_manifest = _started_support_manifest(run_dir)
    original_by_role = _immutable_roles_by_role(started_manifest, immutable_roles)
    support_valid, support_error = _support_validation_result(
        run_dir, started_manifest, immutable_roles, exc
    )
    if support_error is not None:
        failed_manifest.error = support_error
    if support_valid:
        from asago_scenario_generator.pipeline.persistence import (
            recover_finalization_journal,
        )

        recover_finalization_journal(run_dir, expected_run_id=run_id)
    evidence_inventory = _build_failed_evidence_inventory(run_dir, [])
    failed_manifest.inventory = [
        item for item in evidence_inventory if item.role not in original_by_role
    ] + list(original_by_role.values())
    write_failed_manifest(run_dir, failed_manifest)


def _ingest_qualification_facts(
    qualification_facts_path: Path | None,
    generation_notes: list[str],
) -> tuple[bytes | None, str | None, tuple[Any, ...]]:
    """Read and parse explicit qualification facts, if any."""
    qualification_facts_bytes = (
        qualification_facts_path.read_bytes()
        if qualification_facts_path is not None
        else None
    )
    qualification_facts_source: str | None = None
    qualification_facts: tuple[Any, ...] = ()
    if qualification_facts_bytes is not None:
        qualification_facts_source = qualification_facts_bytes.decode("utf-8")
        qualification_facts = _parse_qualification_facts(
            qualification_facts_bytes
        ).facts
    else:
        generation_notes.append(
            "qualification_facts_omitted: compatibility mode defers "
            "unresolved fact conditions to authoritative projection"
        )
    return qualification_facts_bytes, qualification_facts_source, qualification_facts


def _qualification_facts_mode_label(qualification_facts_path: Path | None) -> str:
    """Return the qualification facts mode label for logging."""
    return (
        "explicit" if qualification_facts_path is not None else "omitted_compatibility"
    )


def _resolve_effective_threats_path(threats_path: Path | None) -> Path:
    """Resolve the effective threats path against the bundled default."""
    from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

    return (threats_path or _DEFAULT_THREATS_PATH).resolve()


def _parse_effective_zones(zones: str | None) -> list[str] | None:
    """Parse and trim the zones option into a canonical list."""
    if zones is None:
        return None
    return [z.strip() for z in zones.split(",") if z.strip()]


def _model_control_sources(effective_model: Any) -> dict[str, str]:
    """Return non-secret model control sources for the config digest."""
    return {
        key: value.value
        for key, value in effective_model.sources.items()
        if key != "api_key"
    }


def _sorted_header_names(effective_model: Any) -> list[str]:
    """Return sorted extra-header names for the config digest."""
    return sorted((effective_model.extra_headers or {}).keys())


def _effective_pipeline_options(
    *,
    input_hashes: Any,
    risk_extraction_path: Path,
    sssom_path: Path,
    ct_path: Path,
    effective_threats_path: Path,
    profile_path: Path | None,
    client: Any,
    max_techniques: int,
    max_scenarios_per_pattern: int | None,
    resolved_generation_mode: GenerationMode,
    effective_zones: list[str] | None,
    eval: bool,
    model_profile: str | None,
    profiles_file: Path,
    effective_model: Any,
    presentation_fallback: str,
    qualification_facts_path: Path | None,
) -> dict[str, Any]:
    """Build the canonical effective-options dict for provenance."""
    effective_options = {
        "use_case_hash": input_hashes.use_case_hash,
        "risk_extraction_path": str(risk_extraction_path.resolve()),
        "sssom_path": str(sssom_path.resolve()),
        "cross_taxonomy_path": str(ct_path.resolve()),
        "threats_path": str(effective_threats_path),
        "profile_path": str(profile_path.resolve()) if profile_path else None,
        "model": client.model,
        "base_url": client.base_url,
        "temperature": client.temperature,
        "max_completion_tokens": client.max_completion_tokens,
        "max_techniques": max_techniques,
        "max_scenarios_per_pattern": max_scenarios_per_pattern,
        "generation_mode": resolved_generation_mode.value,
        "zones": effective_zones,
        "eval": eval,
        "model_profile": model_profile,
        "profiles_file": (
            str(profiles_file.resolve()) if model_profile is not None else None
        ),
        "model_control_sources": _model_control_sources(effective_model),
        "timeout": effective_model.timeout,
        "top_p": effective_model.top_p,
        "top_k": effective_model.top_k,
        "use_guided_decoding": effective_model.use_guided_decoding,
        "header_names": _sorted_header_names(effective_model),
        "presentation_fallback": presentation_fallback,
        "qualification_facts_mode": (
            "explicit"
            if qualification_facts_path is not None
            else "omitted_compatibility"
        ),
    }
    if qualification_facts_path is not None:
        effective_options["qualification_facts_path"] = str(
            qualification_facts_path.resolve()
        )
    return effective_options


def _load_or_infer_profile(
    profile_path: Path | None,
    use_case: str,
    client: Any,
    run_dir: Path,
) -> CapabilityProfile:
    """Load a pre-built capability profile, or infer and log one."""
    if profile_path is not None:
        logger.info("[Stage 1] Loading capability profile from %s", profile_path)
        profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        return CapabilityProfile(**profile_data)
    logger.info("[Stage 1] Inferring capability profile...")
    profile, profile_llm_result = infer_capability_profile(use_case, client)
    _log_profile_inference_call(profile_llm_result, run_dir)
    return profile


def _log_profile_inference_call(profile_llm_result: Any, run_dir: Path) -> None:
    """Log the profile inference LLM call to top-level calls.jsonl."""
    raw_content = profile_llm_result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    write_pipeline_call_log(
        [
            {
                "call": "capability_profile",
                "system_prompt": profile_llm_result.system_prompt,
                "user_prompt": profile_llm_result.user_prompt,
                "response": raw_content,
                "prompt_tokens": profile_llm_result.prompt_tokens,
                "completion_tokens": profile_llm_result.completion_tokens,
                "duration_ms": profile_llm_result.duration_ms,
            }
        ],
        run_dir,
    )


def _zone_tag_pattern() -> Any:
    """Compile the entry-point zone-tag suffix pattern."""
    _zone_alts = "|".join(re.escape(z) for z in ZONE_NAMES)
    return re.compile(
        r"\s*\((" + _zone_alts + r")\)\s*$",
    )


def _validate_requested_zones(zones: str) -> list[str]:
    """Validate requested zone names against the canonical set."""
    requested = [z.strip() for z in zones.split(",")]
    invalid = [z for z in requested if z not in ZONE_NAMES]
    if invalid:
        raise ValueError(
            f"Unknown zone(s): {', '.join(invalid)}. Valid: {', '.join(ZONE_NAMES)}"
        )
    return requested


def _strip_zone_kc_codes(kc_codes: list[str], filtered: list[str]) -> list[str]:
    """Strip KC codes for excluded memory/inter-agent zones."""
    return _strip_inter_agent_kc_codes(
        _strip_memory_kc_codes(kc_codes, filtered), filtered
    )


def _strip_memory_kc_codes(kc_codes: list[str], filtered: list[str]) -> list[str]:
    """Strip memory-zone KC codes when the memory zone is filtered out."""
    if "memory" not in filtered:
        return [
            kc
            for kc in kc_codes
            if kc not in {"KC4.3", "KC4.4", "KC4.5", "KC4.6", "KCX-PMEM"}
        ]
    return kc_codes


def _strip_inter_agent_kc_codes(kc_codes: list[str], filtered: list[str]) -> list[str]:
    """Strip inter-agent KC codes when the inter-agent zone is filtered out."""
    if "inter_agent" not in filtered:
        return [kc for kc in kc_codes if kc not in {"KC2.3", "KCX-MAGENT"}]
    return kc_codes


def _zone_kc_filter(profile: CapabilityProfile, filtered: list[str]) -> dict[str, Any]:
    """Return kc_subcodes updates when zone filtering strips codes."""
    kc_codes = _strip_zone_kc_codes(list(profile.kc_subcodes), filtered)
    if kc_codes != list(profile.kc_subcodes):
        return {"kc_subcodes": kc_codes}
    return {}


def _strip_entry_point_zone_tags(
    profile: CapabilityProfile,
    filtered: list[str],
) -> dict[str, Any]:
    """Strip excluded-zone tags from entry points and re-deduplicate."""
    zone_tag_re = _zone_tag_pattern()
    cleaned_entry_points = []
    entry_points_changed = False
    for ep in profile.entry_points:
        m = zone_tag_re.search(ep.name)
        if m and m.group(1) not in filtered:
            cleaned_name = ep.name[: m.start()].rstrip()
            logger.warning(
                "Stripped zone tag from entry point: '%s' -> '%s'",
                ep.name,
                cleaned_name,
            )
            cleaned_entry_points.append(ep.model_copy(update={"name": cleaned_name}))
            entry_points_changed = True
        else:
            cleaned_entry_points.append(ep)
    if entry_points_changed:
        from asago_scenario_generator.models.capability_profile import (
            deduplicate_entry_points,
        )

        return {"entry_points": deduplicate_entry_points(cleaned_entry_points)}
    return {}


def _apply_zone_filter(
    profile: CapabilityProfile, zones: str | None
) -> CapabilityProfile:
    """Apply the zones option filter to the capability profile."""
    if zones is None:
        return profile
    requested = _validate_requested_zones(zones)
    filtered = [z for z in requested if z in profile.zones_active]
    updates: dict[str, Any] = {"zones_active": filtered}
    updates.update(_zone_kc_filter(profile, filtered))
    updates.update(_strip_entry_point_zone_tags(profile, filtered))
    profile = profile.model_copy(update=updates)
    logger.info("  Zone filter applied: %s", filtered)
    return profile


def _stage2_threat_surface(
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    ct_path: Path,
    threats_path: Path | None,
    profile: CapabilityProfile,
    generation_notes: list[str],
) -> tuple[Any, int, int, set[str]]:
    """Run Stage 2 and collect threat-surface accounting."""
    risk_cards = load_risk_extraction(risk_extraction_path)
    coherence_report = validate_risk_card_coherence(use_case, risk_cards)
    if coherence_report.has_warnings:
        for card_result in coherence_report.flagged_cards:
            generation_notes.append(
                f"Risk card {card_result.risk_id} ({card_result.risk_name}) "
                f"may describe a different system (0 keyword overlap with use case)."
            )
    threat_surface = determine_threat_surface(
        profile,
        risk_cards,
        sssom_path,
        ct_path,
        threats_path,
    )
    in_scope_threats = set()
    for entry in threat_surface.entries:
        in_scope_threats.update(entry.agentic_threat_ids)
    return (
        threat_surface,
        len(threat_surface.entries),
        len(threat_surface.governance_only),
        in_scope_threats,
    )


def _expansion_record(stage_records: list[Any]) -> Any:
    """Return the expansion stage record, real or empty."""
    if stage_records:
        return stage_records[-1]
    return StageRecord(
        stage="expansion", input_count=0, output_count=0, collapsed_count=0
    )


def _run_candidate_filter(
    rule_passed: list[Any],
    seeds: list[Any],
    client: Any,
    use_case: str,
    profile: CapabilityProfile,
    run_dir: Path,
) -> tuple[list[Any], list[dict[str, Any]], list[Any], list[Any]]:
    """Run the LLM candidate filter with protocol-failure evidence."""
    try:
        filter_result = filter_candidates(
            rule_passed,
            seeds,
            client,
            use_case,
            profile,
            advisory_on_failure=True,
        )
        if len(filter_result) == 4:
            (
                filtered_seeds,
                filter_call_logs,
                filter_rejected_verdicts,
                filter_quarantines,
            ) = filter_result
        else:
            # Keep runner compatibility with integrations that provide
            # the historical three-item filter result.
            (
                filtered_seeds,
                filter_call_logs,
                filter_rejected_verdicts,
            ) = filter_result
            filter_quarantines = []
    except FilterProtocolError as exc:
        # Persist call/protocol evidence before failing the run.
        write_pipeline_call_log(exc.call_log_entries, run_dir)
        raise
    return (
        filtered_seeds,
        filter_call_logs,
        filter_rejected_verdicts,
        filter_quarantines,
    )


def _record_filter_unavailability_note(
    filter_call_logs: list[dict[str, Any]],
    generation_notes: list[str],
) -> None:
    """Record a generation note when the candidate filter was unavailable."""
    if any(
        item.get("warning") == "candidate_filter_unavailable"
        for item in filter_call_logs
    ):
        generation_notes.append(
            "candidate_filter_unavailable: all rule-eligible candidates "
            "continued to mandatory semantic generation"
        )


def _log_filter_quarantines(filter_quarantines: list[Any]) -> None:
    """Log candidate filter quarantines, if any."""
    if filter_quarantines:
        logger.warning(
            "  Candidate filter quarantined %d seed(s): %s",
            len(filter_quarantines),
            ", ".join(item.seed_id for item in filter_quarantines),
        )


def _selected_authoritative_patterns(
    attack_pattern_records: list[dict[str, Any]],
    filtered_seeds: list[Any],
    taxonomy_resolver: Any,
) -> list[Any]:
    """Validate just the patterns selected by the candidate filter."""
    selected_pattern_ids = {item.seed_id for item in filtered_seeds}
    return [
        validate_attack_pattern(item, taxonomy_resolver)
        for item in attack_pattern_records
        if item.get("id") in selected_pattern_ids
    ]


def _run_projection_readiness_gate(
    selected_patterns: list[Any],
    capability_snapshot: Any,
    qualification_facts_path: Path | None,
) -> None:
    """Ensure projection readiness, deferring unresolved legacy facts."""
    try:
        ensure_projection_readiness(selected_patterns, capability_snapshot)
    except ProjectionReadinessError as exc:
        # Legacy inferred runs have no authoritative fact source to
        # validate. Preserve their existing projection behavior while
        # keeping the gate fail-closed for explicit fact inputs and all
        # missing architecture resources.
        if (
            qualification_facts_path is not None
            or exc.report.missing_resource_categories
        ):
            raise
        logger.warning(
            "Projection readiness has unresolved facts without an explicit "
            "qualification-facts source; deferring to projection conditions."
        )


def _projected_by_pattern_lookup(projection_batch: Any) -> dict[str, list[Any]]:
    """Group projected candidates by pattern id."""
    projected_by_pattern: dict[str, list[Any]] = {}
    for pc in projection_batch.candidates:
        projected_by_pattern.setdefault(pc.pattern_id, []).append(pc)
    return projected_by_pattern


def _project_authoritative_run(
    profile: CapabilityProfile,
    qualification_facts: tuple[Any, ...],
    qualification_facts_path: Path | None,
    filtered_seeds: list[Any],
) -> tuple[list[dict[str, Any]], Any, Any, Any, Any]:
    """Run the authoritative projection phase and build lookups."""
    attack_pattern_records = list(load_attack_patterns().values())
    taxonomy_resolver = load_taxonomy_resolver()
    capability_snapshot = capture_capability_snapshot(profile, qualification_facts)
    selected_patterns = _selected_authoritative_patterns(
        attack_pattern_records, filtered_seeds, taxonomy_resolver
    )
    _run_projection_readiness_gate(
        selected_patterns, capability_snapshot, qualification_facts_path
    )
    coverage_universe = build_coverage_universe(profile)
    projection_batch = project_authoritative_candidates(
        attack_pattern_records,
        taxonomy_resolver,
        capability_snapshot,
        coverage_target_ids=coverage_universe.feasible_target_ids,
    )
    return (
        attack_pattern_records,
        taxonomy_resolver,
        capability_snapshot,
        coverage_universe,
        projection_batch,
    )


def _removal_decision_summaries(matching_verdicts: list[Any]) -> list[str]:
    """Flatten removal decision summaries for matching verdicts."""
    return [
        _removal_decision_summary(d)
        for v in matching_verdicts
        for d in v.removal_decisions
    ]


def _rule_rejection_reasons(c: Any, rule_verdicts: list[Any]) -> str:
    """Return the deterministic rule rejection reasons for a candidate."""
    matching_verdicts = [v for v in rule_verdicts if v.candidate_id == c.candidate_id]
    if not matching_verdicts:
        return "Rejected by deterministic rule filter"
    removals = _removal_decision_summaries(matching_verdicts)
    return "; ".join(removals) or matching_verdicts[0].rationale


def _record_rule_rejections(
    stage_ledger: Any,
    rule_rejected: list[Any],
    rule_verdicts: list[Any],
) -> None:
    """Record rule-rejection stage events with typed rationales."""
    for c in rule_rejected:
        stage_ledger.record(
            entry_point_id=c.entry_point_id,
            candidate_id=c.candidate_id,
            stage=STAGE_RULES,
            reason="deterministic_rule_rejection",
            detail=f"pattern={c.seed_id}: {_rule_rejection_reasons(c, rule_verdicts)}",
        )


def _filter_rejection_rationale(verdict: Any) -> str:
    """Return the typed filter verdict rationale, or a default."""
    return (
        verdict.rationale
        if verdict is not None
        else "Candidate rejected by LLM filter."
    )


def _verdict_payload(verdict: Any) -> Any:
    """Return the typed filter verdict payload, if any."""
    return verdict.model_dump(mode="json") if verdict is not None else None


def _accepted_filter_ids(filtered_seeds: list[Any]) -> set[str]:
    """Return candidate ids accepted by the LLM filter."""
    return {f.candidate_id for f in filtered_seeds}


def _filter_rejection_by_id(filter_rejected_verdicts: list[Any]) -> dict[str, Any]:
    """Index rejected filter verdicts by candidate id."""
    return {v.candidate_id: v for v in filter_rejected_verdicts}


def _record_filter_rejections(
    stage_ledger: Any,
    rule_passed: list[Any],
    filtered_seeds: list[Any],
    filter_rejected_verdicts: list[Any],
) -> None:
    """Record LLM filter-rejection stage events with typed rationales."""
    accepted_filter_ids = _accepted_filter_ids(filtered_seeds)
    rejection_by_id = _filter_rejection_by_id(filter_rejected_verdicts)
    for c in rule_passed:
        if c.candidate_id not in accepted_filter_ids:
            verdict = rejection_by_id.get(c.candidate_id)
            stage_ledger.record(
                entry_point_id=c.entry_point_id,
                candidate_id=c.candidate_id,
                stage=STAGE_FILTER,
                reason="filter_rejection",
                detail=f"pattern={c.seed_id}: {_filter_rejection_rationale(verdict)}",
                payload=_verdict_payload(verdict),
            )


def _matching_projected_candidates(pc_list: list[Any], fseed: Any) -> list[Any]:
    """Return candidates whose canonical ingress matches the seed."""
    return [
        pc
        for pc in pc_list
        if pc.canonical_ingress.entry_point_id == fseed.entry_point_id
    ]


def _record_no_projection(stage_ledger: Any, fseed: Any) -> None:
    """Record a no_projection stage event for the filtered seed."""
    stage_ledger.record(
        entry_point_id=fseed.entry_point_id,
        candidate_id=fseed.candidate_id,
        stage=STAGE_PROJECTION,
        reason="no_projection",
        detail=f"No projected candidate for pattern '{fseed.seed_id}'.",
    )


def _record_no_ingress_match(stage_ledger: Any, fseed: Any) -> None:
    """Record a no_exact_ingress_match stage event for the filtered seed."""
    stage_ledger.record(
        entry_point_id=fseed.entry_point_id,
        candidate_id=fseed.candidate_id,
        stage=STAGE_PROJECTION,
        reason="no_exact_ingress_match",
        detail=(
            f"No projected candidate for pattern '{fseed.seed_id}' "
            f"with ingress entry_point_id '{fseed.entry_point_id}'."
        ),
    )


def _record_projected_match(stage_ledger: Any, fseed: Any, pc: Any) -> None:
    """Record a projected stage event for a matching candidate."""
    stage_ledger.record(
        entry_point_id=fseed.entry_point_id,
        candidate_id=pc.candidate_id,
        stage=STAGE_PROJECTION,
        reason="projected",
        detail=f"Projected candidate for pattern '{fseed.seed_id}'.",
    )


def _projection_event_for_fseed(
    stage_ledger: Any,
    fseed: Any,
    pc_list: list[Any] | None,
) -> tuple[int, dict[str, list[str]]]:
    """Record projection events for one filtered seed.

    Returns ``(rejected_count_delta, rejected_by_target_delta)``.
    """
    if not pc_list:
        _record_no_projection(stage_ledger, fseed)
        return 1, {fseed.entry_point_id: [fseed.candidate_id]}
    matching_pcs = _matching_projected_candidates(pc_list, fseed)
    if not matching_pcs:
        _record_no_ingress_match(stage_ledger, fseed)
        return 1, {fseed.entry_point_id: [fseed.candidate_id]}
    for pc in matching_pcs:
        _record_projected_match(stage_ledger, fseed, pc)
    return 0, {}


def _record_projection_events(
    stage_ledger: Any,
    filtered_seeds: list[Any],
    projected_by_pattern: dict[str, list[Any]],
) -> tuple[int, dict[str, list[str]]]:
    """Record projection acceptance/rejection events for filtered seeds."""
    projection_rejected_count = 0
    projection_rejected_by_target: dict[str, list[str]] = {}
    for fseed in filtered_seeds:
        rejected_count, rejected_by = _projection_event_for_fseed(
            stage_ledger, fseed, projected_by_pattern.get(fseed.seed_id)
        )
        projection_rejected_count += rejected_count
        if rejected_by:
            projection_rejected_by_target.setdefault(fseed.entry_point_id, []).extend(
                rejected_by[fseed.entry_point_id]
            )
    return projection_rejected_count, projection_rejected_by_target


def _log_projection_rejections(projection_rejected_count: int) -> None:
    """Log the projection-stage rejection count, when nonzero."""
    if projection_rejected_count:
        logger.info(
            "  %d filtered seed(s) rejected at projection stage "
            "(no exact ingress match).",
            projection_rejected_count,
        )


def _record_projection_limitation_events(
    stage_ledger: Any,
    projection_batch: Any,
) -> None:
    """Record budget, infeasibility, and limitation projection events."""
    budget_max = ProjectionBudget().max_candidates
    for ep_id in projection_batch.unreserved_coverage_targets:
        stage_ledger.record(
            entry_point_id=ep_id,
            candidate_id="",
            stage=STAGE_PROJECTION,
            reason="budget_exhausted",
            detail=(
                f"Coverage target omitted by projection budget allocation "
                f"(budget={budget_max}, target_id={ep_id})."
            ),
        )
    for ep_id in projection_batch.infeasible_coverage_targets:
        stage_ledger.record(
            entry_point_id=ep_id,
            candidate_id="",
            stage=STAGE_PROJECTION,
            reason="no_compatible_projection",
            detail=(
                f"Coverage target has no compatible projection (target_id={ep_id})."
            ),
        )
    for issue in projection_batch.infeasibilities:
        stage_ledger.record(
            entry_point_id="",
            candidate_id="",
            stage=STAGE_PROJECTION,
            reason=issue.code,
            detail=f"pattern={issue.pattern_id}: {issue.detail}",
            payload=issue.model_dump(mode="json"),
        )
    for limitation in projection_batch.limitations:
        stage_ledger.record(
            entry_point_id="",
            candidate_id="",
            stage=STAGE_PROJECTION,
            reason="variant_truncation",
            detail=(
                f"pattern={limitation.pattern_id}: "
                f"{limitation.emitted_bindings}/"
                f"{limitation.total_compatible_bindings} bindings emitted"
            ),
            payload=limitation.model_dump(mode="json"),
        )


def _record_selection_events(
    stage_ledger: Any,
    selection_result: Any,
    resolved_generation_mode: GenerationMode,
) -> None:
    """Record selection and selection-limitation stage events."""
    for qc in selection_result.selected:
        stage_ledger.record(
            entry_point_id=qc.entry_point_id,
            candidate_id=qc.candidate_id,
            stage=STAGE_SELECTION,
            reason="selected",
            detail=f"Selected for generation (rank {qc.rank}).",
        )
    for ep_id in selection_result.selection_limitation_target_ids:
        limitation_detail = (
            "Per-pattern cap excluded all qualified candidates for this ingress target."
            if resolved_generation_mode is GenerationMode.EXHAUSTIVE
            else "Per-pattern cap could not be respected for this target; "
            "coverage preserved but cap violated."
        )
        stage_ledger.record(
            entry_point_id=ep_id,
            candidate_id=selection_result.primary_candidate_ids.get(ep_id, ""),
            stage=STAGE_SELECTION,
            reason="selection_limitation",
            detail=limitation_detail,
        )


def _log_cap_summary(
    resolved_generation_mode: GenerationMode,
    candidates_capped: int,
) -> None:
    """Log per-pattern cap accounting, when nonzero."""
    if candidates_capped > 0:
        logger.info(
            "  %s generation planning: %d candidates capped by the per-pattern limit.",
            resolved_generation_mode.value.capitalize(),
            candidates_capped,
        )


def _log_uncovered_targets(selection_result: Any) -> None:
    """Log feasible targets with no selected candidate, if any."""
    if selection_result.uncovered_target_ids:
        logger.info(
            "  %d feasible target(s) with no candidate: %s",
            len(selection_result.uncovered_target_ids),
            selection_result.uncovered_target_ids,
        )


def _build_planning_checkpoint(
    *,
    qualification_facts_source: str | None,
    input_hashes: Any,
    stage_ledger: Any,
    projection_limitation_target_ids: set[str],
    selection_result: Any,
    fallback_queues: dict[str, Any],
) -> Any:
    """Build the durable v3 planning checkpoint."""
    from asago_scenario_generator.pipeline.persistence import (
        PlanningCheckpointV1,
    )

    return PlanningCheckpointV1(
        qualification_facts_source=qualification_facts_source,
        qualification_facts_sha256=input_hashes.qualification_facts_hash,
        stage_events=[event.to_dict() for event in stage_ledger.events],
        projection_limitation_target_ids=sorted(projection_limitation_target_ids),
        selected_candidate_ids=[
            candidate.candidate_id for candidate in selection_result.selected
        ],
        capped_count=selection_result.capped_count,
        uncovered_target_ids=sorted(selection_result.uncovered_target_ids),
        per_pattern_counts=dict(sorted(selection_result.per_pattern_counts.items())),
        primary_candidate_ids=dict(
            sorted(selection_result.primary_candidate_ids.items())
        ),
        attempted_candidate_ids=sorted(selection_result.attempted_candidate_ids),
        selection_limitation_target_ids=sorted(
            selection_result.selection_limitation_target_ids
        ),
        fallback_candidate_ids={
            target_id: queue.candidate_ids()
            for target_id, queue in sorted(fallback_queues.items())
        },
    )


def _resume_support_inventory(run_dir: Path) -> list[Any]:
    """Build the immutable resume support inventory entries."""
    return [
        build_artifact_entry(role, run_dir, path)
        for role, path in (
            (ArtifactRole.USE_CASE, "use-case.txt"),
            (ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"),
            (ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"),
            (ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json"),
        )
    ]


def _log_rule_filter_summary(
    rule_rejected_count: int,
    unique_pre_rule_identities: int,
    filter_submitted: int,
) -> None:
    """Log the rule pre-filter summary, when candidates were rejected."""
    if rule_rejected_count:
        logger.info(
            "  Rule pre-filter: %d/%d candidates rejected, %d passed to LLM",
            rule_rejected_count,
            unique_pre_rule_identities,
            filter_submitted,
        )


def _run_pipeline_body(
    *,
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    run_dir: Path,
    cross_taxonomy_path: Path,
    threats_path: Path | None,
    profile_path: Path | None,
    qualification_facts_path: Path | None,
    base_url: str | None,
    api_key: str | None,
    model: str | None,
    model_profile: str | None,
    profiles_file: Path,
    presentation_fallback: str,
    max_techniques: int,
    max_scenarios_per_pattern: int | None,
    resolved_generation_mode: GenerationMode,
    zones: str | None,
    eval: bool,
    log_level: str,
    structured: bool,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    partial_manifest: RunManifest | None,
    generation_notes: list[str],
) -> PipelineResult:
    """Run the full guarded pipeline body (stages 1-4)."""
    from asago_scenario_generator.log_config import setup_logging

    try:
        from asago_scenario_generator.pipeline.persistence import (
            make_finalization_persistence_adapter,
            write_planning_checkpoint,
        )
        from asago_scenario_generator.pipeline.runner_finalization import (
            run_target_finalization,
            strict_v3_coverage_plan,
        )

        qualification_facts_bytes, qualification_facts_source, qualification_facts = (
            _ingest_qualification_facts(qualification_facts_path, generation_notes)
        )
        # --- Capture input hashes at run start (before inputs can change) ---
        input_hashes = _capture_input_hashes(
            use_case,
            risk_extraction_path,
            sssom_path,
            cross_taxonomy_path,
            threats_path,
            profile_path,
            qualification_facts_path,
            qualification_facts_bytes=qualification_facts_bytes,
        )
        logger.info(
            "Qualification facts mode: %s",
            _qualification_facts_mode_label(qualification_facts_path),
        )

        # --- Client construction (after sentinel) ---
        effective_model = resolve_effective_model_config(
            model_profile=model_profile,
            profiles_file=profiles_file,
            base_url=base_url,
            api_key=api_key,
            model=model,
        )
        client = LLMClient(**effective_model.client_kwargs())

        # --- Capture provenance at run start, before inputs can change ---
        # This captures Git state, resolved model config, prompt hashes,
        # input hashes, and canonical config digest of all normalized
        # effective options. Stored in partial_manifest so failed runs
        # retain it; finalization only adds effective written-profile hash
        # and end timestamp.
        #
        # The config digest is bound to the RESOLVED effective options
        # (client-resolved model/base_url/temperature/token config plus
        # resolved default/explicit input paths and normalized generation
        # settings), never raw None CLI args or API key material.  The
        # same object is persisted so digest verification is possible.
        # All default/explicit paths are resolved consistently; zones are
        # parsed and trimmed into a canonical list so whitespace-equivalent
        # inputs produce identical digests.
        effective_threats_path = _resolve_effective_threats_path(threats_path)
        effective_zones = _parse_effective_zones(zones)
        effective_options = _effective_pipeline_options(
            input_hashes=input_hashes,
            risk_extraction_path=risk_extraction_path,
            sssom_path=sssom_path,
            ct_path=cross_taxonomy_path,
            effective_threats_path=effective_threats_path,
            profile_path=profile_path,
            client=client,
            max_techniques=max_techniques,
            max_scenarios_per_pattern=max_scenarios_per_pattern,
            resolved_generation_mode=resolved_generation_mode,
            effective_zones=effective_zones,
            eval=eval,
            model_profile=model_profile,
            profiles_file=profiles_file,
            effective_model=effective_model,
            presentation_fallback=presentation_fallback,
            qualification_facts_path=qualification_facts_path,
        )
        config_digest = compute_config_digest(effective_options)
        provenance = capture_provenance(
            run_id=run_id,
            timestamp_start=timestamp_start,
            command="generate",
            options=effective_options,
            model_config=ModelConfig(**effective_model.public_controls()),
            prompt_template_hashes=hash_prompt_templates(),
            input_hashes=input_hashes,
            config_digest=config_digest,
        )
        provenance.manifest_version = MANIFEST_VERSION

        # --- Build partial manifest inside guarded lifecycle ---
        partial_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("asago-scenario-generator"),
            provenance=provenance,
        )

        # --- Run-local logging (fresh, never appends across runs) ---
        setup_logging(log_level=log_level, output_dir=run_dir, structured=structured)
        logger.info("Run ID: %s", run_id)
        logger.info("Run directory: %s", run_dir)

        # --- Persist use-case description ---
        write_use_case(run_dir, use_case)
        profile = _load_or_infer_profile(profile_path, use_case, client, run_dir)
        profile = _apply_zone_filter(profile, zones)

        logger.info("  Zones active: %s", profile.zones_active)
        logger.info("  Entry points: %d", len(profile.entry_points))
        logger.info("  Confidence: %s", profile.confidence.value)

        # --- I/O boundary: capability profile ---
        profile_output_path = write_capability_profile(profile, run_dir)
        logger.info("  Written to %s", profile_output_path)

        # --- Stage 2: Threat Surface Determination ---
        logger.info("[Stage 2] Determining threat surface...")
        (
            threat_surface,
            actionable_count,
            governance_count,
            in_scope_threats,
        ) = _stage2_threat_surface(
            use_case,
            risk_extraction_path,
            sssom_path,
            cross_taxonomy_path,
            threats_path,
            profile,
            generation_notes,
        )

        # --- I/O boundary: threat surface ---
        ts_path = write_threat_surface(threat_surface, run_dir)
        logger.info("  %d actionable risk cards", actionable_count)
        logger.info("  %d governance-only", governance_count)
        logger.info("  %d in-scope threats", len(in_scope_threats))
        logger.info("  Written to %s", ts_path)

        # --- Stage 3: Scenario Seed Expansion ---
        logger.info("[Stage 3] Expanding scenario seeds...")
        seeds = expand_seeds(threat_surface, threats_path)
        logger.info("  %d scenario seeds to generate", len(seeds))

        # --- Stage 3.5: Candidate Expansion + Filtering (hybrid) ---
        logger.info("[Stage 3.5] Expanding and filtering candidates...")
        stage_records: list[StageRecord] = []

        # expand_candidates deduplicates internally and records its stage.
        candidates = expand_candidates(
            seeds,
            profile,
            max_techniques=max_techniques,
            stage_records=stage_records,
        )
        expansion_record = _expansion_record(stage_records)
        unique_pre_rule_identities = expansion_record.output_count

        # Phase 1: Deterministic rule-based pre-filter.
        # apply_rule_based_filter deduplicates internally and records its stage.
        rule_passed, rule_rejected, rule_verdicts = apply_rule_based_filter(
            candidates, profile, stage_records=stage_records
        )
        rule_rejected_count = len(rule_rejected)
        filter_submitted = len(rule_passed)
        _log_rule_filter_summary(
            rule_rejected_count, unique_pre_rule_identities, filter_submitted
        )

        # Phase 2: LLM filter on survivors only.
        (
            filtered_seeds,
            filter_call_logs,
            filter_rejected_verdicts,
            filter_quarantines,
        ) = _run_candidate_filter(
            rule_passed, seeds, client, use_case, profile, run_dir
        )
        # Log candidate filter LLM calls to top-level calls.jsonl.
        write_pipeline_call_log(filter_call_logs, run_dir)
        _record_filter_unavailability_note(filter_call_logs, generation_notes)
        write_filter_quarantine_evidence(filter_quarantines, run_dir)
        _log_filter_quarantines(filter_quarantines)
        filter_accepted = len(filtered_seeds)
        logger.info(
            "  %d candidates -> %d rule-rejected, %d LLM-filtered -> %d accepted",
            unique_pre_rule_identities,
            rule_rejected_count,
            filter_submitted - filter_accepted,
            filter_accepted,
        )

        # --- Stage 3.6: Authoritative Projection (422o.4) ---
        # Project qualified candidate-v2 records from the authoritative
        # catalog.  Each generated scenario must receive a real
        # ProjectedCandidate + CapabilityFactSnapshot — never a fabricated
        # identity from legacy seed fields.
        #
        # cmps.4 blocker 5: Build the coverage universe BEFORE projection
        # so that coverage-aware budget allocation can reserve one feasible
        # candidate per coverage target before binding variants.
        logger.info("[Stage 3.6] Projecting authoritative candidates...")
        (
            attack_pattern_records,
            taxonomy_resolver,
            capability_snapshot,
            coverage_universe,
            projection_batch,
        ) = _project_authoritative_run(
            profile, qualification_facts, qualification_facts_path, filtered_seeds
        )
        # Build lookup: pattern_id → list[ProjectedCandidate]
        projected_by_pattern = _projected_by_pattern_lookup(projection_batch)
        logger.info(
            "  Projected %d candidates (%d infeasible, %d limited)",
            len(projection_batch.candidates),
            len(projection_batch.infeasibilities),
            len(projection_batch.limitations),
        )

        # --- cmps.4: Stage ledger for actual stage-event recording ---
        # Records events as they occur through the pipeline.  The furthest
        # actual event per target determines gap attribution — never
        # backward set-membership inference.
        stage_ledger = StageLedger()

        # Record rule-rejection events from the rule filter stage.
        _record_rule_rejections(stage_ledger, rule_rejected, rule_verdicts)
        # Record filter-rejection events (rule-passed but LLM-rejected).
        _record_filter_rejections(
            stage_ledger, rule_passed, filtered_seeds, filter_rejected_verdicts
        )
        # --- cmps.4 blocker 1: Qualified candidates over ProjectedCandidate ---
        (
            projection_rejected_count,
            projection_rejected_by_target,
        ) = _record_projection_events(
            stage_ledger, filtered_seeds, projected_by_pattern
        )
        _log_projection_rejections(projection_rejected_count)

        # Build qualified candidates: fan out all valid projected matches,
        # dedupe by projected candidate_id, preserve filter provenance.
        qualified_candidates = build_qualified_candidates(
            filtered_seeds, projected_by_pattern
        )

        # --- Stage 3.7: Generation Planning (cmps.4) ---
        # Exhaustive mode creates one durable target per qualified candidate.
        # Coverage mode retains one bounded fallback queue per ingress.

        # cmps.4 blocker 4: Do NOT append synthetic selection/no_qualified
        # events for empty queues.  Selection limitation requires qualified
        # candidates deliberately not chosen.  The gap for an empty queue is
        # already attributed by the furthest actual event (rules/filter/
        # projection) in the stage ledger — never a synthetic selection event.

        # Check for projection budget limitations affecting coverage targets.
        # Use the authoritative unreserved_coverage_targets from the projection
        # batch (cmps.4 blocker 3), not backward set-membership inference.
        projection_limitation_target_ids: set[str] = set(
            projection_batch.unreserved_coverage_targets
        )
        # Record projection-limitation events for targets omitted by budget
        # allocation (cmps.4 blocker 3), with budget and exact target IDs.
        _record_projection_limitation_events(stage_ledger, projection_batch)

        planning_result = plan_generation(
            qualified_candidates,
            coverage_universe,
            mode=resolved_generation_mode,
            max_per_pattern=max_scenarios_per_pattern,
        )
        selection_result = planning_result.selection
        fallback_queues = planning_result.target_queues
        coverage_fallback_queues = planning_result.coverage_queues
        selected_count = len(selection_result.selected)
        candidates_capped = selection_result.capped_count

        # Record selection events for selected candidates.
        _record_selection_events(
            stage_ledger, selection_result, resolved_generation_mode
        )
        _log_cap_summary(resolved_generation_mode, candidates_capped)
        _log_uncovered_targets(selection_result)
        logger.info(
            "  Selected %d candidate(s) from %d qualified (%d projection-rejected).",
            selected_count,
            len(qualified_candidates),
            projection_rejected_count,
        )

        # --- Manifest v3: target-scoped finalization is the sole lifecycle ---
        # Persist the immutable plan and empty inventory before entering any
        # candidate callback.  Everything below this return is intentionally
        # retained as the v2 implementation for Phase 6 removal only.
        initial_plan = planning_result.plan
        planning_checkpoint = _build_planning_checkpoint(
            qualification_facts_source=qualification_facts_source,
            input_hashes=input_hashes,
            stage_ledger=stage_ledger,
            projection_limitation_target_ids=projection_limitation_target_ids,
            selection_result=selection_result,
            fallback_queues=fallback_queues,
        )
        write_planning_checkpoint(run_dir, planning_checkpoint)
        # Atomically replace the sentinel with a hash-bound inventory of
        # immutable resume support before publishing mutable lifecycle state.
        # This keeps a crash immediately after plan persistence resumable.
        partial_manifest.inventory = _resume_support_inventory(run_dir)
        write_started_manifest(run_dir, partial_manifest)
        make_finalization_persistence_adapter(
            run_dir,
            run_id=run_id,
            coverage_plan=strict_v3_coverage_plan(initial_plan),
        )
        finalization = run_target_finalization(
            run_dir=run_dir,
            run_id=run_id,
            plan=initial_plan,
            profile=profile,
            client=client,
            use_case=use_case,
            taxonomy_resolver=taxonomy_resolver,
            capability_snapshot=capability_snapshot,
            trusted_catalog=attack_pattern_records,
            presentation_fallback=presentation_fallback,
        )
        return _complete_v3_run(
            run_dir=run_dir,
            run_id=run_id,
            timestamp_start=timestamp_start,
            provenance=provenance,
            profile=profile,
            threat_surface=threat_surface,
            finalization=finalization,
            coverage_universe=coverage_universe,
            stage_ledger=stage_ledger,
            selection_result=selection_result,
            fallback_queues=coverage_fallback_queues,
            projection_limitation_target_ids=projection_limitation_target_ids,
            threats_path=threats_path,
            eval_enabled=eval,
            seeds=seeds,
            filtered_seeds=filtered_seeds,
            governance_count=governance_count,
            generation_notes=generation_notes,
            filter_quarantines=filter_quarantines,
        )

    except Exception as exc:
        _recover_and_reraise_failed_run(
            run_dir, run_id, timestamp_start, provenance, partial_manifest, exc
        )
