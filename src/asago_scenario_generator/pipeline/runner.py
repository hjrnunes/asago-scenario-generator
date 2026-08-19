"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import importlib.metadata
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

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
    StageLedger,
    build_coverage_plan,
    build_coverage_universe,
    build_fallback_queues,
    build_qualified_candidates,
    emit_quality_gaps,
    select_with_coverage_priority,
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
from asago_scenario_generator.pipeline.projection import (
    ProjectedCandidate,
    ProjectionReadinessError,
    ProjectionBudget,
    canonical_json_bytes,
    capture_capability_snapshot,
    ensure_projection_readiness,
    project_authoritative_candidates,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed, expand_seeds
from asago_scenario_generator.pipeline.threats import (
    ThreatSurface,
    determine_threat_surface,
)
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
        read_finalization_inventory,
    )
    from asago_scenario_generator.pipeline.runner_finalization import build_v3_inventory

    started_manifest = load_manifest(run_dir, requested_version=MANIFEST_VERSION)
    if started_manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("v3 completion tail requires STARTED manifest")
    ManifestInventoryResolver(run_dir, started_manifest, check_orphans=False)
    final_inventory_doc = read_finalization_inventory(run_dir)
    admitted_scenarios = _load_admitted_scenarios(
        run_dir, run_id, timestamp_start, provenance, final_inventory_doc
    )
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, admitted_scenarios)
    decisions = {
        item.candidate_id: item for item in final_inventory_doc.admission_decisions
    }
    generated_target_ids: set[str] = set()
    quarantined_target_ids: set[str] = set()
    for candidate_attempt in final_inventory_doc.candidate_attempts:
        decision = decisions[candidate_attempt.candidate_id]
        if decision.admitted:
            generated_target_ids.add(candidate_attempt.target_entry_point_id)
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
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
            quarantined_target_ids.add(candidate_attempt.target_entry_point_id)
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
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

    final_status = (
        RunStatus.COMPLETED
        if terminal_processing_succeeded
        and not had_quarantine
        and eval_enabled
        and eval_success
        and report_success
        and qualification_passed
        else RunStatus.COMPLETED_WITH_ERRORS
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
    )
    if final_status is RunStatus.COMPLETED:
        validate_completed_inventory(
            final_manifest, eval_enabled=eval_enabled, run_dir=run_dir
        )
    else:
        ManifestInventoryResolver(run_dir, final_manifest, check_orphans=True)
    finalize_manifest(run_dir, final_manifest)
    filter_quarantine_count = len(filter_quarantines or [])
    admitted_count = len(final_inventory_doc.admitted_inventory)
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
    planning: object, durable_plan: object
) -> tuple[object, dict]:
    """Rebuild the exact typed selection inputs persisted before finalization."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        QualifiedCandidate,
        SelectionResult,
        TargetFallbackQueue,
        deserialize_qualified_candidate,
    )

    hydrated_by_id: dict[str, QualifiedCandidate] = {}
    fallback_queues: dict[str, TargetFallbackQueue] = {}
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
        fallback_queues[target.entry_point_id] = TargetFallbackQueue(
            entry_point_id=target.entry_point_id,
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
    return selection_result, fallback_queues


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
    from asago_scenario_generator.log_config import setup_logging
    from asago_scenario_generator.pipeline.coverage_planning import CoveragePlan
    from asago_scenario_generator.pipeline.persistence import (
        read_coverage_plan,
        read_finalization_inventory,
        read_planning_checkpoint_bytes,
        recover_finalization_journal,
        validate_planning_checkpoint,
    )
    from asago_scenario_generator.pipeline.runner_finalization import (
        run_target_finalization,
    )

    try:
        supplied = Path(run_dir).resolve(strict=True)
    except OSError as exc:
        raise ManifestIntegrityError(
            "resume requires an existing run directory"
        ) from exc
    if not supplied.is_dir():
        raise ManifestIntegrityError("resume requires an existing run directory")
    manifest = load_manifest(supplied, requested_version=MANIFEST_VERSION)
    if manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("only a v3 STARTED run can be resumed")
    try:
        validate_generation_run_id(manifest.run_id)
    except ValueError as exc:
        raise ManifestIntegrityError("resume manifest has noncanonical run_id") from exc
    if supplied.name != manifest.run_id:
        raise ManifestIntegrityError("manifest run_id does not match run directory")
    if manifest.provenance is None or manifest.provenance.run_id != manifest.run_id:
        raise ManifestIntegrityError("manifest provenance run_id mismatch")
    support = ManifestInventoryResolver(supplied, manifest, check_orphans=False)
    use_entry = support.entry_by_role(ArtifactRole.USE_CASE)
    profile_entry = support.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    threat_entry = support.entry_by_role(ArtifactRole.THREAT_SURFACE)
    planning_entry = support.entry_by_role(ArtifactRole.PLANNING_CHECKPOINT)
    if not all((use_entry, profile_entry, threat_entry, planning_entry)):
        raise ManifestIntegrityError("started manifest support inventory is incomplete")
    use_case = support.read_text(use_entry)  # type: ignore[arg-type]
    profile = CapabilityProfile.model_validate(support.read_yaml(profile_entry))  # type: ignore[arg-type]
    threat_surface = ThreatSurface.model_validate(support.read_yaml(threat_entry))  # type: ignore[arg-type]
    planning = read_planning_checkpoint_bytes(support.read_bytes(planning_entry))  # type: ignore[arg-type]
    recover_finalization_journal(supplied, expected_run_id=manifest.run_id)
    inventory = read_finalization_inventory(supplied)
    if inventory.run_id != manifest.run_id:
        raise ManifestIntegrityError("finalization inventory run_id mismatch")

    provenance = manifest.provenance
    if provenance.config_digest != compute_config_digest(provenance.command.options):
        raise ManifestIntegrityError("resume configuration provenance drift")
    if provenance.prompt_template_hashes != hash_prompt_templates():
        raise ManifestIntegrityError("resume prompt template provenance drift")
    if provenance.input_hashes.use_case_hash != compute_bytes_sha256(
        use_case.encode("utf-8")
    ):
        raise ManifestIntegrityError("resume use-case provenance drift")

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
    if eval is not None and eval is not persisted_eval:
        raise ManifestIntegrityError("resume eval override conflicts with provenance")
    current_hashes = _capture_input_hashes(
        use_case,
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
    )
    persisted_hashes = provenance.input_hashes
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

    taxonomy_resolver = load_taxonomy_resolver()
    facts_path = options.get("qualification_facts_path")
    if facts_path is None:
        if (
            planning.qualification_facts_source is not None
            or planning.qualification_facts_sha256 is not None
            or persisted_hashes.qualification_facts_hash is not None
        ):
            raise ManifestIntegrityError(
                "resume qualification facts provenance is inconsistent"
            )
        qualification_facts: tuple[EvaluatedFactEvidence, ...] = ()
    else:
        if planning.qualification_facts_source is None:
            raise ManifestIntegrityError(
                "resume planning checkpoint lacks qualification facts source"
            )
        source_bytes = planning.qualification_facts_source.encode("utf-8")
        if (
            compute_bytes_sha256(source_bytes)
            != persisted_hashes.qualification_facts_hash
        ):
            raise ManifestIntegrityError("resume qualification facts provenance drift")
        try:
            qualification_facts = _parse_qualification_facts(source_bytes).facts
        except ValueError as exc:
            raise ManifestIntegrityError(str(exc)) from exc
    capability_snapshot = capture_capability_snapshot(profile, qualification_facts)
    trusted_catalog = list(load_attack_patterns().values())
    durable_plan = read_coverage_plan(supplied)
    validate_planning_checkpoint(planning, durable_plan)
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
    selection_result, fallback_queues = _hydrate_planning_inputs(planning, durable_plan)

    setup_logging(log_level=log_level, output_dir=supplied, structured=structured)
    persisted_model = provenance.model_config_provenance
    if persisted_model is None:
        raise ManifestIntegrityError(
            "resumable v3 run requires persisted model configuration"
        )
    if model is not None and model != persisted_model.model:
        raise ManifestIntegrityError("resume model override conflicts with provenance")
    if base_url is not None and base_url != persisted_model.base_url:
        raise ManifestIntegrityError(
            "resume endpoint override conflicts with provenance"
        )
    client = LLMClient(
        base_url=base_url or (persisted_model.base_url if persisted_model else None),
        api_key=api_key,
        model=model or (persisted_model.model if persisted_model else None),
        temperature=persisted_model.temperature if persisted_model else None,
        max_completion_tokens=(
            persisted_model.max_completion_tokens if persisted_model else None
        ),
    )
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
    )
    durable_plan = finalization.coverage_plan
    from asago_scenario_generator.pipeline.coverage_planning import StageEvent

    stage_ledger = StageLedger(
        events=[
            StageEvent(**item.model_dump(mode="python"))
            for item in planning.stage_events
        ]
    )
    return _complete_v3_run(
        run_dir=supplied,
        run_id=manifest.run_id,
        timestamp_start=manifest.timestamp_start,
        provenance=manifest.provenance,
        profile=profile,
        threat_surface=threat_surface,
        finalization=finalization,
        coverage_universe=build_coverage_universe(profile),
        stage_ledger=stage_ledger,
        selection_result=selection_result,
        fallback_queues=fallback_queues,
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
    max_techniques: int = 1,
    max_scenarios_per_pattern: int | None = None,
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
        eval: Whether to run deterministic eval metrics after generation (default True).
        log_level: Logging level for the console handler.
        structured: Whether the run-local file log uses JSON-lines format.

    Returns:
        PipelineResult with all artifacts from the pipeline run.
    """
    ct_path = cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH
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

    try:
        qualification_facts_bytes = (
            qualification_facts_path.read_bytes()
            if qualification_facts_path is not None
            else None
        )
        # --- Capture input hashes at run start (before inputs can change) ---
        input_hashes = _capture_input_hashes(
            use_case,
            risk_extraction_path,
            sssom_path,
            ct_path,
            threats_path,
            profile_path,
            qualification_facts_path,
            qualification_facts_bytes=qualification_facts_bytes,
        )
        qualification_facts_source: str | None = None
        qualification_facts: tuple[EvaluatedFactEvidence, ...] = ()
        if qualification_facts_bytes is not None:
            qualification_facts_source = qualification_facts_bytes.decode("utf-8")
            qualification_facts = _parse_qualification_facts(
                qualification_facts_bytes
            ).facts

        # --- Client construction (after sentinel) ---
        client = LLMClient(base_url=base_url, api_key=api_key, model=model)

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
        from asago_scenario_generator.pipeline.seeds import _DEFAULT_THREATS_PATH

        effective_threats_path = (threats_path or _DEFAULT_THREATS_PATH).resolve()
        effective_zones: list[str] | None = None
        if zones is not None:
            effective_zones = [z.strip() for z in zones.split(",") if z.strip()]

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
            "zones": effective_zones,
            "eval": eval,
        }
        if qualification_facts_path is not None:
            effective_options["qualification_facts_path"] = str(
                qualification_facts_path.resolve()
            )
        config_digest = compute_config_digest(effective_options)
        provenance = capture_provenance(
            run_id=run_id,
            timestamp_start=timestamp_start,
            command="generate",
            options=effective_options,
            model_config=ModelConfig(
                model=client.model,
                base_url=client.base_url,
                temperature=client.temperature,
                max_completion_tokens=client.max_completion_tokens,
            ),
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
        from asago_scenario_generator.log_config import setup_logging

        setup_logging(log_level=log_level, output_dir=run_dir, structured=structured)
        logger.info("Run ID: %s", run_id)
        logger.info("Run directory: %s", run_dir)

        # --- Persist use-case description ---
        write_use_case(run_dir, use_case)
        if profile_path is not None:
            logger.info("[Stage 1] Loading capability profile from %s", profile_path)
            profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
            profile = CapabilityProfile(**profile_data)
        else:
            logger.info("[Stage 1] Inferring capability profile...")
            profile, profile_llm_result = infer_capability_profile(use_case, client)
            # Log the profile inference LLM call to top-level calls.jsonl.
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
        if zones is not None:
            requested = [z.strip() for z in zones.split(",")]
            invalid = [z for z in requested if z not in ZONE_NAMES]
            if invalid:
                raise ValueError(
                    f"Unknown zone(s): {', '.join(invalid)}. Valid: {', '.join(ZONE_NAMES)}"
                )
            filtered = [z for z in requested if z in profile.zones_active]
            updates: dict = {"zones_active": filtered}
            # When zones are filtered, strip KC codes that would activate
            # computed flags for the excluded zones so the boolean flags
            # (has_persistent_memory, multi_agent) naturally become False.
            kc_codes = list(profile.kc_subcodes)
            if "memory" not in filtered:
                kc_codes = [
                    kc
                    for kc in kc_codes
                    if kc not in {"KC4.3", "KC4.4", "KC4.5", "KC4.6", "KCX-PMEM"}
                ]
            if "inter_agent" not in filtered:
                kc_codes = [kc for kc in kc_codes if kc not in {"KC2.3", "KCX-MAGENT"}]
            if kc_codes != list(profile.kc_subcodes):
                updates["kc_subcodes"] = kc_codes
            # Strip zone tags from entry points whose zone is excluded.
            _zone_alts = "|".join(re.escape(z) for z in ZONE_NAMES)
            _zone_tag_re = re.compile(
                r"\s*\((" + _zone_alts + r")\)\s*$",
            )
            cleaned_entry_points = []
            entry_points_changed = False
            for ep in profile.entry_points:
                m = _zone_tag_re.search(ep.name)
                if m and m.group(1) not in filtered:
                    cleaned_name = ep.name[: m.start()].rstrip()
                    logger.warning(
                        "Stripped zone tag from entry point: '%s' -> '%s'",
                        ep.name,
                        cleaned_name,
                    )
                    cleaned_entry_points.append(
                        ep.model_copy(update={"name": cleaned_name})
                    )
                    entry_points_changed = True
                else:
                    cleaned_entry_points.append(ep)
            if entry_points_changed:
                # Re-run canonical dedup after zone-tag stripping — removing
                # zone tags may cause two formerly-distinct entry points to
                # become semantic duplicates or collide.
                from asago_scenario_generator.models.capability_profile import (
                    deduplicate_entry_points,
                )

                updates["entry_points"] = deduplicate_entry_points(cleaned_entry_points)
            profile = profile.model_copy(update=updates)
            logger.info("  Zone filter applied: %s", filtered)

        logger.info("  Zones active: %s", profile.zones_active)
        logger.info("  Entry points: %d", len(profile.entry_points))
        logger.info("  Confidence: %s", profile.confidence.value)

        # --- I/O boundary: capability profile ---
        profile_output_path = write_capability_profile(profile, run_dir)
        logger.info("  Written to %s", profile_output_path)

        # --- Stage 2: Threat Surface Determination ---
        logger.info("[Stage 2] Determining threat surface...")
        risk_cards = load_risk_extraction(risk_extraction_path)

        # Validate causal chain coherence before proceeding.
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

        actionable_count = len(threat_surface.entries)
        governance_count = len(threat_surface.governance_only)
        in_scope_threats = set()
        for entry in threat_surface.entries:
            in_scope_threats.update(entry.agentic_threat_ids)

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
        expansion_record = (
            stage_records[-1]
            if stage_records
            else StageRecord(
                stage="expansion", input_count=0, output_count=0, collapsed_count=0
            )
        )
        unique_pre_rule_identities = expansion_record.output_count

        # Phase 1: Deterministic rule-based pre-filter.
        # apply_rule_based_filter deduplicates internally and records its stage.
        rule_passed, rule_rejected, rule_verdicts = apply_rule_based_filter(
            candidates, profile, stage_records=stage_records
        )
        rule_rejected_count = len(rule_rejected)
        filter_submitted = len(rule_passed)

        if rule_rejected_count:
            logger.info(
                "  Rule pre-filter: %d/%d candidates rejected, %d passed to LLM",
                rule_rejected_count,
                unique_pre_rule_identities,
                filter_submitted,
            )

        # Phase 2: LLM filter on survivors only.
        try:
            filter_result = filter_candidates(
                rule_passed,
                seeds,
                client,
                use_case,
                profile,
                quarantine_on_failure=True,
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
        # Log candidate filter LLM calls to top-level calls.jsonl.
        write_pipeline_call_log(filter_call_logs, run_dir)
        write_filter_quarantine_evidence(filter_quarantines, run_dir)
        if filter_quarantines:
            logger.warning(
                "  Candidate filter quarantined %d seed(s): %s",
                len(filter_quarantines),
                ", ".join(item.seed_id for item in filter_quarantines),
            )
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
        attack_pattern_records = list(load_attack_patterns().values())
        taxonomy_resolver = load_taxonomy_resolver()
        capability_snapshot = capture_capability_snapshot(profile, qualification_facts)
        selected_pattern_ids = {item.seed_id for item in filtered_seeds}
        selected_patterns = [
            validate_attack_pattern(item, taxonomy_resolver)
            for item in attack_pattern_records
            if item.get("id") in selected_pattern_ids
        ]
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

        # Build coverage universe before projection (cmps.4 blocker 5).
        coverage_universe = build_coverage_universe(profile)

        # Coverage-aware projection: pass feasible target IDs so projection
        # reserves one candidate per target before variant expansion.
        projection_batch = project_authoritative_candidates(
            attack_pattern_records,
            taxonomy_resolver,
            capability_snapshot,
            coverage_target_ids=coverage_universe.feasible_target_ids,
        )
        # Build lookup: pattern_id → list[ProjectedCandidate]
        projected_by_pattern: dict[str, list[ProjectedCandidate]] = {}
        for pc in projection_batch.candidates:
            projected_by_pattern.setdefault(pc.pattern_id, []).append(pc)
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
        for c in rule_rejected:
            # cmps.4 blocker 4: Record actual rule-rejection details and
            # identities/rationales.  RejectionRecord verdicts from the
            # rule filter are matched by candidate_id for per-candidate
            # removal-decision provenance.
            matching_verdicts = [
                v for v in rule_verdicts if v.candidate_id == c.candidate_id
            ]
            if matching_verdicts:
                removals = [
                    _removal_decision_summary(d)
                    for v in matching_verdicts
                    for d in v.removal_decisions
                ]
                rule_reasons = "; ".join(removals) or matching_verdicts[0].rationale
            else:
                rule_reasons = "Rejected by deterministic rule filter"
            stage_ledger.record(
                entry_point_id=c.entry_point_id,
                candidate_id=c.candidate_id,
                stage=STAGE_RULES,
                reason="deterministic_rule_rejection",
                detail=f"pattern={c.seed_id}: {rule_reasons}",
            )

        # Record filter-rejection events (rule-passed but LLM-rejected).
        # cmps.4 blocker 4: Use the actual typed FilterVerdict rationale,
        # not generic text.  The rejected verdicts survive from the filter
        # protocol result, indexed by candidate_id.
        accepted_filter_ids = {f.candidate_id for f in filtered_seeds}
        filter_rejection_by_id = {v.candidate_id: v for v in filter_rejected_verdicts}
        for c in rule_passed:
            if c.candidate_id not in accepted_filter_ids:
                verdict = filter_rejection_by_id.get(c.candidate_id)
                rationale = (
                    verdict.rationale
                    if verdict is not None
                    else "Candidate rejected by LLM filter."
                )
                stage_ledger.record(
                    entry_point_id=c.entry_point_id,
                    candidate_id=c.candidate_id,
                    stage=STAGE_FILTER,
                    reason="filter_rejection",
                    detail=f"pattern={c.seed_id}: {rationale}",
                    payload=(
                        verdict.model_dump(mode="json") if verdict is not None else None
                    ),
                )

        # --- cmps.4 blocker 1: Qualified candidates over ProjectedCandidate ---
        # Fan out all valid projected matches (distinct bindings for same
        # pattern+ingress are alternatives, not fatal ambiguity).  Dedupe
        # by projected candidate_id.  Preserve accepted filter verdict and
        # provenance as first-class typed evidence.
        projection_rejected_count = 0
        projection_rejected_by_target: dict[str, list[str]] = {}
        for fseed in filtered_seeds:
            pc_list = projected_by_pattern.get(fseed.seed_id)
            if not pc_list:
                projection_rejected_count += 1
                projection_rejected_by_target.setdefault(
                    fseed.entry_point_id, []
                ).append(fseed.candidate_id)
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=fseed.candidate_id,
                    stage=STAGE_PROJECTION,
                    reason="no_projection",
                    detail=f"No projected candidate for pattern '{fseed.seed_id}'.",
                )
                continue
            matching_pcs = [
                pc
                for pc in pc_list
                if pc.canonical_ingress.entry_point_id == fseed.entry_point_id
            ]
            if not matching_pcs:
                projection_rejected_count += 1
                projection_rejected_by_target.setdefault(
                    fseed.entry_point_id, []
                ).append(fseed.candidate_id)
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
                continue
            # Multiple matches with distinct bindings are valid alternatives.
            # Record projection acceptance for each matching candidate.
            for pc in matching_pcs:
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=pc.candidate_id,
                    stage=STAGE_PROJECTION,
                    reason="projected",
                    detail=f"Projected candidate for pattern '{fseed.seed_id}'.",
                )

        if projection_rejected_count:
            logger.info(
                "  %d filtered seed(s) rejected at projection stage "
                "(no exact ingress match).",
                projection_rejected_count,
            )

        # Build qualified candidates: fan out all valid projected matches,
        # dedupe by projected candidate_id, preserve filter provenance.
        qualified_candidates = build_qualified_candidates(
            filtered_seeds, projected_by_pattern
        )

        # --- Stage 3.7: Coverage-Aware Planning (cmps.4) ---
        # Build deterministic ranked fallback queues per feasible target
        # from qualified projected candidates, bounded to at most three
        # choices per target.  Ranking is deterministic and
        # encounter-independent: (pattern_id, candidate_id) — NOT
        # pinned-technique count and NOT filter-result arrival order.
        fallback_queues = build_fallback_queues(qualified_candidates, coverage_universe)

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
        # allocation (cmps.4 blocker 3).  Includes the budget and exact target
        # IDs — not backward set-membership inference.
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

        # Record infeasible coverage targets (no compatible projection at all)
        # as structural projection gaps (cmps.4 blocker 3).
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

        # Preserve projection issues as stage events with complete typed
        # payload (cmps.4 blocker 3: persist complete ProjectionIssue/
        # ProjectionLimitation payloads — step_id, slot_id, evidence/results
        # — not reduced strings/counts).
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

        # Coverage-aware selection: first hard objective is one candidate
        # for every feasible coverage target.  Only then optimize secondary
        # diversity / per-pattern caps.  Capping must not discard a target's
        # sole accepted candidate.  Phase 1 is cap-immune.  Only primaries
        # are selected — remaining choices are fallback_available for cmps.5.
        selection_result = select_with_coverage_priority(
            qualified_candidates,
            fallback_queues,
            coverage_universe,
            max_per_pattern=max_scenarios_per_pattern,
        )
        selected_count = len(selection_result.selected)
        candidates_capped = selection_result.capped_count

        # Record selection events for selected candidates.
        for qc in selection_result.selected:
            stage_ledger.record(
                entry_point_id=qc.entry_point_id,
                candidate_id=qc.candidate_id,
                stage=STAGE_SELECTION,
                reason="selected",
                detail=f"Selected for generation (rank {qc.rank}).",
            )

        # Record selection-limitation events for targets where a per-pattern
        # cap could not be respected (cmps.4 blocker 2/4: these are real
        # selection limitations where qualified candidates were deliberately
        # not chosen for cap reasons — not synthetic events for empty queues).
        for ep_id in selection_result.selection_limitation_target_ids:
            stage_ledger.record(
                entry_point_id=ep_id,
                candidate_id=selection_result.primary_candidate_ids.get(ep_id, ""),
                stage=STAGE_SELECTION,
                reason="selection_limitation",
                detail=(
                    "Per-pattern cap could not be respected for this target; "
                    "coverage preserved but cap violated."
                ),
            )

        if candidates_capped > 0:
            logger.info(
                "  Coverage-aware selection: %d candidates capped by "
                "per-pattern limit (sole-target candidates preserved).",
                candidates_capped,
            )
        if selection_result.uncovered_target_ids:
            logger.info(
                "  %d feasible target(s) with no candidate: %s",
                len(selection_result.uncovered_target_ids),
                selection_result.uncovered_target_ids,
            )
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
        from asago_scenario_generator.pipeline.persistence import (
            PlanningCheckpointV1,
            make_finalization_persistence_adapter,
            write_planning_checkpoint,
        )
        from asago_scenario_generator.pipeline.runner_finalization import (
            run_target_finalization,
            strict_v3_coverage_plan,
        )

        initial_plan = build_coverage_plan(
            coverage_universe, fallback_queues, selection_result
        )
        planning_checkpoint = PlanningCheckpointV1(
            qualification_facts_source=qualification_facts_source,
            qualification_facts_sha256=input_hashes.qualification_facts_hash,
            stage_events=[event.to_dict() for event in stage_ledger.events],
            projection_limitation_target_ids=sorted(projection_limitation_target_ids),
            selected_candidate_ids=[
                candidate.candidate_id for candidate in selection_result.selected
            ],
            capped_count=selection_result.capped_count,
            uncovered_target_ids=sorted(selection_result.uncovered_target_ids),
            per_pattern_counts=dict(
                sorted(selection_result.per_pattern_counts.items())
            ),
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
        write_planning_checkpoint(run_dir, planning_checkpoint)
        # Atomically replace the sentinel with a hash-bound inventory of
        # immutable resume support before publishing mutable lifecycle state.
        # This keeps a crash immediately after plan persistence resumable.
        partial_manifest.inventory = [
            build_artifact_entry(role, run_dir, path)
            for role, path in (
                (ArtifactRole.USE_CASE, "use-case.txt"),
                (ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"),
                (ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"),
                (ArtifactRole.PLANNING_CHECKPOINT, "planning-checkpoint.json"),
            )
        ]
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
            fallback_queues=fallback_queues,
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
        # Best-effort failed manifest with accumulated evidence, then re-raise.
        # Flush/close/remove run-local file handlers BEFORE hashing failed
        # evidence so pipeline.log is stable and we don't log through a
        # closed handler afterward.
        sf_logger = logging.getLogger("asago_scenario_generator")
        for handler in sf_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                try:
                    handler.flush()
                    handler.close()
                except Exception:  # noqa: BLE001, S110 - handler cleanup must not fail
                    pass
                sf_logger.removeHandler(handler)
        # Log to stderr only (run-local handler removed).
        logging.getLogger("asago_scenario_generator").error("Pipeline failed: %s", exc)
        try:
            # If partial_manifest was never constructed (very early failure),
            # load the sentinel from disk as a base.
            if partial_manifest is not None:
                failed_manifest = partial_manifest
            else:
                try:
                    failed_manifest = load_manifest(run_dir)
                except Exception:  # noqa: BLE001 - create fallback manifest if load fails
                    failed_manifest = RunManifest(
                        manifest_version=MANIFEST_VERSION,
                        status=RunStatus.STARTED,
                        run_id=run_id,
                        timestamp_start=timestamp_start,
                        package_version=importlib.metadata.version(
                            "asago-scenario-generator"
                        ),
                        provenance=Provenance(
                            run_id=run_id,
                            timestamp_start=timestamp_start,
                        )
                        if provenance is not None
                        else None,
                    )
            failed_manifest.status = RunStatus.FAILED
            failed_manifest.timestamp_end = datetime.now(UTC).isoformat()
            failed_manifest.error = str(exc)
            if failed_manifest.provenance:
                failed_manifest.provenance.timestamp_end = failed_manifest.timestamp_end
            # Finish any interrupted two-document publication before the
            # failed manifest inventories forensic state.  V3 has one
            # lifecycle authority, so legacy mirrors remain empty.
            from asago_scenario_generator.pipeline.persistence import (
                recover_finalization_journal,
            )

            immutable_roles = {
                ArtifactRole.USE_CASE,
                ArtifactRole.CAPABILITY_PROFILE,
                ArtifactRole.THREAT_SURFACE,
                ArtifactRole.PLANNING_CHECKPOINT,
            }
            try:
                started_manifest = load_manifest(
                    run_dir, requested_version=MANIFEST_VERSION
                )
            except Exception:  # noqa: BLE001 - early failures may predate sentinel
                started_manifest = None
            original_by_role = (
                {
                    item.role: item
                    for item in started_manifest.inventory
                    if item.role in immutable_roles
                }
                if started_manifest is not None
                else {}
            )
            support_published = set(original_by_role) == immutable_roles
            support_valid = False
            if support_published and started_manifest is not None:
                try:
                    ManifestInventoryResolver(
                        run_dir, started_manifest, check_orphans=False
                    )
                    support_valid = True
                except ManifestIntegrityError as support_exc:
                    failed_manifest.error = (
                        f"{exc}; immutable support validation failed: {support_exc}"
                    )
            if support_valid:
                recover_finalization_journal(run_dir, expected_run_id=run_id)
            evidence_inventory = _build_failed_evidence_inventory(run_dir, [])
            failed_manifest.inventory = [
                item for item in evidence_inventory if item.role not in original_by_role
            ] + list(original_by_role.values())
            write_failed_manifest(run_dir, failed_manifest)
            raise
        except Exception:  # noqa: BLE001, S110 - best-effort write during error path
            pass
        raise
