"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import importlib.metadata
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from asago_scenario_generator.data.loaders import (
    load_attack_patterns,
    load_yaml_strict,
)
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
from asago_scenario_generator.models.attack_pattern import (
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.pipeline.candidates import (
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
            qualification_passed = _scorecard_qualification_passed(scorecard)
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
    if _authoritative_products_ready(eval_success, report_success):
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
            qualification_passed = _scorecard_qualification_passed(scorecard)

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

    ordinary_completion_succeeded = _ordinary_completion_succeeded(
        terminal_processing_succeeded=terminal_processing_succeeded,
        had_quarantine=had_quarantine,
        eval_enabled=eval_enabled,
        eval_success=eval_success,
        report_success=report_success,
        qualification_passed=qualification_passed,
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
        if _readable_evidence_file(full):
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
# {"version":1,"tested_at":"2026-08-24T10:18:00Z","module_hash":"2bebcf43b1b8e37f0a14d72c70e471749a5726933bf2e4fcf0c157b17be4ce5a","source_sha256":"ac370c0342bc6f180e2003f09d3a0d410f4c0a47348ece30baa8038abe9eb990","functions":[{"id":"func/_removal_decision_summary","name":"_removal_decision_summary","line":90,"end_line":92,"hash":"d667aee752da438147a4ec70db0a961fe233f2bd85b43f17d5093cf8955ea8d6"},{"id":"func/QualificationFactsV1.canonical_facts","name":"canonical_facts","line":120,"end_line":124,"hash":"e79433cdcf258ae6db4935554e1b3d4e3a7faf7ac00d4bd3add93c9b5d711334"},{"id":"func/_parse_qualification_facts","name":"_parse_qualification_facts","line":127,"end_line":133,"hash":"03ee223c05a0311e8801a378b3c2b2c71b1e99452d41287b46091bbbfe4fc732"},{"id":"func/_load_admitted_scenarios","name":"_load_admitted_scenarios","line":136,"end_line":164,"hash":"730b459ef988526f49fb7b63d6c106b2c717bed87d7f2af071c92051d462e9be"},{"id":"func/_scorecard_qualification_passed","name":"_scorecard_qualification_passed","line":167,"end_line":169,"hash":"9f4709e9478cce1a1455d62578da227705ff09f47854d2e2ac3b6670da3ee3b1"},{"id":"func/_authoritative_products_ready","name":"_authoritative_products_ready","line":172,"end_line":174,"hash":"7f1eb164932cbacbba712867f8071c667eaa60313cbc845dff3e6b47e16d861c"},{"id":"func/_ordinary_completion_succeeded","name":"_ordinary_completion_succeeded","line":177,"end_line":194,"hash":"b88e76347d673d088e57883fd9901eb4eacb3c29f3c250625207d8b73b8c290e"},{"id":"func/_readable_evidence_file","name":"_readable_evidence_file","line":197,"end_line":199,"hash":"4230982093fccad3d46ac9c3fb43f2a408b42e8b0a188ff7a4f8966fffa19f29"},{"id":"func/_complete_v3_run","name":"_complete_v3_run","line":202,"end_line":512,"hash":"bd8a80b2ea192c5597fe54d139c7163a464df1dcad50dc1aa283e14579296550"},{"id":"func/_hydrate_planning_inputs","name":"_hydrate_planning_inputs","line":515,"end_line":594,"hash":"ded65f730429dd21cafe19eb89129d550b85a080ba5fd57cc99bc67219024649"},{"id":"func/resume_pipeline","name":"resume_pipeline","line":597,"end_line":688,"hash":"3afaeaa3ef1f0d34e8460bc6f13b6bbb445dc9051a5ee24e5d440c389815e443"},{"id":"func/run_profile_only","name":"run_profile_only","line":691,"end_line":699,"hash":"655c624fc6fe51e431b1ef1532fcc6302d1a09c38946e58b22195f7b43c1d35f"},{"id":"func/_capture_input_hashes","name":"_capture_input_hashes","line":702,"end_line":775,"hash":"9f7fdce2ca6aed773742af83d95abbcd64143478c91451e54578166985d97807"},{"id":"func/_build_failed_evidence_inventory","name":"_build_failed_evidence_inventory","line":778,"end_line":900,"hash":"cb0ed2e0513ef1e1c77ad0881e730e4b82ae61d8a59e82002c29a4679bdb0934"},{"id":"func/run_pipeline","name":"run_pipeline","line":903,"end_line":981,"hash":"ca83a93d276a7c70cfbd538bfec6835ace3a39257461642e95c09af56c33c688"}]}
# mutate4py-manifest-end
