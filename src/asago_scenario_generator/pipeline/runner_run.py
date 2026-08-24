"""Run orchestration helpers for the manifest-v3 pipeline runner.

Decomposed from ``pipeline.runner`` so the ``run_pipeline`` entry point
stays a thin public facade over self-contained, individually
mutation-scoped stage wiring.
"""

from __future__ import annotations

import importlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from asago_scenario_generator.data.loaders import (
    load_attack_patterns,
    load_risk_extraction,
)
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.data.validation import validate_risk_card_coherence
from asago_scenario_generator.llm.client import LLMClient
from asago_scenario_generator.manifest import (
    MANIFEST_V3 as MANIFEST_VERSION,
)
from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    ModelConfig,
    Provenance,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    capture_provenance,
    compute_config_digest,
    load_manifest,
    resolve_run_dir,
    write_failed_manifest,
    write_manifest_sentinel,
    write_started_manifest,
)
from asago_scenario_generator.models.attack_pattern import validate_attack_pattern
from asago_scenario_generator.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
)
from asago_scenario_generator.pipeline.candidates import (
    FilterProtocolError,
    StageRecord,
    apply_rule_based_filter,
    expand_candidates,
    filter_candidates,
)

if TYPE_CHECKING:
    from asago_scenario_generator.pipeline.runner import PipelineResult
from asago_scenario_generator.pipeline.coverage_planning import (
    STAGE_FILTER,
    STAGE_PROJECTION,
    STAGE_RULES,
    STAGE_SELECTION,
    GenerationMode,
    StageLedger,
    build_coverage_universe,
    build_qualified_candidates,
    plan_generation,
)
from asago_scenario_generator.pipeline.generate import generate_run_id
from asago_scenario_generator.pipeline.io import (
    write_capability_profile,
    write_filter_quarantine_evidence,
    write_pipeline_call_log,
    write_threat_surface,
    write_use_case,
)
from asago_scenario_generator.pipeline.model_configuration import (
    resolve_effective_model_config,
)
from asago_scenario_generator.pipeline.profile import infer_capability_profile
from asago_scenario_generator.pipeline.projection import (
    ProjectionBudget,
    ProjectionReadinessError,
    capture_capability_snapshot,
    ensure_projection_readiness,
    project_authoritative_candidates,
)
from asago_scenario_generator.pipeline.seeds import expand_seeds
from asago_scenario_generator.pipeline.threats import determine_threat_surface
from asago_scenario_generator.prompts import hash_prompt_templates

# The runner-owned completion/input helpers are imported lazily inside the
# functions that use them: pipeline.runner re-exports this module at its
# bottom, so a module-level import here would make the import order of
# runner vs runner_run order-dependent.
logger = logging.getLogger(__name__)


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
    from asago_scenario_generator.pipeline.runner import (
        _DEFAULT_CROSS_TAXONOMY_PATH,
    )

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
    from asago_scenario_generator.pipeline.runner import (
        _build_failed_evidence_inventory,
    )

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
        from asago_scenario_generator.pipeline.runner import (
            _parse_qualification_facts,
        )

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
    from asago_scenario_generator.pipeline.runner import _removal_decision_summary

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
        from asago_scenario_generator.pipeline.runner import _capture_input_hashes

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
        from asago_scenario_generator.pipeline.runner import _complete_v3_run

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
