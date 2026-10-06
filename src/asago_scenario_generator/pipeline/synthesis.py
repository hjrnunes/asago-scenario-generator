"""Composition root for the obligation-aware STPA synthesis workflow.

The synthesis workflow deliberately lives at a composition boundary.  Phase 1
planning, structural consideration/revision, STPA slot filling, and ordinary
scenario production are supplied as typed seams (or adapters around those
seams).  This module owns ordering, shared capability identity, persistence,
and the top-level run record; it does not duplicate the domain contracts used
by those stages.

The adapter surface is intentionally small enough for deterministic acceptance
fakes while still allowing the production CLI to wire the existing STPA
providers.  Adapter functions receive only the keyword arguments they declare,
which keeps small test doubles and richer production adapters interchangeable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import yaml

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.pipeline.model_runtime import (
    ModelRuntime,
)
from asago_scenario_generator.pipeline.target_realization_persistence import (
    TARGET_REALIZATION_FILENAME,
    write_target_realization,
)
from asago_scenario_generator.pipeline.synthesis_baseline import (
    _assert_taxonomy_input_identity as _assert_taxonomy_input_identity,
    _baseline_diagnostics,
    _baseline_failure_message,
    _build_briefs,
    _prepare_capability_profile,
    _prepare_snapshot,
    _prepare_taxonomy_inputs,
    _run_baseline,
    _run_plan,
)
from asago_scenario_generator.pipeline.synthesis_consideration import (
    _applicable_ids,
    _close_consideration_artifact,
    _ensure_route_universe,
    _run_bounded_revision,
    _run_consideration,
)
from asago_scenario_generator.pipeline.synthesis_defaults import (
    _build_synthesis_scenario_contexts as _build_synthesis_scenario_contexts,
    _default_baseline as _default_baseline,
    _default_enrich_control_actions as _default_enrich_control_actions,
    _default_scenarios as _default_scenarios,
    _ensure_obligation_provider,
    _production_defaults as _production_defaults,
    _resolve_adapters,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _accounting_source_pins,
    _run_accounting,
    _run_ica,
    _run_operation_enrichment,
    _run_realization,
    _run_scenarios,
    _run_target_realization,
    _target_realized_stpa_inputs,
    _verified_enriched_operations as _verified_enriched_operations,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    ACCOUNTING_FILENAME,
    CONSIDERATION_FILENAME,
    MANIFEST_FILENAME,
    PLAN_FILENAME,
    REPORT_FILENAME,
    SCENARIO_REALIZATION_FILENAME,
    PersistArtifactPort,
    PersistManifestPort,
    ReportPort,
    SynthesisAdapters,
    SynthesisInputs,
    SynthesisResult,
    SynthesisRunStatus,
    _systemic_inputs,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _declared_capability_labels as _declared_capability_labels,
    _digest_value,
    _dump,
    _ica_considerations,
    _ica_verification as _ica_verification,
    _ordinary_icas as _ordinary_icas,
)
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.infra.provider_record import provider_call_session
from asago_scenario_generator.stpa.models.control_structure import (
    MAX_CONTEXT_ROWS_PER_ACTION,
    ControlStructure,
    control_structure_context_tables,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TARGET_OBSERVATIONS_FILENAME,
)

logger = logging.getLogger(__name__)


_MANIFEST_SCHEMA = "stpa-synthesis-manifest-v1"
_MANIFEST_DOMAIN = "asago-scenario-generator:stpa-synthesis-manifest:v1"


def run_synthesis(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters | object | None = None,
) -> SynthesisResult:
    """Run the obligation-aware synthesis workflow in fixed stage order.

    The order is observable and intentional: shared capability preparation,
    Phase 1 planning, ordinary SP1 baseline, consideration, at most one
    structural revision/recheck, final ICA analysis, ordinary SP3 scenarios,
    and provisional accounting.  A revision-triggering initial pass always
    receives exactly one recheck; a clean pass receives no second pass.

    Every provider request and response lands in ``provider-calls.jsonl`` in
    the output directory (see ``stpa.infra.provider_record``).
    """
    if not isinstance(inputs, SynthesisInputs):
        raise TypeError("run_synthesis requires a SynthesisInputs value")
    with provider_call_session(
        record_dir=Path(inputs.output_dir), replay_dir=inputs.replay_calls_dir
    ):
        return _run_synthesis(inputs, adapters)


def _run_synthesis(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters | object | None,
) -> SynthesisResult:
    """Run the fixed-order workflow inside an active provider-call session."""
    output_dir = Path(inputs.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = _resolve_adapters(adapters)
    if resolved.model_runtime is None:
        resolved = replace(resolved, model_runtime=ModelRuntime.for_inputs(inputs))
    stage_errors: list[str] = []
    stage_warnings: list[str] = []
    calls: list[str] = []

    capability_profile = _prepare_capability_profile(inputs, resolved, calls)
    capability_snapshot = _prepare_snapshot(inputs, capability_profile)
    prepared_profile_path = _persist_prepared_profile(output_dir, capability_profile)
    taxonomy_inputs = _prepare_taxonomy_inputs(
        inputs,
        capability_profile,
        capability_snapshot,
        resolved,
        calls,
    )

    plan = _run_plan(taxonomy_inputs, inputs, resolved, calls)
    plan_path = _persist_plan(output_dir, plan, resolved, calls)
    plan = _reload_persisted_plan(plan, plan_path)

    briefs = _build_briefs(
        plan,
        inputs,
        capability_snapshot,
        taxonomy_inputs,
        resolved,
        calls,
    )

    baseline = _run_baseline(
        inputs,
        capability_profile,
        capability_snapshot,
        taxonomy_inputs,
        plan,
        prepared_profile_path,
        resolved,
        calls,
    )
    baseline_loss = baseline.loss_analysis
    baseline_control = baseline.control_structure
    if baseline_loss is None or baseline_control is None:
        raise ValueError(_baseline_failure_message(baseline))
    stage_warnings.extend(_baseline_diagnostics(baseline))

    # Provider construction is deliberately after the provider-free Phase 1
    # planner and ordinary SP1 baseline.  The same object then reaches
    # routing, bounded revision/recheck, and ICA filling.
    resolved = _ensure_obligation_provider(
        resolved, _systemic_inputs(inputs), output_dir
    )

    initial_consideration = _run_consideration(
        briefs,
        plan,
        baseline_loss,
        baseline_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
    )
    initial_routes = tuple(initial_consideration.routes)
    applicable_briefs = tuple(
        brief for brief in briefs if brief.obligation_id in _applicable_ids(plan)
    )
    _ensure_route_universe(initial_routes, _applicable_ids(plan))
    gaps = tuple(
        route for route in initial_routes if route.disposition == "upstream_gap"
    )

    revision_result, recheck_result, final_loss, final_control, final_routes = (
        _run_bounded_revision(
            gaps,
            initial_routes,
            applicable_briefs,
            plan,
            baseline_loss,
            baseline_control,
            inputs,
            capability_snapshot,
            resolved,
            calls,
            stage_errors,
        )
    )

    _ensure_route_universe(final_routes, _applicable_ids(plan))
    consideration = _close_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial=initial_consideration,
        recheck=recheck_result,
        final_routes=final_routes,
        revision=revision_result,
        baseline_loss=baseline_loss,
        baseline_control=baseline_control,
        final_loss=final_loss,
        final_control=final_control,
    )

    # Enrichment grounding (owner decision, M2 unified path): when an
    # observed target profile is supplied, the same operation-matching
    # discipline as target realization runs before ICA enumeration and names
    # each supported logical control action's documented operation.  Known
    # operations enrich the logical control actions; they never replace the
    # control model with tool enumeration, and no input switches the
    # generation algorithm.
    operation_enrichment = _run_operation_enrichment(
        loss_analysis=final_loss,
        control_structure=final_control,
        capability_profile=capability_profile,
        inputs=inputs,
        adapters=resolved,
        calls=calls,
    )
    if operation_enrichment is not None:
        final_control = operation_enrichment.control_structure
        stage_warnings.extend(
            f"control action enrichment: {warning}"
            for warning in operation_enrichment.record.diagnostics
        )

    # One adaptive analysis: enrichment (capability profile, execution target
    # profile, target observations) feeds ICA enumeration and Stage 5; it
    # never selects a different generation algorithm.
    ica_enumeration = _run_ica(
        final_routes,
        briefs,
        plan,
        final_loss,
        final_control,
        capability_profile,
        inputs,
        capability_snapshot,
        resolved,
        calls,
    )
    target_realization = _run_target_realization(
        ica_enumeration=ica_enumeration,
        loss_analysis=final_loss,
        control_structure=final_control,
        capability_profile=capability_profile,
        inputs=inputs,
        adapters=resolved,
        calls=calls,
    )
    effective_control, effective_icas = _target_realized_stpa_inputs(
        target_realization=target_realization,
        loss_analysis=final_loss,
        control_structure=final_control,
        ica_enumeration=ica_enumeration,
        capability_profile=capability_profile,
    )
    scenario_result = _run_scenarios(
        effective_icas,
        briefs,
        final_routes,
        plan,
        final_loss,
        effective_control,
        capability_profile,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        stage_errors,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
    )
    accounting = _run_accounting(
        plan,
        consideration,
        final_routes,
        effective_icas,
        scenario_result,
        final_loss,
        effective_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        source_pins=_accounting_source_pins(
            plan=plan,
            consideration=consideration,
            final_loss=final_loss,
            final_control=effective_control,
            ica_enumeration=effective_icas,
        ),
    )
    realization = _run_realization(
        accounting=accounting,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        adapters=resolved,
        calls=calls,
    )
    consideration_path = _persist_sidecar(
        output_dir,
        CONSIDERATION_FILENAME,
        consideration,
        resolved.persist_consideration,
        "consideration",
    )
    accounting_path = _persist_sidecar(
        output_dir,
        ACCOUNTING_FILENAME,
        accounting,
        resolved.persist_accounting,
        "accounting",
    )
    realization_path = _persist_sidecar(
        output_dir,
        SCENARIO_REALIZATION_FILENAME,
        realization,
        resolved.persist_realization,
        "realization",
    )
    target_realization_path = _persist_target_realization(
        output_dir,
        target_realization,
        resolved.persist_target_realization,
    )
    manifest = _build_manifest(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        plan=plan,
        baseline=baseline,
        final_loss=final_loss,
        final_control=final_control,
        consideration=consideration,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        calls=calls,
        revision=revision_result,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        provider_stages={
            "consideration_initial": initial_consideration,
            "consideration_recheck": recheck_result,
            "revision": (
                revision_result,
                consideration.revision,
            ),
            "ica": ica_enumeration,
        },
    )
    manifest_path = _persist_manifest(output_dir, manifest, resolved.manifest)

    report_path = _render_report(
        output_dir,
        manifest,
        plan,
        consideration,
        accounting,
        realization,
        target_realization,
        scenario_result,
        resolved.report,
    )

    artifact_paths = _artifact_paths(
        output_dir,
        inputs,
        {
            PLAN_FILENAME: plan_path,
            CONSIDERATION_FILENAME: consideration_path,
            ACCOUNTING_FILENAME: accounting_path,
            SCENARIO_REALIZATION_FILENAME: realization_path,
            MANIFEST_FILENAME: manifest_path,
        },
        target_realization_path=target_realization_path,
        operation_enrichment=operation_enrichment,
        report_path=report_path,
    )

    return SynthesisResult(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        obligation_plan=plan,
        baseline=baseline,
        consideration=consideration,
        ica_enumeration=ica_enumeration.ica_enumeration,
        scenario_result=scenario_result,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        manifest=manifest,
        output_dir=output_dir,
        report_path=report_path,
        artifact_paths=artifact_paths,
        ica_considerations=_ica_considerations(ica_enumeration),
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        ica_hazard_verification=ica_enumeration.ica_hazard_verification,
    )


# ---------------------------------------------------------------------------
# Stage adapters
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Persistence and manifest
# ---------------------------------------------------------------------------


def _persist_prepared_profile(output_dir: Path, profile: CapabilityProfile) -> Path:
    """Persist one typed profile for SP1 to reload without re-derivation.

    The ordinary ``run_sp1`` API accepts a profile path rather than an
    in-memory profile.  Writing the already prepared model once at this seam
    keeps Phase 1 and STPA on the same profile identity and ensures that SP1's
    Stage 1b is skipped.
    """
    payload = profile.model_dump(mode="json", exclude_none=True)
    path = output_dir / "capability-profile.yaml"
    atomic_write_text(
        path, yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    )
    return path


def _persist_plan(
    output_dir: Path,
    plan: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Path:
    """Persist the Phase 1 plan through its adapter and verify a reload."""
    if adapters.persist_plan is not None:
        result = adapters.persist_plan(
            output_dir=output_dir,
            plan=plan,
        )
        calls.append("persist_plan")
        return Path(result) if result is not None else output_dir / PLAN_FILENAME
    path = write_taxonomy_obligation_plan(output_dir, plan)
    calls.append("persist_plan")
    return path


def _reload_persisted_plan(plan: Any, path: Path) -> Any:
    """Use the closed, integrity-checked Phase 1 artifact downstream."""
    reloaded = TaxonomyObligationPlan.from_yaml(path.read_text(encoding="utf-8"))
    if reloaded != plan:
        raise ValueError("persisted Phase 1 plan does not match the planned artifact")
    return reloaded


def _persist_sidecar(
    output_dir: Path,
    filename: str,
    artifact: Any,
    writer: PersistArtifactPort | None,
    label: str,
) -> Path:
    """Write one closed artifact atomically, then perform a best-effort reload."""
    if writer is not None:
        result = writer(output_dir=output_dir, artifact=artifact)
        path = Path(result) if result is not None else output_dir / filename
        if not path.exists():
            raise ValueError(f"{label} persistence adapter did not write {path}")
        return path
    path = output_dir / filename
    content = _artifact_yaml(artifact)
    atomic_write_text(path, content)
    _verify_yaml_round_trip(artifact, path)
    return path


def _persist_target_realization(
    output_dir: Path,
    artifact: Any | None,
    writer: PersistArtifactPort | None,
) -> Path | None:
    """Publish the additive target lens only when a target was supplied."""
    if artifact is None:
        return None
    if writer is None:
        return write_target_realization(output_dir, artifact)
    path = _persist_sidecar(
        output_dir,
        TARGET_REALIZATION_FILENAME,
        artifact,
        writer,
        "target_realization",
    )
    return path


def _persist_manifest(
    output_dir: Path,
    manifest: Any,
    writer: PersistManifestPort | None,
) -> Path:
    """Atomically publish and verify the top-level synthesis manifest."""
    if writer is not None:
        result = writer(output_dir=output_dir, manifest=manifest)
        path = Path(result) if result is not None else output_dir / MANIFEST_FILENAME
        if not path.exists():
            raise ValueError(f"manifest persistence adapter did not write {path}")
        return path
    path = output_dir / MANIFEST_FILENAME
    atomic_write_text(path, _artifact_yaml(manifest))
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("synthesis manifest did not round-trip as a mapping")
    return path


def _build_manifest(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    baseline: Any,
    final_loss: Any,
    final_control: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    ica_enumeration: Any,
    scenario_result: Any,
    calls: list[str],
    revision: Any,
    stage_errors: list[str],
    stage_warnings: list[str],
    target_realization: Any | None = None,
    operation_enrichment: Any | None = None,
    provider_stages: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a digest-bound manifest from stage authorities."""
    scenarios = tuple(scenario_result.scenario_envelopes)
    counts = _summary_dict(accounting.summary)
    if not counts:
        raise ValueError("obligation accounting must carry a numeric summary")
    catalog_pins = _manifest_taxonomy_pins(plan.catalog_pins)
    mapping_pins = _manifest_taxonomy_pins(plan.mapping_pins)
    source_artifacts = _manifest_source_artifacts(
        inputs=inputs,
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        taxonomy_inputs=taxonomy_inputs,
        plan=plan,
        baseline=baseline,
        final_loss=final_loss,
        final_control=final_control,
        consideration=consideration,
        accounting=accounting,
        realization=realization,
        target_realization=target_realization,
        operation_enrichment=operation_enrichment,
        ica_enumeration=ica_enumeration,
        scenario_result=scenario_result,
        counts=counts,
    )
    scenario_counts = _manifest_scenario_counts(scenario_result, len(scenarios))
    run_status, run_status_reason = _scenario_generation_status(scenario_counts)
    payload: dict[str, Any] = {
        "schema_version": _MANIFEST_SCHEMA,
        "run_id": f"synthesis-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "created_at": datetime.now(UTC).isoformat(),
        "use_case_digest": source_artifacts["use_case"]["semantic_digest"],
        "risk_set_digest": source_artifacts["risk_set"]["semantic_digest"],
        "capability_profile_digest": source_artifacts["capability_profile"][
            "semantic_digest"
        ],
        "capability_snapshot_digest": source_artifacts["capability_snapshot"][
            "semantic_digest"
        ],
        "qualification_facts_digest": source_artifacts["qualification_facts"][
            "semantic_digest"
        ],
        "taxonomy_inputs_digest": source_artifacts["taxonomy_inputs"][
            "semantic_digest"
        ],
        # Keep the two Phase 1 pin maps visible at the manifest boundary.  They
        # are taxonomy release/content pins, not generic ArtifactPin values;
        # retaining their native ``release`` and ``digest`` fields prevents a
        # misleading conversion of taxonomy identity into a schema label.
        "catalog_pins": catalog_pins,
        "mapping_pins": mapping_pins,
        "source_artifacts": source_artifacts,
        # Evidence-model status: a missing operation inventory is recorded
        # as unknown (never as empty); conflicting supplied readings stay
        # visible with both values and their sources.
        "evidence_inventory": _manifest_evidence_inventory(inputs),
        "evidence_conflicts": _manifest_evidence_conflicts(inputs.qualification_facts),
        "plan_digest": source_artifacts["taxonomy_obligation_plan"]["semantic_digest"],
        "baseline_loss_analysis_digest": source_artifacts["baseline_loss_analysis"][
            "semantic_digest"
        ],
        "baseline_control_structure_digest": source_artifacts[
            "baseline_control_structure"
        ]["semantic_digest"],
        "final_loss_analysis_digest": source_artifacts["final_loss_analysis"][
            "semantic_digest"
        ],
        "final_control_structure_digest": source_artifacts["final_control_structure"][
            "semantic_digest"
        ],
        "consideration_digest": source_artifacts["obligation_consideration"][
            "semantic_digest"
        ],
        "ica_enumeration_digest": source_artifacts["ica_enumeration"][
            "semantic_digest"
        ],
        "accounting_digest": source_artifacts["obligation_accounting"][
            "semantic_digest"
        ],
        "scenario_realization_digest": source_artifacts["scenario_realization"][
            "semantic_digest"
        ],
        "execution_target_profile_digest": (
            source_artifacts.get("execution_target_profile", {}).get("semantic_digest")
        ),
        "target_realization_digest": (
            source_artifacts.get("target_realization", {}).get("semantic_digest")
        ),
        "scenario_collection_digest": source_artifacts["scenario_collection"][
            "semantic_digest"
        ],
        "model_controls": {
            "profile": inputs.profile,
            "max_workers": inputs.max_workers,
        },
        "stage_call_counts": {name: calls.count(name) for name in sorted(set(calls))},
        "provider_evidence": _manifest_provider_evidence(provider_stages or {}, inputs),
        "prompt_call_evidence": _manifest_prompt_call_evidence(inputs.output_dir),
        "total_prompt_tokens": _total_prompt_tokens(inputs.output_dir),
        "context_tables": _manifest_context_tables(final_control),
        "obligation_disposition_counts": counts,
        "obligation_stop_reason_counts": _obligation_stop_reason_counts(
            accounting, realization
        ),
        "obligation_resolution_funnel": _obligation_resolution_funnel(
            plan=plan,
            accounting=accounting,
            realization=realization,
            scenario_count=len(scenarios),
        ),
        "run_status": run_status.value,
        "run_status_reason": run_status_reason,
        "scenario_counts": scenario_counts,
        "candidate_outcomes": _manifest_candidate_outcomes(scenario_result),
        "scenario_errors": list(scenario_result.stage_errors),
        "revision": _manifest_revision(revision),
        "stage_errors": list(stage_errors),
        "stage_warnings": list(stage_warnings),
        # ``run`` cannot resume; the block keeps the manifest schema stable.
        "resume": {
            "requested": False,
            "state": "not_requested",
            "reused_stages": [],
            "checkpoint": None,
        },
        # The manifest is written before the HTML adapter so the report cannot
        # be included in this digest without a circular dependency.  State
        # that boundary explicitly: the report is optional presentation output,
        # not a normative source artifact.
        "report": {
            "artifact_id": "synthesis-report",
            "schema_version": "synthesis-report-html-v1",
            "filename": REPORT_FILENAME,
            "normative": False,
            "digest": None,
        },
    }
    payload["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, payload)
    return payload


def _manifest_context_tables(control_structure: Any) -> dict[str, Any]:
    """Record how much of each Stage 3 context table the row budget showed."""
    tables = (
        control_structure_context_tables(control_structure)
        if isinstance(control_structure, ControlStructure)
        else ()
    )
    return {
        "row_budget": MAX_CONTEXT_ROWS_PER_ACTION,
        "actions": [
            {
                "control_action": table.control_action,
                "combinations": table.combinations,
                "rows_shown": len(table.rows),
                "hidden_values": [
                    {"process_model_id": pm_id, "value": value}
                    for pm_id, value in table.hidden_values
                ],
            }
            for table in tables
        ],
    }


def _total_prompt_tokens(output_dir: Path) -> int | None:
    """Sum recorded prompt tokens from calls.jsonl for the budget check."""
    path = Path(output_dir) / "calls.jsonl"
    if not path.exists():
        return None
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        total += int(entry.get("prompt_tokens") or 0)
    return total


def _manifest_prompt_call_evidence(output_dir: Path) -> list[dict[str, Any]]:
    """Copy compact prompt-budget and provider-usage evidence into the manifest."""
    path = Path(output_dir) / "calls.jsonl"
    if not path.exists():
        return []
    retained_fields = (
        "stage",
        "step",
        "slot_id",
        "scenario_id",
        "model",
        "system_prompt_hash",
        "user_prompt_hash",
        "prompt_tokens",
        "completion_tokens",
        "duration_ms",
        "success",
        "error",
        "prompt_preflight",
    )
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            source = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"calls.jsonl line {line_number} is not valid JSON"
            ) from exc
        if not isinstance(source, dict):
            raise ValueError(f"calls.jsonl line {line_number} must be an object")
        record = {
            field_name: source[field_name]
            for field_name in retained_fields
            if field_name in source and source[field_name] is not None
        }
        if "response_content" in source:
            record["response_digest"] = _digest_value(source["response_content"])
        records.append(record)
    return records


def _manifest_taxonomy_pins(value: Any) -> dict[str, Any]:
    """Serialize native Phase 1 taxonomy pins without changing their meaning."""
    dumped = _dump(value)
    if not isinstance(dumped, Mapping):
        return {}
    return {str(key): dumped[key] for key in sorted(dumped)}


def _manifest_artifact_identity(
    artifact_id: str,
    schema_version: str,
    value: Any,
    *,
    digest: str | None = None,
) -> dict[str, str]:
    """Return one stable identity record for a manifest source artifact.

    Durable typed artifacts already expose their own verified semantic digest.
    For text, input graphs, and adapter-only test values, the manifest still
    gives the value a deterministic version-framed identity rather than using
    an unframed hash or a YAML byte digest.
    """
    declared = digest or getattr(value, "semantic_digest", None)
    if not isinstance(declared, str) or not declared:
        declared = compute_framed_digest(
            f"{_MANIFEST_DOMAIN}:{artifact_id}:v1", _dump(value)
        )
    actual_schema = getattr(value, "schema_version", None)
    return {
        "artifact_id": artifact_id,
        "schema_version": str(actual_schema or schema_version),
        "semantic_digest": declared,
    }


def _manifest_evidence_inventory(inputs: SynthesisInputs) -> dict[str, Any]:
    """Publish the run's supplied operation inventory status.

    A missing inventory is unknown, never empty. The classification is
    deterministic and consumes only the execution target profile.
    """
    from asago_scenario_generator.pipeline.evidence_inventory import (
        classify_evidence_inventory,
    )

    status = classify_evidence_inventory(
        execution_target_profile=inputs.execution_target_profile,
    )
    return status.model_dump(mode="json")


def _manifest_evidence_conflicts(qualification_facts: Any) -> list[dict[str, Any]]:
    """Publish every contradictory supplied fact with its retained readings."""
    from asago_scenario_generator.pipeline.evidence_inventory import (
        conflicting_fact_readings,
    )

    return conflicting_fact_readings(qualification_facts)


def _manifest_source_artifacts(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    baseline: Any,
    final_loss: Any,
    final_control: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    target_realization: Any | None,
    operation_enrichment: Any | None = None,
    ica_enumeration: Any,
    scenario_result: Any,
    counts: Mapping[str, int],
) -> dict[str, dict[str, str]]:
    """Build the complete source identity inventory for the run manifest."""
    del counts  # reserved for future artifact-level accounting metadata
    baseline_loss = baseline.loss_analysis
    baseline_control = baseline.control_structure
    ordinary_icas = ica_enumeration.ica_enumeration
    scenarios = tuple(scenario_result.scenario_envelopes)
    artifacts = {
        "use_case": _manifest_artifact_identity(
            "use-case", "use-case-text-v1", inputs.use_case
        ),
        "risk_set": _manifest_artifact_identity(
            "risk-set", "reviewed-risk-set-v1", inputs.risk_cards
        ),
        "capability_profile": _manifest_artifact_identity(
            "capability-profile", "capability-profile-v1", capability_profile
        ),
        "capability_snapshot": _manifest_artifact_identity(
            "capability-snapshot",
            "capability-fact-snapshot-v1",
            capability_snapshot,
            digest=capability_snapshot.snapshot_digest,
        ),
        "qualification_facts": _manifest_artifact_identity(
            "qualification-facts", "qualification-facts-v1", inputs.qualification_facts
        ),
        "taxonomy_inputs": _manifest_artifact_identity(
            "taxonomy-obligation-inputs",
            "taxonomy-obligation-inputs-v1",
            taxonomy_inputs,
        ),
        "taxonomy_obligation_plan": _manifest_artifact_identity(
            "taxonomy-obligation-plan", "taxonomy-obligation-plan-v1", plan
        ),
        "baseline_loss_analysis": _manifest_artifact_identity(
            "stpa-loss-analysis-baseline",
            "stpa-loss-analysis-v1",
            baseline_loss,
        ),
        "baseline_control_structure": _manifest_artifact_identity(
            "stpa-control-structure-baseline",
            "stpa-control-structure-v1",
            baseline_control,
        ),
        "final_loss_analysis": _manifest_artifact_identity(
            "stpa-loss-analysis-final", "stpa-loss-analysis-v1", final_loss
        ),
        "final_control_structure": _manifest_artifact_identity(
            "stpa-control-structure-final", "stpa-control-structure-v1", final_control
        ),
        "obligation_consideration": _manifest_artifact_identity(
            "obligation-consideration",
            "stpa-obligation-consideration-v1",
            consideration,
        ),
        "ica_enumeration": _manifest_artifact_identity(
            "ica-enumeration", "ica-enumeration-v1", ordinary_icas
        ),
        "scenario_collection": _manifest_artifact_identity(
            "stpa-scenario-collection", "stpa-scenario-collection-v1", scenarios
        ),
        "obligation_accounting": _manifest_artifact_identity(
            "obligation-accounting", "stpa-obligation-accounting-v1", accounting
        ),
        "scenario_realization": _manifest_artifact_identity(
            "scenario-realization", "stpa-scenario-realization-v1", realization
        ),
    }
    if inputs.execution_target_profile is not None:
        artifacts["execution_target_profile"] = _manifest_artifact_identity(
            "execution-target-profile",
            "execution-target-profile-v1",
            inputs.execution_target_profile,
        )
    if target_realization is not None:
        artifacts["target_realization"] = _manifest_artifact_identity(
            "target-realization",
            "target-realization-v1",
            target_realization,
        )
    if operation_enrichment is not None:
        artifacts["control_action_enrichment"] = _manifest_artifact_identity(
            "control-action-operation-enrichment",
            "control-action-operation-enrichment-v1",
            operation_enrichment.record,
        )
    return artifacts


def _manifest_call_evidence(value: Any) -> tuple[Any, ...]:
    """Extract typed call records from a stage result or its wrapper."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[Any] = []
        for item in value:
            result.extend(_manifest_call_evidence(item))
        return tuple(result)
    direct = getattr(value, "call_evidence", None)
    if direct is not None:
        if direct is value:
            return ()
        return _manifest_call_evidence(direct)
    nested = getattr(value, "result", None)
    if nested is not None and nested is not value:
        return _manifest_call_evidence(nested)
    # A single typed call record is accepted as an element in a revision
    # tuple, but arbitrary values are not presented as provider evidence.
    if getattr(value, "call_id", None) is not None:
        return (value,)
    return ()


def _manifest_scalar_fields(value: Any, names: tuple[str, ...]) -> dict[str, Any]:
    """Keep only named scalar evidence fields from a provider envelope."""
    if value is None:
        return {}
    result: dict[str, Any] = {}
    for name in names:
        field = getattr(value, name, None)
        if isinstance(field, (str, int, float, bool)):
            result[name] = field
    return result


def _manifest_revision_endpoint(
    value: Any, names: tuple[str, ...]
) -> dict[str, Any] | None:
    """Project one revision request/response to identity-only evidence."""
    fields = _manifest_scalar_fields(value, names)
    return fields or None


def _manifest_revision_call(value: Any) -> dict[str, Any]:
    """Project one revision call record without serializing provider payloads."""
    return _manifest_scalar_fields(
        value,
        (
            "call_id",
            "outcome",
            "request_digest",
            "response_digest",
            "attempt_count",
        ),
    )


def _manifest_revision(revision: Any) -> dict[str, Any]:
    """Publish bounded revision status and evidence, never its STPA objects."""

    calls = [
        record
        for item in _manifest_call_evidence(revision)
        if (record := _manifest_revision_call(item))
    ]
    calls.sort(key=lambda item: (str(item.get("call_id", "")), _canonical_json(item)))
    return {
        "status": revision.status,
        "trigger_obligation_ids": sorted(
            set(map(str, revision.trigger_obligation_ids))
        ),
        "trigger_gap_ids": sorted(set(map(str, revision.trigger_gap_ids))),
        "diagnostics": [str(value) for value in revision.diagnostics],
        "request": _manifest_revision_endpoint(
            revision.request,
            ("schema_version", "semantic_digest", "request_ref"),
        ),
        "response": _manifest_revision_endpoint(
            revision.response,
            (
                "schema_version",
                "status",
                "request_digest",
                "response_digest",
                "response_ref",
            ),
        ),
        "call_evidence": calls,
    }


def _manifest_provider_evidence(
    stages: Mapping[str, Any], inputs: SynthesisInputs
) -> dict[str, Any]:
    """Publish request/response identities and outcomes for each provider stage."""
    controls = {
        "profile": inputs.profile,
        # ``generate`` has no temperature or batch-size override; the keys keep
        # the manifest schema stable.
        "temperature": None,
        "max_batch_size": None,
    }
    result: dict[str, Any] = {}
    for stage_name in sorted(stages):
        evidence = _manifest_call_evidence(stages[stage_name])
        records = [_dump(item) for item in evidence]
        attempts = sum(
            int(getattr(item, "attempt_count", None) or 1) for item in evidence
        )
        result[stage_name] = {
            "call_count": attempts,
            "records": records,
            "controls": controls,
        }
        verification = getattr(stages[stage_name], "ica_hazard_verification", None)
        if verification is not None:
            result[stage_name]["ica_hazard_verification"] = _dump(verification)
    return result


def _render_report(
    output_dir: Path,
    manifest: Any,
    plan: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    target_realization: Any,
    scenario_result: Any,
    renderer: ReportPort | None,
) -> Path | None:
    """Render the read-only synthesis report after all normative sidecars."""
    if renderer is not None:
        result = renderer(
            output_dir=output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
        return Path(result) if result is not None else None
    try:
        from asago_scenario_generator.report.synthesis import render_synthesis_report

        return render_synthesis_report(
            output_dir,
            manifest=manifest,
            plan=plan,
            consideration=consideration,
            accounting=accounting,
            realization=realization,
            target_realization=target_realization,
            scenario_result=scenario_result,
        )
    except Exception as exc:  # noqa: BLE001 - report is read-only and non-fatal
        logger.warning("synthesis report generation failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Fallback adapters / compatibility bridges
# ---------------------------------------------------------------------------


def _artifact_paths(
    output_dir: Path,
    inputs: SynthesisInputs,
    artifact_paths: dict[str, Path],
    *,
    target_realization_path: Path | None,
    operation_enrichment: Any | None,
    report_path: Path | None,
) -> dict[str, Path]:
    """Add each optional published artifact to the always-written ones."""
    if target_realization_path is not None:
        artifact_paths[TARGET_REALIZATION_FILENAME] = target_realization_path
    if operation_enrichment is not None:
        from asago_scenario_generator.pipeline.control_action_enrichment import (
            CONTROL_ACTION_ENRICHMENT_FILENAME,
        )

        artifact_paths[CONTROL_ACTION_ENRICHMENT_FILENAME] = (
            output_dir / CONTROL_ACTION_ENRICHMENT_FILENAME
        )
    target_observations_path = (
        output_dir / TARGET_OBSERVATIONS_FILENAME
        if inputs.target_observations is not None
        else None
    )
    if target_observations_path is not None and target_observations_path.exists():
        artifact_paths[TARGET_OBSERVATIONS_FILENAME] = target_observations_path
    if report_path is not None:
        artifact_paths[REPORT_FILENAME] = report_path
    return artifact_paths


# ---------------------------------------------------------------------------
# Generic typed/duck-typed helpers
# ---------------------------------------------------------------------------


def _artifact_yaml(value: Any) -> str:
    to_yaml = getattr(value, "to_yaml", None)
    if callable(to_yaml):
        text = to_yaml()
        if isinstance(text, str):
            return text
    payload = _dump(value)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _verify_yaml_round_trip(original: Any, path: Path) -> None:
    """Reload through a closed ``from_yaml`` hook when the artifact has one."""
    loader = getattr(type(original), "from_yaml", None)
    if callable(loader):
        loaded = loader(path.read_text(encoding="utf-8"))
        if loaded != original:
            raise ValueError(f"{path.name} failed closed-model round-trip equality")


def _manifest_candidate_outcomes(result: Any) -> list[dict[str, Any]] | None:
    """Project explicit terminal records; absence is unknown, not zero failures."""
    outcomes = result.candidate_outcomes
    if outcomes is None:
        return None
    return [
        {
            "scenario_id": item.scenario_id,
            "ica_slot_id": item.ica_slot_id,
            "ica_id": item.ica_id,
            "status": getattr(item.status, "value", item.status),
            "diagnostics": list(item.diagnostics),
        }
        for item in outcomes
    ]


def _manifest_scenario_counts(result: Any, generated: int) -> dict[str, int | None]:
    """Count candidates independently from their possibly repeated diagnostics."""
    outcomes = _manifest_candidate_outcomes(result)
    counts: dict[str, int | None] = {
        "generated": generated,
        "failed": None,
        "requested": None,
        "attempted": None,
        "skipped": None,
        "functional_test": None,
        "diagnostic_count": len(result.stage_errors),
    }
    if outcomes is None:
        return counts
    failures = {"generation_failed", "rendering_failed", "publication_failed"}
    published = sum(item["status"] == "published" for item in outcomes)
    functional_test = sum(item["status"] == "functional_test" for item in outcomes)
    skipped = sum(item["status"] == "skipped" for item in outcomes)
    counts.update(
        # Once explicit terminal outcomes exist, ``published`` is the
        # authoritative adversarial yield.  An envelope can exist briefly
        # before the bundle/index publication fails, so counting envelopes
        # here would incorrectly turn a zero-publication run into a
        # successful one.  ``functional_test`` candidates are resolved
        # outcomes for the owner's information; they are neither failures
        # nor published adversarial yield.
        generated=published,
        failed=sum(item["status"] in failures for item in outcomes),
        requested=len(outcomes),
        attempted=len(outcomes) - skipped,
        skipped=skipped,
        functional_test=functional_test,
    )
    return counts


def _scenario_generation_status(
    counts: Mapping[str, int | None],
) -> tuple[SynthesisRunStatus, str]:
    """Derive a truthful product status from candidate lifecycle counts."""
    requested = counts.get("requested")
    attempted = counts.get("attempted")
    generated = counts.get("generated")
    functional_test = counts.get("functional_test") or 0
    if None in (requested, attempted, generated):
        return (
            SynthesisRunStatus.UNKNOWN,
            "candidate_outcomes_unavailable",
        )
    resolved = (generated or 0) + functional_test
    choices = (
        (
            requested == 0,
            (SynthesisRunStatus.NO_CANDIDATES, "no_eligible_candidates"),
        ),
        (
            attempted > 0 and generated == 0 and functional_test == 0,
            (SynthesisRunStatus.FAILED, "zero_yield_after_attempts"),
        ),
        (
            resolved == requested and attempted == requested,
            (
                SynthesisRunStatus.COMPLETED,
                "all_requested_candidates_resolved",
            ),
        ),
        (
            (generated or 0) > 0,
            (SynthesisRunStatus.DEGRADED, "partial_candidate_yield"),
        ),
    )
    return next(
        (outcome for condition, outcome in choices if condition),
        (
            SynthesisRunStatus.DEGRADED,
            "requested_candidates_not_attempted",
        ),
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _dump(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _digest_payload(domain: str, value: Any) -> str:
    return compute_framed_digest(domain, _dump(value))


def _summary_dict(summary: Any) -> dict[str, int]:
    if summary is None:
        return {}
    values = _dump(summary)
    if not isinstance(values, Mapping):
        return {}
    return {
        str(key): int(value)
        for key, value in values.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def _obligation_stop_reason_counts(accounting: Any, realization: Any) -> dict[str, int]:
    """Count exactly one terminal reason for each applicable accounting row."""
    realization_reasons = _realization_reasons_by_obligation(realization)
    reasons = (
        _accounting_terminal_reason(row, realization_reasons) for row in accounting.rows
    )
    counts: dict[str, int] = {}
    for reason in reasons:
        if reason is not None:
            counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


def _realization_reasons_by_obligation(realization: Any) -> dict[str, set[str]]:
    """Index exact realization outcomes by obligation identity."""
    realization_reasons: dict[str, set[str]] = {}
    for record in realization.records:
        item = _realization_reason(record)
        if item is not None:
            obligation_id, reason = item
            realization_reasons.setdefault(obligation_id, set()).add(reason)
    return realization_reasons


def _realization_reason(record: Any) -> tuple[str, str] | None:
    """Return one complete obligation/reason pair or no index entry."""
    obligation_id = str(record.obligation_id or "")
    reason = record.stop_reason
    if not obligation_id or reason is None:
        return None
    return obligation_id, str(reason)


def _accounting_terminal_reason(
    row: Any, realization_reasons: Mapping[str, set[str]]
) -> str | None:
    """Prefer later scenario evidence over the earlier addressed marker."""
    obligation_id = str(row.obligation_id or "")
    reasons = realization_reasons.get(obligation_id, set())
    for reason in (
        "scenario_realized",
        "scenario_generation_failure",
        "scenario_not_requested",
    ):
        if reason in reasons:
            return reason
    value = row.stop_reason
    return str(value) if value is not None else None


def _obligation_resolution_funnel(
    *, plan: Any, accounting: Any, realization: Any, scenario_count: int
) -> dict[str, Any]:
    """Expose full and survivor denominators with exact reconciliation."""
    rows = tuple(accounting.rows)
    reasons = _obligation_stop_reason_counts(accounting, realization)
    applicable = _count_rows_with_value(rows, "stop_reason")
    realized_obligations = _realized_obligation_count(realization)
    return {
        "all_plan_rows": len(plan.obligations),
        "governance_only": _count_rows_with_value(
            rows, "disposition", "governance_only"
        ),
        "capability_excluded": _count_rows_with_value(
            rows, "disposition", "capability_excluded"
        ),
        "applicable_and_considered": applicable,
        "terminal_reasons": reasons,
        "terminal_reason_total": sum(reasons.values()),
        "reconciles": sum(reasons.values()) == applicable,
        "realized_obligation_denominator": realized_obligations,
        "admitted_scenario_denominator": scenario_count,
    }


def _count_rows_with_value(
    rows: tuple[Any, ...], field: str, expected: str | None = None
) -> int:
    """Count present fields or fields equal to one exact value."""
    values = (getattr(row, field) for row in rows)
    if expected is None:
        return sum(value is not None for value in values)
    return sum(value == expected for value in values)


def _realized_obligation_count(realization: Any) -> int:
    """Count distinct obligations with at least one admitted scenario."""
    return len(
        {
            str(record.obligation_id)
            for record in realization.records
            if record.stop_reason == "scenario_realized"
        }
    )


__all__ = [
    "ACCOUNTING_FILENAME",
    "CONSIDERATION_FILENAME",
    "MANIFEST_FILENAME",
    "PLAN_FILENAME",
    "REPORT_FILENAME",
    "SCENARIO_REALIZATION_FILENAME",
    "SynthesisAdapters",
    "SynthesisInputs",
    "SynthesisRunStatus",
    "SynthesisResult",
    "run_synthesis",
]
