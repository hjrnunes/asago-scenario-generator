"""Composition root for the obligation-aware STPA synthesis workflow.

Phase 1 planning, structural consideration and revision, STPA slot filling,
and ordinary scenario production are stage ports (``synthesis_types``) with
production defaults (``synthesis_defaults``).  This module owns the stage
order: it runs the stages in ``synthesis_baseline``,
``synthesis_consideration``, and ``synthesis_scenarios``, then publishes the
sidecars, the manifest, and the report (``synthesis_persist``,
``synthesis_manifest``).  It does not duplicate the domain contracts used by
those stages.

Acceptance supplies deterministic fakes for any port; the production CLI
leaves the ports unset and gets the defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
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
from asago_scenario_generator.pipeline.synthesis_governance import (
    _run_governance_routing,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _MANIFEST_DOMAIN as _MANIFEST_DOMAIN,
    _build_manifest,
    _digest_payload as _digest_payload,
    _manifest_prompt_call_evidence as _manifest_prompt_call_evidence,
    _scenario_generation_status as _scenario_generation_status,
)
from asago_scenario_generator.pipeline.synthesis_persist import (
    _artifact_paths,
    _persist_manifest,
    _persist_plan,
    _persist_prepared_profile,
    _persist_sidecar,
    _persist_slot_hazard_offers,
    _persist_target_realization,
    _reload_persisted_plan,
    _render_report,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _accounting_source_pins,
    _run_accounting,
    _run_ica,
    _run_operation_enrichment,
    _run_realization,
    _run_scenarios,
    _run_target_realization,
    _slot_hazard_offers,
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
    StageRun,
    SynthesisAdapters,
    SynthesisInputs,
    SynthesisResult,
    SynthesisRunStatus,
    _systemic_inputs,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _declared_capability_labels as _declared_capability_labels,
    _dump as _dump,
    _ica_considerations,
    _ica_verification as _ica_verification,
    _ordinary_icas as _ordinary_icas,
)
from asago_scenario_generator.stpa.infra.provider_record import provider_call_session


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
        record_dir=Path(inputs.output_dir),
        replay_dir=inputs.replay_calls_dir,
        fill=inputs.replay_fill,
    ) as session:
        return _run_synthesis(inputs, adapters, session)


@dataclass
class _RunLog:
    """The stage call records and stage errors of one run, in stage order."""

    calls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def take(self, run: StageRun) -> Any:
        """Record one stage run's calls and errors and return its value."""
        self.calls.extend(run.calls)
        self.errors.extend(run.diagnostics)
        return run.value


def _run_synthesis(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters | object | None,
    session: Any,
) -> SynthesisResult:
    """Run the fixed-order workflow; the run's model client uses *session*."""
    output_dir = Path(inputs.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = _resolve_adapters(adapters)
    if resolved.model_runtime is None:
        resolved = replace(
            resolved, model_runtime=ModelRuntime.for_inputs(inputs, session)
        )
    log = _RunLog()
    stage_warnings: list[str] = []

    capability_profile = log.take(_prepare_capability_profile(inputs, resolved))
    capability_snapshot = _prepare_snapshot(inputs, capability_profile)
    _persist_prepared_profile(output_dir, capability_profile)
    taxonomy_inputs = log.take(
        _prepare_taxonomy_inputs(
            inputs, capability_profile, capability_snapshot, resolved
        )
    )

    plan = log.take(_run_plan(taxonomy_inputs, inputs, resolved))
    plan_path = log.take(_persist_plan(output_dir, plan, resolved))
    plan = _reload_persisted_plan(plan, plan_path)

    briefs = log.take(
        _build_briefs(plan, inputs, capability_snapshot, taxonomy_inputs, resolved)
    )

    baseline = log.take(
        _run_baseline(
            inputs,
            capability_profile,
            capability_snapshot,
            taxonomy_inputs,
            plan,
            resolved,
        )
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

    initial_consideration = log.take(
        _run_consideration(
            briefs,
            plan,
            baseline_loss,
            baseline_control,
            inputs,
            capability_snapshot,
            resolved,
        )
    )
    initial_routes = tuple(initial_consideration.routes)
    applicable_briefs = tuple(
        brief for brief in briefs if brief.obligation_id in _applicable_ids(plan)
    )
    _ensure_route_universe(initial_routes, _applicable_ids(plan))
    gaps = tuple(
        route for route in initial_routes if route.disposition == "upstream_gap"
    )

    revision_result, recheck_result, final_loss, final_control, final_routes = log.take(
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
    operation_enrichment = log.take(
        _run_operation_enrichment(
            loss_analysis=final_loss,
            control_structure=final_control,
            capability_profile=capability_profile,
            inputs=inputs,
            adapters=resolved,
        )
    )
    if operation_enrichment is not None:
        final_control = operation_enrichment.control_structure
        stage_warnings.extend(
            f"control action enrichment: {warning}"
            for warning in operation_enrichment.record.diagnostics
        )

    governance = log.take(
        _run_governance_routing(
            plan=plan,
            loss_analysis=final_loss,
            control_structure=final_control,
            inputs=inputs,
            adapters=resolved,
        )
    )
    stage_warnings.extend(governance.warnings)
    governance_routes = governance.routes
    slot_briefs = (*briefs, *governance.briefs)
    slot_routes = (*final_routes, *governance_routes)

    # One adaptive analysis: enrichment (capability profile, execution target
    # profile, target observations) feeds ICA enumeration and Stage 5; it
    # never selects a different generation algorithm.
    ica_enumeration = log.take(
        _run_ica(
            slot_routes,
            slot_briefs,
            plan,
            final_loss,
            final_control,
            capability_profile,
            inputs,
            capability_snapshot,
            resolved,
        )
    )
    hazard_offers = _slot_hazard_offers(ica_enumeration)
    target_realization = log.take(
        _run_target_realization(
            ica_enumeration=ica_enumeration,
            loss_analysis=final_loss,
            control_structure=final_control,
            capability_profile=capability_profile,
            inputs=inputs,
            adapters=resolved,
            operation_enrichment=operation_enrichment,
        )
    )
    effective_control, effective_icas = _target_realized_stpa_inputs(
        target_realization=target_realization,
        loss_analysis=final_loss,
        control_structure=final_control,
        ica_enumeration=ica_enumeration,
        capability_profile=capability_profile,
    )
    scenario_result = log.take(
        _run_scenarios(
            effective_icas,
            slot_briefs,
            slot_routes,
            plan,
            final_loss,
            effective_control,
            capability_profile,
            inputs,
            capability_snapshot,
            resolved,
            target_realization=target_realization,
            operation_enrichment=operation_enrichment,
            slot_evidence=ica_enumeration,
        )
    )
    accounting = log.take(
        _run_accounting(
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
            source_pins=_accounting_source_pins(
                plan=plan,
                consideration=consideration,
                final_loss=final_loss,
                final_control=effective_control,
                ica_enumeration=effective_icas,
            ),
            slot_evidence=ica_enumeration,
            governance_routes=governance_routes,
            hazard_offers=hazard_offers,
        )
    )
    realization = log.take(
        _run_realization(
            accounting=accounting,
            ica_enumeration=ica_enumeration,
            scenario_result=scenario_result,
            adapters=resolved,
        )
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
    hazard_offers_path = _persist_slot_hazard_offers(output_dir, hazard_offers)
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
        calls=log.calls,
        revision=revision_result,
        stage_errors=log.errors,
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
        call_records=session.call_log.entries(output_dir),
        replay_fill=session.fill_summary(),
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
        hazard_offers_path=hazard_offers_path,
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
        stage_errors=log.errors,
        stage_warnings=stage_warnings,
        ica_hazard_verification=ica_enumeration.ica_hazard_verification,
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
