"""The digest-bound synthesis manifest, built from the stage values.

The manifest also reads the call records that the run's provider-call session
holds; ``calls.jsonl`` is the same records written to the output directory.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.pipeline.synthesis_types import (
    SynthesisInputs,
    SynthesisRunStatus,
)
from asago_scenario_generator.pipeline.synthesis_values import _digest_value, _dump
from asago_scenario_generator.stpa.models.control_structure import (
    MAX_CONTEXT_ROWS_PER_ACTION,
    ControlStructure,
    control_structure_context_tables,
)


_MANIFEST_SCHEMA = "stpa-synthesis-manifest-v2"


# The domain also frames every artifact digest (``_manifest_artifact_identity``),
# so it keeps ``v1`` when the manifest schema label moves.
_MANIFEST_DOMAIN = "asago-scenario-generator:stpa-synthesis-manifest:v1"


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
    call_records: list[dict[str, Any]] | None = None,
    replay_fill: Mapping[str, Any] | None = None,
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
    )
    scenario_counts = _manifest_scenario_counts(scenario_result, len(scenarios))
    run_status, run_status_reason = _scenario_generation_status(scenario_counts)
    payload: dict[str, Any] = {
        "schema_version": _MANIFEST_SCHEMA,
        "run_id": f"synthesis-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "created_at": datetime.now(UTC).isoformat(),
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
        "model_controls": {
            "profile": inputs.profile,
            "max_workers": inputs.max_workers,
        },
        "stage_call_counts": {name: calls.count(name) for name in sorted(set(calls))},
        "provider_evidence": _manifest_provider_evidence(provider_stages or {}, inputs),
        "prompt_call_evidence": _manifest_prompt_call_evidence(call_records),
        "total_prompt_tokens": _total_prompt_tokens(call_records),
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
    }
    payload.update(_replay_fill_block(replay_fill))
    payload["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, payload)
    return payload


def _replay_fill_block(replay_fill: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the manifest block of a replay-fill run, empty for any other run.

    Only a replay-fill run mixes recorded and live requests; every other run's
    manifest keeps its shape so replays compare byte for byte.
    """
    if replay_fill is None:
        return {}
    return {"provider_replay_fill": dict(replay_fill)}


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


def _total_prompt_tokens(call_records: list[dict[str, Any]] | None) -> int | None:
    """Sum recorded prompt tokens for the budget check."""
    if call_records is None:
        return None
    return sum(int(entry.get("prompt_tokens") or 0) for entry in call_records)


def _manifest_prompt_call_evidence(
    call_records: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Copy compact prompt-budget and provider-usage evidence into the manifest."""
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
    for source in call_records or ():
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
) -> dict[str, dict[str, str]]:
    """Build the complete source identity inventory for the run manifest."""
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
        requests_sent = sum(int(item.attempt_count) for item in evidence)
        result[stage_name] = {
            "call_count": requests_sent,
            "records": records,
            "controls": controls,
        }
        lost_slots = getattr(stages[stage_name], "lost_slots", ())
        if lost_slots:
            result[stage_name]["lost_slots"] = [_dump(item) for item in lost_slots]
        verification = getattr(stages[stage_name], "ica_hazard_verification", None)
        if verification is not None:
            result[stage_name]["ica_hazard_verification"] = _dump(verification)
    return result


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
    """Count exactly one terminal reason for each applicable accounting row.

    Governance-only rows are not applicable obligations: a credited row has no
    stop reason, and a routed row without a finding is counted apart.
    """
    realization_reasons = _realization_reasons_by_obligation(realization)
    reasons = (
        _accounting_terminal_reason(row, realization_reasons)
        for row in _considered_rows(accounting.rows)
    )
    counts: dict[str, int] = {}
    for reason in reasons:
        if reason is not None:
            counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


def _considered_rows(rows: Iterable[Any]) -> tuple[Any, ...]:
    """Select the applicable rows that carry a stop reason."""
    return tuple(
        row
        for row in rows
        if row.stop_reason is not None
        and getattr(row, "disposition", None) != "governance_only"
    )


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
        "scenario_functional_test",
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
    applicable = len(_considered_rows(rows))
    realized_obligations = _realized_obligation_count(realization)
    funnel: dict[str, Any] = {
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
    credited = {row.obligation_id for row in rows if _governance_credited(row)}
    if credited:
        funnel["governance_credited"] = len(credited)
        funnel["governance_realized"] = len(
            credited & _realized_obligation_ids(realization)
        )
    routed = _count_rows_with_value(rows, "stop_reason", "governance_routed_no_finding")
    if routed:
        funnel["governance_routed_no_finding"] = routed
    return funnel


def _governance_credited(row: Any) -> bool:
    """Tell whether a governance-only row carries an STPA finding."""
    return row.disposition == "governance_only" and bool(getattr(row, "ica_ids", ()))


def _count_rows_with_value(
    rows: tuple[Any, ...], field: str, expected: str | None = None
) -> int:
    """Count present fields or fields equal to one exact value."""
    values = (getattr(row, field) for row in rows)
    if expected is None:
        return sum(value is not None for value in values)
    return sum(value == expected for value in values)


def _realized_obligation_ids(realization: Any) -> set[str]:
    """Collect the obligations with at least one admitted scenario."""
    return {
        str(record.obligation_id)
        for record in realization.records
        if record.stop_reason == "scenario_realized"
    }


def _realized_obligation_count(realization: Any) -> int:
    """Count distinct obligations with at least one admitted scenario."""
    return len(_realized_obligation_ids(realization))
