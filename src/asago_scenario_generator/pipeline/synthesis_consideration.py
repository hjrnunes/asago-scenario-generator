"""Synthesis stages between the baseline and the final ICAs.

The initial consideration pass, the one bounded structural revision and its
recheck, and the closure of those provider-local results into the durable
obligation-consideration artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.synthesis_types import (
    SynthesisAdapters,
    SynthesisInputs,
    _systemic_inputs,
)


def _run_consideration(
    briefs: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
) -> Any:
    """Run the initial complete structural consideration pass."""
    if adapters.consider is None:
        raise ValueError("synthesis has no obligation consideration adapter")
    result = adapters.consider(
        briefs=briefs,
        plan=plan,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=_systemic_inputs(inputs),
        capability_snapshot=snapshot,
        obligation_adapter=adapters.obligation_adapter,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
    )
    calls.append("consider")
    return result


def _run_revision(
    gaps: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    calls: list[str],
    stage_errors: list[str],
) -> Any:
    """Attempt the one bounded additive structural revision."""
    trigger_ids, gap_ids = _revision_trigger_metadata(gaps)
    if adapters.revise is None:
        stage_errors.append("upstream gaps retained: no structural revision adapter")
        return _LocalRevisionOutcome("technical_failure", trigger_ids, gap_ids)
    try:
        result = adapters.revise(
            gaps=gaps,
            plan=plan,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            inputs=_systemic_inputs(inputs),
            capability_snapshot=snapshot,
            obligation_adapter=adapters.obligation_adapter,
            output_dir=inputs.output_dir,
        )
    except Exception as exc:  # noqa: BLE001 - retained local revision outcome
        stage_errors.append(f"structural revision failed: {exc}")
        result = _LocalRevisionOutcome("technical_failure", trigger_ids, gap_ids)
    calls.append("revision")
    return result or _LocalRevisionOutcome("rejected", trigger_ids, gap_ids)


@dataclass(frozen=True)
class _LocalRevisionOutcome:
    """A revision outcome decided without a revision result.

    It covers no gaps, no revision adapter, a failed call, and an empty
    result, and carries ``RevisionRunResult``'s evidence fields empty so every
    reader sees one shape.
    """

    status: str
    trigger_obligation_ids: tuple[str, ...] = ()
    trigger_gap_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    request: Any = None
    response: Any = None
    delta: Any = None
    call_evidence: Any = None


def _revision_trigger_metadata(
    gaps: tuple[Any, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Retain exact trigger identities when a revision adapter fails locally."""
    obligation_ids = tuple(
        sorted(
            {
                str(identifier)
                for value in gaps
                if (identifier := value.obligation_id) is not None
            }
        )
    )
    gap_ids: set[str] = set()
    for value in gaps:
        concepts = (value,) if hasattr(value, "gap_id") else value.missing_concepts
        for concept in concepts:
            if concept.gap_id is not None:
                gap_ids.add(str(concept.gap_id))
    return obligation_ids, tuple(sorted(gap_ids))


def _run_bounded_revision(
    gaps: tuple[Any, ...],
    initial_routes: tuple[Any, ...],
    applicable_briefs: tuple[Any, ...],
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
    inputs: SynthesisInputs,
    capability_snapshot: Any,
    resolved: SynthesisAdapters,
    calls: list[str],
    stage_errors: list[str],
) -> tuple[Any, Any | None, Any, Any, tuple[Any, ...]]:
    """Run at most one structural revision and its recheck for route gaps.

    Returns the revision result, the recheck result (or None), the final loss
    analysis and control structure, and the final routes.
    """
    final_loss = baseline_loss
    final_control = baseline_control
    revision_result: Any = _LocalRevisionOutcome("not_required")
    recheck_result: Any | None = None
    final_routes = initial_routes

    # One adaptive analysis: no supplied input selects a different generation
    # algorithm, so there is no mode branch here. Obligation-gap structural
    # revision always runs; the observed target never suppresses it.
    if not gaps:
        return revision_result, recheck_result, final_loss, final_control, final_routes
    revision_result = _run_revision(
        gaps,
        plan,
        baseline_loss,
        baseline_control,
        inputs,
        capability_snapshot,
        resolved,
        calls,
        stage_errors,
    )
    # Only an explicitly applied revision changes the authoritative
    # structure. Rejected and technical outcomes retain the baseline and
    # original upstream-gap routes; they do not receive a second pass.
    revision_applied = revision_result.status == "applied"
    if revision_applied:
        final_loss = revision_result.final_loss_analysis or baseline_loss
        final_control = revision_result.final_control_structure or baseline_control

    if revision_applied and resolved.recheck is not None:
        rechecked = resolved.recheck(
            briefs=applicable_briefs,
            plan=plan,
            loss_analysis=final_loss,
            control_structure=final_control,
            revision=revision_result,
            inputs=_systemic_inputs(inputs),
            capability_snapshot=capability_snapshot,
            obligation_adapter=resolved.obligation_adapter,
            output_dir=inputs.output_dir,
        )
        calls.append("recheck")
        recheck_result = rechecked
        final_routes = tuple(rechecked.routes)
    return revision_result, recheck_result, final_loss, final_control, final_routes


def _applicable_ids(plan: TaxonomyObligationPlan) -> set[str]:
    return {
        row.obligation_id
        for row in plan.obligations
        if row.scope_disposition == "applicable"
    }


def _ensure_route_universe(routes: tuple[Any, ...], applicable: set[str]) -> None:
    actual = [route.obligation_id for route in routes]
    if set(actual) != applicable or len(actual) != len(set(actual)):
        missing = sorted(applicable - set(actual))
        extra = sorted(set(actual) - applicable)
        raise ValueError(
            "final obligation route universe does not match Phase 1: "
            f"missing={missing} extra={extra}"
        )


def _close_consideration_artifact(
    *,
    plan: Any,
    briefs: tuple[Any, ...],
    initial: Any,
    recheck: Any | None,
    final_routes: tuple[Any, ...],
    revision: Any,
    baseline_loss: Any,
    baseline_control: Any,
    final_loss: Any,
    final_control: Any,
) -> Any:
    """Close the real routing passes into the shared consideration model.

    The routing and revision workers deliberately return provider-local run
    envelopes.  Accounting accepts only the durable
    ``ObligationConsideration`` contract, so the composition root performs
    this conversion once after the final route universe is known.
    """
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_consideration_artifact,
    )

    initial_routes = _typed_consideration_routes(briefs, initial, final_routes)
    revision_record = _closed_revision(
        revision,
        plan=plan,
        baseline_loss=baseline_loss,
        baseline_control=baseline_control,
        final_loss=final_loss,
        final_control=final_control,
    )
    diagnostics = _consideration_diagnostics(briefs, initial, recheck)
    rechecked = final_routes if revision_record.status == "applied" else ()
    return build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=initial_routes,
        final_routes=final_routes,
        revision=revision_record,
        rechecked_routes=rechecked,
        diagnostics=diagnostics,
    )


def _typed_consideration_routes(
    briefs: tuple[Any, ...],
    initial: Any,
    final_routes: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Require typed briefs and routes; return the initial routes as a tuple."""
    from asago_scenario_generator.models.obligation_consideration import (
        NeutralObligationBrief,
        ObligationRoute,
    )

    if any(not isinstance(item, NeutralObligationBrief) for item in briefs):
        raise TypeError("typed Phase 1 plans require typed neutral obligation briefs")
    initial_routes = tuple(initial.routes)
    if any(not isinstance(item, ObligationRoute) for item in initial_routes):
        raise TypeError("typed Phase 1 plans require typed initial obligation routes")
    if any(not isinstance(item, ObligationRoute) for item in final_routes):
        raise TypeError("typed Phase 1 plans require typed final obligation routes")
    return initial_routes


def _consideration_diagnostics(
    briefs: tuple[Any, ...],
    initial: Any,
    recheck: Any | None,
) -> list[Any]:
    """Collect routing then recheck diagnostics as typed diagnostic records.

    An untyped detail becomes a ``<source>_diagnostic`` record that names
    every briefed obligation.
    """
    from asago_scenario_generator.models.obligation_consideration import (
        ConsiderationDiagnostic,
    )

    diagnostics: list[ConsiderationDiagnostic] = []
    for source, values in (
        ("routing", initial.diagnostics),
        ("recheck", () if recheck is None else recheck.diagnostics),
    ):
        for detail in values:
            if isinstance(detail, ConsiderationDiagnostic):
                diagnostics.append(detail)
            else:
                diagnostics.append(
                    ConsiderationDiagnostic(
                        code=f"{source}_diagnostic",
                        detail=str(detail),
                        obligation_ids=tuple(item.obligation_id for item in briefs),
                    )
                )
    return diagnostics


def _revision_structure_pin(
    artifact_id: str,
    schema_version: str,
    value: Any,
) -> Any:
    """Pin one mutable STPA structure at the revision boundary."""
    from asago_scenario_generator.models.canonical import compute_framed_digest
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=compute_framed_digest(
            f"asago-scenario-generator:{artifact_id}:v1",
            value.model_dump(mode="json"),
        ),
    )


def _revision_trigger_ids(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Read the two identity sets required by a closed revision."""
    trigger_ids = tuple(map(str, value.trigger_obligation_ids))
    trigger_gap_ids = tuple(map(str, value.trigger_gap_ids))
    if not trigger_ids or not trigger_gap_ids:
        # A provider-local technical failure may not carry typed gap IDs.  It
        # cannot be represented as a closed revision without inventing
        # authority, so fail closed before accounting.
        raise ValueError("typed revision outcome is missing trigger obligation/gap IDs")
    return trigger_ids, trigger_gap_ids


def _revision_baseline_pins(
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
) -> tuple[Any, ...]:
    """Pin Phase 1 and the pre-revision STPA structures."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    return (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        _revision_structure_pin(
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            baseline_loss,
        ),
        _revision_structure_pin(
            "stpa-control-structure",
            "stpa-control-structure-v1",
            baseline_control,
        ),
    )


def _revision_revised_pins(
    status: str,
    delta: Any,
    final_loss: Any,
    final_control: Any,
) -> tuple[Any, ...]:
    """Return post-revision pins and enforce the applied-delta invariant."""
    if status != "applied":
        return ()
    if delta is None:
        raise ValueError("applied typed revision has no structural delta")
    return (
        _revision_structure_pin(
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            final_loss,
        ),
        _revision_structure_pin(
            "stpa-control-structure",
            "stpa-control-structure-v1",
            final_control,
        ),
    )


def _closed_revision(
    value: Any,
    *,
    plan: Any,
    baseline_loss: Any,
    baseline_control: Any,
    final_loss: Any,
    final_control: Any,
) -> Any:
    """Map the typed revision worker result to its durable revision record."""
    from asago_scenario_generator.models.obligation_consideration import (
        BoundedStructuralRevision,
        StructuralRevisionDelta,
    )

    if isinstance(value, BoundedStructuralRevision):
        return value
    status = value.status
    if status == "not_required":
        return BoundedStructuralRevision()
    trigger_ids, trigger_gap_ids = _revision_trigger_ids(value)
    delta = value.delta
    if delta is not None and not isinstance(delta, StructuralRevisionDelta):
        delta = None
    call = value.call_evidence
    return BoundedStructuralRevision(
        status=status,
        baseline_pins=_revision_baseline_pins(plan, baseline_loss, baseline_control),
        trigger_obligation_ids=trigger_ids,
        trigger_gap_ids=trigger_gap_ids,
        proposed_delta=delta,
        accepted_delta=delta if status == "applied" else None,
        rejected_additions=()
        if status == "applied" or delta is None
        else tuple(delta.additions),
        revised_pins=_revision_revised_pins(
            status,
            delta,
            final_loss,
            final_control,
        ),
        call_evidence=() if call is None else (call,),
    )
