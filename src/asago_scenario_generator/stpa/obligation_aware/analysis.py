"""Bounded orchestration for obligation-aware structural STPA analysis."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.revision import (
    RevisionRunResult,
    revise_structure_once,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    RoutingRunResult,
    build_neutral_briefs,
    recheck_obligations,
    route_obligations,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder


@dataclass(frozen=True, slots=True)
class ObligationAwareAnalysisResult:
    """Complete bounded structural analysis result before ICA slot filling."""

    briefs: tuple[NeutralObligationBrief, ...]
    initial: RoutingRunResult
    revision: RevisionRunResult
    recheck: RoutingRunResult | None
    final_routes: tuple[ObligationRoute, ...]
    baseline_loss_analysis: LossAnalysis
    baseline_control_structure: ControlStructure
    final_loss_analysis: LossAnalysis
    final_control_structure: ControlStructure
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @property
    def initial_routes(self) -> tuple[ObligationRoute, ...]:
        """Expose the initial canonical route set."""
        return self.initial.routes

    @property
    def rechecked_routes(self) -> tuple[ObligationRoute, ...]:
        """Expose the complete post-revision route set, if any."""
        return () if self.recheck is None else self.recheck.routes


def analyze_obligations(
    adapter: Any,
    *,
    plan: TaxonomyObligationPlan | None = None,
    attack_pattern_catalog: Sequence[Any] | dict[str, Any] | None = None,
    briefs: Sequence[NeutralObligationBrief] | None = None,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] | None = None,
    controls: AnalysisControls | None = None,
    max_batch_size: int | None = None,
) -> ObligationAwareAnalysisResult:
    """Run initial routing, at most one revision, and one complete recheck.

    If any initial route reports an upstream gap, all gaps are sent together
    in one revision request.  An applied revision always re-routes every
    applicable brief exactly once against the resulting final structure,
    including briefs that were not initial gap triggers.
    """
    if briefs is None:
        if plan is None or attack_pattern_catalog is None:
            raise TypeError(
                "plan and attack_pattern_catalog are required when briefs are omitted"
            )
        briefs_tuple = build_neutral_briefs(plan, attack_pattern_catalog)
    else:
        briefs_tuple = tuple(sorted(briefs, key=lambda item: item.obligation_id))
    baseline_la = loss_analysis.model_copy(deep=True)
    baseline_cs = control_structure.model_copy(deep=True)
    initial = route_obligations(
        adapter,
        briefs=briefs_tuple,
        loss_analysis=baseline_la,
        control_structure=baseline_cs,
        slots=slots,
        controls=controls,
        max_batch_size=max_batch_size,
        purpose="initial",
    )
    gap_concepts = tuple(
        concept
        for route in initial.routes
        if route.disposition == "upstream_gap"
        for concept in route.missing_concepts
    )
    trigger_ids = tuple(
        route.obligation_id
        for route in initial.routes
        if route.disposition == "upstream_gap"
    )
    revision = revise_structure_once(
        adapter,
        gaps=gap_concepts,
        trigger_obligation_ids=trigger_ids,
        loss_analysis=baseline_la,
        control_structure=baseline_cs,
        controls=controls,
        plan_digest=None if plan is None else plan.semantic_digest,
    )
    if revision.status == "applied":
        final_slots = None
        if slots is not None:
            # Caller-provided placeholders are tied to the old structure;
            # rebuild the final deterministic universe after additions.
            final_slots = None
        recheck = recheck_obligations(
            adapter,
            briefs=briefs_tuple,
            loss_analysis=revision.final_loss_analysis,
            control_structure=revision.final_control_structure,
            slots=final_slots,
            controls=controls,
            max_batch_size=max_batch_size,
        )
        final_routes = recheck.routes
    else:
        recheck = None
        final_routes = initial.routes
    diagnostics = tuple(
        ConsiderationDiagnostic(
            code="routing_diagnostic",
            detail=detail,
            obligation_ids=tuple(item.obligation_id for item in briefs_tuple),
        )
        for detail in (*initial.diagnostics, *revision.diagnostics)
    )
    return ObligationAwareAnalysisResult(
        briefs=briefs_tuple,
        initial=initial,
        revision=revision,
        recheck=recheck,
        final_routes=final_routes,
        baseline_loss_analysis=baseline_la,
        baseline_control_structure=baseline_cs,
        final_loss_analysis=revision.final_loss_analysis,
        final_control_structure=revision.final_control_structure,
        diagnostics=diagnostics,
    )


run_structural_consideration = analyze_obligations


__all__ = [
    "ObligationAwareAnalysisResult",
    "analyze_obligations",
    "run_structural_consideration",
]
