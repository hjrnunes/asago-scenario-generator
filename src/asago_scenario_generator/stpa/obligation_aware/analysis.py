"""Bounded orchestration for obligation-aware structural STPA analysis."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
from asago_scenario_generator.models.obligation_consideration import (
    BoundedStructuralRevision,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationConsideration,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
)
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


def _structure_pin(artifact_id: str, schema_version: str, value: Any) -> ArtifactPin:
    """Build a deterministic pin for an in-memory STPA authority value."""
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=compute_framed_digest(
            f"asago-scenario-generator:{artifact_id}:v1",
            value.model_dump(mode="json"),
        ),
    )


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

    def bounded_revision(
        self,
        *,
        plan: TaxonomyObligationPlan | None = None,
        source_pins: Sequence[ArtifactPin] = (),
    ) -> BoundedStructuralRevision:
        """Convert the provider-local revision result to the shared record."""
        if plan is not None:
            plan_pin = ArtifactPin(
                artifact_id="taxonomy-obligation-plan",
                schema_version="taxonomy-obligation-plan-v1",
                semantic_digest=plan.semantic_digest,
            )
        else:
            plan_pin = None
        baseline_pins = (
            *source_pins,
            *(() if plan_pin is None else (plan_pin,)),
            _structure_pin(
                "stpa-loss-analysis",
                "stpa-loss-analysis-v1",
                self.baseline_loss_analysis,
            ),
            _structure_pin(
                "stpa-control-structure",
                "stpa-control-structure-v1",
                self.baseline_control_structure,
            ),
        )
        status = self.revision.status
        proposed = self.revision.delta
        rejected_additions = (
            () if status != "rejected" or proposed is None else proposed.additions
        )
        revised_pins: tuple[ArtifactPin, ...] = ()
        if status == "applied":
            revised_pins = (
                _structure_pin(
                    "stpa-loss-analysis",
                    "stpa-loss-analysis-v1",
                    self.final_loss_analysis,
                ),
                _structure_pin(
                    "stpa-control-structure",
                    "stpa-control-structure-v1",
                    self.final_control_structure,
                ),
            )
        return BoundedStructuralRevision(
            status=status,
            baseline_pins=baseline_pins,
            trigger_obligation_ids=self.revision.trigger_obligation_ids,
            trigger_gap_ids=self.revision.trigger_gap_ids,
            proposed_delta=proposed,
            accepted_delta=proposed if status == "applied" else None,
            rejected_additions=rejected_additions,
            revised_pins=revised_pins,
            call_evidence=()
            if self.revision.call_evidence is None
            else (self.revision.call_evidence,),
        )

    def to_consideration_artifact(
        self,
        *,
        plan: TaxonomyObligationPlan,
        source_pins: Iterable[ArtifactPin] = (),
    ) -> ObligationConsideration:
        """Build and validate the shared inward consideration artifact."""
        return build_consideration_artifact(
            plan=plan,
            briefs=self.briefs,
            initial_routes=self.initial.routes,
            final_routes=self.final_routes,
            revision=self.bounded_revision(plan=plan, source_pins=tuple(source_pins)),
            rechecked_routes=self.rechecked_routes,
            source_pins=tuple(source_pins),
            diagnostics=self.diagnostics,
        )


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


# Descriptive aliases for callers that name the stage directly.
run_obligation_aware_analysis = analyze_obligations
run_structural_consideration = analyze_obligations


__all__ = [
    "ObligationAwareAnalysisResult",
    "analyze_obligations",
    "run_obligation_aware_analysis",
    "run_structural_consideration",
]
