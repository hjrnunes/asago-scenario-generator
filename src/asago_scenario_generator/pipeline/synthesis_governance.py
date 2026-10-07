"""Synthesis stage that routes governance-only risks onto control actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.pipeline.governance_rows import (
    GovernanceSelection,
    select_governance_risks,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_governance_briefs,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    StageRun,
    SynthesisAdapters,
    SynthesisInputs,
    _systemic_inputs,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernanceRoutingResult,
)


@dataclass(frozen=True)
class GovernanceStage:
    """What the governance stage selected, routed, and could not route."""

    selection: GovernanceSelection = field(default_factory=GovernanceSelection)
    result: GovernanceRoutingResult = field(default_factory=GovernanceRoutingResult)
    failure: str | None = None

    @property
    def warnings(self) -> tuple[str, ...]:
        """One summary line plus every retained validation diagnostic."""
        selection = self.selection
        if not selection.risk_ids:
            return ()
        result = self.result
        summary = (
            f"governance routing: {len(selection.risk_ids)} routable, "
            f"{len(result.routes)} routed, {len(result.declined)} declined, "
            f"{len(result.unresolved)} unresolved, "
            f"{len(selection.skipped)} not routable"
        )
        failure = (
            (f"governance routing failed: {self.failure}",) if self.failure else ()
        )
        return (summary, *failure, *result.diagnostics)


def _run_governance_routing(
    *,
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Route the cited governance-only risks; a failure never stops the run."""
    selection = select_governance_risks(plan, loss_analysis)
    if not selection.risk_ids or adapters.govern is None:
        return StageRun(GovernanceStage(selection))
    briefs = build_governance_briefs(plan, selection.risk_ids)
    try:
        result = adapters.govern(
            briefs=briefs,
            paths=selection.paths,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            inputs=_systemic_inputs(inputs),
            obligation_adapter=adapters.obligation_adapter,
            output_dir=inputs.output_dir,
        )
    except Exception as exc:  # noqa: BLE001 - an additive stage must not end the run
        return StageRun(GovernanceStage(selection, failure=str(exc)))
    if result is None:
        return StageRun(GovernanceStage(selection))
    calls = ("governance_routing",) if result.requests else ()
    return StageRun(GovernanceStage(selection, result), calls=calls)
