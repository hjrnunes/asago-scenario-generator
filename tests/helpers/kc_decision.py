"""Observed target profiles for the KC fact-decision tests."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    InventoryCompleteness,
    TargetSemanticInterpretation,
)
from tests.helpers.execution_classification import _target_profile


def kc_tool(
    name: str,
    *,
    effect: str = "read",
    state: str = "none",
    roles: tuple[str, ...] = (),
    disposition: str = "supported",
    agreement: str = "agree",
) -> TargetSemanticInterpretation:
    return TargetSemanticInterpretation(
        resource_id=f"mcp:target-1:{name}",
        tool_name=name,
        disposition=disposition,
        likely_effect=effect,
        likely_state_effect=state,
        semantic_roles=roles,
        evidence_refs=(f"inventory:tool:{name}:description",),
        rationale="fixture interpretation",
        interpreter_verifier_agreement=agreement,
    )


def kc_profile(
    *tools: TargetSemanticInterpretation,
    completeness: InventoryCompleteness = InventoryCompleteness.observed_complete,
) -> ExecutionTargetProfile:
    # The rules read only the interpretations and the completeness claim, so
    # the copy skips the inventory closure that the fixture's single tool sets.
    return _target_profile().model_copy(
        update={"interpretations": tools, "inventory_completeness": completeness}
    )
