"""KC sub-codes that an observed target profile decides."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    InventoryCompleteness,
    TargetSemanticInterpretation,
)
from asago_scenario_generator.stpa.system_model.kc_decision import (
    target_kc_decision,
)
from tests.helpers.execution_classification import _target_profile


def _tool(
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


def _profile(
    *tools: TargetSemanticInterpretation,
    completeness: InventoryCompleteness = InventoryCompleteness.observed_complete,
) -> ExecutionTargetProfile:
    # The rules read only the interpretations and the completeness claim, so
    # the copy skips the inventory closure that the fixture's single tool sets.
    return _target_profile().model_copy(
        update={"interpretations": tools, "inventory_completeness": completeness}
    )


def test_no_profile_decides_nothing() -> None:
    decision = target_kc_decision(None)

    assert (decision.present, decision.absent) == (frozenset(), frozenset())


def test_a_verified_state_change_makes_data_access_full_crud() -> None:
    decision = target_kc_decision(
        _profile(_tool("lookup"), _tool("refund", effect="execute", state="changes"))
    )

    assert decision.present == {"KC6.3.2"}
    assert decision.absent == {"KC6.3.1"}
    assert "refund" in decision.reasons["KC6.3.2"]
    assert "refund" in decision.reasons["KC6.3.1"]


def test_an_unverified_state_change_decides_nothing() -> None:
    for tool in (
        _tool("refund", state="changes", agreement="disagree"),
        _tool("refund", state="changes", disposition="ambiguous"),
        _tool("refund", state="may_change"),
    ):
        decision = target_kc_decision(
            _profile(tool, completeness=InventoryCompleteness.observed_partial)
        )

        assert (decision.present, decision.absent) == (frozenset(), frozenset())
