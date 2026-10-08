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


def test_a_complete_inventory_without_state_change_rules_out_full_crud() -> None:
    decision = target_kc_decision(
        _profile(_tool("lookup"), _tool("status", effect="observe"))
    )

    assert decision.present == frozenset()
    assert decision.absent == {"KC6.3.2"}
    assert "complete" in decision.reasons["KC6.3.2"]


def test_a_possible_or_unverified_change_keeps_full_crud_open() -> None:
    for tool in (
        _tool("send", state="may_change"),
        _tool("send", state="unknown"),
        _tool("send", disposition="unresolved"),
    ):
        decision = target_kc_decision(_profile(_tool("lookup"), tool))

        assert "KC6.3.2" not in decision.absent


def test_a_verified_text_search_tool_is_a_rag_data_source() -> None:
    decision = target_kc_decision(
        _profile(_tool("policy", roles=("text_search",)), _tool("lookup"))
    )

    assert "KC6.3.3" in decision.present
    assert "policy" in decision.reasons["KC6.3.3"]


def test_an_unverified_text_search_role_decides_nothing() -> None:
    decision = target_kc_decision(
        _profile(
            _tool("policy", roles=("text_search",), agreement="unverified"),
            completeness=InventoryCompleteness.observed_partial,
        )
    )

    assert "KC6.3.3" not in decision.present | decision.absent


def test_rules_combine_into_one_decision() -> None:
    decision = target_kc_decision(
        _profile(
            _tool("policy", roles=("text_search",)),
            _tool("refund", effect="execute", state="changes"),
        )
    )

    assert decision.present == {"KC6.3.2", "KC6.3.3"}
    assert decision.absent == {"KC6.3.1"}
    assert set(decision.reasons) == {"KC6.3.1", "KC6.3.2", "KC6.3.3"}
