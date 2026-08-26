"""Adversarial coverage for attack-pattern chain invariants."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.models import attack_pattern_chain
from asago_scenario_generator.models import attack_pattern_contracts
from asago_scenario_generator.models import attack_pattern_projection


def test_conditional_step_validates_its_condition(monkeypatch) -> None:
    """A present conditional condition must reach the condition validator."""
    condition = object()
    step = SimpleNamespace(requirement="conditional", condition=condition)
    checked: list[object] = []
    monkeypatch.setattr(
        attack_pattern_chain,
        "_check_condition",
        lambda value: checked.append(value),
    )

    attack_pattern_chain._check_step_condition_agreement(step)

    assert checked == [condition]


def test_earliest_attacker_step_rejects_non_attacker_first_step() -> None:
    """The first step must be attacker-controlled even when its ID matches."""
    first = SimpleNamespace(attacker_controlled=False, step_id="step.1")
    chain = SimpleNamespace(
        steps=(first,),
        earliest_attacker_controlled_step_id="step.1",
    )

    with pytest.raises(ValueError, match="earliest attacker-controlled"):
        attack_pattern_chain._check_earliest_attacker_step(chain)


def test_nonfinal_terminal_outcome_is_rejected() -> None:
    """A terminal security outcome cannot appear before the final step."""
    outcome = SimpleNamespace(security_relevant=True, terminal=True)
    nonfinal = SimpleNamespace(observable_postconditions=(outcome,))
    final = SimpleNamespace(observable_postconditions=())

    with pytest.raises(ValueError, match="only valid on the final step"):
        attack_pattern_chain._check_nonfinal_terminal_outcomes(
            SimpleNamespace(steps=(nonfinal, final))
        )


def test_initial_ingress_must_match_declared_slot_id() -> None:
    """A sole initial-ingress slot with the wrong ID is rejected."""
    slot = SimpleNamespace(
        purpose="initial_ingress",
        slot_id="wrong",
        kind="entry_point",
    )

    with pytest.raises(ValueError, match="referenced initial ingress"):
        attack_pattern_chain._check_initial_ingress_slot(
            SimpleNamespace(
                resource_slots=(slot,),
                initial_ingress_slot_id="expected",
            )
        )


def test_source_influence_requires_a_declared_trust_boundary() -> None:
    """A non-null but absent trust-boundary ID fails at the presence check."""
    link = SimpleNamespace(trust_boundary_slot_id="missing")
    step = SimpleNamespace(step_id="step.2")

    with pytest.raises(ValueError, match="references an absent trust_boundary"):
        attack_pattern_chain._check_source_influence_boundary(
            step,
            link,
            {"source"},
            {"missing": SimpleNamespace(kind="tool")},
        )


def test_non_ingress_link_on_initial_slot_is_not_activation() -> None:
    """Only an ingress-role link can activate the initial ingress slot."""
    chain = SimpleNamespace(initial_ingress_slot_id="ingress")
    link = SimpleNamespace(role="tool_fixture", slot_id="ingress")

    assert attack_pattern_chain._is_ingress_activation(chain, link) is False


def _patch_condition_tree_helpers(monkeypatch) -> None:
    """Use simple nodes to exercise structural-limit boundaries directly."""
    monkeypatch.setattr(
        attack_pattern_contracts,
        "_condition_children",
        lambda node: node.children,
    )
    monkeypatch.setattr(
        attack_pattern_contracts,
        "_check_duplicate_operands",
        lambda children: None,
    )


def test_condition_node_limit_counts_every_node(monkeypatch) -> None:
    """A tree with one node beyond the limit must be rejected."""
    _patch_condition_tree_helpers(monkeypatch)
    root = SimpleNamespace(
        children=tuple(
            SimpleNamespace(children=())
            for _ in range(attack_pattern_contracts.MAX_CONDITION_NODES)
        )
    )

    with pytest.raises(ValueError, match="structural limits"):
        attack_pattern_contracts._check_condition(root)


def test_condition_node_limit_allows_exact_boundary(monkeypatch) -> None:
    """Exactly the maximum number of nodes remains valid."""
    _patch_condition_tree_helpers(monkeypatch)
    root = SimpleNamespace(
        children=tuple(
            SimpleNamespace(children=())
            for _ in range(attack_pattern_contracts.MAX_CONDITION_NODES - 1)
        )
    )

    attack_pattern_contracts._check_condition(root)


def test_condition_depth_limit_starts_at_one(monkeypatch) -> None:
    """The root condition consumes the first allowed depth level."""
    _patch_condition_tree_helpers(monkeypatch)
    leaf = SimpleNamespace(children=())
    node = leaf
    for _ in range(attack_pattern_contracts.MAX_CONDITION_DEPTH):
        node = SimpleNamespace(children=(node,))

    with pytest.raises(ValueError, match="structural limits"):
        attack_pattern_contracts._check_condition(node)


def test_partition_rejects_duplicates_in_either_side() -> None:
    """Selected and omitted partitions must each be unique independently."""
    with pytest.raises(ValueError, match="must be unique"):
        attack_pattern_projection._check_partition_ids_unique(
            ["step.1", "step.1"],
            ["step.2"],
        )


def test_partition_rejects_overlap_even_when_union_is_complete() -> None:
    """Selected and omitted sets must be disjoint as well as complete."""
    with pytest.raises(ValueError, match="exactly partition"):
        attack_pattern_projection._check_partition_exact(
            ["step.1"],
            ["step.1"],
            ["step.1"],
        )


def test_ingress_binding_rejects_wrong_reference_type() -> None:
    """The sole initial-ingress binding must be typed as an entry point."""
    binding = SimpleNamespace(
        slot_id="ingress",
        resource_ref=SimpleNamespace(kind="tool"),
    )

    with pytest.raises(ValueError, match="entry-point canonical"):
        attack_pattern_projection._check_ingress_binding((binding,), "ingress")


def test_terminal_step_must_be_selected() -> None:
    """Selecting an earlier step cannot satisfy terminal selection."""
    chain = SimpleNamespace(
        steps=(
            SimpleNamespace(step_id="step.1"),
            SimpleNamespace(step_id="step.2"),
        )
    )

    with pytest.raises(ValueError, match="terminal final step"):
        attack_pattern_projection._check_terminal_selected(chain, ["step.1"])
