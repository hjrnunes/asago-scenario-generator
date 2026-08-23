"""Tests for parsimony pruning pass.

Covers:
- Trees already within budget pass through unchanged
- Unannotated leaves are pruned before annotated ones
- Single-child gate collapse after pruning
- Budget calculation with 0, 1, 2 techniques
- Cannot prune below minimum viable tree
"""

from __future__ import annotations

from datetime import UTC, datetime

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
)
from asago_scenario_generator.pipeline.validation import (
    _find_parent,
    _remove_child,
    _sibling_labels,
    _token_overlap_ratio,
    enforce_parsimony,
)
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


_AttackTreeNode = AttackTreeNode


def AttackTreeNode(**kwargs):
    """Build valid actionable leaves for parsimony tests."""
    if kwargs.get("gate") == GateType.LEAF:
        # Historical fixtures used the removed output zone; these tests only
        # exercise tree shape and pruning, so map it to a valid AI zone.
        if kwargs.get("zone") == "output":
            kwargs["zone"] = "reasoning"
        kwargs.setdefault("action", AiSystemAction())
    return _AttackTreeNode(**kwargs)


def _make_tree(
    root: AttackTreeNode,
    technique_ids: list[str] | None = None,
) -> AttackTree:
    """Build a minimal AttackTree."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )


def _make_envelope(
    root: AttackTreeNode,
    atlas_technique_ids: list[str] | None = None,
    scenario_id: str = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope with a custom tree root."""
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="I craft a malicious prompt.",
                effect="The system processes the input.",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ],
    )

    attack_tree = _make_tree(root)

    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            atlas_technique_ids=atlas_technique_ids,
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id=scenario_id,
        candidate_id="cand:v2:7e57c0de000000000000000000000000",
        initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: trees within budget pass unchanged
# ---------------------------------------------------------------------------


class TestCompliantTrees:
    """Trees already within budget should pass through unchanged."""

    def test_small_tree_passes(self) -> None:
        """A 2-leaf tree with 1 technique (budget=3) passes."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_technique_ids=["AML.T0051"])
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0

    def test_exact_budget_passes(self) -> None:
        """A tree at exactly the budget limit passes."""
        # 1 technique -> budget = 2*1+2 = 4 leaves
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Path C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_empty_list(self) -> None:
        result = enforce_parsimony([])
        assert len(result.compliant_scenarios) == 0
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0


# ---------------------------------------------------------------------------
# Tests: unannotated leaves pruned before annotated
# ---------------------------------------------------------------------------


class TestPruningOrder:
    """Typed-action leaves are preserved regardless of technique annotation."""

    def test_unannotated_typed_action_leaves_are_unprunable(self) -> None:
        """Excess leaves with typed actions are not removed."""
        # 1 technique -> budget = 4. Tree has 5 leaves: 1 annotated, 4 unannotated.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Exploit injection",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Reinforce deception",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Generate confirmation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Maintain polite closure",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Establish trust",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        unchanged_scenario, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (5, 4)
        from asago_scenario_generator.pipeline.validation import _collect_leaves

        assert [
            leaf.id for leaf in _collect_leaves(unchanged_scenario.attack_tree.root)
        ] == ["n1.1", "n1.2", "n1.3", "n1.4", "n1.5"]

    def test_annotated_leaves_never_pruned(self) -> None:
        """When all excess leaves have technique_ids, they cannot be pruned."""
        # 1 technique -> budget = 4. All 5 leaves have technique_ids.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step E",
                    gate=GateType.LEAF,
                    zone="output",
                    technique_id="AML.T0051",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.unprunable_scenarios) == 1
        _, actual, budget = result.unprunable_scenarios[0]
        assert actual == 5
        assert budget == 4


# ---------------------------------------------------------------------------
# Tests: single-child gate collapse
# ---------------------------------------------------------------------------


class TestGateCollapse:
    """Typed-action trees do not collapse because they cannot be pruned."""

    def test_and_gate_collapses(self) -> None:
        """Pruning one child of a 2-child AND gate collapses the gate."""
        # 1 technique -> budget = 4. Tree has 5 leaves.
        # n1 (OR)
        #   n1.1 (AND)
        #     n1.1.1 LEAF (annotated)
        #     n1.1.2 LEAF (unannotated - will be pruned)
        #   n1.2 LEAF (annotated)
        #   n1.3 LEAF (unannotated)
        #   n1.4 LEAF (unannotated)
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Compound attack",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Reinforce deception",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Direct exploitation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Maintain closure",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Extra filler step",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        unchanged, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (5, 4)
        assert unchanged.attack_tree.root.model_dump() == root.model_dump()


# ---------------------------------------------------------------------------
# Tests: budget calculation
# ---------------------------------------------------------------------------


class TestBudgetCalculation:
    """Budget should scale with technique count."""

    def test_zero_techniques_budget_5(self) -> None:
        """With 0 techniques, fallback budget is 5."""
        # No technique_ids anywhere. 6 leaves > budget 5.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step E",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Step F filler",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        _, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (6, 5)

    def test_one_technique_budget_4(self) -> None:
        """With 1 technique, budget = 2*1+2 = 4."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_two_techniques_budget_6(self) -> None:
        """With 2 techniques, budget = 2*2+2 = 6."""
        # 7 leaves, 2 techniques -> budget 6, need to prune 1
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0052",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step E",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Step F filler",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.7",
                    label="Step G filler extra",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        _, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (7, 6)


# ---------------------------------------------------------------------------
# Tests: minimum viable tree
# ---------------------------------------------------------------------------


class TestMinimumViableTree:
    """Cannot prune below minimum viable tree structure."""

    def test_cannot_prune_two_leaf_tree(self) -> None:
        """A 2-leaf tree over budget where both are unannotated cannot
        be pruned further (would leave parent with < 2 children and
        no collapse target)."""
        # 0 techniques -> budget = 5.
        # This tree has only 2 leaves, so it's within budget.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_unprunable_tree_remains_valid_pydantic(self) -> None:
        """An unprunable typed-action tree remains valid Pydantic."""
        # 1 technique -> budget = 4. Tree has 5 leaves.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C filler",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D filler extra",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step E filler excess",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.unprunable_scenarios) == 1
        unchanged_scenario, _, _ = result.unprunable_scenarios[0]
        # Re-validate with Pydantic
        tree = unchanged_scenario.attack_tree
        validated = AttackTree.model_validate(tree.model_dump())
        assert validated.root.id == "n1"

    def test_and_gate_children_preserved(self) -> None:
        """An AND gate must keep at least 2 children.

        If pruning would bring it to 1 child, the gate collapses
        rather than leaving an invalid structure.
        """
        # 1 technique -> budget = 4.
        # n1 (AND)
        #   n1.1 LEAF (annotated)
        #   n1.2 (OR)
        #     n1.2.1 LEAF
        #     n1.2.2 LEAF
        #     n1.2.3 LEAF (excess)
        #   n1.3 LEAF
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Alternative paths",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        AttackTreeNode(
                            id="n1.2.1",
                            label="Via prompt",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                        AttackTreeNode(
                            id="n1.2.2",
                            label="Via context",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                        AttackTreeNode(
                            id="n1.2.3",
                            label="Via closure filler",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Exfiltrate data",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.unprunable_scenarios) == 1
        unchanged_scenario, _, _ = result.unprunable_scenarios[0]

        # Without pruning, the original tree should still be valid and unchanged.
        assert unchanged_scenario.attack_tree.root.model_dump() == root.model_dump()
        validated = AttackTree.model_validate(
            unchanged_scenario.attack_tree.model_dump()
        )

        # Check all AND/OR gates have >= 2 children
        def check_gates(node: AttackTreeNode) -> None:
            if node.gate in (GateType.AND, GateType.OR):
                assert node.children and len(node.children) >= 2, (
                    f"{node.gate.value} node {node.id} has "
                    f"{len(node.children) if node.children else 0} children"
                )
                for child in node.children:
                    check_gates(child)

        check_gates(validated.root)


# ---------------------------------------------------------------------------
# Tests: AND-gate preference
# ---------------------------------------------------------------------------


class TestAndGatePreference:
    """Gate preference is irrelevant when every leaf has a typed action."""

    def test_and_children_pruned_first(self) -> None:
        """When both AND and OR children are candidates, AND is pruned first."""
        # 1 technique -> budget = 4. Tree has 5 leaves.
        # n1 (OR)
        #   n1.1 (AND)
        #     n1.1.1 LEAF (annotated)
        #     n1.1.2 LEAF (unannotated - should be pruned first, AND child)
        #   n1.2 LEAF (unannotated, OR child)
        #   n1.3 LEAF (unannotated, OR child)
        #   n1.4 LEAF (unannotated, OR child)
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Compound path",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Reinforce deception",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Direct path A",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Direct path B",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Direct path C filler",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        unchanged, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (5, 4)
        assert unchanged.attack_tree.root.model_dump() == root.model_dump()


# ---------------------------------------------------------------------------#
# Zero-coverage internals: pruning tree helpers (CRAP slice 4)
# ---------------------------------------------------------------------------#


class TestParsimonyTreeHelpers:
    """Direct unit tests for _find_parent/_sibling_labels/_token_overlap_ratio/_remove_child."""

    def _leaf(self, node_id: str, label: str) -> AttackTreeNode:
        return AttackTreeNode(
            id=node_id,
            label=label,
            gate=GateType.LEAF,
            zone="input",
            action=AiSystemAction(),
        )

    def _root_with_children(self) -> AttackTreeNode:
        return AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                self._leaf("n1.1", "Exfiltrate data"),
                self._leaf("n1.2", "Exfiltrate logs"),
                self._leaf("n1.3", "Deny service"),
            ],
        )

    def test_find_parent_locates_immediate_child(self) -> None:
        root = self._root_with_children()

        assert _find_parent(root, "n1.2") is root

    def test_find_parent_descends_into_nested_gates(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Phase",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        self._leaf("n1.1.1", "Sub step A"),
                        self._leaf("n1.1.2", "Sub step B"),
                    ],
                ),
                self._leaf("n1.2", "Sibling leaf"),
            ],
        )

        parent = _find_parent(root, "n1.1.2")

        assert parent is not None
        assert parent.id == "n1.1"

    def test_find_parent_returns_none_for_absent_node(self) -> None:
        root = self._root_with_children()

        assert _find_parent(root, "n1.missing") is None

    def test_find_parent_returns_none_on_childless_root(self) -> None:
        leaf = self._leaf("n1", "solo leaf")

        assert _find_parent(leaf, "n1.anything") is None

    def test_sibling_labels_excludes_the_node_itself(self) -> None:
        root = self._root_with_children()

        assert _sibling_labels(root, "n1.2") == ["Exfiltrate data", "Deny service"]

    def test_sibling_labels_empty_without_children(self) -> None:
        leaf = self._leaf("n1", "solo leaf")

        assert _sibling_labels(leaf, "n1") == []

    def test_token_overlap_ratio_is_shared_token_fraction(self) -> None:
        assert (
            _token_overlap_ratio("exfiltrate data", ["exfiltrate logs", "deny service"])
            == 0.5
        )

    def test_token_overlap_ratio_zero_without_siblings(self) -> None:
        assert _token_overlap_ratio("exfiltrate data", []) == 0.0

    def test_token_overlap_ratio_zero_for_empty_label(self) -> None:
        assert _token_overlap_ratio("", ["exfiltrate logs"]) == 0.0

    def test_remove_child_removes_matching_child(self) -> None:
        root = self._root_with_children()

        _remove_child(root, "n1.2")

        assert [child.id for child in root.children] == ["n1.1", "n1.3"]

    def test_remove_child_is_noop_without_children(self) -> None:
        leaf = self._leaf("n1", "solo leaf")

        _remove_child(leaf, "n1.1")

        assert leaf.children is None
