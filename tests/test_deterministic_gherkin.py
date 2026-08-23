"""Tests for deterministic Gherkin projection (asago-scenario-generator-z369).

Covers:
- _collect_leaf_nodes_dfs: depth-first leaf collection
- THREAT_VIOLATION_CATEGORY: mapping completeness
- _build_gherkin_template: tag generation, structure, leaf steps, marker
- Full Call 3 flow: template + assertion splicing
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    InitialIngressAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    ToolInventoryEntry,
    compute_tool_id,
)
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    BehaviorSpec,
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from asago_scenario_generator.pipeline.generate import (
    _ASSERTIONS_MARKER,
    THREAT_VIOLATION_CATEGORY,
    _build_gherkin_template,
    _call_behavior_spec,
    _collect_leaf_nodes_dfs,
    _enumerate_paths,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
)
from asago_scenario_generator.pipeline.generate.assembly import (
    _build_projection_context,
)
from asago_scenario_generator.pipeline.generate.behavior_compiler import (
    build_behavior_spec_from_tree,
    render_gherkin_from_behavior_spec,
)
from asago_scenario_generator.pipeline.generate.behavior_semantics import (
    BehaviorDraftV2,
)
from asago_scenario_generator.pipeline.generate.gherkin import (
    Call3Assertion,
    Call3Response,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from tests.helpers.projection_factory import (
    get_projected_candidate,
    make_projection_block,
    make_step_realizations,
)
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_seed(threat_id: str = "T7", seed_id: str = "AP-T7-01") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name="Misaligned & Deceptive Behavior",
        threat_description="Test threat description",
        attack_pattern_name="Social Engineering via Deception",
        attack_pattern_description="Test pattern description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0054"],
    )


def _make_profile(
    zones: list[str] | None = None,
) -> CapabilityProfile:
    z = zones or ["input", "reasoning"]
    kc = ["KC1.1"]
    kw = {}
    if "tool_execution" in z:
        kc.append("KC6.1.1")
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    if "memory" in z:
        kc.append("KC4.3")
    if "inter_agent" in z:
        kc.append("KC2.3")
    return CapabilityProfile(
        zones_active=z,
        entry_points=["user prompts via chat widget"],
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc,
        **kw,
    )


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Deceptive Response Generation",
        summary="An attacker exploits the LLM to generate misleading outputs.",
        entry_point="user prompts via chat widget",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Submit crafted prompt",
                effect="Prompt accepted by input handler",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Exploit reasoning engine",
                effect="Model generates deceptive output",
                projected_step_ids=("step.2",),
                realizations=make_realizations(
                    ("step.2",),
                    action_kind="observe",
                    executor_role="system",
                    boundary_position="inside",
                ),
            ),
        ],
    )


def _make_leaf(
    node_id: str,
    label: str,
    zone: str,
    technique_id: str | None = None,
    *,
    projected_step_ids: tuple[str, ...] = (),
    realizations: tuple[Any, ...] = (),
    action: Any = None,
) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=action or AiSystemAction(),
        technique_id=technique_id,
        projected_step_ids=projected_step_ids,
        realizations=realizations,
    )


def _make_tree_simple() -> AttackTree:
    """Two-leaf tree: n1 (AND) -> n1.1 (LEAF), n1.2 (LEAF)."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Generate misleading outputs",
        root=AttackTreeNode(
            id="n1",
            label="Root attack",
            gate=GateType.AND,
            zone="input",
            children=[
                _make_leaf("n1.1", "Inject crafted prompt", "input", "AML.T0051"),
                _make_leaf("n1.2", "Exploit reasoning bias", "reasoning", "AML.T0054"),
            ],
        ),
    )


def _make_tree_with_initial_ingress(entry_point_id: str) -> AttackTree:
    """Tree whose first typed action references a profile entry point."""
    tree = _make_tree_simple()
    tree.root.children.insert(
        0,
        AttackTreeNode(
            id="n1.0",
            label="Legacy narrative entry point label",
            gate=GateType.LEAF,
            zone="input",
            action=InitialIngressAction(entry_point_id=entry_point_id),
        ),
    )
    return tree


def _make_tree_deep() -> AttackTree:
    """Deeper tree with nested AND/OR gates and 4 leaves."""
    return AttackTree(
        id="tree-AP-T5-01",
        seed_id="AP-T5-01",
        goal="Poison memory",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Phase 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        _make_leaf("n1.1.1", "Direct injection", "input", "AML.T0051"),
                        _make_leaf(
                            "n1.1.2", "Indirect injection", "input", "AML.T0043"
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Phase 2",
                    gate=GateType.AND,
                    zone="reasoning",
                    children=[
                        _make_leaf(
                            "n1.2.1", "Manipulate reasoning", "reasoning", "AML.T0054"
                        ),
                        _make_leaf("n1.2.2", "Persist to memory", "memory"),
                    ],
                ),
            ],
        ),
    )


def _make_tree_single_leaf() -> AttackTree:
    """Minimal tree: root is a single leaf node."""
    return AttackTree(
        id="tree-AP-T9-01",
        seed_id="AP-T9-01",
        goal="Single step attack",
        root=AttackTreeNode(
            id="n1",
            label="Direct exploit",
            gate=GateType.LEAF,
            zone="input",
            action=AiSystemAction(),
            technique_id="AML.T0051",
        ),
    )


def _make_tree_with_or_gate() -> AttackTree:
    """Tree with an OR gate: root(AND) -> step_A(LEAF), choice(OR) -> opt1(LEAF)/opt2(LEAF), step_B(LEAF)."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test OR gate",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                _make_leaf("n1.1", "Step A initial access", "input", "AML.T0051"),
                AttackTreeNode(
                    id="n1.2",
                    label="Choose attack vector",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _make_leaf(
                            "n1.2.1",
                            "Option 1 prompt injection",
                            "reasoning",
                            "AML.T0054",
                        ),
                        _make_leaf(
                            "n1.2.2",
                            "Option 2 data poisoning",
                            "reasoning",
                            "AML.T0020",
                        ),
                    ],
                ),
                _make_leaf("n1.3", "Step B exfiltrate data", "reasoning"),
            ],
        ),
    )


def _make_tree_with_dual_or_gates() -> AttackTree:
    """Tree with two OR gates under AND root: cross-product of 2x2 = 4 paths."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test dual OR gates",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Choice 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        _make_leaf("n1.1.1", "Path A inject", "input", "AML.T0051"),
                        _make_leaf("n1.1.2", "Path B poison", "input", "AML.T0020"),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Choice 2",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _make_leaf(
                            "n1.2.1", "Method X jailbreak", "reasoning", "AML.T0054"
                        ),
                        _make_leaf(
                            "n1.2.2", "Method Y exploit", "reasoning", "AML.T0043"
                        ),
                    ],
                ),
            ],
        ),
    )


def _make_tree_or_at_root() -> AttackTree:
    """Tree with OR gate as root: two alternative attack paths."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test OR at root",
        root=AttackTreeNode(
            id="n1",
            label="Root alternatives",
            gate=GateType.OR,
            zone="input",
            children=[
                _make_leaf("n1.1", "Direct attack via input", "input", "AML.T0051"),
                _make_leaf(
                    "n1.2", "Indirect attack via reasoning", "reasoning", "AML.T0054"
                ),
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Tests: _collect_leaf_nodes_dfs
# ---------------------------------------------------------------------------


class TestCollectLeafNodesDfs:
    def test_simple_two_leaves(self):
        tree = _make_tree_simple()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 2
        assert leaves[0].id == "n1.1"
        assert leaves[1].id == "n1.2"

    def test_deep_tree_four_leaves_dfs_order(self):
        tree = _make_tree_deep()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 4
        assert [nd.id for nd in leaves] == ["n1.1.1", "n1.1.2", "n1.2.1", "n1.2.2"]

    def test_single_leaf_tree(self):
        tree = _make_tree_single_leaf()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert len(leaves) == 1
        assert leaves[0].id == "n1"
        assert leaves[0].technique_id == "AML.T0051"

    def test_leaf_nodes_have_leaf_gate(self):
        tree = _make_tree_deep()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        for leaf in leaves:
            assert leaf.gate == GateType.LEAF

    def test_preserves_technique_ids(self):
        tree = _make_tree_simple()
        leaves = _collect_leaf_nodes_dfs(tree.root)
        assert leaves[0].technique_id == "AML.T0051"
        assert leaves[1].technique_id == "AML.T0054"


# ---------------------------------------------------------------------------
# Tests: THREAT_VIOLATION_CATEGORY mapping
# ---------------------------------------------------------------------------


class TestThreatViolationCategory:
    def test_all_t1_through_t17_mapped(self):
        for i in range(1, 18):
            key = f"T{i}"
            assert key in THREAT_VIOLATION_CATEGORY, f"Missing mapping for {key}"

    def test_tags_are_kebab_case(self):
        for threat_id, tag in THREAT_VIOLATION_CATEGORY.items():
            assert tag == tag.lower(), f"{threat_id}: tag not lowercase: {tag}"
            assert " " not in tag, f"{threat_id}: tag contains spaces: {tag}"
            assert "&" not in tag, f"{threat_id}: tag contains ampersand: {tag}"

    def test_known_mappings(self):
        assert THREAT_VIOLATION_CATEGORY["T1"] == "memory-poisoning"
        assert THREAT_VIOLATION_CATEGORY["T5"] == "cascading-hallucination-attacks"
        assert THREAT_VIOLATION_CATEGORY["T10"] == "hitl-bypass"
        assert THREAT_VIOLATION_CATEGORY["T15"] == "human-manipulation"


# ---------------------------------------------------------------------------
# Tests: _build_gherkin_template
# ---------------------------------------------------------------------------


class TestBuildGherkinTemplate:
    def test_contains_id_tag(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert (
            "@id:scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d"
            in template
        )

    def test_contains_violation_category_tag(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(threat_id="T5"),
            scenario_tag="scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
        )
        assert "@cascading-hallucination-attacks" in template

    def test_violation_category_for_each_threat_id(self):
        """Each threat_id produces its correct violation category tag."""
        for threat_id, expected_tag in THREAT_VIOLATION_CATEGORY.items():
            seed = _make_seed(threat_id=threat_id, seed_id=f"AP-{threat_id}-01")
            tree_id = f"tree-AP-{threat_id}-01"
            tree = AttackTree(
                id=tree_id,
                seed_id=f"AP-{threat_id}-01",
                goal="Test",
                root=AttackTreeNode(
                    id="n1",
                    label="Root",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        _make_leaf("n1.1", "Step A", "input"),
                        _make_leaf("n1.2", "Step B", "reasoning"),
                    ],
                ),
            )
            template = _build_gherkin_template(
                narrative=_make_narrative(),
                attack_tree=tree,
                profile=_make_profile(),
                seed=seed,
                scenario_tag=f"AP-{threat_id}-01-abc123",
            )
            assert f"@{expected_tag}" in template, (
                f"Expected @{expected_tag} for {threat_id}"
            )

    def test_feature_line_contains_title(self):
        narrative = _make_narrative()
        template = _build_gherkin_template(
            narrative=narrative,
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert f"Feature: {narrative.title}" in template

    def test_background_given_contains_entry_point(self):
        profile = _make_profile()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_initial_ingress(
                profile.entry_points[0].entry_point_id
            ),
            profile=profile,
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert "When user prompts via chat widget (input)" in template

    def test_when_and_steps_from_leaf_nodes(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert "When Inject crafted prompt [AML.T0051] (input)" in template
        assert "And Exploit reasoning bias [AML.T0054] (reasoning)" in template

    def test_leaf_without_technique_id(self):
        """Leaf nodes without technique_id omit the bracket annotation."""
        tree = _make_tree_deep()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(
                zones=["input", "reasoning", "memory"],
            ),
            seed=_make_seed(threat_id="T5", seed_id="AP-T5-01"),
            scenario_tag="scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
        )
        # n1.2.2 has no technique_id
        assert "And Persist to memory (memory)" in template

    def test_contains_assertions_marker(self):
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert _ASSERTIONS_MARKER in template
        # Marker appears exactly once
        assert template.count(_ASSERTIONS_MARKER) == 1

    def test_single_leaf_tree(self):
        """A single-leaf tree produces only a When step, no And."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_single_leaf(),
            profile=_make_profile(),
            seed=_make_seed(threat_id="T9", seed_id="AP-T9-01"),
            scenario_tag="AP-T9-01-abc123",
        )
        assert "When Direct exploit [AML.T0051] (input)" in template
        # No "And" attack step line (And in Background is fine)
        scenario_section = template.split("Scenario:")[1]
        when_and_section = scenario_section.split(_ASSERTIONS_MARKER)[0]
        # Count lines starting with "    And " in the attack step block
        attack_and_lines = [
            line
            for line in when_and_section.split("\n")
            if line.strip().startswith("And ") and "(" in line and ")" in line
        ]
        assert len(attack_and_lines) == 0

    def test_depth_first_ordering(self):
        """Leaf nodes appear in depth-first order matching narrative phases."""
        tree = _make_tree_deep()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(
                zones=["input", "reasoning", "memory"],
            ),
            seed=_make_seed(threat_id="T5", seed_id="AP-T5-01"),
            scenario_tag="scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
        )
        # Extract the attack step lines from the scenario section
        scenario_part = template.split("Scenario:")[1]
        attack_lines = [
            line.strip()
            for line in scenario_part.split("\n")
            if line.strip().startswith(("When ", "And "))
        ]
        # First is When (n1.1.1 Direct injection)
        assert attack_lines[0].startswith("When Direct injection")
        # Last contains "Persist to memory"
        assert "Persist to memory" in attack_lines[-1]

    def test_additional_zones_in_background(self):
        """Background only includes zones actually present in the tree.

        Even if the profile has tool_execution active, it should not appear
        in Background if the tree has no leaf nodes in that zone.
        """
        profile = _make_profile(
            zones=["input", "reasoning", "tool_execution"],
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=profile,
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # tree only uses input and reasoning, so tool_execution should be absent
        assert "Tool Execution capabilities (tool_execution)" not in template
        # reasoning should still be present (it's in the tree)
        assert "Reasoning capabilities (reasoning)" in template

    def test_unknown_threat_id_uses_default(self):
        """Unknown threat_id falls back to misaligned-and-deceptive-behavior."""
        seed = _make_seed(threat_id="T99", seed_id="AP-T7-01")
        # Override threat_id on the seed manually
        seed.threat_id = "T99"
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=seed,
            scenario_tag="AP-T99-01-abc123",
        )
        assert "@misaligned-and-deceptive-behavior" in template

    # --- Regression tests for Gherkin projection bugs (asago-scenario-generator-vaxe) ---

    def test_initial_ingress_uses_profile_effective_zone(self):
        """Typed ingress uses the profile name and effective ingress zone."""
        narrative = NarrativeLayer(
            title="Test scenario",
            summary="Test summary",
            entry_point="obsolete narrative entry point (reasoning)",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Submit query",
                    effect="Query accepted",
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
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                {
                    "name": "user queries via Klarna app",
                    "direction": "input",
                    "controllability": "direct",
                    "ingress_zone": "input",
                }
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        template = _build_gherkin_template(
            narrative=narrative,
            attack_tree=_make_tree_with_initial_ingress(
                profile.entry_points[0].entry_point_id
            ),
            profile=profile,
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert "When user queries via Klarna app (input)" in template
        assert "obsolete narrative entry point" not in template

    def test_raw_technique_id_label_resolved(self):
        """Leaf nodes whose label is a raw technique ID should render
        the technique name instead."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    _make_leaf("n1.1", "AML.T0053", "input", "AML.T0053"),
                    _make_leaf("n1.2", "Normal label", "reasoning", "AML.T0054"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Raw ID should not appear as step text
        assert "When AML.T0053 [AML.T0053]" not in template
        # Should use the ATLAS name instead
        from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_NAMES

        expected_name = ATLAS_TECHNIQUE_NAMES["AML.T0053"]
        assert f"When {expected_name} [AML.T0053] (input)" in template
        # Normal labels remain unchanged
        assert "And Normal label [AML.T0054] (reasoning)" in template

    def test_background_excludes_unused_zones(self):
        """Background should only declare zones present in tree leaves,
        not all zones from the capability profile."""
        profile = _make_profile(
            zones=["input", "reasoning", "tool_execution"],
        )
        # Tree only uses input and reasoning
        tree = _make_tree_simple()
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=profile,
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # tool_execution is in profile but not in tree leaves
        assert "tool_execution" not in template.split("Scenario:")[0]
        # reasoning IS in tree leaves and should be declared
        assert "Reasoning capabilities (reasoning)" in template


# ---------------------------------------------------------------------------
# Tests: Full Call 3 flow (template + assertion splicing)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helper: projection-aligned Call 3 fixtures (422o.4)
# ---------------------------------------------------------------------------


def _make_projection_context():
    """Build a projection context from the shared test projected candidate."""
    return _build_projection_context(get_projected_candidate())


def _make_tree_for_projection():
    """Build a tree with leaves matching the projection's selected steps."""
    candidate = get_projected_candidate()
    selected = candidate.projection.selected_step_ids
    leaves = [
        _make_leaf(
            f"n1.{i + 1}",
            f"Action for {sid}",
            "input" if i == 0 else "reasoning",
            "AML.T0001" if i == 0 else None,
            projected_step_ids=(sid,),
            realizations=make_step_realizations((sid,)),
        )
        for i, sid in enumerate(selected)
    ]
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Test attack",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=leaves,
        ),
    )


def _make_call3_response():
    """Build a valid assertions-only Call3Response matching the projection."""
    candidate = get_projected_candidate()
    selected = candidate.projection.selected_step_ids
    chain = candidate.projection.source_chain

    assertions: list[Call3Assertion] = []
    for step in chain.steps:
        if step.step_id in set(selected):
            for pc in step.observable_postconditions:
                if pc.security_relevant:
                    assertions.append(
                        Call3Assertion(
                            assertion_id=f"assert-{step.step_id}-{pc.postcondition_id}",
                            source_step_ids=(step.step_id,),
                            projected_postcondition_ids=(pc.postcondition_id,),
                            text=f"Verify {pc.postcondition_id}",
                        )
                    )

    return Call3Response(assertions=assertions)


def _make_mock_client_call3(response: Call3Response | None = None) -> MagicMock:
    """Create a mock LLM client that returns a Call3Response."""
    result = MagicMock()
    result.content = response or _make_call3_response()
    result.prompt_tokens = 100
    result.completion_tokens = 50
    result.duration_ms = 1000
    result.system_prompt = "test"
    result.user_prompt = "test"
    client = MagicMock()
    client.complete.return_value = result
    return client


# ---------------------------------------------------------------------------


class TestCallBehaviorSpecIntegration:
    """Test the structured Call 3 flow (422o.4: Call3Response → BehaviorSpec)."""

    def test_structured_response_produces_valid_behavior_spec(self):
        """A valid Call3Response produces a BehaviorSpec with Gherkin text."""
        client = _make_mock_client_call3()
        spec, _result = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_for_projection(),
            profile=_make_profile(),
            client=client,
            use_case="Test system",
            scenario_tag="abc123",
            projection_context=_make_projection_context(),
        )
        assert isinstance(spec, BehaviorSpec)
        assert len(spec.actions) > 0
        assert spec.gherkin_text
        assert "Feature:" in spec.gherkin_text

    def test_returns_tuple_of_behavior_spec_and_result(self):
        """Return type contract: (BehaviorSpec, LLMResult)."""
        client = _make_mock_client_call3()
        result = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_for_projection(),
            profile=_make_profile(),
            client=client,
            use_case="Test",
            scenario_tag="abc123",
            projection_context=_make_projection_context(),
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], BehaviorSpec)

    def test_missing_projection_context_raises(self):
        """Call 3 without projection context raises ValueError."""
        client = _make_mock_client_call3()
        with pytest.raises(ValueError, match="projection context"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
            )

    def test_actions_are_derived_independently_of_llm_response(self):
        tree = _make_tree_for_projection()
        first, _ = _call_behavior_spec(
            _make_seed(),
            _make_narrative(),
            tree,
            _make_profile(),
            _make_mock_client_call3(),
            "Test",
            "abc123",
            projection_context=_make_projection_context(),
        )
        second, _ = _call_behavior_spec(
            _make_seed(),
            _make_narrative(),
            tree,
            _make_profile(),
            _make_mock_client_call3(),
            "Test",
            "abc123",
            projection_context=_make_projection_context(),
        )

        assert first.actions == second.actions
        assert [action.source_leaf_id for action in first.actions] == [
            leaf.id for leaf in _collect_leaf_nodes_dfs(tree.root)
        ]
        assert [action.action_id for action in first.actions] == [
            f"ba-{leaf.id}" for leaf in _collect_leaf_nodes_dfs(tree.root)
        ]

    def test_call3_schema_rejects_llm_authored_actions(self):
        with pytest.raises(ValueError, match="Extra inputs are not permitted"):
            Call3Response.model_validate({"actions": [], "assertions": []})

    def test_llm_receives_projection_context_in_prompt(self):
        """The LLM call receives projection context in the user prompt."""
        client = _make_mock_client_call3()
        _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_for_projection(),
            profile=_make_profile(),
            client=client,
            use_case="Test",
            scenario_tag="abc123",
            projection_context=_make_projection_context(),
        )
        call_args = mock_client_complete_user_prompt(client)
        assert (
            "projection" in call_args.lower()
            or "projected" in call_args.lower()
            or "step" in call_args.lower()
        )
        assert "Produce only the structured JSON assertions" in call_args
        assert issubclass(
            client.complete.call_args.kwargs["response_format"], BehaviorDraftV2
        )


def mock_client_complete_user_prompt(client: MagicMock) -> str:
    """Extract the user_prompt from the client.complete call."""
    call_args = client.complete.call_args
    user_prompt = call_args.kwargs.get("user_prompt", "")
    if not user_prompt:
        # Try positional args
        args = call_args[0]
        if len(args) > 1:
            user_prompt = args[1]
    return user_prompt


# ---------------------------------------------------------------------------
# Tests: Then/But/* indentation (asago-scenario-generator-7kk9 Fix 1)
# ---------------------------------------------------------------------------


class TestBehaviorSpecRendering:
    """Verify that BehaviorSpec rendered from Call3Response has proper structure."""

    def test_rendered_gherkin_has_feature_and_steps(self):
        """Gherkin rendered from BehaviorSpec contains Feature and step lines."""
        client = _make_mock_client_call3()
        spec, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_for_projection(),
            profile=_make_profile(),
            client=client,
            use_case="Test",
            scenario_tag="abc123",
            projection_context=_make_projection_context(),
        )
        assert "Feature:" in spec.gherkin_text
        # Each action should appear in the rendered Gherkin
        for action in spec.actions:
            assert action.text in spec.gherkin_text

    def test_assertions_use_then_keyword(self):
        """Assertions in the BehaviorSpec use the 'Then' keyword."""
        client = _make_mock_client_call3()
        spec, _ = _call_behavior_spec(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_tree_for_projection(),
            profile=_make_profile(),
            client=client,
            use_case="Test",
            scenario_tag="abc123",
            projection_context=_make_projection_context(),
        )
        for assertion in spec.assertions:
            assert assertion.gherkin_keyword == "Then"
            assert assertion.text in spec.gherkin_text


# ---------------------------------------------------------------------------
# Tests: Raw technique name substitution (asago-scenario-generator-7kk9 Fix 2)
# ---------------------------------------------------------------------------


class TestRawTechniqueNameSubstitution:
    """Verify that leaf labels matching ATLAS technique names are replaced."""

    def test_verbatim_technique_name_replaced_with_description(self):
        """Leaf whose label is a verbatim ATLAS technique name should use
        the node's description instead."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="AI Agent Tool Invocation",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        action=ToolInvocationAction(
                            tool_id=compute_tool_id("test_tool", "A test tool")
                        ),
                        technique_id="AML.T0053",
                        description="Agent invokes external API beyond scope",
                    ),
                    _make_leaf("n1.2", "Normal step label", "reasoning", "AML.T0054"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(zones=["input", "reasoning", "tool_execution"]),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Should NOT contain the raw technique name as step text
        assert "When AI Agent Tool Invocation [AML.T0053]" not in template
        # Should use the description
        assert (
            "When Agent invokes external API beyond scope [AML.T0053] (tool_execution)"
            in template
        )
        # Normal labels remain unchanged
        assert "And Normal step label [AML.T0054] (reasoning)" in template

    def test_verbatim_technique_name_fallback_without_description(self):
        """Leaf whose label is a technique name but has no description
        falls back to generic label."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Indirect Prompt Injection",
                        gate=GateType.LEAF,
                        zone="input",
                        action=AiSystemAction(),
                        technique_id="AML.T0051.001",
                        # no description
                    ),
                    _make_leaf("n1.2", "Other step", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Should NOT contain verbatim technique name as-is
        assert "When Indirect Prompt Injection [AML.T0051.001]" not in template
        # Should use generic fallback
        assert (
            "When Execute attack step via Indirect Prompt Injection [AML.T0051.001] (input)"
            in template
        )

    def test_case_insensitive_technique_name_match(self):
        """Matching should be case-insensitive."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="llm jailbreak",  # lowercase variant
                        gate=GateType.LEAF,
                        zone="input",
                        action=AiSystemAction(),
                        technique_id="AML.T0054",
                        description="Bypass safety via crafted prompts",
                    ),
                    _make_leaf("n1.2", "Other step", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Should use description, not the raw technique name
        assert "When Bypass safety via crafted prompts [AML.T0054] (input)" in template

    def test_non_technique_label_unchanged(self):
        """Labels that are NOT technique names should pass through unchanged."""
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[
                    _make_leaf("n1.1", "Craft malicious payload", "input", "AML.T0051"),
                    _make_leaf("n1.2", "Exploit trust boundary", "reasoning"),
                ],
            ),
        )
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=tree,
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert "When Craft malicious payload [AML.T0051] (input)" in template
        assert "And Exploit trust boundary (reasoning)" in template


# ---------------------------------------------------------------------------
# Tests: _enumerate_paths
# ---------------------------------------------------------------------------


class TestEnumeratePaths:
    def test_and_only_tree_single_path(self):
        """Pure AND tree produces a single path with all leaves."""
        tree = _make_tree_simple()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 1
        assert [n.id for n in paths[0]] == ["n1.1", "n1.2"]

    def test_single_leaf_tree_one_path(self):
        """Single-leaf tree produces one path with one leaf."""
        tree = _make_tree_single_leaf()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 1
        assert len(paths[0]) == 1
        assert paths[0][0].id == "n1"

    def test_or_gate_produces_alternative_paths(self):
        """Tree with OR gate produces one path per OR alternative."""
        tree = _make_tree_with_or_gate()
        paths = _enumerate_paths(tree.root)
        # OR gate with 2 children under AND with 2 other leaves -> 2 paths
        assert len(paths) == 2
        # Path 1: n1.1 + n1.2.1 + n1.3
        assert [n.id for n in paths[0]] == ["n1.1", "n1.2.1", "n1.3"]
        # Path 2: n1.1 + n1.2.2 + n1.3
        assert [n.id for n in paths[1]] == ["n1.1", "n1.2.2", "n1.3"]

    def test_dual_or_gates_cross_product(self):
        """Two OR gates under AND produce a cross-product of paths."""
        tree = _make_tree_with_dual_or_gates()
        paths = _enumerate_paths(tree.root)
        # 2x2 = 4 paths
        assert len(paths) == 4
        path_ids = {tuple(n.id for n in p) for p in paths}
        assert ("n1.1.1", "n1.2.1") in path_ids
        assert ("n1.1.1", "n1.2.2") in path_ids
        assert ("n1.1.2", "n1.2.1") in path_ids
        assert ("n1.1.2", "n1.2.2") in path_ids

    def test_or_at_root(self):
        """OR gate at root produces one path per child."""
        tree = _make_tree_or_at_root()
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 2
        assert [n.id for n in paths[0]] == ["n1.1"]
        assert [n.id for n in paths[1]] == ["n1.2"]

    def test_deep_tree_with_nested_or(self):
        """Deep tree with OR gate produces correct paths."""
        tree = _make_tree_deep()
        # n1 (AND) -> n1.1 (OR) -> [n1.1.1, n1.1.2], n1.2 (AND) -> [n1.2.1, n1.2.2]
        # Paths: n1.1.1+n1.2.1+n1.2.2, n1.1.2+n1.2.1+n1.2.2
        paths = _enumerate_paths(tree.root)
        assert len(paths) == 2
        assert [n.id for n in paths[0]] == ["n1.1.1", "n1.2.1", "n1.2.2"]
        assert [n.id for n in paths[1]] == ["n1.1.2", "n1.2.1", "n1.2.2"]

    def test_preserves_leaf_data(self):
        """Enumerated paths preserve technique_id and zone on leaves."""
        tree = _make_tree_with_or_gate()
        paths = _enumerate_paths(tree.root)
        # First leaf in path 1 should have technique_id
        first_leaf = paths[0][0]
        assert first_leaf.technique_id == "AML.T0051"
        assert first_leaf.zone == "input"


# ---------------------------------------------------------------------------
# Tests: OR-gate-aware _build_gherkin_template
# ---------------------------------------------------------------------------


class TestBuildGherkinTemplateOrGates:
    def test_or_gate_produces_multiple_scenario_blocks(self):
        """Tree with OR gate generates separate Scenario blocks."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Should have 2 Scenario blocks
        import re

        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 2

    def test_or_gate_path_names(self):
        """Multi-path scenarios have '(Path N)' suffix."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert "Scenario: Deceptive Response Generation (Path 1)" in template
        assert "Scenario: Deceptive Response Generation (Path 2)" in template

    def test_or_gate_each_scenario_has_assertions_marker(self):
        """Each Scenario block has its own {ASSERTIONS} marker."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert template.count(_ASSERTIONS_MARKER) == 2

    def test_or_gate_shared_and_steps(self):
        """AND-gate steps appear in BOTH scenarios."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Step A (AND-required leaf) appears in both scenarios
        import re

        step_a_count = len(re.findall(r"Step A initial access", template))
        assert step_a_count == 2, (
            f"Step A should appear in both scenarios, found {step_a_count}"
        )
        # Step B appears in both too
        step_b_count = len(re.findall(r"Step B exfiltrate data", template))
        assert step_b_count == 2, (
            f"Step B should appear in both scenarios, found {step_b_count}"
        )

    def test_or_gate_alternatives_in_separate_scenarios(self):
        """Each OR alternative appears in exactly one Scenario block."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        # Split by Scenario blocks
        import re

        blocks = re.split(r"^\s*Scenario:", template, flags=re.MULTILINE)
        # blocks[0] is header, blocks[1] is Path 1, blocks[2] is Path 2
        assert len(blocks) == 3
        assert "Option 1 prompt injection" in blocks[1]
        assert "Option 2 data poisoning" in blocks[2]
        # Each option should NOT appear in the other scenario
        assert "Option 2 data poisoning" not in blocks[1]
        assert "Option 1 prompt injection" not in blocks[2]

    def test_dual_or_gates_four_scenarios(self):
        """Two OR gates produce 4 scenarios (2x2 cross-product)."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_dual_or_gates(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        import re

        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 4
        assert template.count(_ASSERTIONS_MARKER) == 4

    def test_or_at_root_two_scenarios(self):
        """OR gate at root produces 2 Scenario blocks."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_or_at_root(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        import re

        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 2
        assert "Direct attack via input" in template
        assert "Indirect attack via reasoning" in template

    def test_no_or_gate_single_scenario(self):
        """AND-only tree still produces single Scenario block without path suffix."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_simple(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        import re

        scenario_count = len(re.findall(r"^\s*Scenario:", template, re.MULTILINE))
        assert scenario_count == 1
        assert "(Path " not in template
        assert template.count(_ASSERTIONS_MARKER) == 1

    def test_shared_background_across_scenarios(self):
        """Background section appears once, shared by all scenarios."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert template.count("Background: Preconditions") == 1

    def test_or_gate_feature_header_once(self):
        """Feature header appears exactly once."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        assert template.count("Feature:") == 1

    def test_or_gate_correct_when_and_keywords(self):
        """Each Scenario block starts with When and uses And for subsequent steps."""
        template = _build_gherkin_template(
            narrative=_make_narrative(),
            attack_tree=_make_tree_with_or_gate(),
            profile=_make_profile(),
            seed=_make_seed(),
            scenario_tag="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        )
        import re

        blocks = re.split(r"^\s*Scenario:", template, flags=re.MULTILINE)
        for block in blocks[1:]:  # skip header
            attack_lines = [
                line.strip()
                for line in block.split("\n")
                if line.strip().startswith(("When ", "And ")) and "(" in line
            ]
            assert len(attack_lines) >= 1
            assert attack_lines[0].startswith("When ")
            for line in attack_lines[1:]:
                assert line.startswith("And ")


# ---------------------------------------------------------------------------
# Tests: OR-gate Call 3 assertion splicing
# ---------------------------------------------------------------------------


def test_renderer_preserves_when_to_then_keyword_transition() -> None:
    actions = [
        BehaviorAction(
            action_id="ba-n1.1",
            projected_step_ids=("step.1",),
            source_leaf_id="n1.1",
            gherkin_keyword="When",
            text="the attacker enters",
            realizations=make_realizations(("step.1",)),
        ),
        BehaviorAction(
            action_id="ba-n1.2",
            projected_step_ids=("step.2",),
            source_leaf_id="n1.2",
            gherkin_keyword="Then",
            text="the impact is observed",
            realizations=make_realizations(("step.2",)),
        ),
    ]

    rendered = render_gherkin_from_behavior_spec(actions, [])

    assert "    When the attacker enters\n" in rendered
    assert "    Then the impact is observed\n" in rendered
    assert "    And the impact is observed\n" not in rendered


def test_renderer_preserves_given_to_when_and_compacts_repeated_when() -> None:
    actions = [
        BehaviorAction(
            action_id=f"ba-n1.{index}",
            projected_step_ids=(f"step.{index}",),
            source_leaf_id=f"n1.{index}",
            gherkin_keyword=keyword,
            text=text,
            realizations=make_realizations((f"step.{index}",)),
        )
        for index, keyword, text in (
            (1, "Given", "external access exists"),
            (2, "When", "the attacker enters"),
            (3, "When", "the system processes input"),
        )
    ]

    rendered = render_gherkin_from_behavior_spec(actions, [])

    assert "    Given external access exists\n" in rendered
    assert "    When the attacker enters\n" in rendered
    assert "    And the system processes input\n" in rendered


class TestCallBehaviorSpecValidation:
    """422o.4: Test Call 3 structured validation edge cases."""

    def test_ambiguous_cross_step_postcondition_owner_rejected(self):
        response = _make_call3_response()
        context = _make_projection_context()
        first_postcondition = context["selected_steps"][0]["observable_postconditions"][
            0
        ]
        context["selected_steps"][1]["observable_postconditions"].append(
            dict(first_postcondition)
        )
        client = _make_mock_client_call3(response)

        with pytest.raises(ValueError, match="ambiguous owners"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=context,
            )

    def test_assertion_unknown_postcondition_rejected(self):
        """Assertion referencing an unknown postcondition is rejected."""
        response = _make_call3_response()
        if response.assertions:
            response.assertions[0] = Call3Assertion(
                assertion_id=response.assertions[0].assertion_id,
                source_step_ids=response.assertions[0].source_step_ids,
                projected_postcondition_ids=("nonexistent.pc",),
                text=response.assertions[0].text,
            )
        client = _make_mock_client_call3(response)
        with pytest.raises(ValueError, match="unknown postcondition"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )

    def test_duplicate_assertion_id_rejected(self):
        response = _make_call3_response()
        response.assertions.append(response.assertions[0])
        client = _make_mock_client_call3(response)

        with pytest.raises(ValueError, match="Duplicate assertion ID"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #3: Call 3 exact ownership adversarial tests
# ---------------------------------------------------------------------------#


class TestCall3ExactOwnershipAdversarial:
    """Adversarial tests for exact assertion ownership in Call 3."""

    def test_wrong_owner_postcondition_rejected(self):
        """Assertion with globally valid postcondition but wrong source step
        must fail."""
        response = _make_call3_response()
        if response.assertions:
            # Change source_step_ids to a different step
            response.assertions[0] = Call3Assertion(
                assertion_id=response.assertions[0].assertion_id,
                source_step_ids=("step.1",),  # wrong owner
                projected_postcondition_ids=response.assertions[
                    0
                ].projected_postcondition_ids,
                text=response.assertions[0].text,
            )
        client = _make_mock_client_call3(response)
        with pytest.raises(
            ValueError,
            match="source_step_ids must exactly equal the postcondition owner",
        ):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )


# ---------------------------------------------------------------------------#
# Adversarial tests for 422o.4 review blocker #3: exact tuple/ownership
# ---------------------------------------------------------------------------#


class TestCall3TupleOwnershipAdversarial:
    """Adversarial tests for exact assertion identity and ownership."""

    def test_arbitrary_assertion_id_rejected(self):
        """Assertion ID not matching assert-<step>-<postcondition> must fail."""
        response = _make_call3_response()
        if not response.assertions:
            pytest.skip("No assertions in test fixture")
        # Keep valid source/postcondition but use arbitrary ID
        a = response.assertions[0]
        response.assertions[0] = Call3Assertion(
            assertion_id="arbitrary-assert",
            source_step_ids=a.source_step_ids,
            projected_postcondition_ids=a.projected_postcondition_ids,
            text=a.text,
        )
        client = _make_mock_client_call3(response)
        with pytest.raises(
            ValueError, match="does not match deterministic expected ID"
        ):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )

    def test_extra_unrelated_source_step_rejected(self):
        """Assertion with valid postcondition plus extra unrelated source
        step must fail — source_step_ids must have exactly one element."""
        response = _make_call3_response()
        if not response.assertions:
            pytest.skip("No assertions in test fixture")
        a = response.assertions[0]
        # Add an extra unrelated source step (two elements instead of one)
        extra_step = "step.1" if a.source_step_ids[0] != "step.1" else "step.2"
        response.assertions[0] = Call3Assertion(
            assertion_id=a.assertion_id,
            source_step_ids=(a.source_step_ids[0], extra_step),
            projected_postcondition_ids=a.projected_postcondition_ids,
            text=a.text,
        )
        client = _make_mock_client_call3(response)
        with pytest.raises(ValueError, match="exactly one.*owning step.*is required"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )

    def test_omitted_assertion_coverage_rejected(self):
        """Missing a security-relevant postcondition assertion must fail."""
        response = _make_call3_response()
        if not response.assertions:
            pytest.skip("No assertions in test fixture")
        # Remove all assertions
        response.assertions = []
        client = _make_mock_client_call3(response)
        with pytest.raises(ValueError, match="does not cover security-relevant"):
            _call_behavior_spec(
                seed=_make_seed(),
                narrative=_make_narrative(),
                attack_tree=_make_tree_for_projection(),
                profile=_make_profile(),
                client=client,
                use_case="Test",
                scenario_tag="abc123",
                projection_context=_make_projection_context(),
            )


# ---------------------------------------------------------------------------#
# Deterministic compiler: build_behavior_spec_from_tree (CRAP slice 4)
# ---------------------------------------------------------------------------#


def _tree_with_leaves(leaves: list[AttackTreeNode]) -> AttackTree:
    """Build a minimal AND-rooted tree carrying the given leaves.

    AND gates require at least two children, so single-leaf trees get a
    filler unprojected leaf (external precondition, zone-less) that the
    compiler filters out.
    """
    children = list(leaves)
    if len(children) < 2:
        children.append(
            AttackTreeNode(
                id="n1.9",
                label="Filler no-op",
                gate=GateType.LEAF,
                zone=None,
                action=ExternalPreconditionAction(),
            )
        )
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compile projected leaves",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=children,
        ),
    )


def _project_candidate(raw_pattern: dict[str, Any]) -> tuple[Any, Any]:
    """Project one raw pattern dict; returns (candidate, snapshot)."""
    from asago_scenario_generator.models.attack_pattern import AttackPattern
    from asago_scenario_generator.pipeline.projection import (
        ProjectionBudget,
        capture_capability_snapshot,
        project_authoritative_candidates,
    )
    from tests.test_projected_candidates import _evidence, _profile

    pattern = AttackPattern.model_validate(raw_pattern)
    resolver = type("Resolver", (), {})()
    resolver.taxonomy_context = pattern.canonical_chain.taxonomy_context
    resolver.contains = lambda taxonomy, identifier: (
        (taxonomy, identifier) in {("ATLAS", "AML.T0001")}
    )
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    batch = project_authoritative_candidates(
        [raw_pattern], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
    )
    assert len(batch.candidates) >= 1
    return batch.candidates[0], snapshot


def _block_for_candidate(candidate: Any, snapshot: Any) -> ProjectionEnvelopeBlock:
    """Build a valid projection envelope block for a freshly projected candidate."""
    from asago_scenario_generator.pipeline.projection import (
        compute_derivation_context_digest,
    )

    return ProjectionEnvelopeBlock(
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        projected_mappings=candidate.projected_mappings,
        capability_snapshot=snapshot,
        execution_requirements=candidate.execution_requirements,
        requirement_derivation_version=candidate.requirement_derivation_version,
        execution_requirements_digest=candidate.execution_requirements_digest,
        derivation_context_digest=compute_derivation_context_digest(
            candidate.projection.projection_digest,
            candidate.projection.source_chain.pattern_id,
            candidate.ingress_controllability,
        ),
    )


def _pattern_with_second_terminal_postcondition() -> dict[str, Any]:
    """Fixture pattern whose terminal step owns two security postconditions."""
    from asago_scenario_generator.models.attack_pattern import (
        compute_chain_semantic_digest,
    )
    from tests.test_projected_candidates import _pattern

    raw = _pattern(conditional=True)
    terminal = raw["canonical_chain"]["steps"][2]
    terminal["observable_postconditions"].append(
        {
            "postcondition_id": "post.4",
            "description": "second outcome",
            "security_relevant": True,
            "terminal": True,
        }
    )
    # Security-relevant postconditions must own an observable outcome link.
    terminal["observable_outcome_links"].append(
        {
            "postcondition_id": "post.4",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        }
    )
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    return raw


class TestBuildBehaviorSpecFromTree:
    """Deterministic tree+projection → BehaviorSpec compiler (CRAP slice 4)."""

    def _projected_leaves(self) -> list[AttackTreeNode]:
        candidate = get_projected_candidate()
        return [
            _make_leaf(
                f"n1.{i + 1}",
                f"Leaf action {sid}",
                "input" if i == 0 else "reasoning",
                projected_step_ids=(sid,),
                realizations=make_step_realizations((sid,)),
            )
            for i, sid in enumerate(candidate.projection.selected_step_ids)
        ]

    def test_actions_derive_from_fully_projected_leaves_in_dfs_order(self) -> None:
        leaves = self._projected_leaves()
        spec = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves), make_projection_block()
        )

        assert [a.action_id for a in spec.actions] == [
            f"ba-{leaf.id}" for leaf in leaves
        ]
        assert [a.source_leaf_id for a in spec.actions] == [leaf.id for leaf in leaves]
        assert [a.projected_step_ids for a in spec.actions] == [
            leaf.projected_step_ids for leaf in leaves
        ]
        assert [a.text for a in spec.actions] == [leaf.label for leaf in leaves]
        assert all(a.gherkin_keyword == "When" for a in spec.actions)

    def test_actions_carry_leaf_realizations_for_each_projected_step(self) -> None:
        selected = get_projected_candidate().projection.selected_step_ids
        first_id = selected[0]
        realizations = make_step_realizations((first_id,))
        leaf = _make_leaf(
            "n1.1",
            "ingress leaf",
            "input",
            projected_step_ids=(first_id,),
            realizations=realizations,
        )
        spec = build_behavior_spec_from_tree(
            _tree_with_leaves([leaf]), make_projection_block()
        )

        action = spec.actions[0]
        assert action.realizations == realizations
        assert [r.projected_step_id for r in action.realizations] == [first_id]

    @pytest.mark.parametrize(
        "case",
        ["no_projected_steps", "partially_outside_selected"],
    )
    def test_leaf_filters_skip_leaves_outside_the_projection_selection(
        self, case: str
    ) -> None:
        selected = get_projected_candidate().projection.selected_step_ids
        kept = _make_leaf(
            "n1.1",
            "kept leaf",
            "input",
            projected_step_ids=(selected[0],),
            realizations=make_step_realizations((selected[0],)),
        )
        if case == "no_projected_steps":
            filtered = _make_leaf("n1.2", "no projected steps", "input")
        else:
            filtered = AttackTreeNode(
                id="n1.2",
                label="partially outside selection",
                gate=GateType.LEAF,
                zone="input",
                action=AiSystemAction(),
                projected_step_ids=(selected[0], "step.outside"),
                realizations=make_realizations((selected[0], "step.outside")),
            )

        spec = build_behavior_spec_from_tree(
            _tree_with_leaves([kept, filtered]), make_projection_block()
        )

        assert len(spec.actions) == 1
        assert spec.actions[0].source_leaf_id == "n1.1"

    @pytest.mark.parametrize(
        ("label", "description", "expected"),
        [
            ("Leaf label", None, "Leaf label"),
            ("Leaf label", "Description wins", "Description wins"),
            ("", None, "n1.1"),
        ],
    )
    def test_action_text_prefers_description_then_label_then_id(
        self, label: str, description: str | None, expected: str
    ) -> None:
        selected = get_projected_candidate().projection.selected_step_ids
        leaf = AttackTreeNode(
            id="n1.1",
            label=label,
            gate=GateType.LEAF,
            zone="input",
            action=AiSystemAction(),
            projected_step_ids=(selected[0],),
            realizations=make_step_realizations((selected[0],)),
            description=description,
        )

        spec = build_behavior_spec_from_tree(
            _tree_with_leaves([leaf]), make_projection_block()
        )

        assert spec.actions[0].text == expected

    def test_assertions_use_stable_ids_over_security_relevant_postconditions(
        self,
    ) -> None:
        leaves = self._projected_leaves()
        spec = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves), make_projection_block()
        )

        assert [
            (
                a.assertion_id,
                a.source_step_ids,
                a.projected_postcondition_ids,
                a.gherkin_keyword,
                a.text,
            )
            for a in spec.assertions
        ] == [("assert-step.3-post.3", ("step.3",), ("post.3",), "Then", "observable")]

    def test_assertion_ids_join_multiple_postconditions_with_dash(self) -> None:
        candidate, snapshot = _project_candidate(
            _pattern_with_second_terminal_postcondition()
        )
        selected = candidate.projection.selected_step_ids
        leaves = [
            _make_leaf(
                f"n1.{i + 1}",
                f"Leaf action {sid}",
                "input" if i == 0 else "reasoning",
                projected_step_ids=(sid,),
                realizations=make_step_realizations((sid,)),
            )
            for i, sid in enumerate(selected)
        ]

        spec = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves), _block_for_candidate(candidate, snapshot)
        )

        assert [(a.assertion_id, a.text) for a in spec.assertions] == [
            ("assert-step.3-post.3-post.4", "observable; second outcome")
        ]

    def test_gherkin_renders_actions_then_assertions_with_zone_annotations(
        self,
    ) -> None:
        leaves = self._projected_leaves()
        spec = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves), make_projection_block()
        )
        lines = [
            line.strip()
            for line in spec.gherkin_text.splitlines()
            if line.strip().startswith(("When ", "And ", "Then "))
        ]

        assert lines[0] == "When Leaf action step.1 (input)"
        assert lines[1] == "And Leaf action step.2 (reasoning)"
        assert lines[2] == "And Leaf action step.3 (reasoning)"
        assert lines[3] == "Then observable"

    def test_zone_map_excludes_leaves_without_a_zone(self) -> None:
        selected = get_projected_candidate().projection.selected_step_ids
        zoned = _make_leaf(
            "n1.1",
            "Zoned leaf",
            "input",
            projected_step_ids=(selected[0],),
            realizations=make_step_realizations((selected[0],)),
        )
        unzoned = AttackTreeNode(
            id="n1.2",
            label="Unzoned leaf",
            gate=GateType.LEAF,
            zone=None,
            action=ExternalPreconditionAction(),
            projected_step_ids=(selected[1],),
            realizations=make_step_realizations((selected[1],)),
        )

        spec = build_behavior_spec_from_tree(
            _tree_with_leaves([zoned, unzoned]), make_projection_block()
        )

        assert "When Zoned leaf (input)" in spec.gherkin_text
        assert "Unzoned leaf" in spec.gherkin_text
        assert "Unzoned leaf (None)" not in spec.gherkin_text

    def test_compilation_is_deterministic_and_ignores_gherkin_text_argument(
        self,
    ) -> None:
        leaves = self._projected_leaves()
        first = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves), make_projection_block()
        )
        second = build_behavior_spec_from_tree(
            _tree_with_leaves(leaves),
            make_projection_block(),
            gherkin_text="LLM-authored text is cross-checked, never spliced",
        )

        assert first == second
        assert "LLM-authored text" not in first.gherkin_text
