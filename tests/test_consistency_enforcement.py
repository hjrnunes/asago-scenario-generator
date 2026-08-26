"""Tests for post-generation consistency enforcement passes.

Covers:
- Leaf counting (_count_leaves)
- Parsimony check: tree with exactly budget leaves passes, budget+1 fails
- Zone consistency: missing zone detected, all zones present passes
- Step-node correspondence: ratio below 0.7 fails, at 0.7 passes
- _check_consistency integration: returns all violations at once
- Retry loop behavior in generate_scenario (mocked)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import compute_tool_id
from asago_scenario_generator.models.projection_envelope import ProjectionTraceabilityResult
from asago_scenario_generator.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate import (
    _check_consistency,
    _check_non_actionable_leaves,
    _count_leaves,
)
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_leaf(node_id: str, zone: str = "input", **kwargs) -> AttackTreeNode:
    """Create a minimal LEAF node."""
    action = (
        ToolInvocationAction(tool_id=compute_tool_id("test_tool", "A test tool"))
        if zone == "tool_execution"
        else AiSystemAction()
    )
    return AttackTreeNode(
        id=node_id,
        label=f"Leaf {node_id}",
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        **kwargs,
    )


def _make_tree(root: AttackTreeNode) -> AttackTree:
    """Build a minimal AttackTree."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )


def _make_narrative(
    zone_sequence: list[str],
    step_count: int = 3,
) -> NarrativeLayer:
    """Build a minimal NarrativeLayer with given zones and step count."""
    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zone_sequence[i % len(zone_sequence)],
            action=f"Step {i + 1} action.",
            effect=f"Step {i + 1} effect.",
            projected_step_ids=(f"step.{i + 1}",),
            realizations=make_realizations(
                (f"step.{i + 1}",),
                action_kind="prepare",
                executor_role="attacker",
                boundary_position="crossing",
            ),
        )
        for i in range(step_count)
    ]
    return NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=zone_sequence,
        steps=steps,
    )


def _make_or_root(*children: AttackTreeNode) -> AttackTreeNode:
    """Create an OR root node with given children."""
    return AttackTreeNode(
        id="n1",
        label="Root",
        gate=GateType.OR,
        zone="input",
        children=list(children),
    )


def _make_and_node(
    node_id: str, *children: AttackTreeNode, zone: str = "input"
) -> AttackTreeNode:
    """Create an AND gate node with given children."""
    return AttackTreeNode(
        id=node_id,
        label=f"AND gate {node_id}",
        gate=GateType.AND,
        zone=zone,
        children=list(children),
    )


# ---------------------------------------------------------------------------
# Tests: _count_leaves
# ---------------------------------------------------------------------------


class TestCountLeaves:
    """Tests for the _count_leaves helper function."""

    def test_single_leaf(self) -> None:
        """A single LEAF node has 1 leaf."""
        leaf = _make_leaf("n1", zone="input")
        # AttackTree requires root id="n1", but _count_leaves works on nodes
        assert _count_leaves(leaf) == 1

    def test_or_with_two_leaves(self) -> None:
        """OR node with 2 LEAF children has 2 leaves."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 2

    def test_nested_tree(self) -> None:
        """Nested tree: OR -> (AND -> 2 leaves, LEAF) = 3 leaves."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 3

    def test_deep_tree(self) -> None:
        """Deeply nested tree counts all leaves correctly."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_and_node(
                    "n1.1.1",
                    _make_leaf("n1.1.1.1"),
                    _make_leaf("n1.1.1.2"),
                ),
                _make_leaf("n1.1.2"),
            ),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 4


# ---------------------------------------------------------------------------
# Tests: parsimony check
# ---------------------------------------------------------------------------


class TestParsimonyCheck:
    """Parsimony enforcement: leaf count vs. budget."""

    def test_exactly_at_budget_passes(self) -> None:
        """Tree with exactly budget leaves produces no parsimony violation."""
        # Budget = 4 (2*1 + 2 for 1 technique)
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=4)

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        assert not any("parsimony" in v for v in violations)

    def test_one_over_budget_fails(self) -> None:
        """Tree with budget+1 leaves triggers parsimony violation."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
                _make_leaf("n1.2.3"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=5)

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        parsimony_violations = [v for v in violations if "parsimony" in v]
        assert len(parsimony_violations) == 1
        assert "5 leaves > 4 budget" in parsimony_violations[0]

    def test_under_budget_passes(self) -> None:
        """Tree with fewer leaves than budget produces no parsimony violation."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=5)

        assert not any("parsimony" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: zone-sequence consistency
# ---------------------------------------------------------------------------


class TestZoneConsistency:
    """Zone-sequence check: every narrative zone must appear in the tree."""

    def test_all_zones_present_passes(self) -> None:
        """No violation when tree covers all narrative zones."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        assert not any("zone-sequence" in v for v in violations)

    def test_missing_zone_detected(self) -> None:
        """Violation when narrative zone is missing from tree."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="input"),
        )
        tree = _make_tree(root)
        # Narrative mentions "reasoning" but tree has only "input"
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        zone_violations = [v for v in violations if "zone-sequence" in v]
        assert len(zone_violations) == 1
        assert "reasoning" in zone_violations[0]

    def test_tree_has_extra_zones_ok(self) -> None:
        """No violation when tree has zones not in narrative (tree can be broader)."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
            _make_leaf("n1.3", zone="tool_execution"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=3)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        assert not any("zone-sequence" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: step-node correspondence
# ---------------------------------------------------------------------------


class TestStepNodeCorrespondence:
    """Step-node correspondence: min/max ratio must meet floor."""

    def test_ratio_at_floor_passes(self) -> None:
        """Ratio exactly at 0.7 floor produces no violation."""
        # 7 steps, 10 leaves -> ratio = 7/10 = 0.7
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=7)

        violations = _check_consistency(tree, narrative, parsimony_budget=20)

        assert not any("step-node" in v for v in violations)

    def test_ratio_below_floor_fails(self) -> None:
        """Ratio below 0.7 floor triggers step-node violation."""
        # 2 steps, 10 leaves -> ratio = 2/10 = 0.2
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=20)

        step_violations = [v for v in violations if "step-node" in v]
        assert len(step_violations) == 1
        assert "0.20 < 0.7 floor" in step_violations[0]

    def test_equal_steps_and_leaves_passes(self) -> None:
        """Ratio of 1.0 (equal steps and leaves) passes."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
            _make_leaf("n1.3"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=3)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        assert not any("step-node" in v for v in violations)

    def test_custom_floor(self) -> None:
        """Custom floor value is respected."""
        # 3 steps, 5 leaves -> ratio = 3/5 = 0.6
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
                _make_leaf("n1.1.3"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=3)

        # With floor=0.5, ratio 0.6 passes
        violations_low = _check_consistency(
            tree, narrative, parsimony_budget=10, step_node_floor=0.5
        )
        assert not any("step-node" in v for v in violations_low)

        # With floor=0.7, ratio 0.6 fails
        violations_high = _check_consistency(
            tree, narrative, parsimony_budget=10, step_node_floor=0.7
        )
        assert any("step-node" in v for v in violations_high)


# ---------------------------------------------------------------------------
# Tests: _check_consistency integration
# ---------------------------------------------------------------------------


class TestCheckConsistencyIntegration:
    """_check_consistency returns multiple violations when all checks fail."""

    def test_all_checks_fail(self) -> None:
        """All three checks can fail simultaneously."""
        # 10 leaves > budget 4 -> parsimony fails
        # narrative zone "reasoning" missing from tree -> zone fails
        # 2 steps, 10 leaves -> ratio 0.2 < 0.7 -> step-node fails
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}", zone="input") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}", zone="input") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        assert len(violations) == 3
        assert any("parsimony" in v for v in violations)
        assert any("zone-sequence" in v for v in violations)
        assert any("step-node" in v for v in violations)

    def test_no_violations(self) -> None:
        """Clean tree/narrative combination produces zero violations."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
            _make_leaf("n1.3", zone="input"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=3)

        violations = _check_consistency(tree, narrative, parsimony_budget=5)

        assert violations == []


# ---------------------------------------------------------------------------
# Tests: retry loop in generate_scenario (mocked Call 2)
# ---------------------------------------------------------------------------


@patch(
    "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
    new=MagicMock(return_value=ProjectionTraceabilityResult(valid=True, violations=[])),
)
class TestConsistencyRetryLoop:
    """Verify the retry loop re-invokes Call 2 on consistency violations.

    _assemble_envelope is mocked; traceability validation is patched to
    valid (covered by the dedicated traceability suite).
    """

    def _make_call_attack_tree_result(
        self,
        leaf_count: int,
        zones: list[str],
        threat_id: str | None = None,
        technique_id: str | None = None,
    ):
        """Build a mock return value for _call_attack_tree."""
        children = [
            _make_leaf(
                f"n1.{i + 1}",
                zone=zones[i % len(zones)],
                **({"threat_id": threat_id} if threat_id else {}),
                **({"technique_id": technique_id} if technique_id and i == 0 else {}),
            )
            for i in range(leaf_count)
        ]
        root = _make_or_root(*children)
        tree = _make_tree(root)
        result = MagicMock()
        result.content = "mock"
        return tree, result

    @patch(
        "asago_scenario_generator.pipeline.generate._validate_technique_zone_compatibility",
        return_value=0,
    )
    @patch(
        "asago_scenario_generator.pipeline.generate._strip_non_skeleton_techniques",
        return_value=0,
    )
    @patch("asago_scenario_generator.pipeline.generate._warn_dominant_threat_id_crossref")
    @patch("asago_scenario_generator.pipeline.generate._validate_actor_type")
    @patch("asago_scenario_generator.pipeline.generate._assemble_envelope")
    @patch("asago_scenario_generator.pipeline.generate._call_behavior_spec")
    @patch("asago_scenario_generator.pipeline.generate._call_attack_tree")
    @patch("asago_scenario_generator.pipeline.generate._call_narrative")
    @patch("asago_scenario_generator.pipeline.generate._call_actor_profile")
    def test_retry_on_violation_then_clean(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
        mock_tz_compat,
    ) -> None:
        """Call 2 is retried once when first attempt has violations, second is clean."""
        # First call: 10 leaves with budget 4 -> parsimony violation
        bad_tree, bad_result = self._make_call_attack_tree_result(
            10, ["input", "reasoning"]
        )
        # Second call: 4 leaves with matching threat_id + technique -> passes
        good_tree, good_result = self._make_call_attack_tree_result(
            4, ["input", "reasoning"], threat_id="T1", technique_id="AML.T0051"
        )

        mock_call2.side_effect = [
            (bad_tree, bad_result),
            (good_tree, good_result),
        ]

        # Mock Call 0 (actor profile)
        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0, None)
        mock_validate_actor.return_value = mock_actor

        # Mock Call 1 (narrative)
        narrative = _make_narrative(["input", "reasoning"], step_count=4)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        # Mock Call 3 (behavior spec)
        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        # Mock envelope assembly
        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        # Build seed and profile
        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from asago_scenario_generator.pipeline.generate import generate_scenario

        _envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            candidate_id="",
            pinned_technique_ids=["AML.T0051"],
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        # Call 2 should have been invoked twice (initial + 1 retry)
        assert mock_call2.call_count == 2

    @patch(
        "asago_scenario_generator.pipeline.generate._validate_technique_zone_compatibility",
        return_value=0,
    )
    @patch(
        "asago_scenario_generator.pipeline.generate._strip_non_skeleton_techniques",
        return_value=0,
    )
    @patch("asago_scenario_generator.pipeline.generate._warn_dominant_threat_id_crossref")
    @patch("asago_scenario_generator.pipeline.generate._validate_actor_type")
    @patch("asago_scenario_generator.pipeline.generate._assemble_envelope")
    @patch("asago_scenario_generator.pipeline.generate._call_behavior_spec")
    @patch("asago_scenario_generator.pipeline.generate._call_attack_tree")
    @patch("asago_scenario_generator.pipeline.generate._call_narrative")
    @patch("asago_scenario_generator.pipeline.generate._call_actor_profile")
    def test_no_retry_when_clean(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
        mock_tz_compat,
    ) -> None:
        """Call 2 is not retried when the first attempt is clean."""
        good_tree, good_result = self._make_call_attack_tree_result(
            3, ["input", "reasoning"], threat_id="T1", technique_id="AML.T0051"
        )
        mock_call2.return_value = (good_tree, good_result)

        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0, None)
        mock_validate_actor.return_value = mock_actor

        narrative = _make_narrative(["input", "reasoning"], step_count=3)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from asago_scenario_generator.pipeline.generate import generate_scenario

        _envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            candidate_id="",
            pinned_technique_ids=["AML.T0051"],
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        # Call 2 should have been invoked only once
        assert mock_call2.call_count == 1

    @patch(
        "asago_scenario_generator.pipeline.generate._validate_technique_zone_compatibility",
        return_value=0,
    )
    @patch("asago_scenario_generator.pipeline.generate._strip_non_skeleton_techniques")
    @patch("asago_scenario_generator.pipeline.generate._warn_dominant_threat_id_crossref")
    @patch("asago_scenario_generator.pipeline.generate._validate_actor_type")
    @patch("asago_scenario_generator.pipeline.generate._assemble_envelope")
    @patch("asago_scenario_generator.pipeline.generate._call_behavior_spec")
    @patch("asago_scenario_generator.pipeline.generate._call_attack_tree")
    @patch("asago_scenario_generator.pipeline.generate._call_narrative")
    @patch("asago_scenario_generator.pipeline.generate._call_actor_profile")
    def test_max_retries_exhausted(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
        mock_tz_compat,
    ) -> None:
        """All retries exhausted: scenario is kept but Call 2 invoked 3 times total."""
        # All 3 calls return violation (10 leaves > budget 4)
        bad_tree, bad_result = self._make_call_attack_tree_result(
            10, ["input", "reasoning"]
        )
        mock_call2.return_value = (bad_tree, bad_result)

        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0, None)
        mock_validate_actor.return_value = mock_actor

        narrative = _make_narrative(["input", "reasoning"], step_count=4)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from asago_scenario_generator.pipeline.generate import generate_scenario

        # Should NOT raise — scenario is kept despite violations
        _envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            candidate_id="",
            pinned_technique_ids=["AML.T0051"],
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        # 1 initial + 2 retries = 3
        assert mock_call2.call_count == 3


# ---------------------------------------------------------------------------
# Tests: missing scenario threat_id check (k4ja)
# ---------------------------------------------------------------------------


class TestMissingScenarioThreatId:
    """Check 4: at least one tree node must carry the scenario's threat_id."""

    def test_matching_threat_id_no_violation(self) -> None:
        """Tree with a node carrying the scenario's threat_id passes."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input", threat_id="T7"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=10, threat_id="T7"
        )

        assert not any("missing-scenario-threat-id" in v for v in violations)

    def test_different_threat_ids_but_not_scenario(self) -> None:
        """Tree with threat_ids that don't include the scenario's triggers violation."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input", threat_id="T1"),
            _make_leaf("n1.2", zone="reasoning", threat_id="T3"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=10, threat_id="T7"
        )

        threat_violations = [v for v in violations if "missing-scenario-threat-id" in v]
        assert len(threat_violations) == 1
        assert "T7" in threat_violations[0]

    def test_no_threat_ids_at_all(self) -> None:
        """Tree with no threat_ids triggers violation."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=10, threat_id="T7"
        )

        threat_violations = [v for v in violations if "missing-scenario-threat-id" in v]
        assert len(threat_violations) == 1
        assert "'none'" in threat_violations[0] or "none" in threat_violations[0]

    def test_threat_id_none_skips_check(self) -> None:
        """When threat_id is None, the check is skipped entirely."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=10, threat_id=None
        )

        assert not any("missing-scenario-threat-id" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: tool-execution leaf grounding check (xij7)
# ---------------------------------------------------------------------------


class TestToolExecutionLeafGrounding:
    """Check 5: tool_execution leaves must reference a tool from inventory."""

    def test_leaf_with_tool_name_no_violation(self) -> None:
        """Leaf with tool name in label passes."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="tool_execution"),
        )
        # Set a label containing the tool name
        root.children[1].label = "Invoke database_query to extract data"
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "tool_execution"], step_count=2)

        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=10,
            tool_names=["database_query", "send_email"],
        )

        assert not any("ungrounded-tool-leaf" in v for v in violations)

    def test_typed_tool_leaf_with_generic_label_is_grounded(self) -> None:
        """Typed tool identity makes a generic prose label irrelevant."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="tool_execution"),
        )
        root.children[1].label = "Execute malicious operation"
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "tool_execution"], step_count=2)

        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=10,
            tool_names=["database_query", "send_email"],
        )

        assert not any("ungrounded-tool-leaf" in v for v in violations)

    def test_no_tool_names_skips_check(self) -> None:
        """When tool_names is None, the check is skipped."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="tool_execution"),
        )
        root.children[1].label = "Execute malicious operation"
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "tool_execution"], step_count=2)

        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=10,
            tool_names=None,
        )

        assert not any("ungrounded-tool-leaf" in v for v in violations)

    def test_non_tool_execution_leaf_not_checked(self) -> None:
        """Non-tool_execution leaf with generic label is not checked."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        root.children[0].label = "Generic attacker action"
        root.children[1].label = "Generic reasoning step"
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=10,
            tool_names=["database_query"],
        )

        assert not any("ungrounded-tool-leaf" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: non-actionable leaf check (Check 6)
# ---------------------------------------------------------------------------


class TestNonActionableLeaves:
    """Check 6: flag unannotated observation leaves."""

    def test_two_observation_leaves_violation(self) -> None:
        """Tree with 2 unannotated observation leaves triggers violation."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
            _make_leaf("n1.3", zone="reasoning"),
        )
        root.children[1].label = "Confirm exfiltration channel is open"
        root.children[2].label = "Observe system response patterns"
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=3)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        non_actionable = [v for v in violations if "non-actionable-leaves" in v]
        assert len(non_actionable) == 1
        assert "n1.2" in non_actionable[0]
        assert "n1.3" in non_actionable[0]

    def test_one_observation_leaf_no_violation(self) -> None:
        """Tree with only 1 observation leaf does not trigger (below threshold)."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        root.children[1].label = "Verify credentials are valid"

        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)

        assert not any("non-actionable-leaves" in v for v in violations)

    def test_observation_keyword_with_technique_id_no_violation(self) -> None:
        """Observation keyword present but leaf has technique_id -- not flagged."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning", technique_id="AML.T0051"),
            _make_leaf("n1.3", zone="reasoning", technique_id="AML.T0067"),
        )
        root.children[1].label = "Confirm injection path via tool"
        root.children[2].label = "Monitor agent response to exploit"

        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)

        assert not any("non-actionable-leaves" in v for v in violations)

    def test_non_observation_unannotated_no_violation(self) -> None:
        """Unannotated leaf with non-observation label is not flagged."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="tool_execution"),
            _make_leaf("n1.3", zone="reasoning"),
        )
        root.children[1].label = "Invoke database query tool"
        root.children[2].label = "Craft malicious prompt"

        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)

        assert not any("non-actionable-leaves" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: direct integration_interaction in tool_execution (cmps.9 review 2.1)
# ---------------------------------------------------------------------------


class TestDirectIntegrationInToolExecution:
    """A direct integration_interaction in tool_execution must not trigger
    false consistency failures (cmps.9 second review correction 1).

    The authoritative ACTION_ZONE_RULES matrix allows both tool_invocation
    and integration_interaction in tool_execution.  The grounding check
    must accept either, and the consistency path must not retry or flag
    a valid typed direct integration.
    """

    def test_integration_interaction_in_tool_execution_no_violation(self) -> None:
        """An integration_interaction leaf in tool_execution passes grounding."""
        from asago_scenario_generator.models.attack_tree import IntegrationInteractionAction

        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            AttackTreeNode(
                id="n1.2",
                label="Direct integration interaction",
                gate=GateType.LEAF,
                zone="tool_execution",
                action=IntegrationInteractionAction(
                    integration_id="int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "tool_execution"], step_count=2)

        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=10,
            tool_names=["database_query"],
        )

        # No untyped-tool-execution violation for the integration leaf
        assert not any("untyped-tool-execution" in v for v in violations)

    def test_integration_interaction_grounding_no_violation(self) -> None:
        """Direct grounding check accepts integration_interaction."""
        from asago_scenario_generator.models.attack_tree import IntegrationInteractionAction
        from asago_scenario_generator.pipeline.generate.tree_validation import (
            _check_tool_execution_leaf_grounding,
        )

        node = AttackTreeNode(
            id="n1",
            label="Direct integration call",
            gate=GateType.LEAF,
            zone="tool_execution",
            action=IntegrationInteractionAction(
                integration_id="int:v1:cccccccccccccccccccccccccccccccc",
            ),
        )
        violations: list[str] = []
        _check_tool_execution_leaf_grounding(node, violations)
        assert not any("untyped-tool-execution" in v for v in violations)

    def test_ai_action_in_tool_execution_still_flagged(self) -> None:
        """An ai_system_action in tool_execution is still flagged (not a
        valid typed action for that zone per the matrix)."""
        from asago_scenario_generator.pipeline.generate.tree_validation import (
            _check_tool_execution_leaf_grounding,
        )

        node = AttackTreeNode(
            id="n1",
            label="AI reasoning in tool zone",
            gate=GateType.LEAF,
            zone="tool_execution",
            action=AiSystemAction(),
        )
        violations: list[str] = []
        _check_tool_execution_leaf_grounding(node, violations)
        assert any("untyped-tool-execution" in v for v in violations)
