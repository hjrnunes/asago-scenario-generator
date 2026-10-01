"""Tests for goal_category alignment validation in validate_scenario_semantics.

Covers:
- 11a: Supply-chain goal on non-supply-chain actor (goal_actor_mismatch)
- 11b: Data exfiltration goal on tools with no data-moving operation (goal_mechanism_mismatch)
- 11c: Safety bypass goal on social engineering attack (goal_mechanism_mismatch)
- Non-matching goal categories pass cleanly
"""

from __future__ import annotations

from datetime import UTC, datetime

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ToolInventoryEntry,
    compute_tool_id,
)
from asago_scenario_generator.models.scenario import (
    ActorProfile,
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
from asago_scenario_generator.pipeline.validation import validate_scenario_semantics
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_AttackTreeNode = AttackTreeNode


def AttackTreeNode(**kwargs):
    """Build leaves with an action matching their test zone."""
    if kwargs.get("gate") == GateType.LEAF:
        action = (
            ToolInvocationAction(tool_id=compute_tool_id("test_tool", "A test tool"))
            if kwargs.get("zone") == "tool_execution"
            else AiSystemAction()
        )
        kwargs.setdefault("action", action)
    return _AttackTreeNode(**kwargs)


def _make_profile(
    zones_active: list[str] | None = None,
    tool_name: str = "test_tool",
    supported_operations: tuple[str, ...] | None = None,
) -> CapabilityProfile:
    if zones_active is None:
        zones_active = ["input", "reasoning", "tool_execution"]
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=["user prompts (zone 1)"],
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(
                name=tool_name,
                description="A test tool",
                supported_operations=supported_operations,
            ),
        ],
    )


def _make_envelope(
    actor_type: str = "cybercriminal",
    goal_category: str | None = None,
    zone_sequence: list[str] | None = None,
    tree_children: list[AttackTreeNode] | None = None,
    narrative_summary: str = "A test summary.",
    narrative_steps: list[NarrativeStep] | None = None,
    seed_metadata: dict | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for goal_category tests."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

    if tree_children is None:
        tree_children = [
            AttackTreeNode(
                id="n1.1",
                label="Step 1",
                gate=GateType.LEAF,
                zone="input",
                technique_id="AML.T0051.000",
            ),
            AttackTreeNode(
                id="n1.2",
                label="Step 2",
                gate=GateType.LEAF,
                zone="reasoning",
            ),
        ]

    if narrative_steps is None:
        narrative_steps = [
            NarrativeStep(
                step_number=1,
                zone=zone_sequence[0],
                action="Crafting a malicious prompt.",
                effect="System processes input.",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary=narrative_summary,
        entry_point="user prompts (zone 1)",
        zone_sequence=zone_sequence,
        steps=narrative_steps,
    )

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=tree_children,
        ),
    )

    actor_profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["System accepts user input."],
        desires=["Exfiltrate data."],
        intentions=["Inject crafted payload."],
        resources=["Open-source tools."],
        goal_category=goal_category,
    )

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
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=zone_sequence,
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

    if seed_metadata is None:
        seed_metadata = {
            "seed_id": "AP-T1-01",
            "threat_id": "T1",
            "threat_name": "Test Threat",
        }

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id="scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
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
        scenario_seed_metadata=seed_metadata,
        actor_profile=actor_profile,
    )


def _find_violations(envelope: ScenarioEnvelope, rule: str) -> list:
    """Extract semantic violations matching a rule from the envelope."""
    if envelope.validation is None or envelope.validation.semantic is None:
        return []
    return [v for v in envelope.validation.semantic.violations if v.rule == rule]


# ---------------------------------------------------------------------------
# Tests: 11a — Supply-chain goal on non-supply-chain actor
# ---------------------------------------------------------------------------


class TestGoalActorMismatch:
    """IN-7 goal on non-supply-chain actors triggers goal_actor_mismatch."""

    def test_supply_chain_goal_on_cybercriminal_flags(self) -> None:
        """IN-7 goal + cybercriminal actor type -> violation."""
        envelope = _make_envelope(
            actor_type="cybercriminal",
            goal_category="IN-7",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "goal_actor_mismatch")
        assert len(violations) == 1
        assert "IN-7" in violations[0].message
        assert "cybercriminal" in violations[0].message
        assert violations[0].severity == "moderate"

    def test_supply_chain_goal_on_adversarial_user_flags(self) -> None:
        """IN-7 goal + adversarial-user -> violation."""
        envelope = _make_envelope(
            actor_type="adversarial-user",
            goal_category="IN-7",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "goal_actor_mismatch")
        assert len(violations) == 1

    def test_supply_chain_goal_on_nation_state_passes(self) -> None:
        """IN-7 goal + nation-state actor -> no violation."""
        envelope = _make_envelope(
            actor_type="nation-state",
            goal_category="IN-7",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "goal_actor_mismatch")
        assert len(violations) == 0

    def test_non_in7_goal_on_cybercriminal_passes(self) -> None:
        """Non-IN-7 goal + cybercriminal -> no violation."""
        envelope = _make_envelope(
            actor_type="cybercriminal",
            goal_category="AB-3",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "goal_actor_mismatch")
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# Tests: 11b — Data exfiltration goal on tools with no data-moving operation
# ---------------------------------------------------------------------------


class TestGoalMechanismMismatchToolOperations:
    """PR-1 goal with leaves on tools that move no data triggers mismatch."""

    def test_pr1_goal_with_non_data_moving_tool_leaf_flags(self) -> None:
        """PR-1 goal + a tool reviewed as execute-only -> violation."""
        mismatched_leaf = AttackTreeNode(
            id="n1.2",
            label="Invoke the execute-only service",
            gate=GateType.LEAF,
            zone="tool_execution",
            action=ToolInvocationAction(
                tool_id=compute_tool_id("batch_runner", "A test tool")
            ),
        )
        envelope = _make_envelope(
            goal_category="PR-1",
            tree_children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step 1",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051.000",
                ),
                mismatched_leaf,
            ],
        )
        profile = _make_profile(
            tool_name="batch_runner", supported_operations=("execute_code",)
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "goal_mechanism_mismatch")
        assert len(violations) >= 1
        assert any("PR-1" in v.message for v in violations)
        assert any(v.severity == "minor" for v in violations)

    def test_pr1_goal_with_unreviewed_tool_leaf_passes(self) -> None:
        """PR-1 goal + a tool with unknown operations -> no violation."""
        unreviewed_leaf = AttackTreeNode(
            id="n1.2",
            label="Extract user data via database query",
            gate=GateType.LEAF,
            zone="tool_execution",
        )
        envelope = _make_envelope(
            goal_category="PR-1",
            tree_children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step 1",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051.000",
                ),
                unreviewed_leaf,
            ],
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        # Filter only for 11b tool-operation mismatch
        violations = [
            v
            for v in _find_violations(envelope, "goal_mechanism_mismatch")
            if "tool leaves" in v.message
        ]
        assert len(violations) == 0

    def test_pr1_goal_with_data_retrieving_tool_leaf_passes(self) -> None:
        """PR-1 goal + a tool reviewed as retrieving data -> no violation."""
        retrieving_leaf = AttackTreeNode(
            id="n1.2",
            label="Query the record service",
            gate=GateType.LEAF,
            zone="tool_execution",
            action=ToolInvocationAction(
                tool_id=compute_tool_id("record_reader", "A test tool")
            ),
        )
        envelope = _make_envelope(
            goal_category="PR-1",
            tree_children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step 1",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051.000",
                ),
                retrieving_leaf,
            ],
        )
        profile = _make_profile(
            tool_name="record_reader",
            supported_operations=("retrieve_data", "execute_code"),
        )
        validate_scenario_semantics([envelope], profile)

        assert not [
            v
            for v in _find_violations(envelope, "goal_mechanism_mismatch")
            if "tool leaves" in v.message
        ]


# ---------------------------------------------------------------------------
# Tests: 11c — Safety bypass goal on social engineering attack
# ---------------------------------------------------------------------------


class TestGoalMechanismMismatchSocialEngineering:
    """AB-1 goal with social engineering narrative triggers mismatch."""

    def test_ab1_goal_with_phishing_narrative_flags(self) -> None:
        """AB-1 goal + narrative mentioning 'phishing' -> violation."""
        envelope = _make_envelope(
            goal_category="AB-1",
            narrative_summary="A phishing campaign targeting employees.",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = [
            v
            for v in _find_violations(envelope, "goal_mechanism_mismatch")
            if "social engineering" in v.message
        ]
        assert len(violations) == 1
        assert violations[0].severity == "minor"

    def test_ab1_goal_with_impersonation_narrative_flags(self) -> None:
        """AB-1 goal + narrative mentioning 'impersonat' -> violation."""
        envelope = _make_envelope(
            goal_category="AB-1",
            narrative_steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Impersonating a trusted user.",
                    effect="System is deceived.",
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
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = [
            v
            for v in _find_violations(envelope, "goal_mechanism_mismatch")
            if "social engineering" in v.message
        ]
        assert len(violations) == 1

    def test_ab1_goal_without_se_narrative_passes(self) -> None:
        """AB-1 goal + no social engineering keywords -> no violation."""
        envelope = _make_envelope(
            goal_category="AB-1",
            narrative_summary="A jailbreak attempt bypassing content filters.",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        violations = [
            v
            for v in _find_violations(envelope, "goal_mechanism_mismatch")
            if "social engineering" in v.message
        ]
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# Tests: non-matching goal categories pass cleanly
# ---------------------------------------------------------------------------


class TestNonMatchingGoalCategoryPasses:
    """Non-matching goal categories produce no goal_actor/goal_mechanism violations."""

    def test_no_goal_category_no_violations(self) -> None:
        """No goal_category set -> no goal-related violations."""
        envelope = _make_envelope(goal_category=None)
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        actor_violations = _find_violations(envelope, "goal_actor_mismatch")
        mechanism_violations = _find_violations(envelope, "goal_mechanism_mismatch")
        assert len(actor_violations) == 0
        assert len(mechanism_violations) == 0

    def test_unrelated_goal_no_violations(self) -> None:
        """AV-1 goal -> no goal_actor or goal_mechanism violations."""
        envelope = _make_envelope(
            goal_category="AV-1",
            actor_type="cybercriminal",
        )
        profile = _make_profile()
        validate_scenario_semantics([envelope], profile)

        actor_violations = _find_violations(envelope, "goal_actor_mismatch")
        mechanism_violations = _find_violations(envelope, "goal_mechanism_mismatch")
        assert len(actor_violations) == 0
        assert len(mechanism_violations) == 0
