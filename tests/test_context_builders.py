"""Tests for pure context-builder functions (build_call{0,1,2,3}_context).

These functions are independently testable without LLM calls: given a seed
+ profile + prior results, they produce the expected dict of template
variables.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    InitialIngressAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate import (
    build_call0_context,
    build_call1_context,
    build_call2_context,
    build_call3_context,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_seed(
    seed_id: str = "AP-T2-05",
    technique_ids: list[str] | None = None,
    threat_id: str = "T2",
) -> MagicMock:
    seed = MagicMock(spec=ScenarioSeed)
    seed.seed_id = seed_id
    seed.attack_pattern_name = "Test Mechanism"
    seed.attack_pattern_description = "A test mechanism"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.threat_id = threat_id
    seed.atlas_technique_ids = (
        technique_ids if technique_ids is not None else ["AML.T0054"]
    )
    seed.owasp_llm_ids = ["LLM01"]
    seed.agentic_threat_ids = ["T2"]
    seed.owasp_asi_ids = []
    seed.risk_card_ref = None
    seed.min_complexity = None
    seed.laaf_technique_ids = []
    seed.atlas_provenance_ids = []
    seed.owasp_origin = None
    seed.kill_chain = None
    return seed


def _make_profile(
    zones_active: list[str] | None = None,
    entry_points: list[EntryPoint] | None = None,
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    codes = kc_subcodes if kc_subcodes is not None else ["KC1.1"]
    kw = {}
    if any(c.startswith(("KC5.", "KC6.")) for c in codes):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=zones_active
        if zones_active is not None
        else ["input", "reasoning"],
        entry_points=entry_points
        if entry_points is not None
        else [
            EntryPoint(
                name="user prompts via chat interface",
                direction="input",
                controllability="direct",
            ),
        ],
        kc_subcodes=codes,
        confidence="medium",
        **kw,
    )


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user prompts via chat interface",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input [AML.T0054]",
                effect="Input accepted",
                control_point=None,
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
                action="System processes malicious input",
                effect="Reasoning compromised",
                control_point=None,
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


def _make_actor_profile(
    actor_type: str = "adversarial-user",
    capability_level: str = "intermediate",
    goal_category: str | None = None,
    goal_category_name: str | None = None,
    goal_category_parent: str | None = None,
) -> ActorProfile:
    profile = ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=["The system accepts user input"],
        desires=["I want to extract sensitive data"],
        intentions=["I will craft adversarial prompts"],
        resources=["open-source prompt injection toolkits"],
    )
    if goal_category is not None:
        profile.goal_category = goal_category
        profile.goal_category_name = goal_category_name
        profile.goal_category_parent = goal_category_parent
    return profile


def _make_attack_tree(seed_id: str = "AP-T2-05") -> AttackTree:
    return AttackTree(
        id=f"tree-{seed_id}",
        seed_id=seed_id,
        goal="Test goal",
        root=AttackTreeNode(
            id="n1",
            label="Root attack node",
            gate="LEAF",
            zone="input",
            action=InitialIngressAction(
                entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1"
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Tests: build_call0_context
# ---------------------------------------------------------------------------


class TestBuildCall0Context:
    """Tests for build_call0_context."""

    def test_returns_all_required_keys(self):
        """Context dict contains all keys needed by call0 templates."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="A test system",
        )
        # System prompt variables
        assert "minimum_capability_level" in ctx
        assert "compatible_actor_types" in ctx
        # User prompt variables
        assert "use_case" in ctx
        assert "seed" in ctx
        assert "profile" in ctx
        assert "technique_context" in ctx
        assert "technique_framing_0" in ctx
        assert "goal_section" in ctx
        assert "diversity_section" in ctx
        assert "pinned_entry_point" in ctx
        assert "pinned_entry_point_direction" in ctx
        assert "pinned_technique_count" in ctx
        assert "kc_definitions" in ctx
        assert "ontology_context" in ctx

    def test_use_case_passed_through(self):
        """use_case value is passed through unchanged."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="My test system description",
        )
        assert ctx["use_case"] == "My test system description"

    def test_seed_and_profile_passed_through(self):
        """seed and profile objects are passed through unchanged."""
        seed = _make_seed()
        profile = _make_profile()
        ctx = build_call0_context(seed=seed, profile=profile, use_case="test")
        assert ctx["seed"] is seed
        assert ctx["profile"] is profile

    def test_technique_context_uses_seed_techniques_by_default(self):
        """Without pinned techniques, technique_context uses seed techniques."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            profile=_make_profile(),
            use_case="test",
        )
        assert "AML.T0054" in ctx["technique_context"]

    def test_technique_context_uses_pinned_techniques(self):
        """When pinned_technique_ids is set, technique_context uses those."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=["AML.T0051", "AML.T0052"]),
            profile=_make_profile(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert "AML.T0054" in ctx["technique_context"]
        assert "AML.T0051" not in ctx["technique_context"]

    def test_technique_framing_hard_constraint_when_pinned(self):
        """Pinned techniques produce a hard constraint framing."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert "MUST" in ctx["technique_framing_0"]
        assert "hard constraint" in ctx["technique_framing_0"]

    def test_technique_framing_soft_when_not_pinned(self):
        """Without pinned techniques, framing is advisory."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            profile=_make_profile(),
            use_case="test",
        )
        assert "MUST" not in ctx["technique_framing_0"]

    def test_technique_framing_empty_when_no_techniques(self):
        """With no techniques at all, framing is empty."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=[]),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["technique_framing_0"] == ""

    def test_diversity_section_with_forced_actor(self):
        """Forced actor type produces a hard constraint section."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            forced_actor_type="nation-state",
        )
        assert "MUST use actor_type: nation-state" in ctx["diversity_section"]

    def test_diversity_section_with_preferred(self):
        """Preferred actor type produces guidance, not hard constraint."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            preferred_actor_type="cybercriminal",
        )
        assert "Preferred actor type: cybercriminal" in ctx["diversity_section"]

    def test_diversity_section_with_excluded(self):
        """Excluded actor types appear in diversity section."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            excluded_actor_types=["adversarial-user"],
        )
        assert "adversarial-user" in ctx["diversity_section"]
        assert "overused" in ctx["diversity_section"]

    def test_diversity_section_empty_when_no_hints(self):
        """No diversity hints produce empty section."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["diversity_section"] == ""

    def test_goal_section_when_attack_goal_set(self):
        """Attack goal produces a goal guidance section."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            attack_goal={
                "id": "IN-1",
                "name": "Data Exfiltration",
                "description": "Steal sensitive data",
                "category_name": "Integrity",
                "category_description": "Integrity attacks",
            },
        )
        assert "Data Exfiltration" in ctx["goal_section"]
        assert "Integrity" in ctx["goal_section"]

    def test_goal_section_empty_when_no_goal(self):
        """No attack goal produces empty goal section."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["goal_section"] == ""

    def test_pinned_technique_count_defaults_to_1(self):
        """Without pinned techniques, count defaults to 1."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["pinned_technique_count"] == 1

    def test_pinned_technique_count_matches_pinned(self):
        """With pinned techniques, count matches their length."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            pinned_technique_ids=["AML.T0054", "AML.T0053"],
        )
        assert ctx["pinned_technique_count"] == 2

    def test_compatible_actor_types_sorted(self):
        """Compatible actor types are returned sorted."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["compatible_actor_types"] == sorted(ctx["compatible_actor_types"])

    def test_compatible_actor_types_is_list(self):
        """Compatible actor types is a list (not a set)."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert isinstance(ctx["compatible_actor_types"], list)

    def test_minimum_capability_level_is_string(self):
        """minimum_capability_level is a string."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert isinstance(ctx["minimum_capability_level"], str)

    def test_ontology_context_with_pinned_entry_point(self):
        """Ontology context is populated when entry point is pinned."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            profile=_make_profile(),
            use_case="test",
            pinned_entry_point="user prompts via chat interface",
        )
        assert "## Ontology Context" in ctx["ontology_context"]
        assert "user prompts via chat interface" in ctx["ontology_context"]

    def test_kc_definitions_non_empty_with_subcodes(self):
        """KC definitions block is non-empty when profile has subcodes."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(kc_subcodes=["KC1.1"]),
            use_case="test",
        )
        assert "KC1.1" in ctx["kc_definitions"]

    def test_pinned_entry_point_passed_through(self):
        """pinned_entry_point is passed through as-is."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            pinned_entry_point="user prompts via chat interface",
        )
        assert ctx["pinned_entry_point"] == "user prompts via chat interface"

    def test_pinned_entry_point_none_when_not_set(self):
        """pinned_entry_point is None when not provided."""
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["pinned_entry_point"] is None

    def test_tool_inventory_included_in_context(self):
        """tool_inventory from profile is included in context dict."""
        profile = _make_profile(kc_subcodes=["KC5.1"])
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
        )
        assert "tool_inventory" in ctx
        assert len(ctx["tool_inventory"]) == 1
        assert ctx["tool_inventory"][0].name == "test_tool"

    def test_tool_inventory_empty_when_profile_has_none(self):
        """tool_inventory is empty list when profile has no tools."""
        profile = _make_profile(kc_subcodes=["KC1.1"])
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
        )
        assert "tool_inventory" in ctx
        assert ctx["tool_inventory"] == []

    def test_preferred_capability_level_bumped_to_floor(self):
        """preferred_capability_level in diversity_section respects floor."""
        # T3 (Privilege Compromise) is adversarial-only, and with indirect EP
        # the minimum capability floor should be >= intermediate
        ctx = build_call0_context(
            seed=_make_seed(threat_id="T3"),
            profile=_make_profile(
                entry_points=[
                    EntryPoint(
                        name="internal API",
                        direction="input",
                        controllability="indirect",
                    ),
                ],
            ),
            use_case="test",
            preferred_capability_level="novice",
            pinned_entry_point="internal API",
        )
        # The diversity section should show at least intermediate, not novice
        if ctx["diversity_section"]:
            assert "novice" not in ctx["diversity_section"]

    def test_missing_preferred_capability_does_not_create_guidance(self):
        """A computed floor alone must not create a diversity hint."""
        ctx = build_call0_context(
            seed=_make_seed(technique_ids=["AML.T0010"]),
            profile=_make_profile(),
            use_case="test",
            preferred_capability_level=None,
        )

        assert ctx["minimum_capability_level"] == "advanced"
        assert ctx["diversity_section"] == ""

    def test_preferred_capability_at_floor_is_not_overridden(self, caplog):
        """An equal preference should not produce an override diagnostic."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="internal API",
                    direction="input",
                    controllability="indirect",
                )
            ]
        )
        with caplog.at_level("DEBUG"):
            ctx = build_call0_context(
                seed=_make_seed(threat_id="T3"),
                profile=profile,
                use_case="test",
                preferred_capability_level="intermediate",
                pinned_entry_point="internal API",
            )

        assert ctx["minimum_capability_level"] == "intermediate"
        assert "Preferred capability level: intermediate" in ctx["diversity_section"]
        assert "Capability floor override" not in caplog.text

    def test_indirect_entry_point_adds_access_provenance_guidance(self):
        """Indirect ingress includes upstream source evidence guidance."""
        target = EntryPoint(
            name="document feed",
            direction="input",
            controllability="indirect",
        )
        source = EntryPoint(
            name="partner upload",
            direction="input",
            controllability="direct",
        )
        profile = _make_profile(entry_points=[target, source])

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
            pinned_entry_point=target.name,
            pinned_entry_point_id=target.entry_point_id,
        )

        assert (
            "Access Provenance Constraint (MANDATORY)"
            in ctx["access_provenance_section"]
        )
        assert source.name in ctx["access_provenance_section"]

    def test_direct_entry_point_uses_normal_interface_guidance(self):
        """Direct non-insider ingress describes normal interface access."""
        profile = _make_profile()
        target = profile.entry_points[0]

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
            pinned_entry_point=target.name,
            pinned_entry_point_id=target.entry_point_id,
        )

        assert "normal user interface" in ctx["access_provenance_section"]

    def test_direct_insider_entry_point_requires_material_advantage(self):
        """Direct insider ingress requires an explicit material advantage."""
        profile = _make_profile()
        target = profile.entry_points[0]

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
            forced_actor_type="malicious-insider",
            pinned_entry_point=target.name,
            pinned_entry_point_id=target.entry_point_id,
        )

        assert "material_insider_advantage" in ctx["access_provenance_section"]

    def test_system_entry_point_has_no_access_provenance_guidance(self):
        """System-controlled entry points are not actor ingress surfaces."""
        target = EntryPoint(
            name="internal event bus",
            direction="input",
            controllability="system",
        )
        profile = _make_profile(entry_points=[target])

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
            pinned_entry_point=target.name,
            pinned_entry_point_id=target.entry_point_id,
        )

        assert ctx["access_provenance_section"] == ""


# ---------------------------------------------------------------------------
# Tests: build_call1_context
# ---------------------------------------------------------------------------


class TestBuildCall1Context:
    """Tests for build_call1_context."""

    def test_returns_all_required_keys(self):
        """Context dict contains all keys needed by call1 templates."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert "use_case" in ctx
        assert "seed" in ctx
        assert "profile" in ctx
        assert "owasp_llm_formatted" in ctx
        assert "technique_context" in ctx
        assert "technique_framing" in ctx
        assert "actor_section" in ctx
        assert "goal_section" in ctx
        assert "diversity_section" in ctx
        assert "pattern_section" in ctx
        assert "structural_section" in ctx
        assert "pinned_entry_point" in ctx
        assert "pinned_entry_point_direction" in ctx
        assert "kc_definitions" in ctx
        assert "ontology_context" in ctx

    def test_actor_section_populated_with_profile(self):
        """Actor section is populated when actor_profile is provided."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            actor_profile=_make_actor_profile(),
        )
        assert "adversarial-user" in ctx["actor_section"]
        assert "intermediate" in ctx["actor_section"]
        assert (
            "Beliefs" in ctx["actor_section"]
            or "beliefs" in ctx["actor_section"].lower()
        )

    def test_actor_section_empty_without_profile(self):
        """Actor section is empty when no actor_profile is provided."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["actor_section"] == ""

    def test_goal_section_with_actor_goal(self):
        """Goal section populated when actor has a goal category."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            actor_profile=_make_actor_profile(
                goal_category="IN-1",
                goal_category_name="Data Exfiltration",
                goal_category_parent="Integrity",
            ),
        )
        assert "Data Exfiltration" in ctx["goal_section"]

    def test_goal_section_empty_without_actor_goal(self):
        """Goal section empty when actor has no goal category."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            actor_profile=_make_actor_profile(),
        )
        assert ctx["goal_section"] == ""

    def test_prior_titles_in_diversity_section(self):
        """Prior titles appear in the diversity section."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            prior_titles=["Title One", "Title Two"],
        )
        assert "Title One" in ctx["diversity_section"]
        assert "Title Two" in ctx["diversity_section"]
        assert "Previously Generated Titles" in ctx["diversity_section"]

    def test_pinned_entry_point_hard_constraint(self):
        """Pinned entry point produces a hard constraint."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            pinned_entry_point="user prompts via chat interface",
        )
        assert "MUST use this entry point" in ctx["diversity_section"]

    def test_preferred_entry_point_soft_guidance(self):
        """Preferred entry point produces soft guidance."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            preferred_entry_point="admin console",
        )
        assert "Preferred entry point: admin console" in ctx["diversity_section"]

    def test_excluded_entry_points(self):
        """Excluded entry points appear in diversity section."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            excluded_entry_points=["chat interface"],
        )
        assert "chat interface" in ctx["diversity_section"]

    def test_excluded_patterns_in_pattern_section(self):
        """Excluded patterns appear in the pattern section."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            excluded_patterns=["injection", "poisoning"],
        )
        assert "injection" in ctx["pattern_section"]
        assert "poisoning" in ctx["pattern_section"]

    def test_pattern_section_empty_when_no_exclusions(self):
        """Pattern section empty when no exclusions."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["pattern_section"] == ""

    def test_structural_section_with_exclusions(self):
        """Structural section populated with excluded patterns."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            excluded_structural_patterns=["inject->hallucinate->persist"],
        )
        assert ctx["structural_section"] != ""
        assert "Structural" in ctx["structural_section"]

    def test_structural_section_empty_when_no_exclusions(self):
        """Structural section empty when no exclusions."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        assert ctx["structural_section"] == ""

    def test_owasp_llm_formatted(self):
        """OWASP LLM IDs are formatted with names."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
        )
        # LLM01 should be formatted with its name
        assert "LLM01" in ctx["owasp_llm_formatted"]
        assert "Prompt Injection" in ctx["owasp_llm_formatted"]

    def test_novice_actor_diversity_priority(self):
        """Novice actors get capability-level priority note in diversity."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            actor_profile=_make_actor_profile(capability_level="novice"),
            preferred_entry_point="chat",
        )
        assert "NOVICE" in ctx["diversity_section"]
        assert "Capability-level priority" in ctx["diversity_section"]

    def test_non_novice_actor_no_priority_note(self):
        """Non-novice actors do not get capability-level priority note."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            actor_profile=_make_actor_profile(capability_level="advanced"),
            preferred_entry_point="chat",
        )
        assert "NOVICE" not in ctx["diversity_section"]

    def test_technique_framing_hard_when_pinned(self):
        """Pinned techniques get hard-constraint framing."""
        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert "MUST" in ctx["technique_framing"]

    def test_technique_framing_soft_when_not_pinned(self):
        """Unpinned techniques get soft framing."""
        ctx = build_call1_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            profile=_make_profile(),
            use_case="test",
        )
        assert "MUST" not in ctx["technique_framing"]


# ---------------------------------------------------------------------------
# Tests: build_call2_context
# ---------------------------------------------------------------------------


class TestBuildCall2Context:
    """Tests for build_call2_context."""

    def test_returns_all_required_keys(self):
        """Context dict contains all keys needed by call2 templates."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert "seed" in ctx
        assert "use_case" in ctx
        assert "arch_section" in ctx
        assert "actor_section" in ctx
        assert "technique_context" in ctx
        assert "technique_constraint" in ctx
        assert "narrative" in ctx
        assert "technique_count" in ctx
        assert "leaf_budget" in ctx
        assert "skeleton_section" in ctx
        assert "ontology_context" in ctx
        assert "skeleton" in ctx

    def test_leaf_budget_formula_one_technique(self):
        """With 1 technique, budget = 2*1+2 = 4."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["technique_count"] == 1
        assert ctx["leaf_budget"] == 4

    def test_leaf_budget_formula_two_techniques(self):
        """With 2 techniques, budget = 2*2+2 = 6."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0054", "AML.T0053"]),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["technique_count"] == 2
        assert ctx["leaf_budget"] == 6

    def test_leaf_budget_zero_techniques(self):
        """With zero techniques, budget defaults to 5."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=[]),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["technique_count"] == 0
        assert ctx["leaf_budget"] == 5

    def test_arch_section_with_profile(self):
        """Architecture section is populated when profile is provided."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
            profile=_make_profile(),
        )
        assert "Active zones" in ctx["arch_section"]
        assert "Entry points" in ctx["arch_section"]

    def test_arch_section_empty_without_profile(self):
        """Architecture section is empty when no profile."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["arch_section"] == ""

    def test_actor_section_with_actor_profile(self):
        """Actor section references capability level when provided."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
            actor_profile=_make_actor_profile(),
        )
        assert "intermediate" in ctx["actor_section"]
        assert "adversarial-user" in ctx["actor_section"]

    def test_actor_section_empty_without_actor(self):
        """Actor section empty when no actor profile."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["actor_section"] == ""

    def test_technique_constraint_with_pinned(self):
        """Technique constraint uses pinned techniques when set."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0051"]),
            narrative=_make_narrative(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert "AML.T0054" in ctx["technique_constraint"]
        assert "MUST" in ctx["technique_constraint"]

    def test_technique_constraint_without_pinned(self):
        """Technique constraint uses seed techniques when no pinned."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0051"]),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert "AML.T0051" in ctx["technique_constraint"]

    def test_technique_constraint_no_techniques(self):
        """No techniques produces 'do not add' constraint."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=[]),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert "Do NOT add technique_id" in ctx["technique_constraint"]

    def test_skeleton_section_with_pinned_techniques_and_names(self):
        """Skeleton section populated when both pinned IDs and names provided."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
            profile=_make_profile(),
            pinned_technique_ids=["AML.T0054"],
            pinned_technique_names=["LLM Jailbreak"],
        )
        assert "AML.T0054" in ctx["skeleton_section"]
        assert "LLM Jailbreak" in ctx["skeleton_section"]
        # skeleton (raw list) should also be populated
        assert len(ctx["skeleton"]) == 1
        assert ctx["skeleton"][0]["technique_id"] == "AML.T0054"

    def test_skeleton_empty_without_names(self):
        """Skeleton empty when pinned names not provided."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert ctx["skeleton_section"] == ""
        assert ctx["skeleton"] == []

    def test_narrative_passed_through(self):
        """Narrative object is passed through unchanged."""
        narrative = _make_narrative()
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=narrative,
            use_case="test",
        )
        assert ctx["narrative"] is narrative

    def test_pinned_overrides_seed_for_budget(self):
        """When pinned_technique_ids is set, budget uses those, not seed."""
        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0051", "AML.T0052", "AML.T0053"]),
            narrative=_make_narrative(),
            use_case="test",
            pinned_technique_ids=["AML.T0054"],
        )
        assert ctx["technique_count"] == 1
        assert ctx["leaf_budget"] == 4  # 2*1+2

    def test_consistency_feedback_included_when_provided(self):
        """consistency_feedback appears in context when provided."""
        feedback = "- parsimony: 10 leaves > 4 budget"
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
            consistency_feedback=feedback,
        )
        assert ctx["consistency_feedback"] == feedback

    def test_consistency_feedback_none_when_omitted(self):
        """consistency_feedback is None when not provided."""
        ctx = build_call2_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            use_case="test",
        )
        assert ctx["consistency_feedback"] is None


# ---------------------------------------------------------------------------
# Tests: build_call3_context
# ---------------------------------------------------------------------------


class TestBuildCall3Context:
    """Tests for build_call3_context."""

    def test_returns_all_required_keys(self):
        """Context dict contains all keys needed by call3 templates."""
        ctx = build_call3_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
        )
        assert "narrative" in ctx
        assert "seed" in ctx
        assert "leaf_catalog" in ctx
        assert "postcondition_ownership" in ctx

    def test_leaf_catalog_contains_tree_leaves(self):
        """Leaf catalog lists every tree leaf with projected step IDs."""
        ctx = build_call3_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
        )
        assert len(ctx["leaf_catalog"]) > 0
        entry = ctx["leaf_catalog"][0]
        assert "leaf_id" in entry
        assert "projected_step_ids" in entry
        assert "action_kind" in entry
        assert "zone" in entry
        assert "eligible_keyword" in entry

    def test_postcondition_ownership_populated_with_projection(self):
        """Postcondition ownership table is populated when projection is given."""
        ctx = build_call3_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
            projection_context={
                "selected_steps": [
                    {
                        "step_id": "step.1",
                        "observable_postconditions": [
                            {
                                "postcondition_id": "post.1",
                                "description": "test",
                                "security_relevant": True,
                                "terminal": False,
                            }
                        ],
                    }
                ],
            },
        )
        assert len(ctx["postcondition_ownership"]) == 1
        entry = ctx["postcondition_ownership"][0]
        assert entry["postcondition_id"] == "post.1"
        assert entry["owning_step_id"] == "step.1"

    def test_narrative_passed_through(self):
        """Narrative object is passed through unchanged."""
        narrative = _make_narrative()
        ctx = build_call3_context(
            seed=_make_seed(),
            narrative=narrative,
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
        )
        assert ctx["narrative"] is narrative

    def test_seed_passed_through(self):
        """Seed object is passed through unchanged."""
        seed = _make_seed()
        ctx = build_call3_context(
            seed=seed,
            narrative=_make_narrative(),
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
        )
        assert ctx["seed"] is seed


# ---------------------------------------------------------------------------
# Integration: context builders produce renderable template vars
# ---------------------------------------------------------------------------


class TestContextBuildersRenderTemplates:
    """Verify that context builder outputs can render the actual Jinja2 templates."""

    def test_call0_context_renders_user_template(self):
        """build_call0_context output renders call0_user.j2 without error."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="A financial AI assistant",
            pinned_entry_point="user prompts via chat interface",
            pinned_technique_ids=["AML.T0054"],
        )
        result = render_prompt("call0_user.j2", **ctx)
        assert "A financial AI assistant" in result
        assert "AML.T0054" in result

    def test_call0_context_renders_system_template(self):
        """build_call0_context output renders call0_system.j2 without error."""
        from asago_scenario_generator.prompts import render_prompt

        profile = _make_profile()
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
        )
        result = render_prompt(
            "call0_system.j2",
            zones_active=profile.zones_active,
            tool_inventory=ctx["tool_inventory"],
        )
        assert "threat intelligence analyst" in result

    def test_call0_system_template_renders_tool_inventory_constraint(self):
        """call0_system.j2 renders tool inventory constraint when tools present."""
        from asago_scenario_generator.prompts import render_prompt

        profile = _make_profile(kc_subcodes=["KC5.1"])
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
        )
        result = render_prompt(
            "call0_system.j2",
            zones_active=profile.zones_active,
            tool_inventory=ctx["tool_inventory"],
        )
        assert "Tool Inventory (INVARIANT)" in result
        assert "test_tool" in result
        assert "A test tool" in result

    def test_call0_system_template_omits_tool_inventory_when_empty(self):
        """call0_system.j2 omits tool inventory section when no tools."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(kc_subcodes=["KC1.1"]),
            use_case="test",
        )
        result = render_prompt(
            "call0_system.j2",
            zones_active=["input", "reasoning"],
            tool_inventory=ctx["tool_inventory"],
        )
        assert "Tool Inventory (INVARIANT)" not in result

    def test_call0_system_template_renders_adaptation_constraint(self):
        """call0_system.j2 always renders Attack Pattern Example Adaptation."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(kc_subcodes=["KC1.1"]),
            use_case="test",
        )
        result = render_prompt(
            "call0_system.j2",
            zones_active=["input", "reasoning"],
            tool_inventory=ctx["tool_inventory"],
        )
        assert "Attack Pattern Example Adaptation (PREFERENCE)" in result
        assert "Never literalize attack pattern examples" in result

    def test_call0_system_template_renders_system_introspection_constraint(self):
        """call0_system.j2 always renders the system-introspection negative constraint."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(kc_subcodes=["KC1.1"]),
            use_case="test",
        )
        result = render_prompt(
            "call0_system.j2",
            zones_active=["input", "reasoning"],
            tool_inventory=ctx["tool_inventory"],
        )
        assert "System-Introspection Negative Constraint (INVARIANT)" in result
        assert "desires MUST NOT target system prompts" in result
        assert "reframed to target the closest domain-data equivalent" in result

    def test_call0_user_template_renders_tool_inventory(self):
        """call0_user.j2 renders tool inventory when tools present."""
        from asago_scenario_generator.prompts import render_prompt

        profile = _make_profile(kc_subcodes=["KC5.1"])
        ctx = build_call0_context(
            seed=_make_seed(),
            profile=profile,
            use_case="test",
            pinned_entry_point="user prompts via chat interface",
            pinned_technique_ids=["AML.T0054"],
        )
        result = render_prompt("call0_user.j2", **ctx)
        assert "Available tools and APIs" in result
        assert "test_tool" in result

    def test_call0_user_template_omits_tool_inventory_when_empty(self):
        """call0_user.j2 omits tool inventory when no tools."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call0_context(
            seed=_make_seed(),
            profile=_make_profile(kc_subcodes=["KC1.1"]),
            use_case="test",
            pinned_entry_point="user prompts via chat interface",
            pinned_technique_ids=["AML.T0054"],
        )
        result = render_prompt("call0_user.j2", **ctx)
        assert "Available tools and APIs" not in result

    def test_call1_context_renders_user_template(self):
        """build_call1_context output renders call1_user.j2 without error."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call1_context(
            seed=_make_seed(),
            profile=_make_profile(),
            use_case="A financial AI assistant",
            actor_profile=_make_actor_profile(),
        )
        result = render_prompt("call1_user.j2", **ctx)
        assert "A financial AI assistant" in result

    def test_call2_context_renders_user_template(self):
        """build_call2_context output renders call2_user.j2 without error."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call2_context(
            seed=_make_seed(technique_ids=["AML.T0054"]),
            narrative=_make_narrative(),
            use_case="A financial AI assistant",
            profile=_make_profile(),
        )
        result = render_prompt("call2_user.j2", **ctx)
        assert "A financial AI assistant" in result
        assert "1 technique(s)" in result

    def test_call3_context_renders_user_template(self):
        """build_call3_context output renders call3_user.j2 without error."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = build_call3_context(
            seed=_make_seed(),
            narrative=_make_narrative(),
            attack_tree=_make_attack_tree(),
            profile=_make_profile(),
            scenario_tag="abc123",
        )
        result = render_prompt("call3_user.j2", **ctx)
        assert "Test narrative" in result

    def test_call3_system_template_contains_capability_boundary_constraint(self):
        """call3_system.j2 contains the capability boundary constraint."""
        from asago_scenario_generator.prompts import render_prompt

        result = render_prompt("call3_system.j2")
        assert "Capability Boundary (INVARIANT)" in result
        assert "Do NOT introduce platform-level security concepts" in result
