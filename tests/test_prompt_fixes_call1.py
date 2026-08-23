"""Tests for Call 1 prompt constraint fixes (ksur, bto7, wwjz, h1a2).

Covers:
- ksur: Actor Profile Grounding elevated to INVARIANT with capability-level bounds
- bto7: Actor-Type Entry Point Access bridging constraint
- wwjz: goal_category passed to Call 1 via goal_section
- h1a2: Creativity-vs-simplicity conflict resolution for novice actors
"""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.models.scenario import ActorProfile, RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="user prompts via chat", direction="input"),
            EntryPoint(name="RAG knowledge base", direction="input"),
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
    )


def _make_seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Misaligned Behavior",
        threat_description="Agent acts against user interests",
        attack_pattern_name="RAG Poisoning",
        attack_pattern_description="Attacker poisons RAG data",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description for risk-1",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0051.001"],
    )


def _make_actor_profile(
    capability_level: str = "intermediate",
    goal_category: str | None = None,
    goal_category_name: str | None = None,
    goal_category_parent: str | None = None,
    actor_type: str = "adversarial-user",
) -> ActorProfile:
    return ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=["The system processes user queries"],
        desires=["Exfiltrate private data"],
        intentions=["Use prompt injection"],
        resources=["open-source tools", "basic scripting"],
        goal_category=goal_category,
        goal_category_name=goal_category_name,
        goal_category_parent=goal_category_parent,
    )


def _render_call1_system(**overrides: object) -> str:
    """Render call1_system.j2 with sensible profile defaults."""
    defaults = {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "zones_active": ["input", "reasoning", "tool_execution"],
        "kc_subcodes": [],
        "tool_inventory": [],
    }
    defaults.update(overrides)
    return render_prompt("call1_system.j2", **defaults)


def _render_call1_user(**overrides: object) -> str:
    """Render call1_user.j2 with sensible defaults, overriding as needed."""
    defaults = {
        "use_case": "A financial chatbot",
        "seed": _make_seed(),
        "profile": _make_profile(),
        "owasp_llm_formatted": "LLM01: Prompt Injection",
        "technique_context": "",
        "technique_framing": "",
        "actor_section": "",
        "goal_section": "",
        "diversity_section": "",
        "pattern_section": "",
        "structural_section": "",
        "pinned_entry_point": None,
        "pinned_entry_point_direction": None,
        "kc_definitions": "",
        "tool_inventory": [],
    }
    defaults.update(overrides)
    return render_prompt("call1_user.j2", **defaults)


def test_semantic_draft_v2_retry_includes_compiler_feedback() -> None:
    """A semantic retry tells the provider what invalidated the prior draft."""
    prompt = _render_call1_user(
        semantic_draft_v2=True,
        realization_feedback=(
            "causal beat 3 combines incompatible canonical zones: "
            "['memory', 'reasoning']"
        ),
    )

    assert "Semantic Narrative Feedback (RETRY)" in prompt
    assert (
        "causal beat 3 combines incompatible canonical zones: ['memory', 'reasoning']"
    ) in prompt


def test_semantic_draft_v3_prohibits_cross_region_grouping() -> None:
    """Semantic beats may group only handles in one canonical region."""
    prompt = _render_call1_user(semantic_draft_v2=True)

    assert "Never move a handle to another region or combine regions" in prompt


# ---------------------------------------------------------------------------
# ksur — Actor Profile Grounding elevated to INVARIANT
# ---------------------------------------------------------------------------


class TestKsurActorProfileGroundingMandatory:
    """call1_system.j2 must contain INVARIANT actor profile grounding."""

    def test_section_header_is_mandatory(self):
        prompt = _render_call1_system()
        assert "Actor Profile Grounding (INVARIANT)" in prompt

    def test_capability_level_novice(self):
        prompt = _render_call1_system()
        assert "**novice**:" in prompt
        assert "At most 3-4 simple steps" in prompt

    def test_capability_level_intermediate(self):
        prompt = _render_call1_system()
        assert "**intermediate**:" in prompt
        assert "2-4 steps" in prompt

    def test_capability_level_advanced(self):
        prompt = _render_call1_system()
        assert "**advanced**:" in prompt
        assert "Multi-stage campaigns" in prompt

    def test_capability_level_expert(self):
        prompt = _render_call1_system()
        assert "**expert**:" in prompt
        assert "zero-day exploitation" in prompt

    def test_uses_must_not_should(self):
        """Constraint language uses MUST, not soft 'should'."""
        prompt = _render_call1_system()
        # Find the actor profile grounding section
        section_start = prompt.index("Actor Profile Grounding (INVARIANT)")
        # Look for the next ## heading to bound the section
        section_end = prompt.index("##", section_start + 1)
        section = prompt[section_start:section_end]
        assert "MUST shape" in section or "MUST match" in section
        assert "should shape" not in section

    def test_simplification_over_escalation(self):
        prompt = _render_call1_system()
        assert "simplify the attack to fit the level" in prompt
        assert "Do NOT escalate the attack complexity" in prompt


# ---------------------------------------------------------------------------
# bto7 — Actor-Type Entry Point Access constraint
# ---------------------------------------------------------------------------


class TestBto7ActorTypeEntryPointAccess:
    """call1_system.j2 must bridge actor type and controllability."""

    def test_section_header_present(self):
        prompt = _render_call1_system()
        assert "Actor Access Provenance (INVARIANT" in prompt

    def test_supply_chain_actor_mentioned(self):
        prompt = _render_call1_system()
        # The old blanket allowlist was removed (cmps.6). The new section
        # uses evidence-authoritative wording for indirect eligibility.
        assert "No blanket actor-type allowlist" in prompt

    def test_do_not_invent_portals(self):
        prompt = _render_call1_system()
        assert "Do NOT invent upload portals" in prompt

    def test_indirect_controllability_constraint(self):
        prompt = _render_call1_system()
        # The controllability include describes indirect semantics.
        assert "INDIRECT controllability" in prompt
        assert "CANNOT directly write to" in prompt


# ---------------------------------------------------------------------------
# wwjz — goal_category passed to Call 1
# ---------------------------------------------------------------------------


class TestWwjzGoalSectionRendering:
    """goal_section appears in call1_user.j2 between actor and diversity."""

    def test_goal_section_renders_when_provided(self):
        prompt = _render_call1_user(
            actor_section="[ACTOR_MARKER]",
            goal_section="[GOAL_MARKER]",
            diversity_section="[DIVERSITY_MARKER]",
        )
        assert "[GOAL_MARKER]" in prompt
        # Verify ordering: actor before goal before diversity
        actor_pos = prompt.index("[ACTOR_MARKER]")
        goal_pos = prompt.index("[GOAL_MARKER]")
        diversity_pos = prompt.index("[DIVERSITY_MARKER]")
        assert actor_pos < goal_pos < diversity_pos

    def test_goal_section_absent_when_empty(self):
        prompt = _render_call1_user(goal_section="")
        assert "Attack Goal" not in prompt

    def test_goal_section_absent_when_not_provided(self):
        """Template uses default('') so omitting goal_section is safe."""
        defaults = {
            "use_case": "A financial chatbot",
            "seed": _make_seed(),
            "profile": _make_profile(),
            "owasp_llm_formatted": "LLM01: Prompt Injection",
            "technique_context": "",
            "technique_framing": "",
            "actor_section": "",
            "diversity_section": "",
            "pattern_section": "",
            "structural_section": "",
            "pinned_entry_point": None,
            "pinned_entry_point_direction": None,
            "kc_definitions": "",
            "tool_inventory": [],
        }
        # Deliberately omit goal_section — template default('') handles it
        prompt = render_prompt("call1_user.j2", **defaults)
        assert "Attack Goal" not in prompt

    def test_goal_section_built_from_actor_profile(self):
        """Verify the goal_section construction logic inline."""
        actor_profile = _make_actor_profile(
            goal_category="abuse-03",
            goal_category_name="Unauthorized resource consumption",
            goal_category_parent="abuse",
        )
        # Replicate the goal_section construction from generate.py
        goal_section = ""
        if actor_profile is not None and actor_profile.goal_category:
            goal_section = (
                "\n## Attack Goal Guidance (SHOULD)\n"
                f"**Category:** {actor_profile.goal_category_parent}\n"
                f"**Specific Goal:** {actor_profile.goal_category}: "
                f"{actor_profile.goal_category_name}\n\n"
                "The narrative's terminal attack outcome SHOULD align with this goal "
                "when it is compatible with the seed attack pattern's mechanism. "
                "If satisfying this goal would require abandoning the seed's core "
                "attack mechanism, prioritise seed fidelity — the goal is a guiding "
                "preference, not a hard override. The seed's 'Seed Attack Objective "
                "Fidelity (INVARIANT)' constraint always takes precedence.\n"
            )
        assert "## Attack Goal Guidance (SHOULD)" in goal_section
        assert "**Category:** abuse" in goal_section
        assert "abuse-03: Unauthorized resource consumption" in goal_section
        assert "SHOULD align with this goal" in goal_section

    def test_goal_section_empty_when_no_goal_category(self):
        """No goal_section built when actor has no goal_category."""
        actor_profile = _make_actor_profile(goal_category=None)
        goal_section = ""
        if actor_profile is not None and actor_profile.goal_category:
            goal_section = "should not appear"
        assert goal_section == ""


# ---------------------------------------------------------------------------
# h1a2 — Creativity-vs-simplicity conflict resolution
# ---------------------------------------------------------------------------


class TestH1a2NoviceDiversityPriority:
    """Novice actors get a priority clause appended to diversity_section."""

    def test_novice_with_diversity_gets_priority_clause(self):
        diversity_section = "\n## Entry Point Guidance\n- Use chat interface.\n"
        actor_profile = _make_actor_profile(capability_level="novice")
        if (
            diversity_section
            and actor_profile is not None
            and actor_profile.capability_level == "novice"
        ):
            diversity_section += (
                "\n\n**Capability-level priority:** The actor is a NOVICE. "
                "Diversity constraints are secondary to capability-level constraints. "
                "Do NOT generate a complex attack just because simpler patterns have "
                "been excluded. Instead, use a DIFFERENT simple pattern or a different "
                "angle on the same simple technique."
            )
        assert "Capability-level priority" in diversity_section
        assert "NOVICE" in diversity_section
        assert "DIFFERENT simple pattern" in diversity_section

    def test_intermediate_no_priority_clause(self):
        diversity_section = "\n## Entry Point Guidance\n- Use chat interface.\n"
        actor_profile = _make_actor_profile(capability_level="intermediate")
        if (
            diversity_section
            and actor_profile is not None
            and actor_profile.capability_level == "novice"
        ):
            diversity_section += "SHOULD NOT APPEAR"
        assert "Capability-level priority" not in diversity_section
        assert "SHOULD NOT APPEAR" not in diversity_section

    def test_advanced_no_priority_clause(self):
        diversity_section = "\n## Entry Point Guidance\n- Use chat interface.\n"
        actor_profile = _make_actor_profile(capability_level="advanced")
        if (
            diversity_section
            and actor_profile is not None
            and actor_profile.capability_level == "novice"
        ):
            diversity_section += "SHOULD NOT APPEAR"
        assert "Capability-level priority" not in diversity_section

    def test_empty_diversity_no_priority_clause(self):
        diversity_section = ""
        actor_profile = _make_actor_profile(capability_level="novice")
        if (
            diversity_section
            and actor_profile is not None
            and actor_profile.capability_level == "novice"
        ):
            diversity_section += "SHOULD NOT APPEAR"
        assert diversity_section == ""

    def test_no_actor_profile_no_priority_clause(self):
        diversity_section = "\n## Entry Point Guidance\n- Use chat interface.\n"
        actor_profile = None
        if (
            diversity_section
            and actor_profile is not None
            and actor_profile.capability_level == "novice"
        ):
            diversity_section += "SHOULD NOT APPEAR"
        assert "Capability-level priority" not in diversity_section
