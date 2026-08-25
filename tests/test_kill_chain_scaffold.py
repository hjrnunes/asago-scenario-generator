"""Tests for kill chain scaffold threading through seeds to generation prompts.

Covers:
1. ScenarioSeed model accepts kill_chain field.
2. expand_seeds() populates kill_chain from pattern data when available.
3. expand_seeds() leaves kill_chain as None when pattern has no kill_chain.
4. Call 1 and Call 2 templates render correctly with and without kill_chain.
5. build_call1_context and build_call2_context pass kill_chain to template vars.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from asago_scenario_generator.pipeline.generate.narrative import build_call1_context
from asago_scenario_generator.pipeline.generate.tree import build_call2_context
from asago_scenario_generator.pipeline.seeds import ScenarioSeed, expand_seeds
from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry
from asago_scenario_generator.prompts import render_prompt
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_KILL_CHAIN = [
    {
        "step": "reconnaissance",
        "tactic": "discovery",
        "techniques": ["AML.T0054", "AML.T0015"],
        "abstract_action": "Probe the system for exposed entry points.",
    },
    {
        "step": "initial access",
        "tactic": "initial-access",
        "techniques": ["AML.T0051"],
        "abstract_action": "Inject adversarial input through the discovered entry point.",
    },
    {
        "step": "impact",
        "tactic": "impact",
        "techniques": ["AML.T0048"],
        "abstract_action": "Cause the system to produce harmful output.",
    },
]


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_entry(
    risk_id: str,
    owasp_llm_ids: list[str],
    agentic_threat_ids: list[str],
    attack_pattern_ids: list[str],
    atlas_technique_ids: list[str] | None = None,
) -> ThreatSurfaceEntry:
    return ThreatSurfaceEntry(
        risk_card=_make_ref(risk_id),
        owasp_llm_ids=owasp_llm_ids,
        agentic_threat_ids=agentic_threat_ids,
        atlas_technique_ids=atlas_technique_ids or [],
        attack_pattern_ids=attack_pattern_ids,
    )


_FAKE_THREATS = {
    "T7": {
        "name": "Misaligned & Deceptive Behaviors",
        "scenarios": [
            {"id": "T7-S1", "name": "Constraint bypass", "description": "Desc"},
        ],
    },
}

_FAKE_PATTERNS_WITH_KC = {
    "AP-T7-01": {
        "id": "AP-T7-01",
        "name": "Constraint bypass via goal-priority conflict",
        "description": "Agent bypasses constraints",
        "threat_id": "T7",
        "kill_chain": _SAMPLE_KILL_CHAIN,
    },
}

_FAKE_PATTERNS_WITHOUT_KC = {
    "AP-T7-01": {
        "id": "AP-T7-01",
        "name": "Constraint bypass via goal-priority conflict",
        "description": "Agent bypasses constraints",
        "threat_id": "T7",
    },
}


def _run_expand(
    entries: list[ThreatSurfaceEntry],
    patterns: dict,
) -> list[ScenarioSeed]:
    """Run expand_seeds with fake data, bypassing file I/O."""
    ts = ThreatSurface(entries=entries, governance_only=[])
    with (
        patch(
            "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
            return_value=_FAKE_THREATS,
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
            return_value=patterns,
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
            return_value=[],
        ),
    ):
        return expand_seeds(ts)


def _make_seed(
    kill_chain: list[dict] | None = None,
    technique_ids: list[str] | None = None,
) -> MagicMock:
    seed = MagicMock()
    seed.seed_id = "AP-T7-01"
    seed.attack_pattern_name = "Constraint bypass"
    seed.attack_pattern_description = "Agent bypasses constraints"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.atlas_technique_ids = technique_ids or []
    seed.owasp_llm_ids = ["LLM01"]
    seed.agentic_threat_ids = ["T7"]
    seed.kill_chain = kill_chain
    return seed


def _make_profile() -> MagicMock:
    profile = MagicMock()
    profile.zones_active = ["input", "reasoning"]
    profile.entry_points = []
    profile.kc_subcodes = []
    profile.has_persistent_memory = False
    profile.multi_agent = False
    profile.hitl = False
    profile.tool_inventory = []
    return profile


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user chat interface",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input",
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
        ],
    )


# ---------------------------------------------------------------------------
# Tests: ScenarioSeed model
# ---------------------------------------------------------------------------


class TestScenarioSeedKillChain:
    """Verify ScenarioSeed accepts kill_chain field."""

    def test_seed_accepts_kill_chain(self) -> None:
        """ScenarioSeed should accept a kill_chain list of dicts."""
        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Test",
            attack_pattern_name="Test",
            attack_pattern_description="Desc",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            kill_chain=_SAMPLE_KILL_CHAIN,
        )
        assert seed.kill_chain == _SAMPLE_KILL_CHAIN

    def test_seed_kill_chain_default_none(self) -> None:
        """ScenarioSeed kill_chain defaults to None."""
        seed = ScenarioSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Test",
            attack_pattern_name="Test",
            attack_pattern_description="Desc",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
        )
        assert seed.kill_chain is None


# ---------------------------------------------------------------------------
# Tests: expand_seeds() kill_chain population
# ---------------------------------------------------------------------------


class TestExpandSeedsKillChain:
    """Verify expand_seeds() populates kill_chain from pattern data."""

    def test_kill_chain_populated_when_present(self) -> None:
        """expand_seeds() should populate kill_chain from pattern data."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
        )
        seeds = _run_expand([entry], _FAKE_PATTERNS_WITH_KC)
        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert seed.kill_chain == _SAMPLE_KILL_CHAIN

    def test_kill_chain_none_when_absent(self) -> None:
        """expand_seeds() should leave kill_chain as None when pattern lacks it."""
        entry = _make_entry(
            "risk-a",
            ["LLM01"],
            ["T7"],
            ["AP-T7-01"],
        )
        seeds = _run_expand([entry], _FAKE_PATTERNS_WITHOUT_KC)
        seed = next(s for s in seeds if s.seed_id == "AP-T7-01")
        assert seed.kill_chain is None


# ---------------------------------------------------------------------------
# Tests: Template rendering
# ---------------------------------------------------------------------------


class TestCall1TemplateKillChain:
    """Verify Call 1 template renders kill chain scaffold correctly."""

    def test_renders_kill_chain_when_present(self) -> None:
        """call1_user.j2 should render kill chain section when kill_chain is set."""
        seed = _make_seed(kill_chain=_SAMPLE_KILL_CHAIN)
        profile = _make_profile()

        ctx = build_call1_context(
            seed=seed,
            profile=profile,
            use_case="Test use case",
        )

        result = render_prompt("call1_user.j2", **ctx)
        assert "## Kill Chain Scaffold" in result
        assert "Reconnaissance" in result
        assert "Initial Access" in result
        assert "Impact" in result
        assert "discovery" in result
        assert "AML.T0054" in result
        assert "Probe the system" in result

    def test_no_kill_chain_section_when_none(self) -> None:
        """call1_user.j2 should not render kill chain section when kill_chain is None."""
        seed = _make_seed(kill_chain=None)
        profile = _make_profile()

        ctx = build_call1_context(
            seed=seed,
            profile=profile,
            use_case="Test use case",
        )

        result = render_prompt("call1_user.j2", **ctx)
        assert "## Kill Chain Scaffold" not in result
        assert "tactical progression" not in result


class TestCall2TemplateKillChain:
    """Verify Call 2 template renders kill chain scaffold correctly."""

    def test_renders_kill_chain_when_present(self) -> None:
        """call2_user.j2 should render kill chain section when kill_chain is set."""
        seed = _make_seed(kill_chain=_SAMPLE_KILL_CHAIN)
        narrative = _make_narrative()

        ctx = build_call2_context(
            seed=seed,
            narrative=narrative,
            use_case="Test use case",
        )

        result = render_prompt("call2_user.j2", **ctx)
        assert "## Kill Chain Scaffold" in result
        assert "Align the attack tree structure" in result
        assert "Reconnaissance" in result
        assert "Impact" in result
        assert "AML.T0048" in result

    def test_no_kill_chain_section_when_none(self) -> None:
        """call2_user.j2 should not render kill chain section when kill_chain is None."""
        seed = _make_seed(kill_chain=None)
        narrative = _make_narrative()

        ctx = build_call2_context(
            seed=seed,
            narrative=narrative,
            use_case="Test use case",
        )

        result = render_prompt("call2_user.j2", **ctx)
        assert "## Kill Chain Scaffold" not in result
        assert "Align the attack tree structure" not in result


# ---------------------------------------------------------------------------
# Tests: Context builders
# ---------------------------------------------------------------------------


class TestContextBuildersKillChain:
    """Verify build_call1_context and build_call2_context pass kill_chain."""

    def test_call1_context_includes_kill_chain(self) -> None:
        """build_call1_context should include kill_chain in returned dict."""
        seed = _make_seed(kill_chain=_SAMPLE_KILL_CHAIN)
        profile = _make_profile()

        ctx = build_call1_context(
            seed=seed,
            profile=profile,
            use_case="Test use case",
        )
        assert "kill_chain" in ctx
        assert ctx["kill_chain"] == _SAMPLE_KILL_CHAIN

    def test_call1_context_kill_chain_none(self) -> None:
        """build_call1_context should include kill_chain=None when seed lacks it."""
        seed = _make_seed(kill_chain=None)
        profile = _make_profile()

        ctx = build_call1_context(
            seed=seed,
            profile=profile,
            use_case="Test use case",
        )
        assert "kill_chain" in ctx
        assert ctx["kill_chain"] is None

    def test_call2_context_includes_kill_chain(self) -> None:
        """build_call2_context should include kill_chain in returned dict."""
        seed = _make_seed(kill_chain=_SAMPLE_KILL_CHAIN)
        narrative = _make_narrative()

        ctx = build_call2_context(
            seed=seed,
            narrative=narrative,
            use_case="Test use case",
        )
        assert "kill_chain" in ctx
        assert ctx["kill_chain"] == _SAMPLE_KILL_CHAIN

    def test_call2_context_kill_chain_none(self) -> None:
        """build_call2_context should include kill_chain=None when seed lacks it."""
        seed = _make_seed(kill_chain=None)
        narrative = _make_narrative()

        ctx = build_call2_context(
            seed=seed,
            narrative=narrative,
            use_case="Test use case",
        )
        assert "kill_chain" in ctx
        assert ctx["kill_chain"] is None


class TestTreePromptHelperBranches:
    """Direct branch coverage for the decomposed build_call2_context helpers."""

    def test_access_provenance_block_empty_without_actor(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _access_provenance_block_text,
        )

        assert _access_provenance_block_text(None, None) == ""

    def test_access_provenance_block_empty_without_access(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _access_provenance_block_text,
        )

        actor = MagicMock(access=None)
        assert _access_provenance_block_text(actor, MagicMock()) == ""

    def test_access_provenance_block_empty_without_profile(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _access_provenance_block_text,
        )

        actor = MagicMock(access=MagicMock())
        assert _access_provenance_block_text(actor, None) == ""

    def test_accessible_pinned_entry_allowed(self) -> None:
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import (
            _ensure_accessible_pinned_entry,
        )

        ep = EntryPoint(name="User chat", direction="input")
        profile = MagicMock(
            zones_active=["input", "reasoning"],
            resolve_entry_point=MagicMock(return_value=ep),
        )
        _ensure_accessible_pinned_entry(profile, [ep], ep.entry_point_id)

    def test_inaccessible_pinned_entry_rejected(self) -> None:
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _ensure_accessible_pinned_entry,
        )

        ep = EntryPoint(name="Telemetry", direction="output")
        profile = MagicMock(
            zones_active=["input", "reasoning"],
            resolve_entry_point=MagicMock(return_value=ep),
        )
        with pytest.raises(GenerationError, match="not an attacker-accessible"):
            _ensure_accessible_pinned_entry(profile, [ep], ep.entry_point_id)

    def test_pinned_entry_guard_skips_without_profile(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _ensure_accessible_pinned_entry,
        )

        _ensure_accessible_pinned_entry(None, [MagicMock()], "ep")

    def test_pinned_entry_guard_skips_unresolved_count(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _ensure_accessible_pinned_entry,
        )

        profile = MagicMock(zones_active=["input"])
        _ensure_accessible_pinned_entry(profile, [], "ep")

    def test_semantic_draft_flow_requires_projection_and_profile(self) -> None:
        from asago_scenario_generator.pipeline.generate.tree import (
            _semantic_draft_flow,
        )

        assert (
            _semantic_draft_flow(MagicMock(), MagicMock(), "use case", None, None, None)
            is None
        )
