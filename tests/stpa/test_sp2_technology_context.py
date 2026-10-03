"""Unit tests for SP2 Stage 3 — Technology context block."""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.threat_enum.technology_context import (
    build_technology_context,
    context_for,
)


def _make_minimal_profile() -> CapabilityProfile:
    """Build a minimal CapabilityProfile with no zones, KCs, entry points, or tools."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="test", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1"],
    )


def _make_profile_with_zone(zone: str) -> CapabilityProfile:
    """Build a profile with a specific zone active.

    Zones are derived from KC sub-codes by the CapabilityProfile model.
    - tool_execution: needs KC5.* or KC6.*
    - memory: needs KC4.3-KC4.6
    - inter_agent: needs KC2.3
    """
    kc_subcodes = ["KC1.1"]  # always gives input + reasoning
    if zone == "tool_execution":
        kc_subcodes.append("KC5.1")
    elif zone == "memory":
        kc_subcodes.append("KC4.3")
    elif zone == "inter_agent":
        kc_subcodes.append("KC2.3")
    elif zone == "input":
        pass  # already present

    tool_inventory = None
    if zone == "tool_execution":
        tool_inventory = [
            ToolInventoryEntry(name="test-tool", description="A test tool")
        ]

    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="test", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=kc_subcodes,
        tool_inventory=tool_inventory,
    )


def _make_profile_with_kc(kc_subcode: str) -> CapabilityProfile:
    """Build a profile with a specific KC sub-code."""
    kc_subcodes = ["KC1.1", kc_subcode]
    tool_inventory = None
    # KC5.* and KC6.* activate tool_execution which requires tool_inventory
    if kc_subcode.startswith(("KC5.", "KC6.")):
        tool_inventory = [
            ToolInventoryEntry(name="test-tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="test", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=kc_subcodes,
        tool_inventory=tool_inventory,
    )


def _make_profile_with_entry_point(
    name: str, controllability: str | None = None, direction: str | None = None
) -> CapabilityProfile:
    """Build a profile with a specific entry point."""
    ep_kwargs: dict = {"name": name, "direction": direction or "input"}
    if controllability is not None:
        ep_kwargs["controllability"] = controllability
    return CapabilityProfile(
        zones_active=["reasoning"],
        entry_points=[EntryPoint(**ep_kwargs)],
        confidence="medium",
        kc_subcodes=["KC1.1"],
    )


def _make_profile_with_tool(name: str, description: str) -> CapabilityProfile:
    """Build a profile with a specific tool."""
    return CapabilityProfile(
        zones_active=["reasoning"],
        entry_points=[
            EntryPoint(name="test", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1"],
        tool_inventory=[ToolInventoryEntry(name=name, description=description)],
    )


# ---------------------------------------------------------------------------
# Zone-based failure modes (SP2-TECH-01)
# ---------------------------------------------------------------------------


class TestZoneFailureModes:
    """Zone-based failure modes are emitted."""

    def test_input_zone(self):
        profile = _make_profile_with_zone("input")
        ctx = build_technology_context(profile)
        assert "prompt injection" in ctx.lower()

    def test_tool_execution_zone(self):
        profile = _make_profile_with_zone("tool_execution")
        ctx = build_technology_context(profile)
        assert "parameter injection" in ctx.lower()

    def test_memory_zone(self):
        profile = _make_profile_with_zone("memory")
        ctx = build_technology_context(profile)
        assert "memory poisoning" in ctx.lower()

    def test_inter_agent_zone(self):
        profile = _make_profile_with_zone("inter_agent")
        ctx = build_technology_context(profile)
        assert "agent impersonation" in ctx.lower()

    def test_inactive_zone_not_emitted(self):
        """A zone that is not active must not produce its failure mode line."""
        profile = _make_profile_with_zone("input")
        ctx = build_technology_context(profile)
        assert "memory poisoning" not in ctx.lower()
        assert "agent impersonation" not in ctx.lower()


# ---------------------------------------------------------------------------
# KC sub-code specific failure modes (SP2-TECH-02, SP2-TECH-03, SP2-TECH-04)
# ---------------------------------------------------------------------------


class TestKCFailureModes:
    """KC sub-code specific failure modes are emitted."""

    def test_kc633_rag(self):
        profile = _make_profile_with_kc("KC6.3.3")
        ctx = build_technology_context(profile)
        assert "retrieval poisoning" in ctx.lower()

    def test_kcx_hitl(self):
        profile = _make_profile_with_kc("KCX-HITL")
        ctx = build_technology_context(profile)
        assert "alert fatigue" in ctx.lower()

    def test_kc23_multi_agent(self):
        profile = _make_profile_with_kc("KC2.3")
        ctx = build_technology_context(profile)
        assert "multi-agent" in ctx.lower()

    def test_kc43x_cross_session(self):
        profile = _make_profile_with_kc("KC4.3")
        ctx = build_technology_context(profile)
        assert "cross-session" in ctx.lower()

    def test_kc62x_code_execution(self):
        profile = _make_profile_with_kc("KC6.2.1")
        ctx = build_technology_context(profile)
        assert "code execution" in ctx.lower()

    def test_kcx_magent_multi_agent(self):
        """KCX-MAGENT alone triggers multi-agent failure mode."""
        profile = _make_profile_with_kc("KCX-MAGENT")
        ctx = build_technology_context(profile)
        assert "multi-agent" in ctx.lower()


class TestKCFailureModesNegative:
    """KC sub-code specific failure modes are NOT emitted when the KC sub-code is absent."""

    def test_no_rag_when_kc633_absent(self):
        """RAG failure mode is absent when KC6.3.3 is not in the profile."""
        profile = _make_minimal_profile()
        ctx = build_technology_context(profile)
        assert "retrieval poisoning" not in ctx.lower()

    def test_no_cross_session_when_kc43_absent(self):
        """Cross-session failure mode is absent when KC4.3* is not in the profile."""
        profile = _make_minimal_profile()
        ctx = build_technology_context(profile)
        assert "cross-session" not in ctx.lower()

    def test_no_multi_agent_when_both_kc23_and_magent_absent(self):
        """Multi-agent failure mode is absent when neither KC2.3 nor KCX-MAGENT is present."""
        profile = _make_minimal_profile()
        ctx = build_technology_context(profile)
        assert "multi-agent" not in ctx.lower()

    def test_no_hitl_when_kcx_hitl_absent(self):
        """HITL failure mode is absent when KCX-HITL is not in the profile."""
        profile = _make_minimal_profile()
        ctx = build_technology_context(profile)
        assert "alert fatigue" not in ctx.lower()

    def test_no_code_execution_when_kc62_absent(self):
        """Code execution failure mode is absent when KC6.2* is not in the profile."""
        profile = _make_minimal_profile()
        ctx = build_technology_context(profile)
        assert "arbitrary code" not in ctx.lower()

    def test_multi_agent_emitted_for_kcx_magent_only(self):
        """Multi-agent failure mode is emitted when only KCX-MAGENT is present (not KC2.3)."""
        profile = _make_profile_with_kc("KCX-MAGENT")
        ctx = build_technology_context(profile)
        assert "multi-agent" in ctx.lower()

    def test_multi_agent_emitted_for_kc23_only(self):
        """Multi-agent failure mode is emitted when only KC2.3 is present (not KCX-MAGENT)."""
        profile = _make_profile_with_kc("KC2.3")
        ctx = build_technology_context(profile)
        assert "multi-agent" in ctx.lower()


# ---------------------------------------------------------------------------
# Entry point failure modes (SP2-TECH-05, SP2-TECH-06)
# ---------------------------------------------------------------------------


class TestEntryPointFailureModes:
    """Entry point specific failure modes."""

    def test_indirect_controllability(self):
        profile = _make_profile_with_entry_point(
            "RAG-knowledge-base", controllability="indirect"
        )
        ctx = build_technology_context(profile)
        assert "supply chain" in ctx.lower()

    def test_bidirectional_direction(self):
        profile = _make_profile_with_entry_point(
            "file-upload", direction="bidirectional"
        )
        ctx = build_technology_context(profile)
        assert "exfiltration" in ctx.lower()

    def test_direct_controllability_no_supply_chain(self):
        """Direct controllability entry point does not emit supply chain failure mode."""
        profile = _make_profile_with_entry_point("chat-input", controllability="direct")
        ctx = build_technology_context(profile)
        assert "supply chain" not in ctx.lower()

    def test_unidirectional_no_bidirectional_exfiltration(self):
        """Unidirectional entry point does not emit bidirectional exfiltration failure mode."""
        profile = _make_profile_with_entry_point("chat-input", direction="input")
        ctx = build_technology_context(profile)
        assert "bidirectional data exfiltration" not in ctx.lower()


# ---------------------------------------------------------------------------
# Tool inventory failure modes (SP2-TECH-07)
# ---------------------------------------------------------------------------


class TestToolInventoryFailureModes:
    """Tool inventory per-tool failure mode text."""

    def test_write_tool_emits_write_suffix(self):
        profile = _make_profile_with_tool("refund-api", "processes refunds")
        ctx = build_technology_context(profile)
        assert "refund-api" in ctx.lower()
        assert "parameter manipulation" in ctx.lower()
        assert "unauthorized state change" in ctx.lower()

    def test_read_tool_emits_read_suffix(self):
        profile = _make_profile_with_tool(
            "search-index", "Reads and retrieves documents"
        )
        ctx = build_technology_context(profile)
        assert "search-index" in ctx.lower()
        assert "output fabrication" in ctx.lower()
        assert "exfiltration" in ctx.lower()

    def test_unknown_tool_emits_fallback_suffix(self):
        profile = _make_profile_with_tool("mystery-tool", "Does something unspecified")
        ctx = build_technology_context(profile)
        assert "mystery-tool" in ctx.lower()
        assert "unexpected behavior" in ctx.lower()

    def test_overlapping_verbs_classified_as_write(self):
        """Write intent has priority when both read and write verbs are present."""
        profile = _make_profile_with_tool(
            "log-processor", "Reads logs and writes audit entries"
        )
        ctx = build_technology_context(profile)
        assert "parameter manipulation" in ctx.lower()
        assert "unauthorized state change" in ctx.lower()


# ---------------------------------------------------------------------------
# Default text (SP2-TECH-08)
# ---------------------------------------------------------------------------


class TestDefaultText:
    """No relevant capabilities produces default text."""

    def test_default_text(self):
        """No relevant capabilities produces default text.

        The CapabilityProfile model always has at least input+reasoning
        zones from KC1.1, so we test with a mock that has no zones.
        """
        from unittest.mock import MagicMock

        mock_profile = MagicMock()
        mock_profile.zones_active = []
        mock_profile.kc_subcodes = []
        mock_profile.entry_points = []
        mock_profile.tool_inventory = None
        ctx = build_technology_context(mock_profile)
        assert "No specific technology context" in ctx


# ---------------------------------------------------------------------------
# Determinism (SP2-TECH-09)
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Technology context is deterministic."""

    def test_identical_output(self):
        profile = _make_profile_with_zone("input")
        ctx1 = build_technology_context(profile)
        ctx2 = build_technology_context(profile)
        assert ctx1 == ctx2


# ---------------------------------------------------------------------------
# No LLM calls (SP2-TECH-10)
# ---------------------------------------------------------------------------


class TestNoLLMCalls:
    """Technology context makes no LLM calls."""

    def test_no_llm_calls(self):
        profile = _make_profile_with_zone("input")
        ctx = build_technology_context(profile)
        # No LLM client involved — just verify output is a string
        assert isinstance(ctx, str)
        assert len(ctx) > 0


# ---------------------------------------------------------------------------
# Multiple zones (SP2-TECH-11)
# ---------------------------------------------------------------------------


class TestContextFor:
    """Omit-when-absent policy for prompt assemblers."""

    def test_none_profile_omits_block(self):
        assert context_for(None) is None

    def test_profile_matches_builder(self):
        profile = _make_profile_with_zone("input")
        assert context_for(profile) == build_technology_context(profile)


class TestMultipleZones:
    """Multiple zones produce multiple failure mode lines."""

    def test_multiple_zones(self):
        profile = CapabilityProfile(
            zones_active=["input", "tool_execution", "memory"],
            entry_points=[
                EntryPoint(name="test", direction="input", controllability="direct"),
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1", "KC4.3"],
            tool_inventory=[
                ToolInventoryEntry(name="test-tool", description="A test tool")
            ],
        )
        ctx = build_technology_context(profile)
        assert "prompt injection" in ctx.lower()
        assert "parameter injection" in ctx.lower()
        assert "memory poisoning" in ctx.lower()
