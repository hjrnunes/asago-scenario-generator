"""Property tests for envelope enrichment — system_context and consumer_hints.

Uses Hypothesis to verify invariants over broad input ranges:

- **Determinism**: identical inputs always produce identical outputs.
- **Garak testability mapping**: zone → testability is a pure lookup for all
  known zones.
- **Midojo testability rules**: the priority-based mapping holds for all
  combinations of zone, tool-mention, multi-agent, and persistent-state flags.
- **Profile-derivation invariants**: ``requires_multi_agent`` and
  ``requires_persistent_state`` always mirror the capability profile.
- **Backward compatibility**: envelopes assembled without a profile or control
  structure have ``None`` enrichment blocks.
- **Round-trip**: enriched envelopes serialize and deserialize without loss.
"""

from __future__ import annotations

import yaml

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    ScenarioEnvelope,
    SystemContext,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.enrichment import (
    compute_consumer_hints,
    compute_system_context,
)
import typing
from asago_scenario_generator.stpa.models import __all__
from tests.stpa.helpers import make_scenario_spec, make_gherkin_spec


# ---------------------------------------------------------------------------
# Shared fixture builders (mirrors test_envelope_enrichment.py)
# ---------------------------------------------------------------------------

_KC_SUBCODES_NO_TOOLS = ["KC1.1", "KC3.3"]  # input + reasoning only
_KC_SUBCODES_WITH_TOOLS = ["KC1.1", "KC5.1", "KC6.1.1"]  # adds tool_execution
_KC_SUBCODES_MULTI_AGENT = ["KC1.1", "KC2.3"]  # adds inter_agent
_KC_SUBCODES_PERSISTENT = ["KC1.1", "KC4.3"]  # adds memory


def _make_control_structure(
    resp_description: str = "Orchestrate tool calls safely",
    ca_description: str = "Execute requested tool",
) -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=resp_description,
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description=ca_description,
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Interface")],
    )


def _make_capability_profile(
    kc_subcodes: list[str] | None = None,
    tool_inventory: list[ToolInventoryEntry] | None = None,
) -> CapabilityProfile:
    if kc_subcodes is None:
        kc_subcodes = _KC_SUBCODES_WITH_TOOLS
    if tool_inventory is None:
        tool_inventory = [
            ToolInventoryEntry(name="database_query", description="Query the database"),
        ]
    return CapabilityProfile(
        zones_active=[],  # derived from kc_subcodes
        entry_points=[EntryPoint(name="user prompts via chat", direction="input")],
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc_subcodes,
        tool_inventory=tool_inventory,
    )


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_ZONES = st.sampled_from(
    ["input", "reasoning", "tool_execution", "memory", "inter_agent"]
)

_KC_COMBOS = st.lists(
    st.sampled_from(["KC1.1", "KC2.3", "KC3.3", "KC4.3", "KC5.1", "KC6.1.1"]),
    min_size=1,
    unique=True,
)

_TOOL_KEYWORDS = [
    "tool",
    "execute",
    "call",
    "invoke",
    "api",
    "command",
    "function",
    "script",
]

_NON_TOOL_WORDS = [
    "manipulate",
    "inject",
    "exploit",
    "bypass",
    "override",
    "input",
    "prompt",
    "text",
    "content",
    "data",
]

_TOOL_LEAF_TEXT = st.text(
    alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
    min_size=5,
    max_size=30,
).map(lambda s: f"call {s} tool")

_NON_TOOL_LEAF_TEXT = st.text(
    alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
    min_size=5,
    max_size=30,
).map(lambda s: f"manipulate {s} input")

_LEAF_TEXT = st.one_of(_TOOL_LEAF_TEXT, _NON_TOOL_LEAF_TEXT)

_ATTACK_TREES = st.builds(
    lambda leaves: {"root": "Exploit", "branches": [], "leaves": leaves},
    st.lists(_LEAF_TEXT, min_size=0, max_size=5),
)

_NARRATIVES = st.one_of(
    st.just("A single-turn attack narrative."),
    st.builds(
        lambda s: f"The attacker sends a message, then in a subsequent turn {s}",
        st.text(min_size=1, max_size=50),
    ),
)


# ---------------------------------------------------------------------------
# Property tests: compute_system_context determinism
# ---------------------------------------------------------------------------


class TestComputeSystemContextProperties:
    """Determinism and structural invariants for compute_system_context."""

    @given(_KC_COMBOS)
    @settings(max_examples=50, deadline=None)
    def test_deterministic_same_inputs(self, kc_subcodes):
        """Calling compute_system_context twice with the same inputs yields identical results."""
        # Build a profile that is valid for the given KC combo
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="db_tool", description="DB")]
            if needs_tools
            else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return  # skip invalid KC combos
        cs = _make_control_structure()
        spec = make_scenario_spec()

        ctx1 = compute_system_context(profile, cs, spec)
        ctx2 = compute_system_context(profile, cs, spec)

        assert ctx1 == ctx2

    @given(_KC_COMBOS)
    @settings(max_examples=50, deadline=None)
    def test_tool_inventory_matches_profile(self, kc_subcodes):
        """tool_inventory in SystemContext must match the profile's tool names."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="my_tool", description="Does stuff")]
            if needs_tools
            else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        ctx = compute_system_context(profile, cs, spec)

        if profile.tool_inventory:
            assert ctx.tool_inventory == [e.name for e in profile.tool_inventory]
        else:
            assert ctx.tool_inventory == []

    @given(_KC_COMBOS)
    @settings(max_examples=50, deadline=None)
    def test_active_zones_match_profile(self, kc_subcodes):
        """active_zones in SystemContext must match the profile's zones_active."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="t", description="d")] if needs_tools else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        ctx = compute_system_context(profile, cs, spec)

        assert ctx.active_zones == list(profile.zones_active)

    @given(_KC_COMBOS)
    @settings(max_examples=50, deadline=None)
    def test_multi_agent_and_persistent_memory_match_profile(self, kc_subcodes):
        """Boolean flags in SystemContext must match the profile's computed properties."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="t", description="d")] if needs_tools else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        ctx = compute_system_context(profile, cs, spec)

        assert ctx.multi_agent == profile.multi_agent
        assert ctx.has_persistent_memory == profile.has_persistent_memory

    @given(_KC_COMBOS)
    @settings(max_examples=30, deadline=None)
    def test_returns_system_context_type(self, kc_subcodes):
        """compute_system_context always returns a SystemContext instance."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="t", description="d")] if needs_tools else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        ctx = compute_system_context(profile, cs, spec)

        assert isinstance(ctx, SystemContext)


# ---------------------------------------------------------------------------
# Property tests: compute_consumer_hints determinism and rules
# ---------------------------------------------------------------------------


class TestComputeConsumerHintsProperties:
    """Determinism and rule-based invariants for compute_consumer_hints."""

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_deterministic_same_inputs(self, attack_tree, narrative, zone):
        """Calling compute_consumer_hints twice with the same inputs yields identical results."""
        profile = _make_capability_profile()
        hints1 = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        hints2 = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert hints1 == hints2

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_primary_attack_zone_passed_through(self, attack_tree, narrative, zone):
        """primary_attack_zone is always set to the input zone."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert hints.primary_attack_zone == zone

    @given(_ZONES)
    @settings(max_examples=10, deadline=None)
    def test_garak_testability_mapping(self, zone):
        """garak_testability follows the fixed zone→level mapping for all known zones."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree={"root": "r", "branches": [], "leaves": []},
            narrative="Single-turn attack.",
            primary_attack_zone=zone,
        )
        expected = {
            "input": "high",
            "reasoning": "medium",
            "tool_execution": "low",
            "memory": "low",
            "inter_agent": "low",
        }
        assert hints.garak_testability == expected[zone]

    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=50, deadline=None)
    def test_garak_testability_unknown_zone_defaults_low(self, zone):
        """Unknown zones default to 'low' garak_testability."""
        # Only test non-known zones
        known = {"input", "reasoning", "tool_execution", "memory", "inter_agent"}
        if zone in known:
            return
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree={"root": "r", "branches": [], "leaves": []},
            narrative="Single-turn attack.",
            primary_attack_zone=zone,
        )
        assert hints.garak_testability == "low"

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_requires_multi_agent_matches_profile(self, attack_tree, narrative, zone):
        """requires_multi_agent always equals profile.multi_agent."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert hints.requires_multi_agent == profile.multi_agent

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_requires_persistent_state_matches_profile(
        self, attack_tree, narrative, zone
    ):
        """requires_persistent_state always equals profile.has_persistent_memory."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert hints.requires_persistent_state == profile.has_persistent_memory

    @given(
        st.booleans(),  # requires_tool_execution
        st.booleans(),  # requires_multi_agent
        st.booleans(),  # requires_persistent_state
        _ZONES,
    )
    @settings(max_examples=200, deadline=None)
    def test_midojo_testability_priority_rules(
        self,
        req_tool_exec,
        req_multi_agent,
        req_persistent_state,
        zone,
    ):
        """midojo_testability follows the documented priority rules.

        - high: req_tool_exec AND zone == tool_execution
        - medium: req_multi_agent OR req_persistent_state (when not high)
        - low: otherwise
        """
        # We can't directly control the computed booleans, so we build
        # profiles that produce the desired combination and verify the
        # invariant against the computed values.
        kc_subcodes = ["KC1.1"]
        tool_inv = None
        if req_tool_exec:
            kc_subcodes.append("KC5.1")
            tool_inv = [ToolInventoryEntry(name="t", description="d")]
        if req_multi_agent:
            kc_subcodes.append("KC2.3")
        if req_persistent_state:
            kc_subcodes.append("KC4.3")

        try:
            profile = _make_capability_profile(
                kc_subcodes=sorted(set(kc_subcodes)),
                tool_inventory=tool_inv,
            )
        except Exception:
            return

        # Build a tree that mentions tools if req_tool_exec is desired
        leaves = (
            ["Call tool to execute command"]
            if req_tool_exec
            else ["Manipulate input text"]
        )
        tree = {"root": "r", "branches": [], "leaves": leaves}

        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone=zone,
        )

        # Reconstruct the expected midojo from the actual computed booleans
        if hints.requires_tool_execution and zone == "tool_execution":
            assert hints.midojo_testability == "high"
        elif hints.requires_multi_agent or hints.requires_persistent_state:
            assert hints.midojo_testability == "medium"
        else:
            assert hints.midojo_testability == "low"

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_testability_values_are_valid(self, attack_tree, narrative, zone):
        """garak_testability and midojo_testability are always in {high, medium, low}."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert hints.garak_testability in ("high", "medium", "low")
        assert hints.midojo_testability in ("high", "medium", "low")

    @given(_ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_returns_consumer_hints_type(self, attack_tree, narrative, zone):
        """compute_consumer_hints always returns a ConsumerHints instance."""
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )
        assert isinstance(hints, ConsumerHints)


# ---------------------------------------------------------------------------
# Property tests: backward compatibility
# ---------------------------------------------------------------------------


class TestAssembleEnvelopeBackwardCompatProperties:
    """Backward compatibility: no enrichment when profile or CS is missing."""

    def test_both_none_yields_no_enrichment(self):
        """assemble_envelope without profile or CS has None enrichment blocks."""
        spec = make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=make_gherkin_spec(),
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None

    def test_only_profile_yields_no_enrichment(self):
        """assemble_envelope with only profile has None enrichment blocks."""
        spec = make_scenario_spec()
        profile = _make_capability_profile()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=make_gherkin_spec(),
            capability_profile=profile,
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None

    def test_only_cs_yields_no_enrichment(self):
        """assemble_envelope with only CS has None enrichment blocks."""
        spec = make_scenario_spec()
        cs = _make_control_structure()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=make_gherkin_spec(),
            control_structure=cs,
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None


# ---------------------------------------------------------------------------
# Property tests: round-trip serialization
# ---------------------------------------------------------------------------


class TestEnrichmentRoundTripProperties:
    """Enriched envelopes serialize and deserialize without loss."""

    @given(_KC_COMBOS, _ATTACK_TREES, _NARRATIVES, _ZONES)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_envelope_yaml_round_trip(self, kc_subcodes, attack_tree, narrative, zone):
        """An enriched envelope survives YAML dump → load without field loss."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="rt_tool", description="RT")]
            if needs_tools
            else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative=narrative,
            attack_tree=attack_tree,
            gherkin_spec=make_gherkin_spec(),
            capability_profile=profile,
            control_structure=cs,
            primary_attack_zone=zone,
        )

        # Serialize to JSON dict (Pydantic), then YAML, then back
        data = envelope.model_dump(mode="json")
        yaml_text = yaml.dump(data)
        loaded = yaml.safe_load(yaml_text)
        restored = ScenarioEnvelope.model_validate(loaded)

        assert restored.system_context is not None
        assert restored.consumer_hints is not None
        assert restored.system_context == envelope.system_context
        assert restored.consumer_hints == envelope.consumer_hints

    @given(_KC_COMBOS, _ZONES)
    @settings(max_examples=30, deadline=None)
    def test_envelope_model_dump_round_trip(self, kc_subcodes, zone):
        """An enriched envelope survives model_dump → model_validate without loss."""
        kc = sorted(set(kc_subcodes))
        needs_tools = any(k.startswith(("KC5.", "KC6.")) for k in kc)
        tool_inv = (
            [ToolInventoryEntry(name="rt_tool", description="RT")]
            if needs_tools
            else None
        )
        try:
            profile = _make_capability_profile(kc_subcodes=kc, tool_inventory=tool_inv)
        except Exception:
            return
        cs = _make_control_structure()
        spec = make_scenario_spec()

        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=make_gherkin_spec(),
            capability_profile=profile,
            control_structure=cs,
            primary_attack_zone=zone,
        )

        data = envelope.model_dump()
        restored = ScenarioEnvelope.model_validate(data)

        assert restored.system_context == envelope.system_context
        assert restored.consumer_hints == envelope.consumer_hints


# ---------------------------------------------------------------------------
# Property tests: model export invariants
# ---------------------------------------------------------------------------


class TestEnrichmentModelExports:
    """SystemContext and ConsumerHints are exported from the models package."""

    def test_system_context_importable_from_models(self):
        from asago_scenario_generator.stpa.models import SystemContext as SC

        assert SC is SystemContext

    def test_consumer_hints_importable_from_models(self):
        from asago_scenario_generator.stpa.models import ConsumerHints as CH

        assert CH is ConsumerHints

    def test_models_all_includes_enrichment_types(self):
        assert "SystemContext" in __all__
        assert "ConsumerHints" in __all__

    def test_consumer_hints_testability_is_literal(self):
        """ConsumerHints.garak_testability and midojo_testability are Literal types."""
        garak_ann = ConsumerHints.model_fields["garak_testability"].annotation
        midojo_ann = ConsumerHints.model_fields["midojo_testability"].annotation

        # Literal types have __origin__ = typing.Literal
        assert typing.get_origin(garak_ann) is typing.Literal
        assert typing.get_origin(midojo_ann) is typing.Literal

        garak_args = set(typing.get_args(garak_ann))
        midojo_args = set(typing.get_args(midojo_ann))

        assert garak_args == {"high", "medium", "low"}
        assert midojo_args == {"high", "medium", "low"}
