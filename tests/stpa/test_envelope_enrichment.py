"""Tests for envelope enrichment — system_context (umcf) and consumer_hints (8b06).

Covers the Gherkin acceptance specs in:
- features/envelope_umcf_system_context.feature
- features/envelope_8b06_consumer_hints.feature
"""

from __future__ import annotations

import yaml

import pytest

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
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    GherkinSpec,
    ScenarioEnvelope,
    SystemContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.enrichment import (
    compute_consumer_hints,
    compute_system_context,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_control_structure(
    resp_description: str = "Orchestrate tool calls safely",
    ca_description: str = "Execute requested tool",
) -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=resp_description,
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State")
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
        controlled_processes=cps,
    )


def _make_scenario_spec(scenario_id: str = "SCN-001") -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1", content="Belief", vulnerability="Vuln"
                )
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"]
        ),
        loss_scenario="Scenario",
    )


_SENTINEL = object()


def _make_capability_profile(
    kc_subcodes: list[str] | None = None,
    tool_inventory: list[ToolInventoryEntry] | object | None = _SENTINEL,
    entry_points: list[EntryPoint] | None = None,
) -> CapabilityProfile:
    if kc_subcodes is None:
        kc_subcodes = ["KC1.1", "KC5.1", "KC6.1.1"]
    if tool_inventory is _SENTINEL:
        tool_inventory = [
            ToolInventoryEntry(name="database_query", description="Query the database")
        ]
    if entry_points is None:
        entry_points = [EntryPoint(name="user prompts via chat", direction="input")]
    return CapabilityProfile(
        zones_active=[],  # derived from kc_subcodes
        entry_points=entry_points,
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc_subcodes,
        tool_inventory=tool_inventory,
    )


def _make_attack_tree(
    leaves: list[str] | None = None,
    root: str = "Exploit input validation",
) -> dict:
    if leaves is None:
        leaves = ["Call database_query tool", "Execute malicious command"]
    return {
        "root": root,
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
        ],
        "leaves": leaves,
    }


def _make_gherkin_spec() -> GherkinSpec:
    return GherkinSpec(
        feature="Test",
        scenario="Test",
        given=["Given PM-1-1 is valid"],
        when=["When x"],
        then_expected=["Then should reject"],
        then_actual=["But approves"],
    )


def _make_envelope(
    scenario_id: str = "SCN-001",
    system_context: SystemContext | None = None,
    consumer_hints: ConsumerHints | None = None,
) -> ScenarioEnvelope:
    return ScenarioEnvelope(
        scenario_id=scenario_id,
        scenario_spec=_make_scenario_spec(scenario_id),
        narrative="Narrative text",
        attack_tree={"root": "r", "branches": [], "leaves": []},
        gherkin_spec=_make_gherkin_spec(),
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        catalog_mappings=[],
        provenance="structural",
        system_context=system_context,
        consumer_hints=consumer_hints,
    )


# ---------------------------------------------------------------------------
# UMCF — SystemContext
# ---------------------------------------------------------------------------


class TestSystemContextModel:
    """UMCF-01: SystemContext model has required fields."""

    @pytest.mark.parametrize(
        "field, expected_type",
        [
            ("target_responsibility_description", "str"),
            ("target_control_action_description", "str"),
            ("tool_inventory", "list"),
            ("active_zones", "list"),
            ("multi_agent", "bool"),
            ("has_persistent_memory", "bool"),
        ],
    )
    def test_field_exists_with_correct_type(self, field, expected_type):
        fields = SystemContext.model_fields
        assert field in fields
        annotation = fields[field].annotation
        type_str = str(annotation)
        assert expected_type in type_str

    def test_system_context_constructs_with_all_fields(self):
        ctx = SystemContext(
            target_responsibility_description="Orchestrate tool calls safely",
            target_control_action_description="Execute requested tool",
            tool_inventory=["database_query"],
            active_zones=["input", "reasoning", "tool_execution"],
            multi_agent=False,
            has_persistent_memory=False,
        )
        assert ctx.target_responsibility_description == "Orchestrate tool calls safely"
        assert ctx.target_control_action_description == "Execute requested tool"
        assert ctx.tool_inventory == ["database_query"]
        assert ctx.active_zones == ["input", "reasoning", "tool_execution"]
        assert ctx.multi_agent is False
        assert ctx.has_persistent_memory is False


class TestScenarioEnvelopeSystemContextField:
    """UMCF-02: ScenarioEnvelope has optional system_context field."""

    def test_system_context_field_is_optional_with_default_none(self):
        fields = ScenarioEnvelope.model_fields
        assert "system_context" in fields
        # Default should be None
        assert fields["system_context"].default is None


class TestAssembleEnvelopeSystemContext:
    """UMCF-03 through UMCF-08: assemble_envelope populates system_context."""

    def test_umcf_03_system_context_not_none(self):
        cs = _make_control_structure()
        profile = _make_capability_profile()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert envelope.system_context is not None

    def test_umcf_04_responsibility_description_from_resp_id(self):
        cs = _make_control_structure(
            resp_description="Orchestrate tool calls safely"
        )
        profile = _make_capability_profile()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert (
            envelope.system_context.target_responsibility_description
            == "Orchestrate tool calls safely"
        )

    def test_umcf_05_control_action_description_from_ca_id(self):
        cs = _make_control_structure(
            ca_description="Execute requested tool"
        )
        profile = _make_capability_profile()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert (
            envelope.system_context.target_control_action_description
            == "Execute requested tool"
        )

    def test_umcf_06_tool_inventory_inlined(self):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert "database_query" in envelope.system_context.tool_inventory

    @pytest.mark.parametrize("zone", ["input", "reasoning", "tool_execution"])
    def test_umcf_07_active_zones_inlined(self, zone):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert zone in envelope.system_context.active_zones

    @pytest.mark.parametrize(
        "field, value",
        [("multi_agent", False), ("has_persistent_memory", False)],
    )
    def test_umcf_08_boolean_flags_inlined(self, field, value):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert getattr(envelope.system_context, field) is value

    def test_umcf_09_envelope_without_system_context_parses(self):
        envelope = _make_envelope(system_context=None)
        assert envelope.system_context is None

    def test_umcf_10_system_context_serialized_in_yaml(self):
        cs = _make_control_structure()
        profile = _make_capability_profile()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        yaml_text = yaml.dump(envelope.model_dump(mode="json"))
        assert "system_context" in yaml_text
        assert "target_responsibility_description" in yaml_text

    def test_umcf_12_multi_agent_true(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC2.3"])
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert envelope.system_context.multi_agent is True

    def test_umcf_13_has_persistent_memory_true(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC4.3"])
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert envelope.system_context.has_persistent_memory is True

    def test_umcf_14_empty_tool_inventory_when_no_tools(self):
        profile = _make_capability_profile(
            kc_subcodes=["KC1.1"], tool_inventory=None
        )
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert envelope.system_context.tool_inventory == []


# ---------------------------------------------------------------------------
# 8B06 — ConsumerHints
# ---------------------------------------------------------------------------


class TestConsumerHintsModel:
    """8B06-01: ConsumerHints model has required fields."""

    @pytest.mark.parametrize(
        "field, expected_type",
        [
            ("primary_attack_zone", "str"),
            ("requires_tool_execution", "bool"),
            ("requires_multi_turn", "bool"),
            ("requires_multi_agent", "bool"),
            ("requires_persistent_state", "bool"),
            ("garak_testability", "Literal"),
            ("midojo_testability", "Literal"),
        ],
    )
    def test_field_exists_with_correct_type(self, field, expected_type):
        fields = ConsumerHints.model_fields
        assert field in fields
        annotation = fields[field].annotation
        type_str = str(annotation)
        assert expected_type in type_str

    def test_consumer_hints_constructs_with_all_fields(self):
        hints = ConsumerHints(
            primary_attack_zone="input",
            requires_tool_execution=False,
            requires_multi_turn=False,
            requires_multi_agent=False,
            requires_persistent_state=False,
            garak_testability="high",
            midojo_testability="low",
        )
        assert hints.primary_attack_zone == "input"
        assert hints.requires_tool_execution is False
        assert hints.requires_multi_turn is False
        assert hints.requires_multi_agent is False
        assert hints.requires_persistent_state is False
        assert hints.garak_testability == "high"
        assert hints.midojo_testability == "low"


class TestScenarioEnvelopeConsumerHintsField:
    """8B06-02: ScenarioEnvelope has optional consumer_hints field."""

    def test_consumer_hints_field_is_optional_with_default_none(self):
        fields = ScenarioEnvelope.model_fields
        assert "consumer_hints" in fields
        assert fields["consumer_hints"].default is None


class TestComputeConsumerHints:
    """8B06-03 through 8B06-12: compute_consumer_hints determinism and rules."""

    def test_8b06_03_computed_deterministically(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="A single-turn attack narrative.",
            primary_attack_zone="input",
        )
        assert hints is not None
        assert isinstance(hints, ConsumerHints)

    @pytest.mark.parametrize("zone", ["input", "reasoning", "tool_execution", "memory", "inter_agent"])
    def test_8b06_04_primary_attack_zone_passed_through(self, zone):
        profile = _make_capability_profile()
        tree = _make_attack_tree()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="A single-turn attack.",
            primary_attack_zone=zone,
        )
        assert hints.primary_attack_zone == zone

    def test_8b06_05_requires_tool_execution_true_when_tree_mentions_tools(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree(leaves=["Call database_query tool", "Execute malicious code"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.requires_tool_execution is True

    def test_8b06_06_requires_tool_execution_false_when_no_tool_mentions(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree(leaves=["Manipulate input text", "Inject prompt content"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.requires_tool_execution is False

    def test_8b06_07_requires_multi_turn_true(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree()
        narrative = (
            "The attacker sends an initial message, then in a subsequent turn "
            "refines the approach with a follow-up request."
        )
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative=narrative,
            primary_attack_zone="input",
        )
        assert hints.requires_multi_turn is True

    def test_8b06_08_requires_multi_turn_false(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree()
        narrative = "The attacker sends a single crafted prompt to exploit the system."
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative=narrative,
            primary_attack_zone="input",
        )
        assert hints.requires_multi_turn is False

    def test_8b06_09_requires_multi_agent_from_profile(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC2.3"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=_make_attack_tree(),
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.requires_multi_agent is True

    def test_8b06_10_requires_persistent_state_from_profile(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC4.3"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=_make_attack_tree(),
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.requires_persistent_state is True

    @pytest.mark.parametrize(
        "zone, expected_garak",
        [
            ("input", "high"),
            ("reasoning", "medium"),
            ("tool_execution", "low"),
            ("memory", "low"),
            ("inter_agent", "low"),
        ],
    )
    def test_8b06_11_garak_testability_rule_based(self, zone, expected_garak):
        profile = _make_capability_profile()
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=_make_attack_tree(),
            narrative="Single-turn attack.",
            primary_attack_zone=zone,
        )
        assert hints.garak_testability == expected_garak

    def test_8b06_12_midojo_high_tool_execution(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree(leaves=["Call tool", "Execute command"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="tool_execution",
        )
        assert hints.midojo_testability == "high"

    def test_8b06_12_midojo_medium_multi_agent(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC2.3"])
        tree = _make_attack_tree(leaves=["Manipulate input text"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.midojo_testability == "medium"

    def test_8b06_12_midojo_medium_persistent_state(self):
        profile = _make_capability_profile(kc_subcodes=["KC1.1", "KC4.3"])
        tree = _make_attack_tree(leaves=["Manipulate input text"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.midojo_testability == "medium"

    def test_8b06_12_midojo_low_otherwise(self):
        profile = _make_capability_profile()
        tree = _make_attack_tree(leaves=["Manipulate input text"])
        hints = compute_consumer_hints(
            capability_profile=profile,
            attack_tree=tree,
            narrative="Single-turn attack.",
            primary_attack_zone="input",
        )
        assert hints.midojo_testability == "low"


class TestEnvelopeConsumerHintsSerialization:
    """8B06-13, 8B06-14: backward compat and YAML serialization."""

    def test_8b06_13_envelope_without_consumer_hints_parses(self):
        envelope = _make_envelope(consumer_hints=None)
        assert envelope.consumer_hints is None

    def test_8b06_14_consumer_hints_serialized_in_yaml(self):
        hints = ConsumerHints(
            primary_attack_zone="input",
            requires_tool_execution=False,
            requires_multi_turn=False,
            requires_multi_agent=False,
            requires_persistent_state=False,
            garak_testability="high",
            midojo_testability="low",
        )
        envelope = _make_envelope(consumer_hints=hints)
        yaml_text = yaml.dump(envelope.model_dump(mode="json"))
        assert "consumer_hints" in yaml_text
        assert "garak_testability" in yaml_text
        assert "midojo_testability" in yaml_text


class TestAssembleEnvelopeConsumerHints:
    """8B06-15: assemble_envelope populates consumer_hints."""

    def test_8b06_15_consumer_hints_populated(self):
        cs = _make_control_structure()
        profile = _make_capability_profile()
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="A single-turn attack narrative.",
            attack_tree=_make_attack_tree(),
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
            control_structure=cs,
        )
        assert envelope.consumer_hints is not None
        assert envelope.consumer_hints.garak_testability != ""
        assert envelope.consumer_hints.midojo_testability != ""


class TestEnrichmentModule:
    """8B06-16: enrichment computation is in a dedicated module."""

    def test_compute_system_context_importable(self):
        assert callable(compute_system_context)

    def test_compute_consumer_hints_importable(self):
        assert callable(compute_consumer_hints)

    def test_compute_system_context_returns_system_context(self):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        ctx = compute_system_context(profile, cs, spec)
        assert isinstance(ctx, SystemContext)
        assert ctx.target_responsibility_description == "Orchestrate tool calls safely"
        assert ctx.target_control_action_description == "Execute requested tool"
        assert "database_query" in ctx.tool_inventory

    def test_compute_system_context_empty_tool_inventory(self):
        profile = _make_capability_profile(
            kc_subcodes=["KC1.1"], tool_inventory=None
        )
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        ctx = compute_system_context(profile, cs, spec)
        assert ctx.tool_inventory == []


class TestAssembleEnvelopeBackwardCompat:
    """Backward compat: assemble_envelope without profile/CS works as before."""

    def test_no_enrichment_when_profile_and_cs_are_none(self):
        spec = _make_scenario_spec()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None

    def test_no_enrichment_when_only_profile_provided(self):
        spec = _make_scenario_spec()
        profile = _make_capability_profile()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            capability_profile=profile,
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None

    def test_no_enrichment_when_only_cs_provided(self):
        spec = _make_scenario_spec()
        cs = _make_control_structure()
        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            control_structure=cs,
        )
        assert envelope.system_context is None
        assert envelope.consumer_hints is None




class TestGherkinSpecToFeatureText:
    """Tests for GherkinSpec.to_feature_text — kills trailing newline mutant."""

    def test_to_feature_text_ends_with_newline(self):
        """to_feature_text output must end with a trailing newline."""
        spec = GherkinSpec(
            feature="Test Feature",
            scenario="Test Scenario",
            given=["Given a condition"],
            when=["When an action"],
            then_expected=["Then expected result"],
            then_actual=["But actual result"],
        )
        text = spec.to_feature_text()
        assert text.endswith("\n"), "to_feature_text must end with a trailing newline"

    def test_to_feature_text_contains_all_steps(self):
        """to_feature_text must render all given/when/then/but steps."""
        spec = GherkinSpec(
            feature="My Feature",
            scenario="My Scenario",
            given=["Given step 1", "Given step 2"],
            when=["When step 1"],
            then_expected=["Then should do X"],
            then_actual=["But does Y"],
        )
        text = spec.to_feature_text()
        assert "Feature: My Feature" in text
        assert "Scenario: My Scenario" in text
        assert "Given step 1" in text
        assert "Given step 2" in text
        assert "When step 1" in text
        assert "Then should do X" in text
        assert "But does Y" in text


# ---------------------------------------------------------------------------
# Edge-case and error-path tests for internal helpers
# ---------------------------------------------------------------------------


class TestExtractLeafText:
    """Cover all branches of _extract_leaf_text and _extract_text_from_dict."""

    def test_string_leaf_returns_raw_text(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text("Call Tool") == "Call Tool"

    def test_dict_leaf_with_label_key(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"label": "Execute API"}) == "Execute API"

    def test_dict_leaf_with_text_key(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"text": "Invoke function"}) == "Invoke function"

    def test_dict_leaf_with_description_key(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"description": "Run script"}) == "Run script"

    def test_dict_leaf_with_name_key(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"name": "command_executor"}) == "command_executor"

    def test_dict_leaf_prefers_label_over_other_keys(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        leaf = {"label": "first", "text": "second", "name": "third"}
        assert _extract_leaf_text(leaf) == "first"

    def test_dict_leaf_with_no_matching_keys_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"category": "x", "children": []}) == ""

    def test_dict_leaf_with_non_string_values_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text({"label": 42, "text": None}) == ""

    def test_int_leaf_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text(42) == ""

    def test_none_leaf_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text(None) == ""

    def test_list_leaf_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _extract_leaf_text

        assert _extract_leaf_text(["a", "b"]) == ""


class TestTreeMentionsToolsEdgeCases:
    """Cover edge cases in _tree_mentions_tools."""

    def test_non_list_leaves_returns_false(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _tree_mentions_tools

        assert _tree_mentions_tools({"leaves": "not a list"}) is False

    def test_missing_leaves_key_returns_false(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _tree_mentions_tools

        assert _tree_mentions_tools({"root": "x"}) is False

    def test_empty_leaves_returns_false(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _tree_mentions_tools

        assert _tree_mentions_tools({"leaves": []}) is False

    def test_dict_leaf_with_tool_keyword_detected(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _tree_mentions_tools

        tree = {"leaves": [{"label": "Call the API tool"}]}
        assert _tree_mentions_tools(tree) is True

    def test_non_string_non_dict_leaf_ignored(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _tree_mentions_tools

        tree = {"leaves": [42, None, "call tool"]}
        assert _tree_mentions_tools(tree) is True


class TestNarrativeIndicatesMultiTurnEdgeCases:
    """Cover edge cases in _narrative_indicates_multi_turn."""

    def test_empty_narrative_returns_false(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import (
            _narrative_indicates_multi_turn,
        )

        assert _narrative_indicates_multi_turn("") is False

    def test_none_narrative_returns_false(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import (
            _narrative_indicates_multi_turn,
        )

        assert _narrative_indicates_multi_turn(None) is False


class TestComputeSystemContextEdgeCases:
    """Cover not-found paths in compute_system_context."""

    def test_responsibility_not_found_returns_empty_desc(self):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        spec = spec.model_copy(update={"target_controller": "RESP-999"})
        ctx = compute_system_context(profile, cs, spec)
        assert ctx.target_responsibility_description == ""
        assert ctx.target_control_action_description == ""

    def test_control_action_not_found_returns_empty_ca_desc(self):
        profile = _make_capability_profile()
        cs = _make_control_structure()
        spec = _make_scenario_spec()
        spec = spec.model_copy(update={"target_control_action": "CA-999"})
        ctx = compute_system_context(profile, cs, spec)
        assert ctx.target_responsibility_description == "Orchestrate tool calls safely"
        assert ctx.target_control_action_description == ""


class TestFindControlActionDescription:
    """Cover _find_control_action_description with None responsibility."""

    def test_none_responsibility_returns_empty(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import (
            _find_control_action_description,
        )

        assert _find_control_action_description(None, "CA-1") == ""


class TestGarakTestabilityUnknownZone:
    """Cover default fallback for unknown attack zone."""

    def test_unknown_zone_defaults_to_low(self):
        from asago_scenario_generator.stpa.scenario_prod.enrichment import _garak_testability

        assert _garak_testability("unknown_zone") == "low"
