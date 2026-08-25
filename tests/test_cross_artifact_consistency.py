"""Tests for cross-artifact consistency validators (bv5s).

Covers three new semantic validators:
  1. narrative_technique_orphan — technique IDs in narrative but absent from tree
  2. missing_scenario_threat_id — no tree node carries the scenario's threat_id
  3. zone_omission_tree / zone_omission_gherkin — narrative zones missing from
     attack tree or Gherkin behavior_spec
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
    _collect_tree_node_threat_ids,
    _collect_tree_node_zones,
    _extract_gherkin_zones_for_validation,
    _extract_narrative_technique_ids,
    validate_scenario_semantics,
)
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    zones_active: list[str] | None = None,
) -> CapabilityProfile:
    if zones_active is None:
        zones_active = ["input", "reasoning", "tool_execution"]
    kc = ["KC1.1"]
    kw = {}
    if "tool_execution" in zones_active:
        kc.append("KC6.1.1")
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    if "memory" in zones_active:
        kc.append("KC4.3")
    if "inter_agent" in zones_active:
        kc.append("KC2.3")
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=["user prompts (zone 1)"],
        confidence="high",
        kc_subcodes=kc,
        **kw,
    )


def _leaf(
    node_id: str,
    zone: str = "input",
    technique_id: str | None = None,
    threat_id: str | None = None,
) -> AttackTreeNode:
    action = (
        ToolInvocationAction(tool_id=compute_tool_id("test_tool", "A test tool"))
        if zone == "tool_execution"
        else AiSystemAction()
    )
    return AttackTreeNode(
        id=node_id,
        label=f"Step {node_id}",
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        technique_id=technique_id,
        threat_id=threat_id,
    )


def _make_envelope(
    zone_sequence: list[str] | None = None,
    steps: list[NarrativeStep] | None = None,
    narrative_summary: str = "A test summary.",
    tree_root: AttackTreeNode | None = None,
    seed_metadata: dict | None = None,
    behavior_spec: object = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

    if steps is None:
        steps = [
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
        steps=steps,
    )

    if tree_root is None:
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T7"
                ),
            ],
        )

    if behavior_spec is None:
        behavior_spec = make_behavior_spec()
    elif isinstance(behavior_spec, str):
        # Wrap raw Gherkin string into a minimal BehaviorSpec (422o.4).
        from asago_scenario_generator.models.scenario import BehaviorSpec as _BS

        behavior_spec = _BS(
            actions=(),
            assertions=(),
            gherkin_text=behavior_spec if behavior_spec else "Feature: test",
        )

    attack_tree = AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Compromise the system",
        root=tree_root,
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
            agentic_threat_ids=["T7"],
            scenario_seed="AP-T7-01",
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

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id="scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
        candidate_id="cand:v2:7e57c0de000000000000000000000000",
        initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec,
        faceting=faceting,
        priority=priority,
        generation=generation,
        scenario_seed_metadata=seed_metadata,
    )


# ===========================================================================
# 1. Narrative technique orphan detection
# ===========================================================================


class TestExtractNarrativeTechniqueIds:
    """Unit tests for _extract_narrative_technique_ids helper."""

    def test_bracketed_annotation(self):
        """Extracts [AML.T0054] style annotations."""
        narrative = NarrativeLayer(
            title="Test",
            summary="The attacker uses [AML.T0054] jailbreak.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Inject prompt.",
                    effect="System responds.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert "AML.T0054" in ids

    def test_bare_reference(self):
        """Extracts bare AML.T0054 references (no brackets)."""
        narrative = NarrativeLayer(
            title="Test",
            summary="Uses AML.T0051 technique.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Inject prompt.",
                    effect="System responds.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert "AML.T0051" in ids

    def test_technique_in_step_action(self):
        """Extracts technique IDs from step action text."""
        narrative = NarrativeLayer(
            title="Test",
            summary="A test.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Uses [AML.T0051.000] prompt injection.",
                    effect="System responds.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert "AML.T0051.000" in ids

    def test_technique_in_step_effect(self):
        """Extracts technique IDs from step effect text."""
        narrative = NarrativeLayer(
            title="Test",
            summary="A test.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Inject prompt.",
                    effect="AML.T0054 jailbreak succeeds.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert "AML.T0054" in ids

    def test_no_technique_ids(self):
        """Returns empty set when no technique IDs are present."""
        narrative = NarrativeLayer(
            title="Test",
            summary="No techniques mentioned.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Inject prompt.",
                    effect="System responds.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert ids == set()

    def test_multiple_ids_across_locations(self):
        """Collects technique IDs from summary and multiple steps."""
        narrative = NarrativeLayer(
            title="Test",
            summary="Attack uses AML.T0051.",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Applies [AML.T0054] jailbreak.",
                    effect="System responds with AML.T0051.001 effect.",
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
        ids = _extract_narrative_technique_ids(narrative)
        assert ids == {"AML.T0051", "AML.T0054", "AML.T0051.001"}


class TestNarrativeTechniqueOrphan:
    """Integration tests: narrative technique orphan detection via validate_scenario_semantics."""

    def test_no_orphan_when_techniques_match(self):
        """No orphan violation when all narrative techniques are in the tree."""
        profile = _make_profile()
        envelope = _make_envelope(
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Uses [AML.T0051] prompt injection.",
                    effect="System is compromised.",
                    projected_step_ids=("step.1",),
                    realizations=make_realizations(
                        ("step.1",),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
            ],
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        orphan_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "narrative_technique_orphan"
        ]
        assert len(orphan_violations) == 0

    def test_orphan_detected(self):
        """Technique in narrative but absent from tree is flagged."""
        profile = _make_profile()
        # Tree has AML.T0051 and AML.T0054, but narrative mentions AML.T0043
        envelope = _make_envelope(
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Uses [AML.T0043] crafting technique.",
                    effect="System is compromised.",
                    projected_step_ids=("step.1",),
                    realizations=make_realizations(
                        ("step.1",),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
            ],
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        orphan_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "narrative_technique_orphan"
        ]
        assert len(orphan_violations) == 1
        assert orphan_violations[0].severity == "minor"
        assert "AML.T0043" in orphan_violations[0].message

    def test_orphan_in_summary(self):
        """Orphan technique found in narrative summary is flagged."""
        profile = _make_profile()
        envelope = _make_envelope(
            narrative_summary="Attack uses AML.T0043 for evasion.",
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        orphan_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "narrative_technique_orphan"
        ]
        assert len(orphan_violations) == 1
        assert "AML.T0043" in orphan_violations[0].message

    def test_no_narrative_techniques_no_orphans(self):
        """When narrative mentions no technique IDs, no orphan violations."""
        profile = _make_profile()
        envelope = _make_envelope(
            narrative_summary="A generic attack.",
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        orphan_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "narrative_technique_orphan"
        ]
        assert len(orphan_violations) == 0


# ===========================================================================
# 2. Scenario-level threat_id completeness
# ===========================================================================


class TestCollectTreeNodeThreatIds:
    """Unit tests for _collect_tree_node_threat_ids helper."""

    def test_collects_all_threat_ids(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", threat_id="T1"),
                _leaf("n1.2", threat_id="T7"),
            ],
        )
        ids = _collect_tree_node_threat_ids(root)
        assert ids == {"T7", "T1"}

    def test_skips_none_threat_ids(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id=None,
            children=[
                _leaf("n1.1", threat_id="T1"),
                _leaf("n1.2", threat_id=None),
            ],
        )
        ids = _collect_tree_node_threat_ids(root)
        assert ids == {"T1"}

    def test_empty_when_all_none(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id=None,
            children=[
                _leaf("n1.1", threat_id=None),
                _leaf("n1.2", threat_id=None),
            ],
        )
        ids = _collect_tree_node_threat_ids(root)
        assert ids == set()


class TestMissingScenarioThreatId:
    """Integration tests: missing_scenario_threat_id via validate_scenario_semantics."""

    def test_scenario_threat_present_passes(self):
        """No violation when at least one node carries the scenario's threat_id."""
        profile = _make_profile()
        # Default tree root has threat_id="T7", seed expects T7
        envelope = _make_envelope(seed_metadata={"threat_id": "T7"})
        validate_scenario_semantics([envelope], profile)

        missing_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "missing_scenario_threat_id"
        ]
        assert len(missing_violations) == 0

    def test_scenario_threat_missing_flagged(self):
        """Violation when no tree node carries the scenario's threat_id."""
        profile = _make_profile()
        # Tree nodes have T1 and T3, but seed expects T7
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T1",
            children=[
                _leaf("n1.1", threat_id="T1"),
                _leaf("n1.2", threat_id="T3"),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        missing_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "missing_scenario_threat_id"
        ]
        assert len(missing_violations) == 1
        assert missing_violations[0].severity == "major"
        assert "T7" in missing_violations[0].message

    def test_no_seed_metadata_skips_check(self):
        """Without seed metadata, missing_scenario_threat_id check is skipped."""
        profile = _make_profile()
        # Tree has only T1, but no seed_metadata so check should not fire
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T1",
            children=[
                _leaf("n1.1", threat_id="T1"),
                _leaf("n1.2", threat_id="T1"),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata=None,
        )
        validate_scenario_semantics([envelope], profile)

        missing_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "missing_scenario_threat_id"
        ]
        assert len(missing_violations) == 0

    def test_threat_in_deep_child_passes(self):
        """Scenario threat_id in a deeply nested child still passes."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T1",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-goal",
                    gate=GateType.OR,
                    zone="reasoning",
                    threat_id="T3",
                    children=[
                        _leaf("n1.1.1", threat_id="T7"),  # scenario threat here
                        _leaf("n1.1.2", threat_id="T3"),
                    ],
                ),
                _leaf("n1.2", threat_id="T1"),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        missing_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "missing_scenario_threat_id"
        ]
        assert len(missing_violations) == 0

    def test_all_nodes_none_threat_id_flagged(self):
        """All nodes with None threat_id: the check fires."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id=None,
            children=[
                _leaf("n1.1", threat_id=None),
                _leaf("n1.2", threat_id=None),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        missing_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "missing_scenario_threat_id"
        ]
        assert len(missing_violations) == 1
        assert "T7" in missing_violations[0].message


# ===========================================================================
# 3. Zone omission hard flags
# ===========================================================================


class TestCollectTreeNodeZones:
    """Unit tests for _collect_tree_node_zones helper."""

    def test_collects_all_zones(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                _leaf("n1.1", zone="reasoning"),
                _leaf("n1.2", zone="tool_execution"),
            ],
        )
        zones = _collect_tree_node_zones(root)
        assert zones == {"input", "reasoning", "tool_execution"}

    def test_deduplicates(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                _leaf("n1.1", zone="input"),
                _leaf("n1.2", zone="input"),
            ],
        )
        zones = _collect_tree_node_zones(root)
        assert zones == {"input"}


class TestExtractGherkinZonesForValidation:
    """Unit tests for _extract_gherkin_zones_for_validation helper."""

    def test_hash_zone_comment(self):
        """Extracts zones from '# Zone reasoning' comments."""
        gherkin = """\
Feature: Test
  Scenario: Attack
    # Zone input
    Given an attacker
    # Zone reasoning
    When the system processes
"""
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert "input" in zones
        assert "reasoning" in zones

    def test_parenthesized_zone(self):
        """Extracts zones from (zone_name) inline annotations."""
        gherkin = """\
Feature: Test
  Scenario: Attack
    Given an attacker targets (input) channel
    When the (reasoning) engine processes
"""
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert "input" in zones
        assert "reasoning" in zones

    def test_no_zones(self):
        """Returns empty set when no zone annotations are present."""
        gherkin = "Feature: Test\n  Scenario: Attack\n    Given something"
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert zones == set()

    def test_invalid_zone_name_ignored(self):
        """Zone names not in ZONE_NAMES are ignored for parenthesized form."""
        gherkin = "Given (foobar) happens"
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert "foobar" not in zones

    def test_hash_zone_display_name_token(self):
        """Display-label tokens resolve to the canonical zone name."""
        gherkin = "Given a prompt\n# Zone Planning\nWhen the system reasons"
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert zones == {"reasoning"}

    def test_hash_zone_numeric_token(self):
        """Numeric zone annotations resolve via the 1-based name table."""
        gherkin = "Given a prompt\n# Zone 2\nWhen the system reasons"
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert zones == {"reasoning"}

    def test_hash_zone_unknown_token_ignored(self):
        """Unknown hash-zone tokens match neither names nor display labels."""
        gherkin = "Given a prompt\n# Zone foobar\nWhen the system reasons"
        zones = _extract_gherkin_zones_for_validation(gherkin)
        assert zones == set()


class TestZoneOmissionTree:
    """Integration tests: zone_omission_tree via validate_scenario_semantics."""

    def test_all_zones_covered_passes(self):
        """No violation when all narrative zones appear in tree."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                _leaf("n1.1", zone="input"),
                _leaf("n1.2", zone="reasoning"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        # Need a tree node with T7 to pass missing_scenario_threat_id
        tree_root.threat_id = "T7"
        envelope.attack_tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Compromise the system",
            root=tree_root,
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_tree"
        ]
        assert len(zone_violations) == 0

    def test_missing_zone_flagged(self):
        """Zone in narrative but absent from tree is flagged."""
        profile = _make_profile()
        # Tree only has "input" zone, narrative has "input" + "reasoning"
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", threat_id="T7"),
                _leaf("n1.2", zone="input", threat_id="T7"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_tree"
        ]
        assert len(zone_violations) == 1
        # "reasoning" is the terminal zone in ["input", "reasoning"] -> major
        assert zone_violations[0].severity == "major"
        assert "reasoning" in zone_violations[0].message

    def test_zone_in_deep_child_passes(self):
        """Zone present in a deeply nested child satisfies the check."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T7",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-goal",
                    gate=GateType.OR,
                    zone="reasoning",
                    threat_id="T7",
                    children=[
                        _leaf("n1.1.1", zone="tool_execution"),
                        _leaf("n1.1.2", zone="reasoning"),
                    ],
                ),
                _leaf("n1.2", zone="input"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning", "tool_execution"],
            tree_root=tree_root,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_tree"
        ]
        assert len(zone_violations) == 0


class TestZoneOmissionGherkin:
    """Integration tests: zone_omission_gherkin via validate_scenario_semantics."""

    def test_gherkin_covers_all_zones_passes(self):
        """No violation when Gherkin has zone annotations for all narrative zones."""
        profile = _make_profile()
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    # Zone reasoning
    When the system reasons
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        assert len(zone_violations) == 0

    def test_missing_zone_in_gherkin_flagged(self):
        """Zone in narrative but absent from Gherkin is flagged."""
        profile = _make_profile()
        # Gherkin only has "input" zone annotation
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    When the system processes
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        assert len(zone_violations) == 1
        assert zone_violations[0].severity == "minor"
        assert "reasoning" in zone_violations[0].message

    def test_non_string_behavior_spec_skips_gherkin_check(self):
        """When behavior_spec has no Gherkin zones, zone check finds none."""
        profile = _make_profile()
        # Use a BehaviorSpec with minimal Gherkin that has no zone mentions.
        from asago_scenario_generator.models.scenario import BehaviorSpec as _BS

        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            behavior_spec=_BS(
                actions=(),
                assertions=(),
                gherkin_text="Feature: Test\n  Scenario: Test\n    Given something\n",
            ),
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        # Gherkin without zone mentions produces zone omission violations
        # for each narrative zone not found in the Gherkin text.
        assert len(zone_violations) == 2

    def test_empty_behavior_spec_skips_gherkin_check(self):
        """BehaviorSpec with Gherkin containing all zones passes zone check."""
        profile = _make_profile()
        from asago_scenario_generator.models.scenario import BehaviorSpec as _BS

        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            behavior_spec=_BS(
                actions=(),
                assertions=(),
                gherkin_text=(
                    "Feature: Test\n"
                    "  Scenario: Test\n"
                    "    Given something in (input)\n"
                    "    Then something in (reasoning)\n"
                ),
            ),
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        assert len(zone_violations) == 0

    def test_parenthesized_zones_in_gherkin_pass(self):
        """Zones annotated as (zone_name) in Gherkin step text pass."""
        profile = _make_profile()
        gherkin = """\
Feature: Attack
  Scenario: Test
    Given an attacker targets the (input) channel
    When the (reasoning) engine processes the payload
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        zone_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        assert len(zone_violations) == 0


# ===========================================================================
# 4. Zone coverage dropout (cxy4)
# ===========================================================================


class TestZoneCoverageDropout:
    """Integration tests: zone_coverage_dropout via validate_scenario_semantics.

    A zone present in the narrative but absent from BOTH the attack tree
    AND the Gherkin behavior_spec is a hard consistency failure (severity
    'major').  If it is only missing from one of the two, the existing
    minor violations fire but zone_coverage_dropout does NOT.
    """

    def test_outside_boundary_zone_is_not_an_artifact_coverage_zone(self):
        """Outside is valid narrative context, not a tree/Gherkin zone."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T7"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["outside", "input"],
            tree_root=tree_root,
            behavior_spec="""\
Feature: Attack
  Scenario: Test
    # Zone input
    When the system receives the request
""",
            seed_metadata={"threat_id": "T7"},
        )

        validate_scenario_semantics([envelope], profile)

        boundary_zone_rules = {
            "zone_in_profile",
            "zone_omission_tree",
            "zone_omission_gherkin",
            "zone_coverage_dropout",
        }
        assert not any(
            violation.rule in boundary_zone_rules and "outside" in violation.message
            for violation in envelope.validation.semantic.violations
        )

    def test_zone_missing_from_tree_only_no_dropout(self):
        """Zone absent from tree but present in Gherkin -> minor only, no dropout."""
        profile = _make_profile()
        # Tree only has "input", Gherkin has both "input" and "reasoning"
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T7"),
            ],
        )
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    # Zone reasoning
    When the system reasons
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        tree_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_tree"
        ]
        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        assert len(tree_violations) == 1  # reasoning missing from tree
        # "reasoning" is the terminal zone in ["input", "reasoning"] -> major
        assert tree_violations[0].severity == "major"
        assert len(dropout_violations) == 0  # NOT a dropout — Gherkin covers it

    def test_zone_missing_from_gherkin_only_no_dropout(self):
        """Zone absent from Gherkin but present in tree -> minor only, no dropout."""
        profile = _make_profile()
        # Tree has both zones, Gherkin only has "input"
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T7"
                ),
            ],
        )
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    When the system processes
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        gherkin_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_omission_gherkin"
        ]
        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        assert len(gherkin_violations) == 1  # reasoning missing from Gherkin
        assert gherkin_violations[0].severity == "minor"
        assert len(dropout_violations) == 0  # NOT a dropout — tree covers it

    def test_zone_missing_from_both_triggers_dropout(self):
        """Zone absent from BOTH tree AND Gherkin -> major zone_coverage_dropout."""
        profile = _make_profile()
        # Tree only has "input", Gherkin only has "input"
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T7"),
            ],
        )
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    When the system processes
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        assert len(dropout_violations) == 1
        assert dropout_violations[0].severity == "major"
        assert "reasoning" in dropout_violations[0].message
        assert "BOTH" in dropout_violations[0].message

    def test_all_zones_covered_no_dropout(self):
        """All narrative zones present in tree and Gherkin -> no dropout."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T7"
                ),
            ],
        )
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker
    # Zone reasoning
    When the system reasons
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        assert len(dropout_violations) == 0

    def test_multiple_zones_dropped_multiple_violations(self):
        """Multiple zones dropped from both tree and Gherkin -> multiple major violations."""
        profile = _make_profile()
        # Tree and Gherkin only have "tool_execution"
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="tool_execution",
            threat_id="T7",
            children=[
                _leaf(
                    "n1.1",
                    zone="tool_execution",
                    technique_id="AML.T0051",
                    threat_id="T7",
                ),
                _leaf(
                    "n1.2",
                    zone="tool_execution",
                    technique_id="AML.T0054",
                    threat_id="T7",
                ),
            ],
        )
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone tool_execution
    Given attacker uses tools
"""
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning", "tool_execution"],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        assert len(dropout_violations) == 2  # input + reasoning both dropped
        dropped_zones = {v.message.split("'")[1] for v in dropout_violations}
        assert dropped_zones == {"input", "reasoning"}
        assert all(v.severity == "major" for v in dropout_violations)

    def test_no_gherkin_text_dropout_from_tree_only(self):
        """When behavior_spec is empty, gherkin_zones is empty; dropout based on tree only."""
        profile = _make_profile()
        # Tree only has "input", no Gherkin text
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T7"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            tree_root=tree_root,
            behavior_spec="Feature: test\n",  # no zone markers -> gherkin_zones = set()
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        dropout_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "zone_coverage_dropout"
        ]
        # reasoning is missing from tree and gherkin is empty -> dropout
        assert len(dropout_violations) == 1
        assert "reasoning" in dropout_violations[0].message


# ===========================================================================
# Combined validator interactions
# ===========================================================================


class TestCombinedValidatorInteractions:
    """Verify that the three new validators work together correctly."""

    def test_clean_scenario_passes_all(self):
        """A well-formed scenario passes all three validators with no violations."""
        profile = _make_profile()
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given an attacker uses [AML.T0051] injection
    # Zone reasoning
    When the system reasons about the input
"""
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T7",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T7"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T7"
                ),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Uses [AML.T0051] prompt injection.",
                    effect="System processes.",
                    projected_step_ids=("step.1",),
                    realizations=make_realizations(
                        ("step.1",),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
            ],
            narrative_summary="Attack using AML.T0054 jailbreak.",
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        new_rules = {
            "narrative_technique_orphan",
            "missing_scenario_threat_id",
            "zone_omission_tree",
            "zone_omission_gherkin",
            "zone_coverage_dropout",
        }
        new_violations = [
            v for v in envelope.validation.semantic.violations if v.rule in new_rules
        ]
        assert len(new_violations) == 0

    def test_multiple_violations_across_validators(self):
        """All three validators can fire on the same scenario."""
        profile = _make_profile()
        # Gherkin missing "reasoning" zone
        gherkin = """\
Feature: Attack
  Scenario: Test
    # Zone input
    Given attacker
"""
        # Tree missing "reasoning" zone + T7 threat, narrative has orphan technique
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T1",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0051", threat_id="T1"),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T3"),
            ],
        )
        envelope = _make_envelope(
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Uses [AML.T0043] crafting technique.",
                    effect="System processes.",
                    projected_step_ids=("step.1",),
                    realizations=make_realizations(
                        ("step.1",),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
            ],
            tree_root=tree_root,
            behavior_spec=gherkin,
            seed_metadata={"threat_id": "T7"},
        )
        validate_scenario_semantics([envelope], profile)

        rules_found = {v.rule for v in envelope.validation.semantic.violations}
        assert "narrative_technique_orphan" in rules_found  # AML.T0043 orphan
        assert "missing_scenario_threat_id" in rules_found  # T7 not in tree
        assert "zone_omission_tree" in rules_found  # reasoning not in tree
        assert "zone_omission_gherkin" in rules_found  # reasoning not in gherkin
        assert "zone_coverage_dropout" in rules_found  # reasoning dropped from both
