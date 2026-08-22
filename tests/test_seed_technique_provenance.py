"""Tests for seed technique provenance validation (0lfx).

Covers:
- Positive case: seed technique present in tree -> no violation
- Negative case: seed technique absent from tree -> violation flagged
- Edge case: no seed metadata -> check skipped
- Edge case: empty laaf_technique_ids -> check skipped
- Edge case: partial match (1 of N seed techniques) -> passes
"""

from __future__ import annotations

from datetime import UTC, datetime

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ToolInventoryEntry,
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
from asago_scenario_generator.pipeline.validation import validate_scenario_semantics
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
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=["user prompts (zone 1)"],
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
    )


def _leaf(
    node_id: str,
    zone: str = "input",
    technique_id: str | None = None,
    threat_id: str | None = None,
) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=f"Step {node_id}",
        gate=GateType.LEAF,
        zone=zone,
        action=AiSystemAction(),
        technique_id=technique_id,
        threat_id=threat_id,
    )


def _make_envelope(
    zone_sequence: list[str] | None = None,
    tree_root: AttackTreeNode | None = None,
    seed_metadata: dict | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

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
        summary="A test summary.",
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
            threat_id="T10",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0029", threat_id="T10"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T10"
                ),
            ],
        )

    attack_tree = AttackTree(
        id="tree-AP-T10-02",
        seed_id="AP-T10-02",
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
            agentic_threat_ids=["T10"],
            scenario_seed="AP-T10-02",
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
        scenario_id="scenario:v2:ff6276e5c312934a645c4801d2bce454291be257a3a31ff510af2c9dd3f61143",
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
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSeedTechniqueProvenance:
    """Tests for seed_technique_provenance semantic check."""

    def test_seed_technique_present_in_tree_passes(self):
        """No violation when a seed technique appears in the attack tree."""
        profile = _make_profile()
        # Tree has AML.T0029, seed expects AML.T0029
        envelope = _make_envelope(
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["AML.T0029"],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_atlas_provenance_is_checked_instead_of_laaf_namespace(self):
        """LAAF S/M provenance cannot be compared to ATLAS tree IDs."""
        profile = _make_profile()
        envelope = _make_envelope(
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["S3", "M5"],
                "atlas_provenance_ids": ["AML.T0029"],
            },
        )

        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            violation
            for violation in envelope.validation.semantic.violations
            if violation.rule == "seed_technique_provenance"
        ]
        assert provenance_violations == []

    def test_seed_technique_absent_from_tree_flagged(self):
        """Violation when no seed technique appears in the attack tree."""
        profile = _make_profile()
        # Tree has AML.T0054 only, seed expects AML.T0029
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T10",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0054", threat_id="T10"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0054", threat_id="T10"
                ),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["AML.T0029"],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 1
        v = provenance_violations[0]
        assert v.severity == "major"
        assert "AML.T0029" in v.message
        assert "AML.T0054" in v.message

    def test_no_seed_metadata_skips_check(self):
        """Without scenario_seed_metadata, the check is skipped."""
        profile = _make_profile()
        envelope = _make_envelope(seed_metadata=None)
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_empty_laaf_technique_ids_skips_check(self):
        """With empty laaf_technique_ids list, the check is skipped."""
        profile = _make_profile()
        envelope = _make_envelope(
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": [],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_no_laaf_technique_ids_key_skips_check(self):
        """With seed_metadata but no laaf_technique_ids key, check is skipped."""
        profile = _make_profile()
        envelope = _make_envelope(
            seed_metadata={
                "threat_id": "T10",
                "seed_id": "AP-T10-02",
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_partial_match_passes(self):
        """Partial provenance: 1 of 2 seed techniques present -> passes."""
        profile = _make_profile()
        # Tree has AML.T0029 but not AML.T0043; seed has both
        envelope = _make_envelope(
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["AML.T0029", "AML.T0043"],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_technique_in_deep_nested_child_passes(self):
        """Seed technique found in a deeply nested tree node still passes."""
        profile = _make_profile()
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T10",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-goal",
                    gate=GateType.OR,
                    zone="reasoning",
                    threat_id="T10",
                    children=[
                        _leaf(
                            "n1.1.1",
                            zone="input",
                            technique_id="AML.T0054",
                            threat_id="T10",
                        ),
                        _leaf(
                            "n1.1.2",
                            zone="reasoning",
                            technique_id="AML.T0029",
                            threat_id="T10",
                        ),
                    ],
                ),
                _leaf("n1.2", zone="input", technique_id="AML.T0054", threat_id="T10"),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["AML.T0029"],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 0

    def test_complete_dropout_multiple_seed_techniques(self):
        """Complete dropout: none of multiple seed techniques appear in tree."""
        profile = _make_profile()
        # Tree has only AML.T0054, seed expects AML.T0029 and AML.T0043
        tree_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T10",
            children=[
                _leaf("n1.1", zone="input", technique_id="AML.T0054", threat_id="T10"),
                _leaf(
                    "n1.2", zone="reasoning", technique_id="AML.T0051", threat_id="T10"
                ),
            ],
        )
        envelope = _make_envelope(
            tree_root=tree_root,
            seed_metadata={
                "threat_id": "T10",
                "laaf_technique_ids": ["AML.T0029", "AML.T0043"],
            },
        )
        validate_scenario_semantics([envelope], profile)

        provenance_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "seed_technique_provenance"
        ]
        assert len(provenance_violations) == 1
        v = provenance_violations[0]
        assert v.severity == "major"
        assert "AML.T0029" in v.message
        assert "AML.T0043" in v.message
