"""Tests for semantic validation of scenario envelopes.

Covers:
- Valid technique_ids pass
- Invalid technique_ids are flagged
- Zone values not in profile are flagged
- Multiple violations are collected
- Validation block is populated correctly
- validation_passed is updated
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
    ValidationBlock,
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


def _make_envelope(
    technique_ids: list[str | None] | None = None,
    zone_sequence: list[str] | None = None,
    seed_metadata: dict | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing.

    Args:
        technique_ids: Technique IDs to set on leaf nodes.
            If None, uses ["AML.T0051.000", None] (one valid, one absent).
        zone_sequence: Zones for the narrative.
        seed_metadata: Scenario seed metadata dict.
    """
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

    # Build tree leaves with given technique_ids
    if technique_ids is None:
        technique_ids = ["AML.T0051.000", None]

    children = []
    for i, tid in enumerate(technique_ids):
        # Assign zones from zone_sequence to cover all narrative zones in the tree.
        child_zone = zone_sequence[i % len(zone_sequence)]
        children.append(
            AttackTreeNode(
                id=f"n1.{i + 1}",
                label=f"Step {i + 1}",
                gate=GateType.LEAF,
                zone=child_zone,
                technique_id=tid,
            )
        )
    # Ensure at least 2 children for OR gate
    while len(children) < 2:
        child_zone = zone_sequence[len(children) % len(zone_sequence)]
        children.append(
            AttackTreeNode(
                id=f"n1.{len(children) + 1}",
                label=f"Step {len(children) + 1}",
                gate=GateType.LEAF,
                zone=child_zone,
            )
        )

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
    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=children,
        ),
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
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSemanticValidation:
    """Tests for validate_scenario_semantics."""

    def test_valid_technique_ids_pass(self):
        """Known ATLAS technique IDs pass semantic validation."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=["AML.T0051.000", "AML.T0051.001"])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is True
        assert envelope.validation.semantic.violations == []

    def test_all_committed_atlas_techniques_are_valid(self):
        """Techniques added by the pinned ATLAS release pass validation."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=["AML.T0065", "AML.T0068"])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        violations = envelope.validation.semantic.violations
        assert [v for v in violations if v.rule == "technique_exists"] == []

    def test_unknown_technique_id_flagged(self):
        """An unknown technique ID is flagged as a semantic violation."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=["AML.T9999", None])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is False
        assert len(envelope.validation.semantic.violations) == 1
        v = envelope.validation.semantic.violations[0]
        assert v.rule == "technique_exists"
        assert "AML.T9999" in v.message
        assert v.severity == "major"

    def test_laaf_technique_ids_pass(self):
        """LAAF technique IDs (S1, M2, etc.) pass semantic validation."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=["S1", "M2"])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is True

    def test_zone_not_in_profile_flagged(self):
        """A zone not in profile's zones_active is flagged."""
        profile = _make_profile(zones_active=["input", "reasoning"])
        envelope = _make_envelope(zone_sequence=["input", "memory"])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is False
        violations = envelope.validation.semantic.violations
        zone_violations = [v for v in violations if v.rule == "zone_in_profile"]
        assert len(zone_violations) == 1
        assert "memory" in zone_violations[0].message
        assert zone_violations[0].severity == "minor"

    def test_all_zones_valid(self):
        """When all zones are in the profile, no zone violations."""
        profile = _make_profile(zones_active=["input", "reasoning", "tool_execution"])
        envelope = _make_envelope(zone_sequence=["input", "reasoning"])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is True

    def test_multiple_violations(self):
        """Multiple types of violations are collected."""
        profile = _make_profile(zones_active=["input", "reasoning"])
        envelope = _make_envelope(
            technique_ids=["AML.T9999", None],
            zone_sequence=["input", "memory"],
        )
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is False
        rules = {v.rule for v in envelope.validation.semantic.violations}
        assert "technique_exists" in rules
        assert "zone_in_profile" in rules

    def test_validation_block_created_when_none(self):
        """When validation is None, semantic validation creates the block."""
        profile = _make_profile()
        envelope = _make_envelope()
        assert envelope.validation is None
        validate_scenario_semantics([envelope], profile)
        assert envelope.validation is not None
        assert envelope.validation.semantic is not None

    def test_validation_block_updated_when_exists(self):
        """When validation block already exists, semantic updates it."""
        profile = _make_profile()
        envelope = _make_envelope()
        envelope.validation = ValidationBlock()
        validate_scenario_semantics([envelope], profile)
        assert envelope.validation.semantic.valid is True

    def test_validation_passed_reflects_semantic(self):
        """validation_passed reflects semantic result."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=["AML.T9999", None])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation_passed is False

    def test_no_technique_ids_passes(self):
        """Envelope with no technique IDs on any node still passes."""
        profile = _make_profile()
        envelope = _make_envelope(technique_ids=[None, None])
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        assert envelope.validation.semantic.valid is True

    def test_multiple_envelopes(self):
        """Semantic validation runs on all envelopes."""
        profile = _make_profile()
        envelopes = [
            _make_envelope(technique_ids=["AML.T0051.000", None]),
            _make_envelope(technique_ids=["AML.T9999", None]),
        ]
        validate_scenario_semantics(envelopes, profile)

        assert envelopes[0].validation.semantic.valid is True
        assert envelopes[1].validation.semantic.valid is False


class TestSemanticValidationThreatIdConsistency:
    """Tests for threat_id consistency check in semantic validation."""

    def test_no_seed_metadata_skips_check(self):
        """Without scenario_seed_metadata, threat_id check is skipped."""
        profile = _make_profile()
        envelope = _make_envelope(seed_metadata=None)
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        # Should pass since the check is skipped
        threat_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "threat_id_matches_seed"
        ]
        assert len(threat_violations) == 0

    def test_with_seed_metadata_no_threat_id(self):
        """Seed metadata without threat_id key skips the check."""
        profile = _make_profile()
        envelope = _make_envelope(
            seed_metadata={"seed_id": "AP-T1-01", "attack_pattern_name": "Test"}
        )
        validate_scenario_semantics([envelope], profile)

        assert envelope.validation is not None
        threat_violations = [
            v
            for v in envelope.validation.semantic.violations
            if v.rule == "threat_id_matches_seed"
        ]
        assert len(threat_violations) == 0
