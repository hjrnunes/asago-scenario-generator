"""Leaf mapping validation and legacy provenance-reader compatibility.

Legacy envelopes remain readable without classification/leaf intersection.
Explicit per-leaf projected mapping regressions live in test_technique_scopes.
The historical consequence classifier remains covered here.
"""

from __future__ import annotations

from datetime import UTC, datetime

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    GateType,
    ImpactAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.attack_tree import (
    AttackTreeNode as _AttackTreeNode,
)
from asago_scenario_generator.models.capability_profile import compute_tool_id
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
    LeafTechniqueViolation,
    _is_consequence_leaf,
    _leaf_mapping_reason,
    _leaf_provenance_reasons,
    check_leaf_technique_provenance,
)
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block
from tests.helpers.realization_helper import make_realizations


def AttackTreeNode(**kwargs) -> _AttackTreeNode:
    """Build a node, supplying the typed action required by leaf nodes."""
    if kwargs.get("gate") == GateType.LEAF and "action" not in kwargs:
        zone = kwargs.get("zone")
        if zone == "tool_execution":
            kwargs["action"] = ToolInvocationAction(
                tool_id=compute_tool_id("test_tool", "A test tool")
            )
        elif zone == "output":
            kwargs["zone"] = None
            kwargs["action"] = ImpactAction(boundary="external", target=kwargs["label"])
        else:
            kwargs["action"] = AiSystemAction()
    return _AttackTreeNode(**kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_envelope(
    root: AttackTreeNode,
    scenario_id: str = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
    atlas_provenance_ids: list[str] | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope with a custom tree root.

    Parameters
    ----------
    atlas_provenance_ids:
        ATLAS technique IDs from the seed's provenance.  Stored in
        ``scenario_seed_metadata["atlas_provenance_ids"]``.
    """
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft a malicious prompt.",
                effect="The system processes the input.",
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

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
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
            atlas_technique_ids=["AML.T0051"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
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

    seed_metadata = {
        "seed_id": "AP-T1-01",
        "threat_id": "T1",
        "threat_name": "Test Threat",
        "attack_pattern_name": "Test Pattern",
        "attack_pattern_description": "A test attack pattern.",
        "atlas_provenance_ids": atlas_provenance_ids or [],
    }

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id=scenario_id,
        candidate_id="cand:v2:7e57c0de000000000000000000000000",
        initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        scenario_seed_metadata=seed_metadata,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: at least one provenance-matching leaf -> clean
# ---------------------------------------------------------------------------


class TestCleanScenarios:
    """Scenarios with at least one provenance-matching leaf are clean."""

    def test_one_leaf_matches_provenance(self) -> None:
        """A single annotated leaf matching provenance is sufficient."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_multiple_leaves_one_matches(self) -> None:
        """Only one leaf needs to match provenance for clean result."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Exploit reasoning flaw",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0099",  # Not in provenance
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_unannotated_leaves_alongside_provenance_match(self) -> None:
        """Unannotated leaves are excluded; provenance match still holds."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                    # No technique_id — legitimate unannotated step
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Trigger escalation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id — legitimate unannotated step
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_partial_provenance_accepted(self) -> None:
        """Matching 1 of 2 provenance IDs is accepted (partial provenance)."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe behavior",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051", "AML.T0052"],
        )
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_deep_tree_provenance_match(self) -> None:
        """Deeply nested leaf matching provenance is found."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Stage 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Observe system behavior",
                            gate=GateType.LEAF,
                            zone="tool_execution",
                            # No technique_id
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Stage 2",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_empty_list(self) -> None:
        result = check_leaf_technique_provenance([])
        assert result.clean_count == 0
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: flagged scenarios
# ---------------------------------------------------------------------------


class TestFlaggedScenarios:
    """Scenarios without a provenance-matching leaf are flagged."""

    def test_technique_ids_none_from_provenance(self) -> None:
        """Leaves have technique_ids but none match provenance set."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0099",  # Not in provenance
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Exploit reasoning flaw",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0098",  # Not in provenance
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051", "AML.T0052"],
        )
        result = check_leaf_technique_provenance([scenario])

        # Legacy envelopes remain readable and do not reinstate the removed
        # scenario-classification/leaf-intersection requirement.
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_all_unannotated_leaves(self) -> None:
        """No leaves carry any technique_id at all -> flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Craft phishing lure",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Deliver payload via injection",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(
            root,
            atlas_provenance_ids=["AML.T0051"],
        )
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_no_seed_metadata(self) -> None:
        """Scenario with no seed metadata is flagged (empty provenance)."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=[])
        # Clear seed metadata to simulate missing data
        scenario.scenario_seed_metadata = None
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_empty_provenance_set(self) -> None:
        """Scenario with empty atlas_provenance_ids is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=[])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_violation_uses_root_node(self) -> None:
        """Violation references the root node (scenario-level issue)."""
        root = AttackTreeNode(
            id="n1",
            label="Attack Goal",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Some step",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Another step",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 0
        assert result.clean_count == 1


# ---------------------------------------------------------------------------
# Tests: consequence leaf exemption still works
# ---------------------------------------------------------------------------


class TestConsequenceExemption:
    """Consequence leaves do not block clean status under new semantic.

    Unannotated leaves (including consequence leaves) are excluded from
    the check.  A scenario is clean as long as at least one annotated
    leaf matches the provenance set.
    """

    def test_consequence_leaf_with_provenance_match(self) -> None:
        """Consequence leaf (no technique_id) + provenance match -> clean."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Victim transfers funds to attacker account",
                    gate=GateType.LEAF,
                    zone="output",
                    # No technique_id — consequence leaf
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_data_exfiltrated_with_provenance_match(self) -> None:
        """Data exfiltration consequence leaf alongside provenance match."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Credentials stolen via side channel",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_only_consequence_leaves_flagged(self) -> None:
        """Tree with only consequence leaves (no technique_ids) is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Victim transfers funds to attacker account",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System fully compromised",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_provenance_ids=["AML.T0051"])
        result = check_leaf_technique_provenance([scenario])

        assert result.flagged_count == 0
        assert result.clean_count == 1


# ---------------------------------------------------------------------------
# Tests: mixed scenarios (some clean, some flagged)
# ---------------------------------------------------------------------------


class TestMixedBatch:
    """A batch with both clean and flagged scenarios."""

    def test_mixed_batch(self) -> None:
        """One clean scenario and one flagged in the same batch."""
        clean_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Observe response",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        clean = _make_envelope(
            clean_root,
            scenario_id="scenario:v2:bb38b4af8c113eb1fc7205a1f3030844be1213755be8c6bb125154e814f6022a",
            atlas_provenance_ids=["AML.T0051"],
        )

        flagged_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0099",  # Not in provenance
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Follow up step",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        flagged = _make_envelope(
            flagged_root,
            scenario_id="scenario:v2:34e61bd22ffe221825d3fa7a207f099970199c631e0017bdc9eb616d3afec29d",
            atlas_provenance_ids=["AML.T0051"],
        )

        result = check_leaf_technique_provenance([clean, flagged])

        assert result.clean_count == 2
        assert result.flagged_count == 0
        assert {scenario.scenario_id for scenario in result.clean_scenarios} == {
            "scenario:v2:bb38b4af8c113eb1fc7205a1f3030844be1213755be8c6bb125154e814f6022a",
            "scenario:v2:34e61bd22ffe221825d3fa7a207f099970199c631e0017bdc9eb616d3afec29d",
        }


# ---------------------------------------------------------------------------
# Tests: _is_consequence_leaf heuristic
# ---------------------------------------------------------------------------


class TestIsConsequenceLeaf:
    """Unit tests for the _is_consequence_leaf heuristic."""

    def _node(self, label: str, description: str | None = None) -> AttackTreeNode:
        return AttackTreeNode(
            id="n1.1",
            label=label,
            description=description,
            gate=GateType.LEAF,
            zone="output",
        )

    def _active_node(self, label: str) -> AttackTreeNode:
        return AttackTreeNode(
            id="n1.1",
            label=label,
            gate=GateType.LEAF,
            zone="reasoning",
            action=AiSystemAction(),
        )

    def test_victim_transfers(self) -> None:
        assert _is_consequence_leaf(self._node("Victim transfers funds"))

    def test_victim_reveals(self) -> None:
        assert _is_consequence_leaf(self._node("Victim reveals credentials"))

    def test_data_exfiltrated(self) -> None:
        assert _is_consequence_leaf(self._node("Data exfiltrated to C2"))

    def test_credentials_stolen(self) -> None:
        assert _is_consequence_leaf(self._node("Credentials stolen via phishing"))

    def test_funds_diverted(self) -> None:
        assert _is_consequence_leaf(self._node("Funds diverted to attacker"))

    def test_system_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("System compromised"))

    def test_system_fully_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("System fully compromised"))

    def test_breach_completed(self) -> None:
        assert _is_consequence_leaf(self._node("Breach completed"))

    def test_attack_succeeds(self) -> None:
        assert _is_consequence_leaf(self._node("Attack succeeds"))

    def test_achieve_objective(self) -> None:
        assert _is_consequence_leaf(self._node("Achieve attack objective"))

    def test_exfiltrate_data(self) -> None:
        assert _is_consequence_leaf(self._node("Exfiltrate sensitive records"))

    def test_siphon_funds(self) -> None:
        assert _is_consequence_leaf(self._node("Siphon funds from account"))

    def test_gain_persistent_access(self) -> None:
        assert _is_consequence_leaf(self._node("Gain persistent access"))

    def test_obtain_unauthorized_access(self) -> None:
        assert _is_consequence_leaf(self._node("Obtain unauthorized access"))

    def test_impact_realized(self) -> None:
        assert _is_consequence_leaf(self._node("Impact realized across systems"))

    def test_information_leaked(self) -> None:
        assert _is_consequence_leaf(self._node("Information leaked to adversary"))

    def test_assets_compromised(self) -> None:
        assert _is_consequence_leaf(self._node("Assets compromised"))

    # --- Non-consequence labels (attack work) ---

    def test_inject_payload_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._active_node("Inject malicious payload"))

    def test_craft_phishing_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._active_node("Craft phishing lure"))

    def test_manipulate_reasoning_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._active_node("Manipulate reasoning via context injection")
        )

    def test_establish_rapport_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._active_node("Establish rapport with target employee")
        )

    def test_deliver_payload_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._active_node("Deliver social engineering payload")
        )

    def test_exploit_tool_not_consequence(self) -> None:
        assert not _is_consequence_leaf(
            self._active_node("Exploit tool execution vulnerability")
        )

    def test_bypass_guardrails_not_consequence(self) -> None:
        assert not _is_consequence_leaf(self._active_node("Bypass input guardrails"))

    def test_description_triggers_consequence(self) -> None:
        """Consequence pattern in description counts."""
        node = self._node(
            "Final step",
            description="The victim sends credentials to the attacker.",
        )
        assert _is_consequence_leaf(node)

    def test_label_only_no_description(self) -> None:
        """Attack-work label without description is not consequence."""
        node = self._active_node("Perform lateral movement")
        assert not _is_consequence_leaf(node)


# ---------------------------------------------------------------------------
# Tests: violation data class
# ---------------------------------------------------------------------------


class TestLeafTechniqueViolation:
    """Verify violation data class fields."""

    def test_fields(self) -> None:
        v = LeafTechniqueViolation(
            node_id="n1.2",
            label="Craft phishing lure",
            zone="input",
            reason="Missing technique provenance.",
        )
        assert v.node_id == "n1.2"
        assert v.label == "Craft phishing lure"
        assert v.zone == "input"
        assert "provenance" in v.reason


# ---------------------------------------------------------------------------
# Tests: leaf mapping reason helper branches
# ---------------------------------------------------------------------------


class TestLeafMappingReason:
    """Direct coverage of the per-leaf provenance mismatch reason."""

    def _leaf(self, **kwargs) -> _AttackTreeNode:
        projected_ids = kwargs.get("projected_step_ids")
        if projected_ids:
            kwargs.setdefault(
                "realizations",
                make_realizations(
                    projected_ids,
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            )
        return AttackTreeNode(
            id="n1.1", label="Step", gate=GateType.LEAF, zone="input", **kwargs
        )

    def test_unannotated_technique_is_clean(self) -> None:
        leaf = self._leaf(technique_id=None, projected_step_ids=("step.1",))
        assert _leaf_mapping_reason(leaf, {"step.1": frozenset({"AML.T0051"})}) is None

    def test_leaf_without_projected_step_ids_is_flagged(self) -> None:
        leaf = self._leaf(technique_id="AML.T0051")
        reason = _leaf_mapping_reason(leaf, {})
        assert reason is not None
        assert "without projected-step IDs" in reason
        assert "AML.T0051" in reason

    def test_exact_technique_mapping_is_clean(self) -> None:
        leaf = self._leaf(
            technique_id="AML.T0051", projected_step_ids=("step.1", "step.2")
        )
        exact = {
            "step.1": frozenset({"AML.T0051", "AML.T0001"}),
            "step.2": frozenset({"AML.T0051"}),
        }
        assert _leaf_mapping_reason(leaf, exact) is None

    def test_mismatched_technique_is_flagged(self) -> None:
        leaf = self._leaf(technique_id="AML.T0051", projected_step_ids=("step.1",))
        exact = {"step.1": frozenset({"AML.T0001"})}
        reason = _leaf_mapping_reason(leaf, exact)
        assert reason is not None
        assert "not an exact mapping" in reason
        assert "['step.1']" in reason

    def test_partial_mismatch_lists_offending_steps(self) -> None:
        leaf = self._leaf(
            technique_id="AML.T0051", projected_step_ids=("step.1", "step.2")
        )
        exact = {
            "step.1": frozenset({"AML.T0051"}),
            "step.2": frozenset({"AML.T0001"}),
        }
        reason = _leaf_mapping_reason(leaf, exact)
        assert reason is not None
        assert "step.2" in reason
        assert "step.1" not in reason


class TestLeafProvenanceReasons:
    """Aggregate per-leaf reasons keep only non-None entries."""

    def test_mismatches_only(self) -> None:
        good = AttackTreeNode(
            id="n1.1",
            label="Good",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0001",
            projected_step_ids=("step.1",),
            realizations=make_realizations(
                ("step.1",),
                action_kind="prepare",
                executor_role="attacker",
                boundary_position="crossing",
            ),
        )
        bad = AttackTreeNode(
            id="n1.2",
            label="Bad",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0051",
            projected_step_ids=("step.1",),
            realizations=make_realizations(
                ("step.1",),
                action_kind="prepare",
                executor_role="attacker",
                boundary_position="crossing",
            ),
        )
        exact = {"step.1": frozenset({"AML.T0001"})}
        reasons = _leaf_provenance_reasons([good, bad], exact)
        assert len(reasons) == 1
        assert "n1.2" in reasons[0]

    def test_all_clean_yields_no_reasons(self) -> None:
        leaf = AttackTreeNode(
            id="n1.1",
            label="Good",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0051",
            projected_step_ids=("step.1",),
            realizations=make_realizations(
                ("step.1",),
                action_kind="prepare",
                executor_role="attacker",
                boundary_position="crossing",
            ),
        )
        exact = {"step.1": frozenset({"AML.T0051"})}
        assert _leaf_provenance_reasons([leaf], exact) == []
