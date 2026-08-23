"""Adversarial tests for projection persistence and artifact traceability.

Bead asago-scenario-generator-422o.4: Persist kill-chain projections and enforce
artifact traceability.

Covers:
  - Deep nested mutation detection
  - Omitted/reordered/duplicated projected steps
  - Unprojected security actions
  - Incomplete many-to-many coverage
  - Incorrect resource/ingress binding
  - Forged opaque IDs
  - Postcondition/assertion mismatch
  - OR trees prohibited
  - Verify-only recomputation drift
  - Ingress identity mismatch
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    AuthoritativeFactReference,
    EntryPointResourceReference,
    EvaluatedFactEvidence,
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ImpactAction,
    InitialIngressAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    AssertionRealizationMapping,
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    BehaviorAction,
    BehaviorAssertion,
    BehaviorSpec,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    ScenarioEnvelope,
)
from asago_scenario_generator.pipeline.generate.gherkin import (
    Call3Assertion,
    Call3Response,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _check_order_preservation,
)
from asago_scenario_generator.pipeline.projection import (
    ProjectionBudget,
    capture_capability_snapshot,
    compute_derivation_context_digest,
    project_authoritative_candidates,
)
from asago_scenario_generator.pipeline.projection_validation import (
    validate_projection_traceability,
)
from tests.helpers.projection_factory import (
    get_projected_candidate,
    make_behavior_spec,
    make_step_realizations,
)
from tests.helpers.realization_helper import make_realizations

ZERO = "0" * 64


# ---------------------------------------------------------------------------#
# Taxonomy resolver
# ---------------------------------------------------------------------------#


class TaxonomyResolver:
    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
        }


# ---------------------------------------------------------------------------#
# Pattern/chain fixtures
# ---------------------------------------------------------------------------#


def _fact() -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": "string",
        "property_path": [],
    }


def _step(step_id: str, order: int, *, conditional: bool = False) -> dict[str, Any]:
    final = order == 3
    attacker = order == 1
    return {
        "step_id": step_id,
        "requirement": "conditional" if conditional else "required",
        "condition": (
            {
                "op": "equality",
                "schema_version": "1",
                "fact": _fact(),
                "value": "active",
            }
            if conditional
            else None
        ),
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
        "consumed": (
            [{"kind": "state", "ref_id": "state.1", "value_type": "boolean"}]
            if order == 2
            else []
        ),
        "produced": [
            {"kind": "effect", "ref_id": f"effect.{order}", "value_type": "boolean"}
        ],
        "preconditions": [],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "observable",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "resource_links": (
            [{"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None}]
            if attacker
            else [
                {
                    "slot_id": "tool",
                    "role": "tool_fixture",
                    "trust_boundary_slot_id": None,
                }
            ]
            if order == 2
            else []
        ),
        "observable_outcome_links": (
            [
                {
                    "postcondition_id": f"post.{order}",
                    "observation": "model_context",
                    "binding_slot_id": "ingress",
                }
            ]
            if final
            else []
        ),
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"}
            ],
            "confidence": 90,
            "adaptation_rationale": "represented",
        },
        "mappings": (
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _pattern(*, conditional: bool = True) -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": None,
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": [
            _step("step.1", 1),
            _step("step.2", 2, conditional=conditional),
            _step("step.3", 3),
        ],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"},
            {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
            {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
            {
                "slot_id": "boundary",
                "kind": "trust_boundary",
                "purpose": "intermediate",
            },
        ],
        "initial_ingress_slot_id": "ingress",
    }
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain,
    }


def _profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "RAG documents",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )


def _evidence(value: str = "active") -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(_fact()),
        status="present",
        value=value,
    )


def _project():
    """Project candidates and return the first candidate + resolver + snapshot."""
    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    batch = project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    )
    assert len(batch.candidates) >= 1
    return batch.candidates[0], resolver, snapshot, raw


def _ingress_id() -> str:
    """Get the canonical ingress entry_point_id from the projection."""
    candidate, _, _, _ = _project()
    return candidate.canonical_ingress.entry_point_id


# ---------------------------------------------------------------------------#
# Build a valid ProjectionEnvelopeBlock + ScenarioEnvelope
# ---------------------------------------------------------------------------#


def _make_block(
    *,
    narrative_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    tree_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    behavior_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    assertion_realizations: tuple[AssertionRealizationMapping, ...] | None = None,
) -> ProjectionEnvelopeBlock:
    candidate, _, snapshot, _ = _project()
    selected = candidate.projection.selected_step_ids

    if narrative_realizations is None:
        narrative_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(i + 1),
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if tree_realizations is None:
        tree_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id=f"n1.{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if behavior_realizations is None:
        behavior_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.behavior,
                element_id=f"behavior-{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if assertion_realizations is None:
        # Map assertions to the terminal step's security-relevant postcondition.
        chain = candidate.projection.source_chain
        terminal_step = chain.steps[-1]
        assertion_realizations = (
            AssertionRealizationMapping(
                element_id=(
                    f"assert-{terminal_step.step_id}-"
                    f"{terminal_step.observable_postconditions[0].postcondition_id}"
                ),
                source_step_ids=(terminal_step.step_id,),
                projected_postcondition_ids=(
                    terminal_step.observable_postconditions[0].postcondition_id,
                ),
            ),
        )

    return ProjectionEnvelopeBlock(
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        projected_mappings=candidate.projected_mappings,
        capability_snapshot=snapshot,
        execution_requirements=candidate.execution_requirements,
        requirement_derivation_version=candidate.requirement_derivation_version,
        execution_requirements_digest=candidate.execution_requirements_digest,
        derivation_context_digest=compute_derivation_context_digest(
            candidate.projection.projection_digest,
            candidate.projection.source_chain.pattern_id,
            candidate.ingress_controllability,
        ),
        narrative_realizations=narrative_realizations,
        tree_realizations=tree_realizations,
        behavior_realizations=behavior_realizations,
        assertion_realizations=assertion_realizations,
    )


def _collect_all_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes from the tree (depth-first)."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_all_leaves(child))
    return leaves


def _replace_leaf(tree: AttackTree, new_leaf: AttackTreeNode) -> AttackTree:
    """Replace a leaf in the tree by matching leaf.id, returning a new tree."""

    def _replace_node(node: AttackTreeNode) -> AttackTreeNode:
        if node.gate == GateType.LEAF and node.id == new_leaf.id:
            return new_leaf
        if node.children:
            return node.model_copy(
                update={"children": [_replace_node(c) for c in node.children]}
            )
        return node

    return tree.model_copy(update={"root": _replace_node(tree.root)})


def _make_tree(ingress_id: str) -> AttackTree:
    """Build a minimal valid AND-only attack tree matching the projection."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Achieve attack objective",
        root=AttackTreeNode(
            id="n1",
            label="Attack goal",
            gate=GateType.AND,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Initial ingress",
                    gate=GateType.LEAF,
                    zone="input",
                    action=InitialIngressAction(entry_point_id=ingress_id),
                    projected_step_ids=("step.1",),
                    realizations=make_step_realizations(("step.1",)),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System action",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                    projected_step_ids=("step.2",),
                    realizations=make_step_realizations(("step.2",)),
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Impact",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=ImpactAction(boundary="internal", target="data integrity"),
                    projected_step_ids=("step.3",),
                    realizations=make_step_realizations(("step.3",)),
                ),
            ],
        ),
    )


def _make_narrative(ingress_id: str) -> NarrativeLayer:
    return NarrativeLayer(
        title="Test scenario",
        summary="Adversarial summary",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="gain access",
                effect="entry",
                projected_step_ids=("step.1",),
                realizations=make_step_realizations(("step.1",)),
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="exploit",
                effect="control",
                projected_step_ids=("step.2",),
                realizations=make_step_realizations(("step.2",)),
            ),
            NarrativeStep(
                step_number=3,
                zone="reasoning",
                action="impact",
                effect="damage",
                projected_step_ids=("step.3",),
                realizations=make_step_realizations(("step.3",)),
            ),
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ingress_id,
            responsible_step_number=1,
        ),
    )


def _make_envelope(
    block: ProjectionEnvelopeBlock | None = None,
    *,
    tree: AttackTree | None = None,
    narrative: NarrativeLayer | None = None,
    actor: ActorProfile | None = None,
    initial_entry_point_id: str | None = None,
    behavior_spec: Any = None,
) -> ScenarioEnvelope:
    if block is None:
        block = _make_block()
    ingress_id = block.canonical_ingress.entry_point_id
    if tree is None:
        tree = _make_tree(ingress_id)
    if narrative is None:
        narrative = _make_narrative(ingress_id)
    if actor is None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["target has chat interface"],
            desires=["steal data"],
            intentions=["prompt injection"],
            resources=["open-source tools"],
            access=ActorAccessProvenance(
                initial_entry_point_id=ingress_id,
                ingress_mode="direct",
                access_class="public",
            ),
        )
    if initial_entry_point_id is None:
        initial_entry_point_id = ingress_id

    from datetime import UTC

    # Use the actual projected candidate ID so candidate ID recompute passes.
    candidate, _, _, _ = _project()
    cid = candidate.candidate_id

    return ScenarioEnvelope(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id=cid,
        version=3,
        generated_at=datetime.now(UTC),
        generator_version="test",
        initial_entry_point_id=initial_entry_point_id,
        actor_profile=actor,
        projection=block,
        narrative=narrative,
        attack_tree=tree,
        behavior_spec=behavior_spec
        if behavior_spec is not None
        else make_behavior_spec("Feature: test"),
        faceting=_make_faceting(),
        priority=_make_priority(),
        generation=_make_generation(),
    )


def _make_faceting():
    from asago_scenario_generator.models.scenario import (
        ArchitectureMatch,
        CapabilityProfileRef,
        FacetingMetadata,
        RiskCardRef,
        TaxonomyChain,
    )

    return FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="r1",
            risk_name="Risk",
            risk_description="desc",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="chat",
        ),
        maestro_layers=[3],
    )


def _make_priority():
    from asago_scenario_generator.models.scenario import (
        ArchitectureMatch,
        AttackComplexity,
        LikelihoodLevel,
        Priority,
        PrioritySignals,
        SeverityLevel,
        StructuralExposureSignal,
        TechniqueMaturity,
    )

    return Priority(
        composite=0.5,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )


def _make_generation():
    from asago_scenario_generator.models.scenario import GenerationMetadata

    return GenerationMetadata(model="test", call_metadata=[])


# ---------------------------------------------------------------------------#
# Tests: valid baseline
# ---------------------------------------------------------------------------#


class TestValidBaseline:
    def test_valid_envelope_passes_traceability(self):
        """A well-formed envelope with complete realizations passes validation."""
        envelope = _make_envelope()
        result = validate_projection_traceability(envelope)
        assert result.valid, (
            f"Expected valid, got violations: "
            f"{[(v.code.value, v.stage.value, v.detail) for v in result.violations]}"
        )

    def test_none_projection_returns_invalid(self):
        """Envelope without projection returns invalid with typed violation."""
        envelope = _make_envelope()
        envelope.projection = None
        result = validate_projection_traceability(envelope)
        assert result.valid is False
        assert len(result.violations) == 1
        assert (
            result.violations[0].code
            == ProjectionTraceabilityViolationCode.nested_mutation
        )

    def test_block_is_frozen(self):
        """ProjectionEnvelopeBlock is deeply immutable."""
        block = _make_block()
        with pytest.raises((ValidationError, TypeError)):
            block.projection = None  # type: ignore[misc]

    def test_block_extra_forbid(self):
        """ProjectionEnvelopeBlock rejects extra fields."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                derivation_context_digest=compute_derivation_context_digest(
                    candidate.projection.projection_digest,
                    candidate.projection.source_chain.pattern_id,
                    candidate.ingress_controllability,
                ),
                extra_field="bad",
            )


# ---------------------------------------------------------------------------#
# Tests: deep nested mutation (contract §2)
# ---------------------------------------------------------------------------#


class TestNestedMutation:
    def test_nested_mutation_detected(self):
        """Mutating execution requirements digest after construction is rejected."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with the execution requirements digest.
        block_dict["execution_requirements_digest"] = "f" * 64
        with pytest.raises(ValidationError, match="execution_requirements_digest"):
            ProjectionEnvelopeBlock.model_validate(block_dict)

    def test_projection_digest_mutation_detected(self):
        """Mutating the projection_digest field is rejected at model level."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with the projection digest.
        block_dict["projection"]["projection_digest"] = "e" * 64
        with pytest.raises(ValidationError, match="projection_digest"):
            ProjectionEnvelopeBlock.model_validate(block_dict)

    def test_nested_requirement_content_mutation_detected(self):
        """Changing execution requirement content is rejected by digest check."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with a requirement field — the digest check should catch it.
        if block_dict["execution_requirements"]:
            req = block_dict["execution_requirements"][0]
            if "entry_point_slot_id" in req:
                req["entry_point_slot_id"] = "tampered.slot"
        # The execution_requirements_digest check catches the content change.
        with pytest.raises((ValidationError, ValueError)):
            ProjectionEnvelopeBlock.model_validate(block_dict)


# ---------------------------------------------------------------------------#
# Tests: omitted projected steps (contract §4)
# ---------------------------------------------------------------------------#


class TestOmittedSteps:
    def test_omitted_narrative_step(self):
        """Missing a projected step in narrative realizations is flagged."""
        block = _make_block()
        # Remove the last narrative realization.
        truncated = block.narrative_realizations[:-1]
        block = block.model_copy(
            update={"narrative_realizations": truncated},
        )
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes
        # Verify it's attributed to narrative stage.
        stage = next(
            v.stage
            for v in result.violations
            if v.code == ProjectionTraceabilityViolationCode.incomplete_coverage
        )
        assert stage == ProjectionTraceabilityStage.narrative

    def test_omitted_tree_step(self):
        """Missing a projected step in tree realizations is flagged."""
        block = _make_block()
        truncated = block.tree_realizations[:-1]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes

    def test_omitted_behavior_step(self):
        """Missing a projected step in behavior realizations is flagged."""
        block = _make_block()
        truncated = block.behavior_realizations[:-1]
        block = block.model_copy(update={"behavior_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes


# ---------------------------------------------------------------------------#
# Tests: reordered projected steps (contract §5)
# ---------------------------------------------------------------------------#


class TestReorderedSteps:
    def test_reordered_narrative_steps(self):
        """Reordering narrative realizations violates total order."""
        block = _make_block()
        selected = block.selected_step_ids
        # Reverse the narrative realizations — element "1" maps to step.3,
        # element "3" maps to step.1.  The actual narrative steps still have
        # correct projected_step_id, so the block mapping is forged.
        reversed_maps = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(i + 1),
                projected_step_ids=(selected[-1 - i],),
            )
            for i in range(len(selected))
        )
        block = block.model_copy(update={"narrative_realizations": reversed_maps})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        # Reversed sidecar mappings produce forged_opaque_id (block mapping
        # doesn't match actual step projected_step_id) or reordered_projected_step.
        assert codes, "Expected violations for reversed mappings, got none"
        assert codes & {
            ProjectionTraceabilityViolationCode.reordered_projected_step,
            ProjectionTraceabilityViolationCode.forged_opaque_id,
        }, f"Expected reorder/forged violation, got {codes}"

    def test_narrative_physically_reordered_fails(self):
        """Narrative steps physically ordered [2,1,3] fail even if sidecar is ordered."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        # Create a narrative with physical order [2,1,3] — step at position 0
        # has projected_step_id for step.2, position 1 for step.1.
        narrative = NarrativeLayer(
            title="Reordered",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="exploit",
                    effect="control",
                    projected_step_ids=(selected[1],),
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.reordered_projected_step in codes


# ---------------------------------------------------------------------------#
# Tests: duplicated projected steps (contract §5)
# ---------------------------------------------------------------------------#


class TestDuplicatedSteps:
    def test_duplicate_element_id_in_narrative(self):
        """Same element_id appearing twice is flagged as duplicate."""
        block = _make_block()
        selected = block.selected_step_ids
        dup = block.narrative_realizations + (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",  # duplicate of first
                projected_step_ids=(selected[1],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": dup})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.duplicated_projected_step in codes


# ---------------------------------------------------------------------------#
# Tests: unprojected security actions (contract §4)
# ---------------------------------------------------------------------------#


class TestUnprojectedSecurityAction:
    def test_unmapped_security_leaf(self):
        """A security-bearing tree leaf not in realizations is flagged."""
        block = _make_block()
        # Remove the first tree realization (which maps the initial_ingress leaf).
        truncated = block.tree_realizations[1:]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.unprojected_security_action in codes


# ---------------------------------------------------------------------------#
# Tests: incomplete many-to-many coverage (contract §5)
# ---------------------------------------------------------------------------#


class TestManyToManyCoverage:
    def test_combine_multiple_steps_in_one_element(self):
        """Combining multiple projected steps in one element is valid."""
        block = _make_block()
        selected = block.selected_step_ids
        # Combine step.1 and step.2 into one narrative element.
        combined = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0], selected[1]),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": combined})
        # Also update the narrative to match: 2 steps, step 1 covers
        # step.1 (first of combined pair), step 2 covers step.3.
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = NarrativeLayer(
            title="Combined",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access and exploit",
                    effect="entry and control",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        # Should be valid — combine preserves order.
        narrative_codes = {
            v.code
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
        }
        assert (
            ProjectionTraceabilityViolationCode.incomplete_coverage
            not in narrative_codes
        ), f"Unexpected incomplete_coverage: {narrative_codes}"
        assert (
            ProjectionTraceabilityViolationCode.reordered_projected_step
            not in narrative_codes
        ), f"Unexpected reorder: {narrative_codes}"

    def test_split_one_step_across_elements(self):
        """Splitting one projected step across multiple elements is valid."""
        block = _make_block()
        selected = block.selected_step_ids
        # Split step.2 across two narrative elements (shared step).
        split = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[1],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="3",
                projected_step_ids=(selected[1],),  # split: shared step
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="4",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": split})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        # Split should not trigger reorder (shared step).
        reorder_codes = {
            v.code
            for v in result.violations
            if v.code == ProjectionTraceabilityViolationCode.reordered_projected_step
        }
        assert not reorder_codes


# ---------------------------------------------------------------------------#
# Tests: incorrect resource binding (contract §4)
# ---------------------------------------------------------------------------#


class TestResourceBinding:
    def test_wrong_tool_id_in_tree(self):
        """A tree leaf with a tool_id not in projection bindings is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        from asago_scenario_generator.models.attack_tree import ToolInvocationAction

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="wrong tool",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        action=ToolInvocationAction(
                            tool_id="tool:v1:" + "f" * 32,
                        ),
                        projected_step_ids=(selected[1],),
                        realizations=make_realizations((selected[1],)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incorrect_resource_binding in codes


# ---------------------------------------------------------------------------#
# Tests: incorrect ingress binding (contract §7)
# ---------------------------------------------------------------------------#


class TestIngressBinding:
    def test_envelope_ingress_mismatch(self):
        """Envelope initial_entry_point_id mismatching projection is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        envelope = _make_envelope(block, initial_entry_point_id=wrong_id)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_actor_ingress_mismatch(self):
        """Actor access initial_entry_point_id mismatch is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["x"],
            desires=["y"],
            intentions=["z"],
            resources=["tools"],
            access=ActorAccessProvenance(
                initial_entry_point_id=wrong_id,
                ingress_mode="direct",
                access_class="public",
            ),
        )
        envelope = _make_envelope(block, actor=actor)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_narrative_ingress_mismatch(self):
        """Narrative access_realization initial_entry_point_id mismatch is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        narrative = _make_narrative(block.canonical_ingress.entry_point_id)
        narrative = narrative.model_copy(
            update={
                "access_realization": NarrativeAccessRealization(
                    initial_entry_point_id=wrong_id,
                    responsible_step_number=1,
                )
            }
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_tree_ingress_mismatch(self):
        """Tree leaf with wrong initial_ingress entry_point_id is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        tree = _make_tree(wrong_id)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes


# ---------------------------------------------------------------------------#
# Tests: forged opaque IDs (contract §3, §9)
# ---------------------------------------------------------------------------#


class TestForgedOpaqueIds:
    def test_forged_step_id_in_narrative(self):
        """A realization mapping claiming an unprojected step is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        forged = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[1],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="3",
                projected_step_ids=(selected[2],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="4",
                projected_step_ids=("fake.step.id",),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": forged})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes

    def test_forged_tree_leaf_id(self):
        """A tree realization referencing a nonexistent leaf is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        forged_tree = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.nonexistent",
                projected_step_ids=(selected[0],),
            ),
        )
        block = block.model_copy(update={"tree_realizations": forged_tree})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes


# ---------------------------------------------------------------------------#
# Tests: postcondition/assertion mismatch (contract §4)
# ---------------------------------------------------------------------------#


class TestPostconditionMismatch:
    def test_assertion_references_nonexistent_postcondition(self):
        """An assertion referencing a nonexistent postcondition is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        bad_assertions = (
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=(selected[-1],),
                projected_postcondition_ids=("fake.postcondition",),
            ),
        )
        block = block.model_copy(update={"assertion_realizations": bad_assertions})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch
            in codes
        )

    def test_assertion_claims_postcondition_from_wrong_step(self):
        """An assertion claiming a postcondition without listing its step."""
        block = _make_block()
        selected = block.selected_step_ids
        chain = block.projection.source_chain
        # Get a postcondition from step.1 but only list step.3 in source.
        step1 = chain.steps[0]
        bad_assertions = (
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=(selected[-1],),  # step.3
                projected_postcondition_ids=(
                    step1.observable_postconditions[0].postcondition_id,
                ),
            ),
        )
        block = block.model_copy(update={"assertion_realizations": bad_assertions})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch
            in codes
        )

    def test_missing_security_postcondition_assertion(self):
        """Security-relevant postconditions must be covered by assertions."""
        block = _make_block()
        # Empty assertions — terminal step has a security-relevant postcondition.
        block = block.model_copy(update={"assertion_realizations": ()})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes


# ---------------------------------------------------------------------------#
# Tests: OR tree prohibited (contract §6)
# ---------------------------------------------------------------------------#


class TestOrTreeProhibited:
    def test_or_node_in_tree(self):
        """An OR node in the attack tree is flagged."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="alternatives",
                        gate=GateType.OR,
                        children=[
                            AttackTreeNode(
                                id="n1.2.1",
                                label="option A",
                                gate=GateType.LEAF,
                                zone="reasoning",
                                action=AiSystemAction(),
                            ),
                            AttackTreeNode(
                                id="n1.2.2",
                                label="option B",
                                gate=GateType.LEAF,
                                zone="reasoning",
                                action=AiSystemAction(),
                            ),
                        ],
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                    ),
                ],
            ),
        )
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.or_tree_prohibited in codes


# ---------------------------------------------------------------------------#
# Tests: verify-only recomputation drift (contract §2)
# ---------------------------------------------------------------------------#


class TestRecomputationDrift:
    def test_drift_detected_when_source_chain_differs(self):
        """When authoritative pattern is supplied, chain mismatch is flagged."""
        envelope = _make_envelope()
        # Supply a different pattern (different name → different pattern_pin).
        raw = _pattern()
        raw["name"] = "Different Pattern"
        raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
            raw["canonical_chain"]
        )
        pattern = AttackPattern.model_validate(raw)
        resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
        result = validate_projection_traceability(
            envelope,
            authoritative_pattern=raw,
            taxonomy_resolver=resolver,
            capability_snapshot=snapshot,
            expected_catalog_pin="0" * 64,
        )
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.authoritative_pattern_pin_mismatch
            in codes
        )

    def test_no_drift_when_authoritative_inputs_match(self):
        """When authoritative inputs match, no drift violations."""
        _candidate, resolver, snapshot, raw = _project()
        envelope = _make_envelope()
        # Compute the expected catalog pin the same way projection does.
        from asago_scenario_generator.pipeline.projection import (
            _content_pin,
            _pattern_pin,
        )

        pattern = AttackPattern.model_validate(raw)
        pp = _pattern_pin(pattern)
        catalog_pin = _content_pin(
            "asago-scenario-generator:authoritative-catalog:v1", [pp]
        )
        result = validate_projection_traceability(
            envelope,
            authoritative_pattern=raw,
            taxonomy_resolver=resolver,
            capability_snapshot=snapshot,
            expected_catalog_pin=catalog_pin,
        )
        drift_codes = {
            v.code
            for v in result.violations
            if v.code
            in (
                ProjectionTraceabilityViolationCode.projection_drift,
                ProjectionTraceabilityViolationCode.requirement_drift,
            )
        }
        assert not drift_codes, (
            f"Expected no drift violations, got: "
            f"{[(v.code.value, v.detail) for v in result.violations if v.code in drift_codes]}"
        )


# ---------------------------------------------------------------------------#
# Tests: typed violation attribution (contract §8)
# ---------------------------------------------------------------------------#


class TestViolationAttribution:
    def test_narrative_violation_attributed_to_narrative_stage(self):
        """Narrative-stage violations are attributed to the narrative stage."""
        block = _make_block()
        truncated = block.narrative_realizations[:-1]
        block = block.model_copy(update={"narrative_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        narrative_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
        ]
        assert len(narrative_violations) > 0

    def test_tree_violation_attributed_to_tree_stage(self):
        """Tree-stage violations are attributed to the attack_tree stage."""
        block = _make_block()
        truncated = block.tree_realizations[:-1]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        tree_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.attack_tree
        ]
        assert len(tree_violations) > 0

    def test_behavior_violation_attributed_to_behavior_stage(self):
        """Behavior-stage violations are attributed to the behavior_spec stage."""
        block = _make_block()
        truncated = block.behavior_realizations[:-1]
        block = block.model_copy(update={"behavior_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        behavior_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.behavior_spec
        ]
        assert len(behavior_violations) > 0


# ---------------------------------------------------------------------------#
# Tests: realization mapping model validation
# ---------------------------------------------------------------------------#


class TestRealizationModelValidation:
    def test_artifact_mapping_requires_unique_steps(self):
        """ArtifactRealizationMapping rejects duplicate projected_step_ids."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=("step.1", "step.1"),
            )

    def test_assertion_mapping_requires_unique_postconditions(self):
        """AssertionRealizationMapping rejects duplicate postcondition IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1",),
                projected_postcondition_ids=("post.1", "post.1"),
            )

    def test_assertion_mapping_requires_unique_source_steps(self):
        """AssertionRealizationMapping rejects duplicate source step IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1", "step.1"),
                projected_postcondition_ids=("post.1",),
            )

    def test_block_ingress_must_match_projection(self):
        """Block canonical_ingress must match the projection's ingress binding."""
        candidate, _, _, _ = _project()
        wrong_ingress = EntryPointResourceReference(
            kind="entry_point",
            entry_point_id="ep:v1:" + "9" * 32,
        )
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=wrong_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                derivation_context_digest=compute_derivation_context_digest(
                    candidate.projection.projection_digest,
                    candidate.projection.source_chain.pattern_id,
                    candidate.ingress_controllability,
                ),
            )


# ---------------------------------------------------------------------------#
# Schema / model parity and persistence round-trip (contract §1, §2)
# ---------------------------------------------------------------------------#


class TestProjectionEnvelopeBlockSchemaParity:
    """Schema/model parity for ProjectionEnvelopeBlock and related models."""

    def test_block_model_json_schema_is_valid(self):
        """ProjectionEnvelopeBlock generates valid JSON Schema."""
        import jsonschema

        schema = ProjectionEnvelopeBlock.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_block_has_schema_version_const(self):
        """schema_version is a Literal['3'] const."""
        schema = ProjectionEnvelopeBlock.model_json_schema()
        sv = schema["properties"]["schema_version"]
        assert sv.get("const") == "3"

    def test_block_extra_forbid_in_json_schema(self):
        """additionalProperties is False."""
        schema = ProjectionEnvelopeBlock.model_json_schema()
        assert schema.get("additionalProperties") is False

    def test_envelope_schema_includes_projection_defs(self):
        """ScenarioEnvelope JSON schema includes projection-related $defs."""
        from asago_scenario_generator.models.scenario import ScenarioEnvelope

        schema = ScenarioEnvelope.model_json_schema()
        defs = schema.get("$defs", {})
        for name in [
            "ProjectionEnvelopeBlock",
            "ArtifactRealizationMapping",
            "AssertionRealizationMapping",
        ]:
            assert name in defs, f"Missing $def: {name}"

    def test_envelope_schema_includes_projection_properties(self):
        """ScenarioEnvelope JSON schema includes projection properties."""
        from asago_scenario_generator.models.scenario import ScenarioEnvelope

        schema = ScenarioEnvelope.model_json_schema()
        props = schema.get("properties", {})
        assert "projection" in props
        # projection_traceability is transient (422o.4), not persisted.
        assert "projection_traceability" not in props

    def test_hand_schema_includes_projection_properties(self):
        """Hand-maintained JSON schema includes projection properties."""
        import json
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        hand = json.loads(path.read_text(encoding="utf-8"))
        props = hand.get("properties", {})
        assert "projection" in props
        # projection_traceability is transient (422o.4), not persisted.
        assert "projection_traceability" not in props
        defs = hand.get("$defs", {})
        for name in [
            "ProjectionEnvelopeBlock",
            "ArtifactRealizationMapping",
            "AssertionRealizationMapping",
        ]:
            assert name in defs, f"Missing hand schema $def: {name}"

    def test_violation_code_enum_complete(self):
        """ProjectionTraceabilityViolationCode has all expected codes."""
        expected_codes = {
            "omitted_projected_step",
            "reordered_projected_step",
            "duplicated_projected_step",
            "unprojected_security_action",
            "incomplete_coverage",
            "incorrect_resource_binding",
            "incorrect_ingress_binding",
            "forged_opaque_id",
            "postcondition_assertion_mismatch",
            "or_tree_prohibited",
            "projection_drift",
            "nested_mutation",
            "ingress_identity_mismatch",
            "requirement_drift",
            "invalid_technique_mapping",
            "authoritative_pattern_pin_mismatch",
            "authoritative_catalog_pin_mismatch",
        }
        actual = {c.value for c in ProjectionTraceabilityViolationCode}
        assert actual == expected_codes

    def test_stage_enum_complete(self):
        """ProjectionTraceabilityStage has all expected stages."""
        expected = {"actor_profile", "narrative", "attack_tree", "behavior_spec"}
        actual = {s.value for s in ProjectionTraceabilityStage}
        assert actual == expected


class TestProjectionEnvelopeBlockPersistence:
    """Persistence round-trip and deep mutation tests."""

    def test_round_trip_json(self):
        """Block survives JSON round-trip without drift."""
        block = _make_block()
        data = block.model_dump(mode="json")
        restored = ProjectionEnvelopeBlock.model_validate(data)
        assert restored == block

    def test_round_trip_with_realizations(self):
        """Block with realizations survives JSON round-trip."""
        block = _make_block()
        block = block.model_copy(
            update={
                "narrative_realizations": (
                    ArtifactRealizationMapping(
                        artifact_stage=ArtifactStage.narrative,
                        element_id="1",
                        projected_step_ids=("step.1",),
                    ),
                ),
            }
        )
        data = block.model_dump(mode="json")
        restored = ProjectionEnvelopeBlock.model_validate(data)
        assert restored == block
        assert restored.narrative_realizations == block.narrative_realizations

    def test_round_trip_envelope_with_projection(self):
        """Full envelope with projection survives JSON round-trip."""
        envelope = _make_envelope()
        assert envelope.projection is not None
        data = envelope.model_dump(mode="json")
        restored = ScenarioEnvelope.model_validate(data)
        assert restored.projection == envelope.projection

    def test_nested_mutation_detected_after_round_trip(self):
        """Mutating the JSON data before re-validation is detected."""
        block = _make_block()
        data = block.model_dump(mode="json")
        # Tamper with a step ID in the projection snapshot.
        data["projection"]["selected_step_ids"][0] = "forged.step"
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock.model_validate(data)

    def test_execution_requirements_tamper_detected(self):
        """Tampering with execution requirements is detected by digest."""
        block = _make_block()
        data = block.model_dump(mode="json")
        # Tamper with a requirement field.
        if data["execution_requirements"]:
            data["execution_requirements"][0]["requirement_id"] = "forged.req"
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock.model_validate(data)


class TestAdversarialSchemaValidation:
    """Adversarial tests for the modified public validation surfaces."""

    def test_block_rejects_extra_fields(self):
        """ProjectionEnvelopeBlock rejects unknown fields."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                derivation_context_digest=compute_derivation_context_digest(
                    candidate.projection.projection_digest,
                    candidate.projection.source_chain.pattern_id,
                    candidate.ingress_controllability,
                ),
                unknown_field="evil",
            )

    def test_block_rejects_missing_projection(self):
        """ProjectionEnvelopeBlock rejects missing projection field."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )

    def test_block_rejects_missing_canonical_ingress(self):
        """ProjectionEnvelopeBlock rejects missing canonical_ingress."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )

    def test_block_rejects_wrong_ingress_controllability(self):
        """ProjectionEnvelopeBlock rejects invalid ingress_controllability."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability="sideways",
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                derivation_context_digest=compute_derivation_context_digest(
                    candidate.projection.projection_digest,
                    candidate.projection.source_chain.pattern_id,
                    candidate.ingress_controllability,
                ),
            )

    def test_artifact_mapping_rejects_empty_step_ids(self):
        """ArtifactRealizationMapping rejects empty projected_step_ids."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(),
            )

    def test_artifact_mapping_rejects_empty_element_id(self):
        """ArtifactRealizationMapping rejects empty element_id."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="",
                projected_step_ids=("step.1",),
            )

    def test_assertion_mapping_rejects_empty_postcondition_ids(self):
        """AssertionRealizationMapping rejects empty postcondition IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1",),
                projected_postcondition_ids=(),
            )

    def test_traceability_result_rejects_extra_fields(self):
        """ProjectionTraceabilityResult rejects extra fields."""
        from asago_scenario_generator.models.projection_envelope import (
            ProjectionTraceabilityResult,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityResult(
                valid=True,
                violations=[],
                evil_field="bad",
            )

    def test_traceability_violation_rejects_extra_fields(self):
        """ProjectionTraceabilityViolation rejects extra fields."""
        from asago_scenario_generator.models.projection_envelope import (
            ProjectionTraceabilityViolation,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail="test",
                evil="bad",
            )

    def test_traceability_violation_requires_detail(self):
        """ProjectionTraceabilityViolation requires non-empty detail."""
        from asago_scenario_generator.models.projection_envelope import (
            ProjectionTraceabilityViolation,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail="",
            )

    def test_envelope_with_projection_validates_against_hand_schema(self):
        """An envelope with projection validates against the hand JSON schema."""
        import json
        from pathlib import Path

        import jsonschema

        envelope = _make_envelope()
        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        hand = json.loads(path.read_text(encoding="utf-8"))
        envelope_dict = envelope.model_dump(mode="json")
        jsonschema.validate(envelope_dict, hand)


class TestValidatorNoProjection:
    """Validator behavior when projection is absent."""

    def test_no_projection_returns_invalid(self):
        """Envelope without projection returns invalid result with typed violation."""
        envelope = _make_envelope()
        envelope = envelope.model_copy(update={"projection": None})
        result = validate_projection_traceability(envelope)
        assert result.valid is False
        assert len(result.violations) == 1
        assert (
            result.violations[0].code
            == ProjectionTraceabilityViolationCode.nested_mutation
        )

    def test_projection_traceability_not_persisted(self):
        """projection_traceability is not a field on ScenarioEnvelope (transient, 422o.4)."""
        envelope = _make_envelope()
        assert not hasattr(envelope, "projection_traceability")


class TestComputeExecutionRequirementsDigest:
    """Tests for the public compute_execution_requirements_digest function."""

    def test_digest_matches_candidate(self):
        """Digest matches the one computed during projection."""
        from asago_scenario_generator.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        digest = compute_execution_requirements_digest(candidate.execution_requirements)
        assert digest == candidate.execution_requirements_digest

    def test_digest_differs_for_different_requirements(self):
        """Different requirements produce different digests."""
        from asago_scenario_generator.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        original = compute_execution_requirements_digest(
            candidate.execution_requirements
        )
        # Tamper with requirements by passing a dict with wrong ID
        reqs_data = [
            r.model_dump(mode="json") for r in candidate.execution_requirements
        ]
        if reqs_data:
            reqs_data[0]["requirement_id"] = "forged.req"
        tampered = compute_execution_requirements_digest(reqs_data)
        assert tampered != original

    def test_digest_accepts_dicts(self):
        """Digest computation accepts pre-serialized dicts."""
        from asago_scenario_generator.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        reqs_data = [
            r.model_dump(mode="json") for r in candidate.execution_requirements
        ]
        digest = compute_execution_requirements_digest(reqs_data)
        assert digest == candidate.execution_requirements_digest


# ---------------------------------------------------------------------------#
# Adversarial regressions required by independent review (422o.4 blockers #2-#4)
# ---------------------------------------------------------------------------#


class TestStandaloneForgedRequirements:
    """Forged requirements with recomputed digest must be rejected standalone."""

    def test_forged_requirements_with_matching_digest_rejected(self):
        """Arbitrary requirements + recomputed digest must fail standalone recomputation."""
        # Create forged requirements that are different from the real ones
        # but compute a matching digest for them.
        from asago_scenario_generator.models.attack_pattern import (
            DirectInputControlRequirement,
        )
        from asago_scenario_generator.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        forged_reqs = (
            DirectInputControlRequirement(
                schema_version="1",
                requirement_id="req.forged.abc",
                kind="direct_input_control",
                entry_point_slot_id="ingress",
            ),
        )
        forged_digest = compute_execution_requirements_digest(forged_reqs)
        block = _make_block()
        # model_copy bypasses validators on frozen models, so we can inject
        # forged requirements with a matching digest
        block = block.model_copy(
            update={
                "execution_requirements": forged_reqs,
                "execution_requirements_digest": forged_digest,
            }
        )
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.requirement_drift in codes, (
            f"Forged requirements should be rejected by standalone recomputation, "
            f"got {codes}"
        )

    def test_forged_projected_mappings_rejected(self):
        """Projected mappings that don't match embedded chain must be rejected."""
        from asago_scenario_generator.models.attack_pattern import ExactMapping
        from asago_scenario_generator.pipeline.projection import ProjectedMapping

        block = _make_block()
        # Create a forged mapping with a wrong ID
        forged_mappings = block.projected_mappings + (
            ProjectedMapping(
                scope="chain",
                mapping=ExactMapping(
                    decision="exact", taxonomy="ATLAS", ids=["FAKE.T9999"]
                ),
            ),
        )
        block = block.model_copy(update={"projected_mappings": forged_mappings})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.projection_drift in codes, (
            f"Forged projected mappings should be rejected, got {codes}"
        )

    def test_flipped_controllability_rejected(self):
        """Flipping ingress_controllability and re-signing must fail.

        The model validator catches this at construction, but model_copy
        bypasses validators.  The standalone validator must also catch it
        by deriving controllability from the embedded capability evidence.
        """
        from asago_scenario_generator.pipeline.projection import (
            compute_derivation_context_digest,
        )

        block = _make_block()
        # Flip controllability from direct to indirect
        flipped = "indirect" if block.ingress_controllability == "direct" else "direct"
        new_ctx_digest = compute_derivation_context_digest(
            block.projection.projection_digest,
            block.projection.source_chain.pattern_id,
            flipped,
        )
        block = block.model_copy(
            update={
                "ingress_controllability": flipped,
                "derivation_context_digest": new_ctx_digest,
            }
        )
        # Use model_copy on the envelope to bypass model re-validation.
        envelope = _make_envelope()
        envelope = envelope.model_copy(update={"projection": block})
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        # Flipping controllability should cause requirement_drift because
        # the recomputed requirements will differ (indirect fails closed)
        assert ProjectionTraceabilityViolationCode.requirement_drift in codes, (
            f"Flipped controllability should be rejected, got {codes}"
        )


class TestExtraUnmappedNarrativeAction:
    """Extra generated narrative actions not in mappings must fail."""

    def test_extra_unmapped_narrative_action_fails(self):
        """An extra narrative step with projected_step_id not in block realizations fails."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        # Add a 4th narrative step with a projected_step_id
        narrative = NarrativeLayer(
            title="Extra step",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="exploit",
                    effect="control",
                    projected_step_ids=(selected[1],),
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=4,
                    zone="reasoning",
                    action="extra action",
                    effect="extra effect",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes, (
            f"Extra unmapped narrative action should fail, got {codes}"
        )


class TestPhysicallyReorderedTree:
    """Physically reordered tree must fail even with ordered sidecar."""

    def test_physically_reordered_tree_fails(self):
        """Tree leaves physically reordered must fail even if sidecar is ordered."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        # Create a tree with leaves in reversed order: step.3, step.2, step.1
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="impact first",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_realizations((selected[2],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="system action",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=(selected[1],),
                        realizations=make_realizations((selected[1],)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="ingress last",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_realizations((selected[0],)),
                    ),
                ],
            ),
        )
        # Block realizations are in correct order matching leaf IDs
        # But the physical tree order is reversed
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.reordered_projected_step in codes, (
            f"Physically reordered tree should fail, got {codes}"
        )


class TestNonexistentBehaviorIDs:
    """Nonexistent behavior/assertion IDs must fail against actual artifact."""

    def test_nonexistent_behavior_action_id_fails(self):
        """Block behavior realization with nonexistent action ID fails."""
        from asago_scenario_generator.models.scenario import (
            BehaviorSpec,
        )

        block = _make_block()
        selected = block.selected_step_ids
        # Create a BehaviorSpec with action IDs ba-1, ba-2, ba-3
        behavior_spec = BehaviorSpec(
            actions=(
                BehaviorAction(
                    action_id="ba-1",
                    projected_step_ids=(selected[0],),
                    source_leaf_id="n1.1",
                    gherkin_keyword="Given",
                    text="Given the attacker has access",
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                BehaviorAction(
                    action_id="ba-2",
                    projected_step_ids=(selected[1],),
                    source_leaf_id="n1.2",
                    gherkin_keyword="When",
                    text="When the system processes input",
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                BehaviorAction(
                    action_id="ba-3",
                    projected_step_ids=(selected[2],),
                    source_leaf_id="n1.3",
                    gherkin_keyword="Then",
                    text="Then the impact occurs",
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ),
            assertions=(
                BehaviorAssertion(
                    assertion_id="assert-1",
                    source_step_ids=(selected[2],),
                    projected_postcondition_ids=("post.3",),
                    text="Then the security outcome is observed",
                ),
            ),
            gherkin_text="Feature: Test\n  Scenario: Test\n",
        )
        # Create block with a nonexistent behavior action ID
        from asago_scenario_generator.models.projection_envelope import (
            ArtifactRealizationMapping,
            ArtifactStage,
        )

        block = block.model_copy(
            update={
                "behavior_realizations": (
                    ArtifactRealizationMapping(
                        artifact_stage=ArtifactStage.behavior,
                        element_id="behavior-fake",
                        projected_step_ids=(selected[0],),
                    ),
                ),
            }
        )
        envelope = _make_envelope(block)
        envelope = envelope.model_copy(update={"behavior_spec": behavior_spec})
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes, (
            f"Nonexistent behavior action ID should fail, got {codes}"
        )

    def test_nonexistent_assertion_id_fails(self):
        """Block assertion realization with nonexistent assertion ID fails."""
        from asago_scenario_generator.models.scenario import (
            BehaviorSpec,
        )

        block = _make_block()
        selected = block.selected_step_ids
        behavior_spec = BehaviorSpec(
            actions=(
                BehaviorAction(
                    action_id="ba-1",
                    projected_step_ids=(selected[0],),
                    source_leaf_id="n1.1",
                    gherkin_keyword="Given",
                    text="Given the attacker has access",
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                BehaviorAction(
                    action_id="ba-2",
                    projected_step_ids=(selected[1],),
                    source_leaf_id="n1.2",
                    gherkin_keyword="When",
                    text="When the system processes input",
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                BehaviorAction(
                    action_id="ba-3",
                    projected_step_ids=(selected[2],),
                    source_leaf_id="n1.3",
                    gherkin_keyword="Then",
                    text="Then the impact occurs",
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ),
            assertions=(
                BehaviorAssertion(
                    assertion_id="assert-1",
                    source_step_ids=(selected[2],),
                    projected_postcondition_ids=("post.3",),
                    text="Then the security outcome is observed",
                ),
            ),
            gherkin_text="Feature: Test\n  Scenario: Test\n",
        )
        # Create block with a nonexistent assertion ID
        from asago_scenario_generator.models.projection_envelope import (
            AssertionRealizationMapping,
        )

        block = block.model_copy(
            update={
                "assertion_realizations": (
                    AssertionRealizationMapping(
                        element_id="assert-fake",
                        source_step_ids=(selected[2],),
                        projected_postcondition_ids=("post.3",),
                    ),
                ),
            }
        )
        envelope = _make_envelope(block)
        envelope = envelope.model_copy(update={"behavior_spec": behavior_spec})
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes, (
            f"Nonexistent assertion ID should fail, got {codes}"
        )


class TestWrongStepResourceBinding:
    """Leaf mapped to step A but using step B's valid bound tool must fail."""

    def test_wrong_step_tool_binding_fails(self):
        """A leaf mapped to step A using step B's valid tool binding must fail.

        step.2 has a tool_fixture resource link to the 'tool' slot.
        step.3 has no tool link.  A leaf mapped to step.3 but using
        the tool from step.2's binding must fail with
        incorrect_resource_binding.
        """
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        chain = block.projection.source_chain

        # step.2 has the tool_fixture link; step.3 does not.
        step_with_tool = next(s for s in chain.steps if s.step_id == "step.2")
        step_without_tool = next(s for s in chain.steps if s.step_id == "step.3")
        assert any(
            link.role == "tool_fixture" for link in step_with_tool.resource_links
        ), "step.2 must have a tool_fixture link"
        assert not any(
            link.role == "tool_fixture" for link in step_without_tool.resource_links
        ), "step.3 must not have a tool_fixture link"

        # Find the tool binding for the step with the tool link
        tool_link = next(
            link
            for link in step_with_tool.resource_links
            if link.role == "tool_fixture"
        )
        bindings_by_slot = {
            b.slot_id: b.resource_ref for b in block.projection.bindings
        }
        tool_ref = bindings_by_slot.get(tool_link.slot_id)
        from asago_scenario_generator.models.attack_pattern import ToolResourceReference

        assert isinstance(tool_ref, ToolResourceReference), (
            "Tool binding must be a ToolResourceReference"
        )

        from asago_scenario_generator.models.attack_tree import ToolInvocationAction

        # Create a tree where leaf n1.2 is mapped to step_without_tool (step.3)
        # but uses the tool from step_with_tool (step.2)
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="wrong step tool",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        action=ToolInvocationAction(tool_id=tool_ref.tool_id),
                        projected_step_ids=(step_without_tool.step_id,),
                        realizations=make_realizations((step_without_tool.step_id,)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        # Update tree realizations to match the actual tree
        tree_realizations = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.2",
                projected_step_ids=(step_without_tool.step_id,),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.3",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"tree_realizations": tree_realizations})
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.incorrect_resource_binding in codes
        ), f"Tool bound for another step should fail, got {codes}"


class TestYamlFeatureRoundTrip:
    """Persisted YAML + feature round trip independently revalidates."""

    def test_yaml_round_trip_preserves_projection(self):
        """YAML serialization and deserialization preserves the projection block."""
        import yaml

        envelope = _make_envelope()
        data = envelope.model_dump(mode="json", exclude_none=True)
        yaml_text = yaml.dump(data, default_flow_style=False, sort_keys=False)
        loaded = yaml.safe_load(yaml_text)
        restored = ScenarioEnvelope.model_validate(loaded)
        assert restored.projection is not None
        assert (
            restored.projection.projection.projection_digest
            == envelope.projection.projection.projection_digest
        )
        assert (
            restored.projection.derivation_context_digest
            == envelope.projection.derivation_context_digest
        )
        # Revalidate after round trip
        result = validate_projection_traceability(restored)
        assert result.valid, (
            f"Round-trip envelope should be valid, got violations: "
            f"{[(v.code.value, v.detail) for v in result.violations]}"
        )


class TestInvalidTechniqueMapping:
    """Tree leaf with invalid technique_id must produce typed violation."""

    def test_invalid_technique_mapping_fails(self):
        """A tree leaf with a technique_id not in projection mappings must fail."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_realizations((selected[0],)),
                        technique_id="AML.T0001",
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="exploit with invalid technique",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        action=AiSystemAction(),
                        projected_step_ids=(selected[1],),
                        realizations=make_realizations((selected[1],)),
                        technique_id="AML.T9999",
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        tree_realizations = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.2",
                projected_step_ids=(selected[1],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.3",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"tree_realizations": tree_realizations})
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.invalid_technique_mapping in codes, (
            f"Invalid technique mapping should fail, got {codes}"
        )


class TestProductionProjectionPersistence:
    """Production-written YAML always contains projection; exclude_none does not omit it."""

    def test_exclude_none_preserves_projection(self):
        """model_dump(exclude_none=True) must not omit the mandatory projection."""
        envelope = _make_envelope()
        data = envelope.model_dump(mode="json", exclude_none=True)
        assert "projection" in data, "projection must not be omitted by exclude_none"
        assert data["projection"] is not None
        assert "projection_digest" in data["projection"]["projection"]

    def test_exclude_none_preserves_behavior_spec(self):
        """model_dump(exclude_none=True) must not omit structured behavior_spec."""
        envelope = _make_envelope()
        data = envelope.model_dump(mode="json", exclude_none=True)
        assert "behavior_spec" in data
        assert "actions" in data["behavior_spec"]
        assert "assertions" in data["behavior_spec"]

    def test_yaml_always_contains_projection(self):
        """YAML serialization always contains the projection block."""
        import yaml

        envelope = _make_envelope()
        data = envelope.model_dump(mode="json", exclude_none=True)
        yaml_text = yaml.dump(data, default_flow_style=False, sort_keys=False)
        assert "projection:" in yaml_text
        assert "projection_digest:" in yaml_text
        assert "derivation_context_digest:" in yaml_text

    def test_missing_projection_rejected_by_model(self):
        """ScenarioEnvelope model rejects construction without projection."""
        from pydantic import ValidationError

        envelope = _make_envelope()
        data = envelope.model_dump(mode="json")
        del data["projection"]
        with pytest.raises(ValidationError, match="projection"):
            ScenarioEnvelope.model_validate(data)

    def test_behavior_spec_must_be_structured(self):
        """ScenarioEnvelope model rejects raw string behavior_spec."""
        from pydantic import ValidationError

        envelope = _make_envelope()
        data = envelope.model_dump(mode="json")
        data["behavior_spec"] = "Feature: raw string should fail"
        with pytest.raises(ValidationError, match="behavior_spec"):
            ScenarioEnvelope.model_validate(data)


# ===========================================================================
# Production prompt rendering: every Call 0–3 receives identical constraints
# ===========================================================================


class TestProjectionConstraintsInPrompts:
    """Every rendered Call 0–3 prompt embeds the same immutable creative
    constraints — opaque IDs, ingress, and selected-step guidance.

    The LLM may follow but never choose or mutate the projection.  These
    tests prove the production prompt path threads the qualified
    ProjectedCandidate through every call context builder.

    Note: projection_digest was removed from prompts in Phase 2 (the LLM
    cannot use a 64-char SHA-256 hex string).  Realizations are derived
    in post-processing.
    """

    @staticmethod
    def _projection_context() -> dict[str, Any]:
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )

        return _build_projection_context(get_projected_candidate())

    def test_partial_renders_all_constraints(self):
        """The partial renders ingress and selected-step creative guidance."""
        from asago_scenario_generator.prompts import render_prompt

        ctx = self._projection_context()
        rendered = render_prompt("_projection_constraints.j2", projection_context=ctx)
        assert "Canonical Projection Constraints" in rendered
        # projection_digest removed in Phase 2
        assert "projection_digest" not in ctx
        # Phase 3: canonical_ingress_name is preferred; falls back to hex ID
        # when humanization hasn't been applied (e.g. direct template tests).
        ingress_ref = ctx.get(
            "canonical_ingress_name", ctx["canonical_ingress"]["entry_point_id"]
        )
        assert ingress_ref in rendered
        for sid in ctx["selected_step_ids"]:
            assert sid in rendered
        for step in ctx["selected_steps"]:
            assert step["action_kind"] in rendered
            assert step["executor_role"] in rendered
            assert step["boundary_position"] in rendered
            assert step["requirement"] in rendered
        # Adapter-neutral execution records and taxonomy mappings were removed
        # in Phase 4 because they provide no creative guidance to the LLM.
        assert "execution_requirements" not in ctx
        assert "projected_mappings" not in ctx
        assert "Execution Requirements" not in rendered
        assert "Projected Taxonomy Mappings" not in rendered

    def test_context_preserves_explicit_ingress_link_identity(self):
        ctx = self._projection_context()
        assert ctx["initial_ingress_slot_id"] == "ingress"
        ingress_links = [
            link
            for step in ctx["selected_steps"]
            for link in step["resource_links"]
            if link["role"] == "ingress"
        ]
        assert len(ingress_links) == 1
        assert ingress_links[0]["slot_id"] == ctx["initial_ingress_slot_id"]

    def test_call0_prompt_contains_projection_constraints(self):
        from asago_scenario_generator.prompts import render_prompt
        from tests.test_actor_type_compatible_set import (
            TestActorTypePromptConstraint,
        )

        ctx = {
            **TestActorTypePromptConstraint._USER_CTX,
            "compatible_actor_types": [],
            "projection_context": self._projection_context(),
        }
        prompt = render_prompt("call0_user.j2", **ctx)
        pc = self._projection_context()
        assert "Canonical Projection Constraints" in prompt
        for sid in pc["selected_step_ids"]:
            assert sid in prompt

    def test_call3_prompt_contains_projection_constraints(self):
        from asago_scenario_generator.prompts import render_prompt

        pc = self._projection_context()
        # Minimal stubs for call3 template variables.
        ctx = {
            "control_points": [],
            "seed": type(
                "S",
                (),
                {
                    "attack_pattern_name": "X",
                    "threat_name": "X",
                },
            )(),
            "narrative": type(
                "N",
                (),
                {
                    "title": "T",
                    "summary": "S",
                    "entry_point": "E",
                },
            )(),
            "projection_context": pc,
            "leaf_catalog": [],
            "postcondition_ownership": [],
        }
        prompt = render_prompt("call3_user.j2", **ctx)
        assert "Canonical Projection Constraints" in prompt
        for sid in pc["selected_step_ids"]:
            assert sid in prompt

    def test_all_calls_share_identical_ids(self):
        """Every call template that includes the partial embeds the same
        set of opaque step IDs."""
        from asago_scenario_generator.prompts import render_prompt
        from tests.test_actor_type_compatible_set import (
            TestActorTypePromptConstraint,
        )

        pc = self._projection_context()
        ids = set(pc["selected_step_ids"])

        # call0
        ctx0 = {
            **TestActorTypePromptConstraint._USER_CTX,
            "compatible_actor_types": [],
            "projection_context": pc,
        }
        p0 = render_prompt("call0_user.j2", **ctx0)

        # call3
        ctx3 = {
            "control_points": [],
            "seed": type("S", (), {"attack_pattern_name": "X", "threat_name": "X"})(),
            "narrative": type(
                "N", (), {"title": "T", "summary": "S", "entry_point": "E"}
            )(),
            "projection_context": pc,
            "leaf_catalog": [],
            "postcondition_ownership": [],
        }
        p3 = render_prompt("call3_user.j2", **ctx3)

        # Both prompts contain all opaque step IDs.
        for sid in ids:
            assert sid in p0
            assert sid in p3


# ---------------------------------------------------------------------------#
# Adversarial: many-to-many split/combine (contract §5)
# ---------------------------------------------------------------------------#


class TestManyToManyRealization:
    """Controlled many-to-many split/combine with total order preservation."""

    def test_combine_two_steps_in_one_narrative_step(self):
        """One narrative step realizing two projected steps (combine) passes."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = NarrativeLayer(
            title="Combine",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access and exploit",
                    effect="entry and control",
                    projected_step_ids=(selected[0], selected[1]),
                    realizations=make_realizations(
                        (
                            selected[0],
                            selected[1],
                        ),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        # Build block with matching realizations
        from asago_scenario_generator.models.projection_envelope import (
            ArtifactRealizationMapping,
            ArtifactStage,
        )

        block = _make_block(
            narrative_realizations=(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="1",
                    projected_step_ids=(selected[0], selected[1]),
                ),
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="2",
                    projected_step_ids=(selected[2],),
                ),
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        narrative_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
            and v.code
            in (
                ProjectionTraceabilityViolationCode.forged_opaque_id,
                ProjectionTraceabilityViolationCode.incomplete_coverage,
                ProjectionTraceabilityViolationCode.reordered_projected_step,
            )
        ]
        assert not narrative_violations, (
            f"Combine should pass, got {[(v.code.value, v.detail) for v in narrative_violations]}"
        )

    def test_split_one_step_across_two_narrative_steps(self):
        """One projected step realized by two narrative steps (split) passes."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = NarrativeLayer(
            title="Split",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning", "tool_execution"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="continue access",
                    effect="continued entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="exploit",
                    effect="control",
                    projected_step_ids=(selected[1],),
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=4,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        from asago_scenario_generator.models.projection_envelope import (
            ArtifactRealizationMapping,
            ArtifactStage,
        )

        block = _make_block(
            narrative_realizations=(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="1",
                    projected_step_ids=(selected[0],),
                ),
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="2",
                    projected_step_ids=(selected[0],),
                ),
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="3",
                    projected_step_ids=(selected[1],),
                ),
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="4",
                    projected_step_ids=(selected[2],),
                ),
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        narrative_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
            and v.code
            in (
                ProjectionTraceabilityViolationCode.forged_opaque_id,
                ProjectionTraceabilityViolationCode.incomplete_coverage,
                ProjectionTraceabilityViolationCode.reordered_projected_step,
                ProjectionTraceabilityViolationCode.duplicated_projected_step,
            )
        ]
        assert not narrative_violations, (
            f"Split should pass, got {[(v.code.value, v.detail) for v in narrative_violations]}"
        )


# ---------------------------------------------------------------------------#
# Adversarial: unmapped narrative action (no projected_step_ids)
# ---------------------------------------------------------------------------#


class TestUnmappedNarrativeAction:
    """A narrative step with no projected_step_ids must fail."""

    def test_narrative_step_without_projected_step_ids_fails(self):
        """A narrative step with empty projected_step_ids is unprojected."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = NarrativeLayer(
            title="Unmapped",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                ),
                NarrativeStep.model_construct(
                    step_number=2,
                    zone="reasoning",
                    action="unmapped action",
                    effect="unmapped effect",
                    projected_step_ids=(),
                    realizations=make_realizations(
                        (),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.unprojected_security_action in codes
        ), f"Unmapped narrative step should fail, got {codes}"


# ---------------------------------------------------------------------------#
# Adversarial: strict Gherkin validation
# ---------------------------------------------------------------------------#


class TestStrictGherkinValidation:
    """Altered/fabricated Gherkin text must fail strict deterministic comparison."""

    def test_altered_gherkin_text_fails(self):
        """BehaviorSpec with gherkin_text that doesn't match deterministic rendering fails."""
        envelope = _make_envelope()
        # Tamper with the gherkin text
        tampered_spec = BehaviorSpec(
            actions=envelope.behavior_spec.actions,
            assertions=envelope.behavior_spec.assertions,
            gherkin_text="Feature: tampered\n  Scenario: fake\n    When fake action\n",
        )
        envelope = envelope.model_copy(update={"behavior_spec": tampered_spec})
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes, (
            f"Altered Gherkin should fail, got {codes}"
        )

    def test_extra_gherkin_step_fails(self):
        """Extra Gherkin step not in structured actions fails."""
        envelope = _make_envelope()
        # Add an extra step to the Gherkin text
        original = envelope.behavior_spec.gherkin_text
        lines = original.splitlines()
        # Insert an extra step before the last line
        lines.insert(-1, "    And extra fabricated step")
        tampered = "\n".join(lines) + "\n"
        tampered_spec = BehaviorSpec(
            actions=envelope.behavior_spec.actions,
            assertions=envelope.behavior_spec.assertions,
            gherkin_text=tampered,
        )
        envelope = envelope.model_copy(update={"behavior_spec": tampered_spec})
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes, (
            f"Extra Gherkin step should fail, got {codes}"
        )


# ---------------------------------------------------------------------------#
# Adversarial: narrative canonical metadata compatibility
# ---------------------------------------------------------------------------#


class TestNarrativeCanonicalMetadata:
    """Narrative canonical action kind/executor/boundary must match projection."""

    def test_wrong_canonical_action_kind_fails(self):
        """Narrative step with canonical_action_kind not matching projection fails."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        # Get the actual action_kind for step 1
        chain = block.projection.source_chain
        step1 = next(s for s in chain.steps if s.step_id == selected[0])
        wrong_kind = "impact" if step1.action_kind != "impact" else "prepare"
        # Build canonical realizations then corrupt step 1's action_kind
        reals = make_realizations((selected[0],))
        wrong_real = reals[0].model_copy(update={"action_kind": wrong_kind})
        narrative = NarrativeLayer(
            title="Wrong kind",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=(wrong_real,),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="exploit",
                    effect="control",
                    projected_step_ids=(selected[1],),
                    realizations=make_realizations((selected[1],)),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations((selected[2],)),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.incorrect_resource_binding in codes
        ), f"Wrong canonical_action_kind should fail, got {codes}"

    def test_correct_canonical_metadata_passes(self):
        """Narrative step with matching canonical metadata passes."""
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        chain = block.projection.source_chain
        step1 = next(s for s in chain.steps if s.step_id == selected[0])
        narrative = NarrativeLayer(
            title="Correct kind",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access",
                    effect="entry",
                    projected_step_ids=(selected[0],),
                    realizations=make_realizations(
                        (selected[0],),
                        action_kind=step1.action_kind,
                        executor_role=step1.executor_role,
                        boundary_position=step1.boundary_position,
                    ),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="exploit",
                    effect="control",
                    projected_step_ids=(selected[1],),
                    realizations=make_realizations(
                        (selected[1],),
                        action_kind="observe",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
                NarrativeStep(
                    step_number=3,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_realizations(
                        (selected[2],),
                        action_kind="impact",
                        executor_role="system",
                        boundary_position="inside",
                    ),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        metadata_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
            and v.code == ProjectionTraceabilityViolationCode.incorrect_resource_binding
            and "canonical_" in v.detail
        ]
        assert not metadata_violations, (
            f"Correct metadata should pass, got {[(v.detail) for v in metadata_violations]}"
        )


# ---------------------------------------------------------------------------#
# Tests: Call 3 altered output rejection (422o.4 blocker #5)
# ---------------------------------------------------------------------------#


class TestAlteredCall3Output:
    """Altered/omitted/extra Call 3 structured output must be rejected."""

    @staticmethod
    def _make_call3_ctx(selected: list[str]) -> dict:
        """Build a projection context with full realization fields."""
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )

        candidate = get_projected_candidate()
        return _build_projection_context(candidate)

    @staticmethod
    def _make_valid_call3_response(selected: list[str]) -> Call3Response:
        """Build a valid assertions-only Call3Response."""
        # Build assertions for security-relevant postconditions
        candidate = get_projected_candidate()
        chain = candidate.projection.source_chain
        assertions: list[Call3Assertion] = []
        for step in chain.steps:
            if step.step_id in set(selected):
                for pc in step.observable_postconditions:
                    if pc.security_relevant:
                        assertions.append(
                            Call3Assertion(
                                assertion_id=f"assert-{step.step_id}-{pc.postcondition_id}",
                                source_step_ids=(step.step_id,),
                                projected_postcondition_ids=(pc.postcondition_id,),
                                text=f"Verify {pc.postcondition_id}",
                            )
                        )

        return Call3Response(assertions=assertions)

    def test_valid_assertions_only_call3_response_passes(self):
        from asago_scenario_generator.pipeline.generate.gherkin import (
            _validate_call3_response,
        )

        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        selected = list(block.projection.selected_step_ids)
        ctx = self._make_call3_ctx(selected)

        valid_response = self._make_valid_call3_response(selected)
        _validate_call3_response(valid_response, tree, ctx)

    def test_call3_contract_rejects_action_control(self):
        with pytest.raises(ValueError, match="Extra inputs are not permitted"):
            Call3Response.model_validate({"assertions": [], "actions": []})


# ---------------------------------------------------------------------------#
# Tests: Incompatible effect/postcondition mapping (422o.4 blocker #4)
# ---------------------------------------------------------------------------#


class TestIncompatibleEffectPostcondition:
    """Incompatible effect/postcondition mapping must fail."""

    def test_impact_without_effect_produces_violation(self):
        """A leaf with impact action on a step that produces no effect fails.

        This is a true no-effect fixture: step.3 is built with empty
        ``produced`` (no effect entries at all).  The previous version
        skipped when all steps produced effects — that skip is not
        acceptable (422o.4 blocker #4: this skip is not follow-up debt).
        """
        # Build a pattern where step.3 produces no effect (only a state
        # artifact, not an effect).  Produced must be non-empty (min_length=1)
        # but the key is that no entry has kind=="effect".
        raw = _pattern()
        for s in raw["canonical_chain"]["steps"]:
            if s["step_id"] == "step.3":
                s["produced"] = [
                    {"kind": "state", "ref_id": "state.3", "value_type": "boolean"}
                ]
        # Recompute semantic digest after modifying step produced.
        raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
            raw["canonical_chain"]
        )
        pattern = AttackPattern.model_validate(raw)
        resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=100),
        )
        assert len(batch.candidates) >= 1
        candidate = batch.candidates[0]

        # Verify the fixture: step.3 truly has no produced effects.
        chain = candidate.projection.source_chain
        no_effect_step = chain.steps[-1]
        assert no_effect_step.step_id == "step.3"
        assert not any(p.kind == "effect" for p in no_effect_step.produced), (
            "Fixture must have a step with no produced effects"
        )

        selected = candidate.projection.selected_step_ids
        ingress_id = candidate.canonical_ingress.entry_point_id

        # Build realizations: all steps covered, step.3 via impact leaf.
        narrative_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(i + 1),
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
        tree_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id=f"n1.{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
        behavior_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.behavior,
                element_id=f"behavior-{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
        assertion_realizations = (
            AssertionRealizationMapping(
                element_id=(
                    f"assert-{selected[0]}-"
                    f"{chain.steps[0].observable_postconditions[0].postcondition_id}"
                ),
                source_step_ids=(selected[0],),
                projected_postcondition_ids=(
                    chain.steps[0].observable_postconditions[0].postcondition_id,
                ),
            ),
        )

        block = ProjectionEnvelopeBlock(
            projection=candidate.projection,
            canonical_ingress=candidate.canonical_ingress,
            ingress_controllability=candidate.ingress_controllability,
            projected_mappings=candidate.projected_mappings,
            capability_snapshot=snapshot,
            execution_requirements=candidate.execution_requirements,
            requirement_derivation_version=candidate.requirement_derivation_version,
            execution_requirements_digest=candidate.execution_requirements_digest,
            derivation_context_digest=compute_derivation_context_digest(
                candidate.projection.projection_digest,
                candidate.projection.source_chain.pattern_id,
                candidate.ingress_controllability,
            ),
            narrative_realizations=narrative_realizations,
            tree_realizations=tree_realizations,
            behavior_realizations=behavior_realizations,
            assertion_realizations=assertion_realizations,
        )

        # Build a tree leaf with impact action mapped to the no-effect step.
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=("step.1",),
                        realizations=make_step_realizations(("step.1",)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="System",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=("step.2",),
                        realizations=make_step_realizations(("step.2",)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="Wrong impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="no effect"),
                        projected_step_ids=(no_effect_step.step_id,),
                        realizations=make_step_realizations((no_effect_step.step_id,)),
                    ),
                ],
            ),
        )
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produces no effect" in d for d in details), (
            f"Impact on no-effect step should fail, got {details}"
        )

    def test_assertion_postcondition_from_wrong_step_fails(self):
        """An assertion claiming a postcondition from the wrong step fails."""
        block = _make_block()
        chain = block.projection.source_chain
        selected = block.projection.selected_step_ids

        # Find postconditions for step 1 and step 3.
        step1_pcs = []
        step3_pcs = []
        for s in chain.steps:
            if s.step_id == selected[0]:
                step1_pcs = [pc.postcondition_id for pc in s.observable_postconditions]
            if s.step_id == selected[2]:
                step3_pcs = [pc.postcondition_id for pc in s.observable_postconditions]

        if not step1_pcs or not step3_pcs:
            pytest.skip("Need postconditions on both steps")

        # Assertion claims step1's postcondition but maps to step3.
        bad_assertions = (
            AssertionRealizationMapping(
                element_id="assert-wrong",
                source_step_ids=(selected[2],),  # wrong source
                projected_postcondition_ids=(step1_pcs[0],),  # from step 1
            ),
        )
        bad_block = _make_block(assertion_realizations=bad_assertions)
        envelope = _make_envelope(bad_block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch
            in codes
        ), f"Wrong-step postcondition should fail, got {codes}"


# ---------------------------------------------------------------------------#
# Adversarial: per-step realization record mutations (422o.4 blocker #3)
# ---------------------------------------------------------------------------#


class TestRealizationRecordMutations:
    """Adversarial tests for per-step realization record reconciliation.

    Each test mutates a single field in a realization record and verifies
    the validator catches it at the narrative or behavior boundary.
    """

    def test_narrative_forged_consumed_ref_ids_fails(self):
        """Narrative realization with wrong consumed_ref_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # Mutate consumed_ref_ids on step.1's realization
        step1 = narrative.steps[0]
        mutated_realization = step1.realizations[0].model_copy(
            update={"consumed_ref_ids": ("fake.consumed",)}
        )
        new_steps = list(narrative.steps)
        new_steps[0] = step1.model_copy(update={"realizations": (mutated_realization,)})
        narrative = narrative.model_copy(update={"steps": new_steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("consumed_ref_ids" in d for d in details), (
            f"Forged consumed_ref_ids should fail, got {details}"
        )

    def test_narrative_forged_produced_ref_ids_fails(self):
        """Narrative realization with wrong produced_ref_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        step1 = narrative.steps[0]
        mutated_realization = step1.realizations[0].model_copy(
            update={"produced_ref_ids": ("fake.produced",)}
        )
        new_steps = list(narrative.steps)
        new_steps[0] = step1.model_copy(update={"realizations": (mutated_realization,)})
        narrative = narrative.model_copy(update={"steps": new_steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produced_ref_ids" in d for d in details), (
            f"Forged produced_ref_ids should fail, got {details}"
        )

    def test_narrative_forged_postcondition_ids_fails(self):
        """Narrative realization with wrong postcondition_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        step3 = narrative.steps[2]
        mutated_realization = step3.realizations[0].model_copy(
            update={"postcondition_ids": ("fake.post",)}
        )
        new_steps = list(narrative.steps)
        new_steps[2] = step3.model_copy(update={"realizations": (mutated_realization,)})
        narrative = narrative.model_copy(update={"steps": new_steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("postcondition_ids" in d for d in details), (
            f"Forged postcondition_ids should fail, got {details}"
        )

    def test_narrative_forged_outcome_link_pc_ids_fails(self):
        """Narrative realization with wrong outcome_link_pc_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        step3 = narrative.steps[2]
        step3_step = block.projection.source_chain.steps[-1]
        # Add a fake outcome link if the step has outcome links
        if step3_step.observable_outcome_links:
            mutated_realization = step3.realizations[0].model_copy(
                update={"outcome_link_pc_ids": ("fake.outcome",)}
            )
            new_steps = list(narrative.steps)
            new_steps[2] = step3.model_copy(
                update={"realizations": (mutated_realization,)}
            )
            narrative = narrative.model_copy(update={"steps": new_steps})
            envelope = _make_envelope(block, narrative=narrative)
            result = validate_projection_traceability(envelope)
            details = [v.detail for v in result.violations]
            assert any("outcome_link_pc_ids" in d for d in details), (
                f"Forged outcome_link_pc_ids should fail, got {details}"
            )

    def test_narrative_forged_produced_effect_ids_fails(self):
        """Narrative realization with wrong produced_effect_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        step1 = narrative.steps[0]
        step1_step = block.projection.source_chain.steps[0]
        if any(p.kind == "effect" for p in step1_step.produced):
            mutated_realization = step1.realizations[0].model_copy(
                update={"produced_effect_ids": ("fake.effect",)}
            )
            new_steps = list(narrative.steps)
            new_steps[0] = step1.model_copy(
                update={"realizations": (mutated_realization,)}
            )
            narrative = narrative.model_copy(update={"steps": new_steps})
            envelope = _make_envelope(block, narrative=narrative)
            result = validate_projection_traceability(envelope)
            details = [v.detail for v in result.violations]
            assert any("produced_effect_ids" in d for d in details), (
                f"Forged produced_effect_ids should fail, got {details}"
            )

    def test_behavior_forged_consumed_ref_ids_fails(self):
        """Behavior realization with wrong consumed_ref_ids fails."""
        block = _make_block()
        behavior_spec = make_behavior_spec()
        # Mutate consumed_ref_ids on first action's realization
        action0 = behavior_spec.actions[0]
        if action0.realizations[0].consumed_ref_ids:
            mutated_realization = action0.realizations[0].model_copy(
                update={"consumed_ref_ids": ("fake.consumed",)}
            )
            new_actions = list(behavior_spec.actions)
            new_actions[0] = action0.model_copy(
                update={"realizations": (mutated_realization,)}
            )
            behavior_spec = behavior_spec.model_copy(
                update={"actions": tuple(new_actions)}
            )
            envelope = _make_envelope(block, behavior_spec=behavior_spec)
            result = validate_projection_traceability(envelope)
            details = [v.detail for v in result.violations]
            assert any("consumed_ref_ids" in d for d in details), (
                f"Forged behavior consumed_ref_ids should fail, got {details}"
            )

    def test_behavior_forged_produced_ref_ids_fails(self):
        """Behavior realization with wrong produced_ref_ids fails."""
        block = _make_block()
        behavior_spec = make_behavior_spec()
        action0 = behavior_spec.actions[0]
        mutated_realization = action0.realizations[0].model_copy(
            update={"produced_ref_ids": ("fake.produced",)}
        )
        new_actions = list(behavior_spec.actions)
        new_actions[0] = action0.model_copy(
            update={"realizations": (mutated_realization,)}
        )
        behavior_spec = behavior_spec.model_copy(update={"actions": tuple(new_actions)})
        envelope = _make_envelope(block, behavior_spec=behavior_spec)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produced_ref_ids" in d for d in details), (
            f"Forged behavior produced_ref_ids should fail, got {details}"
        )

    def test_behavior_forged_postcondition_ids_fails(self):
        """Behavior realization with wrong postcondition_ids fails."""
        block = _make_block()
        behavior_spec = make_behavior_spec()
        # Find an action with postcondition_ids
        for i, action in enumerate(behavior_spec.actions):
            if action.realizations[0].postcondition_ids:
                mutated_realization = action.realizations[0].model_copy(
                    update={"postcondition_ids": ("fake.post",)}
                )
                new_actions = list(behavior_spec.actions)
                new_actions[i] = action.model_copy(
                    update={"realizations": (mutated_realization,)}
                )
                behavior_spec = behavior_spec.model_copy(
                    update={"actions": tuple(new_actions)}
                )
                envelope = _make_envelope(block, behavior_spec=behavior_spec)
                result = validate_projection_traceability(envelope)
                details = [v.detail for v in result.violations]
                assert any("postcondition_ids" in d for d in details), (
                    f"Forged behavior postcondition_ids should fail, got {details}"
                )
                return
        pytest.skip("No action with postcondition_ids found")

    def test_combine_step_with_per_step_realizations_passes(self):
        """Combine (many-to-many) with correct per-step realization records passes.

        A narrative step mapping to two projected steps carries two
        realization records with different action_kinds — the scalar
        approach couldn't express this, but per-step records can.
        """
        block = _make_block()
        selected = block.selected_step_ids
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = NarrativeLayer(
            title="Combine",
            summary="Adversarial summary",
            entry_point="chat",
            zone_sequence=["input", "reasoning"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="gain access and exploit",
                    effect="entry and control",
                    projected_step_ids=(selected[0], selected[1]),
                    realizations=make_step_realizations((selected[0], selected[1])),
                ),
                NarrativeStep(
                    step_number=2,
                    zone="reasoning",
                    action="impact",
                    effect="damage",
                    projected_step_ids=(selected[2],),
                    realizations=make_step_realizations((selected[2],)),
                ),
            ],
            access_realization=NarrativeAccessRealization(
                initial_entry_point_id=ingress_id,
                responsible_step_number=1,
            ),
        )
        from asago_scenario_generator.models.projection_envelope import (
            ArtifactRealizationMapping,
            ArtifactStage,
        )

        block = _make_block(
            narrative_realizations=(
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="1",
                    projected_step_ids=(selected[0], selected[1]),
                ),
                ArtifactRealizationMapping(
                    artifact_stage=ArtifactStage.narrative,
                    element_id="2",
                    projected_step_ids=(selected[2],),
                ),
            ),
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        semantic_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
            and v.code == ProjectionTraceabilityViolationCode.incorrect_resource_binding
        ]
        assert not semantic_violations, (
            f"Combine with per-step realizations should pass, "
            f"got {[(v.code.value, v.detail) for v in semantic_violations]}"
        )


class TestTreeRealizationRecordMutations:
    """Adversarial tests for per-step realization record reconciliation at the tree boundary.

    Each test mutates a single field in a realization record on a tree leaf
    and verifies the validator catches it at the attack_tree stage.
    """

    def test_tree_forged_consumed_ref_ids_fails(self):
        """Tree leaf realization with wrong consumed_ref_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        leaf = _collect_all_leaves(tree.root)[0]
        mutated = leaf.realizations[0].model_copy(
            update={"consumed_ref_ids": ("fake.consumed",)}
        )
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("consumed_ref_ids" in d for d in details), (
            f"Forged tree consumed_ref_ids should fail, got {details}"
        )

    def test_tree_forged_produced_ref_ids_fails(self):
        """Tree leaf realization with wrong produced_ref_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        leaf = _collect_all_leaves(tree.root)[0]
        mutated = leaf.realizations[0].model_copy(
            update={"produced_ref_ids": ("fake.produced",)}
        )
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produced_ref_ids" in d for d in details), (
            f"Forged tree produced_ref_ids should fail, got {details}"
        )

    def test_tree_forged_postcondition_ids_fails(self):
        """Tree leaf realization with wrong postcondition_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        # Use the last leaf (impact step) which has postconditions
        leaves = _collect_all_leaves(tree.root)
        leaf = leaves[-1]
        mutated = leaf.realizations[0].model_copy(
            update={"postcondition_ids": ("fake.post",)}
        )
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("postcondition_ids" in d for d in details), (
            f"Forged tree postcondition_ids should fail, got {details}"
        )

    def test_tree_forged_outcome_link_pc_ids_fails(self):
        """Tree leaf realization with wrong outcome_link_pc_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        leaves = _collect_all_leaves(tree.root)
        leaf = leaves[-1]
        mutated = leaf.realizations[0].model_copy(
            update={"outcome_link_pc_ids": ("fake.outcome",)}
        )
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("outcome_link_pc_ids" in d for d in details), (
            f"Forged tree outcome_link_pc_ids should fail, got {details}"
        )

    def test_tree_forged_resource_ref_ids_fails(self):
        """Tree leaf realization with wrong resource_ref_ids fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        leaf = _collect_all_leaves(tree.root)[0]
        mutated = leaf.realizations[0].model_copy(
            update={"resource_ref_ids": ("fake.resource",)}
        )
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("resource_ref_ids" in d for d in details), (
            f"Forged tree resource_ref_ids should fail, got {details}"
        )

    def test_tree_forged_action_kind_fails(self):
        """Tree leaf realization with wrong action_kind fails."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)
        leaf = _collect_all_leaves(tree.root)[0]
        wrong_kind = (
            "impact" if leaf.realizations[0].action_kind != "impact" else "prepare"
        )
        mutated = leaf.realizations[0].model_copy(update={"action_kind": wrong_kind})
        leaf = leaf.model_copy(update={"realizations": (mutated,)})
        tree = _replace_leaf(tree, leaf)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("action_kind" in d for d in details), (
            f"Forged tree action_kind should fail, got {details}"
        )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #1: Unconditional realization comparison
# ---------------------------------------------------------------------------#


class TestUnconditionalRealizationComparison:
    """Clearing any realization tuple field must not suppress validation."""

    def test_clear_resource_ref_ids_fails(self):
        """Clearing resource_ref_ids on a step with resources must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # step.1 has resource_ref_ids=('ep:v1:...',)
        step0 = narrative.steps[0]
        cleared = step0.realizations[0].model_copy(update={"resource_ref_ids": ()})
        step0 = step0.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[0] = step0
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("resource_ref_ids" in d for d in details), (
            f"Cleared resource_ref_ids should fail, got {details}"
        )

    def test_clear_produced_ref_ids_fails(self):
        """Clearing produced_ref_ids on a step with produced must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # step.1 has produced_ref_ids=('effect.1',)
        step0 = narrative.steps[0]
        cleared = step0.realizations[0].model_copy(update={"produced_ref_ids": ()})
        step0 = step0.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[0] = step0
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produced_ref_ids" in d for d in details), (
            f"Cleared produced_ref_ids should fail, got {details}"
        )

    def test_clear_produced_effect_ids_fails(self):
        """Clearing produced_effect_ids on a step with effects must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        step0 = narrative.steps[0]
        cleared = step0.realizations[0].model_copy(update={"produced_effect_ids": ()})
        step0 = step0.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[0] = step0
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("produced_effect_ids" in d for d in details), (
            f"Cleared produced_effect_ids should fail, got {details}"
        )

    def test_clear_postcondition_ids_fails(self):
        """Clearing postcondition_ids on a step with postconditions must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # step.3 has postcondition_ids=('post.3',)
        step2 = narrative.steps[2]
        cleared = step2.realizations[0].model_copy(update={"postcondition_ids": ()})
        step2 = step2.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[2] = step2
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("postcondition_ids" in d for d in details), (
            f"Cleared postcondition_ids should fail, got {details}"
        )

    def test_clear_outcome_link_pc_ids_fails(self):
        """Clearing outcome_link_pc_ids on a step with outcome links must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # step.3 has outcome_link_pc_ids=('post.3',)
        step2 = narrative.steps[2]
        cleared = step2.realizations[0].model_copy(update={"outcome_link_pc_ids": ()})
        step2 = step2.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[2] = step2
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("outcome_link_pc_ids" in d for d in details), (
            f"Cleared outcome_link_pc_ids should fail, got {details}"
        )

    def test_clear_consumed_ref_ids_fails(self):
        """Clearing consumed_ref_ids on a step with consumed must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        narrative = _make_narrative(ingress_id)
        # step.2 has consumed_ref_ids=('effect.1',)
        step1 = narrative.steps[1]
        cleared = step1.realizations[0].model_copy(update={"consumed_ref_ids": ()})
        step1 = step1.model_copy(update={"realizations": (cleared,)})
        steps = list(narrative.steps)
        steps[1] = step1
        narrative = narrative.model_copy(update={"steps": steps})
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        details = [v.detail for v in result.violations]
        assert any("consumed_ref_ids" in d for d in details), (
            f"Cleared consumed_ref_ids should fail, got {details}"
        )


class TestDuplicateRealizationRecords:
    """Duplicate realization records (same projected_step_id) must fail."""

    def test_narrative_duplicate_realization_fails(self):
        """NarrativeStep with duplicate realization records must fail."""
        block = _make_block()
        selected = block.selected_step_ids
        reals = make_step_realizations((selected[0],))
        # Duplicate the realization
        dup_reals = reals + reals
        with pytest.raises(ValueError, match="duplicate realization"):
            NarrativeStep(
                step_number=1,
                zone="input",
                action="test",
                effect="test",
                projected_step_ids=(selected[0],),
                realizations=dup_reals,
            )

    def test_tree_duplicate_realization_fails(self):
        """AttackTreeNode with duplicate realization records must fail."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        selected = block.selected_step_ids
        reals = make_step_realizations((selected[0],))
        with pytest.raises(ValueError, match="duplicate realization"):
            AttackTreeNode(
                id="n1.1",
                label="test",
                gate=GateType.LEAF,
                zone="input",
                action=InitialIngressAction(entry_point_id=ingress_id),
                projected_step_ids=(selected[0],),
                realizations=reals + reals,
            )

    def test_behavior_action_duplicate_realization_fails(self):
        """BehaviorAction with duplicate realization records must fail."""
        block = _make_block()
        selected = block.selected_step_ids
        reals = make_step_realizations((selected[0],))
        with pytest.raises(ValueError, match="duplicate realization"):
            BehaviorAction(
                action_id="ba-n1.1",
                projected_step_ids=(selected[0],),
                source_leaf_id="n1.1",
                gherkin_keyword="When",
                text="test",
                realizations=reals + reals,
            )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker: Candidate-ID mismatch
# ---------------------------------------------------------------------------#


class TestCandidateIDMismatch:
    """Standalone traceability must recompute projected candidate ID and
    compare envelope.candidate_id."""

    def test_candidate_id_mismatch_fails(self):
        """Envelope with candidate_id changed to filter-stage ID must fail."""
        block = _make_block()
        narrative = _make_narrative(block.canonical_ingress.entry_point_id)
        envelope = _make_envelope(block, narrative=narrative)
        # Mutate candidate_id to a different value
        wrong_id = "cand:v2:00000000000000000000000000000000"
        mutated = envelope.model_copy(update={"candidate_id": wrong_id})
        result = validate_projection_traceability(mutated)
        # Should produce a candidate identity drift violation
        assert len(result.violations) > 0, (
            "Candidate ID mismatch should produce violations"
        )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #2: Call 2 projection validation
# ---------------------------------------------------------------------------#


class TestCall2ProjectionValidation:
    """Call 2 parsed tree must be validated against the projection context."""

    def test_projectionless_security_leaf_rejected(self):
        """A non-external_precondition leaf without projected_step_ids must fail."""
        from asago_scenario_generator.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            GateType,
        )
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="No projection",
                        gate=GateType.LEAF,
                        zone="input",
                        action=AiSystemAction(),
                        # Missing projected_step_ids and realizations
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Valid leaf",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=("step.2",),
                        realizations=make_step_realizations(("step.2",)),
                    ),
                ],
            ),
        )
        with pytest.raises(ValueError, match="no projected_step_ids"):
            _validate_tree_against_projection(tree, ctx)

    def test_external_precondition_with_projection_rejected(self):
        """An external_precondition leaf with projected_step_ids must fail."""
        from asago_scenario_generator.models.attack_tree import (
            AttackTree,
            AttackTreeNode,
            ExternalPreconditionAction,
            GateType,
        )
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)
        selected = candidate.projection.selected_step_ids

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="External with projection",
                        gate=GateType.LEAF,
                        action=ExternalPreconditionAction(access_provenance="phishing"),
                        projected_step_ids=(selected[0],),
                        realizations=make_step_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Valid leaf",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=("step.2",),
                        realizations=make_step_realizations(("step.2",)),
                    ),
                ],
            ),
        )
        with pytest.raises(ValueError, match="external preconditions must be unmapped"):
            _validate_tree_against_projection(tree, ctx)

    def test_or_gate_rejected(self):
        """OR gates must be rejected by projection validation."""
        from asago_scenario_generator.models.attack_tree import (
            AttackTree,
            AttackTreeNode,
            GateType,
        )
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.OR,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="A",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(
                            entry_point_id=candidate.canonical_ingress.entry_point_id
                        ),
                        projected_step_ids=("step.1",),
                        realizations=make_step_realizations(("step.1",)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="B",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(
                            entry_point_id=candidate.canonical_ingress.entry_point_id
                        ),
                        projected_step_ids=("step.2",),
                        realizations=make_step_realizations(("step.2",)),
                    ),
                ],
            ),
        )
        with pytest.raises(ValueError, match="OR is prohibited"):
            _validate_tree_against_projection(tree, ctx)

    def test_altered_realization_overwritten_by_postprocessing(self):
        """Post-processing overwrites corrupted realizations with canonical ones.

        Since realizations are now derived deterministically in
        ``_fill_tree_realizations`` (post-processing realization engine),
        a corrupted realization on a leaf is silently overwritten with the
        correct canonical realization.  ``_validate_tree_against_projection``
        no longer checks realization equality (it's tautological after
        post-processing).
        """
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _fill_tree_realizations,
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)
        ingress_id = candidate.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)

        # Corrupt the first leaf's realization
        leaf = _collect_all_leaves(tree.root)[0]
        wrong = leaf.realizations[0].model_copy(update={"action_kind": "impact"})
        leaf = leaf.model_copy(update={"realizations": (wrong,)})
        tree = _replace_leaf(tree, leaf)

        # Post-processing overwrites the corrupted realization
        _fill_tree_realizations(tree, ctx)

        # Validation now passes because realizations were overwritten
        _validate_tree_against_projection(tree, ctx)

        # Verify the realization was actually corrected
        corrected_leaf = _collect_all_leaves(tree.root)[0]
        assert corrected_leaf.realizations[0].action_kind != "impact"

    def test_valid_tree_passes(self):
        """A valid tree with correct projection metadata passes validation."""
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)
        ingress_id = candidate.canonical_ingress.entry_point_id
        tree = _make_tree(ingress_id)

        # Should not raise
        _validate_tree_against_projection(tree, ctx)


# ---------------------------------------------------------------------------#
# 422o.4 review blocker #1: canonical derivation tests
# ---------------------------------------------------------------------------#


class TestCanonicalDerivation:
    """Tests for the single source of truth extract_resource_id and
    derive_step_realization functions in models.realization."""

    def test_extract_resource_id_unsupported_type_raises(self):
        """extract_resource_id must raise TypeError for unsupported types."""
        from asago_scenario_generator.models.realization import extract_resource_id

        with pytest.raises(TypeError, match="Unsupported resource reference"):
            extract_resource_id(object())

    def test_extract_resource_id_all_subtypes(self):
        """All six valid resource-reference subtypes return expected IDs."""
        from asago_scenario_generator.models.attack_pattern import (
            AgentInternalResourceReference,
            EntryPointResourceReference,
            IntegrationResourceReference,
            OutputSurfaceResourceReference,
            ToolResourceReference,
            TrustBoundaryResourceReference,
        )
        from asago_scenario_generator.models.realization import extract_resource_id

        _hex32 = "a" * 32
        assert (
            extract_resource_id(
                EntryPointResourceReference(
                    kind="entry_point",
                    entry_point_id=f"ep:v1:{_hex32}",
                )
            )
            == f"ep:v1:{_hex32}"
        )
        assert (
            extract_resource_id(
                ToolResourceReference(
                    kind="tool",
                    tool_id=f"tool:v1:{_hex32}",
                )
            )
            == f"tool:v1:{_hex32}"
        )
        assert (
            extract_resource_id(
                IntegrationResourceReference(
                    kind="integration",
                    integration_id=f"int:v1:{_hex32}",
                )
            )
            == f"int:v1:{_hex32}"
        )
        assert (
            extract_resource_id(
                TrustBoundaryResourceReference(
                    kind="trust_boundary",
                    trust_boundary_id=f"tb:v1:{_hex32}",
                )
            )
            == f"tb:v1:{_hex32}"
        )
        assert (
            extract_resource_id(
                OutputSurfaceResourceReference(
                    kind="output_surface",
                    entry_point_id=f"ep:v1:{_hex32}",
                )
            )
            == f"ep:v1:{_hex32}"
        )
        assert (
            extract_resource_id(AgentInternalResourceReference(kind="agent_internal"))
            == "agent_internal"
        )

    def test_realization_permutation_rejected(self):
        """Reversing a canonically multi-valued tuple must fail.

        Direct model equality (no sorting) means permutations are caught.
        Constructs a synthetic step with ≥2 consumed refs to guarantee
        a multi-valued tuple for permutation testing.
        """
        from asago_scenario_generator.models.attack_pattern import ArtifactReference
        from asago_scenario_generator.models.realization import derive_step_realization

        # Build a synthetic step with ≥2 consumed refs for permutation.
        synthetic_step = type(
            "SyntheticStep",
            (),
            {
                "step_id": "step.synth",
                "action_kind": "execute",
                "executor_role": "attacker",
                "boundary_position": "internal",
                "resource_links": [],
                "consumed": [
                    ArtifactReference(
                        ref_id="ref_a", value_type="string", kind="artifact"
                    ),
                    ArtifactReference(
                        ref_id="ref_b", value_type="string", kind="artifact"
                    ),
                ],
                "produced": [],
                "observable_outcome_links": [],
                "observable_postconditions": [],
            },
        )
        canonical = derive_step_realization(synthetic_step, {})
        assert len(canonical.consumed_ref_ids) == 2
        # Permute the consumed_ref_ids tuple
        permuted = canonical.model_copy(
            update={"consumed_ref_ids": tuple(reversed(canonical.consumed_ref_ids))}
        )
        assert permuted != canonical, (
            "Permuting consumed_ref_ids should produce a different record"
        )
        # Verify direct equality catches the difference (no sorting)
        assert permuted.consumed_ref_ids != canonical.consumed_ref_ids


# ---------------------------------------------------------------------------#
# 422o.4 review blocker #2: external_precondition bypass tests
# ---------------------------------------------------------------------------#


class TestExternalPreconditionBypass:
    """External precondition leaves must have both empty IDs and empty
    realizations — enforced unconditionally at model and validation level."""

    def test_model_rejects_external_precondition_with_realizations(self):
        """AttackTreeNode model must reject external_precondition with
        nonempty realizations even when projected_step_ids is empty."""
        from asago_scenario_generator.models.attack_tree import (
            ExternalPreconditionAction,
        )
        from asago_scenario_generator.models.realization import ProjectedStepRealization

        fake_realization = ProjectedStepRealization(
            projected_step_id="step.1",
            action_kind="prepare",
            executor_role="attacker",
            boundary_position="crossing",
            resource_ref_ids=(),
            consumed_ref_ids=(),
            produced_ref_ids=(),
            produced_effect_ids=(),
            outcome_link_pc_ids=(),
            postcondition_ids=(),
        )
        with pytest.raises(
            ValueError,
            match="1 realization records but 0 projected_step_ids",
        ):
            AttackTreeNode(
                id="n1.1",
                label="External",
                gate=GateType.LEAF,
                action=ExternalPreconditionAction(access_provenance="phishing"),
                projected_step_ids=(),
                realizations=(fake_realization,),
            )

    def test_call2_rejects_external_precondition_with_realizations(self):
        """Call2 tree validation must reject external_precondition with
        nonempty realizations."""
        from asago_scenario_generator.models.attack_tree import (
            ExternalPreconditionAction,
        )
        from asago_scenario_generator.models.realization import ProjectedStepRealization
        from asago_scenario_generator.pipeline.generate.assembly import (
            _build_projection_context,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _validate_tree_against_projection,
        )

        candidate = get_projected_candidate()
        ctx = _build_projection_context(candidate)

        fake_realization = ProjectedStepRealization(
            projected_step_id="step.1",
            action_kind="prepare",
            executor_role="attacker",
            boundary_position="crossing",
            resource_ref_ids=(),
            consumed_ref_ids=(),
            produced_ref_ids=(),
            produced_effect_ids=(),
            outcome_link_pc_ids=(),
            postcondition_ids=(),
        )
        # Use model_construct to bypass model validator on both the bad
        # leaf and the root node (so the child validator doesn't fire).
        bad_leaf = AttackTreeNode.model_construct(
            id="n1.99",
            label="External",
            gate=GateType.LEAF,
            zone=None,
            action=ExternalPreconditionAction(access_provenance="phishing"),
            projected_step_ids=(),
            realizations=(fake_realization,),
        )
        good_leaves = [
            _make_tree_leaf(candidate, i)
            for i in range(len(candidate.projection.selected_step_ids))
        ]
        root = AttackTreeNode.model_construct(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=good_leaves + [bad_leaf],
        )
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Test",
            root=root,
        )
        with pytest.raises(ValueError, match="external preconditions must have empty"):
            _validate_tree_against_projection(tree, ctx)

    def test_final_validation_rejects_external_precondition_with_realizations(self):
        """Final projection validation must report violations for
        external_precondition leaves with nonempty realizations."""
        from asago_scenario_generator.models.attack_tree import (
            ExternalPreconditionAction,
        )
        from asago_scenario_generator.models.realization import ProjectedStepRealization

        block = _make_block()
        narrative = _make_narrative(block.canonical_ingress.entry_point_id)
        envelope = _make_envelope(block, narrative=narrative)

        fake_realization = ProjectedStepRealization(
            projected_step_id="step.1",
            action_kind="prepare",
            executor_role="attacker",
            boundary_position="crossing",
            resource_ref_ids=(),
            consumed_ref_ids=(),
            produced_ref_ids=(),
            produced_effect_ids=(),
            outcome_link_pc_ids=(),
            postcondition_ids=(),
        )
        bad_leaf = AttackTreeNode.model_construct(
            id="n1.99",
            label="External",
            gate=GateType.LEAF,
            zone=None,
            action=ExternalPreconditionAction(access_provenance="phishing"),
            projected_step_ids=(),
            realizations=(fake_realization,),
        )
        # Replace tree with one containing the bad leaf
        if envelope.attack_tree is not None:
            new_root = envelope.attack_tree.root.model_copy(
                update={
                    "children": list(envelope.attack_tree.root.children or [])
                    + [bad_leaf]
                }
            )
            mutated = envelope.model_copy(
                update={
                    "attack_tree": envelope.attack_tree.model_copy(
                        update={"root": new_root}
                    )
                }
            )
            result = validate_projection_traceability(mutated)
            assert any(
                "external precondition" in v.detail.lower()
                and "realization" in v.detail.lower()
                for v in result.violations
            ), (
                f"Expected external_precondition realization violation, "
                f"got: {[v.detail for v in result.violations]}"
            )

    def test_final_validation_rejects_external_precondition_with_projected_ids_only(
        self,
    ):
        """Final projection validation must report violations for
        external_precondition leaves with nonempty projected_step_ids even
        when realizations is empty (the bypass from the surgical fix)."""
        from asago_scenario_generator.models.attack_tree import (
            ExternalPreconditionAction,
        )

        block = _make_block()
        narrative = _make_narrative(block.canonical_ingress.entry_point_id)
        envelope = _make_envelope(block, narrative=narrative)

        bad_leaf = AttackTreeNode.model_construct(
            id="n1.99",
            label="External",
            gate=GateType.LEAF,
            zone=None,
            action=ExternalPreconditionAction(access_provenance="phishing"),
            projected_step_ids=("step.1",),
            realizations=(),
        )
        # Replace tree with one containing the bad leaf
        if envelope.attack_tree is not None:
            new_root = envelope.attack_tree.root.model_copy(
                update={
                    "children": list(envelope.attack_tree.root.children or [])
                    + [bad_leaf]
                }
            )
            mutated = envelope.model_copy(
                update={
                    "attack_tree": envelope.attack_tree.model_copy(
                        update={"root": new_root}
                    )
                }
            )
            result = validate_projection_traceability(mutated)
            assert any(
                "external precondition" in v.detail.lower()
                and "projected_step_ids" in v.detail.lower()
                for v in result.violations
            ), (
                f"Expected external_precondition projected_step_ids violation, "
                f"got: {[v.detail for v in result.violations]}"
            )


def _make_tree_leaf(candidate, index):
    """Helper: make a valid tree leaf for a selected step."""
    selected = candidate.projection.selected_step_ids
    if index >= len(selected):
        return None
    sid = selected[index]
    return AttackTreeNode(
        id=f"n1.{index + 1}",
        label=f"Action for {sid}",
        gate=GateType.LEAF,
        zone="input" if index == 0 else "reasoning",
        action=AiSystemAction()
        if index > 0
        else InitialIngressAction(
            entry_point_id=candidate.canonical_ingress.entry_point_id
        ),
        projected_step_ids=(sid,),
        realizations=make_step_realizations((sid,)),
    )


# ---------------------------------------------------------------------------#
# Zero-coverage internals: _check_order_preservation (CRAP slice 4)
# ---------------------------------------------------------------------------#


class TestCheckOrderPreservation:
    """Direct unit tests for the tuple-position order preservation check."""

    @staticmethod
    def _realizations(
        *pairs: tuple[str, tuple[str, ...]],
    ) -> tuple[ArtifactRealizationMapping, ...]:
        return tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.behavior,
                element_id=element_id,
                projected_step_ids=step_ids,
            )
            for element_id, step_ids in pairs
        )

    @staticmethod
    def _order() -> dict[str, int]:
        return {"step.1": 0, "step.2": 1, "step.3": 2}

    def test_in_order_sequence_is_clean(self) -> None:
        realizations = self._realizations(
            ("a", ("step.1",)),
            ("b", ("step.2",)),
            ("c", ("step.3",)),
        )

        assert (
            _check_order_preservation(
                realizations,
                self._order(),
                ProjectionTraceabilityStage.behavior_spec,
                "behavior",
            )
            == []
        )

    def test_reordered_element_without_shared_steps_is_flagged(self) -> None:
        realizations = self._realizations(
            ("a", ("step.1", "step.3")),
            ("b", ("step.2",)),
        )

        violations = _check_order_preservation(
            realizations,
            self._order(),
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )

        assert len(violations) == 1
        violation = violations[0]
        assert (
            violation.code
            is ProjectionTraceabilityViolationCode.reordered_projected_step
        )
        assert violation.stage is ProjectionTraceabilityStage.narrative
        assert violation.element_id == "b"
        assert "narrative element 'b'" in violation.detail

    def test_shared_step_split_is_allowed(self) -> None:
        realizations = self._realizations(
            ("a", ("step.1", "step.2")),
            ("b", ("step.2", "step.3")),
        )

        assert (
            _check_order_preservation(
                realizations,
                self._order(),
                ProjectionTraceabilityStage.behavior_spec,
                "behavior",
            )
            == []
        )

    def test_elements_with_unknown_step_ids_are_skipped(self) -> None:
        realizations = self._realizations(
            ("a", ("step.unknown",)),
            ("b", ("step.2",)),
        )

        assert (
            _check_order_preservation(
                realizations,
                self._order(),
                ProjectionTraceabilityStage.behavior_spec,
                "behavior",
            )
            == []
        )

    def test_empty_realizations_are_clean(self) -> None:
        assert (
            _check_order_preservation(
                (),
                self._order(),
                ProjectionTraceabilityStage.behavior_spec,
                "behavior",
            )
            == []
        )

    def test_skipped_element_does_not_mispair_earlier_element_citation(
        self,
    ) -> None:
        """A realization with only unknown steps must not shift pair indices.

        Regression: the pair check indexed the filtered ``elements`` list in
        lockstep with the unfiltered ``realizations`` tuple, so a skipped
        realization made the violation cite a wrong earlier element.
        """
        realizations = self._realizations(
            ("a-unknown", ("step.unknown",)),
            ("b", ("step.2",)),
            ("c", ("step.1",)),
        )

        violations = _check_order_preservation(
            realizations,
            self._order(),
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )

        assert len(violations) == 1
        violation = violations[0]
        assert violation.element_id == "c"
        assert "earlier element 'b'" in violation.detail
        assert "a-unknown" not in violation.detail

    def test_skipped_element_cannot_mask_a_real_reorder(self) -> None:
        """The sharing exemption must use the paired elements, not neighbors.

        Regression: 'c' (step.1) precedes 'b' (step.2) with no shared steps,
        but the skip of 'a-unknown' made the sharing check compare
        'a-unknown' against 'b' (both carrying 'step.unknown'), silently
        allowing the reorder.
        """
        realizations = self._realizations(
            ("a-unknown", ("step.unknown",)),
            ("b", ("step.2", "step.unknown")),
            ("c", ("step.1",)),
        )

        violations = _check_order_preservation(
            realizations,
            self._order(),
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )

        assert len(violations) == 1
        assert violations[0].element_id == "c"

    @settings(max_examples=100, deadline=None)
    @given(
        realizations=st.lists(
            st.tuples(
                st.text(alphabet="abc", min_size=1, max_size=4),
                st.lists(
                    st.sampled_from(("step.1", "step.2", "step.3", "step.unknown")),
                    min_size=1,
                    max_size=4,
                    unique=True,
                ),
            ),
            min_size=0,
            max_size=8,
        )
    )
    def test_order_check_matches_an_independent_reference(
        self,
        realizations: list[tuple[str, list[str]]],
    ) -> None:
        """Flagged reorder set matches a reference pairing each element with
        its own ordinals and step IDs (unknown steps skipped in both)."""
        ordered = self._realizations(
            *[(element_id, tuple(step_ids)) for element_id, step_ids in realizations]
        )
        order = self._order()

        # Independent reference: filter unknown-step elements like the
        # production helper, then flag each element whose minimum ordinal
        # precedes an earlier element's maximum without shared steps
        # (first violating later element per element, like the checker).
        elements = [
            (element_id, frozenset(step_ids))
            for element_id, step_ids in realizations
            if any(step_id in order for step_id in step_ids)
        ]
        expected: list[str] = []
        for i in range(len(elements)):
            i_sids = elements[i][1]
            i_max = max(order[sid] for sid in i_sids if sid in order)
            for j in range(i + 1, len(elements)):
                j_id, j_sids = elements[j]
                j_min = min(order[sid] for sid in j_sids if sid in order)
                if j_min < i_max and not (i_sids & j_sids):
                    expected.append(j_id)
                    break

        got = [
            violation.element_id
            for violation in _check_order_preservation(
                ordered,
                order,
                ProjectionTraceabilityStage.behavior_spec,
                "behavior",
            )
        ]
        assert got == expected


class TestPostconditionsForStep:
    """ProjectionEnvelopeBlock.postconditions_for_step contract."""

    def test_returns_postcondition_ids_for_known_step(self) -> None:
        block = _make_block()
        chain = block.projection.source_chain
        step = chain.steps[0]

        assert block.postconditions_for_step(step.step_id) == tuple(
            pc.postcondition_id for pc in step.observable_postconditions
        )

    def test_unknown_step_returns_empty(self) -> None:
        block = _make_block()

        assert block.postconditions_for_step("step.does-not-exist") == ()
