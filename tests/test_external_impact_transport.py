"""Tests for external-impact transport normalization and fail-closed semantics.

Attack-tree transport clears Schneider zones from external impacts before
strict model validation while retaining projection semantic enforcement:
the projected step ID is preserved and a non-outside mapping is rejected as
a boundary semantic violation (taxonomy external impact transport).
"""

from __future__ import annotations

from datetime import datetime, UTC

import pytest

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ImpactAction,
    InitialIngressAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    AssertionRealizationMapping,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    ArchitectureMatch,
    AttackComplexity,
    CapabilityProfileRef,
    ConfidenceLevel,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeAccessRealization,
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
from asago_scenario_generator.pipeline.generate.tree_transport import (
    normalize_attack_tree_transport,
)
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _validate_tree_against_projection,
)
from asago_scenario_generator.pipeline.projection_validation import (
    validate_projection_traceability,
)
from tests.helpers.projection_factory import (
    get_canonical_ingress_id,
    get_projected_candidate,
    make_behavior_spec,
    make_projection_block,
    make_step_realizations,
)
from tests.helpers.realization_helper import make_realizations

INGRESS_ID = get_canonical_ingress_id()


def _context(*steps: dict) -> dict:
    return {
        "selected_step_ids": [step["step_id"] for step in steps],
        "selected_steps": [
            {
                "step_id": step["step_id"],
                "action_kind": step["action_kind"],
                "executor_role": step.get("executor_role", "system"),
                "boundary_position": step["boundary_position"],
                "attacker_controlled": step.get("attacker_controlled", False),
                "requirement": "required",
                "resource_links": [],
                "realization": {"projected_step_id": step["step_id"]},
            }
            for step in steps
        ],
        "canonical_ingress": {"entry_point_id": "entry"},
        "ingress_controllability": "direct",
        "omitted_step_ids": [],
    }


_OUTSIDE_IMPACT = {
    "step_id": "attacker.external_impact",
    "action_kind": "impact",
    "executor_role": "attacker",
    "boundary_position": "outside",
    "attacker_controlled": True,
}
_INSIDE_IMPACT = {
    "step_id": "system.internal_impact",
    "action_kind": "impact",
    "executor_role": "system",
    "boundary_position": "inside",
}


def _impact_leaf(
    *,
    step_id: str,
    boundary: str,
    zone: str | None = "reasoning",
    leaf_id: str = "n1.1",
) -> dict:
    return {
        "id": leaf_id,
        "label": "impact",
        "gate": "LEAF",
        "zone": zone,
        "action": {"kind": "impact", "boundary": boundary, "target": "loss"},
        "projected_step_ids": [step_id],
        "realizations": [],
    }


# ---------------------------------------------------------------------------
# Feature 01: accepted impact zones are normalized by action boundary
# ---------------------------------------------------------------------------


class TestNormalizeExternalImpact:
    @pytest.mark.parametrize(
        ("step", "placement"),
        [
            (_OUTSIDE_IMPACT, "nested"),
            (_OUTSIDE_IMPACT, "direct"),
        ],
    )
    def test_external_impact_zone_is_cleared_and_step_id_preserved(
        self, step, placement
    ):
        leaf = _impact_leaf(step_id=step["step_id"], boundary="external")
        if placement == "nested":
            data = {"root": {"id": "n1", "label": "goal", "gate": "AND",
                             "children": [leaf]}}
        else:
            data = {"root": leaf}
        normalized = normalize_attack_tree_transport(data, _context(step))
        target = normalized["root"]
        if placement == "nested":
            target = target["children"][0]
        assert target["zone"] is None
        assert target["projected_step_ids"] == [step["step_id"]]
        assert target["realizations"] == [
            {"projected_step_id": step["step_id"]}
        ]

    def test_internal_impact_zone_is_unchanged(self):
        data = {"root": _impact_leaf(
            step_id=_INSIDE_IMPACT["step_id"], boundary="internal"
        )}
        normalized = normalize_attack_tree_transport(data, _context(_INSIDE_IMPACT))
        assert normalized["root"]["zone"] == "reasoning"


# ---------------------------------------------------------------------------
# Feature 03: external precondition normalization is unchanged
# ---------------------------------------------------------------------------


def test_external_precondition_normalization_is_unchanged():
    data = {
        "root": {
            "id": "n1",
            "label": "setup",
            "gate": "LEAF",
            "zone": "input",
            "action": {"kind": "external_precondition"},
            "projected_step_ids": ["attacker.prepare"],
            "realizations": [],
        }
    }
    context = _context(
        {
            "step_id": "attacker.prepare",
            "action_kind": "prepare",
            "executor_role": "attacker",
            "boundary_position": "outside",
            "attacker_controlled": True,
        }
    )
    normalized = normalize_attack_tree_transport(data, context)
    leaf = normalized["root"]
    assert leaf["zone"] is None
    assert leaf["projected_step_ids"] == ["attacker.prepare"]
    assert leaf["realizations"] == [{"projected_step_id": "attacker.prepare"}]


# ---------------------------------------------------------------------------
# Feature 02: fail-closed non-outside external impact mappings
# ---------------------------------------------------------------------------


class TestFailClosedExternalImpact:
    def test_tree_validation_rejects_external_impact_on_inside_step(self):
        leaf = AttackTreeNode(
            id="n1",
            label="impact",
            gate="LEAF",
            zone=None,
            action=ImpactAction(boundary="external", target="loss"),
            projected_step_ids=("system.impact",),
            realizations=make_realizations(("system.impact",)),
        )
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="goal",
            root=leaf,
        )
        context = _context(
            {
                "step_id": "system.impact",
                "action_kind": "impact",
                "executor_role": "system",
                "boundary_position": "inside",
            }
        )
        with pytest.raises(ValueError, match="boundary semantic violation"):
            _validate_tree_against_projection(tree, context)

    def test_tree_validation_rejects_external_impact_on_crossing_step(self):
        leaf = AttackTreeNode(
            id="n1",
            label="impact",
            gate="LEAF",
            zone=None,
            action=ImpactAction(boundary="external", target="loss"),
            projected_step_ids=("attacker.deliver",),
            realizations=make_realizations(("attacker.deliver",)),
        )
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="goal",
            root=leaf,
        )
        context = _context(
            {
                "step_id": "attacker.deliver",
                "action_kind": "deliver",
                "executor_role": "attacker",
                "boundary_position": "crossing",
                "attacker_controlled": True,
            }
        )
        with pytest.raises(ValueError, match="boundary semantic violation"):
            _validate_tree_against_projection(tree, context)

    def test_tree_validation_accepts_external_impact_on_outside_step(self):
        leaf = AttackTreeNode(
            id="n1",
            label="impact",
            gate="LEAF",
            zone=None,
            action=ImpactAction(boundary="external", target="loss"),
            projected_step_ids=("attacker.external_impact",),
            realizations=make_realizations(("attacker.external_impact",)),
        )
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="goal",
            root=leaf,
        )
        context = _context(_OUTSIDE_IMPACT)
        # Raises for missing security-leaf realizations/coverage?  The
        # outside external impact is a security-bearing leaf and must map
        # selected steps; it does, and validation passes.
        _validate_tree_against_projection(tree, context)

    def test_strict_envelope_validation_rejects_external_impact_boundary_violation(
        self,
    ):
        """Zone normalization happens before model parsing, but strict
        projection validation still rejects the preserved ID as a boundary
        semantic violation; the ID is not silently removed or remapped."""
        envelope = _make_envelope_with_external_impact()
        result = validate_projection_traceability(envelope)
        assert result.valid is False
        details = " ".join(v.detail for v in result.violations)
        assert "external impact" in details
        assert "boundary semantic violation" in details
        # The violation is attributed to the attack-tree stage and keeps the
        # projected step ID on the leaf.
        tree_violations = [
            v
            for v in result.violations
            if v.stage.value == "attack_tree"
            and "boundary semantic violation" in v.detail
        ]
        assert tree_violations
        assert tree_violations[0].projected_step_id == envelope.projection.selected_step_ids[-1]
        # Only the boundary semantic violation is reported; the external
        # impact leaf is not silently removed or remapped anywhere else.
        assert len(tree_violations) == 1


# ---------------------------------------------------------------------------
# Envelope factory (mirrors tests/test_projection_traceability.py fixtures)
# ---------------------------------------------------------------------------


def _make_envelope_with_external_impact() -> ScenarioEnvelope:
    candidate = get_projected_candidate()
    selected = candidate.projection.selected_step_ids
    ingress = get_canonical_ingress_id()

    # Tree: valid baseline leaves plus an external-impact leaf mapping the
    # inside impact step (step.3) — a boundary semantic violation.
    tree = AttackTree(
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
                    action=InitialIngressAction(entry_point_id=ingress),
                    projected_step_ids=(selected[0],),
                    realizations=make_step_realizations((selected[0],)),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System action",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                    projected_step_ids=(selected[1],),
                    realizations=make_step_realizations((selected[1],)),
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Impact",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=ImpactAction(boundary="internal", target="data integrity"),
                    projected_step_ids=(selected[2],),
                    realizations=make_step_realizations((selected[2],)),
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="External impact claim",
                    gate=GateType.LEAF,
                    zone=None,
                    action=ImpactAction(boundary="external", target="loss"),
                    projected_step_ids=(selected[2],),
                    realizations=make_step_realizations((selected[2],)),
                ),
            ],
        ),
    )

    tree_realizations = (
        ArtifactRealizationMapping(
            artifact_stage=ArtifactStage.attack_tree,
            element_id=f"n1.{i + 1}",
            projected_step_ids=(sid,),
        )
        for i, sid in enumerate(selected)
    )
    behavior = make_behavior_spec()
    block = make_projection_block(
        tree_realizations=tuple(tree_realizations)
        + (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.4",
                projected_step_ids=(selected[2],),
            ),
        ),
        assertion_realizations=tuple(
            AssertionRealizationMapping(
                element_id=assertion.assertion_id,
                source_step_ids=assertion.source_step_ids,
                projected_postcondition_ids=assertion.projected_postcondition_ids,
            )
            for assertion in behavior.assertions
        ),
    )

    narrative = NarrativeLayer(
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
                projected_step_ids=(selected[0],),
                realizations=make_step_realizations((selected[0],)),
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="exploit",
                effect="control",
                projected_step_ids=(selected[1],),
                realizations=make_step_realizations((selected[1],)),
            ),
            NarrativeStep(
                step_number=3,
                zone="reasoning",
                action="impact",
                effect="damage",
                projected_step_ids=(selected[2],),
                realizations=make_step_realizations((selected[2],)),
            ),
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ingress,
            responsible_step_number=1,
        ),
    )

    actor = ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["target has chat interface"],
        desires=["steal data"],
        intentions=["prompt injection"],
        resources=["open-source tools"],
        access=ActorAccessProvenance(
            initial_entry_point_id=ingress,
            ingress_mode="direct",
            access_class="public",
        ),
    )

    return ScenarioEnvelope(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id=candidate.candidate_id,
        version=3,
        generated_at=datetime.now(UTC),
        generator_version="test",
        initial_entry_point_id=ingress,
        actor_profile=actor,
        projection=block,
        narrative=narrative,
        attack_tree=tree,
        behavior_spec=behavior,
        faceting=FacetingMetadata(
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
        ),
        priority=Priority(
            composite=0.5,
            signals=PrioritySignals(
                technique_maturity=TechniqueMaturity.feasible,
                risk_impact=SeverityLevel.high,
                risk_likelihood=LikelihoodLevel.medium,
                attack_complexity=AttackComplexity.medium,
                architecture_match=ArchitectureMatch.explicit,
                structural_exposure=StructuralExposureSignal.none,
            ),
        ),
        generation=GenerationMetadata(model="test", call_metadata=[]),
    )
