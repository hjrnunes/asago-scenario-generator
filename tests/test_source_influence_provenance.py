"""Unit tests for typed source-influence provenance qualification.

Covers the deterministic engine contract behind
``features/taxonomy_source_influence_provenance.feature``:

- typed provenance records (threat sources, mitigations, capability
  constraints) linking projected attack-tree leaves and narrative steps;
- coverage metrics (projected-leaf, narrative-step, source-reference),
  orphaned-source counts, and unreferenced-artifact counts;
- fail-closed validation for missing, unknown, mismatched, orphaned, and
  unreferenced provenance;
- persisted envelope block serialization and the publish-time gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ImpactAction,
    InitialIngressAction,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    ArchitectureMatch,
    CapabilityProfileRef,
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
from asago_scenario_generator.models.source_influence_provenance import (
    SourceInfluenceArtifactElement,
    SourceInfluenceArtifactKind,
    SourceInfluenceArtifactLink,
    SourceInfluenceMetrics,
    SourceInfluenceProvenanceBlock,
    SourceInfluenceQualification,
    SourceInfluenceSourceRef,
    SourceInfluenceSourceType,
    SourceInfluenceViolationCode,
    parse_source_ref,
)
from asago_scenario_generator.pipeline.generate.assembly import (
    SourceInfluenceProvenanceError,
    write_scenario_outputs,
)
from asago_scenario_generator.pipeline.source_influence import (
    EMPTY_METRICS,
    make_source_influence_provenance_block,
    qualify_source_influence_provenance,
    validate_source_influence_provenance,
)
from tests.helpers.projection_factory import (
    make_behavior_spec,
    make_projection_block,
    make_step_realizations,
)

# ---------------------------------------------------------------------------#
# Typed source records used by the fixtures
# ---------------------------------------------------------------------------#

T12 = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.threat_source, source_id="threat:T12"
)
T13 = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.threat_source, source_id="threat:T13"
)
M12 = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.mitigation, source_id="mitigation:M12"
)
M13 = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.mitigation, source_id="mitigation:M13"
)
MAG = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.capability_constraint,
    source_id="constraint:KCX-MAGENT",
)
VST = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.capability_constraint,
    source_id="constraint:KCX-VSTORE",
)
M99 = SourceInfluenceSourceRef(
    source_type=SourceInfluenceSourceType.mitigation, source_id="mitigation:M99"
)

SHARED = (T12, M12, MAG)
CORRESPONDING = (T12, T13, M12, M13, MAG, VST)


def leaf(element_id: str, *step_ids: str) -> SourceInfluenceArtifactElement:
    """Build a projected-leaf artifact element fixture."""
    return SourceInfluenceArtifactElement(
        artifact_id=element_id, projected_step_ids=tuple(step_ids)
    )


def story_step(element_id: str, *step_ids: str) -> SourceInfluenceArtifactElement:
    """Build a narrative-step artifact element fixture."""
    return SourceInfluenceArtifactElement(
        artifact_id=element_id, projected_step_ids=tuple(step_ids)
    )


def link(
    kind: SourceInfluenceArtifactKind,
    artifact_id: str,
    step_id: str,
    refs: tuple[SourceInfluenceSourceRef, ...],
) -> SourceInfluenceArtifactLink:
    """Build a provenance link fixture."""
    return SourceInfluenceArtifactLink(
        artifact_kind=kind,
        artifact_id=artifact_id,
        projected_step_id=step_id,
        source_refs=refs,
    )


def leaf_link(
    artifact_id: str, step_id: str, refs: tuple[SourceInfluenceSourceRef, ...]
) -> SourceInfluenceArtifactLink:
    return link(SourceInfluenceArtifactKind.projected_leaf, artifact_id, step_id, refs)


def narrative_link(
    artifact_id: str, step_id: str, refs: tuple[SourceInfluenceSourceRef, ...]
) -> SourceInfluenceArtifactLink:
    return link(
        SourceInfluenceArtifactKind.narrative_step, artifact_id, step_id, refs
    )


def coverage(metrics: SourceInfluenceMetrics, name: str) -> tuple[int, int]:
    """Return (numerator, denominator) for one coverage metric by name."""
    fraction = {
        "projected_leaf_coverage": metrics.projected_leaf_coverage,
        "narrative_step_coverage": metrics.narrative_step_coverage,
        "source_reference_coverage": metrics.source_reference_coverage,
    }[name]
    return fraction.numerator, fraction.denominator


# ---------------------------------------------------------------------------#
# Real envelope fixture (mirrors the projection-traceability test recipe)
# ---------------------------------------------------------------------------#


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
    *,
    source_influence_provenance: SourceInfluenceProvenanceBlock | None = None,
) -> ScenarioEnvelope:
    """Build a projection-traceability-valid envelope for provenance tests."""
    from asago_scenario_generator.models.projection_envelope import (
        AssertionRealizationMapping,
    )
    from asago_scenario_generator.pipeline.projection_validation import (
        validate_projection_traceability,
    )
    from tests.helpers.projection_factory import get_projected_candidate

    candidate = get_projected_candidate()
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
    projection_block = make_projection_block(
        assertion_realizations=assertion_realizations
    )
    ingress_id = projection_block.canonical_ingress.entry_point_id
    tree = _make_tree(ingress_id)
    narrative = _make_narrative(ingress_id)
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
    envelope = ScenarioEnvelope(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id=candidate.candidate_id,
        version=3,
        generated_at=datetime.now(UTC),
        generator_version="test",
        initial_entry_point_id=ingress_id,
        actor_profile=actor,
        projection=projection_block,
        narrative=narrative,
        attack_tree=tree,
        behavior_spec=make_behavior_spec("Feature: test"),
        faceting=FacetingMetadata(
            risk_card=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="desc",
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
                attack_complexity="medium",
                architecture_match=ArchitectureMatch.explicit,
                structural_exposure=StructuralExposureSignal.none,
            ),
        ),
        generation=GenerationMetadata(model="test", call_metadata=[]),
        source_influence_provenance=source_influence_provenance,
    )
    trace = validate_projection_traceability(envelope)
    assert trace.valid, (
        f"fixture envelope must be traceability-valid: "
        f"{[(v.code.value, v.detail) for v in trace.violations]}"
    )
    return envelope


def _shared_links() -> tuple[tuple[SourceInfluenceArtifactLink, ...], tuple[SourceInfluenceArtifactLink, ...]]:
    """Full coverage links for the three-step envelope fixture."""
    leaf_links = tuple(
        leaf_link(f"n1.{i + 1}", f"step.{i + 1}", SHARED) for i in range(3)
    )
    narrative_links = tuple(
        narrative_link(str(i + 1), f"step.{i + 1}", SHARED) for i in range(3)
    )
    return leaf_links, narrative_links


# ---------------------------------------------------------------------------#
# Qualification engine
# ---------------------------------------------------------------------------#


class TestQualificationEngine:
    """Scenario 01: complete typed provenance qualifies."""

    def test_complete_single_step_provenance_passes(self) -> None:
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[
                leaf_link("n1.1", "attacker.deliver", SHARED),
            ],
            narrative_links=[
                narrative_link("1", "attacker.deliver", SHARED),
            ],
        )
        assert result.valid is True
        assert result.status == "pass"
        assert result.violations == ()
        assert coverage(result.metrics, "projected_leaf_coverage") == (1, 1)
        assert coverage(result.metrics, "narrative_step_coverage") == (1, 1)
        assert coverage(result.metrics, "source_reference_coverage") == (3, 3)
        assert result.metrics.orphaned_source_count == 0
        assert result.metrics.unreferenced_artifact_count == 0

    def test_complete_coverage_metrics_are_exact(self) -> None:
        """Scenario 02: per-step corresponding sources produce exact metrics."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.observe", "attacker.deliver"),
            declared_sources=CORRESPONDING,
            leaf_elements=[
                leaf("n1.1", "attacker.observe"),
                leaf("n1.2", "attacker.deliver"),
            ],
            narrative_elements=[
                story_step("1", "attacker.observe"),
                story_step("2", "attacker.deliver"),
            ],
            leaf_links=[
                leaf_link("n1.1", "attacker.observe", (T12, M12, MAG)),
                leaf_link("n1.2", "attacker.deliver", (T13, M13, VST)),
            ],
            narrative_links=[
                narrative_link("1", "attacker.observe", (T12, M12, MAG)),
                narrative_link("2", "attacker.deliver", (T13, M13, VST)),
            ],
        )
        assert result.valid is True
        assert result.status == "pass"
        assert coverage(result.metrics, "projected_leaf_coverage") == (2, 2)
        assert coverage(result.metrics, "narrative_step_coverage") == (2, 2)
        assert coverage(result.metrics, "source_reference_coverage") == (6, 6)
        assert result.metrics.orphaned_source_count == 0
        assert result.metrics.unreferenced_artifact_count == 0

    def test_shared_source_records_resolve_and_dedupe(self) -> None:
        """Scenario 03: shared records are stored once and resolve everywhere."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.observe", "attacker.deliver"),
            declared_sources=SHARED + (T12,),  # duplicate threat record
            leaf_elements=[
                leaf("n1.1", "attacker.observe"),
                leaf("n1.2", "attacker.deliver"),
            ],
            narrative_elements=[
                story_step("1", "attacker.observe"),
                story_step("2", "attacker.deliver"),
            ],
            leaf_links=[
                leaf_link("n1.1", "attacker.observe", SHARED),
                leaf_link("n1.2", "attacker.deliver", SHARED),
            ],
            narrative_links=[
                narrative_link("1", "attacker.observe", SHARED),
                narrative_link("2", "attacker.deliver", SHARED),
            ],
        )
        assert result.valid is True
        assert coverage(result.metrics, "source_reference_coverage") == (3, 3)
        assert result.metrics.orphaned_source_count == 0
        block = make_source_influence_provenance_block(
            declared_sources=SHARED + (T12,),
            leaf_links=[
                leaf_link("n1.1", "attacker.observe", SHARED),
                leaf_link("n1.2", "attacker.deliver", SHARED),
            ],
            narrative_links=[
                narrative_link("1", "attacker.observe", SHARED),
                narrative_link("2", "attacker.deliver", SHARED),
            ],
            qualification=result,
        )
        # Each declared source record is stored exactly once.
        assert len(block.declared_sources) == 3
        assert len({(r.source_type, r.source_id) for r in block.declared_sources}) == 3

    @pytest.mark.parametrize(
        "missing_type",
        [
            SourceInfluenceSourceType.threat_source,
            SourceInfluenceSourceType.mitigation,
            SourceInfluenceSourceType.capability_constraint,
        ],
    )
    def test_missing_source_type_fails_closed(self, missing_type) -> None:
        """Scenario 04 outline: omitting one source type fails qualification."""
        leaf_without = (T12, M12, MAG)
        narrative_without = (T12, M12, MAG)
        if missing_type is SourceInfluenceSourceType.threat_source:
            leaf_without = (M12, MAG)
            narrative_without = (M12, MAG)
        elif missing_type is SourceInfluenceSourceType.mitigation:
            leaf_without = (T12, MAG)
            narrative_without = (T12, MAG)
        else:
            leaf_without = (T12, M12)
            narrative_without = (T12, M12)
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", leaf_without)],
            narrative_links=[
                narrative_link("1", "attacker.deliver", narrative_without)
            ],
        )
        assert result.valid is False
        assert result.status == "fail"
        codes = [v.code for v in result.violations]
        assert SourceInfluenceViolationCode.missing_source_provenance in codes
        identified = [
            v for v in result.violations if v.source_type == missing_type
        ]
        assert identified, "no violation identified the missing source type"

    def test_unknown_source_reference_fails_closed(self) -> None:
        """Scenario 05: unknown source references are rejected."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", (T12, M12, MAG, M99))],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        assert result.valid is False
        assert any(
            v.code == SourceInfluenceViolationCode.unknown_source_reference
            and v.source_id == "mitigation:M99"
            for v in result.violations
        ), result.violations

    def test_projected_step_mismatch_fails_closed(self) -> None:
        """Scenario 06: a link claiming the wrong projected step is rejected."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.observe", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        assert result.valid is False
        mismatch = [
            v
            for v in result.violations
            if v.code == SourceInfluenceViolationCode.provenance_projected_step_mismatch
        ]
        assert len(mismatch) == 1
        assert mismatch[0].artifact_id == "n1.1"

    def test_orphaned_source_record_fails_closed(self) -> None:
        """Scenario 07: declared but unused sources are orphaned."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED + (M99,),
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        assert result.valid is False
        orphaned = [
            v
            for v in result.violations
            if v.code == SourceInfluenceViolationCode.orphaned_source_provenance
        ]
        assert len(orphaned) == 1
        assert orphaned[0].source_id == "mitigation:M99"
        assert result.metrics.orphaned_source_count == 1

    def test_unreferenced_artifacts_fail_closed(self) -> None:
        """Scenario 08: artifacts without provenance links identify their step."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.observe", "attacker.deliver"),
            declared_sources=CORRESPONDING,
            leaf_elements=[
                leaf("n1.1", "attacker.observe"),
                leaf("n1.2", "attacker.deliver"),
            ],
            narrative_elements=[
                story_step("1", "attacker.observe"),
                story_step("2", "attacker.deliver"),
            ],
            leaf_links=[leaf_link("n1.2", "attacker.deliver", (T13, M13, VST))],
            narrative_links=[narrative_link("2", "attacker.deliver", (T13, M13, VST))],
        )
        assert result.valid is False
        unreferenced = [
            v
            for v in result.violations
            if v.code
            == SourceInfluenceViolationCode.unreferenced_source_influence_artifact
        ]
        assert len(unreferenced) == 1
        assert unreferenced[0].projected_step_id == "attacker.observe"
        assert coverage(result.metrics, "projected_leaf_coverage") == (1, 2)
        assert coverage(result.metrics, "narrative_step_coverage") == (1, 2)
        assert result.metrics.unreferenced_artifact_count == 2

    def test_no_declared_sources_with_links_fails_closed(self) -> None:
        """A link universe with no declared records rejects every reference."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=(),
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        assert result.valid is False
        assert all(
            v.code == SourceInfluenceViolationCode.unknown_source_reference
            for v in result.violations
        )

    def test_violation_order_is_deterministic(self) -> None:
        """Repeated qualification produces identical violation order."""
        kwargs: dict[str, Any] = dict(
            selected_step_ids=("attacker.observe", "attacker.deliver"),
            declared_sources=SHARED + (M99,),
            leaf_elements=[
                leaf("n1.1", "attacker.observe"),
                leaf("n1.2", "attacker.deliver"),
            ],
            narrative_elements=[
                story_step("1", "attacker.observe"),
                story_step("2", "attacker.deliver"),
            ],
            leaf_links=[leaf_link("n1.2", "attacker.deliver", (T13, M13, VST, M99))],
            narrative_links=[narrative_link("2", "attacker.deliver", SHARED)],
        )
        first = qualify_source_influence_provenance(**kwargs)
        second = qualify_source_influence_provenance(**kwargs)
        assert [v.model_dump() for v in first.violations] == [
            v.model_dump() for v in second.violations
        ]

    def test_stray_link_for_unknown_artifact_is_ignored(self) -> None:
        """Links that do not name any existing artifact element are ignored."""
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[
                leaf_link("n1.1", "attacker.deliver", SHARED),
                leaf_link("n9.9", "attacker.deliver", SHARED),
            ],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        assert result.valid is True
        assert coverage(result.metrics, "projected_leaf_coverage") == (1, 1)


# ---------------------------------------------------------------------------#
# Block model and serialization
# ---------------------------------------------------------------------------#


class TestBlockSerialization:
    """Scenario 09: serialized metadata keeps typed, inspectable references."""

    def test_serialized_block_has_explicit_source_type_and_id(self) -> None:
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED,
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
            qualification=result,
        )
        serialized = block.model_dump(mode="json")
        for artifact_group in ("leaf_links", "narrative_links"):
            for item in serialized[artifact_group]:
                for ref in item["source_refs"]:
                    assert "source_type" in ref
                    assert "source_id" in ref
        assert serialized["metrics"]["source_reference_coverage"] == {
            "numerator": 3,
            "denominator": 3,
        }
        assert serialized["status"] == "pass"

    def test_invalid_qualification_serializes_fail_status(self) -> None:
        result = qualify_source_influence_provenance(
            selected_step_ids=("attacker.deliver",),
            declared_sources=SHARED + (M99,),
            leaf_elements=[leaf("n1.1", "attacker.deliver")],
            narrative_elements=[story_step("1", "attacker.deliver")],
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED + (M99,),
            leaf_links=[leaf_link("n1.1", "attacker.deliver", SHARED)],
            narrative_links=[narrative_link("1", "attacker.deliver", SHARED)],
            qualification=result,
        )
        assert block.status == "fail"
        assert block.metrics.orphaned_source_count == 1

    def test_qualification_rejects_inconsistent_status(self) -> None:
        with pytest.raises(ValidationError):
            SourceInfluenceQualification(
                valid=True,
                status="fail",
                violations=(),
                metrics=SourceInfluenceMetrics(
                    projected_leaf_coverage={"numerator": 0, "denominator": 0},
                    narrative_step_coverage={"numerator": 0, "denominator": 0},
                    source_reference_coverage={"numerator": 0, "denominator": 0},
                    orphaned_source_count=0,
                    unreferenced_artifact_count=0,
                ),
            )

    def test_coverage_fraction_rejects_numerator_above_denominator(self) -> None:
        with pytest.raises(ValidationError):
            SourceInfluenceMetrics(
                projected_leaf_coverage={"numerator": 2, "denominator": 1},
                narrative_step_coverage={"numerator": 0, "denominator": 0},
                source_reference_coverage={"numerator": 0, "denominator": 0},
                orphaned_source_count=0,
                unreferenced_artifact_count=0,
            )

    def test_parse_source_ref_vocabulary(self) -> None:
        assert parse_source_ref("threat:T12") == T12
        assert parse_source_ref("mitigation:M12") == M12
        assert parse_source_ref("constraint:KCX-MAGENT") == MAG
        with pytest.raises(ValueError):
            parse_source_ref("unknown:X1")
        with pytest.raises(ValueError):
            parse_source_ref("raw-source")


# ---------------------------------------------------------------------------#
# Envelope-level validation
# ---------------------------------------------------------------------------#


class TestEnvelopeValidation:
    def test_without_block_passes_vacuously(self) -> None:
        envelope = _make_envelope()
        assert envelope.source_influence_provenance is None
        result = validate_source_influence_provenance(envelope)
        assert result.valid is True
        assert result.status == "pass"
        assert result.violations == ()

    def test_stand_in_envelope_without_typed_block_passes_vacuously(self) -> None:
        """Adapter tests mock the traceability gate; a stand-in envelope
        without a typed block must qualify vacuously rather than crash."""
        result = validate_source_influence_provenance(MagicMock())
        assert result.valid is True
        assert result.status == "pass"
        assert result.violations == ()
        assert result.metrics == EMPTY_METRICS

    def test_valid_block_passes_on_full_envelope(self) -> None:
        leaf_links, narrative_links = _shared_links()
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED,
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=narrative_links,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=leaf_links,
            narrative_links=narrative_links,
            qualification=result,
        )
        envelope = _make_envelope(source_influence_provenance=block)
        validated = validate_source_influence_provenance(envelope)
        assert validated.valid is True
        assert validated.status == "pass"
        assert coverage(validated.metrics, "projected_leaf_coverage") == (3, 3)

    def test_invalid_block_returns_invalid_result(self) -> None:
        leaf_links, narrative_links = _shared_links()
        # Narrative link for step 2 omits the mitigation reference.
        partial_narrative = tuple(
            narrative_link("2", "step.2", (T12, MAG))
            if item.artifact_id == "2"
            else item
            for item in narrative_links
        )
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED,
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=partial_narrative,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=leaf_links,
            narrative_links=partial_narrative,
            qualification=result,
        )
        envelope = _make_envelope(source_influence_provenance=block)
        validated = validate_source_influence_provenance(envelope)
        assert validated.valid is False
        assert any(
            v.code == SourceInfluenceViolationCode.missing_source_provenance
            for v in validated.violations
        )

    def test_stale_persisted_metrics_raise(self) -> None:
        leaf_links, narrative_links = _shared_links()
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED,
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=narrative_links,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=leaf_links,
            narrative_links=narrative_links,
            qualification=result,
        )
        tampered = block.model_copy(
            update={
                "metrics": block.metrics.model_copy(
                    update={
                        "orphaned_source_count": block.metrics.orphaned_source_count
                        + 1
                    }
                )
            }
        )
        envelope = _make_envelope(source_influence_provenance=tampered)
        with pytest.raises(ValueError, match="metrics"):
            validate_source_influence_provenance(envelope)

    def test_stale_persisted_status_raises(self) -> None:
        leaf_links, narrative_links = _shared_links()
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED,
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=narrative_links,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=leaf_links,
            narrative_links=narrative_links,
            qualification=result,
        )
        tampered = block.model_copy(update={"status": "fail"})
        envelope = _make_envelope(source_influence_provenance=tampered)
        with pytest.raises(ValueError, match="status"):
            validate_source_influence_provenance(envelope)


# ---------------------------------------------------------------------------#
# Fail-closed publish gate
# ---------------------------------------------------------------------------#


class TestFailClosedPublish:
    def test_publish_rejects_invalid_provenance_without_writing(self, tmp_path) -> None:
        leaf_links, narrative_links = _shared_links()
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED + (M99,),
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=narrative_links,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED + (M99,),
            leaf_links=leaf_links,
            narrative_links=narrative_links,
            qualification=result,
        )
        envelope = _make_envelope(source_influence_provenance=block)
        with pytest.raises(SourceInfluenceProvenanceError) as excinfo:
            write_scenario_outputs(envelope, tmp_path)
        assert excinfo.value.result.valid is False
        assert "scenario:v2:" in excinfo.value.scenario_id
        # Fail-closed: no artifact bytes may be published.
        assert list(tmp_path.iterdir()) == []

    def test_publish_serializes_valid_provenance_block(self, tmp_path) -> None:
        import yaml

        leaf_links, narrative_links = _shared_links()
        result = qualify_source_influence_provenance(
            selected_step_ids=("step.1", "step.2", "step.3"),
            declared_sources=SHARED,
            leaf_elements=[
                leaf("n1.1", "step.1"),
                leaf("n1.2", "step.2"),
                leaf("n1.3", "step.3"),
            ],
            narrative_elements=[
                story_step("1", "step.1"),
                story_step("2", "step.2"),
                story_step("3", "step.3"),
            ],
            leaf_links=leaf_links,
            narrative_links=narrative_links,
        )
        block = make_source_influence_provenance_block(
            declared_sources=SHARED,
            leaf_links=leaf_links,
            narrative_links=narrative_links,
            qualification=result,
        )
        envelope = _make_envelope(source_influence_provenance=block)
        envelope_path, _ = write_scenario_outputs(envelope, tmp_path)
        serialized = yaml.safe_load(envelope_path.read_text(encoding="utf-8"))
        assert "source_influence_provenance" in serialized
        block_data = serialized["source_influence_provenance"]
        assert block_data["status"] == "pass"
        assert block_data["metrics"]["projected_leaf_coverage"] == {
            "numerator": 3,
            "denominator": 3,
        }
        assert len(block_data["declared_sources"]) == 3
        for group in ("leaf_links", "narrative_links"):
            for item in block_data[group]:
                for ref in item["source_refs"]:
                    assert "source_type" in ref
                    assert "source_id" in ref
