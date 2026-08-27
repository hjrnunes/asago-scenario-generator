"""Focused regressions for scenario classification and leaf mapping scopes."""

from __future__ import annotations

from asago_scenario_generator.models.attack_pattern import ExactMapping
from asago_scenario_generator.models.scenario import TechniqueScopeEvidence
from asago_scenario_generator.pipeline.projection_contracts import ProjectedMapping
from asago_scenario_generator.pipeline.technique_scopes import (
    _narrative_reference_texts,
    _step_reference_texts,
    resolved_technique_scope_evidence,
)
from asago_scenario_generator.pipeline.validation import validate_scenario_semantics
from asago_scenario_generator.report.template import _build_atlas_techniques_block
from tests.test_semantic_validation import _make_envelope, _make_profile


def _explicit_scope_envelope():
    envelope = _make_envelope(technique_ids=["AML.T0065", None])
    step_id = envelope.projection.selected_step_ids[0]
    envelope.projection = envelope.projection.model_copy(
        update={
            "projected_mappings": (
                ProjectedMapping(
                    scope="step",
                    step_id=step_id,
                    mapping=ExactMapping(
                        decision="exact", taxonomy="ATLAS", ids=("AML.T0065",)
                    ),
                ),
            )
        }
    )
    leaf = envelope.attack_tree.root.children[0]
    leaf.projected_step_ids = (step_id,)
    envelope.narrative.summary = (
        "The scenario is classified as indirect prompt injection AML.T0051.001."
    )
    envelope.faceting.taxonomy_chain.atlas_technique_ids = ["AML.T0051.001"]
    envelope.candidate_filter = {"pinned_technique_ids": ["AML.T0051.001"]}
    envelope.scenario_seed_metadata = {
        "atlas_technique_ids": ["AML.T0054"],
        "threat_id": "T1",
    }
    envelope.technique_scope_evidence = TechniqueScopeEvidence(
        scenario_classification_ids=["AML.T0051.001"],
        projected_step_mapping_ids=["AML.T0065"],
        narrative_reference_ids=["AML.T0051.001"],
    )
    return envelope


def _rules(envelope) -> set[str]:
    validate_scenario_semantics([envelope], _make_profile())
    return {item.rule for item in envelope.validation.semantic.violations}


def test_disjoint_scenario_and_leaf_scopes_are_valid() -> None:
    envelope = _explicit_scope_envelope()

    rules = _rules(envelope)

    assert "narrative_technique_orphan" not in rules
    assert "leaf_technique_mapping_mismatch" not in rules
    assert "scenario_classification_mismatch" not in rules
    assert "seed_technique_provenance" not in rules


def test_narrative_reference_must_belong_to_either_scope() -> None:
    envelope = _explicit_scope_envelope()
    envelope.narrative.summary += " It also uses AML.T0068."
    envelope.technique_scope_evidence.narrative_reference_ids.append("AML.T0068")

    assert "narrative_technique_orphan" in _rules(envelope)


def test_leaf_technique_must_map_every_represented_step() -> None:
    envelope = _explicit_scope_envelope()
    envelope.attack_tree.root.children[0].technique_id = "AML.T0068"

    assert "leaf_technique_mapping_mismatch" in _rules(envelope)


def test_scenario_classification_must_equal_qualified_pins() -> None:
    envelope = _explicit_scope_envelope()
    envelope.candidate_filter["pinned_technique_ids"] = ["AML.T0054"]

    assert "scenario_classification_mismatch" in _rules(envelope)


def test_legacy_envelope_derives_named_scopes_without_intersection_rule() -> None:
    envelope = _make_envelope(
        technique_ids=["AML.T0065", None],
        seed_metadata={"atlas_provenance_ids": ["AML.T0051.001"]},
    )
    envelope.faceting.taxonomy_chain.atlas_technique_ids = ["AML.T0051.001"]
    envelope.narrative.summary = "Classified as AML.T0051.001."

    evidence = resolved_technique_scope_evidence(envelope)
    rules = _rules(envelope)

    assert evidence.legacy_derived is True
    assert evidence.scenario_classification_ids == ["AML.T0051.001"]
    assert evidence.projected_step_mapping_ids == ["AML.T0065"]
    assert "seed_technique_provenance" not in rules
    assert "narrative_technique_orphan" not in rules


def test_report_labels_both_technique_scopes() -> None:
    raw = _explicit_scope_envelope().model_dump(mode="json")

    rendered = _build_atlas_techniques_block(raw)

    assert "Scenario classifications" in rendered
    assert "AML.T0051.001" in rendered
    assert "Projected-step mappings" in rendered
    assert "AML.T0065" in rendered


class TestNarrativeReferenceTextHelpers:
    """Direct branch coverage for the narrative reference text helpers."""

    def test_narrative_reference_texts_without_summary(self) -> None:
        from types import SimpleNamespace

        narrative = SimpleNamespace(summary=None, steps=())
        assert _narrative_reference_texts(narrative) == []

    def test_step_reference_texts_skips_empty_fields(self) -> None:
        from types import SimpleNamespace

        step = SimpleNamespace(action="", effect=None)
        assert _step_reference_texts(step) == []
