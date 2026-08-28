"""Unit tests for deterministic correspondence proposal generation."""

from __future__ import annotations

from asago_scenario_generator.pipeline.correspondence import propose_correspondence
from tests.helpers.correspondence_factory import make_test_resource_map


def test_propose_exact_id_and_curated_map() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "evidence_source": "exact-id",
            "left_ref": "CA-1-1",
            "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposal_id": "P-1",
            "strength": "high",
            "relation_type": "supports",
        },
        {
            "evidence_source": "curated-map",
            "left_ref": "L-1",
            "right_ref": "AP-T6-01",
            "proposal_id": "P-2",
            "strength": "high",
            "relation_type": "addresses",
        },
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    assert len(pset.proposals) == 2

    p1 = next(p for p in pset.proposals if p.proposal_id == "P-1")
    assert p1.evidence_source == "exact-id"
    assert p1.strength == "high"
    assert p1.relation_type == "supports"
    assert p1.is_confirmed is False
    assert p1.stpa_version == "stpa-v1"
    assert p1.taxonomy_version == "atlas-2026.05"

    p2 = next(p for p in pset.proposals if p.proposal_id == "P-2")
    assert p2.evidence_source == "curated-map"
    assert p2.strength == "high"
    assert p2.relation_type == "addresses"
    assert p2.is_confirmed is False


def test_propose_weak_resource_overlap() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "evidence_source": "resource-overlap",
            "left_ref": "CP-2",
            "right_ref": "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "proposal_id": "P-3",
            "strength": "weak",
            "relation_type": "overlaps",
        }
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    p3 = pset.proposals[0]
    assert p3.evidence_source == "resource-overlap"
    assert p3.strength == "weak"
    assert p3.evidence_source != "exact-id"
    assert p3.evidence_source != "curated-map"
    assert p3.is_confirmed is False


def test_propose_provenance_retained() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "proposal_id": "P-1",
            "left_ref": "CA-1-1",
            "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposer_id": "exact-id-adapter",
            "proposer_version": "1",
            "evidence_refs": ["CA-1-1", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "stpa_version": "stpa-v1",
            "taxonomy_version": "atlas-2026.05",
            "rationale": "exact identifier match",
            "evidence_source": "exact-id",
            "strength": "high",
            "relation_type": "supports",
        }
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    p1 = pset.proposals[0]
    assert p1.left_ref == "CA-1-1"
    assert p1.right_ref == "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert p1.proposer_id == "exact-id-adapter"
    assert p1.proposer_version == "1"
    assert p1.evidence_refs == ["CA-1-1", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert p1.stpa_version == "stpa-v1"
    assert p1.taxonomy_version == "atlas-2026.05"
    assert p1.rationale == "exact identifier match"


def test_propose_default_ids_are_one_based_and_refs_default_to_pair() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "evidence_source": "exact-id",
            "left_ref": "CA-1-1",
            "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        {
            "evidence_source": "curated-map",
            "left_ref": "L-1",
            "right_ref": "AP-T6-01",
        },
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    # Default ids enumerate from 1 in evidence order, then sort canonically.
    assert [p.proposal_id for p in pset.proposals] == ["P-1", "P-2"]
    for p in pset.proposals:
        assert p.evidence_refs == [p.left_ref, p.right_ref]
        assert p.is_confirmed is False


def test_propose_one_sided_evidence_defaults_to_no_evidence_refs() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "proposal_id": "P-1",
            "left_ref": "CA-1-1",
            "right_ref": "",
            "evidence_source": "exact-id",
        }
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    p1 = pset.proposals[0]
    # Default evidence refs require both endpoints; a one-sided item
    # proposes with no evidence rather than a dangling half pair.
    assert p1.evidence_refs == []


def test_propose_heuristic_and_model_assisted_adapters_cannot_confirm() -> None:
    srm = make_test_resource_map()
    evidence = [
        {
            "proposal_id": "P-H",
            "left_ref": "CA-1-1",
            "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposer_id": "heuristic-adapter",
            "adapter_kind": "heuristic",
            "evidence_source": "heuristic",
            "strength": "weak",
            "relation_type": "supports",
        },
        {
            "proposal_id": "P-M",
            "left_ref": "CA-1-1",
            "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposer_id": "model-assisted-adapter",
            "adapter_kind": "model-assisted",
            "evidence_source": "model-assisted",
            "strength": "weak",
            "relation_type": "supports",
        },
    ]

    pset = propose_correspondence(srm, source_artifacts={"evidence": evidence})
    for p in pset.proposals:
        assert p.is_confirmed is False
        if p.proposer_id == "heuristic-adapter":
            assert p.evidence_source == "heuristic"
        elif p.proposer_id == "model-assisted-adapter":
            assert p.evidence_source == "model-assisted"
