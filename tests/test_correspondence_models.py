"""Unit tests for correspondence domain models and serialization contracts."""

from __future__ import annotations

from asago_scenario_generator.models.correspondence import (
    AdjudicationHistoryItem,
    CorrespondenceProposal,
    ProposalProvenance,
    ProposalSet,
    ReconciliationError,
    ReconciliationResult,
    ReconciledProposal,
)


def test_proposal_provenance_creation() -> None:
    prov = ProposalProvenance(
        proposer_id="exact-id-adapter",
        proposer_version="1",
        evidence_refs=["CA-1-1", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        rationale="exact identifier match",
        adapter_kind="deterministic",
    )
    assert prov.proposer_id == "exact-id-adapter"
    assert prov.proposer_version == "1"
    assert prov.evidence_refs == ["CA-1-1", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert prov.stpa_version == "stpa-v1"
    assert prov.taxonomy_version == "atlas-2026.05"
    assert prov.rationale == "exact identifier match"


def test_correspondence_proposal_defaults_and_fields() -> None:
    prop = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        proposer_id="exact-id-adapter",
        proposer_version="1",
        evidence_refs=["CA-1-1", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        rationale="exact identifier match",
    )
    assert prop.proposal_id == "P-1"
    assert prop.left_ref == "CA-1-1"
    assert prop.right_ref == "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert prop.relation_type == "supports"
    assert prop.evidence_source == "exact-id"
    assert prop.strength == "high"
    assert prop.is_confirmed is False


def test_proposal_set_yaml_and_json_roundtrip() -> None:
    prop1 = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    prop2 = CorrespondenceProposal(
        proposal_id="P-2",
        left_ref="L-1",
        right_ref="AP-T6-01",
        relation_type="addresses",
        evidence_source="curated-map",
        strength="high",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    pset = ProposalSet(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        proposals=[prop1, prop2],
    )

    yaml_str = pset.to_yaml()
    loaded_yaml = ProposalSet.from_yaml(yaml_str)
    assert len(loaded_yaml.proposals) == 2
    assert loaded_yaml.proposals[0].proposal_id == "P-1"
    assert loaded_yaml.proposals[1].proposal_id == "P-2"
    assert loaded_yaml.stpa_version == "stpa-v1"

    json_str = pset.to_json()
    loaded_json = ProposalSet.from_json(json_str)
    assert len(loaded_json.proposals) == 2
    assert loaded_json.proposals[0].relation_type == "supports"
    assert loaded_json.proposals[1].evidence_source == "curated-map"


def test_reconciliation_result_roundtrip_and_no_blended_metrics() -> None:
    rec1 = ReconciledProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        adjudication="confirmed",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        adjudication_history=[
            AdjudicationHistoryItem(adjudication="confirmed", reason="verified")
        ],
    )
    rec2 = ReconciledProposal(
        proposal_id="P-2",
        left_ref="L-1",
        right_ref="AP-T6-01",
        relation_type="addresses",
        evidence_source="curated-map",
        strength="high",
        adjudication="rejected",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    rec3 = ReconciledProposal(
        proposal_id="P-3",
        left_ref="CP-2",
        right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        relation_type="overlaps",
        evidence_source="resource-overlap",
        strength="weak",
        adjudication="unresolved",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    result = ReconciliationResult(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        is_valid=True,
        proposals=[rec1, rec2, rec3],
        errors=[],
        network_calls=0,
        model_calls=0,
    )

    yaml_text = result.to_yaml()
    json_text = result.to_json()

    # Verify no coverage score or blended method metric
    assert "coverage" not in yaml_text.lower()
    assert "blended" not in yaml_text.lower()
    assert "coverage" not in json_text.lower()
    assert "blended" not in json_text.lower()

    # YAML round trip
    loaded_yaml = ReconciliationResult.from_yaml(yaml_text)
    assert len(loaded_yaml.proposals) == 3
    assert loaded_yaml.proposals[0].adjudication == "confirmed"
    assert loaded_yaml.proposals[1].adjudication == "rejected"
    assert loaded_yaml.proposals[2].adjudication == "unresolved"

    # JSON round trip
    loaded_json = ReconciliationResult.from_json(json_text)
    assert len(loaded_json.proposals) == 3
    assert loaded_json.proposals[0].relation_type == "supports"
    assert loaded_json.proposals[0].adjudication_history[0].adjudication == "confirmed"


def test_reconciliation_result_byte_identical() -> None:
    rec = ReconciledProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        adjudication="confirmed",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    result = ReconciliationResult(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        proposals=[rec],
    )
    yaml1 = result.to_yaml()
    yaml2 = result.to_yaml()
    assert yaml1 == yaml2

    json1 = result.to_json()
    json2 = result.to_json()
    assert json1 == json2


def test_reconciliation_error_fields() -> None:
    err = ReconciliationError(
        proposal_id="P-9",
        error_code="dangling_reference",
        message="Dangling left ref",
    )
    assert err.proposal_id == "P-9"
    assert err.error_code == "dangling_reference"
    assert err.code == "dangling_reference"
    assert err.message == "Dangling left ref"
