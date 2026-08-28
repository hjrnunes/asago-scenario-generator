"""Unit tests for correspondence domain models and serialization contracts."""

from __future__ import annotations

import json

import yaml

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


def test_correspondence_proposal_post_init_provenance_rules() -> None:
    # No top-level proposer and no provenance: provenance stays absent.
    bare = CorrespondenceProposal(proposal_id="P-1", left_ref="A", right_ref="B")
    assert bare.provenance is None

    # Top-level proposer fields synthesize provenance once.
    derived = CorrespondenceProposal(
        proposal_id="P-2",
        left_ref="A",
        right_ref="B",
        proposer_id="exact-id-adapter",
        evidence_refs=["CA-1-1"],
    )
    assert derived.provenance is not None
    assert derived.provenance.proposer_id == "exact-id-adapter"
    assert derived.provenance.evidence_refs == ["CA-1-1"]

    # An explicit provenance wins over top-level fields: post_init must not
    # rebuild it from the (possibly different) top-level values.
    seeded = CorrespondenceProposal(
        proposal_id="P-3",
        left_ref="A",
        right_ref="B",
        proposer_id="different-adapter",
        provenance=ProposalProvenance(
            proposer_id="seed-adapter", rationale="kept as provided"
        ),
    )
    assert seeded.provenance.proposer_id == "seed-adapter"
    assert seeded.provenance.rationale == "kept as provided"


def test_proposal_set_yaml_is_block_style_with_sorted_keys() -> None:
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        proposer_id="exact-id-adapter",
        rationale="café",
    )
    pset = ProposalSet(stpa_version="stpa-v1", proposals=[proposal])
    text = pset.to_yaml()

    parsed = yaml.safe_load(text)
    top_keys = list(parsed)
    assert top_keys == sorted(top_keys)
    # Byte identity against the canonical dumper: pins block style, key
    # order, and readable unicode in one assertion.
    assert (
        yaml.dump(
            parsed,
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
            default_style='"',
        )
        == text
    )
    # Block sequences remain blocks, not inline flow style.
    assert "\n- " in text or text.startswith("- ")


def test_proposal_set_yaml_round_trips_unicode_line_separator() -> None:
    # PyYAML's plain/single-quoted styles silently corrupt U+0085 (NEL);
    # the double-quoted dumper style must escape it so round trips are
    # lossless.
    pset = ProposalSet(
        proposals=[
            CorrespondenceProposal(
                proposal_id="P-1",
                left_ref="A",
                right_ref="B",
                rationale="flow\x85name",
            )
        ]
    )
    restored = ProposalSet.from_yaml(pset.to_yaml())
    assert restored.proposals[0].rationale == "flow\x85name"
    assert restored == pset


def test_proposal_set_and_reconciliation_json_are_sorted_and_deterministic() -> None:
    proposal = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        proposer_id="exact-id-adapter",
    )
    pset = ProposalSet(stpa_version="stpa-v1", proposals=[proposal])
    json_text = pset.to_json()

    parsed = json.loads(json_text)
    top_keys = list(parsed)
    assert top_keys == sorted(top_keys)
    # Keys are emitted in sorted order, so re-dumping the parsed payload is
    # byte-identical: no serialization detail depends on field order.
    assert json.dumps(parsed, indent=2, sort_keys=True) + "\n" == json_text

    result = ReconciliationResult(
        stpa_version="stpa-v1",
        proposals=[
            ReconciledProposal(
                proposal_id="P-1",
                left_ref="CA-1-1",
                right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                relation_type="supports",
                evidence_source="exact-id",
                strength="high",
            )
        ],
    )
    result_text = result.to_json()
    result_parsed = json.loads(result_text)
    assert list(result_parsed) == sorted(result_parsed)
    assert json.dumps(result_parsed, indent=2, sort_keys=True) + "\n" == result_text


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


def test_reconciliation_result_defaults_are_pinned() -> None:
    # Artifact defaults: a fresh result is valid with zero network and
    # model calls, and proposals start unconfirmed.
    result = ReconciliationResult()
    assert result.is_valid is True
    assert result.network_calls == 0
    assert result.model_calls == 0

    fresh_proposal = CorrespondenceProposal(
        proposal_id="P-1", left_ref="A", right_ref="B"
    )
    assert fresh_proposal.is_confirmed is False


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
