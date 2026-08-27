"""Unit tests for correspondence reconciliation logic."""

from __future__ import annotations

from asago_scenario_generator.models.correspondence import (
    CorrespondenceProposal,
)
from asago_scenario_generator.models.system_resource_map import (
    ControlActionEntry,
    LossLinkEntry,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
)
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence


def _make_test_resource_map() -> SystemResourceMap:
    return SystemResourceMap(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        system_resources=[
            SystemResourceEntry(
                element_id="SR-1",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Issue Payment",
            )
        ],
        loss_links=[
            LossLinkEntry(
                element_id="LL-1",
                loss_id="L-1",
                hazard_id="H-1",
            )
        ],
        trust_boundaries=[
            TrustBoundaryEntry(
                element_id="TB-1",
                resource_ids=["SR-1"],
                taxonomy_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        ],
    )


def test_reconciliation_retains_confirmed_rejected_unresolved() -> None:
    srm = _make_test_resource_map()
    proposals = [
        CorrespondenceProposal(
            proposal_id="P-1",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="supports",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-2",
            left_ref="L-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="addresses",
            evidence_source="curated-map",
            strength="high",
            evidence_refs=["L-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-3",
            left_ref="CA-1-1",
            right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
    ]
    adjudications = {
        "P-1": "confirmed",
        "P-2": "rejected",
        "P-3": "unresolved",
    }

    result = reconcile_correspondence(srm, proposals, adjudications=adjudications)
    assert result.is_valid is True
    assert len(result.proposals) == 3

    p1 = next(p for p in result.proposals if p.proposal_id == "P-1")
    assert p1.adjudication == "confirmed"
    assert p1.relation_type == "supports"
    assert p1.strength == "high"

    p2 = next(p for p in result.proposals if p.proposal_id == "P-2")
    assert p2.adjudication == "rejected"
    assert p2.relation_type == "addresses"

    p3 = next(p for p in result.proposals if p.proposal_id == "P-3")
    assert p3.adjudication == "unresolved"
    assert p3.relation_type == "overlaps"


def test_reconciliation_separates_relation_type_strength_and_adjudication() -> None:
    srm = _make_test_resource_map()
    proposals = [
        CorrespondenceProposal(
            proposal_id="P-1",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="supports",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-4",
            left_ref="CA-1-1",
            right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            relation_type="contradicts",
            evidence_source="exact-id",
            strength="high",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
        CorrespondenceProposal(
            proposal_id="P-3",
            left_ref="CA-1-1",
            right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            relation_type="overlaps",
            evidence_source="resource-overlap",
            strength="weak",
            evidence_refs=["CA-1-1"],
            stpa_version="stpa-v1",
            taxonomy_version="atlas-2026.05",
        ),
    ]

    res = reconcile_correspondence(srm, proposals, adjudications={"P-1": "confirmed"})
    p1 = next(p for p in res.proposals if p.proposal_id == "P-1")
    assert p1.relation_type != p1.strength
    assert p1.relation_type != p1.adjudication


def test_reconciliation_preserves_conflicting_proposals_as_unresolved() -> None:
    srm = _make_test_resource_map()
    prop_a = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    prop_b = CorrespondenceProposal(
        proposal_id="P-4",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="contradicts",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    # Presentation order 1: P-1, P-4
    res1 = reconcile_correspondence(
        srm, [prop_a, prop_b], adjudications={"P-1": "confirmed", "P-4": "confirmed"}
    )
    assert len(res1.proposals) == 2
    for p in res1.proposals:
        assert p.adjudication == "unresolved"
        assert p.conflict_reason == "conflict"

    # Presentation order 2: P-4, P-1
    res2 = reconcile_correspondence(
        srm, [prop_b, prop_a], adjudications={"P-1": "confirmed", "P-4": "confirmed"}
    )
    assert len(res2.proposals) == 2
    for p in res2.proposals:
        assert p.adjudication == "unresolved"
        assert p.conflict_reason == "conflict"


def test_reconciliation_rejects_confirmation_defects() -> None:
    srm = _make_test_resource_map()

    # 1. Dangling left ref
    p_dangling_left = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="NON-EXISTENT",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["NON-EXISTENT"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res1 = reconcile_correspondence(
        srm, [p_dangling_left], adjudications={"P-9": "confirmed"}
    )
    assert res1.is_valid is False
    assert any(
        e.error_code == "dangling_reference" and e.proposal_id == "P-9"
        for e in res1.errors
    )

    # 2. Dangling right ref
    p_dangling_right = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="NON-EXISTENT-TAXONOMY",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res2 = reconcile_correspondence(
        srm, [p_dangling_right], adjudications={"P-9": "confirmed"}
    )
    assert res2.is_valid is False
    assert any(
        e.error_code == "dangling_reference" and e.proposal_id == "P-9"
        for e in res2.errors
    )

    # 3. Stale version
    p_stale = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v0-old",
        taxonomy_version="atlas-2026.05",
    )
    res3 = reconcile_correspondence(srm, [p_stale], adjudications={"P-9": "confirmed"})
    assert res3.is_valid is False
    assert any(
        e.error_code == "source_version_mismatch" and e.proposal_id == "P-9"
        for e in res3.errors
    )

    # 4. Evidence-free confirmation
    p_evidence_free = CorrespondenceProposal(
        proposal_id="P-9",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="",
        evidence_refs=[],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    res4 = reconcile_correspondence(
        srm, [p_evidence_free], adjudications={"P-9": "confirmed"}
    )
    assert res4.is_valid is False
    assert any(
        e.error_code == "evidence_required" and e.proposal_id == "P-9"
        for e in res4.errors
    )


def test_reconciliation_is_deterministic_and_idempotent() -> None:
    srm = _make_test_resource_map()
    p1 = CorrespondenceProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    p2 = CorrespondenceProposal(
        proposal_id="P-2",
        left_ref="L-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="addresses",
        evidence_source="curated-map",
        strength="high",
        evidence_refs=["L-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    p3 = CorrespondenceProposal(
        proposal_id="P-3",
        left_ref="CA-1-1",
        right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        relation_type="overlaps",
        evidence_source="resource-overlap",
        strength="weak",
        evidence_refs=["CA-1-1"],
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    adjudications = {"P-1": "confirmed", "P-2": "rejected", "P-3": "unresolved"}

    res_a = reconcile_correspondence(srm, [p1, p2, p3], adjudications=adjudications)
    res_b = reconcile_correspondence(srm, [p3, p1, p2], adjudications=adjudications)

    # Identical identities and order
    assert [p.proposal_id for p in res_a.proposals] == [
        p.proposal_id for p in res_b.proposals
    ]
    assert [p.adjudication for p in res_a.proposals] == [
        p.adjudication for p in res_b.proposals
    ]

    # Repeating reconciliation on first result
    res_repeat = reconcile_correspondence(
        srm, res_a.proposals, adjudications=adjudications
    )
    assert [p.proposal_id for p in res_repeat.proposals] == [
        p.proposal_id for p in res_a.proposals
    ]
    assert [p.adjudication for p in res_repeat.proposals] == [
        p.adjudication for p in res_a.proposals
    ]
