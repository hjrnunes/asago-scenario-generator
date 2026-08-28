"""Property tests for correspondence proposal and reconciliation.

These properties pin serialization round trips, byte stability,
canonical-order invariance under presentation order, identity
conservation, idempotent re-reconciliation, and the never-confirmed
proposal invariant. They are offline and deterministic; they never
contact an LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.models.correspondence import (
    CorrespondenceProposal,
    ProposalSet,
    ReconciliationResult,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from tests.helpers.correspondence_factory import make_test_resource_map

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=0,
    max_size=12,
)
_RELATION_TYPES = ["supports", "addresses", "overlaps", "contradicts"]
_EVIDENCE_SOURCES = [
    "exact-id",
    "curated-map",
    "resource-overlap",
    "heuristic",
    "model-assisted",
    "mystery-source",
]
_ADJUDICATIONS = ["confirmed", "rejected", "unresolved"]

# Valid references inside the canonical test resource map.
_STPA_REFS = st.sampled_from(["CA-1-1", "L-1", "SR-1", "TB-1", "CP-2", "RESP-1"])
_TAX_REFS = st.sampled_from(
    [
        "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "AP-T6-01",
        "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
)


def _proposal_strategy(proposal_id: str) -> st.SearchStrategy:
    """Draw one arbitrary proposal pinned to the test map's versions."""
    return st.builds(
        CorrespondenceProposal,
        proposal_id=st.just(proposal_id),
        left_ref=st.one_of(_STPA_REFS, _IDS),
        right_ref=st.one_of(_TAX_REFS, _IDS),
        relation_type=st.sampled_from(_RELATION_TYPES),
        evidence_source=st.sampled_from(_EVIDENCE_SOURCES),
        strength=st.sampled_from(["high", "weak"]),
        evidence_refs=st.lists(_IDS, max_size=3),
        stpa_version=st.just("stpa-v1"),
        taxonomy_version=st.just("atlas-2026.05"),
        proposer_id=st.sampled_from(["", "exact-id-adapter", "heuristic-adapter"]),
        rationale=_IDS,
    )


@st.composite
def _reconcilable_input(draw: st.DrawFn) -> tuple[list[CorrespondenceProposal], dict]:
    """Draw a proposal list with unique ids plus per-id adjudications."""
    numbers = draw(st.lists(st.integers(0, 10_000), min_size=0, max_size=6, unique=True))
    proposals = [
        draw(_proposal_strategy(f"P-{number}")) for number in sorted(numbers)
    ]
    adjudications = {
        proposal.proposal_id: draw(st.sampled_from(_ADJUDICATIONS))
        for proposal in proposals
    }
    return proposals, adjudications


@st.composite
def _evidence_items(draw: st.DrawFn) -> list[dict]:
    """Draw raw evidence items with unique ids and optional fields."""
    numbers = draw(st.lists(st.integers(1, 10_000), min_size=0, max_size=6, unique=True))
    items: list[dict] = []
    for number in sorted(numbers):
        item: dict = {
            "proposal_id": f"P-{number}",
            "left_ref": draw(st.one_of(_STPA_REFS, _IDS)),
            "right_ref": draw(st.one_of(_TAX_REFS, _IDS)),
            "evidence_source": draw(st.sampled_from(_EVIDENCE_SOURCES)),
        }
        if draw(st.booleans()):
            item["strength"] = draw(st.sampled_from(["high", "weak"]))
        if draw(st.booleans()):
            item["relation_type"] = draw(st.sampled_from(_RELATION_TYPES))
        if draw(st.booleans()):
            item["proposer_id"] = draw(_IDS)
        items.append(item)
    return items


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(pset=st.builds(ProposalSet, proposals=st.lists(_proposal_strategy("P-1"), max_size=4)))
def test_proposal_set_round_trips_are_lossless(pset: ProposalSet) -> None:
    """YAML and JSON persistence preserve the proposal set model."""
    assert ProposalSet.from_yaml(pset.to_yaml()) == pset
    assert ProposalSet.from_json(pset.to_json()) == pset


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_reconcilable_input())
def test_result_round_trip_and_serialization_are_stable(data: tuple) -> None:
    """Reconciliation results round trip and serialize byte-identically."""
    proposals, adjudications = data
    srm = make_test_resource_map()
    result = reconcile_correspondence(srm, proposals, adjudications=adjudications)

    assert ReconciliationResult.from_yaml(result.to_yaml()) == result
    assert ReconciliationResult.from_json(result.to_json()) == result
    assert result.to_yaml() == result.to_yaml()
    assert result.to_json() == result.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_reconcilable_input())
def test_reconciliation_conserves_every_proposal(data: tuple) -> None:
    """Every input proposal is retained exactly once, in canonical order."""
    proposals, adjudications = data
    srm = make_test_resource_map()
    result = reconcile_correspondence(srm, proposals, adjudications=adjudications)

    input_ids = [p.proposal_id for p in proposals]
    output_ids = [p.proposal_id for p in result.proposals]
    assert sorted(input_ids) == output_ids
    assert len(output_ids) == len(set(output_ids))


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_reconcilable_input())
def test_reconciliation_is_invariant_under_presentation_order(data: tuple) -> None:
    """Shuffled presentation order cannot change the reconciled artifact."""
    proposals, adjudications = data
    srm = make_test_resource_map()

    result_a = reconcile_correspondence(srm, proposals, adjudications=adjudications)
    shuffled = list(reversed(proposals))
    result_b = reconcile_correspondence(srm, shuffled, adjudications=adjudications)

    assert result_a.to_yaml() == result_b.to_yaml()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_reconcilable_input())
def test_repeat_reconciliation_is_idempotent(data: tuple) -> None:
    """Re-reconciling a result never errors and preserves outcomes."""
    proposals, adjudications = data
    srm = make_test_resource_map()
    result = reconcile_correspondence(srm, proposals, adjudications=adjudications)

    repeat = reconcile_correspondence(srm, result.proposals)

    assert repeat.is_valid is True
    assert repeat.errors == []
    assert [p.proposal_id for p in repeat.proposals] == [
        p.proposal_id for p in result.proposals
    ]
    assert [p.adjudication for p in repeat.proposals] == [
        p.adjudication for p in result.proposals
    ]
    assert [p.conflict_reason for p in repeat.proposals] == [
        p.conflict_reason for p in result.proposals
    ]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(items=_evidence_items())
def test_proposals_are_canonical_and_never_confirmed(items: list[dict]) -> None:
    """Proposal sets are canonically ordered and never pre-confirmed."""
    srm = make_test_resource_map()
    pset = propose_correspondence(srm, source_artifacts={"evidence": items})

    proposal_ids = [p.proposal_id for p in pset.proposals]
    assert proposal_ids == sorted(proposal_ids)
    assert len(proposal_ids) == len(set(proposal_ids))
    for proposal in pset.proposals:
        assert proposal.is_confirmed is False
        assert proposal.stpa_version == srm.stpa_version
        assert proposal.taxonomy_version == srm.taxonomy_version
        assert proposal.strength in ("high", "weak")
        assert proposal.relation_type in _RELATION_TYPES
