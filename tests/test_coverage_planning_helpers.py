"""Direct branch tests for the decomposed coverage-planning helpers.

The decomposition split the over-complex coverage-planning functions
(``_solve_min_cost_assignment``, ``select_with_coverage_priority``,
``build_coverage_plan``, ``plan_generation``, ``emit_quality_gaps``,
``deserialize_qualified_candidate``, ``revalidate_qualified_candidate``,
``QualifiedCandidate.to_plan_ref``, ``build_coverage_universe``) into
single-purpose helpers.  Every helper below gets unit tests covering each
branch; the public-API behaviour is covered by
``test_cmps4_coverage_planning.py``.
"""

from __future__ import annotations


import pytest

from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    AcceptedFilterRecord,
    QualifiedCandidate,
    _deserialize_filter_records,
    _expected_authoritative_pin,
    _find_trusted_record,
    _first_filter_summary,
    _merge_deduped,
    _verify_canonical_filter_ids,
    _verify_outer_identity,
    _verify_seed_ingress_agreement,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate
from tests.helpers.projection_factory import get_projected_candidate

_REAL_PC = get_projected_candidate()
_REAL_EP_ID = _REAL_PC.canonical_ingress.entry_point_id
_REAL_PATTERN_ID = _REAL_PC.pattern_id


def _risk() -> RiskCardRef:
    return RiskCardRef(
        risk_id="risk-1",
        risk_name="Test risk",
        risk_description="Test risk description.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _fseed(
    *,
    candidate_id: str = "filter-candidate-1",
    origins: list[CandidateOrigin] | None = None,
    rejections: list[RejectionRecord] | None = None,
    pinned_entry_point: str = "user prompt",
    entry_point_id: str = _REAL_EP_ID,
) -> FilteredSeed:
    return FilteredSeed(
        seed_id=_REAL_PATTERN_ID,
        threat_id="T1",
        threat_name="Test threat",
        attack_pattern_name="Test pattern",
        attack_pattern_description="Test attack pattern description.",
        risk_card_ref=_risk(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=("AML.T0051",),
        pinned_technique_names=("Technique 1",),
        entry_point_id=entry_point_id,
        candidate_id=candidate_id,
        origins=origins or [],
        rejection_rationales=rejections or [],
    )


def _origin(source_candidate_id: str = "src-1") -> CandidateOrigin:
    return CandidateOrigin(
        source_candidate_id=source_candidate_id,
        original_technique_ids=("AML.T0051",),
        transform_stage="expansion",
    )


def _rejection(candidate_id: str = "rejected-1") -> RejectionRecord:
    return RejectionRecord(
        candidate_id=candidate_id,
        entry_point="user prompt",
        atlas_technique_ids=("AML.T0051",),
        rationale="rejected by rules",
    )


def _record(
    candidate_id: str,
    *,
    origins: list[CandidateOrigin] | None = None,
    rejections: list[RejectionRecord] | None = None,
    pinned_entry_point: str = "user prompt",
) -> AcceptedFilterRecord:
    return AcceptedFilterRecord.from_seed(
        _fseed(
            candidate_id=candidate_id,
            origins=origins,
            rejections=rejections,
            pinned_entry_point=pinned_entry_point,
        )
    )


def _pc(
    candidate_id: str = "cand:v2:00000000000000000000000000000001",
    pattern_id: str = _REAL_PATTERN_ID,
) -> ProjectedCandidate:
    return _REAL_PC.model_copy(
        update={
            "candidate_id": candidate_id,
            "pattern_id": pattern_id,
            "canonical_ingress": _REAL_PC.canonical_ingress,
        }
    )


def _qc(number: int, pattern: str = _REAL_PATTERN_ID) -> QualifiedCandidate:
    cid = f"cand:v2:{number:032x}"
    return QualifiedCandidate(
        projected=_pc(cid, pattern_id=pattern),
        accepted_filters=(_record(f"filter-{number}"),),
    )


# ---------------------------------------------------------------------------
# to_plan_ref helpers
# ---------------------------------------------------------------------------


class TestMergeDeduped:
    def test_merges_distinct_items_across_records(self) -> None:
        records = (
            _record("filter-a", origins=[_origin("src-1")]),
            _record("filter-b", origins=[_origin("src-2")]),
        )
        merged = _merge_deduped(records, lambda r: r.origins)
        assert [o.source_candidate_id for o in merged] == ["src-1", "src-2"]

    def test_deduplicates_identical_items(self) -> None:
        records = (
            _record("filter-a", origins=[_origin("src-1")]),
            _record("filter-b", origins=[_origin("src-1")]),
        )
        merged = _merge_deduped(records, lambda r: r.origins)
        assert [o.source_candidate_id for o in merged] == ["src-1"]

    def test_merges_rejection_rationales(self) -> None:
        records = (
            _record("filter-a", rejections=[_rejection("r-1")]),
            _record("filter-b", rejections=[_rejection("r-2")]),
        )
        merged = _merge_deduped(records, lambda r: r.rejection_rationales)
        assert [r.candidate_id for r in merged] == ["r-1", "r-2"]

    def test_empty_input(self) -> None:
        assert _merge_deduped((), lambda r: r.origins) == []


class TestFirstFilterSummary:
    def test_empty_records_defaults_pins(self) -> None:
        assert _first_filter_summary(()) == {
            "pinned_entry_point": "",
            "pinned_technique_ids": [],
            "pinned_technique_names": [],
        }

    def test_summarizes_first_record(self) -> None:
        first = _record("filter-a", pinned_entry_point="user prompt")
        second = _record("filter-b", pinned_entry_point="other prompt")
        summary = _first_filter_summary((first, second))
        assert summary["pinned_entry_point"] == "user prompt"
        assert summary["pinned_technique_ids"] == ["AML.T0051"]


# ---------------------------------------------------------------------------
# Coverage universe helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Min-cost flow solver helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Round-robin exhaustive selection helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Coverage plan entry helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# emit_quality_gaps helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Deserialization / revalidation helpers
# ---------------------------------------------------------------------------


class TestDeserializationHelpers:
    def test_verify_outer_identity_rejects_each_field(self) -> None:
        pc = _pc()
        ref = {
            "candidate_id": "tampered",
            "pattern_id": pc.pattern_id,
            "entry_point_id": pc.canonical_ingress.entry_point_id,
        }
        with pytest.raises(ValueError, match="candidate_id"):
            _verify_outer_identity(ref, pc)
        ref = {
            "candidate_id": pc.candidate_id,
            "pattern_id": "AP-TAMPER-01",
            "entry_point_id": pc.canonical_ingress.entry_point_id,
        }
        with pytest.raises(ValueError, match="pattern_id"):
            _verify_outer_identity(ref, pc)
        ref = {
            "candidate_id": pc.candidate_id,
            "pattern_id": pc.pattern_id,
            "entry_point_id": "ep:v1:tampered",
        }
        with pytest.raises(ValueError, match="entry_point_id"):
            _verify_outer_identity(ref, pc)

    def test_verify_outer_identity_passes_when_agreeing(self) -> None:
        pc = _pc()
        _verify_outer_identity(
            {
                "candidate_id": pc.candidate_id,
                "pattern_id": pc.pattern_id,
                "entry_point_id": pc.canonical_ingress.entry_point_id,
            },
            pc,
        )

    def test_deserialize_filter_records_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="no accepted filter records"):
            _deserialize_filter_records([])

    def test_deserialize_filter_records_rejects_seedless_record(self) -> None:
        raw = _record("filter-a").to_dict()
        raw.pop("seed")
        with pytest.raises(ValueError, match="missing seed"):
            _deserialize_filter_records([raw])

    def test_deserialize_filter_records_rejects_summary_drift(self) -> None:
        raw = _record("filter-a").to_dict()
        raw["rationale"] = "tampered"
        with pytest.raises(ValueError, match="does not match"):
            _deserialize_filter_records([raw])

    def test_deserialize_filter_records_round_trips(self) -> None:
        records = _deserialize_filter_records([_record("filter-a").to_dict()])
        assert records[0].filter_candidate_id == "filter-a"

    def test_verify_canonical_filter_ids_rejects_duplicates(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            _verify_canonical_filter_ids([_record("a"), _record("a")])

    def test_verify_canonical_filter_ids_rejects_order(self) -> None:
        with pytest.raises(ValueError, match="canonical order"):
            _verify_canonical_filter_ids([_record("b"), _record("a")])

    def test_verify_canonical_filter_ids_passes(self) -> None:
        _verify_canonical_filter_ids([_record("a"), _record("b")])

    def test_verify_seed_ingress_agreement(self) -> None:
        pc = _pc()
        record = _record("filter-a")
        _verify_seed_ingress_agreement([record], pc)
        mismatched = AcceptedFilterRecord(
            filter_candidate_id="filter-b",
            rationale="",
            seed=_fseed(
                candidate_id="filter-b",
                entry_point_id="ep:v1:ffffffffffffffffffffffffffffffff",
            ),
        )
        with pytest.raises(ValueError, match="disagrees"):
            _verify_seed_ingress_agreement([mismatched], pc)


class TestRevalidationHelpers:
    def test_find_trusted_record(self) -> None:
        catalog = [{"id": "AP-1"}, {"id": "AP-2"}]
        assert _find_trusted_record(catalog, "AP-2") == {"id": "AP-2"}
        assert _find_trusted_record(catalog, "AP-9") is None

    def test_expected_authoritative_pin_supplied(self) -> None:
        assert _expected_authoritative_pin([], None, "pin-1") == "pin-1"

    def test_expected_authoritative_pin_computed(self) -> None:
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
        )

        catalog = [get_test_raw_pattern()]
        resolver = get_test_resolver()
        result = _expected_authoritative_pin(catalog, resolver, None)
        assert result is not None
        # Supplying the computed pin short-circuits recomputation.
        assert _expected_authoritative_pin(catalog, resolver, result) == result


# ---------------------------------------------------------------------------
# QualifiedCandidate / SelectionResult plumbing
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Uncovered-target derivation / gap-set normalization helpers
# ---------------------------------------------------------------------------


