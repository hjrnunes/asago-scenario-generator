"""Tests for the candidate filtering pipeline stage.

Covers:
  - Data model validation for CandidateTriple, FilterVerdict,
    BatchFilterResponse, and FilteredSeed.
  - expand_candidates() cross-product logic (skipped if not yet available).
  - Multi-technique combo expansion (max_techniques parameter).
  - Rule-based candidate pre-filter (classify_entry_point, individual rules,
    apply_rule_based_filter orchestration).
"""

from __future__ import annotations

import math
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    ToolInventoryEntry,
    compute_entry_point_id,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidates import (
    DIRECT_ONLY_TECHNIQUES,
    BatchFilterResponse,
    CandidateTriple,
    FilterProtocolError,
    FilteredSeed,
    FilterVerdict,
    _rule_direct_vs_indirect,
    _rule_entry_point_not_interactive,
    _rule_preparatory_technique,
    _rule_supply_chain_mismatch,
    _rule_technique_incompatible,
    _rule_technique_targets_wrong_layer,
    _rule_threat_requires_capability,
    _rule_threat_requires_zone,
    _rule_wrong_zone_direction,
    apply_rule_based_filter,
    cap_scenarios_per_pattern,
    classify_entry_point,
    compute_candidate_id,
    is_indirect_entry_point,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_seed(
    seed_id: str = "AP-T7-01",
    threat_id: str = "T7",
    atlas_technique_ids: list[str] | None = None,
    laaf_technique_ids: list[str] | None = None,
) -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        atlas_technique_ids=atlas_technique_ids or [],
        laaf_technique_ids=laaf_technique_ids or [],
    )


def _make_filtered_seed(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    technique_names: tuple[str, ...] | None = None,
    direction: str = "input",
    controllability: str | None = None,
) -> FilteredSeed:
    """Build a FilteredSeed with minimal boilerplate for capping tests."""
    if technique_names is None:
        technique_names = tuple(f"Technique {t}" for t in technique_ids)
    ep_id = compute_entry_point_id(entry_point, direction, controllability)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return FilteredSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        pinned_entry_point=entry_point,
        pinned_technique_ids=technique_ids,
        pinned_technique_names=technique_names,
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


def _make_profile(entry_points: list[str] | None = None) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points or ["user prompts (input)"],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------


class TestCandidateTriple:
    """CandidateTriple model validation."""

    def test_candidate_triple_creation(self):
        """CandidateTriple accepts all required fields with tuple technique fields."""
        ep_id = compute_entry_point_id("user prompts (input)", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        ct = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051",),
            atlas_technique_names=("LLM Prompt Injection",),
            atlas_technique_descriptions=(
                "Crafting inputs to manipulate LLM behavior",
            ),
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01", "LLM06"],
            direction="input",
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert ct.seed_id == "AP-T7-01"
        assert ct.threat_id == "T7"
        assert ct.threat_name == "Misaligned Behaviors"
        assert ct.attack_pattern_name == "Constraint bypass"
        assert ct.attack_pattern_description == "Agent bypasses constraints"
        assert ct.entry_point == "user prompts (input)"
        assert ct.atlas_technique_ids == ("AML.T0051",)
        assert ct.atlas_technique_names == ("LLM Prompt Injection",)
        assert ct.atlas_technique_descriptions == (
            "Crafting inputs to manipulate LLM behavior",
        )
        assert ct.risk_card_ref.risk_id == "risk-1"
        assert ct.owasp_llm_ids == ["LLM01", "LLM06"]
        assert ct.entry_point_id == ep_id
        assert ct.candidate_id == cand_id

    def test_candidate_triple_multi_technique(self):
        """CandidateTriple with multiple techniques in a combo."""
        ep_id = compute_entry_point_id("user prompts (input)", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0054"))
        ct = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051", "AML.T0054"),
            atlas_technique_names=("LLM Prompt Injection", "LLM Jailbreak"),
            atlas_technique_descriptions=("Crafting inputs", "Bypassing guardrails"),
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            direction="input",
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert len(ct.atlas_technique_ids) == 2
        assert ct.atlas_technique_ids == ("AML.T0051", "AML.T0054")


class TestFilterVerdict:
    """FilterVerdict model validation (wire protocol — opaque candidate IDs)."""

    def test_filter_verdict_accept(self):
        """FilterVerdict with verdict='accept' and a rationale."""
        v = FilterVerdict(
            candidate_id="cand:v2:abc123",
            verdict="accept",
            rationale="Entry point directly exposes the LLM to user-crafted input.",
        )
        assert v.verdict == "accept"
        assert (
            v.rationale == "Entry point directly exposes the LLM to user-crafted input."
        )
        assert v.candidate_id == "cand:v2:abc123"

    def test_filter_verdict_reject(self):
        """FilterVerdict with verdict='reject' and a rationale."""
        v = FilterVerdict(
            candidate_id="cand:v2:def456",
            verdict="reject",
            rationale="No plausible path from this entry point to the technique.",
        )
        assert v.verdict == "reject"
        assert v.candidate_id == "cand:v2:def456"

    def test_filter_verdict_invalid_verdict(self):
        """verdict must be 'accept' or 'reject', not 'maybe'."""
        with pytest.raises(ValidationError) as exc_info:
            FilterVerdict(
                candidate_id="cand:v2:abc123",
                verdict="maybe",
                rationale="Uncertain.",
            )
        # Pydantic should report the literal constraint violation
        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert any("verdict" in str(e.get("loc", "")) for e in errors)

    def test_filter_verdict_rejects_extra_fields(self):
        """FilterVerdict uses extra='forbid' — legacy metadata is rejected."""
        with pytest.raises(ValidationError):
            FilterVerdict(
                candidate_id="cand:v2:abc123",
                verdict="accept",
                rationale="Direct exposure.",
                entry_point="user prompts (input)",
                atlas_technique_ids=("AML.T0051",),
            )

    def test_filter_verdict_multi_technique(self):
        """FilterVerdict with a multi-technique combo (still just candidate_id)."""
        v = FilterVerdict(
            candidate_id="cand:v2:abc123",
            verdict="accept",
            rationale="Both techniques are plausible in combination.",
        )
        assert v.verdict == "accept"
        assert v.candidate_id == "cand:v2:abc123"


class TestBatchFilterResponse:
    """BatchFilterResponse model validation (wire protocol)."""

    def test_batch_filter_response(self):
        """BatchFilterResponse with seed_id and list of verdicts."""
        v1 = FilterVerdict(
            candidate_id="cand:v2:abc123",
            verdict="accept",
            rationale="Direct exposure.",
        )
        v2 = FilterVerdict(
            candidate_id="cand:v2:def456",
            verdict="reject",
            rationale="No path.",
        )
        resp = BatchFilterResponse(seed_id="AP-T7-01", verdicts=[v1, v2])
        assert resp.seed_id == "AP-T7-01"
        assert len(resp.verdicts) == 2
        assert resp.verdicts[0].verdict == "accept"
        assert resp.verdicts[1].verdict == "reject"

    def test_batch_filter_response_rejects_extra_fields(self):
        """BatchFilterResponse uses extra='forbid'."""
        with pytest.raises(ValidationError):
            BatchFilterResponse(
                seed_id="AP-T7-01",
                verdicts=[],
                entry_points=["user prompts"],
            )


class TestFilteredSeed:
    """FilteredSeed model validation."""

    def test_filtered_seed_inherits_scenario_seed(self):
        """FilteredSeed has all ScenarioSeed fields plus pinned fields."""
        ep_id = compute_entry_point_id("user prompts (input)", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("LLM Prompt Injection",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        # ScenarioSeed fields present
        assert fs.seed_id == "AP-T7-01"
        assert fs.threat_id == "T7"
        assert fs.threat_name == "Misaligned Behaviors"
        assert fs.attack_pattern_name == "Constraint bypass"
        assert fs.attack_pattern_description == "Agent bypasses constraints"
        assert fs.risk_card_ref.risk_id == "risk-1"
        assert fs.owasp_llm_ids == ["LLM01"]
        assert fs.agentic_threat_ids == ["T7"]
        # Pinned fields
        assert fs.pinned_entry_point == "user prompts (input)"
        assert fs.pinned_technique_ids == ("AML.T0051",)
        assert fs.pinned_technique_names == ("LLM Prompt Injection",)
        # Canonical IDs
        assert fs.entry_point_id == ep_id
        assert fs.candidate_id == cand_id
        # Inherits from ScenarioSeed
        assert isinstance(fs, ScenarioSeed)

    def test_filtered_seed_default_rejection_rationales(self):
        """Default rejection_rationales is an empty list."""
        ep_id = compute_entry_point_id("user prompts (input)", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("LLM Prompt Injection",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert fs.rejection_rationales == []
        assert isinstance(fs.rejection_rationales, list)

    def test_filtered_seed_multi_technique(self):
        """FilteredSeed with multiple pinned techniques."""
        ep_id = compute_entry_point_id("user prompts (input)", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0054"))
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051", "AML.T0054"),
            pinned_technique_names=("LLM Prompt Injection", "LLM Jailbreak"),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert len(fs.pinned_technique_ids) == 2
        assert len(fs.pinned_technique_names) == 2

    def test_filtered_seed_from_model_dump_propagates_all_fields(self):
        """FilteredSeed(**seed.model_dump(), ...) preserves every ScenarioSeed field.

        Regression test: the manual 14-field copy previously dropped
        owasp_asi_ids, min_complexity, and required_capabilities to defaults.
        """
        seed = ScenarioSeed(
            seed_id="AP-T9-01",
            threat_id="T9",
            threat_name="Identity Spoofing",
            threat_description="Agent impersonates another entity",
            attack_pattern_name="Credential replay",
            attack_pattern_description="Replays captured credentials",
            risk_card_ref=_make_ref(),
            contributing_risk_cards=[_make_ref(), _make_ref("risk-2")],
            owasp_llm_ids=["LLM02", "LLM07"],
            agentic_threat_ids=["T9"],
            atlas_technique_ids=["AML.T0051"],
            owasp_asi_ids=["ASI-01", "ASI-02"],
            owasp_origin="OWASP-T9",
            laaf_technique_ids=["LAAF.T001"],
            atlas_provenance_ids=["AML.T0051"],
            min_complexity="advanced",
            required_capabilities=["multi_agent", "persistent_memory"],
        )
        ep_id = compute_entry_point_id("admin API (input)", "input", None)
        cand_id = compute_candidate_id("AP-T9-01", ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            **seed.model_dump(),
            pinned_entry_point="admin API (input)",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("LLM Prompt Injection",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )

        # Previously-dropped fields (regression):
        assert fs.owasp_asi_ids == ["ASI-01", "ASI-02"]
        assert fs.min_complexity == "advanced"
        assert fs.required_capabilities == ["multi_agent", "persistent_memory"]

        # All other ScenarioSeed fields carried through:
        assert fs.seed_id == "AP-T9-01"
        assert fs.threat_id == "T9"
        assert fs.threat_name == "Identity Spoofing"
        assert fs.threat_description == "Agent impersonates another entity"
        assert fs.attack_pattern_name == "Credential replay"
        assert fs.attack_pattern_description == "Replays captured credentials"
        assert fs.risk_card_ref.risk_id == "risk-1"
        assert len(fs.contributing_risk_cards) == 2
        assert fs.owasp_llm_ids == ["LLM02", "LLM07"]
        assert fs.agentic_threat_ids == ["T9"]
        assert fs.atlas_technique_ids == ["AML.T0051"]
        assert fs.owasp_origin == "OWASP-T9"
        assert fs.laaf_technique_ids == ["LAAF.T001"]
        assert fs.atlas_provenance_ids == ["AML.T0051"]

        # FilteredSeed-specific fields:
        assert fs.pinned_entry_point == "admin API (input)"
        assert fs.pinned_technique_ids == ("AML.T0051",)
        assert fs.pinned_technique_names == ("LLM Prompt Injection",)

    def test_filtered_seed_model_dump_roundtrip_field_count(self):
        """FilteredSeed(**seed.model_dump()) never silently loses fields.

        If ScenarioSeed gains a new field, this test will catch it because
        the FilteredSeed dump will contain all parent fields plus pinned fields.
        """
        seed = _make_seed()
        ep_id = compute_entry_point_id("ep", "input", None)
        cand_id = compute_candidate_id(seed.seed_id, ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            **seed.model_dump(),
            pinned_entry_point="ep",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("Technique",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        seed_fields = set(ScenarioSeed.model_fields.keys())
        fs_fields = set(FilteredSeed.model_fields.keys())
        # Every ScenarioSeed field must exist in FilteredSeed
        assert seed_fields.issubset(fs_fields), (
            f"FilteredSeed is missing ScenarioSeed fields: {seed_fields - fs_fields}"
        )
        # The dump of the FilteredSeed must include every seed field
        fs_dump = fs.model_dump()
        for field_name in seed_fields:
            assert field_name in fs_dump, (
                f"FilteredSeed.model_dump() missing field: {field_name}"
            )


# ---------------------------------------------------------------------------
# Expansion tests (skip if expand_candidates not yet available)
# ---------------------------------------------------------------------------

_expand_candidates = (
    pytest.importorskip(
        "asago_scenario_generator.pipeline.candidates",
        reason="expand_candidates not yet available",
    ).expand_candidates
    if hasattr(
        __import__(
            "asago_scenario_generator.pipeline.candidates",
            fromlist=["expand_candidates"],
        ),
        "expand_candidates",
    )
    else None
)

_skip_expand = pytest.mark.skipif(
    _expand_candidates is None,
    reason="expand_candidates not yet available in asago_scenario_generator.pipeline.candidates",
)


@_skip_expand
class TestExpandCandidates:
    """expand_candidates() cross-product logic."""

    def test_expand_candidates_cross_product(self):
        """2 seeds x 2 entry points x 2 techniques = 8 candidates."""
        seeds = [
            _make_seed(
                "AP-T7-01", "T7", atlas_technique_ids=["AML.T0051", "AML.T0054"]
            ),
            _make_seed(
                "AP-T2-01", "T2", atlas_technique_ids=["AML.T0051", "AML.T0054"]
            ),
        ]
        profile = _make_profile(
            entry_points=["user prompts (input)", "API calls (tool_execution)"],
        )
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 8

    def test_expand_candidates_carries_full_context(self):
        """Each CandidateTriple has attack_pattern_name, description,
        technique name(s), technique description(s), and entry point text."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051"]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) >= 1
        c = candidates[0]
        # Full context carried (not empty / not just IDs)
        assert c.attack_pattern_name != ""
        assert c.attack_pattern_description != ""
        assert len(c.atlas_technique_names) >= 1
        assert c.atlas_technique_names[0] != ""
        assert len(c.atlas_technique_descriptions) >= 1
        assert c.entry_point != ""

    def test_expand_candidates_preserves_explicit_ingress_zone_identity(self):
        """Explicit ingress zones remain part of candidate entry-point identity."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                {
                    "name": "configuration loader",
                    "direction": "input",
                    "controllability": "indirect",
                    "ingress_zone": "reasoning",
                }
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )

        candidates = _expand_candidates(
            [_make_seed(atlas_technique_ids=["AML.T0051"])],
            profile,
        )

        assert len(candidates) == 1
        assert candidates[0].ingress_zone == "reasoning"
        assert candidates[0].entry_point_id == profile.entry_points[0].entry_point_id

    def test_expand_candidates_empty_techniques(self):
        """Seed with no technique IDs (ATLAS or LAAF) produces no candidates."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=[], laaf_technique_ids=[]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 0

    def test_expand_candidates_laaf_only_fallback(self):
        """Seed with LAAF IDs but no ATLAS IDs uses LAAF for cross-product."""
        seeds = [
            _make_seed(
                "AP-T7-01",
                "T7",
                atlas_technique_ids=[],
                laaf_technique_ids=["S1", "M3"],
            ),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # 1 seed x 1 entry_point x 2 LAAF techniques = 2 candidates
        assert len(candidates) == 2
        technique_ids = {c.atlas_technique_ids[0] for c in candidates}
        assert technique_ids == {"S1", "M3"}

    def test_expand_candidates_atlas_preferred_over_laaf(self):
        """When seed has both ATLAS and LAAF IDs, ATLAS is used."""
        seeds = [
            _make_seed(
                "AP-T2-01",
                "T2",
                atlas_technique_ids=["AML.T0051"],
                laaf_technique_ids=["S1", "M3"],
            ),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # Should use ATLAS (1 technique), not LAAF (2 techniques)
        assert len(candidates) == 1
        assert candidates[0].atlas_technique_ids == ("AML.T0051",)

    def test_expand_candidates_empty_entry_points(self):
        """Profile with no entry points returns empty list."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051"]),
        ]
        # CapabilityProfile requires min 1 entry point, so we test with
        # an empty-entry-points object if the function handles it,
        # otherwise we verify the cross-product produces nothing when
        # there are no entry points to iterate over.
        # Since CapabilityProfile validates min_length=1, we construct
        # a mock profile with empty entry_points.
        from unittest.mock import MagicMock

        profile = MagicMock(spec=CapabilityProfile)
        profile.entry_points = []
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 0

    def test_expand_candidates_max_techniques_1_default(self):
        """Default max_techniques=1 produces only single-technique candidates."""
        seeds = [
            _make_seed(
                "AP-T7-01",
                "T7",
                atlas_technique_ids=["AML.T0051", "AML.T0054", "AML.T0053"],
            ),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # 1 seed x 1 entry_point x C(3,1)=3 single combos = 3
        assert len(candidates) == 3
        # Each candidate should have exactly 1 technique
        for c in candidates:
            assert len(c.atlas_technique_ids) == 1

    def test_expand_candidates_max_techniques_2(self):
        """max_techniques=2 produces C(N,1)+C(N,2) candidates per seed x entry_point."""
        n_techniques = 4
        technique_ids = [f"AML.T00{i}" for i in range(n_techniques)]
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=technique_ids),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile, max_techniques=2)
        # Expected: C(4,1) + C(4,2) = 4 + 6 = 10
        expected = math.comb(n_techniques, 1) + math.comb(n_techniques, 2)
        assert len(candidates) == expected

        # Verify we have both single and pair combos
        singles = [c for c in candidates if len(c.atlas_technique_ids) == 1]
        pairs = [c for c in candidates if len(c.atlas_technique_ids) == 2]
        assert len(singles) == math.comb(n_techniques, 1)
        assert len(pairs) == math.comb(n_techniques, 2)

    def test_expand_candidates_max_techniques_3(self):
        """max_techniques=3 with 3 techniques produces C(3,1)+C(3,2)+C(3,3)=7."""
        n_techniques = 3
        technique_ids = ["AML.T0051", "AML.T0054", "AML.T0053"]
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=technique_ids),
        ]
        profile = _make_profile(entry_points=["ep1"])
        candidates = _expand_candidates(seeds, profile, max_techniques=3)
        # C(3,1) + C(3,2) + C(3,3) = 3 + 3 + 1 = 7
        expected = sum(math.comb(n_techniques, k) for k in range(1, 4))
        assert len(candidates) == expected

    def test_expand_candidates_max_techniques_2_multiple_seeds_and_entry_points(self):
        """Combinatorial count with 2 seeds x 2 entry points x max_techniques=2."""
        seeds = [
            _make_seed(
                "AP-T7-01", "T7", atlas_technique_ids=["AML.T0051", "AML.T0054"]
            ),
            _make_seed(
                "AP-T2-01", "T2", atlas_technique_ids=["AML.T0051", "AML.T0054"]
            ),
        ]
        profile = _make_profile(
            entry_points=["user prompts (input)", "API calls (tool_execution)"],
        )
        candidates = _expand_candidates(seeds, profile, max_techniques=2)
        # 2 seeds x 2 entry_points x (C(2,1) + C(2,2)) = 2 x 2 x 3 = 12
        combos_per_seed_ep = math.comb(2, 1) + math.comb(2, 2)  # 3
        assert len(candidates) == 2 * 2 * combos_per_seed_ep


# ---------------------------------------------------------------------------
# cap_scenarios_per_pattern greedy marginal coverage tests
# ---------------------------------------------------------------------------


class TestCapScenariosPerPattern:
    """Greedy marginal coverage capping logic."""

    # -- Core algorithm properties --

    def test_dual_technique_preferred_over_single(self):
        """A dual-technique candidate covers more new techniques and is selected first."""
        dual = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        single = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051",),
        )
        # Only 1 slot: the dual-technique candidate should win.
        result = cap_scenarios_per_pattern([single, dual], max_per_pattern=1)
        assert len(result) == 1
        assert result[0].pinned_technique_ids == ("AML.T0051", "AML.T0054")

    def test_entry_point_diversity_adds_score(self):
        """A new entry point contributes +1, so candidates with unseen entry points are preferred."""
        # Both cover the same technique, but ep2 is a new entry point.
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        c = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0051",))

        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=2)
        assert len(result) == 2
        entry_points = {fs.pinned_entry_point for fs in result}
        assert entry_points == {"ep1", "ep2"}

    def test_technique_coverage_then_entry_point_diversity(self):
        """After all techniques are covered, entry-point diversity drives selection."""
        # T0051 + T0054 covered by first pick (dual). Second pick should favor new EP.
        dual_ep1 = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        single_ep1 = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051",),
        )
        single_ep2 = _make_filtered_seed(
            entry_point="ep2",
            technique_ids=("AML.T0051",),
        )
        result = cap_scenarios_per_pattern(
            [dual_ep1, single_ep1, single_ep2],
            max_per_pattern=2,
        )
        assert len(result) == 2
        # First pick: dual on ep1 (marginal=3: 2 new techs + 1 new ep).
        assert result[0] is dual_ep1
        # Second pick: single_ep2 wins (marginal=1 for new ep) over single_ep1 (marginal=0).
        assert result[1] is single_ep2

    def test_cap_respected(self):
        """Never more than max_per_pattern returned per seed_id."""
        seeds = [
            _make_filtered_seed(entry_point=f"ep{i}", technique_ids=(f"AML.T{i:04d}",))
            for i in range(10)
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=3)
        assert len(result) == 3

    def test_no_capping_when_under_limit(self):
        """Groups at or below the limit pass through unchanged."""
        seeds = [
            _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",)),
            _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0054",)),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=5)
        assert len(result) == 2
        assert result == seeds

    # -- Edge cases --

    def test_empty_input(self):
        """Empty input produces empty output."""
        result = cap_scenarios_per_pattern([], max_per_pattern=3)
        assert result == []

    def test_single_candidate(self):
        """A single candidate passes through regardless of cap."""
        seed = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        result = cap_scenarios_per_pattern([seed], max_per_pattern=1)
        assert len(result) == 1
        assert result[0] is seed

    def test_all_same_entry_point(self):
        """When all candidates share the same entry point, technique diversity drives selection."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0054",))
        c = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))

        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=2)
        assert len(result) == 2
        # First pick: a (1 new tech + 1 new ep = 2). Second pick: b (1 new tech = 1).
        techs = {t for fs in result for t in fs.pinned_technique_ids}
        assert techs == {"AML.T0051", "AML.T0054"}

    def test_max_per_pattern_one(self):
        """max_per_pattern=1 selects the single best candidate."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(
            entry_point="ep2",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        result = cap_scenarios_per_pattern([a, b], max_per_pattern=1)
        assert len(result) == 1
        # b has marginal 3 (2 new techs + 1 new ep) vs a's marginal 2 (1 tech + 1 ep).
        assert result[0].pinned_technique_ids == ("AML.T0051", "AML.T0054")

    def test_invalid_max_per_pattern(self):
        """max_per_pattern < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_per_pattern must be >= 1"):
            cap_scenarios_per_pattern([], max_per_pattern=0)

    # -- Multi-group behaviour --

    def test_multiple_seed_ids_capped_independently(self):
        """Each seed_id group is capped independently."""
        group_a = [
            _make_filtered_seed(
                seed_id="AP-01", entry_point=f"ep{i}", technique_ids=("AML.T0051",)
            )
            for i in range(5)
        ]
        group_b = [
            _make_filtered_seed(
                seed_id="AP-02", entry_point=f"ep{i}", technique_ids=("AML.T0054",)
            )
            for i in range(5)
        ]
        result = cap_scenarios_per_pattern(group_a + group_b, max_per_pattern=2)
        ids = [fs.seed_id for fs in result]
        assert ids.count("AP-01") == 2
        assert ids.count("AP-02") == 2

    # -- Tie-breaking --

    def test_tiebreak_prefers_larger_combo(self):
        """When marginal coverage is equal, prefer the larger technique combo."""
        # First pick: 'first' wins with marginal=4 (3 new techs + 1 new ep).
        # After: covered={T1, T2, T3}, seen={ep1}.
        # Second pick:
        #   ta: ep2, (T4,)        -> 1 new tech + 1 new ep = 2, combo_size=1
        #   tb: ep3, (T1, T5)     -> 1 new tech (T5) + 1 new ep = 2, combo_size=2
        # Equal marginal=2 -> tiebreak by combo_size: tb wins.
        first = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0001", "AML.T0002", "AML.T0003"),
        )
        ta = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0004",))
        tb = _make_filtered_seed(
            entry_point="ep3",
            technique_ids=("AML.T0001", "AML.T0005"),
        )
        result = cap_scenarios_per_pattern([first, ta, tb], max_per_pattern=2)
        assert len(result) == 2
        assert result[0] is first
        assert result[1] is tb

    def test_tiebreak_encounter_order(self):
        """When marginal and combo size are equal, earlier encounter order wins."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0054",))
        c = _make_filtered_seed(entry_point="ep3", technique_ids=("AML.T0053",))
        # All have the same marginal on first pick (1 tech + 1 ep = 2) and combo_size=1.
        # Tiebreak by encounter order: a first.
        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=1)
        assert len(result) == 1
        assert result[0] is a

    # -- Greedy selection ordering --

    def test_greedy_technique_coverage_ordering(self):
        """The greedy algorithm picks candidates that maximise new technique coverage."""
        # 4 candidates, 3 techniques, cap=2.
        # dual covers T1+T2, single_t3 covers T3. Together they cover all 3.
        dual = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0001", "AML.T0002"),
        )
        single_t1 = _make_filtered_seed(
            entry_point="ep2",
            technique_ids=("AML.T0001",),
        )
        single_t2 = _make_filtered_seed(
            entry_point="ep3",
            technique_ids=("AML.T0002",),
        )
        single_t3 = _make_filtered_seed(
            entry_point="ep4",
            technique_ids=("AML.T0003",),
        )
        result = cap_scenarios_per_pattern(
            [single_t1, dual, single_t2, single_t3],
            max_per_pattern=2,
        )
        assert len(result) == 2
        # dual is picked first (covers 2 new techniques + 1 ep = 3).
        assert result[0] is dual
        # single_t3 is picked second (covers 1 new technique + 1 new ep = 2)
        # vs single_t1 (0 new tech + 1 new ep = 1) and single_t2 (0 + 1 = 1).
        assert result[1] is single_t3


# ---------------------------------------------------------------------------
# classify_entry_point / is_indirect_entry_point unit tests
# ---------------------------------------------------------------------------


class TestClassifyEntryPoint:
    """classify_entry_point() heuristic classification."""

    # -- Indirect cases --

    @pytest.mark.parametrize(
        "name",
        [
            "RAG knowledge-grounding",
            "rag knowledge base",
            "product knowledge retrieval",
            "third-party data feeds",
            "third party API feeds",
            "authenticated context injection",
            "external data feed ingestion",
            "context injection via plugins",
            "knowledge base retrieval",
            "document ingestion pipeline",
        ],
    )
    def test_indirect_input_entry_points(self, name: str):
        """Input-direction entry points with indirect keywords classify as indirect."""
        assert classify_entry_point(name, "input") == "indirect"

    # -- Direct cases --

    @pytest.mark.parametrize(
        "name",
        [
            "natural language user queries via app",
            "user prompts via chat widget",
            "customer message interface",
            "chat input",
        ],
    )
    def test_direct_input_entry_points(self, name: str):
        """Input-direction entry points with direct keywords classify as direct."""
        assert classify_entry_point(name, "input") == "direct"

    # -- System cases --

    @pytest.mark.parametrize(
        "name",
        [
            "backend API endpoint",
            "internal service bus",
            "system health monitor",
            "cron job trigger",
            "scheduler webhook",
        ],
    )
    def test_system_input_entry_points(self, name: str):
        """Input-direction entry points with system keywords classify as system."""
        assert classify_entry_point(name, "input") == "system"

    # -- Direction overrides --

    def test_bidirectional_always_direct(self):
        """Bidirectional entry points are always direct, even with indirect keywords."""
        assert (
            classify_entry_point("RAG knowledge-grounding", "bidirectional") == "direct"
        )

    def test_output_always_system(self):
        """Output entry points are always system."""
        assert classify_entry_point("RAG knowledge output", "output") == "system"
        assert classify_entry_point("user response channel", "output") == "system"

    def test_no_keyword_defaults_to_direct(self):
        """Input entry points with no recognised keyword default to direct."""
        assert classify_entry_point("unknown channel", "input") == "direct"

    def test_case_insensitive(self):
        """Keyword matching is case-insensitive."""
        assert classify_entry_point("RAG Knowledge-Grounding", "input") == "indirect"
        assert classify_entry_point("THIRD-PARTY DATA", "input") == "indirect"

    def test_indirect_wins_over_direct_keyword(self):
        """When both indirect and direct keywords present, indirect wins."""
        # "user" is direct, "knowledge" is indirect -- indirect takes priority.
        assert classify_entry_point("user knowledge retrieval", "input") == "indirect"


class TestClassifyEntryPointExplicitControllability:
    """classify_entry_point() with explicit controllability parameter."""

    def test_explicit_direct_bypasses_heuristic(self):
        """Explicit controllability='direct' is returned regardless of keywords."""
        assert (
            classify_entry_point("RAG knowledge-grounding", "input", "direct")
            == "direct"
        )

    def test_explicit_indirect_bypasses_heuristic(self):
        """Explicit controllability='indirect' is returned even for user-like name."""
        assert (
            classify_entry_point("user prompts via chat", "input", "indirect")
            == "indirect"
        )

    def test_explicit_system_preserved_for_non_output(self):
        """Explicit controllability='system' is preserved as 'system' even when
        direction is not 'output' — a reviewed profile declaring 'system' must
        remain system-controlled (cmps.9 review correction 5)."""
        assert (
            classify_entry_point("user prompts", "bidirectional", "system") == "system"
        )

    def test_explicit_system_preserved_for_output(self):
        """Explicit controllability='system' is preserved when direction is 'output'."""
        assert classify_entry_point("user prompts", "output", "system") == "system"

    def test_explicit_direct_overrides_output_direction(self):
        """Explicit controllability overrides even output direction."""
        assert classify_entry_point("some channel", "output", "direct") == "direct"

    def test_none_falls_back_to_heuristic(self):
        """controllability=None falls back to keyword heuristic."""
        assert (
            classify_entry_point("RAG knowledge-grounding", "input", None) == "indirect"
        )
        assert classify_entry_point("user prompts via chat", "input", None) == "direct"

    def test_default_falls_back_to_heuristic(self):
        """Omitting controllability (default None) falls back to keyword heuristic."""
        assert classify_entry_point("RAG knowledge-grounding", "input") == "indirect"


class TestIsIndirectEntryPoint:
    """is_indirect_entry_point() backward-compatible wrapper."""

    def test_indirect_input_entry_point(self):
        """Input-direction with indirect keyword returns True."""
        assert is_indirect_entry_point("RAG knowledge-grounding", "input") is True

    def test_direct_input_entry_point(self):
        """Input-direction with direct keyword returns False."""
        assert (
            is_indirect_entry_point("natural language user queries via app", "input")
            is False
        )

    def test_bidirectional_not_indirect(self):
        """Bidirectional entry points are never indirect."""
        assert (
            is_indirect_entry_point("RAG knowledge-grounding", "bidirectional") is False
        )

    def test_output_not_indirect(self):
        """Output entry points are not indirect."""
        assert is_indirect_entry_point("RAG knowledge output", "output") is False

    def test_explicit_indirect_controllability(self):
        """Explicit controllability='indirect' returns True."""
        assert is_indirect_entry_point("user prompts", "input", "indirect") is True

    def test_explicit_direct_controllability(self):
        """Explicit controllability='direct' returns False."""
        assert is_indirect_entry_point("RAG knowledge", "input", "direct") is False


# ---------------------------------------------------------------------------
# Rule function unit tests
# ---------------------------------------------------------------------------


def _make_directed_profile(
    entry_points: list[dict[str, str]],
) -> CapabilityProfile:
    """Build a profile with explicitly directed entry points.

    Each dict should have ``name`` and ``direction`` keys.
    """
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points,
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


_DUMMY_PROFILE = _make_directed_profile(
    [
        {"name": "user prompts", "direction": "input"},
    ]
)


class TestRuleSupplyChainMismatch:
    """_rule_supply_chain_mismatch rejects supply chain techniques on runtime EPs."""

    def test_t0048_on_direct_ep_rejected(self):
        reject, rationale = _rule_supply_chain_mismatch(
            "AML.T0048",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "supply chain" in rationale

    def test_t0010_on_indirect_ep_rejected(self):
        reject, _rationale = _rule_supply_chain_mismatch(
            "AML.T0010",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is True

    def test_t0048_on_system_ep_passes(self):
        reject, _ = _rule_supply_chain_mismatch(
            "AML.T0048",
            "internal API",
            "system",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_non_supply_chain_technique_passes(self):
        reject, _ = _rule_supply_chain_mismatch(
            "AML.T0051.000",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRuleEntryPointNotInteractive:
    """_rule_entry_point_not_interactive rejects techniques on system EPs."""

    def test_system_incompatible_technique_rejected(self):
        reject, rationale = _rule_entry_point_not_interactive(
            "AML.T0024",
            "internal API",
            "system",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "system-controlled" in rationale

    def test_system_compatible_technique_passes(self):
        # AML.T0029 has no "system" in incompatible_entry_types
        reject, _ = _rule_entry_point_not_interactive(
            "AML.T0029",
            "internal API",
            "system",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_non_system_ep_passes(self):
        reject, _ = _rule_entry_point_not_interactive(
            "AML.T0024",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRuleWrongZoneDirection:
    """_rule_wrong_zone_direction rejects techniques on output-direction EPs."""

    def test_output_ep_rejected(self):
        reject, rationale = _rule_wrong_zone_direction(
            "AML.T0051.000",
            "response output channel",
            "system",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "output-direction" in rationale

    def test_system_ep_without_output_signal_passes(self):
        reject, _ = _rule_wrong_zone_direction(
            "AML.T0051.000",
            "internal API",
            "system",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_non_system_ep_passes(self):
        reject, _ = _rule_wrong_zone_direction(
            "AML.T0051.000",
            "response output channel",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRuleTechniqueIncompatible:
    """_rule_technique_incompatible checks incompatible_entry_types."""

    def test_direct_incompatible_rejected(self):
        # AML.T0051.001 has "direct" in incompatible_entry_types
        reject, rationale = _rule_technique_incompatible(
            "AML.T0051.001",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "cannot target" in rationale

    def test_compatible_type_passes(self):
        reject, _ = _rule_technique_incompatible(
            "AML.T0051.001",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_unknown_technique_passes(self):
        reject, _ = _rule_technique_incompatible(
            "UNKNOWN.T9999",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRuleDirectVsIndirect:
    """_rule_direct_vs_indirect enforces direct/indirect access requirements."""

    def test_t0051000_on_indirect_rejected(self):
        reject, rationale = _rule_direct_vs_indirect(
            "AML.T0051.000",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "direct attacker access" in rationale

    def test_t0054_on_indirect_rejected(self):
        reject, _ = _rule_direct_vs_indirect(
            "AML.T0054",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is True

    def test_t0051001_on_direct_rejected(self):
        reject, rationale = _rule_direct_vs_indirect(
            "AML.T0051.001",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "non-user-facing" in rationale

    def test_t0051000_on_direct_passes(self):
        reject, _ = _rule_direct_vs_indirect(
            "AML.T0051.000",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_t0051001_on_indirect_passes(self):
        reject, _ = _rule_direct_vs_indirect(
            "AML.T0051.001",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRulePreparatoryTechnique:
    """_rule_preparatory_technique rejects pre-attack prep techniques."""

    def test_t0043_rejected(self):
        reject, rationale = _rule_preparatory_technique(
            "AML.T0043",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "preparatory" in rationale

    def test_t0016_rejected(self):
        reject, _ = _rule_preparatory_technique(
            "AML.T0016",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True

    def test_t0021_rejected(self):
        reject, _ = _rule_preparatory_technique(
            "AML.T0021",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True

    def test_non_preparatory_passes(self):
        reject, _ = _rule_preparatory_technique(
            "AML.T0051.000",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


class TestRuleTechniqueTargetsWrongLayer:
    """_rule_technique_targets_wrong_layer checks layer-EP compatibility."""

    def test_m4_on_direct_ep_rejected(self):
        reject, rationale = _rule_technique_targets_wrong_layer(
            "M4",
            "user prompts via chat",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "tool schema" in rationale

    def test_m4_on_indirect_ep_passes(self):
        reject, _ = _rule_technique_targets_wrong_layer(
            "M4",
            "RAG knowledge-grounding",
            "indirect",
            _DUMMY_PROFILE,
        )
        assert reject is False

    def test_training_technique_on_direct_rejected(self):
        reject, rationale = _rule_technique_targets_wrong_layer(
            "AML.T0020",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "training pipeline" in rationale

    def test_embedding_on_direct_rejected(self):
        reject, rationale = _rule_technique_targets_wrong_layer(
            "AML.T0025",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is True
        assert "embedding" in rationale

    def test_no_target_layer_passes(self):
        reject, _ = _rule_technique_targets_wrong_layer(
            "AML.T0029",
            "user prompts",
            "direct",
            _DUMMY_PROFILE,
        )
        assert reject is False


# ---------------------------------------------------------------------------
# DIRECT_ONLY_TECHNIQUES backward compatibility
# ---------------------------------------------------------------------------


class TestDirectOnlyTechniques:
    """DIRECT_ONLY_TECHNIQUES derived from TECHNIQUE_PROPERTIES."""

    def test_t0051000_in_set(self):
        assert "AML.T0051.000" in DIRECT_ONLY_TECHNIQUES

    def test_t0054_in_set(self):
        assert "AML.T0054" in DIRECT_ONLY_TECHNIQUES

    def test_m7_in_set(self):
        """M7 (Gradual Trust Escalation) requires direct access."""
        assert "M7" in DIRECT_ONLY_TECHNIQUES

    def test_t0051001_not_in_set(self):
        assert "AML.T0051.001" not in DIRECT_ONLY_TECHNIQUES

    def test_t0053_not_in_set(self):
        assert "AML.T0053" not in DIRECT_ONLY_TECHNIQUES


# ---------------------------------------------------------------------------
# apply_rule_based_filter orchestration tests
# ---------------------------------------------------------------------------


def _make_candidate(
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051.000",),
    technique_names: tuple[str, ...] | None = None,
    technique_descs: tuple[str, ...] | None = None,
    seed_id: str = "AP-T7-01",
    direction: str = "input",
    controllability: str | None = None,
) -> CandidateTriple:
    """Build a CandidateTriple for rule-filter tests."""
    if technique_names is None:
        technique_names = tuple(f"Technique {t}" for t in technique_ids)
    if technique_descs is None:
        technique_descs = tuple(f"Description {t}" for t in technique_ids)
    ep_id = compute_entry_point_id(entry_point, direction, controllability)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return CandidateTriple(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=technique_names,
        atlas_technique_descriptions=technique_descs,
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        direction=direction,
        controllability=controllability,
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


class TestApplyRuleBasedFilter:
    """apply_rule_based_filter orchestration."""

    # -- Core rejection behaviour (replaces old apply_technique_entry_point_filter tests) --

    def test_direct_only_on_indirect_ep_rejected(self):
        """Direct-only technique on indirect EP is rule-rejected."""
        profile = _make_directed_profile(
            [
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0051.000",),
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1
        assert len(verdicts) == 1
        assert "Rejected:" in verdicts[0].rationale

    def test_direct_only_combo_on_indirect_ep_rejected(self):
        """Combo of all direct-only techniques on indirect EP is rejected entirely."""
        profile = _make_directed_profile(
            [
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0051.000", "AML.T0054"),
        )
        passed, rejected, _verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1

    def test_mixed_combo_on_indirect_ep_pruned(self):
        """Combo with both direct-only and compatible techniques is pruned."""
        profile = _make_directed_profile(
            [
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0070", "AML.T0054"),
            technique_names=("RAG Poisoning", "LLM Jailbreak"),
            technique_descs=("RAG poisoning desc", "Jailbreak desc"),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0
        # Only the compatible technique survives.
        assert passed[0].atlas_technique_ids == ("AML.T0070",)
        assert passed[0].atlas_technique_names == ("RAG Poisoning",)

    def test_supply_chain_on_direct_ep_rejected(self):
        """Supply chain technique on direct user EP is rejected."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="user prompts via chat",
            technique_ids=("AML.T0048",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1

    def test_preparatory_technique_rejected(self):
        """Preparatory technique T0043 is rejected on any EP type."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="user prompts via chat",
            technique_ids=("AML.T0043",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1

    # -- Pass-through behaviour --

    def test_compatible_technique_on_direct_ep_passes(self):
        """Direct-only technique on direct EP passes through."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat widget", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="user prompts via chat widget",
            technique_ids=("AML.T0051.000",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_compatible_technique_on_bidirectional_ep_passes(self):
        """Techniques on bidirectional EP pass through."""
        profile = _make_directed_profile(
            [
                {"name": "interactive chat", "direction": "bidirectional"},
            ]
        )
        candidate = _make_candidate(
            entry_point="interactive chat",
            technique_ids=("AML.T0054",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_indirect_technique_on_indirect_ep_passes(self):
        """T0051.001 on indirect EP passes."""
        profile = _make_directed_profile(
            [
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0051.001",),
            technique_names=("Indirect Prompt Injection",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    # -- Edge cases --

    def test_empty_input(self):
        """Empty input produces empty output."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts", "direction": "input"},
            ]
        )
        passed, rejected, verdicts = apply_rule_based_filter([], profile)
        assert passed == []
        assert rejected == []
        assert verdicts == []

    def test_unknown_ep_defaults_to_direct(self):
        """An entry point not in the profile defaults to bidirectional -> direct."""
        profile = _make_directed_profile(
            [
                {"name": "known ep", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="unknown ep",
            technique_ids=("AML.T0054",),
        )
        passed, _rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1

    def test_multiple_candidates_mixed(self):
        """Multiple candidates: only structurally impossible ones are rejected."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via app", "direction": "input"},
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        direct_ok = _make_candidate(
            entry_point="user prompts via app",
            technique_ids=("AML.T0054",),
        )
        indirect_ok = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0051.001",),
        )
        indirect_bad = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0054",),
        )
        passed, rejected, _ = apply_rule_based_filter(
            [direct_ok, indirect_ok, indirect_bad],
            profile,
        )
        assert len(passed) == 2
        assert len(rejected) == 1

    def test_rejection_verdict_has_rationale(self):
        """Rejection verdicts carry a descriptive rationale string."""
        profile = _make_directed_profile(
            [
                {"name": "RAG knowledge-grounding", "direction": "input"},
            ]
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0051.000",),
        )
        _, _, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(verdicts) == 1
        assert "Rejected:" in verdicts[0].rationale
        assert "AML.T0051.000" in verdicts[0].rationale

    # -- Explicit controllability tests --

    def test_explicit_indirect_controllability_rejects_direct_technique(self):
        """Entry point with explicit controllability='indirect' rejects direct-only technique."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(
                    name="some generic channel",
                    direction="input",
                    controllability="indirect",
                ),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        candidate = _make_candidate(
            entry_point="some generic channel",
            technique_ids=("AML.T0051.000",),
            controllability="indirect",
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        # Without explicit controllability, "some generic channel" would default
        # to "direct" (no keywords match). With controllability="indirect",
        # direct-only T0051.000 should be rejected.
        assert len(passed) == 0
        assert len(rejected) == 1

    def test_explicit_direct_controllability_overrides_indirect_keyword(self):
        """Entry point with indirect keyword but controllability='direct' passes direct technique."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(
                    name="RAG knowledge interface",
                    direction="input",
                    controllability="direct",
                ),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge interface",
            technique_ids=("AML.T0054",),
            controllability="direct",
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        # Without explicit controllability, "RAG knowledge interface" would be
        # classified as "indirect" due to keyword match, and T0054 (direct-only)
        # would be rejected. With controllability="direct", it should pass.
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_no_controllability_falls_back_to_heuristic(self):
        """Entry point without controllability uses keyword heuristic as before."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="RAG knowledge interface", direction="input"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        candidate = _make_candidate(
            entry_point="RAG knowledge interface",
            technique_ids=("AML.T0054",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        # "RAG knowledge interface" matches "knowledge" -> indirect.
        # T0054 requires direct access -> rejected.
        assert len(passed) == 0
        assert len(rejected) == 1


# ---------------------------------------------------------------------------
# Threat prerequisite rule unit tests
# ---------------------------------------------------------------------------


def _make_zoned_profile(
    zones: list[str],
    has_persistent_memory: bool = False,
    multi_agent: bool = False,
    hitl: bool = False,
) -> CapabilityProfile:
    """Build a CapabilityProfile with specific zones and capability flags."""
    kc_codes = ["KC1.1"]
    if "tool_execution" in zones:
        kc_codes.append("KC6.1.1")
    if "memory" in zones or has_persistent_memory:
        kc_codes.append("KC4.3")
    if "inter_agent" in zones or multi_agent:
        kc_codes.append("KC2.3")
    if hitl:
        kc_codes.append("KCX-HITL")
    kw = {}
    if any(c.startswith(("KC5.", "KC6.")) for c in kc_codes):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=zones,
        entry_points=["user prompts (input)"],
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc_codes,
        **kw,
    )


class TestRuleThreatRequiresZone:
    """_rule_threat_requires_zone checks threat-level zone prerequisites."""

    # -- T1 Memory Poisoning: requires memory zone --

    def test_t1_without_memory_zone_rejected(self):
        """T1 (Memory Poisoning) requires memory zone; rejected without it."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T1", profile)
        assert reject is True
        assert "memory" in rationale

    def test_t1_with_memory_zone_passes(self):
        """T1 passes when memory zone is active."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "memory"],
            has_persistent_memory=True,
        )
        reject, _ = _rule_threat_requires_zone("T1", profile)
        assert reject is False

    # -- T2 Tool Misuse: requires tool_execution zone --

    def test_t2_without_tool_execution_rejected(self):
        """T2 (Tool Misuse) requires tool_execution zone."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T2", profile)
        assert reject is True
        assert "tool_execution" in rationale

    def test_t2_with_tool_execution_passes(self):
        """T2 passes when tool_execution zone is active."""
        profile = _make_zoned_profile(["input", "reasoning", "tool_execution"])
        reject, _ = _rule_threat_requires_zone("T2", profile)
        assert reject is False

    # -- T3 Privilege Compromise: requires tool_execution zone --

    def test_t3_without_tool_execution_rejected(self):
        """T3 (Privilege Compromise) requires tool_execution zone."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T3", profile)
        assert reject is True
        assert "tool_execution" in rationale

    # -- T5 Cascading Hallucination: requires any of memory/tool_execution/inter_agent --

    def test_t5_without_any_propagation_zone_rejected(self):
        """T5 requires at least one propagation zone; rejected without any."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T5", profile)
        assert reject is True
        assert "at least one of" in rationale

    def test_t5_with_memory_zone_passes(self):
        """T5 passes with memory zone (hallucinations persist across sessions)."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "memory"],
            has_persistent_memory=True,
        )
        reject, _ = _rule_threat_requires_zone("T5", profile)
        assert reject is False

    def test_t5_with_tool_execution_passes(self):
        """T5 passes with tool_execution (hallucinations cause real-world actions)."""
        profile = _make_zoned_profile(["input", "reasoning", "tool_execution"])
        reject, _ = _rule_threat_requires_zone("T5", profile)
        assert reject is False

    def test_t5_with_inter_agent_passes(self):
        """T5 passes with inter_agent (hallucinations spread to other agents)."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        reject, _ = _rule_threat_requires_zone("T5", profile)
        assert reject is False

    # -- T9 Identity Spoofing: requires any of tool_execution/inter_agent --

    def test_t9_without_tool_or_agent_rejected(self):
        """T9 requires at least tool_execution or inter_agent."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T9", profile)
        assert reject is True
        assert "at least one of" in rationale

    def test_t9_with_tool_execution_passes(self):
        """T9 passes with tool_execution (agent has actionable identity)."""
        profile = _make_zoned_profile(["input", "reasoning", "tool_execution"])
        reject, _ = _rule_threat_requires_zone("T9", profile)
        assert reject is False

    # -- T11 Unexpected RCE: requires tool_execution zone --

    def test_t11_without_tool_execution_rejected(self):
        """T11 (Unexpected RCE) requires tool_execution zone."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T11", profile)
        assert reject is True
        assert "tool_execution" in rationale

    # -- T12/T13/T14 Multi-agent threats: require inter_agent zone --

    @pytest.mark.parametrize("threat_id", ["T12", "T13", "T14"])
    def test_multi_agent_threats_without_inter_agent_rejected(self, threat_id: str):
        """T12/T13/T14 require inter_agent zone."""
        profile = _make_zoned_profile(["input", "reasoning", "tool_execution"])
        reject, rationale = _rule_threat_requires_zone(threat_id, profile)
        assert reject is True
        assert "inter_agent" in rationale

    @pytest.mark.parametrize("threat_id", ["T12", "T13", "T14"])
    def test_multi_agent_threats_with_inter_agent_passes(self, threat_id: str):
        """T12/T13/T14 pass with inter_agent zone."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        reject, _ = _rule_threat_requires_zone(threat_id, profile)
        assert reject is False

    # -- T16 Protocol Abuse: requires any of tool_execution/inter_agent --

    def test_t16_without_tool_or_agent_rejected(self):
        """T16 requires at least tool_execution or inter_agent."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_zone("T16", profile)
        assert reject is True
        assert "at least one of" in rationale

    def test_t16_with_inter_agent_passes(self):
        """T16 passes with inter_agent (A2A protocol surface)."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        reject, _ = _rule_threat_requires_zone("T16", profile)
        assert reject is False

    # -- Threats with no zone prerequisites pass unconditionally --

    @pytest.mark.parametrize("threat_id", ["T4", "T6", "T7", "T8", "T15", "T17"])
    def test_no_zone_prerequisite_threats_always_pass(self, threat_id: str):
        """Threats with no zone prerequisites pass with minimal profile."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, _ = _rule_threat_requires_zone(threat_id, profile)
        assert reject is False

    # -- Unknown threat ID passes (no prerequisite data) --

    def test_unknown_threat_id_passes(self):
        """Unknown threat IDs pass (no prerequisite data to check)."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, _ = _rule_threat_requires_zone("T99", profile)
        assert reject is False


class TestRuleThreatRequiresCapability:
    """_rule_threat_requires_capability checks threat-level capability prerequisites."""

    # -- T1 Memory Poisoning: requires has_persistent_memory --

    def test_t1_without_persistent_memory_rejected(self):
        """T1 requires has_persistent_memory; rejected without it."""
        # Test the capability check in isolation (zone check is separate)
        profile_no_mem = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_capability("T1", profile_no_mem)
        assert reject is True
        assert "has_persistent_memory" in rationale

    def test_t1_with_persistent_memory_passes(self):
        """T1 passes when has_persistent_memory is true."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "memory"],
            has_persistent_memory=True,
        )
        reject, _ = _rule_threat_requires_capability("T1", profile)
        assert reject is False

    # -- T10 Overwhelming HITL: requires hitl --

    def test_t10_without_hitl_rejected(self):
        """T10 requires hitl=true; rejected without it."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_capability("T10", profile)
        assert reject is True
        assert "hitl" in rationale

    def test_t10_with_hitl_passes(self):
        """T10 passes when hitl is true."""
        profile = _make_zoned_profile(
            ["input", "reasoning"],
            hitl=True,
        )
        reject, _ = _rule_threat_requires_capability("T10", profile)
        assert reject is False

    # -- T12/T13/T14 Multi-agent: requires multi_agent --

    @pytest.mark.parametrize("threat_id", ["T12", "T13", "T14"])
    def test_multi_agent_threats_without_multi_agent_rejected(self, threat_id: str):
        """T12/T13/T14 require multi_agent capability."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, rationale = _rule_threat_requires_capability(threat_id, profile)
        assert reject is True
        assert "multi_agent" in rationale

    @pytest.mark.parametrize("threat_id", ["T12", "T13", "T14"])
    def test_multi_agent_threats_with_multi_agent_passes(self, threat_id: str):
        """T12/T13/T14 pass with multi_agent capability."""
        profile = _make_zoned_profile(
            ["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        reject, _ = _rule_threat_requires_capability(threat_id, profile)
        assert reject is False

    # -- Threats with no capability prerequisites --

    @pytest.mark.parametrize(
        "threat_id",
        ["T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T11", "T15", "T16", "T17"],
    )
    def test_no_capability_prerequisite_threats_pass(self, threat_id: str):
        """Threats with no capability prerequisites pass with minimal profile."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, _ = _rule_threat_requires_capability(threat_id, profile)
        assert reject is False

    # -- Unknown threat ID passes --

    def test_unknown_threat_id_passes(self):
        """Unknown threat IDs pass."""
        profile = _make_zoned_profile(["input", "reasoning"])
        reject, _ = _rule_threat_requires_capability("T99", profile)
        assert reject is False


# ---------------------------------------------------------------------------
# Threat prerequisite integration with apply_rule_based_filter
# ---------------------------------------------------------------------------


def _make_threat_candidate(
    threat_id: str = "T7",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051.000",),
    seed_id: str = "AP-T7-01",
    direction: str = "input",
    controllability: str | None = None,
) -> CandidateTriple:
    """Build a CandidateTriple with a specific threat_id for prerequisite tests."""
    ep_id = compute_entry_point_id(entry_point, direction, controllability)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return CandidateTriple(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=tuple(f"Technique {t}" for t in technique_ids),
        atlas_technique_descriptions=tuple(f"Desc {t}" for t in technique_ids),
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        direction=direction,
        controllability=controllability,
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


class TestApplyRuleBasedFilterThreatPrereqs:
    """apply_rule_based_filter integration: threat prerequisite rules."""

    def test_t1_candidate_rejected_without_memory(self):
        """T1 candidate rejected when profile has no memory zone."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T1",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0051.000",),
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1
        assert "T1" in verdicts[0].rationale

    def test_t2_candidate_rejected_without_tool_execution(self):
        """T2 candidate rejected when profile has no tool_execution zone."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T2",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0053",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1

    def test_t2_candidate_passes_with_tool_execution(self):
        """T2 candidate passes when profile has tool_execution zone."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "user prompts via chat", "direction": "input"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[
                ToolInventoryEntry(name="test_tool", description="A test tool")
            ],
        )
        candidate = _make_threat_candidate(
            threat_id="T2",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0053",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_t10_candidate_rejected_without_hitl(self):
        """T10 candidate rejected when profile has hitl=false."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T10",
            entry_point="user prompts via chat",
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1
        assert "hitl" in verdicts[0].rationale

    def test_t10_candidate_passes_with_hitl(self):
        """T10 candidate passes when profile has hitl=true."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                {"name": "user prompts via chat", "direction": "input"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KCX-HITL"],
        )
        candidate = _make_threat_candidate(
            threat_id="T10",
            entry_point="user prompts via chat",
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_t12_candidate_rejected_without_multi_agent(self):
        """T12 candidate rejected without inter_agent zone and multi_agent flag."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T12",
            entry_point="user prompts via chat",
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1

    def test_t5_cascade_rejected_without_propagation_zone(self):
        """T5 candidate rejected when profile has only input+reasoning."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T5",
            entry_point="user prompts via chat",
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1
        assert "at least one of" in verdicts[0].rationale

    def test_t5_cascade_passes_with_tool_execution(self):
        """T5 candidate passes with tool_execution zone."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "user prompts via chat", "direction": "input"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[
                ToolInventoryEntry(name="test_tool", description="A test tool")
            ],
        )
        candidate = _make_threat_candidate(
            threat_id="T5",
            entry_point="user prompts via chat",
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_threat_prereq_rejects_before_technique_rules(self):
        """Threat-level rejection occurs before per-technique rules are checked."""
        # T1 requires memory zone. Even with a perfectly valid technique+EP combo,
        # the candidate should be rejected at the threat level.
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T1",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0051.000",),  # valid on direct EP
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 0
        assert len(rejected) == 1
        # Rationale should mention the threat-level check, not a technique-level one
        assert "T1" in verdicts[0].rationale
        assert "memory" in verdicts[0].rationale

    def test_no_prereq_threats_pass_normally(self):
        """Threats with no prerequisites (T6, T7, etc.) pass through to technique rules."""
        profile = _make_directed_profile(
            [
                {"name": "user prompts via chat", "direction": "input"},
            ]
        )
        candidate = _make_threat_candidate(
            threat_id="T7",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0051.000",),
        )
        passed, rejected, _ = apply_rule_based_filter([candidate], profile)
        # T7 has no zone/capability prereqs, and T0051.000 on direct EP is valid
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_mixed_threats_some_rejected_some_pass(self):
        """Multiple candidates with different threats: only impossible ones rejected."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "user prompts via chat", "direction": "input"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[
                ToolInventoryEntry(name="test_tool", description="A test tool")
            ],
        )
        t2_ok = _make_threat_candidate(
            threat_id="T2",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0053",),
            seed_id="AP-T2-01",
        )
        t12_bad = _make_threat_candidate(
            threat_id="T12",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0051.000",),
            seed_id="AP-T12-01",
        )
        t7_ok = _make_threat_candidate(
            threat_id="T7",
            entry_point="user prompts via chat",
            technique_ids=("AML.T0051.000",),
            seed_id="AP-T7-01",
        )
        passed, rejected, _ = apply_rule_based_filter(
            [t2_ok, t12_bad, t7_ok],
            profile,
        )
        assert len(passed) == 2
        assert len(rejected) == 1
        assert rejected[0].threat_id == "T12"


# ---------------------------------------------------------------------------
# Decomposition helper tests (CRAP <= 6)
# ---------------------------------------------------------------------------


class TestExpansionAndFilterHelpers:
    """Direct coverage for decomposed candidates.py helpers."""

    def test_capability_available_branches(self):
        from asago_scenario_generator.pipeline.candidates import (
            _capability_available,
        )

        profile = _make_profile()
        assert _capability_available("multi_agent", profile) is False
        multi = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user prompts (input)"],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KCX-MAGENT"],
        )
        assert _capability_available("multi_agent", multi) is True
        assert _capability_available("persistent_memory", profile) is False
        persistent = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user prompts (input)"],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KCX-PMEM"],
        )
        assert _capability_available("persistent_memory", persistent) is True
        assert _capability_available("tool_execution", profile) is False
        tooled = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=["user prompts (input)"],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC5.1"],
            tool_inventory=[
                ToolInventoryEntry(name="test_tool", description="A test tool")
            ],
        )
        assert _capability_available("tool_execution", tooled) is True
        # Unknown capabilities are treated as satisfied.
        assert _capability_available("hitl", profile) is True

    def test_capability_eligible_seeds_filters(self):
        from asago_scenario_generator.pipeline.candidates import (
            _capability_eligible_seeds,
        )

        base = _make_seed()
        needy = base.model_copy(
            update={"required_capabilities": ["multi_agent", "persistent_memory"]}
        )
        profile = _make_profile()
        assert _capability_eligible_seeds([base, needy], profile) == [base]
        capable = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user prompts (input)"],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KCX-MAGENT", "KCX-PMEM"],
        )
        assert _capability_eligible_seeds([base, needy], capable) == [base, needy]
        tool_only = base.model_copy(
            update={"required_capabilities": ["tool_execution"]}
        )
        tooled = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=["user prompts (input)"],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC5.1"],
            tool_inventory=[
                ToolInventoryEntry(name="test_tool", description="A test tool")
            ],
        )
        assert _capability_eligible_seeds([tool_only], tooled) == [tool_only]
        assert _capability_eligible_seeds([tool_only], profile) == []
        # Seeds without requirements always pass.
        assert _capability_eligible_seeds([base], profile) == [base]

    def test_filter_modes_mutually_exclusive(self):
        from asago_scenario_generator.pipeline.candidates import (
            filter_candidates,
        )

        client = MagicMock()
        client.complete.return_value = _llm_result_dummy()
        with pytest.raises(ValueError, match="mutually exclusive"):
            filter_candidates(
                [_make_seed()],
                [_make_seed()],
                client,
                "test",
                _make_profile(),
                quarantine_on_failure=True,
                advisory_on_failure=True,
            )

    def test_reconcile_batch_exception_branch(self):
        from asago_scenario_generator.pipeline.candidates import (
            _reconcile_batch,
        )

        class BrokenResponse:
            seed_id = "AP-T7-01"

            @property
            def verdicts(self):
                raise AttributeError("boom")

        ok, err = _reconcile_batch(BrokenResponse(), "AP-T7-01", {"c1"})
        assert ok is False
        assert "Reconciliation exception" in err

    def test_post_reconciliation_results_seed_not_found(self):
        from asago_scenario_generator.pipeline.candidates import (
            _post_reconciliation_results,
        )

        cand = _make_candidate()
        verdict = FilterVerdict(
            candidate_id=cand.candidate_id,
            verdict="accept",
            rationale="ok",
        )
        batch = BatchFilterResponse(seed_id="AP-T7-01", verdicts=[verdict])
        lookup = {cand.candidate_id: cand}
        results, n_acc, n_rej, logs, rejected = _post_reconciliation_results(
            batch, lookup, {}, "AP-T7-01", [cand], []
        )
        assert results == []
        assert n_acc == 0
        assert n_rej == 1
        assert rejected == []

    def test_filter_infrastructure_failure_is_recorded(self):
        """A non-protocol exception inside _filter_one_seed is escalated."""
        from asago_scenario_generator.pipeline.candidates import (
            filter_candidates,
        )

        cand = _make_candidate()
        forged = cand.model_copy(update={"entry_point_id": "forged"})
        client = MagicMock()
        client.complete.return_value = _llm_result_dummy()
        with pytest.raises(FilterProtocolError, match="Filter infrastructure failure"):
            filter_candidates([forged], [_make_seed()], client, "test", _make_profile())


def _llm_result_dummy():
    from asago_scenario_generator.llm.client import LLMResult

    return LLMResult(
        content=BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:00000000000000000000000000000000",
                    verdict="accept",
                    rationale="ok",
                )
            ],
        ),
        system_prompt="s",
        user_prompt="u",
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
    )
