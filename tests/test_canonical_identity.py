"""Focused tests for canonical candidate identity and strict filter protocol.

Covers the asago-scenario-generator-cmps.2 bead contract:
  - Stable/changing entry-point IDs.
  - Semantic duplicate dedup and ambiguous/colliding identity rejection.
  - Stable candidate ID with sorted unique technique IDs; changes on any
    identity component.
  - Reordered response accepted; wrong seed, unknown ID, duplicate ID,
    omitted ID, repeated accept/reject, empty response.
  - Metadata immutability / application authority.
  - Retry succeeds on second attempt; second failure raises with no output
    and two evidence entries.
  - Bounded set-based coverage.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.eval.diversity import entry_point_entropy
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    compute_entry_point_id,
    deduplicate_entry_points,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidates import (
    BatchFilterDraftV2,
    BatchFilterResponse,
    CandidateTriple,
    FilteredSeed,
    FilterDecisionDraftV2,
    FilterProtocolError,
    FilterVerdict,
    _reconcile_filter_response,
    apply_rule_based_filter,
    compute_candidate_id,
    filter_candidates,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed


def test_filter_wire_protocol_uses_exact_key_map_and_restores_canonical_id() -> None:
    candidate = _make_candidate()
    client = MagicMock()
    client.complete.side_effect = lambda **request: _make_llm_result(
        request["response_format"].model_validate(
            {
                "c0": {
                    "relevant": True,
                    "rationale": "The entry path supports the selected technique.",
                }
            }
        )
    )

    accepted, _, _ = filter_candidates(
        [candidate], [_make_seed()], client, "test", _make_profile()
    )

    request = client.complete.call_args.kwargs
    schema = request["response_format"].model_json_schema()
    assert schema["required"] == ["c0"]
    assert set(schema["properties"]) == {"c0"}
    assert schema["additionalProperties"] is False
    assert request["max_completion_tokens"] == 4096
    assert "`c0`" in request["user_prompt"]
    assert candidate.candidate_id not in request["user_prompt"]
    assert accepted[0].candidate_id == candidate.candidate_id


def test_filter_completion_cap_preserves_lower_operator_limit() -> None:
    candidate = _make_candidate()
    client = MagicMock(max_completion_tokens=2048)
    client.complete.return_value = _make_llm_result(
        BatchFilterDraftV2(
            decisions=(
                FilterDecisionDraftV2(
                    candidate="c0",
                    relevant=True,
                    rationale="The candidate is relevant.",
                ),
            )
        )
    )

    filter_candidates([candidate], [_make_seed()], client, "test", _make_profile())

    assert client.complete.call_args.kwargs["max_completion_tokens"] == 2048


def test_filter_protocol_failure_is_advisory_when_requested() -> None:
    candidates = [
        _make_candidate(),
        _make_candidate(entry_point="api requests", direction="input"),
    ]
    client = MagicMock()
    client.complete.side_effect = [RuntimeError("offline"), RuntimeError("offline")]

    accepted, logs, rejected = filter_candidates(
        candidates,
        [_make_seed()],
        client,
        "test",
        _make_profile(),
        advisory_on_failure=True,
    )

    assert {item.candidate_id for item in accepted} == {
        item.candidate_id for item in candidates
    }
    assert rejected == []
    assert logs[-1]["warning"] == "candidate_filter_unavailable"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_seed(seed_id: str = "AP-T7-01") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0051"],
    )


def _make_candidate(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    direction: str = "input",
    controllability: str | None = None,
    technique_names: tuple[str, ...] | None = None,
    technique_descs: tuple[str, ...] | None = None,
) -> CandidateTriple:
    ep_id = compute_entry_point_id(entry_point, direction, controllability)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    if technique_names is None:
        technique_names = tuple(f"Technique {t}" for t in technique_ids)
    if technique_descs is None:
        technique_descs = tuple(f"Desc {t}" for t in technique_ids)
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


def _make_profile(entry_points: list[EntryPoint] | None = None) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points
        or [EntryPoint(name="user prompts", direction="input")],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _make_llm_result(content, attempt_label: str = "test") -> MagicMock:
    """Build a mock LLMResult with the given parsed content."""
    result = MagicMock()
    result.content = content
    result.system_prompt = "sys"
    result.user_prompt = "user"
    result.prompt_tokens = 100
    result.completion_tokens = 50
    result.duration_ms = 500
    return result


# ---------------------------------------------------------------------------
# 1. Stable / changing entry-point IDs
# ---------------------------------------------------------------------------


class TestEntryPointIdStability:
    """Entry-point IDs are deterministic and change only when identity changes."""

    def test_same_name_direction_controllability_same_id(self):
        """Same canonical inputs produce the same entry_point_id."""
        id1 = compute_entry_point_id("User Prompts", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_different_direction_different_id(self):
        """Changing direction changes the ID."""
        id_input = compute_entry_point_id("user prompts", "input", None)
        id_output = compute_entry_point_id("user prompts", "output", None)
        assert id_input != id_output

    def test_different_controllability_different_id(self):
        """Changing explicit controllability changes the ID."""
        id_direct = compute_entry_point_id("user prompts", "input", "direct")
        id_indirect = compute_entry_point_id("user prompts", "input", "indirect")
        assert id_direct != id_indirect

    def test_different_name_different_id(self):
        """Different names produce different IDs (barring hash collision)."""
        id1 = compute_entry_point_id("user prompts", "input", None)
        id2 = compute_entry_point_id("RAG knowledge", "input", None)
        assert id1 != id2

    def test_case_and_whitespace_invariant(self):
        """Case and whitespace variations produce the same ID."""
        id1 = compute_entry_point_id("User   Prompts", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_trailing_punctuation_invariant(self):
        """Trailing punctuation is stripped for canonical comparison."""
        id1 = compute_entry_point_id("user prompts.", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_id_format(self):
        """ID follows the ep:v1:<32 hex> format (128-bit digest)."""
        eid = compute_entry_point_id("user prompts", "input", None)
        assert eid.startswith("ep:v1:")
        hex_part = eid.split(":")[2]
        assert len(hex_part) == 32
        int(hex_part, 16)  # valid hex

    def test_entry_point_model_has_entry_point_id(self):
        """EntryPoint model exposes entry_point_id as a computed field."""
        ep = EntryPoint(name="user prompts", direction="input")
        assert ep.entry_point_id.startswith("ep:v1:")

    def test_entry_point_id_in_model_dump(self):
        """entry_point_id appears in model_dump()."""
        ep = EntryPoint(name="user prompts", direction="input")
        d = ep.model_dump()
        assert "entry_point_id" in d
        assert d["entry_point_id"].startswith("ep:v1:")


# ---------------------------------------------------------------------------
# 2. Semantic duplicate dedup and ambiguous/colliding identity rejection
# ---------------------------------------------------------------------------


class TestEntryPointDedup:
    """deduplicate_entry_points dedupes semantic duplicates and rejects collisions."""

    def test_semantic_duplicates_deduped(self):
        """Entry points with same canonical name/direction/controllability are deduped."""
        eps = [
            EntryPoint(name="User Prompts", direction="input"),
            EntryPoint(name="user prompts", direction="input"),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 1

    def test_different_directions_not_deduped(self):
        """Entry points with different directions are NOT deduped."""
        eps = [
            EntryPoint(name="user prompts", direction="input"),
            EntryPoint(name="user prompts", direction="output"),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 2

    def test_different_controllability_not_deduped(self):
        """Entry points with different controllability are NOT deduped."""
        eps = [
            EntryPoint(
                name="some channel", direction="input", controllability="direct"
            ),
            EntryPoint(
                name="some channel", direction="input", controllability="indirect"
            ),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 2

    def test_first_encounter_order_preserved(self):
        """Dedup keeps the first-encountered entry point."""
        eps = [
            EntryPoint(name="User Prompts", direction="input"),
            EntryPoint(name="user prompts", direction="input"),
        ]
        result = deduplicate_entry_points(eps)
        assert result[0].name == "User Prompts"

    def test_collision_rejected(self):
        """Two entry points with same ID but different canonical names raise ValueError."""
        # This is hard to trigger naturally (requires a hash collision),
        # so we monkeypatch compute_entry_point_id to force a collision.
        with patch(
            "asago_scenario_generator.models.capability_profile.compute_entry_point_id",
            return_value="ep:v1:collision00",
        ):
            eps = [
                EntryPoint(name="entry A", direction="input"),
                EntryPoint(name="entry B", direction="input"),
            ]
            with pytest.raises(ValueError, match="Ambiguous entry point identity"):
                deduplicate_entry_points(eps)

    def test_profile_post_init_deduplicates(self):
        """CapabilityProfile model_validator deduplicates entry points."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="User Prompts", direction="input"),
                EntryPoint(name="user prompts", direction="input"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        assert len(profile.entry_points) == 1


# ---------------------------------------------------------------------------
# 3. Stable candidate ID with sorted unique technique IDs
# ---------------------------------------------------------------------------


class TestCandidateIdStability:
    """Candidate IDs are deterministic from (seed_id, entry_point_id, sorted unique technique IDs)."""

    def test_same_identity_same_id(self):
        """Same (seed_id, entry_point_id, technique_ids) produces same candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        assert id1 == id2

    def test_technique_order_invariant(self):
        """Technique order does not change the candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0054"))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0054", "AML.T0051"))
        assert id1 == id2

    def test_duplicate_techniques_collapsed(self):
        """Duplicate technique IDs are collapsed to unique set."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0051"))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        assert id1 == id2

    def test_different_seed_different_id(self):
        """Different seed_id produces different candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-02", ep_id, ("AML.T0051",))
        assert id1 != id2

    def test_different_entry_point_different_id(self):
        """Different entry_point_id produces different candidate_id."""
        id1 = compute_candidate_id("AP-T7-01", "ep:v1:aaa111", ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", "ep:v1:bbb222", ("AML.T0051",))
        assert id1 != id2

    def test_different_techniques_different_id(self):
        """Different technique set produces different candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0054",))
        assert id1 != id2

    def test_id_format(self):
        """ID follows the cand:v2:<32 hex> format (128-bit digest)."""
        cid = compute_candidate_id("AP-T7-01", "ep:v1:abc123", ("AML.T0051",))
        assert cid.startswith("cand:v2:")
        hex_part = cid.split(":")[2]
        assert len(hex_part) == 32
        int(hex_part, 16)  # valid hex


# ---------------------------------------------------------------------------
# 4. Reconciliation: reordered, wrong seed, unknown ID, duplicate ID,
#    omitted ID, repeated accept/reject, empty response
# ---------------------------------------------------------------------------


class TestReconciliation:
    """_reconcile_filter_response validates against the exact submitted ID set."""

    def _make_submitted_ids(self) -> set[str]:
        return {"cand:v2:aaa111", "cand:v2:bbb222", "cand:v2:ccc333"}

    def test_valid_response_accepted(self):
        """A correct response with all IDs passes reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is True
        assert err is None

    def test_reordered_response_accepted(self):
        """Response with verdicts in different order passes reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is True
        assert err is None

    def test_wrong_seed_rejected(self):
        """Response with wrong seed_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-99",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "seed_id" in err

    def test_unknown_id_rejected(self):
        """Response with an unknown candidate_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:zzz999", verdict="accept", rationale="unknown"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Unknown" in err

    def test_duplicate_id_rejected(self):
        """Response with duplicate candidate_ids fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="reject", rationale="dup"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Duplicate" in err

    def test_omitted_id_rejected(self):
        """Response missing a submitted candidate_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Missing" in err

    def test_repeated_accept_reject_is_duplicate(self):
        """Two verdicts for the same ID (one accept, one reject) is a duplicate."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:aaa111", verdict="reject", rationale="dup"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v2:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Duplicate" in err

    def test_empty_verdicts_rejected(self):
        """Empty verdicts list fails reconciliation (all IDs omitted)."""
        resp = BatchFilterResponse(seed_id="AP-T7-01", verdicts=[])
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Missing" in err


# ---------------------------------------------------------------------------
# 5. Metadata immutability / application authority
# ---------------------------------------------------------------------------


class TestMetadataImmutability:
    """The LLM is never authoritative for metadata — IDs are application-computed."""

    def test_candidate_triple_ids_are_application_computed(self):
        """CandidateTriple IDs are deterministic from application inputs, not LLM."""
        c = _make_candidate(entry_point="user prompts", technique_ids=("AML.T0051",))
        expected_ep_id = compute_entry_point_id("user prompts", "input", None)
        expected_cand_id = compute_candidate_id(
            "AP-T7-01", expected_ep_id, ("AML.T0051",)
        )
        assert c.entry_point_id == expected_ep_id
        assert c.candidate_id == expected_cand_id

    def test_filter_verdict_has_no_metadata_fields(self):
        """FilterVerdict (wire protocol) only has candidate_id, verdict, rationale."""
        fields = set(FilterVerdict.model_fields.keys())
        assert fields == {"candidate_id", "verdict", "rationale"}

    def test_filter_verdict_rejects_entry_point_field(self):
        """FilterVerdict with extra='forbid' rejects legacy entry_point field."""
        with pytest.raises(ValidationError):
            FilterVerdict(
                candidate_id="cand:v2:abc",
                verdict="accept",
                rationale="ok",
                entry_point="user prompts",
            )

    def test_filtered_seed_carries_canonical_ids(self):
        """FilteredSeed carries entry_point_id and candidate_id from the candidate."""
        ep_id = compute_entry_point_id("user prompts", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="T7",
            attack_pattern_name="P",
            attack_pattern_description="D",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("T1",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert fs.entry_point_id == ep_id
        assert fs.candidate_id == cand_id

    def test_rule_pruning_recomputes_candidate_id(self):
        """When rule-based filter prunes techniques, candidate_id is recomputed."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="RAG knowledge-grounding", direction="input"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        # AML.T0070 is compatible with indirect EP, AML.T0054 is not.
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0070", "AML.T0054"),
            technique_names=("RAG Poisoning", "LLM Jailbreak"),
            technique_descs=("RAG poisoning desc", "Jailbreak desc"),
        )
        original_cand_id = candidate.candidate_id
        passed, _, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        # Candidate ID should change because technique set changed.
        assert passed[0].candidate_id != original_cand_id
        # New candidate_id should match the recomputed value.
        expected_new_id = compute_candidate_id(
            candidate.seed_id,
            candidate.entry_point_id,
            ("AML.T0070",),
        )
        assert passed[0].candidate_id == expected_new_id


# ---------------------------------------------------------------------------
# 6. Retry / exhaustion behaviour
# ---------------------------------------------------------------------------


class TestFilterRetryExhaustion:
    """filter_candidates retries malformed batches exactly once, then fails."""

    def _make_two_candidates(self) -> list[CandidateTriple]:
        return [
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="user prompts",
                technique_ids=("AML.T0051",),
            ),
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="RAG knowledge",
                technique_ids=("AML.T0051.001",),
            ),
        ]

    def _make_valid_response(
        self, seed_id: str, candidates: list[CandidateTriple]
    ) -> BatchFilterResponse:
        return BatchFilterResponse(
            seed_id=seed_id,
            verdicts=[
                FilterVerdict(
                    candidate_id=c.candidate_id,
                    verdict="accept" if i == 0 else "reject",
                    rationale=f"verdict {i}",
                )
                for i, c in enumerate(candidates)
            ],
        )

    def test_retry_succeeds_on_second_attempt(self):
        """First attempt malformed, second attempt valid — filter succeeds."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        malformed_resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[],  # empty -> omitted IDs
        )

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(malformed_resp),
            _make_llm_result(valid_resp),
        ]

        results, logs, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        assert results[0].candidate_id == candidates[0].candidate_id
        assert len(logs) == 2  # two attempts logged

    def test_second_failure_raises_with_no_output(self):
        """Two malformed attempts raise FilterProtocolError with no partial output."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        malformed_resp = BatchFilterResponse(
            seed_id="WRONG",
            verdicts=[],
        )

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(malformed_resp),
            _make_llm_result(malformed_resp),
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)

        # Two call log entries (one per attempt).
        assert len(exc_info.value.call_log_entries) == 2

    def test_second_failure_quarantines_only_the_seed_when_requested(self):
        """Runner mode keeps an irreconcilable seed local and preserves evidence."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()
        unknown = "cand:v2:ffffffffffffffffffffffffffffffff"
        malformed = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id=unknown,
                    verdict="accept",
                    rationale="unknown",
                )
            ],
        )
        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(malformed),
            _make_llm_result(malformed),
        ]

        results, logs, rejected, quarantined = filter_candidates(
            candidates,
            seeds,
            client,
            "test",
            profile,
            quarantine_on_failure=True,
        )

        assert results == []
        assert rejected == []
        assert len(logs) == 2
        assert len(quarantined) == 1
        evidence = quarantined[0].reconciliation
        assert evidence.seed_id == "AP-T7-01"
        assert evidence.expected_ids == tuple(
            sorted(c.candidate_id for c in candidates)
        )
        assert evidence.received_ids == (unknown,)
        assert evidence.missing_ids == evidence.expected_ids
        assert evidence.unknown_ids == (unknown,)
        assert evidence.attempts == 2

    def test_duplicate_input_candidate_ids_raise(self):
        """Duplicate candidate IDs in submitted input raise FilterProtocolError."""
        # Create two candidates with the same candidate_id by using same inputs.
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        # Force same candidate_id (they should already be identical).
        assert c1.candidate_id == c2.candidate_id

        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()
        client = MagicMock()

        with pytest.raises(FilterProtocolError, match="Duplicate candidate IDs"):
            filter_candidates([c1, c2], seeds, client, "test", profile)

    def test_metadata_from_application_not_llm(self):
        """Accepted FilteredSeed metadata comes from CandidateTriple, not LLM response."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        results, _, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        # The accepted candidate's entry_point and technique_ids come from
        # the CandidateTriple, not from the LLM response.
        assert results[0].pinned_entry_point == candidates[0].entry_point
        assert results[0].pinned_technique_ids == candidates[0].atlas_technique_ids
        assert results[0].entry_point_id == candidates[0].entry_point_id
        assert results[0].candidate_id == candidates[0].candidate_id

    def test_rejection_records_carry_application_metadata(self):
        """RejectionRecord metadata is resolved from candidate lookup, not LLM."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        results, _, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        # The rejected candidate's metadata should be in rejection_rationales.
        assert len(results[0].rejection_rationales) == 1
        rr = results[0].rejection_rationales[0]
        assert rr.candidate_id == candidates[1].candidate_id
        assert rr.entry_point == candidates[1].entry_point
        assert rr.atlas_technique_ids == candidates[1].atlas_technique_ids

    def test_no_partial_output_on_protocol_failure(self):
        """When one seed fails protocol, no results are returned for any seed."""
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-02",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        seeds = [_make_seed("AP-T7-01"), _make_seed("AP-T7-02")]
        profile = _make_profile()

        valid_resp_1 = self._make_valid_response("AP-T7-01", [c1])
        malformed_resp = BatchFilterResponse(seed_id="WRONG", verdicts=[])

        client = MagicMock()
        # Seed 1 succeeds, seed 2 fails twice.
        client.complete.side_effect = [
            _make_llm_result(valid_resp_1),  # seed 1 attempt 1 (success)
            _make_llm_result(malformed_resp),  # seed 2 attempt 1 (fail)
            _make_llm_result(malformed_resp),  # seed 2 attempt 2 (fail)
        ]

        with pytest.raises(FilterProtocolError):
            filter_candidates([c1, c2], seeds, client, "test", profile)


# ---------------------------------------------------------------------------
# 7. Bounded set-based coverage
# ---------------------------------------------------------------------------


class TestBoundedCoverage:
    """Coverage is set-based and bounded in [0, 1]."""

    def test_coverage_bounded_at_1(self):
        """Coverage is clamped to 1.0 when actual exceeds expected."""
        scenarios = [
            {
                "narrative": {"entry_point": "ep1"},
                "candidate_filter": {"entry_point_id": "ep:v1:a"},
            },
            {
                "narrative": {"entry_point": "ep2"},
                "candidate_filter": {"entry_point_id": "ep:v1:b"},
            },
            {
                "narrative": {"entry_point": "ep3"},
                "candidate_filter": {"entry_point_id": "ep:v1:c"},
            },
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=2)
        assert result["entry_point_coverage"] == 1.0
        assert 0.0 <= result["entry_point_coverage"] <= 1.0

    def test_coverage_zero_when_no_entry_points(self):
        """Coverage is 0.0 when no scenarios have entry points."""
        scenarios = [{"narrative": {}, "candidate_filter": {}}]
        result = entry_point_entropy(scenarios, expected_entry_points=5)
        assert result["entry_point_coverage"] == 0.0

    def test_coverage_fractional(self):
        """Coverage is a proper fraction in [0, 1]."""
        scenarios = [
            {"narrative": {}, "candidate_filter": {"entry_point_id": "ep:v1:a"}},
            {"narrative": {}, "candidate_filter": {"entry_point_id": "ep:v1:b"}},
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=4)
        assert result["entry_point_coverage"] == 0.5

    def test_coverage_uses_canonical_ids(self):
        """Coverage counts unique canonical entry_point_ids, not display text."""
        scenarios = [
            {
                "narrative": {"entry_point": "User Prompts"},
                "candidate_filter": {"entry_point_id": "ep:v1:same"},
            },
            {
                "narrative": {"entry_point": "user prompts"},
                "candidate_filter": {"entry_point_id": "ep:v1:same"},
            },
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=5)
        # Only 1 unique entry_point_id despite 2 scenarios.
        assert result["entry_point_coverage"] == round(1 / 5, 4)


# ---------------------------------------------------------------------------
# 8. Retry / infrastructure: exceptions, parsed None, concurrent evidence
# ---------------------------------------------------------------------------


class TestFilterRetryInfrastructure:
    """Exceptions and parsed None inside the two-attempt loop are handled."""

    def _make_two_candidates(self) -> list[CandidateTriple]:
        return [
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="user prompts",
                technique_ids=("AML.T0051",),
            ),
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="RAG knowledge",
                technique_ids=("AML.T0051.001",),
            ),
        ]

    def _make_valid_response(
        self, seed_id: str, candidates: list[CandidateTriple]
    ) -> BatchFilterResponse:
        return BatchFilterResponse(
            seed_id=seed_id,
            verdicts=[
                FilterVerdict(
                    candidate_id=c.candidate_id,
                    verdict="accept" if i == 0 else "reject",
                    rationale=f"verdict {i}",
                )
                for i, c in enumerate(candidates)
            ],
        )

    def test_exception_then_success(self):
        """Exception on attempt 1, valid response on attempt 2 — filter succeeds."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.side_effect = [
            RuntimeError("network error"),
            _make_llm_result(valid_resp),
        ]

        results, logs, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        assert len(logs) == 2  # two attempts logged
        # First log should be a synthetic error entry.
        assert logs[0]["error"] is not None
        assert "network error" in logs[0]["error"]
        # Second log should be a normal entry with a response.
        assert logs[1]["response"] is not None

    def test_exception_twice_raises(self):
        """Two exceptions raise FilterProtocolError with two evidence entries."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        client = MagicMock()
        client.complete.side_effect = [
            RuntimeError("error 1"),
            RuntimeError("error 2"),
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)
        assert len(exc_info.value.call_log_entries) == 2
        assert "error 1" in exc_info.value.call_log_entries[0]["error"]
        assert "error 2" in exc_info.value.call_log_entries[1]["error"]

    def test_parsed_none_retries_then_raises(self):
        """Parsed None on both attempts raises FilterProtocolError."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(None),
            _make_llm_result(None),
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)
        assert len(exc_info.value.call_log_entries) == 2

    def test_parsed_none_then_success(self):
        """Parsed None on attempt 1, valid response on attempt 2 — succeeds."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(None),
            _make_llm_result(valid_resp),
        ]

        results, logs, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        assert len(logs) == 2

    def test_concurrent_successful_seed_evidence_aggregated(self):
        """When one seed exhausts retries, successful seed logs are included."""
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-02",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        seeds = [_make_seed("AP-T7-01"), _make_seed("AP-T7-02")]
        profile = _make_profile()

        valid_resp_1 = self._make_valid_response("AP-T7-01", [c1])
        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(valid_resp_1),  # seed 1 succeeds
            RuntimeError("error"),  # seed 2 attempt 1
            RuntimeError("error"),  # seed 2 attempt 2
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates([c1, c2], seeds, client, "test", profile)
        # All call logs (from successful seed 1 + failed seed 2) should
        # be aggregated in the raised error.
        all_logs = exc_info.value.call_log_entries
        # At least 3 entries: 1 from seed 1, 2 from seed 2.
        assert len(all_logs) >= 3


# ---------------------------------------------------------------------------
# 9. Coverage: exact canonical set arithmetic with profile
# ---------------------------------------------------------------------------


class TestCanonicalCoverage:
    """Coverage uses exact canonical set arithmetic from the profile."""

    def _make_profile_with_eps(self) -> CapabilityProfile:
        return CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="user prompts", direction="input"),
                EntryPoint(name="RAG knowledge", direction="input"),
                EntryPoint(name="admin console", direction="output"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )

    def test_mixed_canonical_and_fallback_covers_both(self):
        """Canonical candidate + fallback narrative covers both expected IDs."""
        profile = self._make_profile_with_eps()
        ep_id_1 = compute_entry_point_id("user prompts", "input", None)
        scenarios = [
            {
                "narrative": {"entry_point": "user prompts"},
                "candidate_filter": {"entry_point_id": ep_id_1},
            },
            {
                "narrative": {"entry_point": "RAG knowledge"},
                "candidate_filter": {},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=2, profile=profile
        )
        # Both ingress EPs covered (output EP excluded).
        assert result["entry_point_coverage"] == 1.0

    def test_unknown_id_does_not_inflate_coverage(self):
        """An unknown provenance ID must not inflate the numerator."""
        profile = self._make_profile_with_eps()
        scenarios = [
            {
                "narrative": {"entry_point": "unknown ep"},
                "candidate_filter": {"entry_point_id": "ep:v1:unknown"},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=2, profile=profile
        )
        # 0 covered out of 2 expected ingress EPs.
        assert result["entry_point_coverage"] == 0.0

    def test_duplicate_representation_counts_once(self):
        """Canonical ID + fallback display of same EP counts once."""
        profile = self._make_profile_with_eps()
        ep_id_1 = compute_entry_point_id("user prompts", "input", None)
        scenarios = [
            {
                "narrative": {"entry_point": "user prompts"},
                "candidate_filter": {"entry_point_id": ep_id_1},
            },
            {
                "narrative": {"entry_point": "User Prompts"},
                "candidate_filter": {},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=2, profile=profile
        )
        # Only 1 unique EP covered out of 2.
        assert result["entry_point_coverage"] == 0.5

    def test_exact_numerator_denominator(self):
        """Coverage is exactly len(used & expected) / len(expected)."""
        profile = self._make_profile_with_eps()
        ep_id_1 = compute_entry_point_id("user prompts", "input", None)
        scenarios = [
            {
                "narrative": {"entry_point": "user prompts"},
                "candidate_filter": {"entry_point_id": ep_id_1},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=2, profile=profile
        )
        # 1 out of 2 ingress EPs.
        assert result["entry_point_coverage"] == round(1 / 2, 4)

    def test_ambiguous_same_name_not_arbitrarily_resolved(self):
        """Two same-name EPs with different direction: fallback covers both."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="shared channel", direction="input"),
                EntryPoint(name="shared channel", direction="bidirectional"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        # Fallback narrative with ambiguous name must NOT credit any ID.
        # Ambiguous same-name fallback is unresolved — coverage stays 0.
        scenarios = [
            {
                "narrative": {"entry_point": "shared channel"},
                "candidate_filter": {},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=2, profile=profile
        )
        # Ambiguous name unresolved — neither ID credited.
        assert result["entry_point_coverage"] == 0.0
        assert result["covered_entry_point_count"] == 0
        assert result["expected_entry_point_count"] == 2


# ---------------------------------------------------------------------------
# 10. Join behaviour: same-name different-identity EPs remain distinct
# ---------------------------------------------------------------------------


class TestSameNameDifferentIdentity:
    """Same display name with different direction/controllability stays distinct."""

    def test_same_name_different_direction_different_id(self):
        """EPs with same name but different direction have different IDs."""
        id_input = compute_entry_point_id("shared channel", "input", None)
        id_output = compute_entry_point_id("shared channel", "output", None)
        assert id_input != id_output

    def test_same_name_different_controllability_different_id(self):
        """EPs with same name but different controllability have different IDs."""
        id_direct = compute_entry_point_id("shared channel", "input", "direct")
        id_indirect = compute_entry_point_id("shared channel", "input", "indirect")
        assert id_direct != id_indirect

    def test_dedup_keeps_same_name_different_direction(self):
        """Dedup keeps both same-name EPs with different directions."""
        eps = [
            EntryPoint(name="shared channel", direction="input"),
            EntryPoint(name="shared channel", direction="output"),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 2

    def test_rule_filter_uses_candidate_own_metadata(self):
        """Rule filter uses each candidate's own direction/controllability."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="shared channel", direction="input"),
            ]
        )
        # Two candidates with same name but different controllability.
        c_direct = _make_candidate(
            entry_point="shared channel",
            technique_ids=("AML.T0051.000",),
            direction="input",
            controllability="direct",
        )
        c_indirect = _make_candidate(
            entry_point="shared channel",
            technique_ids=("AML.T0051.000",),
            direction="input",
            controllability="indirect",
        )
        # They should have different entry_point_ids.
        assert c_direct.entry_point_id != c_indirect.entry_point_id

        passed, rejected, _ = apply_rule_based_filter([c_direct, c_indirect], profile)
        # T0051.000 is direct-only; direct candidate passes, indirect rejected.
        assert len(passed) == 1
        assert len(rejected) == 1
        # The passed candidate should be the direct one.
        assert passed[0].entry_point_id == c_direct.entry_point_id


# ---------------------------------------------------------------------------
# 11. Immutability / ID validation
# ---------------------------------------------------------------------------


class TestImmutabilityAndIdValidation:
    """Frozen models and canonical ID validation."""

    def test_entry_point_frozen(self):
        """EntryPoint is frozen — assignment raises."""
        ep = EntryPoint(name="test", direction="input")
        with pytest.raises(ValidationError):
            ep.name = "changed"  # type: ignore[misc]

    def test_candidate_triple_frozen(self):
        """CandidateTriple is frozen — assignment raises."""
        c = _make_candidate()
        with pytest.raises(ValidationError):
            c.entry_point = "changed"  # type: ignore[misc]

    def test_inconsistent_entry_point_id_rejected(self):
        """Supplied entry_point_id that doesn't match recomputation is rejected."""
        wrong_ep_id = compute_entry_point_id("other ep", "input", None)
        with pytest.raises(ValidationError, match="entry_point_id"):
            CandidateTriple(
                seed_id="AP-T7-01",
                threat_id="T7",
                threat_name="T7",
                attack_pattern_name="P",
                attack_pattern_description="D",
                entry_point="user prompts",
                atlas_technique_ids=("AML.T0051",),
                atlas_technique_names=("T1",),
                atlas_technique_descriptions=("D1",),
                risk_card_ref=_make_ref(),
                owasp_llm_ids=["LLM01"],
                direction="input",
                entry_point_id=wrong_ep_id,
                candidate_id=compute_candidate_id(
                    "AP-T7-01", wrong_ep_id, ("AML.T0051",)
                ),
            )

    def test_inconsistent_candidate_id_rejected(self):
        """Supplied candidate_id that doesn't match recomputation is rejected."""
        ep_id = compute_entry_point_id("user prompts", "input", None)
        wrong_cand_id = "cand:v2:00000000000000000000000000000000"
        with pytest.raises(ValidationError, match="candidate_id"):
            CandidateTriple(
                seed_id="AP-T7-01",
                threat_id="T7",
                threat_name="T7",
                attack_pattern_name="P",
                attack_pattern_description="D",
                entry_point="user prompts",
                atlas_technique_ids=("AML.T0051",),
                atlas_technique_names=("T1",),
                atlas_technique_descriptions=("D1",),
                risk_card_ref=_make_ref(),
                owasp_llm_ids=["LLM01"],
                direction="input",
                entry_point_id=ep_id,
                candidate_id=wrong_cand_id,
            )

    def test_mutation_during_submission_cannot_alter_result(self):
        """Frozen models prevent mutation during submission."""
        candidates = [
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="user prompts",
                technique_ids=("AML.T0051",),
            ),
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="RAG knowledge",
                technique_ids=("AML.T0051.001",),
            ),
        ]
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id=c.candidate_id,
                    verdict="accept" if i == 0 else "reject",
                    rationale="ok",
                )
                for i, c in enumerate(candidates)
            ],
        )
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        results, _, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        # Result metadata comes from the frozen candidate, not from any
        # mutable copy.
        assert results[0].pinned_entry_point == candidates[0].entry_point
        assert results[0].entry_point_id == candidates[0].entry_point_id


# ---------------------------------------------------------------------------
# 12. Collisions / digest width
# ---------------------------------------------------------------------------


class TestCollisionsAndDigest:
    """128-bit digests and forced collision detection."""

    def test_entry_point_id_is_32_hex_chars(self):
        """Entry-point ID has 32 hex characters (128 bits)."""
        eid = compute_entry_point_id("user prompts", "input", None)
        hex_part = eid.split(":")[2]
        assert len(hex_part) == 32
        int(hex_part, 16)

    def test_candidate_id_is_32_hex_chars(self):
        """Candidate ID has 32 hex characters (128 bits)."""
        ep_id = compute_entry_point_id("user prompts", "input", None)
        cid = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        hex_part = cid.split(":")[2]
        assert len(hex_part) == 32
        int(hex_part, 16)

    def test_forced_ep_collision_same_name_different_direction_raises(self):
        """Forced collision: same name, different direction must raise."""
        with patch(
            "asago_scenario_generator.models.capability_profile.compute_entry_point_id",
            return_value="ep:v1:collision0000000000000000000000",
        ):
            eps = [
                EntryPoint(name="shared channel", direction="input"),
                EntryPoint(name="shared channel", direction="output"),
            ]
            with pytest.raises(ValueError, match="Ambiguous entry point identity"):
                deduplicate_entry_points(eps)

    def test_forced_ep_collision_same_name_different_controllability_raises(self):
        """Forced collision: same name, different controllability must raise."""
        with patch(
            "asago_scenario_generator.models.capability_profile.compute_entry_point_id",
            return_value="ep:v1:collision0000000000000000000000",
        ):
            eps = [
                EntryPoint(
                    name="shared channel", direction="input", controllability="direct"
                ),
                EntryPoint(
                    name="shared channel",
                    direction="input",
                    controllability="indirect",
                ),
            ]
            with pytest.raises(ValueError, match="Ambiguous entry point identity"):
                deduplicate_entry_points(eps)

    def test_candidate_collision_raises(self):
        """Forced candidate collision at population boundary raises."""
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-02",
            entry_point="RAG knowledge",
            technique_ids=("AML.T0054",),
        )
        # Force same candidate_id but different identity inputs.
        c2_forged = c2.model_copy(update={"candidate_id": c1.candidate_id})
        with pytest.raises(ValueError, match="Candidate collision"):
            from asago_scenario_generator.pipeline.candidates import (
                _check_candidate_collisions,
            )

            _check_candidate_collisions([c1, c2_forged])


# ---------------------------------------------------------------------------
# 13. Wrong content type retry and evidence
# ---------------------------------------------------------------------------


class TestWrongContentTypeRetry:
    """Malformed non-model content bypasses retry and evidence path."""

    def _make_two_candidates(self) -> list[CandidateTriple]:
        return [
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="user prompts",
                technique_ids=("AML.T0051",),
            ),
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="RAG knowledge",
                technique_ids=("AML.T0051.001",),
            ),
        ]

    def _make_valid_response(
        self, seed_id: str, candidates: list[CandidateTriple]
    ) -> BatchFilterResponse:
        return BatchFilterResponse(
            seed_id=seed_id,
            verdicts=[
                FilterVerdict(
                    candidate_id=c.candidate_id,
                    verdict="accept" if i == 0 else "reject",
                    rationale=f"verdict {i}",
                )
                for i, c in enumerate(candidates)
            ],
        )

    def test_wrong_content_type_then_success(self):
        """Wrong content type on attempt 1, valid on attempt 2 — succeeds."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result("this is not a BatchFilterResponse"),
            _make_llm_result(valid_resp),
        ]

        results, logs, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        assert len(logs) == 2  # two attempts logged

    def test_wrong_content_type_twice_raises(self):
        """Wrong content type on both attempts raises FilterProtocolError."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result({"bad": "shape"}),
            _make_llm_result("not valid"),
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)
        assert len(exc_info.value.call_log_entries) == 2

    def test_unexpected_post_call_exception_retains_logs(self):
        """Unexpected exception after a completed call carries accumulated logs."""
        candidates = self._make_two_candidates()
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        # Use a mock seed that raises on model_dump() to trigger a
        # post-reconciliation exception after the call log is recorded.
        exploding_seed = MagicMock()
        exploding_seed.seed_id = "AP-T7-01"
        exploding_seed.model_dump.side_effect = RuntimeError("model_dump explosion")
        seeds = [exploding_seed]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)
        # The exception should carry accumulated call logs, not empty.
        assert len(exc_info.value.call_log_entries) >= 1


# ---------------------------------------------------------------------------
# 14. Forged model_copy and deep-validated snapshot
# ---------------------------------------------------------------------------


class TestForgedModelCopyAndSnapshot:
    """model_copy(update=...) bypasses validation; snapshot must revalidate."""

    def test_forged_candidate_id_via_model_copy_rejected(self):
        """A candidate forged with model_copy(update={candidate_id: ...})
        is rejected when revalidated through model_validate in the snapshot.
        """
        c = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        # Forge a candidate with a wrong candidate_id via model_copy.
        forged = c.model_copy(
            update={"candidate_id": "cand:v2:forged00000000000000000000"}
        )
        # The forged candidate has the wrong ID — model_validate should reject it.
        with pytest.raises(ValidationError, match="candidate_id"):
            CandidateTriple.model_validate(forged.model_dump(mode="python"))

    def test_nested_metadata_snapshot_not_shared(self):
        """Deep-validated snapshot does not share nested mutable collections."""
        c = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        # Reconstruct through model_validate (as the filter does).
        snapshot = CandidateTriple.model_validate(c.model_dump(mode="python"))
        # The owasp_llm_ids list should be a different object.
        assert snapshot.owasp_llm_ids is not c.owasp_llm_ids
        # Mutating the original should not affect the snapshot.
        original_ids = list(c.owasp_llm_ids)
        c.owasp_llm_ids.append("LLM99")
        assert list(snapshot.owasp_llm_ids) == original_ids

    def test_rule_pruned_candidate_validates_canonical_ids(self):
        """Rule-pruned candidate is reconstructed via model_validate and
        validates canonical IDs."""
        # Make a candidate with two techniques, one of which is supply-chain.
        c = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051", "AML.T0048"),
            technique_names=("Prompt Injection", "Supply Chain Compromise"),
            technique_descs=("Desc 1", "Desc 2"),
        )
        profile = _make_profile()
        passed, rejected, _verdicts = apply_rule_based_filter([c], profile)
        # Supply chain technique should be pruned, candidate survives.
        assert len(passed) == 1
        assert len(rejected) == 0
        pruned = passed[0]
        # The pruned candidate should have a valid candidate_id matching
        # canonical recomputation.
        expected_id = compute_candidate_id(
            pruned.seed_id, pruned.entry_point_id, pruned.atlas_technique_ids
        )
        assert pruned.candidate_id == expected_id
        # Only the compatible technique should remain.
        assert "AML.T0048" not in pruned.atlas_technique_ids


# ---------------------------------------------------------------------------
# 15. Score diversity with profile evidence
# ---------------------------------------------------------------------------


class TestScoreDiversityWithProfile:
    """score_diversity threads CapabilityProfile and returns evidence."""

    def _make_profile(self) -> CapabilityProfile:
        return CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="user prompts", direction="input"),
                EntryPoint(name="RAG knowledge", direction="input"),
                EntryPoint(name="admin console", direction="output"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )

    def test_score_diversity_with_profile_returns_evidence(self):
        """score_diversity with profile returns numerator/denominator evidence."""
        from asago_scenario_generator.eval.diversity import score_diversity

        profile = self._make_profile()
        ep_id_1 = compute_entry_point_id("user prompts", "input", None)
        scenarios = [
            {
                "narrative": {"entry_point": "user prompts", "zone_sequence": []},
                "candidate_filter": {"entry_point_id": ep_id_1},
            },
        ]
        result = score_diversity(
            scenarios,
            expected_entry_points=2,
            profile=profile,
        )
        ep = result["entry_point_entropy"]
        assert isinstance(ep, dict)
        assert ep["covered_entry_point_count"] == 1
        assert ep["expected_entry_point_count"] == 2
        assert ep["covered_entry_point_ids"] == [ep_id_1]
        assert len(ep["expected_entry_point_ids"]) == 2

    def test_unique_fallback_credited(self):
        """A narrative name that uniquely resolves to one ID is credited."""
        from asago_scenario_generator.eval.diversity import score_diversity

        profile = self._make_profile()
        ep_id_2 = compute_entry_point_id("RAG knowledge", "input", None)
        scenarios = [
            {
                "narrative": {"entry_point": "RAG knowledge", "zone_sequence": []},
                "candidate_filter": {},
            },
        ]
        result = score_diversity(
            scenarios,
            expected_entry_points=2,
            profile=profile,
        )
        ep = result["entry_point_entropy"]
        assert ep["entry_point_coverage"] == 0.5
        assert ep["covered_entry_point_count"] == 1
        assert ep_id_2 in ep["covered_entry_point_ids"]


# ---------------------------------------------------------------------------
# 16. Structured entry-point gaps
# ---------------------------------------------------------------------------


class TestStructuredEntryPointGaps:
    """EntryPointGap carries canonical identity; names are labels only."""

    def test_same_name_different_id_gaps_remain_distinct(self):
        """Two same-name EPs with different IDs produce distinct gaps."""
        from asago_scenario_generator.pipeline.coverage import analyze_coverage_gaps
        from asago_scenario_generator.models import ThreatSurface

        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="shared channel", direction="input"),
                EntryPoint(name="shared channel", direction="bidirectional"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        threat_surface = ThreatSurface(entries=[], governance_only=[])
        gaps = analyze_coverage_gaps(profile, threat_surface, [])
        # Two distinct gaps with same name but different IDs.
        assert len(gaps.uncovered_entry_points) == 2
        ids = {g.entry_point_id for g in gaps.uncovered_entry_points}
        assert len(ids) == 2
        names = {g.name for g in gaps.uncovered_entry_points}
        assert names == {"shared channel"}

    def test_gap_serialization_emits_entry_point_id_and_name(self):
        """to_dict emits list of {entry_point_id, name} dicts."""
        from asago_scenario_generator.pipeline.coverage import (
            CoverageGaps,
            EntryPointGap,
        )

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep:v1:aaa", name="EP A"),
                EntryPointGap(entry_point_id="ep:v1:bbb", name="EP B"),
            ],
        )
        d = gaps.to_dict()
        assert d["uncovered_entry_points"] == [
            {"entry_point_id": "ep:v1:aaa", "name": "EP A"},
            {"entry_point_id": "ep:v1:bbb", "name": "EP B"},
        ]

    def test_report_template_displays_name_looks_up_by_id(self):
        """Report template displays gap names but looks up attribution by ID."""
        from asago_scenario_generator.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "uncovered_entry_points": [
                    {"entry_point_id": "ep:v1:aaa", "name": "EP Alpha"},
                ],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
                "gap_attributions": {
                    "entry_points": {"ep:v1:aaa": "rejected"},
                },
            },
        }
        html = build_coverage_section(coverage_data)
        assert "EP Alpha" in html
        # The attribution label for "rejected" is "filtered out".
        assert "filtered out" in html.lower()


# ---------------------------------------------------------------------------
# 17. Ingress-only fallback: output EPs don't make unique ingress ambiguous
# ---------------------------------------------------------------------------


class TestIngressOnlyFallback:
    """Fallback name→ID map excludes output-only EPs so a unique ingress
    name is not made ambiguous by a same-name output EP."""

    def _make_profile(self) -> CapabilityProfile:
        return CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="shared channel", direction="input"),
                EntryPoint(name="shared channel", direction="output"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )

    def test_eval_fallback_resolves_unique_ingress_not_ambiguous(self):
        """Legacy narrative with same name as input+output EP resolves to
        the unique ingress ID, yielding coverage 1.0."""
        profile = self._make_profile()
        ingress_ep = next(ep for ep in profile.entry_points if ep.direction == "input")
        scenarios = [
            {
                "narrative": {"entry_point": "shared channel", "zone_sequence": []},
                "candidate_filter": {},
            },
        ]
        result = entry_point_entropy(
            scenarios, expected_entry_points=1, profile=profile
        )
        assert result["entry_point_coverage"] == 1.0
        assert result["covered_entry_point_count"] == 1
        assert result["expected_entry_point_count"] == 1
        assert ingress_ep.entry_point_id in result["covered_entry_point_ids"]

    def test_pipeline_coverage_no_gap_for_unique_ingress_fallback(self):
        """A legacy/no-provenance scenario covering the unique ingress EP
        by name produces no ingress coverage gap."""
        from asago_scenario_generator.pipeline.coverage import analyze_coverage_gaps
        from asago_scenario_generator.models import ThreatSurface

        profile = self._make_profile()
        threat_surface = ThreatSurface(entries=[], governance_only=[])

        scenario = MagicMock()
        scenario.narrative.entry_point = "shared channel"
        scenario.narrative.zone_sequence = ["input"]
        scenario.faceting.taxonomy_chain.agentic_threat_ids = []
        scenario.faceting.taxonomy_chain.scenario_seed = "AP-T1-01"
        scenario.candidate_filter = {}

        gaps = analyze_coverage_gaps(profile, threat_surface, [scenario])
        assert gaps.uncovered_entry_points == []
