"""Property tests for the control-structure merge fallback.

Covers ``_sanitize_for_fallback`` and ``_strip_all_element_refs`` (conservation,
non-mutation, completeness, idempotence), and ``_enrich_responsibilities`` and
``_assemble_with_fallback`` (every CA and FB lands on the responsibility its ID
prefix names; the sanitize and strip tiers conserve them).
"""

from __future__ import annotations


import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _assemble_with_fallback,
    _enrich_responsibilities,
    _sanitize_for_fallback,
    _strip_all_element_refs,
)


# ---------------------------------------------------------------------------
# Helpers — build responsibility sets with configurable refs
# ---------------------------------------------------------------------------


def _make_resp_with_refs(
    resp_id: str = "RESP-1",
    pm_fb_source: ElementRef | None = None,
    ca_target: ElementRef | None = None,
    fb_source: ElementRef | None = None,
) -> Responsibility:
    """Build a responsibility with explicit ElementRef slots."""
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {resp_id}",
        process_model_parts=[
            ProcessModelPart(
                pm_id=f"PM-{resp_id.split('-')[-1]}-1",
                description="State",
                feedback_source=pm_fb_source,
            )
        ],
        control_actions=[
            ControlAction(
                ca_id=f"CA-{resp_id.split('-')[-1]}-1",
                description="Action",
                target=ca_target,
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{resp_id.split('-')[-1]}-1",
                description="Feedback",
                updates=f"PM-{resp_id.split('-')[-1]}-1",
                source=fb_source,
            )
        ],
    )


def _make_resp_set(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess] | None = None,
) -> ResponsibilitySet:
    return ResponsibilitySet(
        responsibilities=responsibilities,
        controlled_processes=controlled_processes or [],
    )


def _valid_ref(resp_id: str = "RESP-1") -> ElementRef:
    return ElementRef(type=ReferenceType.responsibility, id=resp_id)


def _invalid_ref(id_suffix: str = "999") -> ElementRef:
    return ElementRef(type=ReferenceType.responsibility, id=f"RESP-{id_suffix}")


def _invalid_cp_ref(cp_id: str = "CP-999") -> ElementRef:
    return ElementRef(type=ReferenceType.controlled_process, id=cp_id)


# ---------------------------------------------------------------------------
# 1. Sanitization property tests
# ---------------------------------------------------------------------------


class TestSanitizeForFallbackProperties:
    """Property tests for _sanitize_for_fallback invariants."""

    @given(
        n_valid=st.integers(min_value=1, max_value=3),
        n_invalid=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_conserves_all_resp_ids(self, n_valid, n_invalid):
        """Conservation: every original resp_id appears in the sanitized output."""
        resps = []
        for i in range(1, n_valid + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        for i in range(1, n_invalid + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{n_valid + i}",
                    fb_source=_invalid_ref(str(900 + i)),
                )
            )
        cps: list[ControlledProcess] = []
        sanitized, _, _ = _sanitize_for_fallback(resps, cps)
        input_ids = {r.resp_id for r in resps}
        output_ids = {r.resp_id for r in sanitized}
        assert input_ids == output_ids

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=20, deadline=None)
    def test_does_not_mutate_input(self, n_resps):
        """Non-mutation: original responsibility list is not modified."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_invalid_ref(str(900 + i)),
                )
            )
        _sanitize_for_fallback(resps, [])
        for r in resps:
            for fb in r.feedback_channels:
                assert fb.source is not None, (
                    f"Original {fb.fb_id}.source was mutated to None"
                )

    @given(
        n_invalid=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_all_invalid_refs_nullified(self, n_invalid):
        """Completeness: no invalid refs remain after sanitization."""
        resps = []
        for i in range(1, n_invalid + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    pm_fb_source=_invalid_ref(str(900 + i)),
                    ca_target=_invalid_ref(str(900 + i)),
                    fb_source=_invalid_ref(str(900 + i)),
                )
            )
        sanitized, _, warnings = _sanitize_for_fallback(resps, [])
        # After sanitization, no responsibility should have non-None refs
        # that point to non-existent IDs
        for r in sanitized:
            for pm in r.process_model_parts:
                assert pm.feedback_source is None
            for ca in r.control_actions:
                assert ca.target is None
            for fb in r.feedback_channels:
                assert fb.source is None
        assert len(warnings) == n_invalid * 3  # 3 invalid refs per resp

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=15, deadline=None)
    def test_idempotent_on_clean_input(self, n_resps):
        """Idempotence: sanitizing already-valid refs is a no-op (no warnings)."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        sanitized, _, warnings = _sanitize_for_fallback(resps, [])
        assert warnings == []
        assert len(sanitized) == n_resps

    @given(
        n_valid=st.integers(min_value=1, max_value=3),
        n_invalid=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_valid_refs_preserved(self, n_valid, n_invalid):
        """Selective preservation: valid refs are kept, only invalid ones are stripped."""
        resps = []
        for i in range(1, n_valid + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        for i in range(1, n_invalid + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{n_valid + i}",
                    fb_source=_invalid_ref(str(900 + i)),
                )
            )
        sanitized, _, _ = _sanitize_for_fallback(resps, [])
        for i, r in enumerate(sanitized[:n_valid], 1):
            fb = r.feedback_channels[0]
            assert fb.source is not None
            assert fb.source.id == f"RESP-{i}"
        for r in sanitized[n_valid:]:
            fb = r.feedback_channels[0]
            assert fb.source is None


class TestStripAllElementRefsProperties:
    """Property tests for _strip_all_element_refs invariants."""

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_all_refs_stripped(self, n_resps):
        """Completeness: all ElementRefs are None after stripping."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    pm_fb_source=_valid_ref(f"RESP-{i}"),
                    ca_target=_valid_ref(f"RESP-{i}"),
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        stripped, _, _ = _strip_all_element_refs(resps, [])
        for r in stripped:
            for pm in r.process_model_parts:
                assert pm.feedback_source is None
            for ca in r.control_actions:
                assert ca.target is None
            for fb in r.feedback_channels:
                assert fb.source is None

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=15, deadline=None)
    def test_does_not_mutate_input(self, n_resps):
        """Non-mutation: original responsibilities are not modified."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        _strip_all_element_refs(resps, [])
        for r in resps:
            for fb in r.feedback_channels:
                assert fb.source is not None

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=15, deadline=None)
    def test_idempotent(self, n_resps):
        """Idempotence: stripping an already-stripped result is a no-op."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        stripped1, _, warnings1 = _strip_all_element_refs(resps, [])
        stripped2, _, warnings2 = _strip_all_element_refs(stripped1, [])
        # Second strip should produce no warnings (already stripped)
        assert warnings2 == []
        assert len(stripped2) == len(stripped1)

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
        n_dups=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_deduplicates_resp_ids(self, n_resps, n_dups):
        """Deduplication: duplicate resp_ids are removed, keeping first occurrence."""
        resps = []
        for i in range(1, n_resps + 1):
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{i}",
                    fb_source=_valid_ref(f"RESP-{i}"),
                )
            )
        # Add duplicates
        for i in range(1, n_dups + 1):
            dup_idx = ((i - 1) % n_resps) + 1
            resps.append(
                _make_resp_with_refs(
                    resp_id=f"RESP-{dup_idx}",
                    fb_source=_valid_ref(f"RESP-{dup_idx}"),
                )
            )
        stripped, _, warnings = _strip_all_element_refs(resps, [])
        output_ids = [r.resp_id for r in stripped]
        assert len(output_ids) == len(set(output_ids))
        # Warnings should include duplicate removal messages
        dup_warnings = [w for w in warnings if "duplicate" in w.lower()]
        assert len(dup_warnings) == n_dups


# ---------------------------------------------------------------------------
# 1b. Enrichment and fallback conservation property tests
# ---------------------------------------------------------------------------


def _make_resp_pm_only(resp_id: str = "RESP-1") -> Responsibility:
    """Build a Call 2a responsibility: one PM part, no CAs/FBs."""
    num = resp_id.split("-")[-1]
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {resp_id}",
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{num}-1", description=f"State {num}")
        ],
    )


def _make_control_element_set(
    n_resps: int,
    n_cas_per_resp: int = 1,
    n_fbs_per_resp: int = 1,
) -> ControlElementSet:
    """Build a Call 2b ControlElementSet with CAs and FBs for n_resps.

    CA-X-Y and FB-X-Y are generated for resp_num X in 1..n_resps. Each FB
    updates ``PM-X-1`` so it matches the PM in RESP-X (required for
    ControlStructure validation). CAs and FBs carry no ElementRef
    target/source (None) so the fallback tiers do not need to strip them.
    """
    control_actions = [
        ControlAction(ca_id=f"CA-{x}-{y}", description=f"Action {x}-{y}")
        for x in range(1, n_resps + 1)
        for y in range(1, n_cas_per_resp + 1)
    ]
    feedback_channels = [
        FeedbackChannel(
            fb_id=f"FB-{x}-{y}",
            description=f"Feedback {x}-{y}",
            updates=f"PM-{x}-1",
        )
        for x in range(1, n_resps + 1)
        for y in range(1, n_fbs_per_resp + 1)
    ]
    return ControlElementSet(
        control_actions=control_actions,
        feedback_channels=feedback_channels,
    )


class TestEnrichResponsibilitiesProperties:
    """Property tests for _enrich_responsibilities invariants."""

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
        n_cas=st.integers(min_value=1, max_value=3),
        n_fbs=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=30, deadline=None)
    def test_conserves_all_cas_and_fbs_by_id_prefix(self, n_resps, n_cas, n_fbs):
        """Conservation: every CA-X-Y and FB-X-Y lands on RESP-X after enrichment."""
        resp_set = ResponsibilitySet(
            responsibilities=[
                _make_resp_pm_only(f"RESP-{x}") for x in range(1, n_resps + 1)
            ]
        )
        ces = _make_control_element_set(n_resps, n_cas, n_fbs)
        enriched = _enrich_responsibilities(resp_set, ces)

        # Every CA and FB from the ControlElementSet appears on the
        # matching responsibility (by ID prefix).
        for x in range(1, n_resps + 1):
            resp = next(r for r in enriched if r.resp_id == f"RESP-{x}")
            ca_ids = {ca.ca_id for ca in resp.control_actions}
            fb_ids = {fb.fb_id for fb in resp.feedback_channels}
            for y in range(1, n_cas + 1):
                assert f"CA-{x}-{y}" in ca_ids
            for y in range(1, n_fbs + 1):
                assert f"FB-{x}-{y}" in fb_ids

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=20, deadline=None)
    def test_does_not_mutate_inputs(self, n_resps):
        """Non-mutation: original ResponsibilitySet stays CA/FB-free."""
        resp_set = ResponsibilitySet(
            responsibilities=[
                _make_resp_pm_only(f"RESP-{x}") for x in range(1, n_resps + 1)
            ]
        )
        ces = _make_control_element_set(n_resps)
        _enrich_responsibilities(resp_set, ces)
        for resp in resp_set.responsibilities:
            assert resp.control_actions == []
            assert resp.feedback_channels == []
        # ControlElementSet CAs/FBs are untouched
        assert len(ces.control_actions) == n_resps
        assert len(ces.feedback_channels) == n_resps

    @given(
        n_dups=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_first_occurrence_wins_on_duplicate_resp_ids(self, n_dups):
        """First-occurrence: CAs/FBs land on the FIRST RESP-X, duplicates get none."""
        # n_dups+1 copies of RESP-1, all with the same resp_num (1).
        resp_set = ResponsibilitySet(
            responsibilities=[_make_resp_pm_only("RESP-1") for _ in range(n_dups + 1)]
        )
        ces = _make_control_element_set(1)
        enriched = _enrich_responsibilities(resp_set, ces)

        first = enriched[0]
        rest = enriched[1:]
        # The first occurrence carries the CA and FB.
        assert len(first.control_actions) == 1
        assert first.control_actions[0].ca_id == "CA-1-1"
        assert len(first.feedback_channels) == 1
        assert first.feedback_channels[0].fb_id == "FB-1-1"
        # Duplicates carry no CAs/FBs.
        for dup in rest:
            assert dup.control_actions == []
            assert dup.feedback_channels == []

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=15, deadline=None)
    def test_elements_with_no_matching_resp_rejected(self, n_resps):
        """Orphan elements: CAs/FBs whose resp_num matches no responsibility fail."""
        resp_set = ResponsibilitySet(
            responsibilities=[
                _make_resp_pm_only(f"RESP-{x}") for x in range(1, n_resps + 1)
            ]
        )
        # Add CAs/FBs for a resp_num that does not exist (n_resps + 1).
        ces = ControlElementSet(
            control_actions=[
                ControlAction(
                    ca_id=f"CA-{n_resps + 1}-1",
                    description="Orphan CA",
                )
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{n_resps + 1}-1",
                    description="Orphan FB",
                    updates=f"PM-{n_resps + 1}-1",
                )
            ],
        )
        with pytest.raises(ValueError) as exc_info:
            _enrich_responsibilities(resp_set, ces)
        assert str(exc_info.value) == (
            "unmatched control-element ownership; cannot distribute by response "
            f"order: CA CA-{n_resps + 1}-1, FB FB-{n_resps + 1}-1"
        )


class TestFallbackConservationProperties:
    """Property tests for _assemble_with_fallback conservation invariants.

    The fallback-fix (bead asago-scenario-generator-32aa) ensures CAs and FBs from
    the Call 2b ControlElementSet are carried over onto the fallback
    ControlStructure instead of being silently dropped. These tests
    verify the conservation invariant end-to-end for both the sanitize
    tier and the strip tier.
    """

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
        n_cas=st.integers(min_value=1, max_value=2),
        n_fbs=st.integers(min_value=1, max_value=2),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_sanitize_tier_conserves_cas_and_fbs(self, tmp_path, n_resps, n_cas, n_fbs):
        """Sanitize tier: every CA/FB from Call 2b appears on the fallback CS.

        The assembly is forced to fail by giving each PM an invalid
        feedback_source (controlled_process CP-999, which does not exist).
        The sanitize tier nullifies those refs and the structure validates,
        conserving all CAs/FBs from the ControlElementSet.
        """
        responsibilities = []
        for x in range(1, n_resps + 1):
            resp = _make_resp_pm_only(f"RESP-{x}")
            # Inject an invalid feedback_source to force assembly failure.
            resp.process_model_parts[0].feedback_source = _invalid_cp_ref("CP-999")
            responsibilities.append(resp)
        resp_set = ResponsibilitySet(responsibilities=responsibilities)
        ces = _make_control_element_set(n_resps, n_cas, n_fbs)

        cs, warnings = _assemble_with_fallback(resp_set, ces, tmp_path, "test-model")

        # The fallback was triggered (warnings non-empty).
        assert len(warnings) >= 1
        # Every CA and FB from the ControlElementSet appears on the CS.
        all_ca_ids = {
            ca.ca_id for resp in cs.responsibilities for ca in resp.control_actions
        }
        all_fb_ids = {
            fb.fb_id for resp in cs.responsibilities for fb in resp.feedback_channels
        }
        for x in range(1, n_resps + 1):
            for y in range(1, n_cas + 1):
                assert f"CA-{x}-{y}" in all_ca_ids
            for y in range(1, n_fbs + 1):
                assert f"FB-{x}-{y}" in all_fb_ids
        # Invalid PM feedback_source was nullified by the sanitize tier.
        for resp in cs.responsibilities:
            for pm in resp.process_model_parts:
                assert pm.feedback_source is None
