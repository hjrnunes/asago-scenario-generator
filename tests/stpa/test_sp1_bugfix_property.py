"""Property-based tests for SP1 bug-fix invariants.

Covers three feature areas added in the SP1 combined bug fixes:

1. **Sanitization invariants** — ``_sanitize_for_fallback`` and
   ``_strip_all_element_refs``: conservation, non-mutation, completeness,
   and idempotence.

1b. **Enrichment and fallback conservation invariants** —
   ``_enrich_responsibilities`` and ``_assemble_with_fallback``: every CA
   and FB from the Call 2b ControlElementSet is assigned onto the matching
   responsibility by ID prefix; the fallback path (sanitize and strip
   tiers) conserves those CAs/FBs onto the resulting ControlStructure.

2. **RevisionDelta merge invariants** — ``_merge_revision_delta``:
   conservation of existing elements, non-mutation of the original
   ControlStructure, idempotence (empty delta = identity), and correct
   modified-responsibility replacement by resp_id.

3. **HTML rendering invariants** — ``calls_html``: HTML escaping of
   special characters, empty-content produces no sections, and
   conservation (every entry appears in the rendered HTML).

These complement the example-based tests in test_merge_fallback_sanitize,
test_revision_delta, and test_calls_html_full_content.
"""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.infra.call_log import make_call_log_entry
from asago_scenario_generator.stpa.infra.calls_html import render_calls_html
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
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
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _merge_revision_delta,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


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
    def test_elements_with_no_matching_resp_dropped(self, n_resps):
        """Orphan elements: CAs/FBs whose resp_num matches no responsibility are dropped."""
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
        enriched = _enrich_responsibilities(resp_set, ces)
        for resp in enriched:
            assert resp.control_actions == []
            assert resp.feedback_channels == []


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
    def test_strip_tier_conserves_cas_and_fbs(self, tmp_path, n_resps, n_cas, n_fbs):
        """Strip tier: every CA/FB from Call 2b appears on the fallback CS.

        The sanitize tier is forced to fail by adding a duplicate RESP-1
        (duplicate resp_id fails ControlStructure validation even after
        sanitizing refs). The strip tier deduplicates by resp_id (keeping
        the first occurrence, which carries the enriched CAs/FBs) and
        strips all ElementRefs, conserving the CAs/FBs themselves.
        """
        responsibilities = [_make_resp_pm_only("RESP-1")]
        # Add a duplicate RESP-1 to force sanitize-tier failure.
        responsibilities.append(_make_resp_pm_only("RESP-1"))
        # Add distinct responsibilities for resp_nums 2..n_resps.
        for x in range(2, n_resps + 1):
            responsibilities.append(_make_resp_pm_only(f"RESP-{x}"))
        resp_set = ResponsibilitySet(responsibilities=responsibilities)
        ces = _make_control_element_set(n_resps, n_cas, n_fbs)

        cs, warnings = _assemble_with_fallback(resp_set, ces, tmp_path, "test-model")

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
        # The strip tier nullified all ElementRefs.
        for resp in cs.responsibilities:
            for pm in resp.process_model_parts:
                assert pm.feedback_source is None
            for ca in resp.control_actions:
                assert ca.target is None
            for fb in resp.feedback_channels:
                assert fb.source is None
        # The duplicate RESP-1 was removed (dedup keeping first).
        resp_ids = [r.resp_id for r in cs.responsibilities]
        assert len(resp_ids) == len(set(resp_ids))

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_strip_tier_strips_valid_refs_but_keeps_cas_fbs(self, tmp_path, n_resps):
        """Sanitize-11 invariant: strip tier carries over CAs/FBs with refs stripped.

        CAs carry valid targets (controlled_process CP-1) and FBs carry
        valid sources (responsibility RESP-X). The strip tier nullifies
        those refs but the CAs/FBs themselves survive on the fallback CS.
        """
        responsibilities = [_make_resp_pm_only("RESP-1")]
        # Duplicate RESP-1 forces sanitize failure → strip tier runs.
        responsibilities.append(_make_resp_pm_only("RESP-1"))
        for x in range(2, n_resps + 1):
            responsibilities.append(_make_resp_pm_only(f"RESP-{x}"))
        resp_set = ResponsibilitySet(responsibilities=responsibilities)

        # CAs with valid targets and FBs with valid sources.
        control_actions = [
            ControlAction(
                ca_id=f"CA-{x}-1",
                description=f"Action {x}",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
            for x in range(1, n_resps + 1)
        ]
        feedback_channels = [
            FeedbackChannel(
                fb_id=f"FB-{x}-1",
                description=f"Feedback {x}",
                updates=f"PM-{x}-1",
                source=ElementRef(type=ReferenceType.responsibility, id=f"RESP-{x}"),
            )
            for x in range(1, n_resps + 1)
        ]
        ces = ControlElementSet(
            control_actions=control_actions,
            feedback_channels=feedback_channels,
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process")
            ],
        )

        cs, _ = _assemble_with_fallback(resp_set, ces, tmp_path, "test-model")

        # CAs and FBs survive but their refs are stripped to None.
        all_ca_ids = {
            ca.ca_id for resp in cs.responsibilities for ca in resp.control_actions
        }
        all_fb_ids = {
            fb.fb_id for resp in cs.responsibilities for fb in resp.feedback_channels
        }
        for x in range(1, n_resps + 1):
            assert f"CA-{x}-1" in all_ca_ids
            assert f"FB-{x}-1" in all_fb_ids
        for resp in cs.responsibilities:
            for ca in resp.control_actions:
                assert ca.target is None
            for fb in resp.feedback_channels:
                assert fb.source is None


# ---------------------------------------------------------------------------
# 2. RevisionDelta merge property tests
# ---------------------------------------------------------------------------


def _make_cs(n_resps: int = 2) -> ControlStructure:
    """Build a ControlStructure with n responsibilities."""
    responsibilities = []
    for i in range(1, n_resps + 1):
        responsibilities.append(
            Responsibility(
                resp_id=f"RESP-{i}",
                description=f"Controller {i}",
                process_model_parts=[
                    ProcessModelPart(pm_id=f"PM-{i}-1", description=f"State {i}")
                ],
                control_actions=[
                    ControlAction(ca_id=f"CA-{i}-1", description=f"Action {i}")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{i}-1",
                        description=f"FB {i}",
                        updates=f"PM-{i}-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id=f"RESP-{i}"
                        ),
                    )
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities)


def _make_new_resp(resp_num: int) -> Responsibility:
    """Build a new responsibility with the given number."""
    return Responsibility(
        resp_id=f"RESP-{resp_num}",
        description=f"New controller {resp_num}",
        process_model_parts=[
            ProcessModelPart(pm_id=f"PM-{resp_num}-1", description="New state")
        ],
        control_actions=[
            ControlAction(ca_id=f"CA-{resp_num}-1", description="New action")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{resp_num}-1",
                description="New FB",
                updates=f"PM-{resp_num}-1",
                source=ElementRef(
                    type=ReferenceType.responsibility, id=f"RESP-{resp_num}"
                ),
            )
        ],
    )


class TestMergeRevisionDeltaProperties:
    """Property tests for _merge_revision_delta invariants."""

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
        n_new=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_conserves_existing_responsibilities(self, n_existing, n_new):
        """Conservation: all existing resp_ids appear in the merged output."""
        cs = _make_cs(n_existing)
        new_resps = [_make_new_resp(n_existing + i + 1) for i in range(n_new)]
        delta = RevisionDelta(new_responsibilities=new_resps)
        merged, _ = _merge_revision_delta(cs, delta)
        existing_ids = {r.resp_id for r in cs.responsibilities}
        merged_ids = {r.resp_id for r in merged.responsibilities}
        assert existing_ids.issubset(merged_ids)

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=15, deadline=None)
    def test_empty_delta_is_identity(self, n_existing):
        """Idempotence: merging an empty delta preserves the CS unchanged."""
        cs = _make_cs(n_existing)
        delta = RevisionDelta()
        merged, _ = _merge_revision_delta(cs, delta)
        merged_ids = {r.resp_id for r in merged.responsibilities}
        original_ids = {r.resp_id for r in cs.responsibilities}
        assert merged_ids == original_ids
        assert len(merged.responsibilities) == len(cs.responsibilities)

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
        n_new=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_does_not_mutate_original_cs(self, n_existing, n_new):
        """Non-mutation: the original ControlStructure is not modified."""
        cs = _make_cs(n_existing)
        original_count = len(cs.responsibilities)
        original_ids = [r.resp_id for r in cs.responsibilities]
        new_resps = [_make_new_resp(n_existing + i + 1) for i in range(n_new)]
        delta = RevisionDelta(new_responsibilities=new_resps)
        _merge_revision_delta(cs, delta)
        assert len(cs.responsibilities) == original_count
        assert [r.resp_id for r in cs.responsibilities] == original_ids

    @given(
        n_existing=st.integers(min_value=2, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_modified_responsibilities_replace_by_id(self, n_existing):
        """Replacement: modified responsibilities replace existing ones by resp_id."""
        cs = _make_cs(n_existing)
        # Modify RESP-1
        modified = Responsibility(
            resp_id="RESP-1",
            description="Updated controller",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="Updated state")
            ],
            control_actions=[
                ControlAction(ca_id="CA-1-1", description="Updated action")
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="Updated FB",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
        delta = RevisionDelta(modified_responsibilities=[modified])
        merged, _ = _merge_revision_delta(cs, delta)
        resp1 = next(r for r in merged.responsibilities if r.resp_id == "RESP-1")
        assert resp1.description == "Updated controller"
        # Other responsibilities should be unchanged
        resp2 = next(r for r in merged.responsibilities if r.resp_id == "RESP-2")
        assert resp2.description == "Controller 2"

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        n_new_cps=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_new_cps_merged(self, n_existing, n_new_cps):
        """Conservation: new controlled processes appear in merged output."""
        cs = _make_cs(n_existing)
        new_cps = [
            ControlledProcess(cp_id=f"CP-{i + 1}", description=f"New CP {i + 1}")
            for i in range(n_new_cps)
        ]
        delta = RevisionDelta(new_controlled_processes=new_cps)
        merged, _ = _merge_revision_delta(cs, delta)
        merged_cp_ids = {cp.cp_id for cp in merged.controlled_processes}
        for cp in new_cps:
            assert cp.cp_id in merged_cp_ids

    @given(
        n_existing=st.integers(min_value=1, max_value=3),
        n_new_cls=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_new_cls_merged(self, n_existing, n_new_cls):
        """Conservation: new coordination links appear in merged output."""
        cs = _make_cs(max(n_existing, 2))
        new_cls = [
            CoordinationLink(
                link_id=f"CL-{i + 1}",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id=f"CM-{i + 1}",
                    description=f"Mechanism {i + 1}",
                    payload="Payload",
                ),
                description=f"Link {i + 1}",
            )
            for i in range(n_new_cls)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)
        merged_cl_ids = {cl.link_id for cl in merged.coordination_links}
        for cl in new_cls:
            assert cl.link_id in merged_cl_ids

    @given(
        n_existing=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=15, deadline=None)
    def test_duplicate_new_resps_skipped(self, n_existing):
        """Deduplication: new responsibilities with existing IDs are skipped."""
        cs = _make_cs(n_existing)
        # Try to add a resp with an existing ID
        dup_resp = _make_new_resp(1)  # RESP-1 already exists
        delta = RevisionDelta(new_responsibilities=[dup_resp])
        merged, _ = _merge_revision_delta(cs, delta)
        # Should still have only n_existing responsibilities
        assert len(merged.responsibilities) == n_existing


# ---------------------------------------------------------------------------
# 2b. cm_id renumbering property tests
# ---------------------------------------------------------------------------


def _make_cs_with_cls(n_cls: int = 2) -> ControlStructure:
    """Build a ControlStructure with two responsibilities and n coordination links.

    Links use CM-1, CM-2, ... so new links with those cm_ids will collide.
    """
    resps = [
        Responsibility(
            resp_id=f"RESP-{i}",
            description=f"Controller {i}",
            process_model_parts=[
                ProcessModelPart(pm_id=f"PM-{i}-1", description=f"State {i}")
            ],
            control_actions=[
                ControlAction(ca_id=f"CA-{i}-1", description=f"Action {i}")
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{i}-1",
                    description=f"FB {i}",
                    updates=f"PM-{i}-1",
                    source=ElementRef(
                        type=ReferenceType.responsibility, id=f"RESP-{i}"
                    ),
                )
            ],
        )
        for i in range(1, 3)
    ]
    links = [
        CoordinationLink(
            link_id=f"CL-{i}",
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-2-1" if i % 2 == 0 else "PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id=f"CM-{i}",
                description=f"Mechanism {i}",
                payload=f"Payload {i}",
            ),
            description=f"Link {i}",
        )
        for i in range(1, n_cls + 1)
    ]
    return ControlStructure(responsibilities=resps, coordination_links=links)


def _make_new_cl(
    cl_num: int,
    cm_id: str,
    *,
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
    description: str = "New link",
    payload: str = "new payload",
    mech_desc: str = "New mechanism",
) -> CoordinationLink:
    """Build a new CoordinationLink with the given link_id and cm_id."""
    return CoordinationLink(
        link_id=f"CL-{cl_num}",
        source=source,
        target=target,
        shared_pm=shared_pm,
        coordination_mechanism=CoordinationMechanism(
            cm_id=cm_id,
            description=mech_desc,
            payload=payload,
        ),
        description=description,
    )


def _make_critic_findings() -> CriticFindings:
    """Build minimal critic findings for run_revision."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            )
        ],
        checklist_results={"input_validation": "absent_unjustified"},
    )


class TestCmIdRenumberingProperties:
    """Property tests for cm_id collision renumbering invariants."""

    @given(
        n_existing_cls=st.integers(min_value=1, max_value=4),
        n_new_cls=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=30, deadline=None)
    def test_no_duplicate_cm_ids_after_merge(self, n_existing_cls, n_new_cls):
        """Invariant: the merged structure never contains duplicate cm_ids.

        New links all use CM-1 (guaranteed collision with the first
        existing link). After merge + renumbering, every cm_id is unique.
        """
        cs = _make_cs_with_cls(n_existing_cls)
        new_cls = [
            _make_new_cl(n_existing_cls + i + 1, "CM-1") for i in range(n_new_cls)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)
        cm_ids = [cl.coordination_mechanism.cm_id for cl in merged.coordination_links]
        assert len(cm_ids) == len(set(cm_ids)), f"Duplicate cm_ids found: {cm_ids}"

    @given(
        n_existing_cls=st.integers(min_value=1, max_value=3),
        n_new=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_renumbering_preserves_non_cm_id_content(self, n_existing_cls, n_new):
        """Invariant: renumbering never alters a link's non-cm_id content.

        Each new link gets distinct source/target/shared_pm/description/
        payload so we can verify they survive renumbering unchanged.
        """
        cs = _make_cs_with_cls(n_existing_cls)
        new_cls = [
            _make_new_cl(
                n_existing_cls + i + 1,
                "CM-1",  # collides with existing CM-1
                source="RESP-2",
                target="RESP-1",
                shared_pm="PM-2-1",
                description=f"Unique desc {i}",
                payload=f"Unique payload {i}",
                mech_desc=f"Unique mech {i}",
            )
            for i in range(n_new)
        ]
        delta = RevisionDelta(new_coordination_links=new_cls)
        merged, _ = _merge_revision_delta(cs, delta)

        # Find the new links by link_id
        new_link_ids = {cl.link_id for cl in new_cls}
        merged_new = [
            cl for cl in merged.coordination_links if cl.link_id in new_link_ids
        ]
        assert len(merged_new) == n_new

        for original, renumbered in zip(new_cls, merged_new, strict=False):
            assert renumbered.source == original.source
            assert renumbered.target == original.target
            assert renumbered.shared_pm == original.shared_pm
            assert renumbered.description == original.description
            assert renumbered.coordination_mechanism.description == (
                original.coordination_mechanism.description
            )
            assert renumbered.coordination_mechanism.payload == (
                original.coordination_mechanism.payload
            )
            # cm_id should have changed (was CM-1, now something else)
            assert renumbered.coordination_mechanism.cm_id != "CM-1"

    @given(
        n_existing_cls=st.integers(min_value=0, max_value=3),
        n_new=st.integers(min_value=0, max_value=4),
        collide=st.booleans(),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_run_revision_never_raises(self, tmp_path, n_existing_cls, n_new, collide):
        """Invariant: run_revision never raises regardless of delta shape.

        Uses a mock LLM client that returns a RevisionDelta with new
        coordination links. When *collide* is True, all new links use
        CM-1 (which collides if existing links have CM-1). When False,
        new links use unique cm_ids starting after the existing max.
        """
        n_resps = max(n_existing_cls, 2)  # need >=2 resps for valid CLs
        cs = _make_cs(n_resps)
        if n_existing_cls > 0:
            # Rebuild with coordination links
            cs = _make_cs_with_cls(n_existing_cls)
            # _make_cs_with_cls always creates 2 responsibilities
            n_resps = 2

        if collide and n_existing_cls > 0:
            cm_start = 1  # CM-1 collides
        else:
            cm_start = n_existing_cls + 1

        new_cls = [
            _make_new_cl(n_existing_cls + i + 1, f"CM-{cm_start + i}")
            for i in range(n_new)
        ]
        # Wrap new links in dicts for the mock client ( RevisionDelta
        # is parsed from dict by call_with_policy).
        new_cl_dicts = [
            {
                "link_id": cl.link_id,
                "source": cl.source,
                "target": cl.target,
                "shared_pm": cl.shared_pm,
                "coordination_mechanism": {
                    "cm_id": cl.coordination_mechanism.cm_id,
                    "description": cl.coordination_mechanism.description,
                    "payload": cl.coordination_mechanism.payload,
                },
                "description": cl.description,
            }
            for cl in new_cls
        ]
        delta_dict = {"new_coordination_links": new_cl_dicts}

        client = MockLLMClient()
        client.set_response_for(RevisionDelta, delta_dict)

        # run_revision must not raise — the degradation guard catches
        # any merge exception and returns (pre-revision-cs, [warning]).
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(revised, ControlStructure)
        assert isinstance(warnings, list)


# ---------------------------------------------------------------------------
# 3. HTML rendering property tests
# ---------------------------------------------------------------------------


# Safe text for HTML content — exclude characters that would break JSON
# serialization or contain HTML special chars we want to test separately.
st_safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=0,
    max_size=100,
)

# Text guaranteed to contain HTML special characters.
st_html_special = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("<", ">", "&", '"', " ", "-"),
    ),
    min_size=1,
    max_size=50,
)


def _write_calls_jsonl(tmp_path: Path, entries: list[dict]) -> Path:
    """Write entries to calls.jsonl and return the path."""
    calls_path = tmp_path / "calls.jsonl"
    with calls_path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return calls_path


class TestCallsHtmlRenderingProperties:
    """Property tests for calls_html rendering invariants."""

    @given(content=st_html_special)
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_escaping_in_prompt_text(self, tmp_path, content):
        """HTML escaping: special characters in prompt text are escaped."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            system_prompt=content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # The raw content should not appear unescaped (unless it has no
        # special chars). Check that < > & " are escaped.
        if "<" in content:
            assert "&lt;" in html
        if ">" in content:
            assert "&gt;" in html
        if "&" in content:
            assert "&amp;" in html
        if '"' in content:
            assert "&quot;" in html

    @given(
        n_entries=st.integers(min_value=0, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_entries_appear_in_html(self, tmp_path, n_entries):
        """Conservation: every entry's step label appears in the rendered HTML."""
        entries = []
        for i in range(n_entries):
            entries.append(
                make_call_log_entry(
                    stage=f"stage_{i + 1}",
                    step=f"step_{i + 1}",
                    model="test",
                    system_prompt=f"prompt {i + 1}",
                )
            )
        calls_path = _write_calls_jsonl(tmp_path, entries)
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        for entry in entries:
            assert entry["step"] in html
            assert entry["stage"] in html

    @given(
        system_prompt=st_safe_text,
        user_prompt=st_safe_text,
        response_content=st_safe_text,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_empty_content_produces_no_section(
        self, tmp_path, system_prompt, user_prompt, response_content
    ):
        """Empty content: when a field is empty, no section is rendered for it."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_content=response_content if response_content else None,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # Check that empty fields don't produce collapsible sections
        if not system_prompt:
            assert "system_prompt</summary>" not in html
        if not user_prompt:
            assert "user_prompt</summary>" not in html
        if not response_content:
            assert "response_content</summary>" not in html

    @given(
        n_success=st.integers(min_value=0, max_value=3),
        n_failure=st.integers(min_value=0, max_value=3),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_summary_counts_match_entries(self, tmp_path, n_success, n_failure):
        """Summary accuracy: success and failure counts match the entries."""
        entries = []
        for i in range(n_success):
            entries.append(
                make_call_log_entry(
                    stage="stage_2",
                    step=f"step_{i + 1}",
                    model="test",
                    success=True,
                )
            )
        for i in range(n_failure):
            entries.append(
                make_call_log_entry(
                    stage="stage_2",
                    step=f"fail_{i + 1}",
                    model="test",
                    success=False,
                    error="Connection timeout",
                )
            )
        calls_path = _write_calls_jsonl(tmp_path, entries)
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # The summary table should contain the correct counts
        total = n_success + n_failure
        if total > 0:
            assert str(total) in html
            assert str(n_success) in html
            assert str(n_failure) in html

    @given(
        content=st_html_special,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_escaping_in_error_message(self, tmp_path, content):
        """HTML escaping: special characters in error messages are escaped."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            success=False,
            error=content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        if "<" in content:
            assert "&lt;" in html
        if ">" in content:
            assert "&gt;" in html
        if "&" in content:
            assert "&amp;" in html

    @given(
        key=st.from_regex(r"[a-z]{1,5}", fullmatch=True),
        value=st.from_regex(r"[a-z]{1,5}", fullmatch=True),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_json_response_pretty_printed(self, tmp_path, key, value):
        """JSON response: valid JSON is pretty-printed in the HTML output."""
        json_content = json.dumps({key: value})
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            response_content=json_content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # Pretty-printed JSON has newlines and indentation
        assert "response_content" in html
        # The pretty-printed version should contain the key and value
        parsed = json.loads(json_content)
        for key in parsed:
            assert key in html
