"""Property tests for assigning Call 2b elements to Call 2a responsibilities.

``_enrich_responsibilities`` puts every CA and FB on the responsibility its ID
prefix names, leaves its inputs unchanged, and rejects an element no
responsibility owns.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    ResponsibilitySet,
    _enrich_responsibilities,
)


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
    target/source (None).
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
