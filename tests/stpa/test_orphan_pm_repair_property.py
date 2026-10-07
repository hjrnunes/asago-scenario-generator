"""Property tests for ``repair_orphan_pms`` in ``control_structure.py``.

No orphan PM survives repair, existing elements are preserved, repair is
idempotent and a no-op when there are no orphans, and the warning count
matches the number of repaired orphans.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    repair_orphan_pms,
)

st_description = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)


# ---------------------------------------------------------------------------
# Strategies — repair
# ---------------------------------------------------------------------------


def _make_resp(
    num: int,
    pm_count: int,
    fb_count: int,
    description: str,
) -> Responsibility:
    """Build a responsibility for RESP-{num} with *pm_count* PMs and *fb_count* FBs.

    FB channels are assigned to the first *fb_count* PMs (if any).
    Remaining PMs are orphans. A single CA is always added so the
    responsibility is structurally valid.
    """
    pms = [
        ProcessModelPart(
            pm_id=f"PM-{num}-{j + 1}",
            description=f"State {j + 1}",
        )
        for j in range(pm_count)
    ]
    cas = [ControlAction(ca_id=f"CA-{num}-1", description="Action")]
    fbs: list[FeedbackChannel] = []
    for j in range(min(fb_count, pm_count)):
        fbs.append(
            FeedbackChannel(
                fb_id=f"FB-{num}-{j + 1}",
                description=f"FB {j + 1}",
                updates=f"PM-{num}-{j + 1}",
            )
        )
    return Responsibility(
        resp_id=f"RESP-{num}",
        description=description,
        process_model_parts=pms,
        control_actions=cas,
        feedback_channels=fbs,
    )


@st.composite
def st_responsibility_set(draw) -> ResponsibilitySet:
    """Generate a ResponsibilitySet with 1-5 responsibilities.

    Each responsibility has 1-4 PM parts and 0 to (pm_count) FB channels,
    producing a mix of fully-covered, partially-orphan, and fully-orphan
    responsibilities.
    """
    n = draw(st.integers(min_value=1, max_value=5))
    responsibilities: list[Responsibility] = []
    for i in range(1, n + 1):
        pm_count = draw(st.integers(min_value=1, max_value=4))
        # FB count can be 0 to pm_count — 0 means all PMs are orphans
        fb_count = draw(st.integers(min_value=0, max_value=pm_count))
        desc = draw(st_description)
        responsibilities.append(_make_resp(i, pm_count, fb_count, desc))
    return ResponsibilitySet(responsibilities=responsibilities)


def _count_orphan_pms(resp_set: ResponsibilitySet) -> int:
    """Count the total number of orphan PMs across all responsibilities."""
    total = 0
    for resp in resp_set.responsibilities:
        updated = {fb.updates for fb in resp.feedback_channels}
        for pm in resp.process_model_parts:
            if pm.pm_id not in updated:
                total += 1
    return total


@st.composite
def st_no_orphan_responsibility_set(draw) -> ResponsibilitySet:
    """Generate a ResponsibilitySet where every PM has a matching FB."""
    n = draw(st.integers(min_value=1, max_value=5))
    responsibilities: list[Responsibility] = []
    for i in range(1, n + 1):
        pm_count = draw(st.integers(min_value=1, max_value=4))
        desc = draw(st_description)
        responsibilities.append(_make_resp(i, pm_count, pm_count, desc))
    return ResponsibilitySet(responsibilities=responsibilities)


# ---------------------------------------------------------------------------
# Repair property tests
# ---------------------------------------------------------------------------


class TestRepairOrphanPmsProperties:
    """Property tests for repair_orphan_pms invariants."""

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_no_orphan_pms_after_repair(self, resp_set: ResponsibilitySet) -> None:
        """After repair, every PM is referenced by at least one FB."""
        repaired, _ = repair_orphan_pms(resp_set)
        for resp in repaired.responsibilities:
            updated_pms = {fb.updates for fb in resp.feedback_channels}
            for pm in resp.process_model_parts:
                assert pm.pm_id in updated_pms, (
                    f"Orphan PM {pm.pm_id} survived repair in {resp.resp_id}"
                )

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_existing_pms_preserved(self, resp_set: ResponsibilitySet) -> None:
        """No existing PM is removed by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        for orig_resp, rep_resp in zip(
            resp_set.responsibilities,
            repaired.responsibilities,
            strict=True,
        ):
            orig_pm_ids = {pm.pm_id for pm in orig_resp.process_model_parts}
            rep_pm_ids = {pm.pm_id for pm in rep_resp.process_model_parts}
            assert orig_pm_ids.issubset(rep_pm_ids)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_existing_fbs_preserved(self, resp_set: ResponsibilitySet) -> None:
        """No existing FB is removed by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        for orig_resp, rep_resp in zip(
            resp_set.responsibilities,
            repaired.responsibilities,
            strict=True,
        ):
            orig_fb_ids = {fb.fb_id for fb in orig_resp.feedback_channels}
            rep_fb_ids = {fb.fb_id for fb in rep_resp.feedback_channels}
            assert orig_fb_ids.issubset(rep_fb_ids)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_idempotence(self, resp_set: ResponsibilitySet) -> None:
        """Repairing twice produces no warnings on the second call."""
        repaired_once, warnings_once = repair_orphan_pms(resp_set)
        repaired_twice, warnings_twice = repair_orphan_pms(repaired_once)
        assert len(warnings_twice) == 0

    @given(resp_set=st_no_orphan_responsibility_set())
    @settings(max_examples=50, deadline=None)
    def test_no_op_when_no_orphans(self, resp_set: ResponsibilitySet) -> None:
        """When there are no orphans, the same instance is returned."""
        repaired, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == 0
        assert repaired is resp_set

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_warning_count_equals_orphan_count(
        self, resp_set: ResponsibilitySet
    ) -> None:
        """The number of warnings equals the number of orphan PMs repaired."""
        orphan_count = _count_orphan_pms(resp_set)
        _, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == orphan_count

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_resp_count_preserved(self, resp_set: ResponsibilitySet) -> None:
        """The number of responsibilities is preserved by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        assert len(repaired.responsibilities) == len(resp_set.responsibilities)

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_resp_ids_preserved(self, resp_set: ResponsibilitySet) -> None:
        """Responsibility IDs are preserved in order by repair."""
        repaired, _ = repair_orphan_pms(resp_set)
        orig_ids = [r.resp_id for r in resp_set.responsibilities]
        rep_ids = [r.resp_id for r in repaired.responsibilities]
        assert orig_ids == rep_ids
