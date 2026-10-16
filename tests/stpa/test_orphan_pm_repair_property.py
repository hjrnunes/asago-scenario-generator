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


class TestRepairOrphanPmsProperties:
    """Property tests for repair_orphan_pms invariants."""

    @given(resp_set=st_responsibility_set())
    @settings(max_examples=80, deadline=None)
    def test_repair_links_every_orphan_and_keeps_existing_elements(
        self, resp_set: ResponsibilitySet
    ) -> None:
        """Repair warns once per orphan, removes nothing, and leaves no orphan."""
        orphan_count = _count_orphan_pms(resp_set)
        repaired, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == orphan_count
        assert [r.resp_id for r in repaired.responsibilities] == [
            r.resp_id for r in resp_set.responsibilities
        ]
        for orig_resp, rep_resp in zip(
            resp_set.responsibilities,
            repaired.responsibilities,
            strict=True,
        ):
            assert {pm.pm_id for pm in orig_resp.process_model_parts} <= {
                pm.pm_id for pm in rep_resp.process_model_parts
            }
            assert {fb.fb_id for fb in orig_resp.feedback_channels} <= {
                fb.fb_id for fb in rep_resp.feedback_channels
            }
            updated_pms = {fb.updates for fb in rep_resp.feedback_channels}
            for pm in rep_resp.process_model_parts:
                assert pm.pm_id in updated_pms, (
                    f"Orphan PM {pm.pm_id} survived repair in {rep_resp.resp_id}"
                )
        _, warnings_twice = repair_orphan_pms(repaired)
        assert warnings_twice == []

    @given(resp_set=st_no_orphan_responsibility_set())
    @settings(max_examples=50, deadline=None)
    def test_no_op_when_no_orphans(self, resp_set: ResponsibilitySet) -> None:
        """When there are no orphans, the same instance is returned."""
        repaired, warnings = repair_orphan_pms(resp_set)
        assert len(warnings) == 0
        assert repaired is resp_set
