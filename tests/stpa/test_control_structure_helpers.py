"""Unit contracts for the Stage 2 control-structure helpers.

- ``_assign_elements_to_responsibilities``: an element with no matching
  responsibility is not assigned.
- ``_next_fb_num``: the next feedback number is the maximum matching number
  plus one.
- ``_find_orphan_pms``: a process-model part no feedback channel updates.
- ``_add_coordination_links``: an empty link list returns the structure
  unchanged; valid links are added.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
    _add_coordination_links,
    _assign_elements_to_responsibilities,
    _find_orphan_pms,
    _next_fb_num,
)


def _resp(resp_id: str = "RESP-1") -> Responsibility:
    return Responsibility(
        resp_id=resp_id,
        description="Controller",
        process_model_parts=[
            ProcessModelPart(
                pm_id=f"PM-{resp_id.split('-')[-1]}-1", description="State"
            )
        ],
        control_actions=[
            ControlAction(ca_id=f"CA-{resp_id.split('-')[-1]}-1", description="Action")
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{resp_id.split('-')[-1]}-1",
                description="Feedback",
                updates=f"PM-{resp_id.split('-')[-1]}-1",
            )
        ],
    )


# ---------------------------------------------------------------------------
# _assign_elements_to_responsibilities — element with no matching resp
# ---------------------------------------------------------------------------


class TestAssignElementsUnmatched:
    """Element with no matching responsibility is not assigned."""

    def test_unmatched_ca_is_dropped(self):
        """CA whose numeric prefix has no matching RESP is not assigned."""
        resp1 = _resp("RESP-1")
        unmatched_ca = ControlAction(ca_id="CA-99-1", description="Orphan CA")
        _assign_elements_to_responsibilities(
            [unmatched_ca], "ca_id", {1: resp1}, "control_actions"
        )
        assert len(resp1.control_actions) == 1

    def test_unmatched_fb_is_dropped(self):
        """FB whose numeric prefix has no matching RESP is not assigned."""
        resp1 = _resp("RESP-1")
        unmatched_fb = FeedbackChannel(
            fb_id="FB-99-1", description="Orphan FB", updates="PM-99-1"
        )
        _assign_elements_to_responsibilities(
            [unmatched_fb], "fb_id", {1: resp1}, "feedback_channels"
        )
        assert len(resp1.feedback_channels) == 1

    def test_matched_and_unmatched_mixed(self):
        """Mixed elements: matched ones assigned, unmatched dropped."""
        resp1 = _resp("RESP-1")
        resp2 = _resp("RESP-2")
        matched_ca = ControlAction(ca_id="CA-1-2", description="Matched")
        unmatched_ca = ControlAction(ca_id="CA-99-1", description="Unmatched")
        _assign_elements_to_responsibilities(
            [matched_ca, unmatched_ca],
            "ca_id",
            {1: resp1, 2: resp2},
            "control_actions",
        )
        assert len(resp1.control_actions) == 2  # original + matched
        assert len(resp2.control_actions) == 1


# ---------------------------------------------------------------------------
# _next_fb_num — multiple FBs with matching IDs
# ---------------------------------------------------------------------------


def _resp_with_fbs(fb_ids: list[str]) -> Responsibility:
    """A responsibility whose channels bypass validation, like deserialized data."""
    return Responsibility.model_construct(
        resp_id="RESP-1",
        description="Controller",
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
        control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
        feedback_channels=[
            FeedbackChannel.model_construct(
                fb_id=fb_id, description="F", updates="PM-1-1"
            )
            for fb_id in fb_ids
        ],
    )


@pytest.mark.parametrize(
    ("fb_ids", "expected"),
    [
        (["FB-1-1", "FB-1-3", "FB-1-2"], 4),
        (["FB-1-2", "FB-1-5"], 6),
        (["FB-XYZ"], 1),
        ([], 1),
    ],
    ids=["max_plus_one", "gap_is_not_filled", "non_matching_ids", "no_channels"],
)
def test_next_fb_num(fb_ids, expected):
    """The next number follows the largest matching ``FB-<r>-<n>`` id, else 1."""
    assert _next_fb_num(_resp_with_fbs(fb_ids)) == expected


# ---------------------------------------------------------------------------
# _find_orphan_pms — direct test of the not-in condition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pm_ids", "updated_pm_ids", "orphans"),
    [
        (["PM-1-1", "PM-1-2"], [], {"PM-1-1", "PM-1-2"}),
        (["PM-1-1", "PM-1-2"], ["PM-1-1", "PM-1-2"], set()),
        (["PM-1-1", "PM-1-2", "PM-1-3"], ["PM-1-1"], {"PM-1-2", "PM-1-3"}),
    ],
    ids=["all_orphan", "no_orphan", "partial_orphan"],
)
def test_find_orphan_pms(pm_ids, updated_pm_ids, orphans):
    """A process-model part is orphan when no feedback channel updates it."""
    resp = Responsibility(
        resp_id="RESP-1",
        description="Controller",
        process_model_parts=[
            ProcessModelPart(pm_id=pm_id, description="S") for pm_id in pm_ids
        ],
        control_actions=[ControlAction(ca_id="CA-1-1", description="A")],
        feedback_channels=[
            FeedbackChannel(fb_id=f"FB-1-{n}", description="F", updates=pm_id)
            for n, pm_id in enumerate(updated_pm_ids, start=1)
        ],
    )
    assert set(_find_orphan_pms(resp)) == orphans


# ---------------------------------------------------------------------------
# _add_coordination_links
# ---------------------------------------------------------------------------


class TestAddCoordinationLinks:
    """Coordination links are added when Call 3 returns valid ones."""

    def test_empty_links_returns_original(self, tmp_path):
        """Empty coordination links return original CS with no warnings."""
        resp = _resp("RESP-1")
        cs = ControlStructure(responsibilities=[resp])
        analysis = CoordinationAnalysis(
            coordination_links=[],
            integrity_findings=[],
        )

        assert _add_coordination_links(cs, analysis, tmp_path, "test-model") is cs

    def test_valid_links_added(self, tmp_path):
        """Valid coordination links are added to the CS."""
        resp1 = _resp("RESP-1")
        resp2 = _resp("RESP-2")
        cs = ControlStructure(responsibilities=[resp1, resp2])

        link = CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="Coord", payload="data"
            ),
            description="Valid link",
        )
        analysis = CoordinationAnalysis(
            coordination_links=[link],
            integrity_findings=[],
        )

        result_cs = _add_coordination_links(cs, analysis, tmp_path, "test-model")

        assert len(result_cs.coordination_links) == 1
        assert not (tmp_path / "calls.jsonl").exists()
