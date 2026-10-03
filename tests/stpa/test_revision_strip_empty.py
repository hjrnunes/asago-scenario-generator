"""Unit tests for stripping empty responsibilities after revision.

Covers SP1-STRIP-01 through SP1-STRIP-06 from the Gherkin feature file:
  features/sp1_revision_strip_empty.feature

Tests verify that `strip_empty_responsibilities` detects and removes
responsibilities with no PM parts, no CAs, and no FB channels, and
that warnings are returned for each stripped responsibility.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model.critic import (
    strip_empty_responsibilities,
)


def _make_resp(
    resp_id: str,
    description: str = "",
    *,
    with_pm: bool = False,
    with_ca: bool = False,
    with_fb: bool = False,
    with_constraints: bool = False,
) -> Responsibility:
    """Build a responsibility with optional PM/CA/FB/constraints.

    IDs are derived from the resp_id numeric suffix so that multiple
    responsibilities in the same ControlStructure do not collide.
    """
    num = resp_id.split("-")[-1]
    pm_parts = (
        [ProcessModelPart(pm_id=f"PM-{num}-1", description="State")] if with_pm else []
    )
    ca_parts = (
        [ControlAction(ca_id=f"CA-{num}-1", description="Action")] if with_ca else []
    )
    fb_parts = (
        [
            FeedbackChannel(
                fb_id=f"FB-{num}-1",
                description="Feedback",
                updates=f"PM-{num}-1",
                source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
            )
        ]
        if with_fb
        else []
    )
    constraints = (
        [ResponsibilityConstraint(rc_id=f"RC-{num}-1", description="Constraint")]
        if with_constraints
        else []
    )
    return Responsibility(
        resp_id=resp_id,
        description=description,
        responsibility_constraints=constraints,
        process_model_parts=pm_parts,
        control_actions=ca_parts,
        feedback_channels=fb_parts,
    )


def _make_cs(responsibilities: list[Responsibility]) -> ControlStructure:
    """Build a ControlStructure with the given responsibilities."""
    return ControlStructure(responsibilities=responsibilities)


# ---------------------------------------------------------------------------
# SP1-STRIP-01: empty responsibilities are stripped, non-empty are kept
# ---------------------------------------------------------------------------


class TestStripEmptyResponsibilities:
    """SP1-STRIP-01: revision with empty responsibilities strips them."""

    def test_strip_01_empty_stripped_non_empty_kept(self):
        """RESP-2 (all empty) is stripped; RESP-1 (has PM/CA/FB) is kept."""
        cs = _make_cs(
            [
                _make_resp("RESP-1", "Full", with_pm=True, with_ca=True, with_fb=True),
                _make_resp("RESP-2", "Empty"),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        resp_ids = {r.resp_id for r in stripped.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" not in resp_ids


# ---------------------------------------------------------------------------
# SP1-STRIP-02: no empty responsibilities means all preserved
# ---------------------------------------------------------------------------


class TestNoEmptyResponsibilitiesKept:
    """SP1-STRIP-02: all responsibilities preserved when none are empty."""

    def test_strip_02_all_preserved_when_non_empty(self):
        """When every responsibility has PM/CA/FB, all are preserved."""
        cs = _make_cs(
            [
                _make_resp(
                    "RESP-1", "Full A", with_pm=True, with_ca=True, with_fb=True
                ),
                _make_resp(
                    "RESP-3", "Full B", with_pm=True, with_ca=True, with_fb=True
                ),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        assert len(stripped.responsibilities) == 2
        assert warnings == []


# ---------------------------------------------------------------------------
# SP1-STRIP-03: responsibility with some parts is not stripped
# ---------------------------------------------------------------------------


class TestPartialResponsibilityNotStripped:
    """SP1-STRIP-03: a responsibility with PM parts but no CA/FB is kept."""

    def test_strip_03_partial_resp_preserved(self):
        """RESP-3 with PM parts but no CA/FB is not stripped."""
        cs = _make_cs(
            [
                _make_resp("RESP-1", "Full", with_pm=True, with_ca=True, with_fb=True),
                _make_resp("RESP-3", "Partial", with_pm=True),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        resp_ids = {r.resp_id for r in stripped.responsibilities}
        assert "RESP-3" in resp_ids


# ---------------------------------------------------------------------------
# SP1-STRIP-04: warning logged for each stripped responsibility
# ---------------------------------------------------------------------------


class TestWarningForStrippedResponsibilities:
    """SP1-STRIP-04: a warning is logged for each stripped responsibility."""

    def test_strip_04_warnings_for_each_stripped_resp(self):
        """Warnings for RESP-2 and RESP-4 include resp_id and description."""
        cs = _make_cs(
            [
                _make_resp("RESP-1", "Full", with_pm=True, with_ca=True, with_fb=True),
                _make_resp("RESP-2", "Empty A"),
                _make_resp(
                    "RESP-3", "Full B", with_pm=True, with_ca=True, with_fb=True
                ),
                _make_resp("RESP-4", "Empty B"),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        resp_ids = {r.resp_id for r in stripped.responsibilities}
        assert "RESP-2" not in resp_ids
        assert "RESP-4" not in resp_ids
        # Each warning contains resp_id and description
        warning_text = " | ".join(warnings)
        assert "RESP-2" in warning_text
        assert "Empty A" in warning_text
        assert "RESP-4" in warning_text
        assert "Empty B" in warning_text


# ---------------------------------------------------------------------------
# SP1-STRIP-05: stripped control structure passes validation
# ---------------------------------------------------------------------------


class TestStrippedControlStructureValid:
    """SP1-STRIP-05: the stripped control structure is valid and non-empty."""

    def test_strip_05_stripped_cs_has_at_least_one_resp(self):
        """After stripping RESP-7, the control structure still has responsibilities."""
        cs = _make_cs(
            [
                _make_resp("RESP-1", "Full", with_pm=True, with_ca=True, with_fb=True),
                _make_resp("RESP-7", "Empty"),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        resp_ids = {r.resp_id for r in stripped.responsibilities}
        assert "RESP-7" not in resp_ids
        assert len(stripped.responsibilities) >= 1


# ---------------------------------------------------------------------------
# SP1-STRIP-06: responsibility with only constraints but no PM/CA/FB is stripped
# ---------------------------------------------------------------------------


class TestConstraintsOnlyResponsibilityStripped:
    """SP1-STRIP-06: constraints alone do not prevent stripping."""

    def test_strip_06_constraints_only_stripped(self):
        """RESP-5 with constraints but no PM/CA/FB is stripped."""
        cs = _make_cs(
            [
                _make_resp("RESP-1", "Full", with_pm=True, with_ca=True, with_fb=True),
                _make_resp("RESP-5", "Constraints only", with_constraints=True),
            ]
        )
        stripped, warnings = strip_empty_responsibilities(cs)
        resp_ids = {r.resp_id for r in stripped.responsibilities}
        assert "RESP-5" not in resp_ids
