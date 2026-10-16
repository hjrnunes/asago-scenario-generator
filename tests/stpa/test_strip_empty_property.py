"""Property-based tests for strip_empty_responsibilities invariants.

The output must equal the input filtered by ``_is_responsibility_empty``,
in input order and with each kept responsibility unchanged. That one
oracle implies idempotence, that no empty responsibility survives, and
that output IDs are an ordered subset of the input. Each removal yields
one warning, and when nothing is removed the same object is returned.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

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
    _is_responsibility_empty,
    strip_empty_responsibilities,
)


st_description = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)


def _make_resp(
    num: int,
    description: str,
    *,
    with_pm: bool,
    with_ca: bool,
    with_fb: bool,
    with_constraints: bool,
) -> Responsibility:
    """Build a valid responsibility for RESP-{num}.

    IDs are derived from *num* so multiple responsibilities in the same
    ControlStructure never collide.  FB channels require a PM in the
    same responsibility (FB.updates references a PM), so *with_fb*
    implies *with_pm* at the call site.
    """
    resp_id = f"RESP-{num}"
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


@st.composite
def st_control_structure(draw) -> ControlStructure:
    """Generate a valid ControlStructure with 1-6 responsibilities.

    Each responsibility independently has:
    - Optional PM parts.
    - Optional CA parts.
    - Optional FB channels (only if PM is present — FB.updates references PM).
    - Optional responsibility_constraints.

    This produces a mix of empty, partial, and full responsibilities,
    which is exactly the input space ``strip_empty_responsibilities``
    must handle.
    """
    n = draw(st.integers(min_value=1, max_value=6))
    responsibilities: list[Responsibility] = []
    for i in range(1, n + 1):
        desc = draw(st_description)
        has_pm = draw(st.booleans())
        has_ca = draw(st.booleans())
        # FB requires PM (FB.updates must reference a PM in the same resp)
        has_fb = has_pm and draw(st.booleans())
        has_constraints = draw(st.booleans())
        responsibilities.append(
            _make_resp(
                i,
                desc,
                with_pm=has_pm,
                with_ca=has_ca,
                with_fb=has_fb,
                with_constraints=has_constraints,
            )
        )
    return ControlStructure(responsibilities=responsibilities)


class TestStripEmptyResponsibilities:
    """Stripping is a filter that drops exactly the empty responsibilities."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_strip_keeps_exactly_the_non_empty_responsibilities(self, cs):
        """Output equals the order-preserving filter; one warning per removal."""
        stripped, warnings = strip_empty_responsibilities(cs)
        kept = [r for r in cs.responsibilities if not _is_responsibility_empty(r)]
        assert stripped.responsibilities == kept
        assert len(warnings) == len(cs.responsibilities) - len(kept)
        if len(kept) == len(cs.responsibilities):
            assert stripped is cs
