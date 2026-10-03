"""Property-based tests for strip_empty_responsibilities invariants.

These tests verify invariants that hold across broad input ranges:

- **Idempotence**: stripping twice yields the same result as stripping once.
- **No empty survives**: every responsibility in the output has at least one
  PM part, control action, or feedback channel.
- **Order preservation**: kept responsibilities maintain their relative order.
- **Warning-stripped correspondence**: the number of warnings equals the
  number of responsibilities removed.
- **No-op identity**: when nothing is stripped, the returned object is the
  same instance (identity preserved).
- **Subset preservation**: output resp_ids are a subset of input resp_ids.
- **Kept responsibilities unchanged**: kept responsibilities are identical
  to their input counterparts (same field values).
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

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Idempotence: strip(strip(cs)) == strip(cs)
# ---------------------------------------------------------------------------


class TestStripIdempotence:
    """Stripping twice produces the same result as stripping once."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_strip_is_idempotent(self, cs):
        """strip(strip(cs)) has the same resp_ids as strip(cs)."""
        stripped_once, _ = strip_empty_responsibilities(cs)
        stripped_twice, _ = strip_empty_responsibilities(stripped_once)
        ids_once = [r.resp_id for r in stripped_once.responsibilities]
        ids_twice = [r.resp_id for r in stripped_twice.responsibilities]
        assert ids_once == ids_twice


# ---------------------------------------------------------------------------
# No empty survives: every output responsibility is non-empty
# ---------------------------------------------------------------------------


class TestNoEmptySurvives:
    """No responsibility in the output is empty."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_no_empty_in_output(self, cs):
        """Every responsibility in the stripped output is non-empty."""
        stripped, _ = strip_empty_responsibilities(cs)
        for resp in stripped.responsibilities:
            assert not _is_responsibility_empty(resp), (
                f"Empty responsibility {resp.resp_id} survived stripping"
            )


# ---------------------------------------------------------------------------
# Order preservation: kept responsibilities maintain relative order
# ---------------------------------------------------------------------------


class TestOrderPreservation:
    """Kept responsibilities maintain their input relative order."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_relative_order_preserved(self, cs):
        """The output resp_ids are a subsequence of the input resp_ids."""
        stripped, _ = strip_empty_responsibilities(cs)
        input_ids = [r.resp_id for r in cs.responsibilities]
        output_ids = [r.resp_id for r in stripped.responsibilities]
        # output_ids must be a subsequence of input_ids
        idx = 0
        for oid in output_ids:
            idx = input_ids.index(oid, idx) + 1
        # If we reach here without ValueError, order is preserved


# ---------------------------------------------------------------------------
# Warning-stripped correspondence: len(warnings) == count of stripped
# ---------------------------------------------------------------------------


class TestWarningStrippedCorrespondence:
    """The number of warnings equals the number of stripped responsibilities."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_warning_count_equals_stripped_count(self, cs):
        """len(warnings) == number of responsibilities removed."""
        stripped, warnings = strip_empty_responsibilities(cs)
        stripped_count = len(cs.responsibilities) - len(stripped.responsibilities)
        assert len(warnings) == stripped_count


# ---------------------------------------------------------------------------
# No-op identity: when nothing stripped, same object returned
# ---------------------------------------------------------------------------


class TestNoOpIdentity:
    """When no responsibilities are empty, the same object is returned."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_no_op_returns_same_object(self, cs):
        """When nothing is stripped, the returned object is identical."""
        stripped, warnings = strip_empty_responsibilities(cs)
        if len(warnings) == 0:
            assert stripped is cs, (
                "No-op strip should return the same object (identity preserved)"
            )


# ---------------------------------------------------------------------------
# Subset preservation: output resp_ids ⊆ input resp_ids
# ---------------------------------------------------------------------------


class TestSubsetPreservation:
    """Output resp_ids are a subset of input resp_ids."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_output_ids_subset_of_input(self, cs):
        """Every output resp_id was in the input."""
        stripped, _ = strip_empty_responsibilities(cs)
        input_ids = {r.resp_id for r in cs.responsibilities}
        output_ids = {r.resp_id for r in stripped.responsibilities}
        assert output_ids <= input_ids


# ---------------------------------------------------------------------------
# Kept responsibilities unchanged: identical field values
# ---------------------------------------------------------------------------


class TestKeptResponsibilitiesUnchanged:
    """Kept responsibilities have the same field values as their input."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_kept_resps_unchanged(self, cs):
        """Each kept responsibility has identical fields to its input counterpart."""
        stripped, _ = strip_empty_responsibilities(cs)
        input_by_id = {r.resp_id: r for r in cs.responsibilities}
        for resp in stripped.responsibilities:
            original = input_by_id[resp.resp_id]
            assert resp.resp_id == original.resp_id
            assert resp.description == original.description
            assert (
                resp.responsibility_constraints == original.responsibility_constraints
            )
            assert resp.process_model_parts == original.process_model_parts
            assert resp.control_actions == original.control_actions
            assert resp.feedback_channels == original.feedback_channels


# ---------------------------------------------------------------------------
# Conservation: stripped count == count of empty input responsibilities
# ---------------------------------------------------------------------------


class TestStrippedCountConservation:
    """The number of stripped responsibilities equals the empty input count."""

    @given(cs=st_control_structure())
    @settings(max_examples=80, deadline=None)
    def test_stripped_equals_empty_input(self, cs):
        """len(input) - len(output) == count of empty responsibilities in input."""
        stripped, _ = strip_empty_responsibilities(cs)
        empty_count = sum(1 for r in cs.responsibilities if _is_responsibility_empty(r))
        stripped_count = len(cs.responsibilities) - len(stripped.responsibilities)
        assert stripped_count == empty_count
