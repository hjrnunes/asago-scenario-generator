"""Property tests for the CLI ``generate`` exit-code policy.

``_default_generate_exit_code`` maps a manifest status and the count of
admitted candidates to the process exit code of the ``generate`` command.
These properties pin the policy over the whole input domain: it must stay
total and binary, and the failure semantics (degraded completion or an
empty admission) must hold for any status string the manifest may report
in the future.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.cli import _default_generate_exit_code
from asago_scenario_generator.manifest import RunStatus

# Real statuses the manifest can report, plus arbitrary strings so the
# policy stays total for future or unknown status values.
st_status = st.one_of(
    st.sampled_from([status.value for status in RunStatus]),
    st.text(),
)
st_admitted = st.integers(min_value=0, max_value=1_000_000)


@given(status=st_status, admitted=st_admitted)
@settings(max_examples=200, deadline=None)
def test_exit_code_is_total_and_binary(status: str, admitted: int) -> None:
    """Every legal input maps to exactly 0 or 1 without raising."""
    assert _default_generate_exit_code(status, admitted) in (0, 1)


@given(status=st_status, admitted=st.integers(min_value=1, max_value=1_000_000))
@settings(max_examples=200, deadline=None)
def test_nonempty_admission_fails_only_on_error_status(
    status: str, admitted: int
) -> None:
    """A run that admitted candidates fails only when completion reports errors."""
    assert _default_generate_exit_code(status, admitted) == (
        1 if status == RunStatus.COMPLETED_WITH_ERRORS.value else 0
    )


@given(status=st_status)
@settings(max_examples=100, deadline=None)
def test_empty_admission_always_fails(status: str) -> None:
    """A run that admitted no candidates fails regardless of status."""
    assert _default_generate_exit_code(status, 0) == 1
