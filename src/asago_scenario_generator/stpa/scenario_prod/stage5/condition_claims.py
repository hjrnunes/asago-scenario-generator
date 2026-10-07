"""Check that a discriminating condition agrees with its own command-attempt claim.

The condition check (``condition_check``) asks whether a condition resolves
and separates an unsafe call from a safe one. The checks here compare the
condition with structured fields of its own scenario, and run only when the
safe outcome claims a ``command_attempt``, which the consumer scores with the
bound tool-call condition:

- An ``INCORRECT`` unsafe control action is provided incorrectly, so the
  unsafe behavior calls the action's operation. A ``not_called`` on that
  operation holds only when the call never happens, which is the safe
  behavior: the condition detects the opposite of the failure.
- A condition with no call-level part binds as ``state_only``: it names no
  call, so the command-attempt claim has no tool-call condition to run.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
    NotCalledComparison,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.tool_call_condition import REASON_STATE_ONLY

from ..condition_check import ConditionFinding
from ..tool_call_binding import bind_tool_call_condition

POLARITY_INVERTED = "discriminating_condition_polarity_inverted"
NO_CALL = "discriminating_condition_no_call"


def condition_claim_findings(
    condition: DiscriminatingCondition,
    fact_values: Mapping[str, object],
    *,
    uca_type: UCAType,
    unsafe_operation: str | None,
    safe_outcome: SafeObservableOutcome | None,
) -> tuple[ConditionFinding, ...]:
    """Return where a condition contradicts its scenario's command-attempt claim.

    ``unsafe_operation`` is the exact operation the selected control action
    maps to, or ``None`` when it maps to none.
    """

    if (
        safe_outcome is None
        or not safe_outcome.observable
        or safe_outcome.claim_level != "command_attempt"
    ):
        return ()
    return (
        *_inverted_not_called(condition, uca_type, unsafe_operation),
        *_no_call(condition, fact_values, safe_outcome.operation_name),
    )


def _inverted_not_called(
    condition: DiscriminatingCondition,
    uca_type: UCAType,
    unsafe_operation: str | None,
) -> Iterator[ConditionFinding]:
    """Flag a not_called on the operation an INCORRECT action calls."""

    if uca_type != UCAType.incorrect or unsafe_operation is None:
        return
    for index, comparison in enumerate(condition.comparisons):
        if (
            isinstance(comparison, NotCalledComparison)
            and comparison.operation == unsafe_operation
        ):
            yield ConditionFinding(
                POLARITY_INVERTED,
                f"comparisons[{index}] is not_called {unsafe_operation}, but the "
                f"unsafe control action provides {unsafe_operation} incorrectly "
                f"(category {UCAType.incorrect.value}), so the unsafe behavior "
                f"is a call of {unsafe_operation}. not_called holds only when "
                f"{unsafe_operation} is never called, which is the safe "
                "behavior. State what makes that call unsafe instead: compare "
                f"an argument of {unsafe_operation} with a supplied value, or "
                "select the record the unsafe call acts on",
            )


def _no_call(
    condition: DiscriminatingCondition,
    fact_values: Mapping[str, object],
    operation: str | None,
) -> Iterator[ConditionFinding]:
    """Flag a condition that binds as state_only under a command-attempt claim."""

    status = bind_tool_call_condition(condition, fact_values).status
    if status.reason != REASON_STATE_ONLY:
        return
    named = operation or "the claimed operation"
    yield ConditionFinding(
        NO_CALL,
        f"{status.detail}, but the safe outcome claims a command_attempt on "
        f"{named}, which is checked on tool calls. Add a comparison on an "
        f"argument of {named}, or name in record_selection.argument_values "
        f"the {named} argument that selects the record the comparisons "
        "describe",
    )
