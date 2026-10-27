"""Check that a discriminating condition agrees with its own scenario.

The condition check (``condition_check``) asks whether a condition resolves
and separates an unsafe call from a safe one. The checks here compare the
condition with structured fields of its own scenario:

- An ``INCORRECT`` unsafe control action is provided incorrectly, so the
  unsafe behavior calls the action's operation. A ``not_called`` on that
  operation holds only when the call never happens, which is the safe
  behavior: the condition detects the opposite of the failure. This check
  runs only when the safe outcome claims a ``command_attempt``, which the
  consumer scores with the bound tool-call condition.
- A failure criterion whose failure call is an ``incorrect_call`` of an
  operation states the same of that operation, whatever the category of the
  control action, whether or not it maps to an operation, and whatever the
  safe outcome claims, so a ``not_called`` on it is refused as well: the
  failure call alone proves that the unsafe behavior is that call.
- The condition routing applies the same ``not_called`` rule
  (:func:`not_called_inversion`) before it derives ``not_called`` from a
  missing call, so code never publishes a predicate this check refuses.
- A condition with no call-level part binds as ``state_only``: it names no
  call, so a command-attempt claim has no tool-call condition to run. This
  check runs only under a ``command_attempt`` safe outcome.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
    NotCalledComparison,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import (
    FailureCall,
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.tool_call_condition import REASON_STATE_ONLY

from ..condition_check import ConditionFinding
from ..tool_call_binding import bind_tool_call_condition
from .issues import IssueCode


@dataclass(frozen=True)
class ConditionClaim:
    """The scenario fields a discriminating condition must agree with.

    ``unsafe_operation`` is the exact operation the selected control action
    maps to, or ``None`` when it maps to none. ``failure_call`` is the call
    the failure criterion is about, when it states one.
    """

    uca_type: UCAType
    unsafe_operation: str | None
    safe_outcome: SafeObservableOutcome | None
    failure_call: FailureCall | None = None


def condition_claim_findings(
    condition: DiscriminatingCondition,
    fact_values: Mapping[str, object],
    *,
    uca_type: UCAType,
    unsafe_operation: str | None,
    safe_outcome: SafeObservableOutcome | None,
    failure_call: FailureCall | None = None,
) -> tuple[ConditionFinding, ...]:
    """Return where a condition contradicts its scenario.

    The keyword arguments are the fields of :class:`ConditionClaim`. Only the
    failure call is judged without a ``command_attempt`` safe outcome.
    """

    claim = ConditionClaim(uca_type, unsafe_operation, safe_outcome, failure_call)
    inverted = tuple(_inverted_not_called(condition, claim))
    if not _claims_command_attempt(safe_outcome):
        return inverted
    return (*inverted, *_no_call(condition, fact_values, safe_outcome.operation_name))


def _claims_command_attempt(safe_outcome: SafeObservableOutcome | None) -> bool:
    return (
        safe_outcome is not None
        and safe_outcome.observable
        and safe_outcome.claim_level == "command_attempt"
    )


def not_called_inversion(operation: str, claim: ConditionClaim) -> str | None:
    """Return why ``not_called`` on ``operation`` detects the safe behavior, if it does.

    That operation is the one an INCORRECT action calls (judged only under a
    ``command_attempt`` safe outcome), or the one the failure criterion
    states an incorrect call of. Returns ``None`` when ``not_called`` on it
    agrees with the scenario.
    """

    unsafe_operation = (
        claim.unsafe_operation if _claims_command_attempt(claim.safe_outcome) else None
    )
    failure_call = claim.failure_call
    if claim.uca_type == UCAType.incorrect and operation == unsafe_operation:
        return (
            f"the unsafe control action provides {operation} incorrectly "
            f"(category {UCAType.incorrect.value})"
        )
    if (
        failure_call is not None
        and failure_call.kind == "incorrect_call"
        and operation == failure_call.operation_name
    ):
        return (
            f"the failure criterion states an incorrect call of {operation} "
            "(failure_call kind incorrect_call)"
        )
    return None


def _inverted_not_called(
    condition: DiscriminatingCondition, claim: ConditionClaim
) -> Iterator[ConditionFinding]:
    """Flag a not_called on an operation whose call is the unsafe behavior."""

    for index, comparison in enumerate(condition.comparisons):
        if not isinstance(comparison, NotCalledComparison):
            continue
        operation = comparison.operation
        reason = not_called_inversion(operation, claim)
        if reason is None:
            continue
        yield ConditionFinding(
            IssueCode.discriminating_condition_polarity_inverted,
            f"comparisons[{index}] is not_called {operation}, but {reason}, so "
            f"the unsafe behavior is a call of {operation}. not_called holds "
            f"only when {operation} is never called, which is the safe "
            "behavior. State what makes that call unsafe instead: compare "
            f"an argument of {operation} with a supplied value, or "
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
        IssueCode.discriminating_condition_no_call,
        f"{status.detail}, but the safe outcome claims a command_attempt on "
        f"{named}, which is checked on tool calls. Add a comparison on an "
        f"argument of {named}, or name in record_selection.argument_values "
        f"the {named} argument that selects the record the comparisons "
        "describe",
    )
