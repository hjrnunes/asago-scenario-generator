"""Route a command-attempt scenario that lost its discriminating condition.

A ``command_attempt`` claim is scored by a tool-call condition over the
captured arguments. A scenario whose condition failed after the one
correction has none, so publishing the claim leaves the consumer nothing to
execute. The routing below is deterministic code over the response the model
already wrote: no model request. Code writes no reply wording; the only text
it adds is the note on a criterion it withdrew.

A failure call of an operation the target records is observed whatever the
condition, so such a draft keeps its command-attempt claim: a failed
condition never makes an observable call analytical. When that failure call
is a missing call, the failure is that the operation is never called, and
code derives the tool-call condition ``not_called(<operation>)`` from it,
recorded as a normalization, unless the condition check would refuse that
``not_called`` as detecting the safe behavior (``not_called_inversion``): an
INCORRECT action that provides the same operation. An incorrect call says
only that the call is wrong, not what makes it wrong, so code derives
nothing for it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import (
    FailureCall,
    ObservationContract,
    ObservationCriterion,
    SafeObservableOutcome,
    failure_call_criterion,
    supports_reply_criterion,
)
from ..tool_call_binding import ToolCallBinding, bind_missing_call
from .condition_claims import ConditionClaim, not_called_inversion
from .records import Stage5Normalization
from .validate import _replace_safe_outcome

ConditionRoute = Literal["reply", "failure_call", "analytical_only"]

_COMMAND_ATTEMPT = "command_attempt"
_MISSING_CALL = "missing_call"
# The reason of the record of a condition derived from a missing call.
MISSING_CALL_CONDITION_REASON = "missing_call_of_recorded_operation"
_CRITERION_FIELDS = (
    "observable",
    "claim_level",
    "evidence",
    "operation_name",
    "reason",
)
_DEMOTION_NOTES: dict[ConditionRoute, str] = {
    "analytical_only": (
        "Not observable: the discriminating condition failed validation "
        "({code}), so the scenario is published as analytical_only and no "
        "criterion is observed."
    ),
    "reply": (
        "Not observable: the claim is command_attempt and the discriminating "
        "condition failed validation ({code}), so it has no condition to run on."
    ),
}
_ANALYTICAL_SAFE_OUTCOME = {
    "observable": False,
    "claim_level": None,
    "evidence": None,
    "operation_name": None,
    "record_refs": (),
    "fact_refs": (),
}
_REPLY_SAFE_OUTCOME = {
    "claim_level": "reply",
    "evidence": "assistant_message",
    "operation_name": None,
}


@dataclass(frozen=True)
class RoutedDraft:
    """A draft moved off its command-attempt claim, with the changes recorded."""

    draft: BaseModel
    route: ConditionRoute
    normalizations: tuple[Stage5Normalization, ...]
    # The code-derived tool-call condition the draft publishes; None when
    # code derived none.
    binding: ToolCallBinding | None = None


def _route_reason(route: ConditionRoute, failure_code: str) -> str:
    """Return the normalization reason that names a route and its failure code."""

    return f"condition_dropped_{route}:{failure_code}"


def condition_removal(
    original: object, route: ConditionRoute | None, failure_code: str
) -> tuple[Stage5Normalization, ...]:
    """Return the record of a failed condition code removed before routing.

    ``original`` is the condition as the reply returned it; a reply that
    returned none has nothing to record. The reason names the route the
    draft took (``condition_dropped:<code>`` when it took none) and the
    failure code, like the route's own records.
    """

    if original is None:
        return ()
    reason = (
        f"condition_dropped:{failure_code}"
        if route is None
        else _route_reason(route, failure_code)
    )
    return (
        Stage5Normalization(
            field="discriminating_condition",
            original=original,
            normalized=None,
            reason=reason,
        ),
    )


def route_without_condition(
    draft: BaseModel,
    contract: ObservationContract,
    failure_code: str,
    *,
    uca_type: UCAType,
    unsafe_operation: str | None,
    recorded_operations: tuple[str, ...] = (),
) -> RoutedDraft | None:
    """Move a condition-less command-attempt draft to a claim it can run at.

    Returns ``None`` when the safe outcome is not an observable command
    attempt, so every other draft publishes unchanged. The draft goes to
    ``reply`` when the response itself declares a reply criterion the contract
    supports: a reply claim needs the model's own reply-level observation,
    and code never writes one. Otherwise a draft whose failure call names one
    of ``recorded_operations`` takes the ``failure_call`` route, which keeps
    the draft unchanged (a missing call also gets its derived condition), and
    every other draft goes to ``analytical_only``. ``uca_type`` and
    ``unsafe_operation`` (the operation the control action maps to, if any)
    are the scenario fields the condition check judges a ``not_called`` by.
    """

    outcome = draft.unsafe_outcome
    safe_outcome = outcome.safe_observable_outcome
    if not _is_command_attempt(safe_outcome):
        return None
    failure_call = getattr(outcome, "failure_call", None)
    if _declares_supported_reply(outcome, contract):
        route: ConditionRoute = "reply"
    elif failure_call_criterion(failure_call, contract, recorded_operations):
        claim = ConditionClaim(uca_type, unsafe_operation, safe_outcome, failure_call)
        return _failure_call_route(draft, claim)
    else:
        route = "analytical_only"
    reason = _route_reason(route, failure_code)
    note = _DEMOTION_NOTES[route].format(code=failure_code)
    routed = copy.deepcopy(draft)
    outcome = routed.unsafe_outcome
    normalizations: list[Stage5Normalization] = []
    outcome.safe_observable_outcome = _replace_safe_outcome(
        safe_outcome,
        _REPLY_SAFE_OUTCOME if route == "reply" else _ANALYTICAL_SAFE_OUTCOME,
        reason=reason,
        normalizations=normalizations,
    )
    outcome.observation_criteria = [
        _demoted(criterion, index, route, reason, note, normalizations)
        for index, criterion in enumerate(outcome.observation_criteria)
    ]
    return RoutedDraft(routed, route, tuple(normalizations))


def _failure_call_route(draft: BaseModel, claim: ConditionClaim) -> RoutedDraft:
    """Keep the draft; derive ``not_called`` when its failure call is a missing call.

    The caller has checked that the target records the operation and that
    the contract captures tool calls at ``command_attempt``. Code derives no
    ``not_called`` the condition check refuses for ``claim``: the draft then
    publishes without a condition, as an incorrect call does.
    """

    failure_call: FailureCall = claim.failure_call
    if (
        failure_call.kind != _MISSING_CALL
        or not_called_inversion(failure_call.operation_name, claim) is not None
    ):
        return RoutedDraft(copy.deepcopy(draft), "failure_call", ())
    binding = bind_missing_call(failure_call.operation_name)
    record = Stage5Normalization(
        field="tool_call_condition",
        original=None,
        normalized=binding.condition.model_dump(mode="json"),
        reason=MISSING_CALL_CONDITION_REASON,
    )
    return RoutedDraft(copy.deepcopy(draft), "failure_call", (record,), binding)


def _is_command_attempt(safe_outcome: SafeObservableOutcome | None) -> bool:
    return (
        safe_outcome is not None
        and safe_outcome.observable
        and safe_outcome.claim_level == _COMMAND_ATTEMPT
    )


def _declares_supported_reply(
    outcome: BaseModel, contract: ObservationContract
) -> bool:
    """Return whether the response declares a reply criterion the contract supports."""

    criteria = [
        ObservationCriterion.model_validate(item.model_dump(mode="json"))
        for item in outcome.observation_criteria
    ]
    return supports_reply_criterion(criteria, contract)


def _stops_observing(criterion: BaseModel, route: ConditionRoute) -> bool:
    if not criterion.observable:
        return False
    return route == "analytical_only" or criterion.claim_level == _COMMAND_ATTEMPT


def _demoted(
    criterion: BaseModel,
    index: int,
    route: ConditionRoute,
    reason: str,
    note: str,
    normalizations: list[Stage5Normalization],
) -> BaseModel:
    """Return the criterion as an analytical one when the route stops observing it.

    The analytical route observes no criterion; the reply route observes every
    criterion except a command attempt, which has no condition to run on. The
    model's ``reason`` justified the observable claim code just withdrew, so
    the criterion carries ``note`` instead and the record keeps the original.
    """

    if not _stops_observing(criterion, route):
        return criterion
    cleared = criterion.model_copy(
        update={
            "observable": False,
            "claim_level": None,
            "evidence": None,
            "operation_name": None,
            "reason": note,
        }
    )
    normalizations.extend(
        Stage5Normalization(
            field=f"observation_criteria[{index}].{name}",
            original=getattr(criterion, name),
            normalized=getattr(cleared, name),
            reason=reason,
        )
        for name in _CRITERION_FIELDS
        if getattr(criterion, name) != getattr(cleared, name)
    )
    return cleared
