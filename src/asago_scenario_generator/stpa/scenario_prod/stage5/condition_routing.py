"""Route a command-attempt scenario that lost its discriminating condition.

A ``command_attempt`` claim is scored by a tool-call condition over the
captured arguments. A scenario whose condition failed after the one
correction has none, so publishing the claim leaves the consumer nothing to
execute. The routing below is deterministic code over the response the model
already wrote: no model request and no text the model did not author.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from asago_scenario_generator.stpa.observation_contract import (
    ObservationContract,
    ObservationCriterion,
    SafeObservableOutcome,
    assess_observation_criteria,
)
from .records import Stage5Normalization
from .validate import _replace_safe_outcome

ConditionRoute = Literal["reply", "analytical_only"]

_COMMAND_ATTEMPT = "command_attempt"
_CRITERION_FIELDS = ("observable", "claim_level", "evidence", "operation_name")
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


def _route_reason(route: ConditionRoute, failure_code: str) -> str:
    """Return the normalization reason that names a route and its failure code."""

    return f"condition_dropped_{route}:{failure_code}"


def route_without_condition(
    draft: BaseModel,
    contract: ObservationContract,
    failure_code: str,
) -> RoutedDraft | None:
    """Move a condition-less command-attempt draft to a claim it can run at.

    Returns ``None`` when the safe outcome is not an observable command
    attempt, so every other draft publishes unchanged. The draft goes to
    ``reply`` when the response itself declares a reply criterion the contract
    supports, and to ``analytical_only`` otherwise: a reply claim needs the
    model's own reply-level observation, and code never writes one.
    """

    safe_outcome = draft.unsafe_outcome.safe_observable_outcome
    if not _is_command_attempt(safe_outcome):
        return None
    route: ConditionRoute = (
        "reply"
        if _declares_supported_reply(draft.unsafe_outcome, contract)
        else "analytical_only"
    )
    reason = _route_reason(route, failure_code)
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
        _demoted(criterion, index, route, reason, normalizations)
        for index, criterion in enumerate(outcome.observation_criteria)
    ]
    return RoutedDraft(routed, route, tuple(normalizations))


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
    supported = set(assess_observation_criteria(criteria, contract).supported_criteria)
    return any(
        item.criterion_id in supported and item.claim_level == "reply"
        for item in criteria
    )


def _stops_observing(criterion: BaseModel, route: ConditionRoute) -> bool:
    if not criterion.observable:
        return False
    return route == "analytical_only" or criterion.claim_level == _COMMAND_ATTEMPT


def _demoted(
    criterion: BaseModel,
    index: int,
    route: ConditionRoute,
    reason: str,
    normalizations: list[Stage5Normalization],
) -> BaseModel:
    """Return the criterion as an analytical one when the route stops observing it.

    The analytical route observes no criterion; the reply route observes every
    criterion except a command attempt, which has no condition to run on.
    """

    if not _stops_observing(criterion, route):
        return criterion
    cleared = criterion.model_copy(
        update={
            "observable": False,
            "claim_level": None,
            "evidence": None,
            "operation_name": None,
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
