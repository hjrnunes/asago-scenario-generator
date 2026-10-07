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

from asago_scenario_generator.stpa.observation_contract import ObservationContract
from .records import Stage5Normalization
from .validate import _replace_safe_outcome

ConditionRoute = Literal["analytical_only"]

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


@dataclass(frozen=True)
class RoutedDraft:
    """A draft moved off its command-attempt claim, with the changes recorded."""

    draft: BaseModel
    route: ConditionRoute
    normalizations: tuple[Stage5Normalization, ...]


def route_reason(route: ConditionRoute, failure_code: str) -> str:
    """Return the normalization reason that names a route and its failure code."""

    return f"condition_dropped_{route}:{failure_code}"


def route_without_condition(
    draft: BaseModel,
    contract: ObservationContract,
    failure_code: str,
) -> RoutedDraft | None:
    """Move a condition-less command-attempt draft to a claim it can run at.

    Returns ``None`` when the safe outcome is not an observable command
    attempt, so every other draft publishes unchanged.
    """

    safe_outcome = draft.unsafe_outcome.safe_observable_outcome
    if (
        safe_outcome is None
        or not safe_outcome.observable
        or safe_outcome.claim_level != _COMMAND_ATTEMPT
    ):
        return None
    route: ConditionRoute = "analytical_only"
    reason = route_reason(route, failure_code)
    routed = copy.deepcopy(draft)
    outcome = routed.unsafe_outcome
    normalizations: list[Stage5Normalization] = []
    outcome.safe_observable_outcome = _replace_safe_outcome(
        safe_outcome,
        _ANALYTICAL_SAFE_OUTCOME,
        reason=reason,
        normalizations=normalizations,
    )
    outcome.observation_criteria = [
        _demoted(criterion, index, reason, normalizations)
        for index, criterion in enumerate(outcome.observation_criteria)
    ]
    return RoutedDraft(routed, route, tuple(normalizations))


def _demoted(
    criterion: BaseModel,
    index: int,
    reason: str,
    normalizations: list[Stage5Normalization],
) -> BaseModel:
    """Return the criterion as an analytical one, recording each changed field."""

    if not criterion.observable:
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
