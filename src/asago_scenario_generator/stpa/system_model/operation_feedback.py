"""Model the result an invoked operation returns as feedback to its caller.

Stage 2 derives feedback only as the update of a process-model part, and
Call 2a derives those parts before any action exists.  No part holds what
the controller learns from the operations it invokes, so the result of a
tool call never appears as feedback from the process the call acts on.

The discovered evidence states the missing fact: an observed operation that
declares an output returns that output to the caller.  For each tool-call
action bound to such an operation, on a process from which the issuing
responsibility has no feedback channel, this step adds the channel
(``source_kind: operation_result``, sourced from the action's target) and the
variable it updates.  Everything the evidence leaves open stays unset: the
variable has no values and no action depends on it, and the channel carries
no authority assessment.
"""

from __future__ import annotations

import re

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.target_evidence import TargetEvidence

_TRAILING_NUMBER = re.compile(r"-(\d+)$")


def _next_number(ids: list[str]) -> int:
    numbers = [
        int(match.group(1)) for item in ids if (match := _TRAILING_NUMBER.search(item))
    ]
    return max(numbers, default=0) + 1


def _observed_processes(responsibility: Responsibility) -> set[str]:
    return {
        channel.source.id
        for channel in responsibility.feedback_channels
        if channel.source is not None
        and channel.source.type is ReferenceType.controlled_process
    }


def _unobserved_result_actions(
    responsibility: Responsibility, result_operations: frozenset[str]
) -> list[ControlAction]:
    observed = _observed_processes(responsibility)
    return [
        action
        for action in responsibility.control_actions
        if action.effect_kind is ControlActionEffectKind.tool_call
        and action.operation in result_operations
        and action.target is not None
        and action.target.type is ReferenceType.controlled_process
        and action.target.id not in observed
    ]


def _with_result_feedback(
    responsibility: Responsibility, actions: list[ControlAction]
) -> Responsibility:
    resp_number = responsibility.resp_id.removeprefix("RESP-")
    parts = list(responsibility.process_model_parts)
    channels = list(responsibility.feedback_channels)
    pm_number = _next_number([part.pm_id for part in parts])
    fb_number = _next_number([channel.fb_id for channel in channels])
    for action in actions:
        pm_id = f"PM-{resp_number}-{pm_number}"
        parts.append(
            ProcessModelPart(
                pm_id=pm_id,
                description=(
                    f"Outcome of {action.ca_id} as the result of operation "
                    f"`{action.operation}` reports it"
                ),
            )
        )
        channels.append(
            FeedbackChannel(
                fb_id=f"FB-{resp_number}-{fb_number}",
                description=(
                    f"Result that operation `{action.operation}` returns to "
                    f"this responsibility for {action.ca_id}"
                ),
                updates=pm_id,
                source=action.target,
                source_kind=FeedbackSourceKind.operation_result,
            )
        )
        pm_number += 1
        fb_number += 1
    return responsibility.model_copy(
        update={"process_model_parts": parts, "feedback_channels": channels},
        deep=True,
    )


def add_operation_result_feedback(
    control_structure: ControlStructure, evidence: TargetEvidence | None
) -> ControlStructure:
    """Return the structure with each unmodelled operation result as feedback.

    A responsibility gains one variable and one channel per tool-call action
    whose bound operation declares an output and whose target process sends
    it no feedback.  Without such an action the input is returned as it is;
    the input is never mutated.
    """
    if evidence is None:
        return control_structure
    result_operations = frozenset(
        item.name for item in evidence.operations if item.returns_result
    )
    changed = False
    responsibilities: list[Responsibility] = []
    for responsibility in control_structure.responsibilities:
        actions = _unobserved_result_actions(responsibility, result_operations)
        if actions:
            responsibility = _with_result_feedback(responsibility, actions)
            changed = True
        responsibilities.append(responsibility)
    if not changed:
        return control_structure
    return control_structure.model_copy(update={"responsibilities": responsibilities})


__all__ = ["add_operation_result_feedback"]
