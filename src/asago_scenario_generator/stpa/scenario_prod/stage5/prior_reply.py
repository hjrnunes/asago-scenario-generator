"""The prior reply a Stage 5 correction shows the model.

A correction shows the reply it corrects, so the model fixes the failing
fields in place. A name outside the request's operation inventory is shown
as null instead: a model shown a malformed name (one that carries JSON
closing characters, for example) copies it into the next reply until the
condition is removed. The exact error the correction also sends still names
the refused value and the available operations.

The fields are the ones the request schema closes to the inventory
(:mod:`.schema`): the discriminating condition's operation names, the failure
call's and the observation criteria's.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Collection, Iterator
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.stpa._model_data import raw_model_data
from asago_scenario_generator.stpa.infra.llm_helpers import strip_json_fence


def without_unknown_operations(content: Any, operations: Collection[str]) -> Any:
    """Return ``content`` with each operation name outside ``operations`` nulled.

    A name the checks accept once stripped is kept as written. When no name
    is nulled, or the content is not a JSON object, ``content`` itself is
    returned, so the correction shows it as it came. ``content`` is never
    changed.
    """

    data = _reply_data(content)
    outcome = data.get("unsafe_outcome") if isinstance(data, dict) else None
    if not isinstance(outcome, dict):
        return content
    nulled = False
    for holder, key in _operation_slots(outcome):
        value = holder.get(key)
        if isinstance(value, str) and value.strip() not in operations:
            holder[key] = None
            nulled = True
    return data if nulled else content


def _reply_data(content: Any) -> Any:
    """Return an independent JSON-data copy of the reply, or ``None``."""

    if isinstance(content, BaseModel):
        return raw_model_data(content)
    if isinstance(content, dict):
        return copy.deepcopy(content)
    if isinstance(content, str):
        try:
            return json.loads(strip_json_fence(content))
        except ValueError:
            return None
    return None


def _operation_slots(outcome: dict) -> Iterator[tuple[dict, str]]:
    """Yield each object of the outcome and its key that names an operation."""

    condition = outcome.get("discriminating_condition")
    if isinstance(condition, dict):
        for comparison in _objects(condition.get("comparisons")):
            yield comparison, "operation"
            yield comparison, "requires_prior"
            for side in ("left", "right"):
                operand = comparison.get(side)
                if isinstance(operand, dict):
                    yield operand, "operation"
        selection = condition.get("record_selection")
        if isinstance(selection, dict):
            for value in _objects(selection.get("argument_values")):
                yield value, "operation"
    failure_call = outcome.get("failure_call")
    if isinstance(failure_call, dict):
        yield failure_call, "operation_name"
    for criterion in _objects(outcome.get("observation_criteria")):
        yield criterion, "operation_name"


def _objects(items: Any) -> list[dict]:
    return (
        [item for item in items if isinstance(item, dict)]
        if isinstance(items, list)
        else []
    )
