"""Reduce Stage 5 fixture payloads to the scenario-semantics provider wire.

Several fixtures were written for the removed execution-design wire. The
fields below have no place on the semantics wire, so the response queue drops
them instead of every fixture repeating the reduction.
"""

from __future__ import annotations

import copy
from typing import Any

_EXECUTION_ONLY_TOP_LEVEL = ("stimulus", "execution_route")
_EXECUTION_ONLY_FACTOR = ("selected_for_route",)
_EXECUTION_ONLY_OUTCOME = ("condition",)


def normal_wire(payload: Any) -> Any:
    """Return *payload* without execution-design fields; pass non-payloads through."""
    if not isinstance(payload, dict) or "causal_factors" not in payload:
        return payload
    reduced = copy.deepcopy(payload)
    for key in _EXECUTION_ONLY_TOP_LEVEL:
        reduced.pop(key, None)
    for factor in reduced.get("causal_factors") or []:
        if isinstance(factor, dict):
            for key in _EXECUTION_ONLY_FACTOR:
                factor.pop(key, None)
    outcome = reduced.get("unsafe_outcome")
    if isinstance(outcome, dict):
        for key in _EXECUTION_ONLY_OUTCOME:
            outcome.pop(key, None)
    return reduced


def normal_wire_queue(responses: list[Any]) -> list[Any]:
    """Reduce every payload in a response queue."""
    return [normal_wire(response) for response in responses]
