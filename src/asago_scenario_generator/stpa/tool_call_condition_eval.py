"""Compatibility shim: the condition-v2 evaluator lives in ``asago_handoff``.

``asago_handoff.condition_eval`` holds the single implementation. The producer,
the consumer and the orchestrator all evaluate with it, so the producer's Stage
5 publication, the binder's tests and the vector generator cannot drift apart.
This module re-exports the names the producer uses and keeps the import path
its callers already have.
"""

from asago_handoff.condition_eval import (
    DETECTED,
    INCONCLUSIVE,
    NOT_DETECTED,
    ConditionEvaluation,
    evaluate_condition_v2,
    validate_condition,
)

__all__ = [
    "DETECTED",
    "INCONCLUSIVE",
    "NOT_DETECTED",
    "ConditionEvaluation",
    "evaluate_condition_v2",
    "validate_condition",
]
