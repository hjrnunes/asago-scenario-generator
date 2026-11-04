"""The scenario-handoff-v5 rules the producer, the consumer and the orchestrator share.

``validate_handoff`` is the one rule reader: the ownership walker, the composed
schema, and the rules the schema cannot state. ``run_conformance`` runs a kit's
manifest against the same rules, and ``evaluate_condition_v2`` is the one
``tool-call-condition-v2`` evaluator.
"""

from __future__ import annotations

from .boundary import iter_boundary_strings, ownership_violations
from .companion import feature_violations, render_feature_text
from .condition_eval import (
    DETECTED,
    INCONCLUSIVE,
    NOT_DETECTED,
    ConditionEvaluation,
    evaluate_condition,
    evaluate_condition_v2,
    validate_condition,
)
from .conformance import (
    ConformanceCase,
    ConformanceResult,
    load_conformance_cases,
    run_conformance,
)
from .contract import (
    HANDOFF_SCHEMA_VERSION_V5,
    KIT_V5,
    Contract,
    ContractError,
    load_contract,
    load_ownership_rules,
    packaged_contract,
)
from .shape import (
    CHANNEL_DIRECT,
    CHANNEL_FORGED,
    CHANNEL_INDIRECT,
    attack_shape_violation,
)
from .violation import Violation
from .violations import (
    OTHER_VERSION_VIOLATIONS,
    hand_rule_violations,
    schema_violations,
    validate_handoff,
)

__all__ = [
    "CHANNEL_DIRECT",
    "CHANNEL_FORGED",
    "CHANNEL_INDIRECT",
    "DETECTED",
    "HANDOFF_SCHEMA_VERSION_V5",
    "INCONCLUSIVE",
    "KIT_V5",
    "NOT_DETECTED",
    "OTHER_VERSION_VIOLATIONS",
    "ConditionEvaluation",
    "ConformanceCase",
    "ConformanceResult",
    "Contract",
    "ContractError",
    "Violation",
    "attack_shape_violation",
    "evaluate_condition",
    "evaluate_condition_v2",
    "feature_violations",
    "hand_rule_violations",
    "iter_boundary_strings",
    "load_conformance_cases",
    "load_contract",
    "load_ownership_rules",
    "ownership_violations",
    "packaged_contract",
    "render_feature_text",
    "run_conformance",
    "schema_violations",
    "validate_condition",
    "validate_handoff",
]
