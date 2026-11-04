"""The Asago contracts core: shared rules, canonical JSON and conformance.

``validate_handoff`` is the one scenario-handoff rule reader: the ownership
walker, the composed schema, and the rules the schema cannot state.
``run_conformance`` runs a contract kit's manifest against the same rules,
``evaluate_condition_v2`` is the one ``tool-call-condition-v2`` evaluator, and
``canonical_json``, ``framed_digest`` and ``digest_record`` pin the producer
and consumer canonical-JSON encodings.

The package needs the standard library and ``jsonschema`` only. It carries the
``handoff-v5`` schema and the ownership rules as package data, so it can move
to its own repository without a code change.
"""

from __future__ import annotations

from .boundary import iter_boundary_strings, ownership_violations
from .canonical import (
    CONSUMER_ENCODING,
    NFC_ALLOW_NAN_ENCODING,
    NO_NAN_ENCODING,
    PRODUCER_ENCODING,
    Encoding,
    canonical_json,
    canonical_json_bytes,
    digest_record,
    encoding_for,
    framed_digest,
    normalize_unicode,
    sha256_hex,
)
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
    "CONSUMER_ENCODING",
    "DETECTED",
    "HANDOFF_SCHEMA_VERSION_V5",
    "INCONCLUSIVE",
    "KIT_V5",
    "NFC_ALLOW_NAN_ENCODING",
    "NOT_DETECTED",
    "NO_NAN_ENCODING",
    "OTHER_VERSION_VIOLATIONS",
    "PRODUCER_ENCODING",
    "ConditionEvaluation",
    "ConformanceCase",
    "ConformanceResult",
    "Contract",
    "ContractError",
    "Encoding",
    "Violation",
    "attack_shape_violation",
    "canonical_json",
    "canonical_json_bytes",
    "digest_record",
    "encoding_for",
    "evaluate_condition",
    "evaluate_condition_v2",
    "feature_violations",
    "framed_digest",
    "hand_rule_violations",
    "iter_boundary_strings",
    "load_conformance_cases",
    "load_contract",
    "load_ownership_rules",
    "normalize_unicode",
    "ownership_violations",
    "packaged_contract",
    "render_feature_text",
    "run_conformance",
    "schema_violations",
    "sha256_hex",
    "validate_condition",
    "validate_handoff",
]
