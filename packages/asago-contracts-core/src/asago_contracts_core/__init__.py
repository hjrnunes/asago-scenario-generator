"""The Asago contracts core: shared rules, canonical JSON and conformance.

``validate_handoff`` is the one scenario-handoff rule reader: the ownership
walker, the composed schema, and the rules the schema cannot state.
``run_conformance`` runs a contract kit's manifest against the same rules,
``evaluate_condition_v2`` is the one ``tool-call-condition-v2`` evaluator, and
``canonical_json``, ``framed_digest`` and ``digest_record`` pin the producer
and consumer canonical-JSON encodings.

``load_specs`` reads a contract kit's installed runtime specs, and ``spec_digest``
pins one: the bytes of ``spec.json`` and its schema, never its cases or docs.
``SpecSet.read`` selects the spec a document names and enforces the reader rules;
``write_envelope`` gives a new-version document its identity.

The package needs the standard library and ``jsonschema`` only. It carries the
``handoff-v5`` schema, the ownership rules and the envelope schema as package
data, so it can move to its own repository without a code change.
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
from .envelope import (
    CORE_VERSION,
    ENVELOPE_FIELD,
    ENVELOPE_SCHEMA_ID,
    VALIDATOR,
    ContractEnvelope,
    ContractEnvelopeError,
    ContractSpec,
    InvalidDocumentError,
    InvalidEnvelopeError,
    InvalidSpecError,
    MissingEnvelopeError,
    Provenance,
    SpecDigestMismatchError,
    SpecSet,
    UnknownContractError,
    UnknownFieldError,
    UnknownRequirementError,
    UnsupportedVersionError,
    envelope_schema,
    load_specs,
    read_envelope,
    spec_digest,
    write_envelope,
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
    "CORE_VERSION",
    "DETECTED",
    "ENVELOPE_FIELD",
    "ENVELOPE_SCHEMA_ID",
    "HANDOFF_SCHEMA_VERSION_V5",
    "INCONCLUSIVE",
    "KIT_V5",
    "NFC_ALLOW_NAN_ENCODING",
    "NOT_DETECTED",
    "NO_NAN_ENCODING",
    "OTHER_VERSION_VIOLATIONS",
    "PRODUCER_ENCODING",
    "VALIDATOR",
    "ConditionEvaluation",
    "ConformanceCase",
    "ConformanceResult",
    "Contract",
    "ContractEnvelope",
    "ContractEnvelopeError",
    "ContractError",
    "ContractSpec",
    "Encoding",
    "InvalidDocumentError",
    "InvalidEnvelopeError",
    "InvalidSpecError",
    "MissingEnvelopeError",
    "Provenance",
    "SpecDigestMismatchError",
    "SpecSet",
    "UnknownContractError",
    "UnknownFieldError",
    "UnknownRequirementError",
    "UnsupportedVersionError",
    "Violation",
    "attack_shape_violation",
    "canonical_json",
    "canonical_json_bytes",
    "digest_record",
    "encoding_for",
    "evaluate_condition",
    "evaluate_condition_v2",
    "envelope_schema",
    "feature_violations",
    "framed_digest",
    "hand_rule_violations",
    "iter_boundary_strings",
    "load_conformance_cases",
    "load_contract",
    "load_ownership_rules",
    "load_specs",
    "normalize_unicode",
    "ownership_violations",
    "packaged_contract",
    "read_envelope",
    "render_feature_text",
    "run_conformance",
    "schema_violations",
    "sha256_hex",
    "spec_digest",
    "validate_condition",
    "validate_handoff",
    "write_envelope",
]
