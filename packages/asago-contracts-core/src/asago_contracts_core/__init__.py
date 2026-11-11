"""The Asago contracts core: shared rules, canonical JSON and conformance.

``validate_handoff`` is the one scenario-handoff rule reader: the ownership
walker, the composed schema, and the rules the schema cannot state.
``run_conformance`` runs a contract kit's manifest against the same rules,
``evaluate_condition`` is the one ``tool-call-condition-v1`` evaluator, and
``canonical_json``, ``framed_digest`` and ``digest_record`` pin the producer
and consumer canonical-JSON encodings.

``load_specs`` reads a contract kit's installed runtime specs, and ``spec_digest``
pins one: the bytes of ``spec.json`` and its schema, never its cases or docs.
``SpecSet.read`` selects the spec a document names and enforces the reader rules;
``write_envelope`` gives a document its identity. ``parse_version_name``
reads the semantic version a version directory carries.

The package needs the standard library and ``jsonschema`` only. It carries the
scenario-handoff schemas, the ownership rules and the envelope schema as package
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
    validate_condition,
)
from .conformance import (
    ConformanceCase,
    ConformanceResult,
    load_conformance_cases,
    run_conformance,
)
from .contract import (
    CASES_NAME,
    CONTRACT,
    CONTRACT_DIR,
    HANDOFF_SCHEMA_VERSION,
    HANDOFF_KIT,
    VERSION,
    Contract,
    ContractError,
    installed_specs,
    load_contract,
    load_ownership_rules,
    packaged_contract,
    read_handoff,
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
from .semver import (
    ContractVersionName,
    ContractVersionNameError,
    InvalidVersionNameError,
    SemVer,
    parse_version,
    parse_version_name,
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
    "CASES_NAME",
    "CHANNEL_DIRECT",
    "CHANNEL_FORGED",
    "CHANNEL_INDIRECT",
    "CONSUMER_ENCODING",
    "CONTRACT",
    "CONTRACT_DIR",
    "CORE_VERSION",
    "DETECTED",
    "ENVELOPE_FIELD",
    "ENVELOPE_SCHEMA_ID",
    "HANDOFF_SCHEMA_VERSION",
    "INCONCLUSIVE",
    "HANDOFF_KIT",
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
    "ContractVersionName",
    "ContractVersionNameError",
    "Encoding",
    "InvalidDocumentError",
    "InvalidEnvelopeError",
    "InvalidSpecError",
    "InvalidVersionNameError",
    "MissingEnvelopeError",
    "Provenance",
    "SemVer",
    "SpecDigestMismatchError",
    "SpecSet",
    "UnknownContractError",
    "UnknownFieldError",
    "UnknownRequirementError",
    "UnsupportedVersionError",
    "VERSION",
    "Violation",
    "attack_shape_violation",
    "canonical_json",
    "canonical_json_bytes",
    "digest_record",
    "encoding_for",
    "evaluate_condition",
    "envelope_schema",
    "feature_violations",
    "framed_digest",
    "hand_rule_violations",
    "installed_specs",
    "iter_boundary_strings",
    "load_conformance_cases",
    "load_contract",
    "load_ownership_rules",
    "load_specs",
    "normalize_unicode",
    "ownership_violations",
    "packaged_contract",
    "parse_version",
    "parse_version_name",
    "read_handoff",
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
