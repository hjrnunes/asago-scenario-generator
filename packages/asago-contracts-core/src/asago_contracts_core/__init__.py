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
``write_envelope`` gives a new-version document its identity. ``parse_version_name``
reads the semantic version a version directory carries, ``diff_schemas`` refuses a
breaking schema change without a major bump, and ``support_window`` applies the
dcpl.2 support rule. ``upgrade(document)`` applies the registered saved-artifact
migration and writes the target envelope.

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
    CASES_NAME,
    CONTRACT,
    CONTRACT_DIR,
    HANDOFF_SCHEMA_VERSION_V5,
    HANDOFF_SCHEMA_VERSION_V6,
    KIT_V5,
    KIT_V6,
    LEGACY_VERSION,
    VERSION,
    VERSIONS,
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
from .schema_diff import (
    SchemaChange,
    SchemaDiffError,
    check_roots,
    diff_schemas,
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
from .support import (
    SUPPORT_POLICY,
    SUPPORT_STATUSES,
    VersionSupport,
    check_support_window,
    support_window,
)
from .upgrade import (
    Upgrade,
    UpgradeError,
    register_upgrade,
    registered_upgrades,
    upgrade,
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
    "HANDOFF_SCHEMA_VERSION_V5",
    "HANDOFF_SCHEMA_VERSION_V6",
    "INCONCLUSIVE",
    "KIT_V5",
    "KIT_V6",
    "LEGACY_VERSION",
    "NFC_ALLOW_NAN_ENCODING",
    "NOT_DETECTED",
    "NO_NAN_ENCODING",
    "OTHER_VERSION_VIOLATIONS",
    "PRODUCER_ENCODING",
    "SUPPORT_POLICY",
    "SUPPORT_STATUSES",
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
    "SchemaChange",
    "SchemaDiffError",
    "SemVer",
    "SpecDigestMismatchError",
    "SpecSet",
    "UnknownContractError",
    "UnknownFieldError",
    "UnknownRequirementError",
    "UnsupportedVersionError",
    "Upgrade",
    "UpgradeError",
    "VERSION",
    "VERSIONS",
    "VersionSupport",
    "Violation",
    "attack_shape_violation",
    "canonical_json",
    "canonical_json_bytes",
    "check_roots",
    "check_support_window",
    "diff_schemas",
    "digest_record",
    "encoding_for",
    "evaluate_condition",
    "evaluate_condition_v2",
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
    "register_upgrade",
    "registered_upgrades",
    "render_feature_text",
    "run_conformance",
    "schema_violations",
    "sha256_hex",
    "spec_digest",
    "support_window",
    "upgrade",
    "validate_condition",
    "validate_handoff",
    "write_envelope",
]
