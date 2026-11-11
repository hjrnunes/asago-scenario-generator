"""The self-identifying contract envelope and the reader's installed specs.

A contract kit is split into three parts: its *runtime spec* (``spec.json`` and the
schema it names), its *cases* and its *docs*. The spec digest covers the runtime spec
bytes alone, so editing a case or a doc never changes the contract's identity.

A document written from the 13c envelope carries one ``contract`` block:

.. code-block:: json

   {
     "contract": {
       "id": "midojo-delivery",
       "version": "midojo-delivery-v1",
       "spec_digest": "sha256:...",
       "requires": ["feature-a"],
       "provenance": {
         "writer": "asago-orch.qualification.midojo_episode_runner",
         "writer_version": "0.1.0",
         "validator_version": "asago-contracts-core 0.1.0"
       }
     }
   }

A reader selects one of its *installed* specs by the contract id and version, never a
schema the document points to. It then enforces four rules:

- an unsupported version fails, and the error lists the versions it supports;
- a ``requires`` entry the spec does not support fails, so an old reader cannot
  silently ignore a new constraint;
- a top-level field outside the schema and the spec's declared extensions fails;
- a ``spec_digest`` that is not exactly the installed spec's fails, for a draft as
  for a published version.

A document that carries no envelope is a legacy document of the version its
``schema_version`` names; a spec with ``"envelope": "required"`` refuses one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import PRODUCER_ENCODING, framed_digest, sha256_hex
from .semver import InvalidVersionNameError, SemVer, parse_version_name

ENVELOPE_FIELD = "contract"
ENVELOPE_SCHEMA_ID = "asago-contract-envelope-v1"
VALIDATOR = "asago-contracts-core"
CORE_VERSION = "0.1.0"
STATUSES = ("draft", "published")
ENVELOPE_MODES = ("required", "optional")
ENVELOPE_FIELDS = ("id", "version", "spec_digest", "requires", "provenance")
PROVENANCE_FIELDS = ("writer", "writer_version", "validator_version")
SPEC_FIELDS = (
    "contract",
    "version",
    "status",
    "envelope",
    "supports",
    "extensions",
    "schema",
    "cases",
    "docs",
    "spec_digest",
)
_SPEC_REQUIRED = tuple(field for field in SPEC_FIELDS if field not in ("cases", "docs"))
_SPEC_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATA_DIR = Path(__file__).resolve().parent / "data"
_ENVELOPE_SCHEMA_FILE = _DATA_DIR / "envelope-v1.schema.json"


class ContractEnvelopeError(ValueError):
    """A document or a spec breaks the self-identifying envelope's rules."""


class InvalidEnvelopeError(ContractEnvelopeError):
    """The ``contract`` block is not the five-field envelope."""


class MissingEnvelopeError(ContractEnvelopeError):
    """The document is a legacy document of a spec that requires the envelope."""


class UnknownContractError(ContractEnvelopeError):
    """No installed spec names the contract the document names."""


class UnsupportedVersionError(ContractEnvelopeError):
    """No installed spec names the version, or the document's version is not installed."""


class UnknownRequirementError(ContractEnvelopeError):
    """The document requires a feature the selected spec does not support."""


class UnknownFieldError(ContractEnvelopeError):
    """The document carries a top-level field outside the schema and its extensions."""


class SpecDigestMismatchError(ContractEnvelopeError):
    """A spec digest does not match the runtime spec bytes, or a document's does not match."""


class InvalidDocumentError(ContractEnvelopeError):
    """The document does not validate against the selected spec's schema."""


class InvalidSpecError(ContractEnvelopeError):
    """An installed contract spec is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Provenance:
    """Who wrote a document and which validator checked it."""

    writer: str
    writer_version: str
    validator_version: str


@dataclass(frozen=True)
class ContractEnvelope:
    """The five fields a self-identifying document carries."""

    id: str
    version: str
    spec_digest: str
    requires: tuple[str, ...]
    provenance: Provenance


@dataclass(frozen=True)
class ContractSpec:
    """One installed version of one contract: its identity and its runtime schema.

    ``root`` is the version's directory. ``extensions`` names top-level document fields
    the reader ignores on purpose; the envelope itself is never an extension. ``cases`` and
    ``docs`` name the version's conformance cases and its reader documentation, as the
    version publishes them.
    """

    contract: str
    version: str
    status: str
    envelope: str
    supports: tuple[str, ...]
    extensions: tuple[str, ...]
    schema: Mapping[str, Any]
    spec_digest: str
    root: Path
    cases: str | None = None
    docs: str | None = None

    @property
    def name(self) -> str:
        return f"{self.contract} {self.version}"

    @property
    def semver(self) -> SemVer:
        """The semantic version the version's name carries.

        The name's prefix is not required to equal the contract's name: an
        installed kit may keep a historical prefix such as
        ``artifact-runtime-contract-v1`` for the ``runtime-contract`` contract.
        """

        return parse_version_name(self.version).version

    @property
    def allows_legacy(self) -> bool:
        return self.envelope == "optional"

    def allowed_fields(self) -> frozenset[str]:
        """The top-level fields a document of this spec may carry."""

        properties = self.schema.get("properties")
        declared = set(properties) if isinstance(properties, Mapping) else set()
        return frozenset(declared | set(self.extensions) | {ENVELOPE_FIELD})

    def validate(self, document: Mapping[str, Any]) -> None:
        """Raise the first rule the document breaks: an unknown field, then the schema."""

        unknown = sorted(set(document) - self.allowed_fields())
        if unknown:
            declared = ", ".join(self.extensions) or "none"
            names = ", ".join(repr(field) for field in unknown)
            raise UnknownFieldError(
                f"{self.name}: unknown field {names} outside the spec's schema "
                f"(declared extensions: {declared})"
            )
        payload = {
            key: value
            for key, value in document.items()
            if key != ENVELOPE_FIELD and key not in self.extensions
        }
        errors = sorted(
            Draft202012Validator(self.schema).iter_errors(payload),
            key=lambda error: tuple(str(part) for part in error.path),
        )
        if errors:
            location = ".".join(str(part) for part in errors[0].path) or "<root>"
            raise InvalidDocumentError(
                f"{self.name}: at {location}: {errors[0].message}"
            )


@dataclass(frozen=True)
class SpecSet:
    """The specs a reader has installed, and the one reader for their documents."""

    specs: tuple[ContractSpec, ...]
    version_key: str = "schema_version"

    def versions(self, contract: str | None = None) -> tuple[str, ...]:
        """Return the installed versions, of one contract or of every contract."""

        return tuple(
            sorted(
                {
                    spec.version
                    for spec in self.specs
                    if contract is None or spec.contract == contract
                }
            )
        )

    def contracts(self) -> tuple[str, ...]:
        return tuple(sorted({spec.contract for spec in self.specs}))

    def spec(self, contract: str, version: str) -> ContractSpec:
        """Select one installed spec; an unknown contract or version lists what is installed."""

        for spec in self.specs:
            if spec.contract == contract and spec.version == version:
                return spec
        if contract not in self.contracts():
            installed = ", ".join(self.contracts()) or "none"
            raise UnknownContractError(
                f"unknown contract {contract!r}; installed contracts: {installed}"
            )
        supported = ", ".join(self.versions(contract)) or "none"
        raise UnsupportedVersionError(
            f"unsupported {contract} version {version!r}; supported versions: {supported}"
        )

    def read(self, document: Mapping[str, Any]) -> ContractSpec:
        """Select the spec a document names and enforce every reader rule on it."""

        if not isinstance(document, Mapping):
            raise InvalidDocumentError("a contract document must be a JSON object")
        if ENVELOPE_FIELD in document:
            envelope = read_envelope(document)
            spec = self.spec(envelope.id, envelope.version)
            unknown = [need for need in envelope.requires if need not in spec.supports]
            if unknown:
                supported = ", ".join(spec.supports) or "none"
                names = ", ".join(repr(need) for need in unknown)
                raise UnknownRequirementError(
                    f"{spec.name}: unknown requires {names} (the spec supports: {supported})"
                )
            if envelope.spec_digest != spec.spec_digest:
                raise SpecDigestMismatchError(
                    f"{spec.name} ({spec.status}): spec_digest {envelope.spec_digest!r} "
                    f"does not match the installed spec digest {spec.spec_digest!r}; "
                    "a published draft never changes meaning"
                )
            spec.validate(document)
            return spec
        version = document.get(self.version_key)
        if not isinstance(version, str) or not version:
            supported = ", ".join(self.versions()) or "none"
            raise UnsupportedVersionError(
                f"the document names no {self.version_key!r}; supported versions: {supported}"
            )
        matches = [spec for spec in self.specs if spec.version == version]
        if not matches:
            supported = ", ".join(self.versions()) or "none"
            raise UnsupportedVersionError(
                f"unsupported contract version {version!r}; supported versions: {supported}"
            )
        if len(matches) > 1:
            raise InvalidSpecError(
                f"more than one installed spec names the version {version!r}"
            )
        spec = matches[0]
        if not spec.allows_legacy:
            raise MissingEnvelopeError(
                f"{spec.name} requires the self-identifying envelope "
                f"({ENVELOPE_FIELD!r}); the document carries none"
            )
        spec.validate(document)
        return spec

    def read_file(
        self,
        path: str | Path,
        *,
        error: type[ContractEnvelopeError] = InvalidDocumentError,
    ) -> ContractSpec:
        """Read one JSON file and enforce the reader rules on it."""

        document = _read_json(Path(path), error)
        if not isinstance(document, Mapping):
            raise error(f"{path}: a contract document must be a JSON object")
        return self.read(document)


def load_specs(root: str | Path) -> SpecSet:
    """Load every ``<contract>/<version>/spec.json`` under ``root``."""

    root = Path(root)
    paths = sorted(root.glob("*/*/spec.json"))
    if not paths:
        raise InvalidSpecError(
            f"{root}: no installed contract spec "
            "(expected <root>/<contract>/<version>/spec.json)"
        )
    specs = tuple(_load_spec(path) for path in paths)
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        key = (spec.contract, spec.version)
        if key in seen:
            raise InvalidSpecError(f"more than one installed spec names {spec.name}")
        seen.add(key)
    return SpecSet(specs)


def read_envelope(document: Mapping[str, Any]) -> ContractEnvelope:
    """Parse and shape-check one document's ``contract`` block."""

    value = document.get(ENVELOPE_FIELD)
    if value is None:
        raise MissingEnvelopeError(
            f"the document carries no {ENVELOPE_FIELD!r} envelope"
        )
    if not isinstance(value, Mapping):
        raise InvalidEnvelopeError(
            f"{ENVELOPE_FIELD!r} must be a JSON object, not {type(value).__name__}"
        )
    unknown = sorted(set(value) - set(ENVELOPE_FIELDS))
    if unknown:
        names = ", ".join(repr(field) for field in unknown)
        raise InvalidEnvelopeError(
            f"the contract envelope has unknown field {names}; it holds exactly "
            f"{', '.join(ENVELOPE_FIELDS)}"
        )
    missing = [field for field in ENVELOPE_FIELDS if field not in value]
    if missing:
        names = ", ".join(repr(field) for field in missing)
        raise InvalidEnvelopeError(f"the contract envelope is missing {names}")
    for field in ("id", "version", "spec_digest"):
        if not isinstance(value[field], str) or not value[field]:
            raise InvalidEnvelopeError(
                f"the contract envelope's {field!r} must be text"
            )
    if not _SPEC_DIGEST.match(value["spec_digest"]):
        raise InvalidEnvelopeError(
            "the contract envelope's 'spec_digest' must be 'sha256:' and 64 hex digits"
        )
    requires = value["requires"]
    if not isinstance(requires, list) or not all(
        isinstance(need, str) and need for need in requires
    ):
        raise InvalidEnvelopeError(
            "the contract envelope's 'requires' must be a list of names"
        )
    if len(set(requires)) != len(requires):
        raise InvalidEnvelopeError("the contract envelope's 'requires' repeats a name")
    provenance = value["provenance"]
    if not isinstance(provenance, Mapping):
        raise InvalidEnvelopeError(
            "the contract envelope's 'provenance' must be an object"
        )
    unknown = sorted(set(provenance) - set(PROVENANCE_FIELDS))
    if unknown:
        names = ", ".join(repr(field) for field in unknown)
        raise InvalidEnvelopeError(
            f"the contract envelope's provenance has unknown field {names}; it holds "
            f"exactly {', '.join(PROVENANCE_FIELDS)}"
        )
    missing = [field for field in PROVENANCE_FIELDS if field not in provenance]
    if missing:
        names = ", ".join(repr(field) for field in missing)
        raise InvalidEnvelopeError(
            f"the contract envelope's provenance is missing {names}"
        )
    for field in PROVENANCE_FIELDS:
        if not isinstance(provenance[field], str) or not provenance[field]:
            raise InvalidEnvelopeError(
                f"the contract envelope's provenance {field!r} must be text"
            )
    return ContractEnvelope(
        id=value["id"],
        version=value["version"],
        spec_digest=value["spec_digest"],
        requires=tuple(requires),
        provenance=Provenance(
            writer=provenance["writer"],
            writer_version=provenance["writer_version"],
            validator_version=provenance["validator_version"],
        ),
    )


def write_envelope(
    document: Mapping[str, Any],
    spec: ContractSpec,
    *,
    writer: str,
    writer_version: str,
    requires: Iterable[str] = (),
    validator_version: str | None = None,
) -> dict[str, Any]:
    """Return ``document`` with its envelope, refusing what the spec's reader would reject."""

    needs = list(requires)
    unknown = [need for need in needs if need not in spec.supports]
    if unknown:
        supported = ", ".join(spec.supports) or "none"
        names = ", ".join(repr(need) for need in unknown)
        raise UnknownRequirementError(
            f"{spec.name}: unknown requires {names} (the spec supports: {supported})"
        )
    written = {
        **document,
        ENVELOPE_FIELD: {
            "id": spec.contract,
            "version": spec.version,
            "spec_digest": spec.spec_digest,
            "requires": needs,
            "provenance": {
                "writer": writer,
                "writer_version": writer_version,
                "validator_version": validator_version or f"{VALIDATOR} {CORE_VERSION}",
            },
        },
    }
    read_envelope(written)
    spec.validate(written)
    return written


def spec_digest(body: Mapping[str, Any], schema_bytes: bytes) -> str:
    """Digest one spec body and its schema bytes; the body's ``spec_digest`` is left out."""

    if not isinstance(body, Mapping):
        raise InvalidSpecError("a contract spec must be a JSON object")
    payload = {key: value for key, value in body.items() if key != "spec_digest"}
    digest = framed_digest(
        "asago-contract-spec",
        {"schema_sha256": sha256_hex(schema_bytes), "spec": payload},
        encoding=PRODUCER_ENCODING,
    )
    return f"sha256:{digest}"


@cache
def envelope_schema() -> Mapping[str, Any]:
    """Return the JSON Schema of the ``contract`` block, as package data pins it."""

    document = json.loads(_ENVELOPE_SCHEMA_FILE.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise InvalidSpecError(f"{_ENVELOPE_SCHEMA_FILE} is not a JSON object")
    return document


def _load_spec(path: Path) -> ContractSpec:
    document = _read_json(path, InvalidSpecError)
    if not isinstance(document, Mapping):
        raise InvalidSpecError(f"{path}: a contract spec must be a JSON object")
    unknown = sorted(set(document) - set(SPEC_FIELDS))
    if unknown:
        names = ", ".join(repr(field) for field in unknown)
        raise InvalidSpecError(f"{path}: unknown spec field {names}")
    missing = [field for field in _SPEC_REQUIRED if field not in document]
    if missing:
        names = ", ".join(repr(field) for field in missing)
        raise InvalidSpecError(f"{path}: missing spec field {names}")
    for field in ("contract", "version"):
        if not isinstance(document[field], str) or not document[field]:
            raise InvalidSpecError(f"{path}: spec {field!r} must be text")
    try:
        parse_version_name(document["version"])
    except InvalidVersionNameError as error:
        raise InvalidSpecError(f"{path}: {error}") from error
    if path.parent.name != document["version"]:
        raise InvalidSpecError(
            f"{path}: the version's directory must be {document['version']!r}"
        )
    if document["status"] not in STATUSES:
        raise InvalidSpecError(
            f"{path}: status must be one of {', '.join(STATUSES)}, not {document['status']!r}"
        )
    if document["envelope"] not in ENVELOPE_MODES:
        raise InvalidSpecError(
            f"{path}: envelope must be one of {', '.join(ENVELOPE_MODES)}, "
            f"not {document['envelope']!r}"
        )
    supports = _names(path, "supports", document["supports"])
    extensions = _names(path, "extensions", document["extensions"])
    if ENVELOPE_FIELD in extensions:
        raise InvalidSpecError(
            f"{path}: the envelope field {ENVELOPE_FIELD!r} cannot be an extension"
        )
    root = path.parent
    schema_path = _member(path, root, "schema", document["schema"])
    for optional in ("cases", "docs"):
        if optional in document:
            _member(path, root, optional, document[optional])
    try:
        schema_bytes = schema_path.read_bytes()
    except OSError as exc:
        raise InvalidSpecError(f"{path}: cannot read its schema: {exc}") from exc
    schema = _read_json(schema_path, InvalidSpecError)
    if not isinstance(schema, Mapping):
        raise InvalidSpecError(
            f"{schema_path}: the runtime schema must be a JSON object"
        )
    expected = document["spec_digest"]
    if not isinstance(expected, str) or not _SPEC_DIGEST.match(expected):
        raise InvalidSpecError(
            f"{path}: 'spec_digest' must be 'sha256:' and 64 hex digits"
        )
    actual = spec_digest(document, schema_bytes)
    if expected != actual:
        raise SpecDigestMismatchError(
            f"{path}: spec_digest {expected!r} does not match the runtime spec bytes "
            f"({actual!r}); recompute it when the spec or schema changes"
        )
    return ContractSpec(
        contract=document["contract"],
        version=document["version"],
        status=document["status"],
        envelope=document["envelope"],
        supports=supports,
        extensions=extensions,
        schema=schema,
        spec_digest=expected,
        root=root,
        cases=document.get("cases"),
        docs=document.get("docs"),
    )


def _names(path: Path, label: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise InvalidSpecError(f"{path}: spec {label!r} must be a list of names")
    if len(set(value)) != len(value):
        raise InvalidSpecError(f"{path}: spec {label!r} repeats a name")
    return tuple(value)


def _member(path: Path, root: Path, label: str, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise InvalidSpecError(f"{path}: spec {label!r} must be a file name")
    if Path(value).is_absolute() or Path(value).name != value:
        raise InvalidSpecError(
            f"{path}: spec {label!r} must name a file in the version's directory, "
            f"not {value!r}"
        )
    member = root / value
    if not member.exists():
        raise InvalidSpecError(f"{path}: spec {label!r} names a missing {member}")
    return member


def _read_json(path: Path, error: type[ContractEnvelopeError]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise error(f"{path}: cannot read JSON: {exc}") from exc


__all__ = [
    "CORE_VERSION",
    "ENVELOPE_FIELD",
    "ENVELOPE_FIELDS",
    "ENVELOPE_MODES",
    "ENVELOPE_SCHEMA_ID",
    "PROVENANCE_FIELDS",
    "STATUSES",
    "VALIDATOR",
    "ContractEnvelope",
    "ContractEnvelopeError",
    "ContractSpec",
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
    "envelope_schema",
    "load_specs",
    "read_envelope",
    "spec_digest",
    "write_envelope",
]
