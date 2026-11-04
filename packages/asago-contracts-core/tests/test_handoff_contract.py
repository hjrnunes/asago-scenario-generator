"""The scenario-handoff specs: their identity, their documents, and their refusals.

The producer owns ``data/contracts/scenario-handoff/``; this package ships the
whole contract directory under ``src/asago_contracts_core/data`` and reads every
handoff through the spec it carries. The test kit under ``tests/data`` holds the
same tree, so these tests run after extraction.

Two versions are published, so the refusals run against each: whatever a v5
reader refuses, a v6 reader refuses too.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from asago_contracts_core import (
    ENVELOPE_FIELD,
    ContractSpec,
    MissingEnvelopeError,
    SpecDigestMismatchError,
    SpecSet,
    UnknownContractError,
    UnknownFieldError,
    UnknownRequirementError,
    UnsupportedVersionError,
    installed_specs,
    load_specs,
    read_handoff,
    spec_digest,
    validate_handoff,
    write_envelope,
)
from asago_contracts_core.contract import DATA_DIR

CONTRACT = "scenario-handoff"
V5 = "scenario-handoff-v5"
V6 = "scenario-handoff-v6"
VERSIONS = (V5, V6)
#: Whether each version still reads a document that carries no envelope.
_ENVELOPE = {V5: "optional", V6: "required"}
_CONTRACT_DIR = Path(__file__).resolve().parent / "data" / CONTRACT
_VERSION_DIRS = {version: _CONTRACT_DIR / version for version in VERSIONS}


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _spec(version: str = V5) -> ContractSpec:
    return installed_specs().spec(CONTRACT, version)


def _cases(version: str, kind: str) -> list[Path]:
    return sorted((_VERSION_DIRS[version] / "cases" / kind).glob("*.json"))


def _enveloped(
    spec: ContractSpec, document: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    """Return a case document with the envelope, overriding envelope fields."""

    envelope = {
        "id": spec.contract,
        "version": spec.version,
        "spec_digest": spec.spec_digest,
        "requires": [],
        "provenance": {
            "writer": "tests.handoff_contract",
            "writer_version": "0.1.0",
            "validator_version": "asago-contracts-core 0.1.0",
        },
        **overrides,
    }
    return {**document, ENVELOPE_FIELD: envelope}


def _recorded_documents() -> list[Path]:
    """Return every recorded handoff the reader must keep reading."""

    documents = _cases(V5, "valid")
    corpus = os.environ.get("ASAGO_REPLAY_CORPUS")
    if corpus:
        documents = documents + sorted(Path(corpus).rglob("handoff.json"))
    return documents


def _valid_case(version: str) -> dict[str, Any]:
    return _json(_cases(version, "valid")[0])


@pytest.mark.parametrize("version", VERSIONS)
def test_the_installed_spec_is_published(version: str) -> None:
    spec = _spec(version)
    body = _json(_VERSION_DIRS[version] / "spec.json")

    assert (spec.contract, spec.version, spec.status, spec.envelope) == (
        CONTRACT,
        version,
        "published",
        _ENVELOPE[version],
    )
    assert spec.supports == ()
    assert spec.extensions == ()
    assert body["cases"] == "cases"
    assert body["docs"] == "README.md"
    assert spec.spec_digest == spec_digest(
        body, (_VERSION_DIRS[version] / "schema.json").read_bytes()
    )


def test_the_installed_root_holds_the_contract_and_the_envelope_schema() -> None:
    specs = load_specs(DATA_DIR)

    assert specs.versions() == VERSIONS
    assert specs.contracts() == (CONTRACT,)


@pytest.mark.parametrize("case", _cases(V5, "valid"), ids=lambda case: case.stem)
def test_the_reader_accepts_every_valid_case_as_a_legacy_document(case: Path) -> None:
    """A v5 document without the envelope still reads; the recorded handoffs never had one."""

    assert read_handoff(_json(case)).version == V5


@pytest.mark.parametrize(
    ("version", "case"),
    [(version, case) for version in VERSIONS for case in _cases(version, "valid")],
    ids=lambda value: getattr(value, "name", value),
)
def test_the_reader_accepts_every_valid_case_with_the_envelope(
    version: str, case: Path
) -> None:
    written = write_envelope(
        _json(case),
        _spec(version),
        writer="tests.handoff_contract",
        writer_version="0.1.0",
    )

    assert read_handoff(written).version == version


def test_a_v6_document_without_the_envelope_is_rejected() -> None:
    with pytest.raises(MissingEnvelopeError) as raised:
        read_handoff(_json(_cases(V6, "valid")[0]))

    assert V6 in str(raised.value)


@pytest.mark.parametrize("case", _recorded_documents(), ids=lambda case: case.name)
def test_every_recorded_handoff_still_reads(case: Path) -> None:
    document = _json(case)

    assert document.get("schema_version") == V5
    assert read_handoff(document).version == V5


@pytest.mark.parametrize("version", VERSIONS)
def test_the_rules_read_an_enveloped_handoff_before_they_walk_it(version: str) -> None:
    case = _valid_case(version)

    assert validate_handoff(_enveloped(_spec(version), case)) == []
    with pytest.raises(UnsupportedVersionError):
        validate_handoff(
            _enveloped(_spec(version), case, version="scenario-handoff-v9")
        )


@pytest.mark.parametrize("version", VERSIONS)
def test_an_unsupported_version_names_the_supported_versions(version: str) -> None:
    case = _valid_case(version)

    with pytest.raises(UnsupportedVersionError) as raised:
        installed_specs().read(
            _enveloped(_spec(version), case, version="scenario-handoff-v9")
        )

    assert "scenario-handoff-v9" in str(raised.value)
    for supported in VERSIONS:
        assert supported in str(raised.value)


@pytest.mark.parametrize("version", VERSIONS)
def test_an_unknown_contract_names_the_installed_one(version: str) -> None:
    case = _valid_case(version)

    with pytest.raises(UnknownContractError) as raised:
        installed_specs().read(_enveloped(_spec(version), case, id="not-a-contract"))

    assert CONTRACT in str(raised.value)


@pytest.mark.parametrize("version", VERSIONS)
def test_an_unknown_requires_entry_is_rejected(version: str) -> None:
    case = _valid_case(version)

    with pytest.raises(UnknownRequirementError) as raised:
        installed_specs().read(
            _enveloped(_spec(version), case, requires=["scenario-handoff-v2"])
        )

    assert "scenario-handoff-v2" in str(raised.value)


@pytest.mark.parametrize("version", VERSIONS)
def test_an_unknown_field_outside_an_extension_is_rejected(version: str) -> None:
    case = _valid_case(version)
    document = _enveloped(_spec(version), case)
    document["probe_key"] = f"a field {version} never declared"

    with pytest.raises(UnknownFieldError) as raised:
        installed_specs().read(document)

    assert "probe_key" in str(raised.value)
    assert "declared extensions: none" in str(raised.value)


@pytest.mark.parametrize("version", VERSIONS)
def test_a_draft_with_a_mismatched_spec_digest_is_rejected(version: str) -> None:
    case = _valid_case(version)
    draft = replace(_spec(version), status="draft")
    other = "sha256:" + "0" * 64

    with pytest.raises(SpecDigestMismatchError) as raised:
        SpecSet((draft,)).read(_enveloped(draft, case, spec_digest=other))

    assert "draft" in str(raised.value)
    assert other in str(raised.value)
