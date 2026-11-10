"""The scenario-handoff spec: its identity, its documents, and its refusals.

The producer owns ``data/contracts/scenario-handoff/``; this package ships the
whole contract directory under ``src/asago_contracts_core/data`` and reads every
handoff through the spec it carries. The test kit under ``tests/data`` holds the
same tree, so these tests run after extraction.
"""

from __future__ import annotations

import json
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
VERSION = "scenario-handoff-v6"
_CONTRACT_DIR = Path(__file__).resolve().parent / "data" / CONTRACT
_VERSION_DIR = _CONTRACT_DIR / VERSION


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _spec() -> ContractSpec:
    return installed_specs().spec(CONTRACT, VERSION)


def _cases(kind: str) -> list[Path]:
    return sorted((_VERSION_DIR / "cases" / kind).glob("*.json"))


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


def _valid_case() -> dict[str, Any]:
    return _json(_cases("valid")[0])


def test_the_installed_spec_is_published() -> None:
    spec = _spec()
    body = _json(_VERSION_DIR / "spec.json")

    assert (spec.contract, spec.version, spec.status, spec.envelope) == (
        CONTRACT,
        VERSION,
        "published",
        "required",
    )
    assert spec.supports == ()
    assert spec.extensions == ()
    assert body["cases"] == "cases"
    assert body["docs"] == "README.md"
    assert spec.spec_digest == spec_digest(
        body, (_VERSION_DIR / "schema.json").read_bytes()
    )


def test_the_installed_root_holds_the_contract_and_the_envelope_schema() -> None:
    specs = load_specs(DATA_DIR)

    assert specs.versions() == (VERSION,)
    assert specs.contracts() == (CONTRACT,)


@pytest.mark.parametrize("case", _cases("valid"), ids=lambda case: case.name)
def test_the_reader_accepts_every_valid_case_with_the_envelope(case: Path) -> None:
    written = write_envelope(
        _json(case),
        _spec(),
        writer="tests.handoff_contract",
        writer_version="0.1.0",
    )

    assert read_handoff(written).version == VERSION


def test_a_document_without_the_envelope_is_rejected() -> None:
    with pytest.raises(MissingEnvelopeError) as raised:
        read_handoff(_valid_case())

    assert VERSION in str(raised.value)


def test_the_rules_read_an_enveloped_handoff_before_they_walk_it() -> None:
    case = _valid_case()

    assert validate_handoff(_enveloped(_spec(), case)) == []
    with pytest.raises(UnsupportedVersionError):
        validate_handoff(_enveloped(_spec(), case, version="scenario-handoff-v9"))


def test_an_unsupported_version_names_the_supported_version() -> None:
    case = _valid_case()

    with pytest.raises(UnsupportedVersionError) as raised:
        installed_specs().read(_enveloped(_spec(), case, version="scenario-handoff-v9"))

    assert "scenario-handoff-v9" in str(raised.value)
    assert VERSION in str(raised.value)


def test_an_unknown_contract_names_the_installed_one() -> None:
    case = _valid_case()

    with pytest.raises(UnknownContractError) as raised:
        installed_specs().read(_enveloped(_spec(), case, id="not-a-contract"))

    assert CONTRACT in str(raised.value)


def test_an_unknown_requires_entry_is_rejected() -> None:
    case = _valid_case()

    with pytest.raises(UnknownRequirementError) as raised:
        installed_specs().read(
            _enveloped(_spec(), case, requires=["scenario-handoff-v9"])
        )

    assert "scenario-handoff-v9" in str(raised.value)


def test_an_unknown_field_outside_an_extension_is_rejected() -> None:
    case = _valid_case()
    document = _enveloped(_spec(), case)
    document["probe_key"] = "a field the spec never declared"

    with pytest.raises(UnknownFieldError) as raised:
        installed_specs().read(document)

    assert "probe_key" in str(raised.value)
    assert "declared extensions: none" in str(raised.value)


def test_a_draft_with_a_mismatched_spec_digest_is_rejected() -> None:
    case = _valid_case()
    draft = replace(_spec(), status="draft")
    other = "sha256:" + "0" * 64

    with pytest.raises(SpecDigestMismatchError) as raised:
        SpecSet((draft,)).read(_enveloped(draft, case, spec_digest=other))

    assert "draft" in str(raised.value)
    assert other in str(raised.value)
