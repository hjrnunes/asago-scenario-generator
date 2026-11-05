"""The installed runtime-contract reader behind the declared-target builder.

The producer's builder validates each declared target's contract against the copy
``asago_package`` carries, and that copy reads each document through the installed spec
set. These tests read every case, every contract the builder emits and the four refusals a
reader owes for both versions, so a builder that drifts from the installed spec fails here.
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
    ContractEnvelopeError,
    ContractSpec,
    MissingEnvelopeError,
    SpecDigestMismatchError,
    SpecSet,
    UnknownFieldError,
    UnknownRequirementError,
    UnsupportedVersionError,
    spec_digest,
    write_envelope,
)

from asago_package.contract_kit import contract_dir
from asago_package.runtime_contract_spec import (
    CONTRACT,
    LEGACY_VERSION,
    VERSION,
    VERSIONS,
    installed_specs,
    read_runtime_contract,
)

from asago_target_discovery.runtime_contract import (
    RUNTIME_CONTRACT_VERSION,
    declared_runtime_contract,
)

REPO = Path(__file__).resolve().parents[3]
_ROOTS = {version: contract_dir(CONTRACT) / version for version in VERSIONS}
#: The workspace checkout holds the replay corpus beside this repository.
_REPLAY_CORPUS = REPO.parent / "replay-corpus"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _replay_corpus() -> Path:
    """Return the replay corpus the recorded contracts live in.

    VAL-SAFETY-006: a test that reads the corpus fails loudly when the
    configured directory is missing; it must not read nothing and pass.
    """

    corpus = Path(os.environ.get("ASAGO_REPLAY_CORPUS", _REPLAY_CORPUS))
    if not corpus.is_dir():
        pytest.fail(f"the replay corpus directory does not exist: {corpus}")
    return corpus


def _spec(version: str = VERSION) -> ContractSpec:
    return installed_specs().spec(CONTRACT, version)


def _base() -> dict[str, Any]:
    return _json(_ROOTS[VERSION] / "cases" / "valid" / "minimal.json")


def _slot(**overrides: Any) -> dict[str, Any]:
    slot = {
        "id": "orders.note",
        "carrier_operation": "get_order",
        "field": "note",
        "writable_by": ["counterparty"],
        "content_kind": "free_text",
        "records": ["ORD-1"],
        "max_chars": 200,
        "mode": "replace",
    }
    slot.update(overrides)
    return slot


def _cases(version: str, kind: str) -> list[Path]:
    return sorted((_ROOTS[version] / "cases" / kind).glob("*.json"))


_VALID_CASES = [
    pytest.param(version, case, id=f"{version.rsplit('-', 1)[-1]}-{case.stem}")
    for version in VERSIONS
    for case in _cases(version, "valid")
]
_INVALID_CASES = [
    pytest.param(version, case, id=f"{version.rsplit('-', 1)[-1]}-{case.stem}")
    for version in VERSIONS
    for case in _cases(version, "invalid")
]


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
            "writer": "tests.runtime_contract_reader",
            "writer_version": "0.1.0",
            "validator_version": "asago-contracts-core 0.1.0",
        },
        **overrides,
    }
    return {**document, ENVELOPE_FIELD: envelope}


def test_the_builder_names_the_installed_version() -> None:
    assert (CONTRACT, RUNTIME_CONTRACT_VERSION) == ("runtime-contract", VERSION)
    assert _spec().spec_digest == spec_digest(
        _json(_ROOTS[VERSION] / "spec.json"),
        (_ROOTS[VERSION] / "schema.json").read_bytes(),
    )


@pytest.mark.parametrize(
    "case", _cases(LEGACY_VERSION, "valid"), ids=lambda case: case.stem
)
def test_the_reader_accepts_every_v2_case_as_a_legacy_document(case: Path) -> None:
    assert read_runtime_contract(_json(case)).version == LEGACY_VERSION


def test_the_reader_refuses_a_v3_document_without_the_envelope() -> None:
    with pytest.raises(
        MissingEnvelopeError, match="requires the self-identifying envelope"
    ):
        read_runtime_contract(_json(_cases(VERSION, "valid")[0]))


@pytest.mark.parametrize(("version", "case"), _VALID_CASES)
def test_the_reader_accepts_every_valid_case_with_the_envelope(
    version: str, case: Path
) -> None:
    written = write_envelope(
        _json(case),
        _spec(version),
        writer="tests.runtime_contract_reader",
        writer_version="0.1.0",
    )

    assert read_runtime_contract(written).version == version


@pytest.mark.parametrize(("version", "case"), _INVALID_CASES)
def test_the_reader_refuses_every_invalid_case(version: str, case: Path) -> None:
    document = _json(case)
    if _spec(version).envelope == "required":
        document = _enveloped(_spec(version), document)

    with pytest.raises(ContractEnvelopeError):
        read_runtime_contract(document)


def test_every_contract_the_builder_emits_reads() -> None:
    contracts = [
        declared_runtime_contract(_base(), seed_slots=[]),
        declared_runtime_contract(_base(), seed_slots=[_slot()]),
        declared_runtime_contract(
            _base(),
            seed_slots=[_slot()],
            delivery=["direct_user_message"],
            limits={"max_turns": 6},
        ),
    ]

    for contract in contracts:
        assert contract["contract"]["version"] == VERSION
        assert read_runtime_contract(contract).version == VERSION


@pytest.mark.replay_corpus
def test_every_recorded_contract_still_reads() -> None:
    """Every runtime contract recorded outside the cases reads as a v2 or v3 document."""

    corpus = _replay_corpus()
    recorded = sorted(corpus.rglob("runtime-contract.json"))
    if not recorded:
        pytest.skip(f"no recorded runtime contracts under {corpus}")

    for path in recorded:
        assert read_runtime_contract(_json(path)).version in VERSIONS, path


def test_a_missing_replay_corpus_fails_and_names_the_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "no-such-corpus"
    monkeypatch.setenv("ASAGO_REPLAY_CORPUS", str(missing))

    with pytest.raises(pytest.fail.Exception) as raised:
        _replay_corpus()

    assert str(missing) in str(raised.value)


@pytest.mark.parametrize(
    "version", VERSIONS, ids=lambda value: value.rsplit("-", 1)[-1]
)
def test_an_unsupported_version_names_the_supported_versions(version: str) -> None:
    case = _json(_cases(version, "valid")[0])

    with pytest.raises(UnsupportedVersionError) as raised:
        installed_specs().read(
            _enveloped(_spec(version), case, version="artifact-runtime-contract-v9")
        )

    assert "artifact-runtime-contract-v9" in str(raised.value)
    assert VERSION in str(raised.value)


@pytest.mark.parametrize(
    "version", VERSIONS, ids=lambda value: value.rsplit("-", 1)[-1]
)
def test_an_unknown_requires_entry_is_rejected(version: str) -> None:
    case = _json(_cases(version, "valid")[0])

    with pytest.raises(UnknownRequirementError) as raised:
        installed_specs().read(
            _enveloped(_spec(version), case, requires=["runtime-contract-v3"])
        )

    assert "runtime-contract-v3" in str(raised.value)


@pytest.mark.parametrize(
    "version", VERSIONS, ids=lambda value: value.rsplit("-", 1)[-1]
)
def test_an_unknown_field_outside_an_extension_is_rejected(version: str) -> None:
    case = _json(_cases(version, "valid")[0])
    document = _enveloped(_spec(version), case)
    document["probe_key"] = "a field the contract never declared"

    with pytest.raises(UnknownFieldError) as raised:
        read_runtime_contract(document)

    assert "probe_key" in str(raised.value)
    assert "declared extensions: none" in str(raised.value)


@pytest.mark.parametrize(
    "version", VERSIONS, ids=lambda value: value.rsplit("-", 1)[-1]
)
def test_a_draft_with_a_mismatched_spec_digest_is_rejected(version: str) -> None:
    case = _json(_cases(version, "valid")[0])
    draft = replace(_spec(version), status="draft")
    other = "sha256:" + "0" * 64

    with pytest.raises(SpecDigestMismatchError) as raised:
        SpecSet((draft,)).read(_enveloped(draft, case, spec_digest=other))

    assert "draft" in str(raised.value)
    assert other in str(raised.value)
