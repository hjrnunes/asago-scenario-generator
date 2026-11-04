"""The installed runtime-contract reader behind the declared-target builder.

The producer's builder validates each declared target's contract against the copy
``asago_package`` carries, and that copy now reads each document through the installed spec
set. These tests read every case, every contract the builder emits and the four refusals a
reader owes, so a builder that drifts from the installed spec fails here.
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
    VERSION,
    installed_specs,
    read_runtime_contract,
)

from asago_target_discovery.runtime_contract import (
    RUNTIME_CONTRACT_VERSION,
    declared_runtime_contract,
)

REPO = Path(__file__).resolve().parents[3]
_SPEC_ROOT = contract_dir(CONTRACT) / VERSION
_CASES = _SPEC_ROOT / "cases"
_SCHEMA = _SPEC_ROOT / "schema.json"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _spec() -> ContractSpec:
    return installed_specs().spec(CONTRACT, VERSION)


def _base() -> dict[str, Any]:
    return _json(_CASES / "valid" / "minimal.json")


def _slot(**overrides: Any) -> dict[str, Any]:
    slot = {
        "id": "orders.note",
        "carrier_operation": "get_order",
        "field": "note",
        "controller": "counterparty",
        "content_kind": "free_text",
        "records": ["ORD-1"],
        "max_chars": 200,
        "mode": "replace",
    }
    slot.update(overrides)
    return slot


def _valid_cases() -> list[Path]:
    return sorted((_CASES / "valid").glob("*.json"))


def _invalid_cases() -> list[Path]:
    return sorted((_CASES / "invalid").glob("*.json"))


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
        _json(_SPEC_ROOT / "spec.json"), _SCHEMA.read_bytes()
    )


@pytest.mark.parametrize("case", _valid_cases(), ids=lambda case: case.stem)
def test_the_reader_accepts_every_valid_case_as_a_legacy_document(case: Path) -> None:
    assert read_runtime_contract(_json(case)).version == VERSION


@pytest.mark.parametrize("case", _valid_cases(), ids=lambda case: case.stem)
def test_the_reader_accepts_every_valid_case_with_the_envelope(case: Path) -> None:
    written = write_envelope(
        _json(case),
        _spec(),
        writer="tests.runtime_contract_reader",
        writer_version="0.1.0",
    )

    assert read_runtime_contract(written).version == VERSION


@pytest.mark.parametrize("case", _invalid_cases(), ids=lambda case: case.stem)
def test_the_reader_refuses_every_invalid_case(case: Path) -> None:
    with pytest.raises(ContractEnvelopeError):
        read_runtime_contract(_json(case))


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
        assert read_runtime_contract(contract).version == VERSION


def test_every_recorded_contract_still_reads() -> None:
    """Every runtime contract recorded outside the cases reads as a v2 document."""

    corpus = Path(os.environ.get("ASAGO_REPLAY_CORPUS", REPO.parent / "replay-corpus"))
    recorded = sorted(corpus.rglob("runtime-contract.json")) if corpus.is_dir() else []
    if not recorded:
        pytest.skip(f"no recorded runtime contracts under {corpus}")

    for path in recorded:
        assert read_runtime_contract(_json(path)).version == VERSION, path


def test_an_unsupported_version_names_the_supported_versions() -> None:
    with pytest.raises(UnsupportedVersionError) as raised:
        installed_specs().read(
            _enveloped(_spec(), _base(), version="artifact-runtime-contract-v9")
        )

    assert "artifact-runtime-contract-v9" in str(raised.value)
    assert VERSION in str(raised.value)


def test_an_unknown_requires_entry_is_rejected() -> None:
    with pytest.raises(UnknownRequirementError) as raised:
        installed_specs().read(
            _enveloped(_spec(), _base(), requires=["runtime-contract-v3"])
        )

    assert "runtime-contract-v3" in str(raised.value)


def test_an_unknown_field_outside_an_extension_is_rejected() -> None:
    document = _enveloped(_spec(), _base())
    document["probe_key"] = "a field v2 never declared"

    with pytest.raises(UnknownFieldError) as raised:
        read_runtime_contract(document)

    assert "probe_key" in str(raised.value)
    assert "declared extensions: none" in str(raised.value)


def test_a_draft_with_a_mismatched_spec_digest_is_rejected() -> None:
    draft = replace(_spec(), status="draft")
    other = "sha256:" + "0" * 64

    with pytest.raises(SpecDigestMismatchError) as raised:
        SpecSet((draft,)).read(_enveloped(draft, _base(), spec_digest=other))

    assert "draft" in str(raised.value)
    assert other in str(raised.value)
