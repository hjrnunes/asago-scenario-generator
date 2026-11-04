"""The self-identifying envelope: installed specs, selection, and the reader rules.

A contract kit is split into its runtime spec (``spec.json`` and ``schema.json``, whose
bytes the spec digest covers), its cases and its docs. A document that carries the
envelope names the contract, the version and the spec digest it was written against;
a reader selects one of its installed specs and rejects everything it cannot place.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from asago_contracts_core.envelope import (
    CORE_VERSION,
    ENVELOPE_FIELD,
    ContractSpec,
    InvalidDocumentError,
    InvalidEnvelopeError,
    InvalidSpecError,
    MissingEnvelopeError,
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


def _schema(version: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["schema_version", "value"],
        "properties": {
            "schema_version": {"const": version},
            "value": {"type": "integer"},
        },
        "additionalProperties": False,
    }


def _write_spec(
    directory: Path,
    *,
    contract: str,
    version: str,
    status: str = "published",
    envelope: str = "required",
    supports: tuple[str, ...] = (),
    extensions: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Write one version's runtime spec and schema; return the spec document."""

    directory.mkdir(parents=True, exist_ok=True)
    schema_path = directory / "schema.json"
    schema_path.write_text(
        json.dumps(_schema(version), indent=2) + "\n", encoding="utf-8"
    )
    body: dict[str, Any] = {
        "contract": contract,
        "version": version,
        "status": status,
        "envelope": envelope,
        "supports": list(supports),
        "extensions": list(extensions),
        "schema": "schema.json",
    }
    body["spec_digest"] = spec_digest(body, schema_path.read_bytes())
    (directory / "spec.json").write_text(
        json.dumps(body, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return body


@pytest.fixture
def kit(tmp_path: Path) -> Path:
    """A contract kit with a published v1 (legacy documents allowed) and a draft v2."""

    root = tmp_path / "contracts"
    _write_spec(
        root / "demo" / "demo-v1",
        contract="demo",
        version="demo-v1",
        envelope="optional",
        supports=("feature-a",),
        extensions=("note",),
    )
    (root / "demo" / "demo-v1" / "cases").mkdir()
    (root / "demo" / "demo-v1" / "cases" / "valid.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (root / "demo" / "demo-v1" / "README.md").write_text(
        "# demo-v1\n", encoding="utf-8"
    )
    _write_spec(
        root / "demo" / "demo-v2",
        contract="demo",
        version="demo-v2",
        status="draft",
        supports=("feature-a", "feature-b"),
    )
    return root


def _legacy(version: str = "demo-v1") -> dict[str, Any]:
    return {"schema_version": version, "value": 1}


def _enveloped(spec: ContractSpec, **overrides: Any) -> dict[str, Any]:
    document = _legacy(spec.version)
    document[ENVELOPE_FIELD] = {
        "id": spec.contract,
        "version": spec.version,
        "spec_digest": spec.spec_digest,
        "requires": [],
        "provenance": {
            "writer": "tests",
            "writer_version": "1.0.0",
            "validator_version": f"asago-contracts-core {CORE_VERSION}",
        },
        **overrides,
    }
    return document


def test_the_envelope_is_part_of_the_public_surface() -> None:
    import asago_contracts_core as core

    for name in (
        "CORE_VERSION",
        "ENVELOPE_FIELD",
        "SpecSet",
        "envelope_schema",
        "load_specs",
        "read_envelope",
        "spec_digest",
        "write_envelope",
    ):
        assert hasattr(core, name), name


def test_an_installed_spec_identifies_itself(kit: Path) -> None:
    specs = load_specs(kit)

    spec = specs.spec("demo", "demo-v1")

    assert spec.status == "published"
    assert spec.envelope == "optional"
    assert spec.supports == ("feature-a",)
    assert spec.extensions == ("note",)
    assert spec.spec_digest == spec_digest(
        {
            "contract": "demo",
            "version": "demo-v1",
            "status": "published",
            "envelope": "optional",
            "supports": ["feature-a"],
            "extensions": ["note"],
            "schema": "schema.json",
        },
        (kit / "demo" / "demo-v1" / "schema.json").read_bytes(),
    )
    assert specs.versions("demo") == ("demo-v1", "demo-v2")


def test_editing_a_case_does_not_change_the_spec_digest(kit: Path) -> None:
    before = load_specs(kit).spec("demo", "demo-v1").spec_digest

    (kit / "demo" / "demo-v1" / "cases" / "valid.json").write_text('{"x": 1}\n')
    (kit / "demo" / "demo-v1" / "README.md").write_text("# changed\n")

    assert load_specs(kit).spec("demo", "demo-v1").spec_digest == before


def test_editing_the_runtime_schema_changes_the_spec_digest(kit: Path) -> None:
    before = load_specs(kit).spec("demo", "demo-v1").spec_digest
    schema_path = kit / "demo" / "demo-v1" / "schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["title"] = "changed"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    with pytest.raises(SpecDigestMismatchError, match="demo-v1"):
        load_specs(kit)

    assert before != spec_digest(
        {
            "contract": "demo",
            "version": "demo-v1",
            "status": "published",
            "envelope": "optional",
            "supports": ["feature-a"],
            "extensions": ["note"],
            "schema": "schema.json",
        },
        schema_path.read_bytes(),
    )


def test_a_written_envelope_is_read_back(kit: Path) -> None:
    specs = load_specs(kit)
    spec = specs.spec("demo", "demo-v2")

    written = write_envelope(
        _legacy("demo-v2"),
        spec,
        writer="tests.writer",
        writer_version="1.2.3",
        requires=["feature-b"],
    )

    assert written[ENVELOPE_FIELD] == {
        "id": "demo",
        "version": "demo-v2",
        "spec_digest": spec.spec_digest,
        "requires": ["feature-b"],
        "provenance": {
            "writer": "tests.writer",
            "writer_version": "1.2.3",
            "validator_version": f"asago-contracts-core {CORE_VERSION}",
        },
    }
    assert specs.read(written) is spec
    assert (
        list(
            Draft202012Validator(envelope_schema()).iter_errors(written[ENVELOPE_FIELD])
        )
        == []
    )


def test_the_envelope_has_exactly_the_five_fields() -> None:
    envelope = {
        "id": "demo",
        "version": "demo-v1",
        "spec_digest": "sha256:" + "0" * 64,
        "requires": [],
        "provenance": {
            "writer": "w",
            "writer_version": "1",
            "validator_version": "2",
        },
        "extra": True,
    }

    assert Draft202012Validator(envelope_schema()).iter_errors(envelope)
    with pytest.raises(InvalidEnvelopeError, match="extra"):
        read_envelope({"contract": envelope})


def test_an_unsupported_version_lists_the_supported_ones(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v2"), version="demo-v9")

    with pytest.raises(UnsupportedVersionError) as raised:
        specs.read(document)

    assert "demo-v9" in str(raised.value)
    assert "demo-v1" in str(raised.value)
    assert "demo-v2" in str(raised.value)


def test_an_unknown_contract_lists_the_installed_ones(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"), id="other")

    with pytest.raises(UnknownContractError) as raised:
        specs.read(document)

    assert "other" in str(raised.value)
    assert "demo" in str(raised.value)


def test_an_unknown_requirement_is_rejected(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"), requires=["feature-z"])

    with pytest.raises(UnknownRequirementError) as raised:
        specs.read(document)

    assert "feature-z" in str(raised.value)
    assert "feature-a" in str(raised.value)


def test_a_known_requirement_is_accepted(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"), requires=["feature-a"])

    assert specs.read(document).version == "demo-v1"


def test_an_unknown_field_is_rejected(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"))
    document["surprise"] = 1

    with pytest.raises(UnknownFieldError) as raised:
        specs.read(document)

    assert "surprise" in str(raised.value)
    assert "note" in str(raised.value)


def test_a_declared_extension_is_ignored(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"))
    document["note"] = "the reader may ignore this"

    assert specs.read(document).version == "demo-v1"


def test_a_draft_with_another_spec_digest_is_rejected(kit: Path) -> None:
    specs = load_specs(kit)
    other = "sha256:" + "1" * 64
    document = _enveloped(specs.spec("demo", "demo-v2"), spec_digest=other)

    with pytest.raises(SpecDigestMismatchError) as raised:
        specs.read(document)

    assert "demo-v2" in str(raised.value)
    assert "draft" in str(raised.value)
    assert other in str(raised.value)


def test_a_published_spec_with_another_spec_digest_is_rejected(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(
        specs.spec("demo", "demo-v1"), spec_digest="sha256:" + "2" * 64
    )

    with pytest.raises(SpecDigestMismatchError, match="published"):
        specs.read(document)


def test_a_legacy_document_is_read_by_its_version(kit: Path) -> None:
    specs = load_specs(kit)

    assert specs.read(_legacy("demo-v1")).version == "demo-v1"


def test_a_legacy_document_a_spec_requires_the_envelope_for_is_rejected(
    kit: Path,
) -> None:
    specs = load_specs(kit)

    with pytest.raises(MissingEnvelopeError, match="demo-v2"):
        specs.read(_legacy("demo-v2"))


def test_a_legacy_document_naming_an_unknown_version_lists_the_supported_ones(
    kit: Path,
) -> None:
    specs = load_specs(kit)

    with pytest.raises(UnsupportedVersionError) as raised:
        specs.read(_legacy("demo-v9"))

    assert "demo-v1" in str(raised.value)


def test_the_schema_rejects_a_document_the_spec_does_not_admit(kit: Path) -> None:
    specs = load_specs(kit)
    document = _enveloped(specs.spec("demo", "demo-v1"))
    del document["value"]

    with pytest.raises(InvalidDocumentError, match="value"):
        specs.read(document)


def test_writing_refuses_a_document_the_spec_rejects(kit: Path) -> None:
    spec = load_specs(kit).spec("demo", "demo-v1")

    with pytest.raises(UnknownFieldError, match="surprise"):
        write_envelope(
            {**_legacy(), "surprise": 1},
            spec,
            writer="tests",
            writer_version="1",
        )


def test_a_spec_with_a_wrong_digest_is_refused_when_loaded(kit: Path) -> None:
    path = kit / "demo" / "demo-v1" / "spec.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["spec_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SpecDigestMismatchError, match="demo-v1"):
        load_specs(kit)


def test_a_spec_must_not_point_outside_its_directory(kit: Path) -> None:
    path = kit / "demo" / "demo-v1" / "spec.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["schema"] = "../demo-v2/schema.json"
    document["spec_digest"] = spec_digest(
        document, (kit / "demo" / "demo-v1" / "schema.json").read_bytes()
    )
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(InvalidSpecError, match="schema"):
        load_specs(kit)


def test_the_same_contract_and_version_cannot_be_installed_twice(
    tmp_path: Path,
) -> None:
    root = tmp_path / "contracts"
    _write_spec(root / "demo" / "demo-v1", contract="demo", version="demo-v1")
    _write_spec(root / "other" / "demo-v1", contract="demo", version="demo-v1")

    with pytest.raises(InvalidSpecError, match="demo-v1"):
        load_specs(root)


def test_a_directory_without_a_spec_is_not_an_installed_contract(
    tmp_path: Path,
) -> None:
    (tmp_path / "contracts" / "notes").mkdir(parents=True)
    (tmp_path / "contracts" / "notes" / "README.md").write_text("# notes\n")

    with pytest.raises(InvalidSpecError, match="no installed"):
        load_specs(tmp_path / "contracts")


def test_a_spec_set_without_the_contract_names_the_installed_ones(kit: Path) -> None:
    specs: SpecSet = load_specs(kit)

    with pytest.raises(UnknownContractError, match="demo"):
        specs.spec("midojo-delivery", "midojo-delivery-v1")
