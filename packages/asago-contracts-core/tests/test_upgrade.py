"""Tests for the saved-artifact upgrade hook."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_contracts_core import (
    CORE_VERSION,
    ENVELOPE_FIELD,
    UnknownRequirementError,
    Upgrade,
    UpgradeError,
    UnsupportedVersionError,
    canonical_json,
    load_specs,
    register_upgrade,
    registered_upgrades,
    spec_digest,
    upgrade,
    write_envelope,
)

_DEMO_V1 = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "value"],
    "properties": {
        "schema_version": {"const": "demo-v1"},
        "value": {"type": "integer"},
    },
}
_DEMO_V2 = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "count"],
    "properties": {
        "schema_version": {"const": "demo-v2"},
        "count": {"type": "integer"},
    },
}
_DEMO_V3 = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "count", "label"],
    "properties": {
        "schema_version": {"const": "demo-v3"},
        "count": {"type": "integer"},
        "label": {"type": "string"},
    },
}


def _install(root, contract, version, schema, *, envelope="required", supports=()):
    directory = Path(root) / contract / version
    directory.mkdir(parents=True)
    schema_bytes = canonical_json(schema).encode("utf-8")
    (directory / "schema.json").write_bytes(schema_bytes)
    body = {
        "contract": contract,
        "version": version,
        "status": "published",
        "envelope": envelope,
        "supports": list(supports),
        "extensions": [],
        "schema": "schema.json",
    }
    body["spec_digest"] = spec_digest(body, schema_bytes)
    (directory / "spec.json").write_text(json.dumps(body), encoding="utf-8")


@pytest.fixture
def demo(tmp_path):
    root = tmp_path / "contracts"
    _install(root, "demo", "demo-v1", _DEMO_V1, envelope="optional")
    _install(root, "demo", "demo-v2", _DEMO_V2)
    _install(root, "demo", "demo-v3", _DEMO_V3, supports=("note",))
    return root, load_specs(root)


def _to_v2(body):
    body = dict(body)
    body["count"] = body.pop("value")
    body["schema_version"] = "demo-v2"
    return body


def _to_v3(body):
    body = dict(body)
    body["label"] = "migrated"
    body["schema_version"] = "demo-v3"
    return body


def _steps():
    return (
        Upgrade("demo", "demo-v1", "demo-v2", _to_v2),
        Upgrade("demo", "demo-v2", "demo-v3", _to_v3),
    )


def _enveloped(specs, contract, version, body, requires=()):
    return write_envelope(
        body,
        specs.spec(contract, version),
        writer="test",
        writer_version="0",
        requires=requires,
    )


def test_a_legacy_document_upgrades_and_carries_the_target_envelope(demo):
    _, specs = demo
    result = upgrade({"schema_version": "demo-v1", "value": 7}, specs, steps=_steps())

    assert result[ENVELOPE_FIELD]["id"] == "demo"
    assert result[ENVELOPE_FIELD]["version"] == "demo-v3"
    assert {k: v for k, v in result.items() if k != ENVELOPE_FIELD} == {
        "schema_version": "demo-v3",
        "count": 7,
        "label": "migrated",
    }
    assert specs.read(result).version == "demo-v3"


def test_an_upgraded_document_records_who_wrote_the_envelope(demo):
    _, specs = demo
    result = upgrade({"schema_version": "demo-v1", "value": 7}, specs, steps=_steps())

    provenance = result[ENVELOPE_FIELD]["provenance"]
    assert provenance["writer"] == "asago-contracts-core.upgrade"
    assert provenance["writer_version"] == CORE_VERSION


def test_an_upgrade_runs_each_registered_step_in_order(demo):
    _, specs = demo
    calls = []

    def first(body):
        calls.append("first")
        return _to_v2(body)

    def second(body):
        calls.append("second")
        return _to_v3(body)

    upgrade(
        {"schema_version": "demo-v1", "value": 7},
        specs,
        steps=(
            Upgrade("demo", "demo-v1", "demo-v2", first),
            Upgrade("demo", "demo-v2", "demo-v3", second),
        ),
    )

    assert calls == ["first", "second"]


def test_an_upgrade_carries_the_requirements_it_read(tmp_path):
    root = tmp_path / "contracts"
    _install(root, "demo", "demo-v1", _DEMO_V1, envelope="optional", supports=("note",))
    _install(root, "demo", "demo-v2", _DEMO_V2, supports=("note",))
    specs = load_specs(root)
    document = _enveloped(
        specs,
        "demo",
        "demo-v1",
        {"schema_version": "demo-v1", "value": 7},
        requires=("note",),
    )

    result = upgrade(
        document, specs, steps=(Upgrade("demo", "demo-v1", "demo-v2", _to_v2),)
    )

    assert result[ENVELOPE_FIELD]["requires"] == ["note"]


def test_an_upgrade_refuses_a_requirement_the_target_does_not_support(tmp_path):
    root = tmp_path / "contracts"
    _install(root, "demo", "demo-v1", _DEMO_V1, envelope="optional", supports=("note",))
    _install(root, "demo", "demo-v2", _DEMO_V2)
    specs = load_specs(root)
    document = _enveloped(
        specs,
        "demo",
        "demo-v1",
        {"schema_version": "demo-v1", "value": 7},
        requires=("note",),
    )

    with pytest.raises(UnknownRequirementError, match="unknown requires"):
        upgrade(document, specs, steps=(Upgrade("demo", "demo-v1", "demo-v2", _to_v2),))


def test_a_document_already_at_the_newest_version_is_refused(demo):
    _, specs = demo
    document = _enveloped(
        specs,
        "demo",
        "demo-v3",
        {"schema_version": "demo-v3", "count": 7, "label": "x"},
    )

    with pytest.raises(UnsupportedVersionError, match="already the newest"):
        upgrade(document, specs, steps=_steps())


def test_a_missing_hop_is_refused_and_names_the_next_version(demo):
    _, specs = demo
    document = _enveloped(
        specs, "demo", "demo-v2", {"schema_version": "demo-v2", "count": 7}
    )

    with pytest.raises(UnsupportedVersionError, match="no upgrade from demo-v2"):
        upgrade(document, specs, steps=_steps()[:1])


def test_a_step_that_does_not_advance_the_version_is_refused(demo):
    _, specs = demo

    def stalled(body):
        return dict(body)

    with pytest.raises(UpgradeError, match="left the document"):
        upgrade(
            {"schema_version": "demo-v1", "value": 7},
            specs,
            steps=(Upgrade("demo", "demo-v1", "demo-v2", stalled),),
        )


def test_a_step_may_not_move_a_version_backwards():
    with pytest.raises(UpgradeError, match="forward"):
        register_upgrade("demo", "demo-v2", "demo-v1", _to_v2)


def test_the_registry_reports_and_filters_a_registered_upgrade():
    hop = register_upgrade(
        "registry-demo", "registry-demo-v1", "registry-demo-v2", _to_v2
    )

    assert hop in registered_upgrades()
    assert registered_upgrades("registry-demo") == (hop,)
