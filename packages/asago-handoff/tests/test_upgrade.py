"""Tests for the scenario-handoff saved-artifact migration."""

from __future__ import annotations

import json

import pytest

from asago_contracts_core import (
    ENVELOPE_FIELD,
    UnsupportedVersionError,
    registered_upgrades,
    write_envelope,
)
from asago_handoff import (
    CONTRACT,
    CONTRACT_DIR,
    HANDOFF_UPGRADE,
    KIT_V5,
    KIT_V6,
    installed_specs,
    upgrade,
)


def _valid_cases(version):
    return sorted((CONTRACT_DIR / version / "cases" / "valid").glob("*.json"))


def test_the_handoff_package_registers_its_v5_to_v6_upgrade():
    assert HANDOFF_UPGRADE.contract == CONTRACT
    assert (HANDOFF_UPGRADE.from_version, HANDOFF_UPGRADE.to_version) == (
        KIT_V5,
        KIT_V6,
    )
    assert HANDOFF_UPGRADE in registered_upgrades(CONTRACT)


def test_every_v5_valid_case_upgrades_to_its_v6_case():
    cases = _valid_cases(KIT_V5)

    assert len(cases) == 18
    for path in cases:
        upgraded = upgrade(json.loads(path.read_text()), installed_specs())
        body = {key: value for key, value in upgraded.items() if key != ENVELOPE_FIELD}
        expected = json.loads(
            (CONTRACT_DIR / KIT_V6 / "cases" / "valid" / path.name).read_text()
        )

        assert body == expected, path.name


def test_an_upgraded_handoff_reads_as_the_current_version():
    upgraded = upgrade(
        json.loads(_valid_cases(KIT_V5)[0].read_text()), installed_specs()
    )

    assert installed_specs().read(upgraded).version == KIT_V6
    assert upgraded[ENVELOPE_FIELD]["version"] == KIT_V6
    assert upgraded[ENVELOPE_FIELD]["provenance"]["writer"] == (
        "asago-contracts-core.upgrade"
    )


def test_a_current_handoff_is_not_upgraded():
    specs = installed_specs()
    current = write_envelope(
        json.loads(_valid_cases(KIT_V6)[0].read_text()),
        specs.spec(CONTRACT, KIT_V6),
        writer="test",
        writer_version="0",
    )

    with pytest.raises(UnsupportedVersionError, match="already the newest"):
        upgrade(current, specs)
