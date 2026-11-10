"""Tests for the contract version-name and semantic-version rules."""

from __future__ import annotations

import pytest

from asago_contracts_core import (
    ContractVersionNameError,
    InvalidVersionNameError,
    SemVer,
    parse_version,
    parse_version_name,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1", (1, 0, 0)),
        ("2.3", (2, 3, 0)),
        ("1.2.3", (1, 2, 3)),
        (" 1.2.3 ", (1, 2, 3)),
    ],
)
def test_parse_version_fills_missing_components(text, expected):
    version = parse_version(text)

    assert (version.major, version.minor, version.patch) == expected


@pytest.mark.parametrize(
    "text",
    ["", " ", "v1", "1.", "1.2.", ".1", "1.2.3.4", "1..2", "1.2.x", "-1", "1.0.0-rc1"],
)
def test_parse_version_refuses_a_name_that_is_not_release_semver(text):
    with pytest.raises(InvalidVersionNameError):
        parse_version(text)


def test_semvers_order_and_compare_by_number_not_text():
    ordered = [
        parse_version("1.0.0"),
        parse_version("1.0.1"),
        parse_version("1.2.0"),
        parse_version("1.10.0"),
        parse_version("2.0.0"),
    ]

    assert ordered == sorted(ordered)
    assert len(set(ordered)) == len(ordered)


def test_a_semver_renders_and_compares_against_another_semver():
    version = SemVer(1, 2, 3)

    assert str(version) == "1.2.3"
    assert version == SemVer(1, 2, 3)
    assert version > SemVer(1, 2, 0)


@pytest.mark.parametrize(
    ("name", "contract", "expected"),
    [
        ("execution-receipt-v2", "execution-receipt", (2, 0, 0)),
        ("demo-v5", "demo", (5, 0, 0)),
        ("example-v1.1.0", "example", (1, 1, 0)),
        ("attack-flow-2.0.0", "attack-flow", (2, 0, 0)),
    ],
)
def test_parse_version_name_reads_the_version_of_a_named_contract(
    name, contract, expected
):
    parsed = parse_version_name(name, contract=contract)

    assert parsed.contract == contract
    assert (
        parsed.version.major,
        parsed.version.minor,
        parsed.version.patch,
    ) == expected


def test_parse_version_name_reads_the_contract_the_version_name_carries():
    parsed = parse_version_name("artifact-seed-v1")

    assert parsed.contract == "artifact-seed"
    assert parsed.version == SemVer(1, 0, 0)


@pytest.mark.parametrize(
    "name",
    [
        "example",
        "example-v",
        "example-v1.0-beta",
        "example-2",
        "example-2.0",
        "example-v1.2.3.4",
    ],
)
def test_parse_version_name_refuses_a_name_without_a_release_version(name):
    with pytest.raises(InvalidVersionNameError):
        parse_version_name(name, contract="example")


def test_parse_version_name_refuses_a_name_for_another_contract():
    with pytest.raises(ContractVersionNameError):
        parse_version_name("other-v1", contract="example")
