"""Tests for the contract support window."""

from __future__ import annotations

import pytest

from asago_contracts_core import (
    SUPPORT_POLICY,
    InvalidVersionNameError,
    UnsupportedVersionError,
    check_support_window,
    support_window,
)


def test_the_policy_names_the_precedent_it_encodes():
    assert "readers" in SUPPORT_POLICY
    assert "saved artifacts" in SUPPORT_POLICY
    assert "current and the previous major" in SUPPORT_POLICY
    assert "dcpl.2" in SUPPORT_POLICY
    assert "artifact-package-v4" in SUPPORT_POLICY
    assert "tool-call-condition-v1" in SUPPORT_POLICY


def test_a_retirement_keeps_the_version_a_newer_reader_still_reads():
    windows = support_window(
        "demo",
        ("demo-v1", "demo-v2", "demo-v3"),
        read_by={"demo-v1": "demo-v3"},
        retired=("demo-v2",),
    )
    statuses = {w.version: w.status for w in windows}

    assert statuses == {
        "demo-v1": "supported",
        "demo-v2": "retired",
        "demo-v3": "supported",
    }


def test_a_version_a_newer_version_still_reads_is_supported_outside_the_window():
    windows = support_window(
        "demo", ("demo-v1", "demo-v3"), read_by={"demo-v1": "demo-v3"}
    )

    assert [(w.version, w.status) for w in windows] == [
        ("demo-v1", "supported"),
        ("demo-v3", "supported"),
    ]


def test_a_version_without_a_reader_retires_outside_the_window():
    windows = support_window(
        "demo", ("demo-v1", "demo-v2", "demo-v4"), read_by={"demo-v1": "demo-v3"}
    )

    assert [(w.version, w.status) for w in windows] == [
        ("demo-v1", "supported"),
        ("demo-v2", "retired"),
        ("demo-v4", "supported"),
    ]


def test_an_explicit_retirement_overrides_the_window():
    windows = support_window("demo", ("demo-v1", "demo-v4"), retired=("demo-v1",))

    assert [(w.version, w.status, w.retired) for w in windows] == [
        ("demo-v1", "retired", True),
        ("demo-v4", "supported", False),
    ]


def test_the_current_and_previous_major_stay_supported():
    windows = support_window("demo", ("demo-v1", "demo-v3", "demo-v4"))
    statuses = {w.version: (w.major, w.status) for w in windows}

    assert statuses == {
        "demo-v1": (1, "retired"),
        "demo-v3": (3, "supported"),
        "demo-v4": (4, "supported"),
    }


def test_a_new_major_beyond_the_previous_one_does_not_keep_older_majors():
    windows = support_window("demo", ("demo-v1", "demo-v2", "demo-v3", "demo-v5"))

    assert [w.status for w in windows] == [
        "retired",
        "retired",
        "retired",
        "supported",
    ]


def test_the_window_lists_versions_in_ascending_order():
    windows = support_window("demo", ("demo-v10", "demo-v2", "demo-v9"))

    assert [w.version for w in windows] == ["demo-v2", "demo-v9", "demo-v10"]


def test_the_window_reports_the_reader():
    windows = support_window(
        "demo", ("demo-v1", "demo-v3"), read_by={"demo-v1": "demo-v2"}
    )

    assert windows[0].read_by == "demo-v2"


def test_check_support_window_refuses_a_retired_version_and_names_it():
    with pytest.raises(UnsupportedVersionError, match="demo-v4 is retired"):
        check_support_window("demo", ("demo-v4", "demo-v5"), retired=("demo-v4",))


def test_check_support_window_accepts_every_supported_version():
    assert (
        check_support_window(
            "demo", ("demo-v1", "demo-v4"), read_by={"demo-v1": "demo-v3"}
        )
        is None
    )


def test_support_window_accepts_a_historical_version_prefix():
    entries = support_window(
        "runtime-contract",
        ("artifact-runtime-contract-v2", "artifact-runtime-contract-v3"),
    )

    assert [entry.version for entry in entries] == [
        "artifact-runtime-contract-v2",
        "artifact-runtime-contract-v3",
    ]
    assert [entry.status for entry in entries] == ["supported", "supported"]


@pytest.mark.parametrize(
    ("versions", "read_by", "retired"),
    [
        (("demo-v1", "demo-v1"), None, ()),
        (("demo-latest",), None, ()),
        (("demo-v1",), {"demo-v1": "demo-v1.0.0-beta"}, ()),
        (("demo-v1",), {"demo-v2": "demo-v3"}, ()),
        (("demo-v1",), None, ("demo-v2",)),
    ],
)
def test_support_window_refuses_a_version_that_is_not_release_semver(
    versions, read_by, retired
):
    with pytest.raises((InvalidVersionNameError, ValueError)):
        support_window("demo", versions, read_by=read_by, retired=retired)


def test_support_window_refuses_a_reader_key_that_is_not_an_installed_name():
    with pytest.raises(InvalidVersionNameError):
        support_window("demo", ("demo-v1",), read_by={"demo": "demo-v2"})


def test_support_window_refuses_a_retired_newest_version():
    with pytest.raises(ValueError, match="newest installed version"):
        support_window("demo", ("demo-v4", "demo-v5"), retired=("demo-v5",))


def test_support_window_refuses_a_version_that_is_both_retired_and_read():
    with pytest.raises(ValueError, match="both retired and read"):
        support_window(
            "demo",
            ("demo-v4", "demo-v5"),
            read_by={"demo-v4": "demo-v5"},
            retired=("demo-v4",),
        )


def test_support_window_refuses_a_reader_older_than_the_version_it_reads():
    with pytest.raises(ValueError, match="older than"):
        support_window("demo", ("demo-v4", "demo-v5"), read_by={"demo-v5": "demo-v3"})
