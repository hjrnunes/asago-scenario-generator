"""The contract support window.

A published version is immortal: saved artifacts still name it, so a reader must
keep reading it. Support therefore follows actual readers and saved artifacts,
not a calendar. The dcpl.2 retirement is the precedent: the owner retired
``artifact-package-v4`` reading and ``tool-call-condition-v1`` because nothing
that must still load used them, and re-locked every copy.

The rules make that decision reviewable:

* A version that a newer installed version still reads is supported.
* The newest installed major and the major before it are supported.
* A version the change names for retirement is retired, even inside that window.
* Every other installed version is retired.

``check_support_window`` fails when the set contains a retired version. Retire a
version by naming it in the change that removes it, as dcpl.2 did, and by
dropping its reader; do not let it linger unreadable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .envelope import UnsupportedVersionError
from .semver import InvalidVersionNameError, SemVer, parse_version_name

SUPPORT_POLICY = (
    "support follows actual readers and saved artifacts: a version that a newer "
    "installed version still reads is supported, the current and the previous "
    "major stay supported, and a version named for retirement is retired even "
    "inside that window (precedent: the dcpl.2 retirement of artifact-package-v4 "
    "reading and tool-call-condition-v1, which needed no reader because nothing "
    "that must still load used them)"
)

SUPPORT_STATUSES = ("supported", "retired")


@dataclass(frozen=True)
class VersionSupport:
    """One installed version and the support the window gives it."""

    version: str
    semver: SemVer
    major: int
    read_by: str | None
    retired: bool
    status: str


def support_window(
    contract: str,
    versions: Iterable[str],
    *,
    read_by: Mapping[str, str] | None = None,
    retired: Iterable[str] = (),
) -> tuple[VersionSupport, ...]:
    """Return the support status of each installed version, oldest first.

    ``read_by`` maps an installed version to the newest version that still reads
    it; ``retired`` names the versions this change retires. A version name needs
    a semantic version, not the contract's prefix: the runtime contract's
    versions begin with ``artifact-runtime-contract``.
    """

    if not isinstance(contract, str) or not contract.strip():
        raise ValueError("a contract name must be a non-empty string")
    read_by = dict(read_by or {})
    parsed: dict[str, SemVer] = {}
    for name in versions:
        item = parse_version_name(name)
        if name in parsed:
            raise InvalidVersionNameError(f"duplicate version name: {name!r}")
        parsed[name] = item.version
    if not parsed:
        return ()
    ordered = sorted(parsed, key=lambda name: parsed[name])
    readers: dict[str, str] = {}
    for name, reader in sorted(read_by.items()):
        parse_version_name(name)
        if name not in parsed:
            raise ValueError(
                f"read_by names {name!r}, which is not an installed version"
            )
        reader_version = parse_version_name(reader).version
        if reader_version < parsed[name]:
            raise ValueError(
                f"read_by names {reader!r}, which is older than the version "
                f"{name!r} it reads"
            )
        readers[name] = reader
    named = set(retired)
    for name in sorted(named):
        if name not in parsed:
            raise ValueError(f"retired names {name!r}, which is not installed")
        if name == ordered[-1]:
            raise ValueError(f"the newest installed version {name!r} cannot be retired")
        if name in readers:
            raise ValueError(f"{name!r} is both retired and read by {readers[name]!r}")

    newest = parsed[ordered[-1]].major
    previous = newest - 1
    entries = []
    for name in ordered:
        retired_now = name in named
        in_window = parsed[name].major in (newest, previous)
        status = (
            "retired"
            if retired_now or not (name in readers or in_window)
            else "supported"
        )
        entries.append(
            VersionSupport(
                version=name,
                semver=parsed[name],
                major=parsed[name].major,
                read_by=readers.get(name),
                retired=retired_now,
                status=status,
            )
        )
    return tuple(entries)


def check_support_window(
    contract: str,
    versions: Iterable[str],
    *,
    read_by: Mapping[str, str] | None = None,
    retired: Iterable[str] = (),
) -> None:
    """Fail when an installed version is outside the support window."""

    for entry in support_window(contract, versions, read_by=read_by, retired=retired):
        if entry.status == "retired":
            raise UnsupportedVersionError(
                f"{contract}: {entry.version} is retired; support follows actual "
                "readers and saved artifacts"
            )
