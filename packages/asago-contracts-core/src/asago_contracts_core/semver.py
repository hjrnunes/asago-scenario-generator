"""Semantic versions and contract version-directory names.

A published contract version never changes meaning, so a schema change that
breaks an existing document needs a new major version. Version directories carry
the version in their name; these helpers read that name and compare versions
without changing any contract bytes. The directory name is the authority for the
semantic version: a spec's ``version`` field must equal it, but the spec does not
carry a second copy that could drift.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_RELEASE = re.compile(
    r"^(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?$"
)
_VERSIONED_NAME = re.compile(
    r"^(?P<contract>.+?)-v(?P<version>"
    r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,2})$"
)
_BARE_SEMVER_NAME = re.compile(
    r"^(?P<contract>.+?)-(?P<version>0|[1-9]\d*\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$"
)


class InvalidVersionNameError(ValueError):
    """A version or a version-directory name is not release semver."""


class ContractVersionNameError(InvalidVersionNameError):
    """A version-directory name belongs to a different contract."""


@dataclass(frozen=True, order=True)
class SemVer:
    """A release semantic version: major, minor and patch numbers only."""

    major: int
    minor: int = 0
    patch: int = 0

    def __post_init__(self):
        for name in ("major", "minor", "patch"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidVersionNameError(
                    f"a semantic version {name} must be a non-negative integer: "
                    f"{value!r}"
                )

    @property
    def series(self) -> tuple[int, int]:
        """Return the ``major.minor`` series a version belongs to."""

        return (self.major, self.minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class ContractVersionName:
    """A version-directory name split into its contract and version."""

    name: str
    contract: str
    version: SemVer


def parse_version(text: str) -> SemVer:
    """Read ``major``, ``major.minor`` or ``major.minor.patch`` as a SemVer."""

    if not isinstance(text, str):
        raise InvalidVersionNameError(f"a version must be text: {text!r}")
    match = _RELEASE.match(text.strip())
    if match is None:
        raise InvalidVersionNameError(
            f"{text!r} is not a release semantic version (expected "
            "'major', 'major.minor' or 'major.minor.patch')"
        )
    return SemVer(
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )


def parse_version_name(
    name: str, *, contract: str | None = None
) -> ContractVersionName:
    """Read a version-directory name such as ``example-v2`` or ``example-2.0.0``.

    A name carries its version as ``-v<major>[.<minor>[.<patch>]]`` or as a bare
    ``-<major>.<minor>.<patch>``. When ``contract`` is given, a name for another
    contract raises ``ContractVersionNameError``.
    """

    if not isinstance(name, str) or not name.strip():
        raise InvalidVersionNameError(f"a version name must be text: {name!r}")
    match = _VERSIONED_NAME.match(name) or _BARE_SEMVER_NAME.match(name)
    if match is None:
        raise InvalidVersionNameError(
            f"{name!r} does not carry a release version (expected "
            "'-v<major>[.<minor>[.<patch>]]' or '-<major>.<minor>.<patch>')"
        )
    parsed_contract = match.group("contract")
    if contract is not None and parsed_contract != contract:
        raise ContractVersionNameError(
            f"{name!r} names contract {parsed_contract!r}, not {contract!r}"
        )
    return ContractVersionName(
        name=name,
        contract=parsed_contract,
        version=parse_version(match.group("version")),
    )
