"""The saved-artifact upgrade hook.

A contract version is immortal, but a saved artifact may still name an older
version. ``upgrade(document)`` reads the version, applies the registered steps in
order, writes the target version's envelope, and validates the result against
the installed spec. A step migrates the body only: it never writes the envelope,
and it must advance the document's ``schema_version``. An upgrade that has no
registered hop fails closed; silently returning a document the newest reader
would reject is worse than refusing it.

Register a hop where the contract's owner lives, not here::

    register_upgrade(
        CONTRACT, KIT_V5, KIT_V6, rename_the_party_relation
    )
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .envelope import (
    CORE_VERSION,
    ENVELOPE_FIELD,
    SpecSet,
    UnsupportedVersionError,
    write_envelope,
)
from .semver import InvalidVersionNameError, parse_version_name

DEFAULT_WRITER = "asago-contracts-core.upgrade"


class UpgradeError(ValueError):
    """A saved-artifact upgrade is missing, stalled or malformed."""


@dataclass(frozen=True)
class Upgrade:
    """One registered hop from a saved version to the next version."""

    contract: str
    from_version: str
    to_version: str
    step: Callable[[Mapping[str, Any]], Mapping[str, Any]]


_REGISTRY: dict[tuple[str, str, str], Upgrade] = {}


def register_upgrade(
    contract: str,
    from_version: str,
    to_version: str,
    step: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> Upgrade:
    """Register one upgrade hop; registering the same hop again replaces it."""

    if not isinstance(contract, str) or not contract.strip():
        raise UpgradeError("an upgrade needs a non-empty contract name")
    if not callable(step):
        raise UpgradeError(f"{contract}: an upgrade step must be callable")
    try:
        source = parse_version_name(from_version)
        target = parse_version_name(to_version)
    except InvalidVersionNameError as error:
        raise UpgradeError(str(error)) from error
    if not source.version < target.version:
        raise UpgradeError(
            f"{contract}: an upgrade must move forward, not "
            f"{from_version} -> {to_version}"
        )
    hop = Upgrade(
        contract=contract,
        from_version=from_version,
        to_version=to_version,
        step=step,
    )
    _REGISTRY[(contract, from_version, to_version)] = hop
    return hop


def registered_upgrades(contract: str | None = None) -> tuple[Upgrade, ...]:
    """Return the registered hops, of one contract or of every contract."""

    return tuple(
        hop
        for hop in _REGISTRY.values()
        if contract is None or hop.contract == contract
    )


def upgrade(
    document: Mapping[str, Any],
    specs: SpecSet | None = None,
    *,
    steps: Iterable[Upgrade] | None = None,
    writer: str = DEFAULT_WRITER,
    writer_version: str = CORE_VERSION,
) -> dict[str, Any]:
    """Return ``document`` upgraded to its contract's newest installed version."""

    if specs is None:
        from .contract import installed_specs

        specs = installed_specs()
    source = specs.read(document)
    target = _newest(specs, source.contract)
    if source.version == target:
        raise UnsupportedVersionError(
            f"{source.contract}: {source.version} is already the newest installed "
            "version"
        )
    source_version = parse_version_name(source.version).version
    target_version = parse_version_name(target).version
    if source_version > target_version:
        raise UnsupportedVersionError(
            f"{source.contract}: {source.version} is newer than the newest "
            f"installed version {target}"
        )
    hops = tuple(
        hop
        for hop in (steps if steps is not None else registered_upgrades())
        if hop.contract == source.contract
    )
    envelope = document.get(ENVELOPE_FIELD)
    requires: tuple[str, ...] = ()
    if isinstance(envelope, Mapping):
        named = envelope.get("requires", ())
        if isinstance(named, (list, tuple)):
            requires = tuple(named)
    body = {key: value for key, value in document.items() if key != ENVELOPE_FIELD}
    version = source.version
    while version != target:
        hop = next((hop for hop in hops if hop.from_version == version), None)
        if hop is None:
            raise UnsupportedVersionError(
                f"{source.contract}: no upgrade from {version} toward {target}; "
                "register the missing hop"
            )
        stepped = hop.step(dict(body))
        if not isinstance(stepped, Mapping):
            raise UpgradeError(
                f"{source.contract}: the {hop.from_version} -> {hop.to_version} "
                "step must return a JSON object"
            )
        body = dict(stepped)
        advanced = body.get(specs.version_key)
        if advanced != hop.to_version:
            raise UpgradeError(
                f"{source.contract}: the {hop.from_version} -> {hop.to_version} "
                f"step left the document at {advanced!r}"
            )
        version = hop.to_version
    spec = specs.spec(source.contract, target)
    return write_envelope(
        body,
        spec,
        writer=writer,
        writer_version=writer_version,
        requires=requires,
    )


def _newest(specs: SpecSet, contract: str) -> str:
    versions = specs.versions(contract)
    if not versions:
        raise UnsupportedVersionError(f"{contract}: no installed version")
    return max(versions, key=lambda name: parse_version_name(name).version)
