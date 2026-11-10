"""The handoff contract documents the shared rules read.

The producer owns ``data/contracts/scenario-handoff/``. This package carries the
whole contract directory, and the envelope schema, so a reader needs no
checkout. ``scripts/sync_handoff_package_data.py`` copies them and a producer
test fails when the copies differ.

``installed_specs`` reads the specs the package installs and ``read_handoff``
reads one handoff through them; ``load_contract`` pairs each published version's
schema with the ownership rules. Two versions are published: ``VERSION`` (the
newest, which requires the envelope) and ``LEGACY_VERSION`` (the retired version,
which a reader still validates).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from .envelope import ContractSpec, SpecSet, UnsupportedVersionError, load_specs

HANDOFF_SCHEMA_VERSION_V5 = "scenario-handoff-v5"
HANDOFF_SCHEMA_VERSION_V6 = "scenario-handoff-v6"
#: A version's directory, as the contract layout names it.
KIT_V5 = HANDOFF_SCHEMA_VERSION_V5
KIT_V6 = HANDOFF_SCHEMA_VERSION_V6
CASES_NAME = "cases"
OWNERSHIP_RULES_NAME = "ownership-rules.json"
CONTRACT = "scenario-handoff"
#: The older published version, retired: no writer publishes it.
LEGACY_VERSION = HANDOFF_SCHEMA_VERSION_V5
#: The newest published version, the one a new writer publishes.
VERSION = HANDOFF_SCHEMA_VERSION_V6
#: Every published version, oldest first.
VERSIONS = (LEGACY_VERSION, VERSION)
#: The installed spec root: ``<data>/<contract>/<version>/spec.json``.
DATA_DIR = Path(__file__).resolve().parent / "data"
CONTRACT_DIR = DATA_DIR / CONTRACT
_REGEX_FLAGS = {"IGNORECASE": re.IGNORECASE}


class ContractError(ValueError):
    """Raised when a handoff contract document cannot be read."""


@dataclass(frozen=True)
class Contract:
    """The documents one handoff kit states its rules in.

    ``schema`` is the newest installed version's, which is what a reader that
    knows no version uses; ``schemas`` holds each installed version's, so one
    contract serves a v5 document and a v6 document alike.
    """

    schema: Mapping[str, Any]
    forbidden_keys: frozenset[str]
    forbidden_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    specs: SpecSet | None = None
    schemas: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def schema_for(self, version: Any) -> Mapping[str, Any]:
        """Return one published version's schema, or the newest when it is unknown."""

        if isinstance(version, str) and version in self.schemas:
            return self.schemas[version]
        return self.schema


@cache
def installed_specs() -> SpecSet:
    """Return the contract specs this package installs."""

    return load_specs(DATA_DIR)


def read_handoff(document: Any) -> ContractSpec:
    """Read one handoff through the installed scenario-handoff specs.

    A document that carries the envelope is selected by its contract id and
    version; a legacy document without one is selected by ``schema_version``.
    """

    return installed_specs().read(document)


def load_contract(contract_dir: Path | None = None) -> Contract:
    """Read the schemas and the ownership rules of *contract_dir*.

    *contract_dir* is a directory holding ``ownership-rules.json`` and one
    directory per published version, as the producer's contract tree does.
    Without it, the package's own copies are read. A directory that holds only
    the older version states the older schema alone.
    """

    root = Path(contract_dir) if contract_dir is not None else CONTRACT_DIR
    rules = load_ownership_rules(root / OWNERSHIP_RULES_NAME)
    specs = installed_specs() if contract_dir is None else load_specs(root.parent)
    installed = {
        spec.version: spec for spec in specs.specs if spec.contract == CONTRACT
    }
    newest = next(
        (version for version in reversed(VERSIONS) if version in installed), None
    )
    if newest is None:
        supported = ", ".join(sorted(installed)) or "none"
        raise UnsupportedVersionError(
            f"no installed {CONTRACT} spec; installed versions: {supported}"
        )
    return Contract(
        schema=installed[newest].schema,
        forbidden_keys=rules[0],
        forbidden_patterns=rules[1],
        specs=specs,
        schemas={
            version: installed[version].schema
            for version in VERSIONS
            if version in installed
        },
    )


@cache
def packaged_contract() -> Contract:
    """Return the contract documents this package carries."""

    return load_contract()


def load_ownership_rules(
    path: Path,
) -> tuple[frozenset[str], tuple[tuple[str, re.Pattern[str]], ...]]:
    """Read an ownership-rules document into its forbidden keys and patterns.

    A pattern whose document names a flag this module does not know is refused,
    rather than silently matched with the wrong semantics.
    """

    document = _read_json(path, "ownership rules")
    forbidden_keys = frozenset(document["forbidden_keys"])
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for entry in document["forbidden_value_patterns"]:
        unknown = sorted(set(entry["flags"]) - _REGEX_FLAGS.keys())
        if unknown:
            raise ContractError(
                f"ownership rule {entry['code']} has unknown flags: {unknown}"
            )
        flags = 0
        for name in entry["flags"]:
            flags |= _REGEX_FLAGS[name]
        patterns.append((entry["code"], re.compile(entry["pattern"], flags)))
    return forbidden_keys, tuple(patterns)


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {label} {path}: {exc}") from exc


__all__ = [
    "CASES_NAME",
    "CONTRACT",
    "CONTRACT_DIR",
    "DATA_DIR",
    "Contract",
    "ContractError",
    "HANDOFF_SCHEMA_VERSION_V5",
    "HANDOFF_SCHEMA_VERSION_V6",
    "KIT_V5",
    "KIT_V6",
    "LEGACY_VERSION",
    "OWNERSHIP_RULES_NAME",
    "VERSION",
    "VERSIONS",
    "installed_specs",
    "load_contract",
    "load_ownership_rules",
    "packaged_contract",
    "read_handoff",
]
