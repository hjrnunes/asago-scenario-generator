"""The handoff contract documents the shared rules read.

The producer owns ``data/contracts/scenario-handoff/``. This package carries the
whole contract directory, and the envelope schema, so a reader needs no
checkout. ``scripts/sync_handoff_package_data.py`` copies them and a producer
test fails when the copies differ.

``installed_specs`` reads the specs the package installs and ``read_handoff``
reads one handoff through them; ``load_contract`` pairs the selected spec's
schema with the ownership rules.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from .envelope import ContractSpec, SpecSet, load_specs

HANDOFF_SCHEMA_VERSION_V5 = "scenario-handoff-v5"
#: The version's directory, as the contract layout names it.
KIT_V5 = HANDOFF_SCHEMA_VERSION_V5
CASES_NAME = "cases"
OWNERSHIP_RULES_NAME = "ownership-rules.json"
CONTRACT = "scenario-handoff"
VERSION = HANDOFF_SCHEMA_VERSION_V5
#: The installed spec root: ``<data>/<contract>/<version>/spec.json``.
DATA_DIR = Path(__file__).resolve().parent / "data"
CONTRACT_DIR = DATA_DIR / CONTRACT
_REGEX_FLAGS = {"IGNORECASE": re.IGNORECASE}


class ContractError(ValueError):
    """Raised when a handoff contract document cannot be read."""


@dataclass(frozen=True)
class Contract:
    """The documents one handoff kit states its rules in."""

    schema: Mapping[str, Any]
    forbidden_keys: frozenset[str]
    forbidden_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    specs: SpecSet | None = None


@cache
def installed_specs() -> SpecSet:
    """Return the contract specs this package installs."""

    return load_specs(DATA_DIR)


def read_handoff(document: Any) -> ContractSpec:
    """Read one handoff through the installed scenario-handoff-v5 spec.

    A document that carries the envelope is selected by its contract id and
    version; a legacy document without one is selected by ``schema_version``.
    """

    return installed_specs().read(document)


def load_contract(contract_dir: Path | None = None) -> Contract:
    """Read the schema and the ownership rules of *contract_dir*.

    *contract_dir* is a directory holding ``ownership-rules.json`` and
    ``scenario-handoff-v5/``, as the producer's contract tree does. Without it,
    the package's own copies are read.
    """

    root = Path(contract_dir) if contract_dir is not None else CONTRACT_DIR
    rules = load_ownership_rules(root / OWNERSHIP_RULES_NAME)
    specs = installed_specs() if contract_dir is None else load_specs(root.parent)
    spec = specs.spec(CONTRACT, VERSION)
    return Contract(
        schema=spec.schema,
        forbidden_keys=rules[0],
        forbidden_patterns=rules[1],
        specs=specs,
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
    "KIT_V5",
    "OWNERSHIP_RULES_NAME",
    "VERSION",
    "installed_specs",
    "load_contract",
    "load_ownership_rules",
    "packaged_contract",
    "read_handoff",
]
