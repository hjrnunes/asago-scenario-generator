"""The handoff contract documents the shared rules read.

The producer owns ``data/contracts/scenario-handoff/``. This package carries a
copy of the two documents ``validate_handoff`` reads, so a reader needs no
checkout. ``scripts/sync_handoff_package_data.py`` copies them and a producer
test fails when the copies differ.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

HANDOFF_SCHEMA_VERSION_V5 = "scenario-handoff-v5"
KIT_V5 = "handoff-v5"
OWNERSHIP_RULES_NAME = "ownership-rules.json"
DATA_DIR = Path(__file__).resolve().parent / "data"
_REGEX_FLAGS = {"IGNORECASE": re.IGNORECASE}


class ContractError(ValueError):
    """Raised when a handoff contract document cannot be read."""


@dataclass(frozen=True)
class Contract:
    """The documents one handoff kit states its rules in."""

    schema: Mapping[str, Any]
    forbidden_keys: frozenset[str]
    forbidden_patterns: tuple[tuple[str, re.Pattern[str]], ...]


def load_contract(contract_dir: Path | None = None) -> Contract:
    """Read the schema and the ownership rules of *contract_dir*.

    *contract_dir* is a directory holding ``ownership-rules.json`` and
    ``handoff-v5/schema.json``, as the producer's contract tree does. Without it,
    the package's own copies are read.
    """

    root = Path(contract_dir) if contract_dir is not None else DATA_DIR
    rules = load_ownership_rules(root / OWNERSHIP_RULES_NAME)
    schema = _read_json(root / KIT_V5 / "schema.json", "handoff schema")
    return Contract(schema=schema, forbidden_keys=rules[0], forbidden_patterns=rules[1])


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
    "DATA_DIR",
    "Contract",
    "ContractError",
    "HANDOFF_SCHEMA_VERSION_V5",
    "KIT_V5",
    "OWNERSHIP_RULES_NAME",
    "load_contract",
    "load_ownership_rules",
    "packaged_contract",
]
