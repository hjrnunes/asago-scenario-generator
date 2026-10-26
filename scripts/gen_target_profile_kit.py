#!/usr/bin/env python3
"""Generate the target-profile-v1 contract kit and refresh CONTRACT.lock.

Run from any directory: ``uv run --frozen python scripts/gen_target_profile_kit.py``.
``valid/minimal.json`` and ``invalid/unknown-field.json`` are written by hand
and only read here; every other kit file is derived from them and from
``ExecutionTargetProfile``. Regenerating the kit must leave every byte
unchanged, which ``git status --porcelain data/contracts`` confirms.
Downstream repositories mirror the regenerated files byte-identically.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from asago_scenario_generator.stpa.models.execution_classification import (
    EXECUTION_TARGET_PROFILE_SCHEMA_VERSION,
    ExecutionTargetProfile,
)
from asago_scenario_generator.models.canonical import compute_framed_digest

ROOT = Path(__file__).resolve().parents[1] / "data/contracts/target-profile"
KIT_NAME = "target-profile-v1"
AUTHORITY = "asago-scenario-generator"
SCHEMA_DESCRIPTION = "Observed MCP target or explicit simulation execution profile."

#: The value facts of ``valid/value-facts.json``, on ``valid/minimal.json``.
VALUE_FACTS = {
    "arguments": [
        {
            "operation_id": "process_refund",
            "argument": "order_id",
            "record_kind": "order_id",
        }
    ],
    "state_fields": [
        {"path": "orders.*.customer_id", "record_kind": "customer_id"},
        {"path": "orders.*.ordered_on", "format": "date"},
    ],
    "state_keys": [{"path": "orders", "record_kind": "order_id"}],
}

#: Each invalid value-facts vector: the value facts it carries and its code.
#: The first two break the JSON Schema too; a reference to an operation or
#: an argument the profile does not list is a rule only the model checks.
INVALID_VALUE_FACTS = {
    "invalid/value-fact-without-declaration.json": (
        {"arguments": [{"operation_id": "process_refund", "argument": "order_id"}]},
        "value_fact_without_declaration",
    ),
    "invalid/value-fact-null-declaration.json": (
        {
            "state_fields": [
                {"path": "orders.*.customer_id", "record_kind": None, "format": None}
            ]
        },
        "value_fact_without_declaration",
    ),
    "invalid/value-fact-unknown-operation.json": (
        {
            "arguments": [
                {
                    "operation_id": "lookup_order",
                    "argument": "order_id",
                    "record_kind": "order_id",
                }
            ]
        },
        "value_fact_unknown_argument",
    ),
    "invalid/value-fact-unknown-argument.json": (
        {
            "arguments": [
                {
                    "operation_id": "process_refund",
                    "argument": "customer_id",
                    "record_kind": "customer_id",
                }
            ]
        },
        "value_fact_unknown_argument",
    ),
}

#: The codes of the hand-written invalid vectors.
HAND_WRITTEN_VIOLATIONS = {"invalid/unknown-field.json": ["unexpected_field"]}


def dump(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schema() -> dict:
    """The model's JSON Schema, framed with the contract's identity."""

    value = ExecutionTargetProfile.model_json_schema()
    value["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    value["$id"] = EXECUTION_TARGET_PROFILE_SCHEMA_VERSION
    value["description"] = SCHEMA_DESCRIPTION
    return value


def _minimal(kit: Path) -> dict:
    return json.loads((kit / "valid/minimal.json").read_text(encoding="utf-8"))


def _with_value_facts(minimal: dict, facts: dict) -> dict:
    """``minimal`` with value facts, re-signed as the model would sign it."""

    payload = copy.deepcopy(minimal)
    payload.pop("semantic_digest")
    payload["value_facts"] = copy.deepcopy(facts)
    payload["semantic_digest"] = compute_framed_digest(
        EXECUTION_TARGET_PROFILE_SCHEMA_VERSION, payload
    )
    return payload


def build(kit: Path) -> dict[str, str]:
    """Return every derived kit file's text by its kit-relative path."""

    minimal = _minimal(kit)
    valid = ExecutionTargetProfile.model_validate(
        {**copy.deepcopy(minimal), "value_facts": VALUE_FACTS, "semantic_digest": None}
    )
    files = {
        "schema.json": dump(schema()),
        "valid/value-facts.json": dump(valid.model_dump(mode="json")),
    }
    for relative, (facts, _) in INVALID_VALUE_FACTS.items():
        files[relative] = dump(_with_value_facts(minimal, facts))
    violations = dict(HAND_WRITTEN_VIOLATIONS)
    violations.update(
        {relative: [code] for relative, (_, code) in INVALID_VALUE_FACTS.items()}
    )
    files["expected-violations.json"] = dump(dict(sorted(violations.items())))
    return files


def write_kit(kit: Path) -> None:
    for relative, text in build(kit).items():
        path = kit / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    semantic = {
        relative: json.loads((kit / relative).read_text(encoding="utf-8"))[
            "semantic_digest"
        ]
        for relative in sorted(
            path.relative_to(kit).as_posix() for path in kit.glob("valid/*.json")
        )
    }
    pinned = {
        path.relative_to(kit).as_posix(): sha(path)
        for path in sorted(kit.rglob("*.json"))
        if path.name not in {"canonical-digests.json", "expected-violations.json"}
    }
    (kit / "canonical-digests.json").write_text(
        json.dumps(
            {"files": pinned, "semantic_digests": semantic},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def write_lock(root: Path) -> None:
    lock = {
        "authority": AUTHORITY,
        "contract": "target-profile",
        "digest_domain": EXECUTION_TARGET_PROFILE_SCHEMA_VERSION,
        "files": {
            path.relative_to(root).as_posix(): sha(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.name != "CONTRACT.lock"
        },
        "schema_version": EXECUTION_TARGET_PROFILE_SCHEMA_VERSION,
    }
    (root / "CONTRACT.lock").write_text(dump(lock), encoding="utf-8")


def main(root: Path = ROOT) -> None:
    write_kit(root / KIT_NAME)
    write_lock(root)


if __name__ == "__main__":
    main()
