#!/usr/bin/env python3
"""Independent external QA for the offline Phase 3 challenge ledger."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
LEDGER_PATH = ROOT / "tests/fixtures/stpa-obligation-challenge-ledger.yaml"
ASSESSMENT_PATH = ROOT / "tests/fixtures/hybrid-coverage-assessment.yaml"
LEDGER_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge-ledger:v1"
CHALLENGE_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge:v1"


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize(item)
            for key, item in value.items()
        }
    return value


def _digest(domain: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        _normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + canonical).hexdigest()


def _semantic_payload(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: data[key]
        for key in (
            "schema_version",
            "assessment_pin",
            "source_pins",
            "selection_policy_version",
            "challenge_budget",
            "records",
            "diagnostics",
            "network_calls",
            "model_calls",
        )
    }


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    """Check identity, selection, history, and digest without project imports."""
    ledger = yaml.safe_load(LEDGER_PATH.read_text(encoding="utf-8"))
    assessment = yaml.safe_load(ASSESSMENT_PATH.read_text(encoding="utf-8"))
    _check(isinstance(ledger, dict), "ledger is not a mapping")
    _check(
        ledger["schema_version"] == "stpa-obligation-challenge-ledger-v1",
        "schema version mismatch",
    )
    _check(
        ledger["selection_policy_version"] == "explicit-priority-v1",
        "selection policy mismatch",
    )
    _check(
        ledger["semantic_digest"] == _digest(LEDGER_DOMAIN, _semantic_payload(ledger)),
        "ledger digest mismatch",
    )
    _check(
        ledger["assessment_pin"]["semantic_digest"] == assessment["semantic_digest"],
        "assessment pin mismatch",
    )
    _check(
        ledger["source_pins"] == assessment["source_pins"],
        "upstream source pins changed",
    )
    records = ledger["records"]
    ordered = sorted(
        records,
        key=lambda item: (item["priority"], item["obligation_id"], item["slot_id"]),
    )
    _check(records == ordered, "records are not in deterministic priority order")
    _check(
        len({(item["obligation_id"], item["slot_id"]) for item in records})
        == len(records),
        "duplicate challenge target",
    )
    for index, record in enumerate(records):
        expected_status = (
            "selected" if index < ledger["challenge_budget"] else "not_selected_budget"
        )
        _check(record["selection_status"] == expected_status, "selection mismatch")
        expected_id = "challenge:v1:" + _digest(
            CHALLENGE_DOMAIN,
            {
                "assessment_digest": ledger["assessment_pin"]["semantic_digest"],
                "obligation_id": record["obligation_id"],
                "slot_id": record["slot_id"],
            },
        )
        _check(record["challenge_id"] == expected_id, "challenge identity mismatch")
    _check(
        ledger["diagnostics"]
        == {
            "eligible_targets": len(records),
            "selected_targets": min(ledger["challenge_budget"], len(records)),
            "not_selected_budget": max(0, len(records) - ledger["challenge_budget"]),
        },
        "diagnostics do not reconcile",
    )
    structural = {row["slot_id"]: row for row in assessment["structural_consideration"]}
    for record in records:
        source = structural[record["slot_id"]]
        original = record["original_decision"]
        for field in (
            "row_id",
            "slot_id",
            "controller_id",
            "control_action_id",
            "uca_type",
            "disposition",
            "ica_ids",
            "evidence",
            "trace_refs",
        ):
            _check(original[field] == source[field], f"original {field} changed")
    _check(all(record["outcome"] is None for record in records), "outcome was invented")
    serialized = json.dumps(ledger).lower()
    _check("relation_id" not in serialized, "ledger created correspondence")
    _check("scenario_id" not in serialized, "ledger created a scenario")
    _check(ledger["network_calls"] == ledger["model_calls"] == 0, "nonzero calls")
    print("STPA challenge ledger external QA: 14/14 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"STPA challenge ledger external QA: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
