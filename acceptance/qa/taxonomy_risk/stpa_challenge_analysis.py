#!/usr/bin/env python3
"""Independent external QA for one Phase 3 challenge-analysis result."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
RESULT_PATH = ROOT / "tests/fixtures/stpa-obligation-challenge-analysis.yaml"
REQUEST_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge-request:v1"
RESPONSE_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge-response:v1"
RESULT_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge-analysis:v1"
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


def _digest(domain: str, payload: Any) -> str:
    canonical = json.dumps(
        _normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + canonical).hexdigest()


def _without(data: dict[str, Any], field: str) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key != field}


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _response_payload(result: dict[str, Any]) -> dict[str, Any]:
    outcome = result["outcome"]
    evidence = result["call_evidence"]
    return {
        "status": "completed",
        "request_digest": result["request"]["semantic_digest"],
        "draft": {
            "disposition": outcome["disposition"],
            "reason": result["unresolved_reason"],
            "rationale": outcome["rationale"],
            "evidence_refs": outcome["evidence_refs"],
        },
        "effective_controls": evidence["effective_controls"],
        "adapter_kind": evidence["adapter_kind"],
        "request_ref": evidence["request_ref"],
        "response_ref": evidence["response_ref"],
        "provider_calls": evidence["provider_calls"],
        "network_calls": evidence["network_calls"],
    }


def main() -> int:
    """Verify the result without importing the application package."""
    result = yaml.safe_load(RESULT_PATH.read_text(encoding="utf-8"))
    _check(isinstance(result, dict), "analysis result is not a mapping")
    _check(
        result["schema_version"] == "stpa-obligation-challenge-analysis-v1",
        "analysis schema mismatch",
    )
    request = result["request"]
    _check(
        request["semantic_digest"]
        == _digest(REQUEST_DOMAIN, _without(request, "semantic_digest")),
        "request digest mismatch",
    )
    _check(
        result["semantic_digest"]
        == _digest(RESULT_DOMAIN, _without(result, "semantic_digest")),
        "analysis digest mismatch",
    )
    taxonomy = request["context"]["taxonomy"]
    original = request["original_decision"]
    expected_challenge = "challenge:v1:" + _digest(
        CHALLENGE_DOMAIN,
        {
            "assessment_digest": request["assessment_pin"]["semantic_digest"],
            "obligation_id": taxonomy["obligation_id"],
            "slot_id": original["slot_id"],
        },
    )
    _check(request["challenge_id"] == expected_challenge, "challenge identity mismatch")
    _check(result["original_decision"] == original, "original decision changed")
    controls = request["controls"]
    _check(
        controls["attempt_limit"] == 1 and controls["automatic_retries"] == 0,
        "attempt/retry controls changed",
    )
    evidence = result["call_evidence"]
    _check(
        evidence["request_digest"] == request["semantic_digest"],
        "call evidence request mismatch",
    )
    _check(
        evidence["response_digest"]
        == _digest(RESPONSE_DOMAIN, _response_payload(result)),
        "response digest mismatch",
    )
    _check(
        evidence["adapter_attempts"] == 1,
        "adapter attempt count mismatch",
    )
    _check(
        evidence["adapter_kind"] == "fake"
        and evidence["provider_calls"] == evidence["network_calls"] == 0,
        "offline fake adapter evidence mismatch",
    )
    _check(result["status"] == "completed", "result is not completed")
    _check(
        result["outcome"]["disposition"] == "unresolved"
        and result["unresolved_reason"] == "missing_evidence",
        "unresolved outcome lost its typed reason",
    )
    _check(
        result["technical_failure"] is None, "structural result has technical failure"
    )
    _check(
        result["correspondence_changes"] == result["coverage_changes"] == 0,
        "challenge result changed correspondence or coverage",
    )
    _check(
        result["hybrid_generation_status"] == "not_attempted"
        and result["hybrid_admission_status"] == "not_assessed",
        "challenge result started hybrid generation",
    )
    _check(
        request["context"]["exec_candidate_id"] == "EXEC:RESP-1:CA-1-1:WRONG_TIMING",
        "canonical EXEC identity mismatch",
    )
    print("STPA challenge analysis external QA: 14/14 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"STPA challenge analysis external QA: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
