"""Offline checks over supplied rules and recorded facts; no policy inference."""

import json
import operator
from collections.abc import Mapping
from typing import Any, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class FactRef(_Closed):
    document: Annotated[StrictStr, Field(min_length=1)]
    path: tuple[StrictStr, ...]


class Comparison(_Closed):
    left: FactRef
    operator: Literal["equals", "not_equals", "greater_than", "less_than"]
    right: FactRef


class OutcomeCheck(_Closed):
    rule_id: Annotated[StrictStr, Field(min_length=1)]
    case_digest: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    rule_source: FactRef
    observation_complete: FactRef
    execution_status: FactRef
    applicability: Annotated[tuple[Comparison, ...], Field(min_length=1)]
    violation: Comparison


_MISSING = object()
_COMPARE = {
    "equals": operator.eq,
    "not_equals": operator.ne,
    "greater_than": operator.gt,
    "less_than": operator.lt,
}


def evaluate_supplied_outcome(
    check: OutcomeCheck | None, documents: Mapping[str, Any], *, case_digest: str
) -> dict:
    """An effect alone cannot establish a violation without a supplied rule."""
    result = {
        "condition_verdict": "inconclusive",
        "reason": "No explicit outcome check supplied",
        "vulnerability_confirmed": False,
        "assessment_scope": "supplied_check_only",
        "rule_interpretation_independently_verified": False,
    }
    if check is None:
        return result
    if not isinstance(check, OutcomeCheck):
        raise TypeError("check must be an OutcomeCheck")
    check = OutcomeCheck.model_validate(check.model_dump())
    snapshot = json.loads(canonical_json_bytes(documents))
    result["check_digest"] = compute_framed_digest(
        "offline-outcome-check-v1", check.model_dump()
    )
    result["document_digests"] = {
        name: compute_framed_digest("offline-outcome-document-v1", value)
        for name, value in snapshot.items()
    }
    if check.case_digest != case_digest:
        return {
            **result,
            "condition_verdict": "execution_error",
            "reason": "Check names a different artifact",
        }
    evidence = []
    result["evidence"] = evidence
    rule_text = _resolve(check.rule_source, snapshot, evidence)
    if not isinstance(rule_text, str) or not rule_text.strip():
        return {**result, "reason": "Referenced rule text is missing"}
    status = _resolve(check.execution_status, snapshot, evidence)
    if status == "failed":
        return {
            **result,
            "condition_verdict": "execution_error",
            "reason": "Recorded execution failed",
        }
    if status != "completed":
        return {**result, "reason": "Completed execution is not established"}
    if _resolve(check.observation_complete, snapshot, evidence) is not True:
        return {**result, "reason": "Complete observation is not established"}
    applies = [_compare(item, snapshot, evidence) for item in check.applicability]
    if False in applies:
        return {
            **result,
            "reason": "Supplied rule does not apply",
            "applicability": False,
        }
    if None in applies:
        return {**result, "reason": "Applicability evidence is missing or incompatible"}
    violation = _compare(check.violation, snapshot, evidence)
    if violation is None:
        return {**result, "reason": "Outcome evidence is missing or incompatible"}
    return {
        **result,
        "condition_verdict": "unsafe" if violation else "safe",
        "reason": "Recorded facts evaluated against the explicitly supplied check",
        "applicability": True,
    }


def _resolve(ref: FactRef, documents: dict, evidence: list) -> Any:
    value = documents.get(ref.document, _MISSING)
    for key in ref.path:
        if not isinstance(value, Mapping) or key not in value:
            evidence.append(
                {"document": ref.document, "path": list(ref.path), "status": "missing"}
            )
            return _MISSING
        value = value[key]
    if value is not _MISSING:
        evidence.append(
            {"document": ref.document, "path": list(ref.path), "value": value}
        )
    else:
        evidence.append(
            {"document": ref.document, "path": list(ref.path), "status": "missing"}
        )
    return value


def _compare(comparison: Comparison, documents: dict, evidence: list) -> bool | None:
    left = _resolve(comparison.left, documents, evidence)
    right = _resolve(comparison.right, documents, evidence)
    numeric = type(left) in (int, float) and type(right) in (int, float)
    if comparison.operator in ("greater_than", "less_than"):
        return _COMPARE[comparison.operator](left, right) if numeric else None
    if type(left) not in (str, bool, int, float, type(None)):
        return None
    if type(left) is not type(right) and not numeric:
        return None
    return _COMPARE[comparison.operator](left, right)
